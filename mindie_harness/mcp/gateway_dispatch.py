"""Managed MCP dispatch: component CLIs, diagnostics reporting, and `remote` envelopes.

[Role]
Implements the execution half of `mindie_harness.mcp.gateway.ManagedMCPAdapter`:
`run_component_tool`, `run_diagnostics_tool`, `list_remote_tools`, and
`dispatch_remote_tool`. In-process `remote_dev` results (`{"result": ..., "text": ...}`)
are wrapped into a real MCP `{"content", "structuredContent", "isError"}` envelope
using `remote_dev.mcp.outcome.operation_outcome` + `remote_dev.mcp.server.tool_text`.

[Invariants]
- Principle 10: `ProcessSpec(..., max_output_bytes=16 MiB)` is the child spool cap;
  `max_output_tokens * 4` applies ONLY when slicing the reply, so a small token cap
  never kills a verbose child command.
- `remote` calls never take a global lock: state dir / session are process-constant
  `os.environ.setdefault` values and cancellation is passed through `remote_dev`'s
  `request_context` ContextVar, so `remote_bash` never serializes `remote_job_status`.
- Subprocess fallback uses `ctx.deadline` (never a hardcoded `120s`) and returns
  `isError=True` for non-zero exits, empty stdout, or non-JSON output.
- `<host>.json` `component_commands` wins for every component (custom wrappers kept).
- Every `except OSError:` is preceded by `except TimeoutError: raise`.

[Timeouts & Locks]
- Component tools run under `Deadline.from_timeout(timeout_ms + 5s, grace 5s)`.
- Remote in-process calls are lock-free; the subprocess fallback uses the caller's
  `ctx.deadline` and `ctx.cancel`.

[Side-Effect Policy]
- Spawns bounded child processes and optional in-process `remote_dev` calls only.
"""
from __future__ import annotations

import contextlib
import json
import os
import sys
from pathlib import Path
from typing import Any, Mapping

from ..component_commands import COMPONENT_MODULES, resolve_component_command
from ..paths import ProfileRef
from ..process.supervisor import Deadline, ProcessSpec, run_owned
from .router import RequestContext

HOST_REMOTE_PROFILES: dict[str, str] = {
    "codex": "codex", "cc": "claude", "kimi": "kimi", "dsh": "dsh",
    "wb": "wb", "agy": "agy", "oc": "oc",
}
COMPONENT_OUTPUT_SPOOL_BYTES = 16 * 1024 * 1024
_STDERR_TAIL_CHARS = 2000


def resolve_remote_profile(host: str, env: Mapping[str, str]) -> str:
    """Return `REMOTE_DEV_HARNESS_PROFILE` or the canonical host profile."""
    return env.get("REMOTE_DEV_HARNESS_PROFILE") or HOST_REMOTE_PROFILES.get(str(host), "canonical")


def mcp_result(text: str, *, is_error: bool = False, structured: Mapping[str, Any] | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {"content": [{"type": "text", "text": str(text)}], "isError": bool(is_error)}
    if structured is not None:
        result["structuredContent"] = dict(structured)
    return result


def error_result(reason: str, message: str, *, state: str = "not_sent", extra: Mapping[str, Any] | None = None) -> dict[str, Any]:
    structured = {"stage": "dispatch", "reason": reason, "submission_state": state, "retryable": False, "message": message}
    if extra:
        structured.update(extra)
    return mcp_result(message, is_error=True, structured=structured)


def int_clamped(value: Any, default: int, low: int, high: int) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return default
    return max(low, min(high, int(value)))


def python_exe(profile: ProfileRef, cfg: Mapping[str, Any] | None = None) -> str:
    from ..atomic import read_json_safe

    document = cfg if isinstance(cfg, Mapping) else read_json_safe(profile.config_path)
    raw = document.get("python") if isinstance(document, Mapping) else None
    return str(raw) if isinstance(raw, str) and Path(raw).is_file() else sys.executable


def _config(profile: ProfileRef) -> dict[str, Any]:
    from ..atomic import read_json_safe

    raw = read_json_safe(profile.config_path)
    return dict(raw) if isinstance(raw, Mapping) else {}


def _slice_bytes(raw: bytes, limit: int) -> tuple[str, bool]:
    limit = max(1, int(limit))
    if len(raw) <= limit:
        return raw.decode("utf-8", errors="replace"), False
    return raw[:limit].decode("utf-8", errors="ignore") + "...[truncated]", True


def run_component_tool(
    ctx: RequestContext,
    tool_name: str,
    arguments: Mapping[str, Any],
    profile: ProfileRef,
    *,
    component: str | None = None,
    leading_argv: list[str] | None = None,
) -> dict[str, Any]:
    """Run one component CLI with a 16 MiB spool cap and a token-sized reply."""
    arguments = arguments or {}
    name = component or tool_name
    cfg = _config(profile)
    timeout_ms = int_clamped(arguments.get("timeout_ms"), 120000, 1, 300000)
    max_tokens = int_clamped(arguments.get("max_output_tokens"), 16384, 1, 262144)
    base = resolve_component_command(cfg, python_exe(profile, cfg), name)
    argv = leading_argv if leading_argv is not None else arguments.get("argv")
    extra = [str(item) for item in argv] if isinstance(argv, (list, tuple)) else []
    try:
        outcome = run_owned(
            ProcessSpec(
                argv=tuple([*base, *extra]),
                env=dict(ctx.env),
                role="foreground",
                max_output_bytes=COMPONENT_OUTPUT_SPOOL_BYTES,
                allowed_returncodes=None,
            ),
            deadline=Deadline.from_timeout(timeout_ms / 1000.0 + 5.0, cleanup_grace=5.0),
            cancel=ctx.cancel,
        )
    except TimeoutError:
        raise
    except OSError as exc:
        return error_result("component_unavailable", f"Could not start `{name}` ({type(exc).__name__}).")
    stdout_bytes = (outcome.stdout or "").encode("utf-8", errors="replace")
    stderr_bytes = (outcome.stderr or "").encode("utf-8", errors="replace")
    reply_limit = max_tokens * 4
    stdout_text, _ = _slice_bytes(stdout_bytes, reply_limit)
    stderr_text, _ = _slice_bytes(stderr_bytes, reply_limit)
    output_truncated = (len(stdout_bytes) + len(stderr_bytes)) > reply_limit
    text = stdout_text.strip() or stderr_text.strip()
    if output_truncated:
        text = f"{text}\n...[output truncated]"
    return mcp_result(
        text or f"{tool_name} exited {outcome.returncode}",
        is_error=outcome.returncode != 0,
        structured={
            "stage": "component",
            "tool": tool_name,
            "component": name,
            "module": COMPONENT_MODULES.get(name),
            "command": list(base),
            "returncode": outcome.returncode,
            "stdout": stdout_text,
            "stderr": stderr_text,
            "output_truncated": output_truncated,
            "elapsed_ms": outcome.elapsed_ms,
        },
    )


def _diagnostics_config(arguments: Mapping[str, Any], ctx: RequestContext, profile: ProfileRef) -> str:
    explicit = arguments.get("config")
    if isinstance(explicit, str) and explicit.strip():
        return explicit.strip()
    configured = ctx.env.get("MINDIE_DIAGNOSTICS_CONFIG") or os.environ.get("MINDIE_DIAGNOSTICS_CONFIG")
    return str(configured).strip() if isinstance(configured, str) and configured.strip() else str(profile.config_path.parent / "diagnostics.json")


def run_diagnostics_tool(ctx: RequestContext, tool_name: str, arguments: Mapping[str, Any], profile: ProfileRef) -> dict[str, Any]:
    """Run `diagnostics reporting status --config <cfg>` (or `diagnostics bundle`)."""
    arguments = arguments or {}
    if tool_name == "diagnostics_status":
        leading = ["reporting", "status", "--config", _diagnostics_config(arguments, ctx, profile)]
    else:
        raw_argv = arguments.get("argv")
        leading = ["bundle", *([str(item) for item in raw_argv] if isinstance(raw_argv, (list, tuple)) else [])]
    passthrough = {key: value for key, value in arguments.items() if key not in {"argv", "config"}}
    return run_component_tool(ctx, tool_name, passthrough, profile, component="diagnostics", leading_argv=leading)


def _remote_state_dir(ctx: RequestContext, profile: ProfileRef) -> str:
    return (
        ctx.env.get("REMOTE_DEV_STATE_DIR")
        or ctx.env.get("MINDIE_REMOTE_STATE_DIR")
        or str(profile.data_dir / "remote-dev")
    )


def _bind_remote_process_env(ctx: RequestContext, state_dir: str) -> None:
    """Publish profile-constant process env without locking across network calls."""
    os.environ.setdefault("REMOTE_DEV_STATE_DIR", str(state_dir))
    session = str(ctx.session_id or "").strip()
    if session:
        # remote-dev (0.1.x) resolves its ledger scope from env only; set it once
        # instead of mutating/per-call restoring os.environ under a global lock.
        os.environ.setdefault("REMOTE_DEV_SESSION_ID", session)


@contextlib.contextmanager
def _session_scope(session_id: str):
    """Bind the session through remote-dev's ContextVar when the package exposes one."""
    scope = None
    try:
        from remote_dev.core.state_store import session_scope  # type: ignore[import-not-found]

        scope = session_scope
    except TimeoutError:
        raise
    except Exception:
        try:
            from remote_dev.core.state_store import bind_session  # type: ignore[import-not-found]

            scope = bind_session
        except TimeoutError:
            raise
        except Exception:
            scope = None
    if scope is None:
        yield
        return
    try:
        manager = scope(str(session_id))
    except TimeoutError:
        raise
    except Exception:
        yield
        return
    with manager:
        yield


@contextlib.contextmanager
def _remote_request_context(cancel: Any):
    try:
        from remote_dev.core.cancellation import request_context  # type: ignore[import-not-found]
    except TimeoutError:
        raise
    except Exception:
        yield
        return
    with request_context(cancel):
        yield


def _fallback_tool_text(payload: Mapping[str, Any]) -> str:
    text = str(payload.get("text") or "").strip()
    if text:
        return text
    details = payload.get("result")
    if isinstance(details, Mapping):
        return json.dumps(dict(details), sort_keys=True, default=str)[:4000]
    return json.dumps(dict(payload), sort_keys=True, default=str)[:4000]


def _fallback_operation_outcome(_tool_name: str, payload: Mapping[str, Any]) -> str:
    details = payload.get("result")
    if not isinstance(details, Mapping):
        return "failed"
    if details.get("outcome") in {"success", "cancelled", "cancellation-requested", "already-finished"}:
        return "succeeded"
    if details.get("kind") == "background" and details.get("jobId") not in (None, ""):
        return "succeeded"
    if details.get("state") in {"succeeded", "failed", "timeout", "cancelled"} and type(details.get("exit_code")) is int:
        return "succeeded"
    if details.get("error") or details.get("error_details"):
        return "failed"
    return "succeeded" if payload.get("text") or details else "failed"


def remote_envelope(tool_name: str, raw: Any) -> dict[str, Any]:
    """Wrap a raw `remote_dev.mcp.tools.call_tool` payload as an MCP tool result."""
    try:
        from remote_dev.mcp.outcome import operation_outcome  # type: ignore[import-not-found]
        from remote_dev.mcp.server import tool_text  # type: ignore[import-not-found]
    except TimeoutError:
        raise
    except Exception:
        operation_outcome = _fallback_operation_outcome
        tool_text = _fallback_tool_text
    payload: dict[str, Any] = dict(raw) if isinstance(raw, Mapping) else {"result": raw}
    outcome = operation_outcome(tool_name, payload)
    blocks: list[dict[str, Any]] = [{"type": "text", "text": tool_text(payload)}]
    extra = payload.get("content")
    if isinstance(extra, list):
        for block in extra:
            if isinstance(block, Mapping) and isinstance(block.get("type"), str):
                blocks.append(dict(block))
    return {"content": blocks, "structuredContent": payload, "isError": outcome != "succeeded"}


def _remote_exception_result(tool_name: str, exc: BaseException) -> dict[str, Any]:
    try:
        from remote_dev.core.errors import error_details, safe_auth_error_details  # type: ignore[import-not-found]
    except TimeoutError:
        raise
    except Exception:
        error_details = lambda error: {"type": type(error).__name__, "category": "internal", "retryable": False}
        safe_auth_error_details = lambda _details: None
    try:
        details = error_details(exc)
    except TimeoutError:
        raise
    except Exception:
        details = {"type": type(exc).__name__, "category": "internal", "retryable": False}
    auth = safe_auth_error_details(details) if isinstance(details, dict) else None
    message = str((auth or {}).get("hint") or f"{tool_name} failed ({type(exc).__name__}).")
    structured = {"stage": "dispatch", "reason": "remote_tool_failed", "message": message}
    if isinstance(details, dict):
        structured.update({key: value for key, value in details.items() if key not in structured})
        structured["error_details"] = details
    if auth:
        structured["auth"] = auth
    return mcp_result(message, is_error=True, structured=structured)


def list_remote_tools(profile: ProfileRef, env: Mapping[str, str], host: str | None = None) -> list[dict[str, Any]]:
    remote_profile = resolve_remote_profile(host or profile.host, env)
    try:
        from remote_dev.mcp.tools import list_tools  # type: ignore[import-not-found]

        tools = list_tools(remote_profile)
        return [dict(item) for item in tools] if isinstance(tools, (list, tuple)) else []
    except TimeoutError:
        raise
    except Exception:
        pass
    statement = "import json; from remote_dev.mcp.tools import list_tools; print(json.dumps(list_tools()))"
    child_env = dict(env, REMOTE_DEV_HARNESS_PROFILE=remote_profile)
    try:
        outcome = run_owned(ProcessSpec(argv=(python_exe(profile), "-I", "-X", "utf8", "-c", statement), env=child_env, role="foreground", allowed_returncodes=None), deadline=Deadline.from_timeout(15.0))
        parsed = json.loads((outcome.stdout or "[]").strip() or "[]")
        return [dict(item) for item in parsed] if isinstance(parsed, list) else []
    except TimeoutError:
        raise
    except Exception:
        return []


def _remote_via_python(ctx: RequestContext, arguments: Mapping[str, Any], profile: ProfileRef, remote_profile: str, state_dir: str) -> dict[str, Any]:
    statement = "import json,sys; from remote_dev.mcp.tools import call_tool; print(json.dumps(call_tool(sys.argv[1], json.loads(sys.argv[2]), profile=sys.argv[3])))"
    env = dict(ctx.env, REMOTE_DEV_SESSION_ID=ctx.session_id, REMOTE_DEV_STATE_DIR=state_dir, REMOTE_DEV_HARNESS_PROFILE=remote_profile)
    try:
        outcome = run_owned(
            ProcessSpec(
                argv=(python_exe(profile), "-I", "-X", "utf8", "-c", statement, ctx.tool_name, json.dumps(dict(arguments or {})), remote_profile),
                env=env,
                role="foreground",
                max_output_bytes=COMPONENT_OUTPUT_SPOOL_BYTES,
                allowed_returncodes=None,
            ),
            deadline=ctx.deadline,
            cancel=ctx.cancel,
        )
    except TimeoutError:
        raise
    except OSError as exc:
        return error_result("remote_unavailable", f"remote-dev is unavailable ({type(exc).__name__}).")
    text = (outcome.stdout or "").strip()
    if outcome.returncode != 0:
        return error_result(
            "remote_tool_failed",
            f"{ctx.tool_name} failed (exit {outcome.returncode}).",
            extra={"returncode": outcome.returncode, "stderr": (outcome.stderr or "")[-_STDERR_TAIL_CHARS:]},
        )
    if not text:
        return error_result("remote_failed", f"{ctx.tool_name} returned no result.", extra={"returncode": outcome.returncode})
    try:
        parsed = json.loads(text)
    except ValueError:
        return error_result("remote_failed", f"{ctx.tool_name} returned invalid JSON.")
    if not isinstance(parsed, dict):
        return mcp_result(str(parsed), structured={"result": parsed})
    return remote_envelope(ctx.tool_name, parsed)


def dispatch_remote_tool(ctx: RequestContext, arguments: Mapping[str, Any], profile: ProfileRef, host: str | None = None) -> dict[str, Any]:
    """Dispatch one `remote_*` tool without holding a global environment lock."""
    remote_profile = resolve_remote_profile(host or profile.host, ctx.env)
    state_dir = _remote_state_dir(ctx, profile)
    try:
        from remote_dev.mcp.tools import call_tool  # type: ignore[import-not-found]
    except TimeoutError:
        raise
    except Exception:
        return _remote_via_python(ctx, arguments, profile, remote_profile, state_dir)
    _bind_remote_process_env(ctx, state_dir)
    with _session_scope(ctx.session_id), _remote_request_context(ctx.cancel):
        try:
            raw = call_tool(ctx.tool_name, dict(arguments or {}), profile=remote_profile)
        except TimeoutError:
            raise
        except Exception as exc:
            return _remote_exception_result(ctx.tool_name, exc)
    return remote_envelope(ctx.tool_name, raw)


__all__ = [
    "COMPONENT_MODULES", "COMPONENT_OUTPUT_SPOOL_BYTES", "HOST_REMOTE_PROFILES",
    "dispatch_remote_tool", "error_result", "int_clamped", "list_remote_tools",
    "mcp_result", "python_exe", "remote_envelope", "resolve_remote_profile",
    "run_component_tool", "run_diagnostics_tool",
]
