"""Managed MCP dispatch: component CLIs, diagnostics reporting, and `remote` envelopes.

[Role]
Implements the execution half of `mindie_harness.mcp.gateway.ManagedMCPAdapter`:
`run_component_tool`, `run_diagnostics_tool`, `list_remote_tools`, and
`dispatch_remote_tool`. Unwraps `remote_dev` payloads into canonical MCP
`{"content", "structuredContent", "isError"}` envelopes and pipes bounded
`stdin_json` / `stdin_text` (`<= 1 MiB`) to RSI and debugger CLIs.

[Invariants]
- Principle 10: `ProcessSpec(..., max_output_bytes=16 MiB)` is the child spool cap;
  `max_output_tokens * 4` applies ONLY when slicing the reply.
- Single-session `remote_*` calls run in-process when `cfg["python"]` matches
  `sys.executable`; any second distinct `session_id` on the same `state_dir` or any
  cross-interpreter call routes via framed stdin/stdout child IPC (`MINDIE_GREMOTE_JSON:`),
  preventing cross-session bleed, password argv leaks, and Win32 `32 KB` argv limits.
- Every `except OSError:` is preceded by `except TimeoutError: raise`.

[Timeouts & Locks]
- Component tools honor `ctx.deadline` (`<= 600s` inner + grace) and `ctx.cancel`.
- Remote in-process calls are lock-free on the network path; child IPC uses `ctx.deadline`.

[Side-Effect Policy]
- Spawns bounded child processes and optional in-process `remote_dev` calls only.
"""
from __future__ import annotations

import contextlib
import json
import os
from pathlib import Path
import sys
import threading
import time
from typing import Any, Mapping

from ..component_commands import COMPONENT_MODULES, resolve_component_command
from ..paths import ProfileRef, same_interpreter
from ..process.supervisor import (
    DEFAULT_CONTROL_PLANE_MEMORY_BYTES,
    Deadline,
    ProcessSpec,
    run_owned,
)
from .router import RequestContext

FRAME_PREFIX = "MINDIE_GREMOTE_JSON:"
HOST_REMOTE_PROFILES: dict[str, str] = {
    "codex": "codex",
    "cc": "claude",
    "kimi": "kimi",
    "dsh": "dsh",
    "wb": "wb",
    "agy": "agy",
    "oc": "oc",
    "omp": "canonical",
}
COMPONENT_OUTPUT_SPOOL_BYTES = 16 * 1024 * 1024
MAX_STDIN_PAYLOAD_BYTES = 1 * 1024 * 1024
_STDERR_TAIL_CHARS = 2000
_UNBOUNDED_MEMORY_COMPONENTS: frozenset[str] = frozenset({"profiler", "sim", "debugger"})

_REMOTE_SESSION_LOCK = threading.Lock()
_BOUND_REMOTE_INPROC: tuple[str, str] | None = None


def resolve_remote_profile(host: str, env: Mapping[str, str]) -> str:
    """Return `REMOTE_DEV_HARNESS_PROFILE` or the canonical host profile."""
    return env.get("REMOTE_DEV_HARNESS_PROFILE") or HOST_REMOTE_PROFILES.get(str(host), "canonical")


def mcp_result(
    text: str,
    *,
    is_error: bool = False,
    structured: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "content": [{"type": "text", "text": str(text)}],
        "isError": bool(is_error),
    }
    if structured is not None:
        result["structuredContent"] = dict(structured)
    return result


def error_result(
    reason: str,
    message: str,
    *,
    state: str = "not_sent",
    extra: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    structured: dict[str, Any] = {
        "stage": "dispatch",
        "reason": reason,
        "submission_state": state,
        "retryable": False,
        "message": message,
    }
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


def _prepare_stdin_bytes(arguments: Mapping[str, Any]) -> tuple[bytes, dict[str, Any] | None]:
    if "stdin_json" in arguments and arguments.get("stdin_json") is not None:
        raw_json = arguments["stdin_json"]
        if not isinstance(raw_json, (Mapping, list)):
            return b"", error_result("invalid_arguments", "`stdin_json` must be a JSON object or array.")
        encoded = (json.dumps(raw_json, ensure_ascii=False) + "\n").encode("utf-8")
        if len(encoded) > MAX_STDIN_PAYLOAD_BYTES:
            return b"", error_result("input_too_large", "`stdin_json` exceeds 1 MiB limit.")
        return encoded, None
    if "stdin_text" in arguments and arguments.get("stdin_text") is not None:
        raw_text = arguments["stdin_text"]
        if not isinstance(raw_text, str):
            return b"", error_result("invalid_arguments", "`stdin_text` must be a string.")
        encoded = raw_text.encode("utf-8")
        if len(encoded) > MAX_STDIN_PAYLOAD_BYTES:
            return b"", error_result("input_too_large", "`stdin_text` exceeds 1 MiB limit.")
        return encoded, None
    return b"", None


def _component_deadline(ctx: RequestContext, timeout_ms: int) -> Deadline:
    requested_inner = timeout_ms / 1000.0
    grace = 60.0 if requested_inner > 120.0 else 5.0
    if ctx.deadline is None:
        return Deadline.from_timeout(requested_inner + grace, cleanup_grace=grace)
    rem = ctx.deadline.inner_remaining()
    if rem <= 0:
        raise TimeoutError("Component tool budget exhausted before dispatch")
    eff_inner = min(requested_inner, rem)
    eff_grace = min(ctx.deadline.cleanup_grace, grace)
    now = time.monotonic()
    return Deadline(
        expires_at=min(ctx.deadline.expires_at, now + eff_inner + eff_grace),
        cleanup_grace=eff_grace,
    )


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
    stdin_bytes, stdin_err = _prepare_stdin_bytes(arguments)
    if stdin_err is not None:
        return stdin_err

    cfg = _config(profile)
    timeout_ms = int_clamped(arguments.get("timeout_ms"), 120000, 1, 600000)
    max_tokens = int_clamped(arguments.get("max_output_tokens"), 16384, 1, 262144)
    base = resolve_component_command(cfg, python_exe(profile, cfg), name)
    argv = leading_argv if leading_argv is not None else arguments.get("argv")
    extra = [str(item) for item in argv] if isinstance(argv, (list, tuple)) else []
    if name == "npu_top" and not extra:
        extra = ["--json", "servers"]
    mod_name = COMPONENT_MODULES.get(name)
    if (
        name in {"rsi_loop", "experiment_ledger", "rsi_plan", "rsi_autotune"}
        and mod_name is not None
        and len(base) >= 3
        and base[-2:] == ["-m", mod_name]
        and not _venv_has_gateway(Path(base[0]))
    ):
        caller_root = str(Path(__file__).resolve().parents[2])
        launch_argv = (
            base[0],
            "-I",
            "-X",
            "utf8",
            "-c",
            "import runpy,sys; sys.path.append(sys.argv.pop(1)); m=sys.argv.pop(1); sys.argv=[m,*sys.argv[1:]]; runpy.run_module(m, run_name='__main__')",
            caller_root,
            mod_name,
            *extra,
        )
    else:
        launch_argv = tuple([*base, *extra])

    child_env = dict(ctx.env)
    allow_breakaway = False
    if name == "coordinator":
        child_env["MINDIE_COORDINATOR_NATIVE_CALL"] = "1"
        allow_breakaway = True
    mem_limit = None if name in _UNBOUNDED_MEMORY_COMPONENTS else DEFAULT_CONTROL_PLANE_MEMORY_BYTES
    eff_cwd = ctx.cwd if (ctx.cwd is not None and ctx.cwd.is_dir()) else None
    eff_deadline = _component_deadline(ctx, timeout_ms)

    try:
        outcome = run_owned(
            ProcessSpec(
                argv=launch_argv,
                cwd=eff_cwd,
                env=child_env,
                stdin_bytes=stdin_bytes,
                role="foreground",
                max_output_bytes=COMPONENT_OUTPUT_SPOOL_BYTES,
                memory_limit_bytes=mem_limit,
                allow_daemon_breakaway=allow_breakaway,
                allowed_returncodes=None,
            ),
            deadline=eff_deadline,
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

    structured: dict[str, Any] = {
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
    }
    receipt_warning: str | None = None
    if name in {"rsi_loop", "experiment_ledger", "rsi_plan", "rsi_autotune"} and (outcome.stdout or "").strip():
        try:
            parsed_rsi = json.loads((outcome.stdout or "").strip())
            if isinstance(parsed_rsi, Mapping):
                structured["rsi"] = dict(parsed_rsi)
                if outcome.returncode == 3:
                    structured["status"] = str(parsed_rsi.get("status") or "blocked")
                if outcome.returncode == 0 and isinstance(parsed_rsi.get("receipt_warning"), str):
                    receipt_warning = parsed_rsi["receipt_warning"]
                    structured["receipt_warning"] = receipt_warning
                    structured["receipt_unconfirmed"] = True
        except ValueError:
            pass

    res = mcp_result(
        text or f"{tool_name} exited {outcome.returncode}",
        is_error=outcome.returncode != 0,
        structured=structured,
    )
    if receipt_warning is not None:
        res["receipt_warning"] = receipt_warning
        res["receipt_unconfirmed"] = True
    return res


def _diagnostics_config(arguments: Mapping[str, Any], ctx: RequestContext, profile: ProfileRef) -> str:
    explicit = arguments.get("config")
    if isinstance(explicit, str) and explicit.strip():
        return explicit.strip()
    configured = ctx.env.get("MINDIE_DIAGNOSTICS_CONFIG") or os.environ.get("MINDIE_DIAGNOSTICS_CONFIG")
    return (
        str(configured).strip()
        if isinstance(configured, str) and configured.strip()
        else str(profile.config_path.parent / "diagnostics.json")
    )


def run_diagnostics_tool(
    ctx: RequestContext,
    tool_name: str,
    arguments: Mapping[str, Any],
    profile: ProfileRef,
) -> dict[str, Any]:
    """Run `diagnostics reporting status --config <cfg>` (or `diagnostics bundle`)."""
    arguments = arguments or {}
    if tool_name == "diagnostics_status":
        leading = ["reporting", "status", "--config", _diagnostics_config(arguments, ctx, profile)]
    else:
        raw_argv = arguments.get("argv")
        leading = [
            "bundle",
            *([str(item) for item in raw_argv] if isinstance(raw_argv, (list, tuple)) else []),
        ]
    passthrough = {key: value for key, value in arguments.items() if key not in {"argv", "config"}}
    return run_component_tool(ctx, tool_name, passthrough, profile, component="diagnostics", leading_argv=leading)


def _remote_state_dir(ctx: RequestContext, profile: ProfileRef) -> str:
    return (
        ctx.env.get("REMOTE_DEV_STATE_DIR")
        or ctx.env.get("MINDIE_REMOTE_STATE_DIR")
        or str(profile.data_dir / "remote-dev")
    )


def _claim_inproc_remote_session(state_dir: str, session_id: str) -> bool:
    """Bind `(state_dir, session_id)` once in-process; route distinct sessions to child IPC."""
    global _BOUND_REMOTE_INPROC
    clean_session = str(session_id or "").strip()
    clean_state = str(state_dir)
    with _REMOTE_SESSION_LOCK:
        if _BOUND_REMOTE_INPROC is None or _BOUND_REMOTE_INPROC[0] != clean_state:
            _BOUND_REMOTE_INPROC = (clean_state, clean_session)
            os.environ["REMOTE_DEV_STATE_DIR"] = clean_state
            if clean_session:
                os.environ["REMOTE_DEV_SESSION_ID"] = clean_session
            return True
        return _BOUND_REMOTE_INPROC[1] == clean_session


@contextlib.contextmanager
def _remote_request_context(cancel: Any):
    try:
        from remote_dev.core.cancellation import request_context  # type: ignore[import-not-found]
    except TimeoutError:
        raise
    except ImportError:
        yield
        return
    with request_context(cancel):
        yield


def _minimal_outcome(_tool_name: str, payload: Mapping[str, Any]) -> str:
    details = payload.get("result", payload)
    if not isinstance(details, Mapping):
        return "failed"
    err = details.get("error_details") if isinstance(details.get("error_details"), Mapping) else {}
    if (
        details.get("unknown") is True
        or details.get("status") == "submission_uncertain"
        or err.get("submission_state") == "uncertain"
    ):
        return "unknown"
    if details.get("outcome") in {"success", "cancelled", "cancellation-requested", "already-finished"}:
        return "succeeded"
    if details.get("kind") == "background" and details.get("jobId") not in (None, ""):
        return "succeeded"
    if details.get("state") in {"succeeded", "failed", "timeout", "cancelled"} and type(details.get("exit_code")) is int:
        return "succeeded"
    if details.get("error") or details.get("error_details"):
        return "failed"
    return "succeeded" if payload.get("text") or details else "failed"


def _minimal_text(payload: Mapping[str, Any]) -> str:
    text = str(payload.get("text") or "").strip()
    if text:
        return text
    details = payload.get("result", payload)
    if isinstance(details, Mapping):
        return json.dumps(dict(details), sort_keys=True, default=str)[:4000]
    return json.dumps(dict(payload), sort_keys=True, default=str)[:4000]


def remote_envelope(tool_name: str, raw: Any) -> dict[str, Any]:
    """Wrap a raw `remote_dev.mcp.tools.call_tool` payload as an MCP tool result."""
    try:
        from remote_dev.mcp.outcome import operation_outcome  # type: ignore[import-not-found]
        from remote_dev.result import tool_text  # type: ignore[import-not-found]
    except TimeoutError:
        raise
    except ImportError:
        operation_outcome = _minimal_outcome
        tool_text = _minimal_text

    payload: dict[str, Any] = dict(raw) if isinstance(raw, Mapping) else {"result": raw}
    outcome = operation_outcome(tool_name, payload)
    details: dict[str, Any] = (
        dict(payload["result"])
        if isinstance(payload.get("result"), Mapping)
        else dict(payload)
    )
    if outcome == "unknown":
        details.setdefault("submission_state", "uncertain")

    blocks: list[dict[str, Any]] = [{"type": "text", "text": tool_text(payload)}]
    extra = payload.get("content")
    if isinstance(extra, list):
        for block in extra:
            if isinstance(block, Mapping) and isinstance(block.get("type"), str):
                blocks.append(dict(block))
    return {
        "content": blocks,
        "structuredContent": details,
        "isError": outcome != "succeeded",
    }


def _remote_exception_result(tool_name: str, exc: BaseException) -> dict[str, Any]:
    try:
        from remote_dev.core.errors import error_details, safe_auth_error_details  # type: ignore[import-not-found]

        details = error_details(exc)
        auth = safe_auth_error_details(details) if isinstance(details, dict) else None
    except TimeoutError:
        raise
    except ImportError:
        details = {"type": type(exc).__name__, "category": "internal", "retryable": False}
        auth = None
    except Exception:
        details = {"type": type(exc).__name__, "category": "internal", "retryable": False}
        auth = None

    public_details = auth if isinstance(auth, dict) else details
    message = str((auth or {}).get("hint") or f"{tool_name} failed ({type(exc).__name__}).")
    structured: dict[str, Any] = {
        "stage": "dispatch",
        "reason": "remote_tool_failed",
        "submission_state": str(public_details.get("submission_state") or "not_sent") if isinstance(public_details, dict) else "not_sent",
        "message": message,
    }
    if isinstance(public_details, dict):
        structured.update({key: value for key, value in public_details.items() if key not in structured})
        structured["error_details"] = public_details
    if auth:
        structured["auth"] = auth
    return mcp_result(message, is_error=True, structured=structured)


def _venv_has_gateway(target_py: Path) -> bool:
    venv_root = target_py.parent.parent
    sites = [venv_root / "Lib" / "site-packages"]
    lib_dir = venv_root / "lib"
    if lib_dir.is_dir():
        sites.extend(lib_dir.glob("python*/site-packages"))
    return any(
        (site / "mindie_harness" / "mcp" / "gateway_dispatch.py").is_file()
        for site in sites
        if site.is_dir()
    )


def _child_argv(target_py: Path) -> tuple[str, ...]:
    if _venv_has_gateway(target_py):
        return (str(target_py), "-I", "-X", "utf8", "-m", "mindie_harness.mcp.gateway_dispatch")
    caller_root = str(Path(__file__).resolve().parents[2])
    return (
        str(target_py),
        "-I",
        "-X",
        "utf8",
        "-c",
        "import runpy,sys; sys.path.append(sys.argv.pop(1)); runpy.run_module('mindie_harness.mcp.gateway_dispatch', run_name='__main__')",
        caller_root,
    )


def list_remote_tools(profile: ProfileRef, env: Mapping[str, str], host: str | None = None) -> list[dict[str, Any]]:
    remote_profile = resolve_remote_profile(host or profile.host, env)
    target_py = Path(python_exe(profile))
    if same_interpreter(target_py, sys.executable):
        try:
            from remote_dev.mcp.tools import list_tools  # type: ignore[import-not-found]

            tools = list_tools(remote_profile)
            return [dict(item) for item in tools] if isinstance(tools, (list, tuple)) else []
        except TimeoutError:
            raise
        except ImportError:
            pass
        except Exception:
            return []

    child_env = dict(env, REMOTE_DEV_HARNESS_PROFILE=remote_profile, MINDIE_REMOTE_CHILD="1")
    req = {"op": "list_tools", "remote_profile": remote_profile}
    try:
        outcome = run_owned(
            ProcessSpec(
                argv=_child_argv(target_py),
                env=child_env,
                stdin_bytes=(json.dumps(req, ensure_ascii=True) + "\n").encode("utf-8"),
                role="foreground",
                allowed_returncodes=None,
            ),
            deadline=Deadline.from_timeout(15.0),
        )
        for line in reversed((outcome.stdout or "").splitlines()):
            if line.startswith(FRAME_PREFIX):
                parsed = json.loads(line[len(FRAME_PREFIX) :])
                tools_raw = parsed.get("tools") if isinstance(parsed, Mapping) else None
                return [dict(item) for item in tools_raw] if isinstance(tools_raw, list) else []
        return []
    except TimeoutError:
        raise
    except Exception:
        return []


def _remote_via_python(
    ctx: RequestContext,
    arguments: Mapping[str, Any],
    target_py: Path,
    remote_profile: str,
    state_dir: str,
) -> dict[str, Any]:
    env = dict(
        ctx.env,
        REMOTE_DEV_SESSION_ID=ctx.session_id,
        REMOTE_DEV_STATE_DIR=state_dir,
        REMOTE_DEV_HARNESS_PROFILE=remote_profile,
        MINDIE_REMOTE_CHILD="1",
    )
    req = {
        "op": "call_tool",
        "tool_name": ctx.tool_name,
        "arguments": dict(arguments or {}),
        "remote_profile": remote_profile,
    }
    try:
        outcome = run_owned(
            ProcessSpec(
                argv=_child_argv(target_py),
                env=env,
                stdin_bytes=(json.dumps(req, ensure_ascii=True) + "\n").encode("utf-8"),
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

    stdout_text = outcome.stdout or ""
    for line in reversed(stdout_text.splitlines()):
        if line.startswith(FRAME_PREFIX):
            try:
                parsed = json.loads(line[len(FRAME_PREFIX) :])
            except ValueError:
                break
            if isinstance(parsed, Mapping) and isinstance(parsed.get("envelope"), Mapping):
                return dict(parsed["envelope"])

    if outcome.returncode != 0:
        return error_result(
            "remote_tool_failed",
            f"{ctx.tool_name} failed (exit {outcome.returncode}).",
            extra={
                "returncode": outcome.returncode,
                "stderr": (outcome.stderr or "")[-_STDERR_TAIL_CHARS:],
            },
        )
    return error_result(
        "remote_failed",
        f"{ctx.tool_name} exited without a valid framed JSON response.",
        extra={"returncode": outcome.returncode},
    )


def dispatch_remote_tool(
    ctx: RequestContext,
    arguments: Mapping[str, Any],
    profile: ProfileRef,
    host: str | None = None,
) -> dict[str, Any]:
    """Dispatch one `remote_*` tool without cross-session `os.environ` bleed."""
    remote_profile = resolve_remote_profile(host or profile.host, ctx.env)
    state_dir = _remote_state_dir(ctx, profile)
    target_py = Path(python_exe(profile))
    if not same_interpreter(target_py, sys.executable):
        return _remote_via_python(ctx, arguments, target_py, remote_profile, state_dir)

    try:
        from remote_dev.mcp.tools import call_tool  # type: ignore[import-not-found]
    except TimeoutError:
        raise
    except ImportError:
        return _remote_via_python(ctx, arguments, target_py, remote_profile, state_dir)

    auth_dir = ctx.env.get("REMOTE_DEV_AUTH_DIR")
    try:
        from remote_dev.core.state_store import session_scope  # type: ignore[import-not-found]
    except TimeoutError:
        raise
    except ImportError:
        session_scope = None

    if session_scope is not None:
        with session_scope(ctx.session_id, state_dir=state_dir, auth_dir=auth_dir), _remote_request_context(ctx.cancel):
            try:
                raw = call_tool(ctx.tool_name, dict(arguments or {}), profile=remote_profile)
            except TimeoutError:
                raise
            except Exception as exc:
                return _remote_exception_result(ctx.tool_name, exc)
        return remote_envelope(ctx.tool_name, raw)

    if not _claim_inproc_remote_session(state_dir, ctx.session_id):
        return _remote_via_python(ctx, arguments, target_py, remote_profile, state_dir)

    with _remote_request_context(ctx.cancel):
        try:
            raw = call_tool(ctx.tool_name, dict(arguments or {}), profile=remote_profile)
        except TimeoutError:
            raise
        except Exception as exc:
            return _remote_exception_result(ctx.tool_name, exc)
    return remote_envelope(ctx.tool_name, raw)


def _cli_main() -> int:
    raw_in = sys.stdin.buffer.read(16 * 1024 * 1024)
    req = json.loads(raw_in.decode("utf-8-sig"))
    op = req.get("op")
    if op == "list_tools":
        from remote_dev.mcp.tools import list_tools  # type: ignore[import-not-found]

        tools = list_tools(req.get("remote_profile"))
        body: dict[str, Any] = {"tools": [dict(item) for item in tools] if isinstance(tools, (list, tuple)) else []}
    elif op == "call_tool":
        tool_name = str(req["tool_name"])
        try:
            from remote_dev.mcp.tools import call_tool  # type: ignore[import-not-found]

            raw = call_tool(tool_name, dict(req.get("arguments") or {}), profile=req.get("remote_profile"))
            body = {"envelope": remote_envelope(tool_name, raw)}
        except Exception as exc:
            body = {"envelope": _remote_exception_result(tool_name, exc)}
    else:
        raise ValueError(f"Unknown gateway_dispatch op: {op!r}")

    sys.stdout.buffer.write((FRAME_PREFIX + json.dumps(body, ensure_ascii=True) + "\n").encode("utf-8"))
    sys.stdout.buffer.flush()
    return 0


__all__ = [
    "COMPONENT_MODULES",
    "COMPONENT_OUTPUT_SPOOL_BYTES",
    "HOST_REMOTE_PROFILES",
    "MAX_STDIN_PAYLOAD_BYTES",
    "dispatch_remote_tool",
    "error_result",
    "int_clamped",
    "list_remote_tools",
    "mcp_result",
    "python_exe",
    "remote_envelope",
    "resolve_remote_profile",
    "run_component_tool",
    "run_diagnostics_tool",
]

if __name__ == "__main__":
    raise SystemExit(_cli_main())
