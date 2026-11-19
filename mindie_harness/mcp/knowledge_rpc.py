"""Canonical `knowledge_*` MCP schemas and lazy thin-host knowledge RPC dispatch.

[Role]
Defines the 5 canonical `KNOWLEDGE_TOOL_SCHEMAS` (`knowledge_query`, `knowledge_explain`,
`knowledge_feedback`, `knowledge_distill`, `knowledge_sync`), `KNOWLEDGE_NAMES`, and
`invoke_knowledge_tool`—dispatching in-process through `mindie_knowledge`
loop APIs (`Admission`, domain routing, service RPC, distillation views) or via
the profile's configured Python when the MCP server runs under a bootstrap interpreter.

[Invariants]
- Zero top-level `mindie_knowledge` import: the optional package is imported only
  inside `invoke_knowledge_tool`, so `import mindie_harness` stays pure stdlib.
- Receipt Honesty: once primary `rpc` succeeds, a local `adm_store.finish(...)`
  failure keeps `isError=False` and attaches `receipt_warning`
  plus `receipt_unconfirmed=True`.
- Unknown operations and malformed arguments return structured `isError=True`
  results; they never raise across the MCP boundary.

[Timeouts & Locks]
- Child fallback uses `run_owned` with a `35s` (read) or `110s` (sync/distill)
  budget plus `10s` cleanup grace; no global environment or cwd is mutated.

[Side-Effect Policy]
- Public reads do not create capture leases; mutations execute the knowledge package's
  own idempotent ledgers. The child fallback reads `<host>.json` read-only.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import sys
from typing import Any, Mapping

from ..atomic import read_json_safe
from ..paths import HarnessError, ProfileRef
from ..process.supervisor import Deadline, ProcessSpec, run_owned
from .receipts import apply_receipt_honesty

from .knowledge_schemas import KNOWLEDGE_NAMES, KNOWLEDGE_TOOL_SCHEMAS

def _error_result(reason: str, message: str, *, is_error: bool = True) -> dict[str, Any]:
    return {
        "content": [{"type": "text", "text": message}],
        "isError": bool(is_error),
        "structuredContent": {"stage": "dispatch", "reason": reason, "submission_state": "not_sent", "retryable": False, "message": message},
    }


def _normalize_result(value: Any) -> dict[str, Any]:
    if isinstance(value, Mapping) and isinstance(value.get("content"), list):
        result = dict(value)
        result.setdefault("isError", False)
        return result
    if isinstance(value, Mapping):
        payload = dict(value)
        return {
            "content": [{"type": "text", "text": json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str)}],
            "isError": bool(payload.get("isError")),
            "structuredContent": payload,
        }
    return {"content": [{"type": "text", "text": str(value)}], "isError": False}


def _try_in_process(
    operation: str, arguments: dict[str, Any], *, profile: ProfileRef,
    session_id: str, cwd: Path | None, deadline: Deadline | None = None,
) -> dict[str, Any] | None:
    try:
        # Knowledge exposes these in its loop modules, not its package root.
        from mindie_knowledge.loop.activation import Admission
        from mindie_knowledge.loop.cli import config_at, ensure_service
        from mindie_knowledge.loop.domain_routes import select_engine_config
        from mindie_knowledge.loop.transport import rpc
    except ModuleNotFoundError as exc:
        if exc.name == "mindie_knowledge":
            return None
        return _error_result("knowledge_import_failed", f"Knowledge import failed ({exc}).")
    except ImportError as exc:
        return _error_result("knowledge_import_failed", f"Knowledge import failed ({exc}).")

    method = operation.removeprefix("knowledge_")
    stage = "config"
    submitted = False
    admission = None
    lease = None
    try:
        if not isinstance(session_id, str) or not session_id.strip():
            return _error_result("knowledge_identity_missing", "A host session identity is required.")
        if any(str(key).startswith("_") for key in arguments):
            return _error_result("invalid_arguments", "Internal identity fields are not tool arguments.")
        adapter = read_json_safe(profile.config_path)
        default = Path(adapter.get("engine_config") or profile.config_path.with_name(profile.config_path.stem + ".engine.json"))
        engine = config_at(default)
        routes = dict(adapter.get("domain_configs") or {})
        # Native upgrades retain old domain mappings while publishing this engine.
        routes[engine["domain"]] = str(default.resolve())
        refs = ([arguments["ref"]] if arguments.get("ref") else []) + list(arguments.get("refs") or [])
        selected = select_engine_config(default, domain=arguments.get("domain"), ref=refs[0] if refs else None, domain_configs=routes)
        for ref in refs[1:]:
            if select_engine_config(default, domain=arguments.get("domain"), ref=ref, domain_configs=routes) != selected:
                raise ValueError("references select different knowledge domains")
        payload = dict(arguments)
        payload.pop("domain", None)
        if method in {"query", "explain", "feedback", "distill"}:
            payload["_session_id"] = session_id
        if method == "distill":
            stage = "authorization"
            admission = Admission(config_at(selected)["admission_path"])
            lease = admission.active_lease(session_id)
            if not lease or not lease.get("token") or not lease.get("entry_enabled"):
                return _error_result("knowledge_authorization_required", "Distillation requires existing scoped capture authorization.")
            payload["_activation"] = lease["token"]
        elif method in {"query", "explain", "feedback"}:
            payload["_session_verified"] = True
        stage = "service"
        if deadline is not None:
            deadline.require_remaining()
        connection = ensure_service(selected)
        stage = "rpc"
        timeout = 110.0 if method in {"sync", "distill"} else 35.0
        if deadline is not None:
            timeout = deadline.inner_remaining()
            if timeout <= 0:
                raise TimeoutError("Knowledge RPC budget exhausted before dispatch")
        submitted = True
        raw = rpc(connection, method, payload, timeout=timeout)
    except TimeoutError:
        raise
    except HarnessError:
        raise
    except Exception as exc:
        result = _error_result(f"knowledge_{stage}_failed", f"{type(exc).__name__}: {exc}")
        result["structuredContent"].update(stage=stage, submission_state="sent" if submitted else "not_sent")
        return result

    if method == "distill":
        from mindie_knowledge.graded.distill import result_view
        raw, is_error = result_view(raw)
        result = _normalize_result(raw)
        result["isError"] = is_error
    else:
        result = _normalize_result(raw if isinstance(raw, Mapping) else {"results": raw})
    if admission is not None and lease is not None:
        try:
            admission.finish(session_id, lease["token"], not result["isError"])
        except Exception as exc:
            # A completed operation survives even a timeout writing its receipt.
            if result["isError"] is not True:
                result = apply_receipt_honesty(result, exc)
    # ensure_service returns a shared connection; it is never owned by this call.
    return result


def _child_script() -> str:
    return (
        "import json,sys\n"
        "from mindie_harness.paths import ProfileRef\n"
        "from mindie_harness.mcp.knowledge_rpc import invoke_knowledge_tool\n"
        "operation,args_json,host,plugin_root,config_path,data_dir,session_id,cwd = sys.argv[1:9]\n"
        "profile = ProfileRef.resolve(host, plugin_root=plugin_root, config_path=config_path, data_dir=data_dir)\n"
        "res = invoke_knowledge_tool(operation, json.loads(args_json), profile=profile, session_id=session_id, cwd=None if cwd == '-' else cwd)\n"
        "print(json.dumps(res, ensure_ascii=False))\n"
    )


def _invoke_via_python(operation: str, arguments: dict[str, Any], *, profile: ProfileRef, session_id: str, cwd: Path | None, deadline: Deadline | None = None) -> dict[str, Any]:
    if os.environ.get("MINDIE_KNOWLEDGE_FALLBACK") == "1":
        return _error_result("knowledge_unavailable", "mindie_knowledge RPC is unavailable in this interpreter; refusing recursive fallback.")
    cfg = read_json_safe(profile.config_path)
    python_raw = cfg.get("python") if isinstance(cfg, Mapping) else None
    python = Path(python_raw) if isinstance(python_raw, str) and python_raw.strip() else None
    if python is None or not python.is_file():
        return _error_result("knowledge_unavailable", "mindie_knowledge is unavailable in this interpreter and no validated profile Python is configured.")
    repo_root = Path(__file__).resolve().parents[2]
    inner = 110.0 if operation in {"knowledge_sync", "knowledge_distill"} else 35.0
    env = dict(profile_env(profile, session_id), MINDIE_KNOWLEDGE_FALLBACK="1")
    env["PYTHONPATH"] = str(repo_root) + (f"{os.pathsep}{env['PYTHONPATH']}" if env.get("PYTHONPATH") else "")
    script = f"import sys; sys.path.insert(0, {str(repo_root)!r}); " + _child_script()
    try:
        outcome = run_owned(
            ProcessSpec(
                argv=(str(python), "-I", "-X", "utf8", "-c", script, operation, json.dumps(arguments, sort_keys=True), profile.host, str(profile.plugin_root), str(profile.config_path), str(profile.data_dir), session_id, str(cwd) if cwd else "-"),
                env=env,
                role="foreground",
                allowed_returncodes=None,
            ),
            deadline=deadline if deadline is not None else Deadline.from_budgets([inner], cleanup_grace=10.0),
        )
    except TimeoutError:
        raise
    except OSError as exc:
        return _error_result("knowledge_unavailable", f"Could not start knowledge fallback ({type(exc).__name__}).")
    text = (outcome.stdout or "").strip()
    if outcome.returncode != 0:
        return _error_result("knowledge_failed", f"knowledge fallback exited {outcome.returncode}: {(outcome.stderr or text)[:512]}")
    if not text:
        return _error_result("knowledge_failed", f"knowledge fallback exited {outcome.returncode} without a result")
    try:
        parsed = json.loads(text.splitlines()[-1])
    except ValueError:
        return _error_result("knowledge_invalid_result", "knowledge fallback returned invalid JSON.")
    if not isinstance(parsed, Mapping) or not parsed:
        return _error_result("knowledge_invalid_result", "knowledge fallback returned an empty or non-object result.")
    return _normalize_result(parsed)


def profile_env(profile: ProfileRef, session_id: str) -> dict[str, str]:
    return {"MINDIE_AGENT_CONFIG": str(profile.config_path), "MINDIE_SESSION_ID": session_id, "MINDIE_CONFIG_HOME": str(profile.config_path.parent), "MINDIE_DATA_HOME": str(profile.data_dir)}


def invoke_knowledge_tool(
    operation: str,
    arguments: Mapping[str, Any] | None,
    *,
    profile: ProfileRef,
    session_id: str,
    cwd: Path | None = None,
    deadline: Deadline | None = None,
) -> dict[str, Any]:
    """Dispatch one canonical knowledge operation with in-process or profile-Python fallback."""
    name = str(operation or "").strip()
    if name not in KNOWLEDGE_NAMES:
        return _error_result("unknown_operation", f"Unknown knowledge operation {name!r}.")
    if arguments is None:
        args: dict[str, Any] = {}
    elif isinstance(arguments, Mapping):
        args = dict(arguments)
    else:
        return _error_result("invalid_arguments", "Knowledge tool arguments must be a JSON object.")
    try:
        in_process = _try_in_process(name, args, profile=profile, session_id=session_id, cwd=cwd, deadline=deadline)
    except HarnessError as exc:
        return _error_result(exc.reason, str(exc))
    if in_process is not None:
        return in_process
    return _invoke_via_python(name, args, profile=profile, session_id=session_id, cwd=cwd, deadline=deadline)


__all__ = ["KNOWLEDGE_NAMES", "KNOWLEDGE_TOOL_SCHEMAS", "invoke_knowledge_tool", "profile_env"]
