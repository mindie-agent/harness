"""Canonical `knowledge_*` MCP schemas and lazy thin-host knowledge RPC dispatch.

[Role]
Defines the 5 canonical `KNOWLEDGE_TOOL_SCHEMAS` (`knowledge_query`, `knowledge_explain`,
`knowledge_feedback`, `knowledge_distill`, `knowledge_sync`), `KNOWLEDGE_NAMES`, and
`invoke_knowledge_tool`—dispatching in-process through `mindie_knowledge`
(`Admission`, `select_engine_config`, `ensure_service`, `rpc`, `result_view`) or via
the profile's configured Python when the MCP server runs under a bootstrap interpreter.

[Invariants]
- Zero top-level `mindie_knowledge` import: the optional package is imported only
  inside `invoke_knowledge_tool`, so `import mindie_harness` stays pure stdlib.
- Receipt Honesty: once primary `rpc` succeeds, a local `adm_store.finish(...)`
  `OSError` / `sqlite3.Error` keeps `isError=False` and attaches `receipt_warning`
  plus `receipt_unconfirmed=True`.
- Unknown operations and malformed arguments return structured `isError=True`
  results; they never raise across the MCP boundary.

[Timeouts & Locks]
- Child fallback uses `run_owned` with a `35s` (read) or `110s` (sync/distill)
  budget plus `10s` cleanup grace; no global environment or cwd is mutated.

[Side-Effect Policy]
- Read tools are side-effect free; mutation tools execute the knowledge package's
  own idempotent ledgers. The child fallback reads `<host>.json` read-only.
"""
from __future__ import annotations

import importlib
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import sys
from typing import Any, Mapping, Sequence

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


def _call_variants(fn: Any, variants: Sequence[tuple[tuple[Any, ...], dict[str, Any]]]) -> Any:
    last_error: Exception | None = None
    for args, kwargs in variants:
        try:
            return fn(*args, **kwargs)
        except TypeError as exc:
            last_error = exc
    if last_error is not None:
        raise last_error
    return None


def _try_in_process(operation: str, arguments: dict[str, Any], *, profile: ProfileRef, session_id: str, cwd: Path | None) -> dict[str, Any] | None:
    package = sys.modules.get("mindie_knowledge")
    if package is None:
        try:
            spec = importlib.util.find_spec("mindie_knowledge")
        except (ImportError, AttributeError, ValueError):
            return None
        if spec is None:
            return None
        try:
            package = importlib.import_module("mindie_knowledge")
        except TimeoutError:
            raise
        except ImportError:
            return None
        except Exception as exc:
            return _error_result("knowledge_import_failed", f"mindie_knowledge import failed ({type(exc).__name__}).")
    if not callable(getattr(package, "rpc", None)):
        return None

    admission: Any = None
    service: Any = None
    closeables: list[Any] = []
    try:
        admission_cls = getattr(package, "Admission", None)
        if callable(admission_cls):
            admission = _call_variants(
                admission_cls,
                [
                    ((profile.admission_db,), {"session_id": session_id}),
                    ((profile.admission_db,), {}),
                    ((profile,), {"session_id": session_id}),
                    ((), {}),
                ],
            )
            closeables.append(admission)
        select_config = getattr(package, "select_engine_config", None)
        config = None
        if callable(select_config):
            config = _call_variants(
                select_config,
                [((profile.config_path,), {}), ((str(profile.config_path),), {}), ((profile,), {}), ((), {})],
            )
        ensure_service = getattr(package, "ensure_service", None)
        if callable(ensure_service):
            service = _call_variants(
                ensure_service,
                [((config,), {"session_id": session_id, "admission": admission}), ((config,), {"session_id": session_id}), ((config,), {}), ((), {})],
            )
            closeables.append(service)
        rpc_fn = package.rpc
        raw = _call_variants(
            rpc_fn,
            [
                ((service, operation, arguments), {"session_id": session_id, "cwd": cwd}),
                ((service, operation, arguments), {"session_id": session_id}),
                ((operation, arguments), {"session_id": session_id, "admission": admission}),
                ((), {"operation": operation, "arguments": arguments, "session_id": session_id}),
                ((service, operation, arguments), {}),
                ((operation, arguments), {}),
            ],
        )
    except TimeoutError:
        raise
    except HarnessError:
        raise
    except Exception as exc:
        return _error_result("knowledge_rpc_failed", f"mindie_knowledge RPC failed ({type(exc).__name__}): {exc}")

    view = getattr(package, "result_view", None)
    if callable(view):
        try:
            raw = _call_variants(view, [((raw,), {}), ((operation, raw), {})])
        except Exception:
            pass
    result = _normalize_result(raw)
    adm_store = getattr(admission, "store", admission)
    finish = getattr(adm_store, "finish", None)
    if callable(finish):
        try:
            _call_variants(finish, [((), {"session_id": session_id, "operation": operation, "status": "succeeded"}), ((session_id,), {}), ((operation,), {})])
        except TimeoutError:
            raise
        except (OSError, sqlite3.Error) as exc:
            if result.get("isError") is not True:
                result = apply_receipt_honesty(result, exc)
        except Exception:
            pass
    for item in reversed(closeables):
        close = getattr(item, "close", None) or getattr(item, "stop", None)
        if callable(close):
            try:
                close()
            except TimeoutError:
                raise
            except Exception:
                pass
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
        in_process = _try_in_process(name, args, profile=profile, session_id=session_id, cwd=cwd)
    except HarnessError as exc:
        return _error_result(exc.reason, str(exc))
    if in_process is not None:
        return in_process
    return _invoke_via_python(name, args, profile=profile, session_id=session_id, cwd=cwd, deadline=deadline)


__all__ = ["KNOWLEDGE_NAMES", "KNOWLEDGE_TOOL_SCHEMAS", "invoke_knowledge_tool", "profile_env"]
