"""Canonical `knowledge_*` MCP schemas and lazy thin-host knowledge RPC dispatch.

[Role]
Defines `invoke_knowledge_tool` and re-exports `KNOWLEDGE_NAMES` /
`KNOWLEDGE_TOOL_SCHEMAS`—dispatching through `mindie_knowledge` loop APIs
(`Admission`, `domain_routes`, `ensure_service`, `rpc`, `distill.result_view`) in
the profile's configured `.venv` Python (via framed stdin/stdout IPC when it differs
from `sys.executable`, or in-process when already running inside that `.venv`).

[Invariants]
- Zero top-level `mindie_knowledge` import (`HAR-ABI` pure stdlib).
- Child fallback never passes JSON payloads on `sys.argv` and never prepends caller
  `repo_root` ahead of the target `.venv`'s `site-packages`.
- Public reads (`query`, `explain`) and unauthorized calls never create `admission.sqlite3`;
  `knowledge_distill` mints an on-demand scoped lease ONLY when `status == "missing"`
  and saved `CommunitySettings` + `project_roots` authorize `cwd` (revoked `inactive`
  sessions are never revived).
- Receipt Honesty: post-RPC local accounting failures (`Admission.finish` or
  `local_receipt_failed`) keep `isError=False` and attach `receipt_warning` +
  `receipt_unconfirmed=True`.

[Timeouts & Locks]
- `sync`/`distill` default to a `450s` inner budget (`510s` outer with `60s` grace);
  `query`/`explain`/`feedback` default to `35s` inner (`45s` outer with `10s` grace).
- Propagates `deadline.inner_remaining()` and `cancel` across `Admission`,
  `ensure_service`, `rpc`, and child IPC.

[Side-Effect Policy]
- Public reads do not create capture leases; lazy healing delegates to
  `ensure_knowledge_binding` only when `<host>.json` engine routes are missing/retired.
"""
from __future__ import annotations

import http.client
import json
import os
from pathlib import Path
import re
import sys
import threading
import urllib.error
from typing import Any, Mapping

from ..atomic import read_json_safe
from ..paths import HarnessError, ProfileRef, same_interpreter
from ..process.supervisor import Deadline, ProcessSpec, run_owned
from ..runtime.knowledge_binding import (
    DEFAULT_DOMAIN,
    _resolve_redactor,
    _resolve_transcript_adapter,
    ensure_knowledge_binding,
)
from .knowledge_schemas import KNOWLEDGE_NAMES, KNOWLEDGE_TOOL_SCHEMAS
from .receipts import apply_receipt_honesty

FRAME_PREFIX = "MINDIE_KRPC_JSON:"
SYNC_DISTILL_INNER_SECONDS = 450.0
READ_FEEDBACK_INNER_SECONDS = 35.0
SYNC_DISTILL_GRACE_SECONDS = 60.0
READ_FEEDBACK_GRACE_SECONDS = 10.0

_URI_DOMAIN_RE = re.compile(r"^mindie://([a-z][a-z0-9-]{0,63})/")
_LOCAL_REF_RE = re.compile(r"^(?:unit-[a-z0-9]+(?:-[a-z0-9]+)*(?:@[0-9]+)?|[0-9a-f]{16,64}(?:@[0-9a-f]{16,64})?)\Z")
_FEED_FAILURE_STATUSES: frozenset[str] = frozenset({"unavailable", "busy", "invalid", "failed", "error"})
_NOT_SENT_EXC_NAMES: frozenset[str] = frozenset(
    {"RequestRejected", "FeedUnavailableError", "MaterialReadError", "ReadReferenceError", "QueryContinuationError"}
)


def _error_result(
    reason: str,
    message: str,
    *,
    stage: str = "dispatch",
    submission_state: str = "not_sent",
    is_error: bool = True,
    extra: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    structured: dict[str, Any] = {
        "stage": stage,
        "reason": reason,
        "submission_state": submission_state,
        "retryable": False,
        "message": message,
        **(dict(extra) if extra else {}),
    }
    return {"content": [{"type": "text", "text": message}], "isError": bool(is_error), "structuredContent": structured}


def _normalize_result(value: Any) -> dict[str, Any]:
    if isinstance(value, Mapping) and isinstance(value.get("content"), list):
        result = dict(value)
        result.setdefault("isError", False)
        return result
    if isinstance(value, Mapping):
        payload = dict(value)
        text = json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str)
        return {"content": [{"type": "text", "text": text}], "isError": bool(payload.get("isError")), "structuredContent": payload}
    return {"content": [{"type": "text", "text": str(value)}], "isError": False}


def _validate_method_args(method: str, arguments: dict[str, Any]) -> dict[str, Any] | None:
    if any(str(key).startswith("_") for key in arguments):
        return _error_result("invalid_arguments", "Internal identity fields are not tool arguments.", stage="tool_schema")
    if method == "query":
        raw_q, raw_c = arguments.get("query"), arguments.get("continuation")
        if raw_q is not None and not isinstance(raw_q, str):
            return _error_result("invalid_arguments", "`query` must be a string.", stage="tool_schema")
        if raw_c is not None and not isinstance(raw_c, str):
            return _error_result("invalid_arguments", "`continuation` must be a string.", stage="tool_schema")
        if bool(isinstance(raw_q, str) and raw_q.strip()) == bool(isinstance(raw_c, str) and raw_c.strip()):
            return _error_result("invalid_arguments", "knowledge_query requires exactly one of non-empty `query` or `continuation`.", stage="tool_schema")
    elif method == "explain":
        raw_ref, raw_refs = arguments.get("ref"), arguments.get("refs")
        if raw_ref is not None and (not isinstance(raw_ref, str) or not raw_ref.strip()):
            return _error_result("invalid_arguments", "`ref` must be a non-empty string.", stage="tool_schema")
        if raw_refs is not None and (not isinstance(raw_refs, (list, tuple)) or any(not isinstance(item, str) or not item.strip() for item in raw_refs)):
            return _error_result("invalid_arguments", "`refs` must be an array of non-empty reference strings.", stage="tool_schema")
        if not raw_ref and not raw_refs:
            return _error_result("invalid_arguments", "knowledge_explain requires `ref` or a non-empty `refs` array.", stage="tool_schema")
    elif method == "feedback":
        raw_ref = arguments.get("ref")
        if not isinstance(raw_ref, str) or not raw_ref.strip():
            return _error_result("invalid_arguments", "`ref` is required for knowledge_feedback.", stage="tool_schema")
        rating, event_type = arguments.get("rating"), arguments.get("event_type")
        if rating is None and event_type is None:
            return _error_result("invalid_arguments", "knowledge_feedback requires `rating` or `event_type`.", stage="tool_schema")
        if rating is not None and rating not in {"up", "down"}:
            return _error_result("invalid_arguments", "`rating` must be `up` or `down`.", stage="tool_schema")
        if event_type is not None and event_type not in {"discovered", "loaded", "applied", "evaluated"}:
            return _error_result("invalid_arguments", "Invalid `event_type`.", stage="tool_schema")
        if event_type == "evaluated":
            if arguments.get("outcome") not in {"supported", "refuted", "inconclusive"}:
                return _error_result("invalid_arguments", "`outcome` (`supported`, `refuted`, or `inconclusive`) is required when `event_type` is `evaluated`.", stage="tool_schema")
            run_id = arguments.get("run_id")
            if not isinstance(run_id, str) or not run_id.strip():
                return _error_result("invalid_arguments", "`run_id` is required when `event_type` is `evaluated`.", stage="tool_schema")
    elif method == "distill":
        inputs, task_state = arguments.get("inputs"), arguments.get("task_state")
        if not isinstance(inputs, list) or any(not isinstance(item, Mapping) for item in inputs):
            return _error_result("invalid_arguments", "`inputs` must be an array of objects.", stage="tool_schema")
        if task_state not in {"in_flight", "verified_milestone", "completed"}:
            return _error_result("invalid_arguments", "Invalid `task_state`.", stage="tool_schema")
        rel = arguments.get("related_refs")
        if rel is not None and (not isinstance(rel, (list, tuple)) or any(not isinstance(item, str) or not item.strip() for item in rel)):
            return _error_result("invalid_arguments", "`related_refs` must be an array of non-empty strings.", stage="tool_schema")
    return None


def _collect_refs(arguments: Mapping[str, Any]) -> list[str]:
    out: list[str] = []
    single = arguments.get("ref")
    if isinstance(single, str) and single.strip():
        out.append(single.strip())
    for key in ("refs", "related_refs"):
        seq = arguments.get(key)
        if isinstance(seq, (list, tuple)):
            for item in seq:
                if isinstance(item, str) and item.strip():
                    out.append(item.strip())
    return out


def _routing_ref(ref_value: str) -> str | None:
    if _LOCAL_REF_RE.fullmatch(ref_value):
        return None
    return ref_value


def _requested_catalog_domain(arguments: Mapping[str, Any], refs: list[str]) -> str | None:
    dom = arguments.get("domain")
    if isinstance(dom, str) and dom.strip():
        return dom.strip()
    for item in refs:
        m = _URI_DOMAIN_RE.match(item)
        if m is not None:
            return m.group(1)
    return None


def _maybe_heal_binding(
    profile: Any,
    adapter: dict[str, Any],
    *,
    method: str,
    target_domain: str | None,
) -> dict[str, Any]:
    if not isinstance(profile, ProfileRef):
        return adapter
    try:
        from mindie_knowledge.loop import domain_catalog
        from mindie_knowledge.loop.cli import config_at
        from mindie_knowledge.loop.lifecycle import inspect_retirement
    except ImportError:
        return adapter

    raw_default = adapter.get("engine_config")
    default_path = Path(raw_default) if isinstance(raw_default, str) and raw_default.strip() else None
    routes = adapter.get("domain_configs") if isinstance(adapter.get("domain_configs"), Mapping) else {}

    need_provision = False
    include_default_feed = False
    retire_replaced = False

    if default_path is None or not default_path.is_file():
        need_provision = True
    else:
        try:
            if inspect_retirement(default_path) is not None:
                need_provision = True
            else:
                default_doc = config_at(default_path)
                if (
                    method == "sync"
                    and (target_domain is None or target_domain == DEFAULT_DOMAIN)
                    and default_doc.get("domain") == DEFAULT_DOMAIN
                    and default_doc.get("domain_catalog")
                    and not default_doc.get("feeds")
                ):
                    need_provision = True
                    include_default_feed = True
                    retire_replaced = True
                elif (
                    default_doc.get("capture_mode") == "disabled"
                    or Path(str(default_doc.get("transcript_adapter") or "")).name == "noop_transcript_adapter.py"
                ):
                    cand_adapter = _resolve_transcript_adapter(profile.host, profile.plugin_root, default_doc)
                    cand_red = Path(_resolve_redactor(profile, install_redactor=False))
                    if cand_adapter.name != "noop_transcript_adapter.py" and cand_red.is_file():
                        need_provision = True
                        retire_replaced = True
        except TimeoutError:
            raise
        except Exception:
            need_provision = True

    if (
        not need_provision
        and target_domain
        and target_domain != DEFAULT_DOMAIN
        and target_domain in domain_catalog.DOMAIN_CONFIGS
    ):
        cand_raw = routes.get(target_domain)
        cand_path = Path(cand_raw) if isinstance(cand_raw, str) and cand_raw.strip() else None
        if cand_path is None or not cand_path.is_file():
            need_provision = True
        else:
            try:
                if inspect_retirement(cand_path) is not None:
                    need_provision = True
            except TimeoutError:
                raise
            except Exception:
                need_provision = True

    if not need_provision:
        return adapter

    ensured = ensure_knowledge_binding(
        profile,
        python_executable=sys.executable,
        install_redactor=False,
        retire_previous=retire_replaced,
        include_default_feed=include_default_feed,
    )
    reloaded = read_json_safe(profile.config_path)
    if isinstance(reloaded, Mapping):
        return dict(reloaded)
    if ensured.get("status") == "configured" and isinstance(ensured.get("binding_fields"), Mapping):
        merged = dict(adapter)
        merged.update(ensured["binding_fields"])
        return merged
    return adapter


def _try_on_demand_distill_lease(
    admission: Any,
    selected_cfg: Mapping[str, Any],
    *,
    session_id: str,
    cwd: Path | None,
    work_deadline: float | None,
) -> dict[str, Any] | None:
    if cwd is None:
        return None
    comm_raw = selected_cfg.get("community_config")
    if not isinstance(comm_raw, str) or not comm_raw.strip():
        return None
    try:
        from mindie_knowledge.loop.settings import load as load_community_settings
    except ImportError:
        return None

    inspected = (
        admission.inspect(session_id, deadline=work_deadline)
        if work_deadline is not None
        else admission.inspect(session_id)
    )
    if not isinstance(inspected, Mapping) or inspected.get("status") != "missing":
        return None

    settings = load_community_settings(comm_raw)
    if not settings.allows_capture():
        return None
    resolved_cwd = str(Path(cwd).expanduser().resolve(strict=False))
    if not settings.in_scope(resolved_cwd):
        return None

    matched_root = resolved_cwd
    for root in settings.project_roots:
        if isinstance(root, str) and settings.in_scope(resolved_cwd):
            try:
                c_norm = os.path.normcase(resolved_cwd)
                r_norm = os.path.normcase(str(Path(root).expanduser().resolve(strict=False)))
                if os.path.splitdrive(c_norm)[0] == os.path.splitdrive(r_norm)[0] and os.path.commonpath(
                    (c_norm, r_norm)
                ) == r_norm:
                    matched_root = root
                    break
            except ValueError:
                continue

    return admission.activate(
        session_id,
        project_root=matched_root,
        root_session=session_id,
        not_before=0.0,
    )


def _classify_rpc_exception(exc: BaseException, *, stage: str, submitted: bool) -> dict[str, Any]:
    exc_name = type(exc).__name__
    extra: dict[str, Any] = {}
    err_attrs = vars(exc) if hasattr(exc, "__dict__") else {}
    if isinstance(err_attrs.get("error_code"), str):
        extra["error_code"] = err_attrs["error_code"]
    if err_attrs.get("read_ref") is not None:
        extra["read_ref"] = err_attrs["read_ref"]

    if exc_name in _NOT_SENT_EXC_NAMES or isinstance(exc, ConnectionRefusedError):
        state = "not_sent"
    elif isinstance(exc, urllib.error.URLError) and isinstance(exc.reason, ConnectionRefusedError):
        state = "not_sent"
    elif submitted and isinstance(
        exc, (OSError, EOFError, http.client.HTTPException, urllib.error.URLError)
    ):
        state = "uncertain"
    else:
        state = "sent" if submitted else "not_sent"

    reason = (
        str(extra["error_code"])
        if exc_name == "FeedUnavailableError" and "error_code" in extra
        else ("feed_unavailable" if exc_name == "FeedUnavailableError" else f"knowledge_{stage}_failed")
    )
    return _error_result(
        reason,
        f"{exc_name}: {exc}",
        stage=stage,
        submission_state=state,
        extra=extra,
    )


def _try_in_process(
    operation: str,
    arguments: dict[str, Any],
    *,
    profile: Any,
    session_id: str,
    cwd: Path | None,
    deadline: Deadline | None = None,
) -> dict[str, Any] | None:
    try:
        from mindie_knowledge.loop.activation import Admission
        from mindie_knowledge.loop.cli import config_at, ensure_service
        from mindie_knowledge.loop.domain_routes import select_engine_config
        from mindie_knowledge.loop.transport import rpc
    except ModuleNotFoundError as exc:
        if exc.name and exc.name.startswith("mindie_knowledge"):
            return None
        return _error_result("knowledge_import_failed", f"Knowledge import failed ({exc}).")
    except ImportError as exc:
        return _error_result("knowledge_import_failed", f"Knowledge import failed ({exc}).")

    if not isinstance(session_id, str) or not session_id.strip():
        return _error_result("knowledge_identity_missing", "A host session identity is required.")
    method = operation.removeprefix("knowledge_")
    validation_error = _validate_method_args(method, arguments)
    if validation_error is not None:
        return validation_error
    if deadline is not None:
        deadline.require_remaining()
        if deadline.inner_remaining() <= 0:
            raise TimeoutError("Knowledge RPC budget exhausted before dispatch")

    stage = "config"
    submitted = False
    admission = None
    lease = None
    try:
        raw_adapter = read_json_safe(profile.config_path)
        adapter = dict(raw_adapter) if isinstance(raw_adapter, Mapping) else {}
        refs = _collect_refs(arguments)
        target_dom = _requested_catalog_domain(arguments, refs)
        adapter = _maybe_heal_binding(profile, adapter, method=method, target_domain=target_dom)

        default = Path(
            adapter.get("engine_config")
            or Path(profile.config_path).with_name(Path(profile.config_path).stem + ".engine.json")
        )
        routes = dict(adapter.get("domain_configs") or {})
        try:
            engine = config_at(default)
            routes[engine["domain"]] = str(default.resolve())
        except TimeoutError:
            raise
        except Exception:
            if not (target_dom and target_dom in routes):
                raise

        if refs:
            selected = select_engine_config(
                default,
                domain=arguments.get("domain"),
                ref=_routing_ref(refs[0]),
                domain_configs=routes,
            )
            for extra_ref in refs[1:]:
                if (
                    select_engine_config(
                        default,
                        domain=arguments.get("domain"),
                        ref=_routing_ref(extra_ref),
                        domain_configs=routes,
                    )
                    != selected
                ):
                    raise ValueError("references select different knowledge domains")
        else:
            selected = select_engine_config(
                default,
                domain=arguments.get("domain"),
                ref=None,
                domain_configs=routes,
            )

        payload = dict(arguments)
        payload.pop("domain", None)
        if method == "query":
            payload.pop("known_refs", None)
        if method in {"query", "explain", "feedback", "distill"}:
            payload["_session_id"] = session_id

        if method == "distill":
            stage = "authorization"
            work_deadline: float | None = None
            if deadline is not None:
                rem = deadline.inner_remaining()
                if rem <= 0:
                    raise TimeoutError("Knowledge authorization budget exhausted before dispatch")
                work_deadline = deadline.expires_at - deadline.cleanup_grace
            selected_cfg = config_at(selected)
            admission = Admission(selected_cfg["admission_path"])
            lease = (
                admission.active_lease(session_id, deadline=work_deadline)
                if work_deadline is not None
                else admission.active_lease(session_id)
            )
            if not lease or not lease.get("token") or not lease.get("entry_enabled"):
                lease = _try_on_demand_distill_lease(
                    admission,
                    selected_cfg,
                    session_id=session_id,
                    cwd=cwd,
                    work_deadline=work_deadline,
                )
            if not lease or not lease.get("token") or not lease.get("entry_enabled"):
                return _error_result(
                    "knowledge_authorization_required",
                    "Distillation requires existing scoped capture authorization.",
                    stage="authorization",
                )
            payload["_activation"] = lease["token"]
        elif method in {"query", "explain", "feedback"}:
            payload["_session_verified"] = True

        stage = "service"
        if deadline is not None:
            deadline.require_remaining()
            if deadline.inner_remaining() <= 0:
                raise TimeoutError("Knowledge service startup budget exhausted before dispatch")
        connection = ensure_service(selected)

        stage = "rpc"
        timeout = (
            SYNC_DISTILL_INNER_SECONDS
            if method in {"sync", "distill"}
            else READ_FEEDBACK_INNER_SECONDS
        )
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
        return _classify_rpc_exception(exc, stage=stage, submitted=submitted)

    if method == "distill":
        from mindie_knowledge.graded.distill import result_view

        raw_view, is_error = result_view(raw)
        result = _normalize_result(raw_view)
        result["isError"] = is_error
        if (
            not is_error
            and isinstance(raw_view, Mapping)
            and raw_view.get("status") in {"local_receipt_failed", "local_application_failed"}
        ):
            result["receipt_unconfirmed"] = True
            result.setdefault(
                "receipt_warning",
                str(raw_view.get("receipt_error") or raw_view.get("status")),
            )
    elif (
        method == "sync"
        and isinstance(raw, list)
        and len(raw) > 0
        and all(
            isinstance(item, Mapping) and str(item.get("status") or "") in _FEED_FAILURE_STATUSES
            for item in raw
        )
    ):
        retryable = any(bool(item.get("retryable")) for item in raw if isinstance(item, Mapping))
        summary_payload = {
            "results": raw,
            "stage": "sync",
            "reason": "knowledge_sync_failed",
            "submission_state": "sent",
            "retryable": retryable,
        }
        result = {
            "content": [
                {
                    "type": "text",
                    "text": json.dumps(summary_payload, ensure_ascii=False, sort_keys=True, default=str),
                }
            ],
            "isError": True,
            "structuredContent": summary_payload,
        }
    else:
        result = _normalize_result(raw if isinstance(raw, Mapping) else {"results": raw})

    if admission is not None and lease is not None:
        try:
            admission.finish(session_id, lease["token"], not result["isError"])
        except Exception as exc:
            if result["isError"] is not True:
                result = apply_receipt_honesty(result, exc)
    return result


def _venv_has_harness(python_exe: Path) -> bool:
    venv_root = python_exe.parent.parent
    candidates = [venv_root / "Lib" / "site-packages"]
    lib_dir = venv_root / "lib"
    if lib_dir.is_dir():
        candidates.extend(lib_dir.glob("python*/site-packages"))
    return any((site / "mindie_harness" / "mcp" / "knowledge_rpc.py").is_file() for site in candidates if site.is_dir())


def _invoke_via_python(
    operation: str,
    arguments: dict[str, Any],
    *,
    profile: ProfileRef,
    session_id: str,
    cwd: Path | None,
    deadline: Deadline | None = None,
    cancel: threading.Event | None = None,
) -> dict[str, Any]:
    if os.environ.get("MINDIE_KNOWLEDGE_FALLBACK") == "1":
        return _error_result(
            "knowledge_unavailable",
            "mindie_knowledge RPC is unavailable in this interpreter; refusing recursive fallback.",
        )
    cfg = read_json_safe(profile.config_path)
    python_raw = cfg.get("python") if isinstance(cfg, Mapping) else None
    python = Path(python_raw) if isinstance(python_raw, str) and python_raw.strip() else None
    if python is None or not python.is_file():
        return _error_result(
            "knowledge_unavailable",
            "mindie_knowledge is unavailable in this interpreter and no validated profile Python is configured.",
        )

    is_heavy = operation in {"knowledge_sync", "knowledge_distill"}
    default_inner = SYNC_DISTILL_INNER_SECONDS if is_heavy else READ_FEEDBACK_INNER_SECONDS
    default_grace = SYNC_DISTILL_GRACE_SECONDS if is_heavy else READ_FEEDBACK_GRACE_SECONDS
    eff_deadline = (
        deadline
        if deadline is not None
        else Deadline.from_budgets([default_inner], cleanup_grace=default_grace)
    )
    rem_inner = eff_deadline.inner_remaining()
    if rem_inner <= 0:
        raise TimeoutError("Knowledge child fallback budget exhausted before dispatch")

    req_payload = {
        "operation": operation,
        "arguments": arguments,
        "host": profile.host,
        "plugin_root": str(profile.plugin_root),
        "config_path": str(profile.config_path),
        "data_dir": str(profile.data_dir),
        "session_id": session_id,
        "cwd": str(cwd) if cwd is not None else None,
        "timeout_sec": rem_inner,
    }
    env = dict(profile_env(profile, session_id), MINDIE_KNOWLEDGE_FALLBACK="1")
    if _venv_has_harness(python):
        argv: tuple[str, ...] = (
            str(python),
            "-I",
            "-X",
            "utf8",
            "-m",
            "mindie_harness.mcp.knowledge_rpc",
        )
    else:
        # Legacy/test venv without mindie_harness installed: append caller root LAST
        # so child .venv site-packages always takes precedence over caller files.
        caller_root = str(Path(__file__).resolve().parents[2])
        argv = (
            str(python),
            "-I",
            "-X",
            "utf8",
            "-c",
            "import runpy,sys; sys.path.append(sys.argv.pop(1)); runpy.run_module('mindie_harness.mcp.knowledge_rpc', run_name='__main__')",
            caller_root,
        )

    try:
        outcome = run_owned(
            ProcessSpec(
                argv=argv,
                env=env,
                stdin_bytes=(json.dumps(req_payload, ensure_ascii=True, sort_keys=True) + "\n").encode("utf-8"),
                role="foreground",
                allowed_returncodes=None,
            ),
            deadline=eff_deadline,
            cancel=cancel,
        )
    except TimeoutError:
        raise
    except OSError as exc:
        return _error_result(
            "knowledge_unavailable",
            f"Could not start knowledge fallback ({type(exc).__name__}).",
        )

    stdout_text = outcome.stdout or ""
    for line in reversed(stdout_text.splitlines()):
        if line.startswith(FRAME_PREFIX):
            try:
                parsed = json.loads(line[len(FRAME_PREFIX) :])
            except ValueError:
                break
            if isinstance(parsed, Mapping) and parsed:
                return _normalize_result(parsed)
    if outcome.returncode != 0:
        detail = (outcome.stderr or stdout_text).strip()[:512]
        return _error_result(
            "knowledge_failed",
            f"knowledge fallback exited {outcome.returncode}: {detail}",
        )
    return _error_result(
        "knowledge_invalid_result",
        "knowledge fallback exited without a valid framed JSON result.",
    )


def profile_env(profile: ProfileRef, session_id: str) -> dict[str, str]:
    return {
        "MINDIE_AGENT_CONFIG": str(profile.config_path),
        "MINDIE_SESSION_ID": session_id,
        "MINDIE_CONFIG_HOME": str(profile.config_path.parent),
        "MINDIE_DATA_HOME": str(profile.data_dir),
    }


def invoke_knowledge_tool(
    operation: str,
    arguments: Mapping[str, Any] | None,
    *,
    profile: ProfileRef,
    session_id: str,
    cwd: Path | None = None,
    deadline: Deadline | None = None,
    cancel: threading.Event | None = None,
) -> dict[str, Any]:
    """Dispatch one canonical knowledge operation in `cfg['python']` or in-process."""
    name = str(operation or "").strip()
    if name not in KNOWLEDGE_NAMES:
        return _error_result("unknown_operation", f"Unknown knowledge operation {name!r}.")
    if arguments is None:
        args: dict[str, Any] = {}
    elif isinstance(arguments, Mapping):
        args = dict(arguments)
    else:
        return _error_result("invalid_arguments", "Knowledge tool arguments must be a JSON object.")

    if isinstance(profile, ProfileRef) and os.environ.get("MINDIE_KNOWLEDGE_FALLBACK") != "1":
        cfg = read_json_safe(profile.config_path)
        py_raw = cfg.get("python") if isinstance(cfg, Mapping) else None
        if (
            isinstance(py_raw, str)
            and py_raw.strip()
            and Path(py_raw).is_file()
            and not same_interpreter(py_raw, sys.executable)
        ):
            return _invoke_via_python(
                name,
                args,
                profile=profile,
                session_id=session_id,
                cwd=cwd,
                deadline=deadline,
                cancel=cancel,
            )

    try:
        in_process = _try_in_process(
            name,
            args,
            profile=profile,
            session_id=session_id,
            cwd=cwd,
            deadline=deadline,
        )
    except HarnessError as exc:
        return _error_result(exc.reason, str(exc), stage=exc.stage, submission_state=exc.submission_state)
    if in_process is not None:
        return in_process
    return _invoke_via_python(
        name,
        args,
        profile=profile,
        session_id=session_id,
        cwd=cwd,
        deadline=deadline,
        cancel=cancel,
    )


def _cli_main() -> int:
    raw = sys.stdin.buffer.read(8 * 1024 * 1024)
    req = json.loads(raw.decode("utf-8-sig"))
    profile = ProfileRef.resolve(
        str(req["host"]),
        plugin_root=req.get("plugin_root"),
        config_path=req.get("config_path"),
        data_dir=req.get("data_dir"),
    )
    cwd_raw = req.get("cwd")
    total = max(1.0, float(req.get("timeout_sec") or READ_FEEDBACK_INNER_SECONDS))
    grace = min(5.0, max(0.5, total * 0.05))
    child_deadline = Deadline.from_timeout(total + grace, cleanup_grace=grace)
    res = invoke_knowledge_tool(
        str(req["operation"]),
        req.get("arguments") or {},
        profile=profile,
        session_id=str(req["session_id"]),
        cwd=Path(cwd_raw) if isinstance(cwd_raw, str) and cwd_raw else None,
        deadline=child_deadline,
    )
    sys.stdout.buffer.write((FRAME_PREFIX + json.dumps(res, ensure_ascii=True) + "\n").encode("utf-8"))
    sys.stdout.buffer.flush()
    return 0


__all__ = ["KNOWLEDGE_NAMES", "KNOWLEDGE_TOOL_SCHEMAS", "invoke_knowledge_tool", "profile_env"]

if __name__ == "__main__":
    raise SystemExit(_cli_main())
