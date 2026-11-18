"""Silent default-on & `P2.7`/`P2.8` zero-binding MCP router across all MindIE surfaces.

[Role]
Validates MCP `tools/call` envelopes, rejects forged-identity arguments, exposes
all registered tools across `remote`, `tools`, `components`, `knowledge`, and `all`
with ZERO pre-call session-binding or manual admission gates (`P2.7` / `P2.8`),
and preserves Receipt Honesty when local accounting fails after primary success.

[Invariants]
- Never mutates global `os.environ` or `os.chdir()`; every call builds an isolated
  `RequestContext` (`session_id`, `cwd`, `env`, `deadline`, `cancel`).
- Read-only / status / cancel tools (`is_readonly_or_control_tool`, including
  `mindie_doctor`, `mindie_status`, `knowledge_query`, `knowledge_explain`, and the
  case-accurate native read/poll/control names across all 7 host harnesses) have ZERO
  artificial concurrency cap (`AD-09` fixed) and zero replay-ledger lock contention.
- `remote_auth` is action-aware: `{"action": "status"}` is read-only, while `setup`
  and `forget` remain mutation-accounted so SSH state changes get receipts.
- All tools uniformly strip legacy optional `_mindie_bind_id`, `request_nonce`, and
  `context_file` from `inputSchema["required"]` and incoming arguments, falling back
  to `{host}-conn-{connection_id[:12]}` when host session metadata is absent.

[Timeouts & Locks]
- Enforces Principle 10 per-tool budgets (`remote_bash` `660s = 600s + 60s`,
  `remote_write_stdin` `360s = 300s + 60s`, `mindie_doctor` `10s/15s + grace`,
  `components` `130s..660s`, `knowledge` `45s = 35s + 10s` / `120s = 110s + 10s`).

[Side-Effect Policy]
- Dispatches validated tool invocations through the bound `HostAdapter` or handler map
  and records idempotent mutation receipts in `RemoteReceipts`.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import math
import os
from pathlib import Path
import sqlite3
import threading
from typing import Any, Callable, Mapping
import uuid

from ..paths import HarnessError, ProfileRef
from ..process.supervisor import Deadline, ProcessCancelledError
from ..rsi import rsi_explore
from .doctor import DOCTOR_TOOL_NAME, doctor_tool_definition, run_doctor_tool
from .receipts import BindStore, RemoteReceipts, apply_receipt_honesty

FORGED_IDENTITY_KEYS: frozenset[str] = frozenset(
    {
        "session",
        "session_id",
        "conversation_id",
        "mindie_activation",
        "token",
        "project_root",
    }
)
CORRELATION_STRIP_KEYS: frozenset[str] = frozenset(
    {"_mindie_bind_id", "request_nonce", "context_file"}
)

REMOTE_NATIVE_MAX_WAIT_MS: dict[str, int] = {
    "remote_bash": 600_000,
    "remote_Bash": 600_000,
    "remote_run_command": 600_000,
    "remote_write_stdin": 300_000,
    "remote_job_stdin": 300_000,
    "remote_manage_task": 300_000,
    "remote_TaskOutput": 600_000,
    "remote_exec_command": 30_000,
}
REMOTE_GRACE_SECONDS = 60.0
REMOTE_MIN_BUDGET_SECONDS = 180.0

DOCTOR_LOCAL_OUTER_SECONDS = 10.0
DOCTOR_PROBE_OUTER_SECONDS = 20.0
DOCTOR_CLEANUP_GRACE_SECONDS = 5.0

READONLY_TOOL_PREFIXES: tuple[str, ...] = (
    "remote_read",
    "remote_cat",
    "remote_grep",
    "remote_glob",
    "remote_find",
    "remote_stat",
    "remote_list",
    "remote_ls",
    "remote_job_status",
    "remote_job_output",
    "remote_job_poll",
    "remote_job_list",
    "remote_job_cancel",
    "remote_cancel",
    "remote_ping",
    "remote_hosts",
    # Case-accurate Codex / Kimi / DSH native read, poll, and task-control tools.
    "remote_Read",
    "remote_Glob",
    "remote_Grep",
    "remote_TaskOutput",
    "remote_TaskList",
    "remote_TaskStop",
    "remote_ViewImage",
    "remote_ReadMediaFile",
    # Antigravity / OpenCode native read, image, and probe tools (`remote_manage_task`
    # is classified by `Action` in `is_readonly_tool_call` so `send_input` stays receipted).
    "remote_view_image",
    "remote_probe",
    # Antigravity native read-only file and search tools.
    "remote_read_file",
    "remote_find_by_name",
    "remote_grep_search",
    "remote_list_dir",
    # Diagnostics and harness status/control tools stay on the lock-free lane.
    "mindie_status",
    "mindie_doctor",
    "mindie_interrupt",
    "npu_top",
    "diagnostics_status",
    "debugger_triage",
    "knowledge_query",
    "knowledge_explain",
)

REMOTE_AUTH_READONLY_ACTIONS: frozenset[str] = frozenset({"status"})
REMOTE_MANAGE_TASK_READONLY_ACTIONS: frozenset[str] = frozenset({"list", "status", "kill", "stop"})


@dataclass(frozen=True)
class RequestContext:
    """Per-request isolated execution context (zero global `os.environ`/`cwd` mutation)."""

    request_id: str | int
    surface: str
    tool_name: str
    session_id: str
    cwd: Path | None
    env: dict[str, str]
    deadline: Deadline
    cancel: threading.Event


def is_readonly_or_control_tool(name: str, tool_schema: Mapping[str, Any] | None = None) -> bool:
    """Return True when `name` is a read-only query, status poll, or cancellation tool."""
    clean = str(name or "").strip()
    if clean.startswith(READONLY_TOOL_PREFIXES):
        return True
    if isinstance(tool_schema, Mapping):
        annotations = tool_schema.get("annotations")
        if isinstance(annotations, Mapping) and annotations.get("readOnlyHint") is True:
            return True
    return False


def is_readonly_tool_call(
    name: str,
    arguments: Mapping[str, Any] | None = None,
    tool_schema: Mapping[str, Any] | None = None,
) -> bool:
    """Classify a call as read-only/control, evaluating action-multiplexed tools first."""
    clean = str(name or "").strip()
    args = arguments if isinstance(arguments, Mapping) else {}
    if clean == "remote_auth":
        action = str(args.get("action") or "").strip().lower()
        return action in REMOTE_AUTH_READONLY_ACTIONS
    if clean == "remote_manage_task":
        raw_action = args.get("Action") if "Action" in args else args.get("action")
        action = str(raw_action or "").strip().lower()
        return action in REMOTE_MANAGE_TASK_READONLY_ACTIONS
    return is_readonly_or_control_tool(clean, tool_schema)


def compute_tool_deadline(
    surface: str,
    tool_name: str,
    arguments: Mapping[str, Any] | None = None,
    *,
    explicit_timeout: float | None = None,
) -> Deadline:
    """Compute Principle-10 outer `Deadline` (`outer >= inner + cleanup_grace`)."""
    args = arguments or {}

    # Local diagnostics doctor: 5s inner local budget, +5s for an optional remote probe,
    # plus cleanup grace. Read-only and lock-free, but still bounded end-to-end.
    if tool_name == DOCTOR_TOOL_NAME:
        probe_remote = args.get("probe_remote") is True
        inner_sec = DOCTOR_PROBE_OUTER_SECONDS if probe_remote else DOCTOR_LOCAL_OUTER_SECONDS
        outer = inner_sec + DOCTOR_CLEANUP_GRACE_SECONDS
        if explicit_timeout is not None and float(explicit_timeout) > outer:
            outer = float(explicit_timeout)
        return Deadline.from_timeout(outer, cleanup_grace=DOCTOR_CLEANUP_GRACE_SECONDS)

    if surface == "remote" or tool_name.startswith("remote_"):
        native_ms = float(REMOTE_NATIVE_MAX_WAIT_MS.get(tool_name, 0))
        caller_ms = 0.0
        for k in ("yield_time_ms", "timeout_ms", "WaitMsBeforeAsync", "timeout"):
            val = args.get(k)
            if not isinstance(val, bool) and isinstance(val, (int, float)) and math.isfinite(val) and val > 0:
                caller_ms = max(caller_ms, float(val))
        inner_sec = max(native_ms / 1000.0, caller_ms / 1000.0)
        outer = max(REMOTE_MIN_BUDGET_SECONDS, inner_sec + REMOTE_GRACE_SECONDS)
        if explicit_timeout is not None and explicit_timeout > outer:
            outer = float(explicit_timeout)
        return Deadline.from_timeout(outer, cleanup_grace=REMOTE_GRACE_SECONDS)

    if surface == "knowledge" or tool_name.startswith("knowledge_"):
        inner_sec = 110.0 if tool_name in {"knowledge_sync", "knowledge_distill"} else 35.0
        grace = 10.0
        required = inner_sec + grace
        if explicit_timeout is not None:
            if float(explicit_timeout) < required:
                raise HarnessError(
                    f"{tool_name} timeout ({explicit_timeout}s) is shorter than inner+grace ({required}s)",
                    stage="tool_schema",
                    reason="invalid_timeout_budget",
                    reportable=False,
                )
            return Deadline.from_timeout(float(explicit_timeout), cleanup_grace=grace)
        return Deadline.from_timeout(required, cleanup_grace=grace)

    # Deterministic component tools (coordinator, debugger, profiler, sim, npu-top, diagnostics)
    caller_ms = args.get("timeout_ms")
    caller_sec = (
        float(caller_ms) / 1000.0
        if not isinstance(caller_ms, bool)
        and isinstance(caller_ms, (int, float))
        and math.isfinite(caller_ms)
        and caller_ms > 0
        else 120.0
    )
    inner_sec = max(120.0, min(600.0, caller_sec))
    grace = 60.0 if inner_sec > 120.0 else 10.0
    outer = max(inner_sec + grace, float(explicit_timeout or 0.0))
    return Deadline.from_timeout(outer, cleanup_grace=grace)


def _extract_meta_session(request: Mapping[str, Any], env: Mapping[str, str]) -> str | None:
    params = request.get("params")
    meta = params.get("_meta") if isinstance(params, Mapping) else None
    if isinstance(meta, Mapping):
        for key in ("session_id", "sessionId", "threadId", "conversationId", "claudecode/sessionId"):
            val = meta.get(key)
            if isinstance(val, str) and val.strip():
                return val.strip()
    for env_key in (
        "MINDIE_SESSION_ID",
        "REMOTE_DEV_SESSION_ID",
        "CODEX_THREAD_ID",
        "KIMI_SESSION_ID",
        "OPENCODE_SESSION_ID",
        "CLAUDE_SESSION_ID",
    ):
        val = env.get(env_key)
        if isinstance(val, str) and val.strip():
            return val.strip()
    return None


def _extract_meta_bind_id(request: Mapping[str, Any]) -> str | None:
    params = request.get("params")
    meta = params.get("_meta") if isinstance(params, Mapping) else None
    if isinstance(meta, Mapping):
        for key in ("claudecode/toolUseId", "toolUseId", "bind_id", "_mindie_bind_id"):
            val = meta.get(key)
            if isinstance(val, str) and val.strip():
                return val.strip()
    return None


def _normalize_tool_def(tool: Mapping[str, Any]) -> dict[str, Any]:
    """Normalize a tool definition once, stripping `CORRELATION_STRIP_KEYS` from `properties` and `required`."""
    cleaned = dict(tool)
    schema = cleaned.get("inputSchema")
    if isinstance(schema, Mapping):
        norm_schema = dict(schema)
        props = schema.get("properties")
        if isinstance(props, Mapping):
            norm_schema["properties"] = {
                k: v for k, v in props.items() if k not in CORRELATION_STRIP_KEYS
            }
        req = schema.get("required")
        if isinstance(req, (list, tuple)):
            norm_schema["required"] = [
                r for r in req if r not in CORRELATION_STRIP_KEYS
            ]
        cleaned["inputSchema"] = norm_schema
    return cleaned


def _format_mcp_error(exc: BaseException, *, handler_started: bool = False) -> dict[str, Any]:
    if isinstance(exc, HarnessError):
        info = exc.to_dict()
        return {
            "content": [{"type": "text", "text": f"{exc} (reason={exc.reason}). No automatic retry."}],
            "isError": True,
            "structuredContent": info,
        }
    if isinstance(exc, TimeoutError):
        if handler_started:
            return {
                "content": [
                    {
                        "type": "text",
                        "text": "MindIE request deadline exceeded; external outcome may be unconfirmed. Inspect state before retrying.",
                    }
                ],
                "isError": True,
                "structuredContent": {
                    "stage": "timeout",
                    "reason": "helper_timeout",
                    "submission_state": "uncertain",
                    "retryable": False,
                },
            }
        return {
            "content": [
                {
                    "type": "text",
                    "text": "MindIE request timed out before tool dispatch; operation was not sent.",
                }
            ],
            "isError": True,
            "structuredContent": {
                "stage": "timeout",
                "reason": "helper_timeout",
                "submission_state": "not_sent",
                "retryable": False,
            },
        }
    return {
        "content": [{"type": "text", "text": f"MindIE tool execution failed ({type(exc).__name__})."}],
        "isError": True,
        "structuredContent": {
            "stage": "dispatch",
            "reason": "internal_error",
            "error_type": type(exc).__name__,
            "retryable": False,
        },
    }


ToolHandler = Callable[[RequestContext, dict[str, Any]], dict[str, Any]]


class MCPRouter:
    """Thread-safe MCP `tools/list` and `tools/call` router for one resident connection."""

    def __init__(
        self,
        profile: ProfileRef,
        *,
        surface: str = "all",
        tools: list[dict[str, Any]] | None = None,
        handler: ToolHandler | None = None,
        session_extractor: Callable[[Mapping[str, Any], Mapping[str, str]], str | None] | None = None,
        base_env: Mapping[str, str] | None = None,
    ) -> None:
        self.profile = profile
        self.surface = surface
        self.connection_id = uuid.uuid4().hex
        self._base_env = dict(os.environ if base_env is None else base_env)
        raw_tools = self._default_tools() if tools is None else list(tools)
        self._tools = [
            _normalize_tool_def(t) for t in raw_tools if isinstance(t, Mapping) and "name" in t
        ]
        self._tool_map = {str(t["name"]): t for t in self._tools}
        self._handler = handler
        self._session_extractor = session_extractor
        self.receipts = RemoteReceipts(profile.receipts_db)
        self.binds = BindStore(profile.binds_db)

    def _default_tools(self) -> list[dict[str, Any]]:
        status_tool = {
            "name": "mindie_status",
            "description": "Read active MindIE Harness runtime and profile health (read-only, zero binding required).",
            "annotations": {"readOnlyHint": True},
            "inputSchema": {
                "type": "object",
                "properties": {},
                "required": [],
            },
        }
        return [status_tool, doctor_tool_definition()]

    def list_tools(self) -> list[dict[str, Any]]:
        """Return normalized registered tools for `self.surface`."""
        return [dict(tool) for tool in self._tools]

    def is_fast_lane_call(self, request: Mapping[str, Any]) -> bool:
        params = request.get("params")
        if not isinstance(params, Mapping):
            return True
        name = str(params.get("name") or "")
        arguments = params.get("arguments")
        if not isinstance(arguments, Mapping):
            arguments = {}
        return is_readonly_tool_call(name, arguments, self._tool_map.get(name))

    def _validate_and_clean_args(self, name: str, raw_args: Any) -> dict[str, Any]:
        if raw_args is None:
            raw_args = {}
        if not isinstance(raw_args, Mapping):
            raise HarnessError(
                "MCP tool arguments must be a JSON object",
                stage="tool_schema",
                reason="input_not_object",
                reportable=False,
            )
        forged = FORGED_IDENTITY_KEYS.intersection(raw_args.keys())
        if forged:
            raise HarnessError(
                "Model-supplied identity override arguments are forbidden",
                stage="tool_schema",
                reason="forged_identity_argument",
                reportable=False,
            )
        args = dict(raw_args)
        for key in CORRELATION_STRIP_KEYS:
            args.pop(key, None)

        tool_def = self._tool_map.get(name)
        if tool_def is None:
            raise HarnessError(
                f"Unknown MindIE MCP tool: {name!r}",
                stage="tool_schema",
                reason="unknown_operation",
                reportable=False,
            )
        schema = tool_def.get("inputSchema")
        if isinstance(schema, Mapping):
            props = schema.get("properties")
            req = list(schema.get("required") or ())
            missing = [r for r in req if r not in args]
            if missing:
                raise HarnessError(
                    f"Missing required argument `{missing[0]}` for {name}",
                    stage="tool_schema",
                    reason="schema_missing_field",
                    reportable=False,
                    details={"field": missing[0]},
                )
            if isinstance(props, Mapping) and schema.get("additionalProperties") is False:
                unknown = set(args) - set(props)
                if unknown:
                    raise HarnessError(
                        f"Undeclared arguments supplied to {name}",
                        stage="tool_schema",
                        reason="schema_unknown_field",
                        reportable=False,
                    )

        if name in {"knowledge_query", "knowledge_explain"}:
            try:
                args = rsi_explore.parse_args(args)
            except ValueError as exc:
                raise HarnessError(
                    str(exc),
                    stage="tool_schema",
                    reason="invalid_rsi_arguments",
                    reportable=False,
                ) from exc
        return args

    def call_tool(
        self,
        request: Mapping[str, Any],
        *,
        cancel: threading.Event | None = None,
        timeout: float | None = None,
    ) -> dict[str, Any]:
        """Validate, execute, and finalize one MCP `tools/call` request across any surface."""
        cancel_ev = cancel or threading.Event()
        req_id = request.get("id", "0")
        params = request.get("params")
        if not isinstance(params, Mapping):
            return _format_mcp_error(
                HarnessError("Missing params object", stage="cli_input", reason="input_not_object", reportable=False)
            )
        name = str(params.get("name") or "")
        claimed_call_id: str | None = None
        claimed_bind_id: str | None = None
        handler_started = False
        primary_succeeded = False
        outcome_label = "unknown"
        result: dict[str, Any] | None = None

        try:
            args = self._validate_and_clean_args(name, params.get("arguments"))
            deadline = compute_tool_deadline(self.surface, name, args, explicit_timeout=timeout)
            args_digest = hashlib.sha256(json.dumps(args, sort_keys=True).encode("utf-8")).hexdigest()

            extracted_session = (
                self._session_extractor(request, self._base_env)
                if self._session_extractor is not None
                else None
            ) or _extract_meta_session(request, self._base_env)
            effective_bind_id = _extract_meta_bind_id(request)

            bound_cwd: Path | None = None
            bind_row: dict[str, Any] | None = None
            if effective_bind_id is not None or extracted_session is not None:
                try:
                    bind_row = self.binds.claim_bind(
                        bind_id=effective_bind_id,
                        session=extracted_session,
                        tool=name,
                        args_digest=args_digest,
                        deadline=deadline.expires_at,
                    )
                except TimeoutError:
                    raise
                except (sqlite3.Error, OSError):
                    bind_row = None

            if bind_row is not None:
                claimed_bind_id = bind_row["bind_id"]
                extracted_session = extracted_session or bind_row["session"]
                if bind_row.get("cwd"):
                    bound_cwd = Path(bind_row["cwd"])

            # Iron Rule 5 (P2.7 / P2.8): zero pre-call session binding across all surfaces!
            session_id = extracted_session or f"{self.profile.host}-conn-{self.connection_id[:12]}"

            readonly = is_readonly_tool_call(name, args, self._tool_map.get(name))
            if not readonly:
                req_hash = hashlib.sha256(json.dumps(req_id, sort_keys=True).encode("utf-8")).hexdigest()[:24]
                call_id = f"{self.connection_id}:{req_hash}"
                if not self.receipts.claim(
                    call_id,
                    session=session_id,
                    tool=name,
                    args_sha256=args_digest,
                    deadline=deadline.expires_at,
                ):
                    raise HarnessError(
                        "Duplicate MCP mutation request ID on this connection; not replayed.",
                        stage="admission",
                        reason="duplicate_request",
                        submission_state="not_sent",
                        retryable=False,
                        reportable=False,
                    )
                claimed_call_id = call_id

            req_env = {
                **self._base_env,
                "MINDIE_SESSION_ID": session_id,
                "REMOTE_DEV_SESSION_ID": session_id,
                "MINDIE_AGENT_CONFIG": str(self.profile.config_path),
            }
            ctx = RequestContext(
                request_id=req_id,
                surface=self.surface,
                tool_name=name,
                session_id=session_id,
                cwd=bound_cwd,
                env=req_env,
                deadline=deadline,
                cancel=cancel_ev,
            )

            if name == "mindie_status" and self._handler is None:
                result = {
                    "content": [
                        {
                            "type": "text",
                            "text": json.dumps(
                                {
                                    "status": "ok",
                                    "host": self.profile.host,
                                    "session_id": session_id,
                                    "config_path": str(self.profile.config_path),
                                },
                                sort_keys=True,
                            ),
                        }
                    ],
                    "isError": False,
                }
            elif name == DOCTOR_TOOL_NAME and self._handler is None:
                handler_started = True
                doctor_args = dict(args)
                if "cwd" not in doctor_args and ctx.cwd is not None:
                    doctor_args["cwd"] = str(ctx.cwd)
                result = run_doctor_tool(
                    doctor_args,
                    deadline=ctx.deadline,
                    cancel=ctx.cancel,
                    env=ctx.env,
                )
            elif self._handler is not None:
                handler_started = True
                result = self._handler(ctx, args)
            else:
                raise HarnessError(
                    f"No execution handler registered for tool {name!r}",
                    stage="dispatch",
                    reason="handler_unavailable",
                    submission_state="not_sent",
                    reportable=False,
                )

            if not isinstance(result, dict):
                raise HarnessError("Tool handler returned non-object response", stage="dispatch", reason="invalid_response")

            structured = result.get("structuredContent")
            uncertain = isinstance(structured, Mapping) and (
                structured.get("submission_state") == "uncertain"
                or structured.get("status") == "submission_uncertain"
            )
            if uncertain:
                outcome_label = "unknown"
            elif result.get("isError") is True:
                outcome_label = "failed"
            else:
                outcome_label = "succeeded"
                primary_succeeded = True
            return result

        except ProcessCancelledError as exc:
            outcome_label = "unknown" if handler_started else "failed"
            result = _format_mcp_error(exc, handler_started=handler_started)
            return result
        except Exception as exc:
            outcome_label = "unknown" if (isinstance(exc, TimeoutError) and handler_started) else "failed"
            result = _format_mcp_error(exc, handler_started=handler_started)
            return result
        finally:
            accounting_exc: BaseException | None = None
            if claimed_call_id is not None:
                try:
                    self.receipts.finish(claimed_call_id, outcome_label)
                except TimeoutError as exc:
                    if not primary_succeeded:
                        raise
                    accounting_exc = exc
                except (OSError, sqlite3.Error, HarnessError, ValueError) as exc:
                    accounting_exc = exc
            if claimed_bind_id is not None:
                try:
                    self.binds.finish_bind(
                        claimed_bind_id,
                        "completed" if outcome_label == "succeeded" else "failed",
                    )
                except TimeoutError as exc:
                    if not primary_succeeded and accounting_exc is None:
                        raise
                    accounting_exc = accounting_exc or exc
                except (OSError, sqlite3.Error, HarnessError, ValueError) as exc:
                    accounting_exc = accounting_exc or exc

            if accounting_exc is not None and primary_succeeded and isinstance(result, dict):
                patched = apply_receipt_honesty(result, accounting_exc)
                result.clear()
                result.update(patched)
