"""Read-only `mindie_doctor` dispatch: in-process diagnostics or generation-local CLI fallback.

[Role]
Provides the canonical `mindie_doctor` MCP tool definition and dispatches it to
`mindie_diagnostics.doctor.run_doctor` when installed in the active runtime
generation (`sys.executable`), otherwise to a bounded generation-local
`python -m mindie_diagnostics.cli doctor` child process, and finally to an honest
`doctor_unavailable` result for older rollback generations predating `doctor`.

[Invariants]
- Imports `mindie_diagnostics` lazily inside the dispatch call; zero top-level
  third-party or sibling imports.
- Never searches ambient `$PATH` via `shutil.which` (preventing cross-generation
  leakage and WSL2 DrvFS shim hazards) and never uses `inspect.signature` (`Iron Rule 4`).
- Validates `probe_remote` strictly as a boolean (`"false"` is rejected, never coerced).

[Timeouts & Locks]
- Respects caller `Deadline` and `cancel` event (`DOCTOR_LOCAL_CHILD_SECONDS = 5.0`,
  `DOCTOR_PROBE_CHILD_SECONDS = 15.0`, `DOCTOR_CHILD_CLEANUP_GRACE_SECONDS = 2.0`),
  capping child execution to the remaining outer budget.

[Side-Effect Policy]
- Strictly read-only; spawns at most one generation-local `mindie_diagnostics.cli`
  child process via `run_owned` when in-process import is unavailable.
"""
from __future__ import annotations

import importlib
import importlib.util
import json
from pathlib import Path
import sys
import threading
from typing import Any, Mapping

from ..process.supervisor import Deadline, ProcessSpec, run_owned

DOCTOR_TOOL_NAME = "mindie_doctor"
DOCTOR_LOCAL_CHILD_SECONDS = 5.0
DOCTOR_PROBE_CHILD_SECONDS = 15.0
DOCTOR_CHILD_CLEANUP_GRACE_SECONDS = 2.0
DOCTOR_OUTPUT_CAP_BYTES = 256 * 1024
_UNAVAILABLE = object()


def doctor_tool_definition() -> dict[str, Any]:
    """Return the read-only `mindie_doctor` MCP tool schema."""
    return {
        "name": DOCTOR_TOOL_NAME,
        "description": (
            "Run the read-only MindIE diagnostics doctor to inspect runtime versions, "
            "experience/privacy mode, default remote NPU endpoint, GitHub CLI readiness, "
            "and local diagnostics health. Optional helper: if unavailable or failing, "
            "continue the user's task directly via standard tools or native SSH."
        ),
        "annotations": {
            "readOnlyHint": True,
            "destructiveHint": False,
            "openWorldHint": False,
        },
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "cwd": {
                    "type": "string",
                    "description": "Optional working directory for scope checks.",
                },
                "probe_remote": {
                    "type": "boolean",
                    "default": False,
                    "description": "Opt in to a bounded read-only SSH/NPU probe of the default endpoint.",
                },
            },
            "required": [],
        },
    }


def run_doctor_tool(
    arguments: Mapping[str, Any] | None = None,
    *,
    deadline: Deadline | None = None,
    cancel: threading.Event | None = None,
    env: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Dispatch `mindie_doctor` within the active generation and request budget."""
    args = arguments or {}
    cwd_value = args.get("cwd")
    if cwd_value is not None and not isinstance(cwd_value, str):
        return _error_result("invalid_doctor_arguments", "`cwd` must be a string when supplied.", state="not_sent")
    probe_raw = args.get("probe_remote", False)
    if not isinstance(probe_raw, bool):
        return _error_result(
            "invalid_doctor_arguments",
            "`probe_remote` must be a boolean when supplied.",
            state="not_sent",
        )
    probe_remote = probe_raw
    cwd = Path(cwd_value).expanduser() if isinstance(cwd_value, str) and cwd_value.strip() else None

    target_budget = DOCTOR_PROBE_CHILD_SECONDS if probe_remote else DOCTOR_LOCAL_CHILD_SECONDS
    if deadline is not None:
        rem = deadline.remaining()
        if rem <= 0:
            raise TimeoutError("mindie_doctor outer deadline expired before dispatch")
        target_budget = min(target_budget, rem)

    in_process = _try_in_process_doctor(cwd, probe_remote, timeout_sec=target_budget)
    if in_process is not _UNAVAILABLE:
        return in_process
    return _run_cli_doctor(cwd, probe_remote, budget_sec=target_budget, cancel=cancel, env=env)


def _try_in_process_doctor(
    cwd: Path | None,
    probe_remote: bool,
    *,
    timeout_sec: float,
) -> dict[str, Any] | object:
    try:
        module = importlib.import_module("mindie_diagnostics.doctor")
    except TimeoutError:
        raise
    except ImportError:
        return _UNAVAILABLE
    except Exception as exc:
        return _error_result(
            "doctor_failed",
            f"mindie_diagnostics.doctor import failed ({type(exc).__name__}): {exc}",
            state="failed",
        )
    run_doctor = getattr(module, "run_doctor", None)
    if not callable(run_doctor):
        return _UNAVAILABLE
    kwargs: dict[str, Any] = {"probe_remote": probe_remote, "timeout_sec": timeout_sec}
    if cwd is not None:
        kwargs["cwd"] = str(cwd)
    try:
        return _normalize_result(run_doctor(**kwargs))
    except TimeoutError:
        raise
    except Exception as exc:
        return _error_result(
            "doctor_failed",
            f"mindie_diagnostics.doctor.run_doctor failed ({type(exc).__name__}): {exc}",
            state="failed",
        )


def _doctor_cli_argv(probe_remote: bool) -> list[str] | None:
    try:
        spec = importlib.util.find_spec("mindie_diagnostics.cli")
    except (ImportError, AttributeError, ValueError):
        spec = None
    if spec is None:
        return None
    argv = [sys.executable, "-I", "-X", "utf8", "-m", "mindie_diagnostics.cli", "doctor"]
    if probe_remote:
        argv.append("--probe-remote")
    return argv


def _run_cli_doctor(
    cwd: Path | None,
    probe_remote: bool,
    *,
    budget_sec: float,
    cancel: threading.Event | None,
    env: Mapping[str, str] | None,
) -> dict[str, Any]:
    argv = _doctor_cli_argv(probe_remote)
    if argv is None:
        return _unavailable_result()
    if cwd is not None:
        argv = [*argv, "--cwd", str(cwd)]
    spec = ProcessSpec(
        argv=tuple(argv),
        cwd=cwd if cwd is not None and cwd.is_dir() else None,
        env=dict(env) if env is not None else None,
        role="foreground",
        max_output_bytes=DOCTOR_OUTPUT_CAP_BYTES,
        allowed_returncodes=None,
    )
    try:
        outcome = run_owned(
            spec,
            deadline=Deadline.from_budgets(
                [max(0.5, budget_sec)],
                cleanup_grace=DOCTOR_CHILD_CLEANUP_GRACE_SECONDS,
            ),
            cancel=cancel,
        )
    except TimeoutError:
        raise
    except OSError as exc:
        return _error_result(
            "doctor_unavailable",
            f"Could not start generation-local `mindie_diagnostics.cli doctor` ({type(exc).__name__}).",
            state="not_sent",
        )
    if outcome.returncode != 0:
        detail = (outcome.stderr or outcome.stdout or "").strip()
        if outcome.returncode == 2 and "invalid choice" in detail.lower():
            return _unavailable_result()
        suffix = f": {detail[:512]}" if detail else ""
        return _error_result(
            "doctor_failed",
            f"`mindie_diagnostics.cli doctor` exited with code {outcome.returncode}{suffix}",
            state="failed",
        )
    text = (outcome.stdout or "").strip()
    if not text:
        return _normalize_result({"status": "ok", "detail": "mindie-diagnostics doctor completed"})
    try:
        return _normalize_result(json.loads(text))
    except (TypeError, ValueError):
        return _normalize_result(text)


def _normalize_result(value: Any) -> dict[str, Any]:
    if isinstance(value, Mapping) and isinstance(value.get("content"), list):
        result = dict(value)
        result.setdefault("isError", False)
        return result
    if isinstance(value, Mapping):
        payload = dict(value)
        return {
            "content": [
                {
                    "type": "text",
                    "text": json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str),
                }
            ],
            "isError": bool(payload.get("isError")),
            "structuredContent": payload,
        }
    text = value.strip() if isinstance(value, str) else json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
    return {"content": [{"type": "text", "text": text or "mindie_doctor completed"}], "isError": False}


def _unavailable_result() -> dict[str, Any]:
    return _error_result(
        "doctor_unavailable",
        (
            "`mindie_doctor` is unavailable in this runtime generation: active `mindie-diagnostics` "
            "predates `doctor`. Continue the task normally or use `mindie_status` / `diagnostics_status`."
        ),
        state="not_sent",
    )


def _error_result(reason: str, message: str, *, state: str) -> dict[str, Any]:
    return {
        "content": [{"type": "text", "text": message}],
        "isError": True,
        "structuredContent": {
            "stage": "dispatch",
            "reason": reason,
            "submission_state": state,
            "retryable": False,
            "message": message,
        },
    }
