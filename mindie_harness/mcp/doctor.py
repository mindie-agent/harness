"""Read-only `mindie_doctor` dispatch: in-process diagnostics or generation-local CLI fallback.

[Role]
Provides the canonical `mindie_doctor` MCP tool definition and dispatches it to
`mindie_diagnostics.doctor.run_doctor` inside the profile's active runtime
generation (`cfg["python"]` or `sys.executable`), passing `adapter_config` and
`reporting_config` so isolated/custom host profiles are inspected accurately.

[Invariants]
- Imports `mindie_diagnostics` lazily inside the dispatch call; zero top-level
  third-party or sibling imports (`HAR-ABI`).
- Prefers `<host>.json["python"]` when it differs from `sys.executable` so a
  stdlib bootstrap process never misses `.venv`-installed `mindie-diagnostics`.
- Never searches ambient `$PATH` via `shutil.which` and never uses `inspect.signature`.
- Validates `probe_remote` strictly as a boolean and rejects empty or malformed
  stdout on `rc == 0` instead of fabricating success.

[Timeouts & Locks]
- Respects caller `Deadline` (`inner_remaining()`) and `cancel` event
  (`DOCTOR_LOCAL_CHILD_SECONDS = 5.0`, `DOCTOR_PROBE_CHILD_SECONDS = 15.0`,
  `DOCTOR_CHILD_CLEANUP_GRACE_SECONDS = 2.0`).

[Side-Effect Policy]
- Strictly read-only; spawns at most one generation-local `mindie_diagnostics.cli`
  child process via `run_owned` when cross-interpreter or out-of-process.
"""
from __future__ import annotations

import importlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import threading
from typing import Any, Mapping

from ..atomic import read_json_safe
from ..paths import ProfileRef, same_interpreter
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


def _resolve_doctor_targets(
    profile: ProfileRef | None,
    env: Mapping[str, str] | None,
) -> tuple[Path, str | None, str | None]:
    environ = os.environ if env is None else env
    if profile is None:
        explicit_cfg = environ.get("MINDIE_AGENT_CONFIG")
        adapter_cfg = explicit_cfg.strip() if isinstance(explicit_cfg, str) and explicit_cfg.strip() else None
        rep_cfg = environ.get("MINDIE_DIAGNOSTICS_CONFIG")
        reporting_cfg = rep_cfg.strip() if isinstance(rep_cfg, str) and rep_cfg.strip() else None
        return Path(sys.executable), adapter_cfg, reporting_cfg

    cfg = read_json_safe(profile.config_path)
    py_raw = cfg.get("python") if isinstance(cfg, Mapping) else None
    target_py = (
        Path(py_raw)
        if isinstance(py_raw, str) and py_raw.strip() and Path(py_raw).is_file()
        else Path(sys.executable)
    )
    rep_raw = environ.get("MINDIE_DIAGNOSTICS_CONFIG")
    reporting_cfg = (
        rep_raw.strip()
        if isinstance(rep_raw, str) and rep_raw.strip()
        else str(profile.config_path.parent / "diagnostics.json")
    )
    return target_py, str(profile.config_path), reporting_cfg


def run_doctor_tool(
    arguments: Mapping[str, Any] | None = None,
    *,
    profile: ProfileRef | None = None,
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
        rem = deadline.inner_remaining()
        if rem <= 0:
            raise TimeoutError("mindie_doctor outer deadline expired before dispatch")
        target_budget = min(target_budget, rem)

    target_py, adapter_cfg, reporting_cfg = _resolve_doctor_targets(profile, env)
    if same_interpreter(target_py, sys.executable):
        in_process = _try_in_process_doctor(
            cwd,
            probe_remote,
            adapter_config=adapter_cfg,
            reporting_config=reporting_cfg,
            timeout_sec=target_budget,
        )
        if in_process is not _UNAVAILABLE:
            return in_process  # type: ignore[return-value]

    return _run_cli_doctor(
        target_py,
        cwd,
        probe_remote,
        adapter_config=adapter_cfg,
        reporting_config=reporting_cfg,
        budget_sec=target_budget,
        deadline=deadline,
        cancel=cancel,
        env=env,
    )


def _try_in_process_doctor(
    cwd: Path | None,
    probe_remote: bool,
    *,
    adapter_config: str | None,
    reporting_config: str | None,
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
    if not hasattr(module, "run_doctor"):
        return _UNAVAILABLE
    kwargs: dict[str, Any] = {
        "adapter_config": adapter_config,
        "reporting_config": reporting_config,
        "probe_remote": probe_remote,
        "timeout_sec": timeout_sec,
    }
    if cwd is not None:
        kwargs["cwd"] = str(cwd)
    try:
        return _normalize_result(module.run_doctor(**kwargs))
    except TimeoutError:
        raise
    except Exception as exc:
        return _error_result(
            "doctor_failed",
            f"mindie_diagnostics.doctor.run_doctor failed ({type(exc).__name__}): {exc}",
            state="failed",
        )


def _has_diagnostics_cli(target_py: Path) -> bool:
    if same_interpreter(target_py, sys.executable):
        try:
            return importlib.util.find_spec("mindie_diagnostics.cli") is not None
        except (ImportError, AttributeError, ValueError):
            return False
    venv_root = target_py.parent.parent
    sites = [venv_root / "Lib" / "site-packages"]
    lib_dir = venv_root / "lib"
    if lib_dir.is_dir():
        sites.extend(lib_dir.glob("python*/site-packages"))
    existing = [s for s in sites if s.is_dir()]
    if any((s / "mindie_diagnostics" / "cli.py").is_file() for s in existing):
        return True
    return any(any(s.glob("*.pth")) for s in existing)


def _doctor_cli_argv(probe_remote: bool) -> list[str] | None:
    if not _has_diagnostics_cli(Path(sys.executable)):
        return None
    argv = [sys.executable, "-I", "-X", "utf8", "-m", "mindie_diagnostics.cli", "doctor"]
    if probe_remote:
        argv.append("--probe-remote")
    return argv


def _run_cli_doctor(
    target_py: Path,
    cwd: Path | None,
    probe_remote: bool,
    *,
    adapter_config: str | None,
    reporting_config: str | None,
    budget_sec: float,
    deadline: Deadline | None,
    cancel: threading.Event | None,
    env: Mapping[str, str] | None,
) -> dict[str, Any]:
    if same_interpreter(target_py, sys.executable):
        base_argv = _doctor_cli_argv(probe_remote)
        if base_argv is None:
            return _unavailable_result()
        argv = list(base_argv)
    else:
        if not _has_diagnostics_cli(target_py):
            return _unavailable_result()
        argv = [str(target_py), "-I", "-X", "utf8", "-m", "mindie_diagnostics.cli", "doctor"]
        if probe_remote:
            argv.append("--probe-remote")
    if adapter_config:
        argv.extend(["--adapter-config", adapter_config])
    if reporting_config:
        argv.extend(["--reporting-config", reporting_config])
    if cwd is not None:
        argv.extend(["--cwd", str(cwd)])

    child_deadline = (
        deadline
        if deadline is not None
        else Deadline.from_budgets([max(0.5, budget_sec)], cleanup_grace=DOCTOR_CHILD_CLEANUP_GRACE_SECONDS)
    )
    spec = ProcessSpec(
        argv=tuple(argv),
        env=dict(env) if env is not None else None,
        role="foreground",
        max_output_bytes=DOCTOR_OUTPUT_CAP_BYTES,
        allowed_returncodes=None,
    )
    try:
        outcome = run_owned(spec, deadline=child_deadline, cancel=cancel)
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
        lowered = detail.lower()
        if (outcome.returncode == 2 and "invalid choice" in lowered) or "no module named 'mindie_diagnostics" in lowered:
            return _unavailable_result()
        suffix = f": {detail[:512]}" if detail else ""
        return _error_result(
            "doctor_failed",
            f"`mindie_diagnostics.cli doctor` exited with code {outcome.returncode}{suffix}",
            state="failed",
        )
    text = (outcome.stdout or "").strip()
    if not text:
        return _error_result(
            "doctor_invalid_output",
            "`mindie_diagnostics.cli doctor` exited 0 with empty stdout.",
            state="failed",
        )
    try:
        parsed = json.loads(text)
    except (TypeError, ValueError):
        return _error_result(
            "doctor_invalid_output",
            "`mindie_diagnostics.cli doctor` returned malformed non-JSON stdout.",
            state="failed",
        )
    if not isinstance(parsed, Mapping):
        return _error_result(
            "doctor_invalid_output",
            "`mindie_diagnostics.cli doctor` returned a non-object JSON payload.",
            state="failed",
        )
    return _normalize_result(parsed)


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
            "is absent or predates `doctor`. Continue the task normally or use `mindie_status` / `diagnostics_status`."
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
