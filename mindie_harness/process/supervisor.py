"""Monotonic deadline arithmetic and cross-platform owned subprocess dispatcher.

[Role]
Defines `Deadline`, `ProcessSpec`, `ProcessOutcome`, and `run_owned`—the single
authoritative subprocess execution surface across POSIX, WSL2, and Windows 11.

[Invariants]
- Enforces Principle 10 timeout arithmetic: `outer_timeout >= sum(inner_budgets) + cleanup_grace`.
- Decouples the OS process capture/spool ceiling (`max_output_bytes`, default `16 MiB`)
  from the MCP text truncation budget (`mcp_response_cap_bytes`, default `1 MiB`) so
  legitimate multi-MB tool outputs are never killed prematurely.
- Distinguishes `execution="not_started"`, `"completed"` (clean exit, whether `0` or
  non-zero), and `"unknown"` (timed out, cancelled, or killed mid-flight).
- Never lets `except OSError:` swallow `TimeoutError` (Principle 9 & 14).

[Timeouts & Locks]
- Every `run_owned` call operates under a monotonic `Deadline` (`default 60.0s` when
  unspecified) and optional `threading.Event` cancellation token.

[Side-Effect Policy]
- Never mutates global `os.environ` or process working directory; spawns and reaps
  isolated child process trees.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import math
import os
from pathlib import Path
import threading
import time
from typing import Any, Literal, Mapping, Sequence

from ..paths import HarnessError

DEFAULT_CLEANUP_GRACE_SECONDS = 2.0
DEFAULT_PROCESS_TIMEOUT_SECONDS = 60.0
DEFAULT_MAX_OUTPUT_BYTES = 16 * 1024 * 1024
DEFAULT_MCP_RESPONSE_CAP_BYTES = 1 * 1024 * 1024
DEFAULT_CONTROL_PLANE_MEMORY_BYTES = 512 * 1024 * 1024

ProcessRole = Literal["foreground", "background_maintenance", "gui_worker", "mcp_server"]
ExecutionState = Literal["not_started", "completed", "unknown"]


@dataclass(frozen=True)
class Deadline:
    """Monotonic deadline enforcing `outer_timeout >= sum(inner_budgets) + cleanup_grace`."""

    expires_at: float
    cleanup_grace: float = DEFAULT_CLEANUP_GRACE_SECONDS

    def __post_init__(self) -> None:
        if isinstance(self.expires_at, bool) or not math.isfinite(self.expires_at):
            raise ValueError("expires_at must be a finite monotonic timestamp")
        if (
            isinstance(self.cleanup_grace, bool)
            or not math.isfinite(self.cleanup_grace)
            or self.cleanup_grace < 0
        ):
            raise ValueError("cleanup_grace must be a nonnegative finite number")

    @staticmethod
    def compute_outer(inner_budgets: Sequence[float], cleanup_grace: float = DEFAULT_CLEANUP_GRACE_SECONDS) -> float:
        if isinstance(cleanup_grace, bool) or not math.isfinite(cleanup_grace) or cleanup_grace < 0:
            raise ValueError("cleanup_grace must be a nonnegative finite number")
        total_inner = 0.0
        for item in inner_budgets:
            if isinstance(item, bool) or not isinstance(item, (int, float)) or not math.isfinite(item) or item < 0:
                raise ValueError("inner budget must be a nonnegative finite number")
            total_inner += float(item)
        return total_inner + float(cleanup_grace)

    @classmethod
    def validate_outer(
        cls,
        outer_timeout: float,
        inner_budgets: Sequence[float],
        *,
        cleanup_grace: float = DEFAULT_CLEANUP_GRACE_SECONDS,
    ) -> float:
        if isinstance(outer_timeout, bool) or not isinstance(outer_timeout, (int, float)) or not math.isfinite(outer_timeout) or outer_timeout <= 0:
            raise ValueError("outer_timeout must be a positive finite number")
        required = cls.compute_outer(inner_budgets, cleanup_grace)
        if float(outer_timeout) + 1e-9 < required:
            raise ValueError(
                f"outer_timeout ({outer_timeout:g}s) violates Principle 10: "
                f"must be >= sum(inner_budgets) + cleanup_grace ({required:g}s)"
            )
        return float(outer_timeout)

    @classmethod
    def from_timeout(
        cls,
        timeout_seconds: float,
        *,
        cleanup_grace: float = DEFAULT_CLEANUP_GRACE_SECONDS,
        now: float | None = None,
    ) -> "Deadline":
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not math.isfinite(timeout_seconds)
            or timeout_seconds <= 0
        ):
            raise ValueError("timeout_seconds must be a positive finite number")
        base = time.monotonic() if now is None else float(now)
        return cls(expires_at=base + float(timeout_seconds), cleanup_grace=float(cleanup_grace))

    @classmethod
    def from_budgets(
        cls,
        inner_budgets: Sequence[float],
        *,
        cleanup_grace: float = DEFAULT_CLEANUP_GRACE_SECONDS,
        outer_timeout: float | None = None,
        now: float | None = None,
    ) -> "Deadline":
        required = cls.compute_outer(inner_budgets, cleanup_grace)
        chosen = required if outer_timeout is None else cls.validate_outer(
            outer_timeout, inner_budgets, cleanup_grace=cleanup_grace
        )
        return cls.from_timeout(chosen, cleanup_grace=cleanup_grace, now=now)

    def remaining(self, *, now: float | None = None) -> float:
        curr = time.monotonic() if now is None else float(now)
        return max(0.0, self.expires_at - curr)

    def inner_remaining(self, *, now: float | None = None) -> float:
        return max(0.0, self.remaining(now=now) - self.cleanup_grace)

    def expired(self, *, now: float | None = None) -> bool:
        curr = time.monotonic() if now is None else float(now)
        return curr >= self.expires_at

    def require_remaining(self, minimum_seconds: float = 0.0) -> float:
        rem = self.remaining()
        if rem <= 0.0 or rem < float(minimum_seconds):
            raise TimeoutError(
                f"Deadline expired or below required {minimum_seconds:g}s floor (remaining={rem:.3f}s)"
            )
        return rem


@dataclass(frozen=True)
class ProcessSpec:
    """Immutable specification for an owned OS child process."""

    argv: tuple[str, ...]
    cwd: Path | None = None
    env: Mapping[str, str] | None = None
    stdin_bytes: bytes = b""
    max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES
    mcp_response_cap_bytes: int = DEFAULT_MCP_RESPONSE_CAP_BYTES
    spool_dir: Path | None = None
    role: ProcessRole = "foreground"
    memory_limit_bytes: int | None = DEFAULT_CONTROL_PLANE_MEMORY_BYTES
    cpu_rate_percent: int | None = None
    below_normal_priority: bool = False
    require_gui_subsystem: bool = False
    allowed_returncodes: tuple[int, ...] | None = (0,)
    allow_daemon_breakaway: bool = False

    def __post_init__(self) -> None:
        if not self.argv or any(not isinstance(a, str) or not a for a in self.argv):
            raise ValueError("ProcessSpec.argv must be a non-empty tuple of non-empty strings")
        object.__setattr__(self, "argv", tuple(self.argv))
        if self.cwd is not None:
            object.__setattr__(self, "cwd", Path(self.cwd))
        if self.spool_dir is not None:
            object.__setattr__(self, "spool_dir", Path(self.spool_dir))
        if self.max_output_bytes < 1024:
            raise ValueError("max_output_bytes must be >= 1024")
        if self.mcp_response_cap_bytes < 256:
            raise ValueError("mcp_response_cap_bytes must be >= 256")
        if self.memory_limit_bytes is not None and self.memory_limit_bytes <= 0:
            raise ValueError("memory_limit_bytes must be positive or None")
        if self.cpu_rate_percent is not None and not (1 <= int(self.cpu_rate_percent) <= 100):
            raise ValueError("cpu_rate_percent must be in 1..100 when specified")

    @property
    def effective_below_normal(self) -> bool:
        return bool(self.below_normal_priority or self.role == "background_maintenance")

    @property
    def effective_cpu_rate_percent(self) -> int | None:
        if self.cpu_rate_percent is not None:
            return int(self.cpu_rate_percent)
        if self.role == "background_maintenance":
            return 25
        return None

    @property
    def effective_require_gui(self) -> bool:
        return bool(self.require_gui_subsystem or self.role == "gui_worker")


@dataclass(frozen=True)
class ProcessOutcome:
    """Settled or interrupted process result decoupled from MCP truncation caps."""

    execution: ExecutionState
    returncode: int | None
    stdout: str = ""
    stderr: str = ""
    elapsed_ms: int = 0
    stdout_truncated: bool = False
    stderr_truncated: bool = False
    spooled_stdout_path: Path | None = None
    cleanup_issues: tuple[dict[str, str], ...] = field(default_factory=tuple)
    job_metadata: dict[str, Any] | None = None

    def mcp_stdout(self, cap_bytes: int | None = None) -> tuple[str, bool]:
        """Project `stdout` into an MCP response budget without killing the process."""
        limit = DEFAULT_MCP_RESPONSE_CAP_BYTES if cap_bytes is None else int(cap_bytes)
        encoded = self.stdout.encode("utf-8", errors="replace")
        if len(encoded) <= limit:
            return self.stdout, False
        head = limit // 2
        tail = max(0, limit - head - 64)
        prefix = encoded[:head].decode("utf-8", errors="ignore")
        suffix = encoded[-tail:].decode("utf-8", errors="ignore") if tail else ""
        omitted = len(encoded) - len(prefix.encode("utf-8")) - len(suffix.encode("utf-8"))
        return f"{prefix}\n...[truncated {omitted} bytes]...\n{suffix}", True


class OutputLimitError(HarnessError):
    """Raised when child output exceeds `ProcessSpec.max_output_bytes`."""

    def __init__(self, max_bytes: int, outcome: ProcessOutcome) -> None:
        self.outcome = outcome
        super().__init__(
            f"Child process output exceeded {max_bytes} bytes hard cap",
            stage="process_output",
            reason="output_limit_exceeded",
            submission_state="uncertain",
            retryable=False,
        )


class ProcessCancelledError(HarnessError):
    """Raised when caller cancellation stops an owned process."""

    def __init__(self, message: str, outcome: ProcessOutcome) -> None:
        self.outcome = outcome
        super().__init__(
            message,
            stage="process_cancel",
            reason="caller_cancelled",
            submission_state="not_sent" if outcome.execution == "not_started" else "uncertain",
            retryable=False,
            reportable=False,
        )


class ProcessExecutionError(HarnessError):
    """Raised on clean non-zero exit when `allowed_returncodes` rejects `returncode`."""

    def __init__(self, outcome: ProcessOutcome) -> None:
        self.outcome = outcome
        super().__init__(
            f"Process exited with disallowed code {outcome.returncode}",
            stage="process_exit",
            reason="process_nonzero_exit",
            submission_state="acknowledged",
            retryable=True,
            details={"returncode": outcome.returncode},
        )


def coerce_deadline(deadline: Deadline | float | int | None) -> Deadline:
    if isinstance(deadline, Deadline):
        return deadline
    if deadline is None:
        return Deadline.from_timeout(DEFAULT_PROCESS_TIMEOUT_SECONDS)
    return Deadline.from_timeout(float(deadline))


def build_child_env(overrides: Mapping[str, str] | None) -> dict[str, str]:
    """Construct UTF-8 safe child environment without mutating global `os.environ`."""
    merged = dict(os.environ)
    if overrides is not None:
        for k, v in overrides.items():
            merged[str(k)] = str(v)
    merged.setdefault("PYTHONUTF8", "1")
    merged.setdefault("PYTHONIOENCODING", "utf-8")
    return merged


def run_owned(
    spec: ProcessSpec,
    *,
    deadline: Deadline | float | int | None = None,
    cancel: threading.Event | None = None,
) -> ProcessOutcome:
    """Execute `spec` inside an owned OS process group / Win32 Job Object."""
    resolved_deadline = coerce_deadline(deadline)
    if cancel is not None and cancel.is_set():
        raise ProcessCancelledError(
            "Request cancelled before process spawn",
            ProcessOutcome(execution="not_started", returncode=None),
        )
    resolved_deadline.require_remaining(0.01)

    if os.name == "nt":
        from .win32 import run_win32

        outcome = run_win32(spec, deadline=resolved_deadline, cancel=cancel)
    else:
        from .posix import run_posix

        outcome = run_posix(spec, deadline=resolved_deadline, cancel=cancel)

    if spec.allowed_returncodes is not None and outcome.returncode not in spec.allowed_returncodes:
        raise ProcessExecutionError(outcome)
    return outcome
