"""POSIX / WSL2 process-group supervision and full-PATH native Linux binary resolver.

[Role]
Implements `which_posix_binary` (iterating ALL `os.pathsep` `$PATH` entries while
rejecting `.exe`/`.cmd`/`.bat`, WSL2 DrvFS mounts, and `b"MZ"` Windows PE shims)
and `run_posix` (`start_new_session=True`, event-driven `selectors` I/O, and
`os.killpg` descendant tree reclamation).

[Invariants]
- `which_posix_binary` NEVER stops at the first Windows `.exe` / PE match on WSL2
  `$PATH`; it scans every entry (including paths with spaces and `(x86)`) until a
  genuine POSIX executable is found.
- Child processes always spawn in a dedicated session/process group (`pgid == pid`);
  upon leader exit, timeout, cancellation, or output overflow, `os.killpg` reclaims
  all descendants so inherited pipes cannot hang.

[Timeouts & Locks]
- Uses `selectors.DefaultSelector` with deadline-clamped waits (zero `100Hz` busy-sleep
  polling) and bounded `SIGTERM -> SIGKILL` drain within `deadline.cleanup_grace`.

[Side-Effect Policy]
- Spawns only the caller-requested child process and writes optional stdout spool
  files inside `spec.spool_dir`.
"""
from __future__ import annotations

import errno
import os
from pathlib import Path
import selectors
import signal
import subprocess
import tempfile
import threading
import time
from typing import IO

from ..paths import HarnessError, is_wsl_drvfs
from .supervisor import (
    Deadline,
    OutputLimitError,
    ProcessCancelledError,
    ProcessOutcome,
    ProcessSpec,
    build_child_env,
)

_WINDOWS_SUFFIXES = frozenset({".exe", ".cmd", ".bat", ".com", ".ps1"})
_CHUNK_BYTES = 65536


def _has_mz_pe_header(path: Path) -> bool:
    """Return True if `path` starts with DOS/PE `b'MZ'` magic bytes."""
    try:
        with path.open("rb") as fh:
            return fh.read(2) == b"MZ"
    except TimeoutError:
        raise
    except OSError:
        return True


def which_posix_binary(
    name: str,
    *,
    path_env: str | None = None,
    mountinfo_text: str | None = None,
    reject_drvfs: bool = True,
) -> Path | None:
    """Resolve a native POSIX binary across ALL `$PATH` entries, skipping Windows shims."""
    clean = str(name or "").strip()
    if not clean:
        return None
    if clean.lower().endswith(tuple(_WINDOWS_SUFFIXES)):
        return None

    def _acceptable(cand: Path) -> bool:
        if cand.suffix.lower() in _WINDOWS_SUFFIXES:
            return False
        if reject_drvfs and is_wsl_drvfs(cand, mountinfo_text=mountinfo_text):
            return False
        try:
            if not cand.is_file() or not os.access(cand, os.X_OK):
                return False
        except TimeoutError:
            raise
        except OSError:
            return False
        return not _has_mz_pe_header(cand)

    if "/" in clean:
        direct = Path(clean).expanduser()
        return direct if _acceptable(direct) else None

    raw_path = os.environ.get("PATH", "") if path_env is None else path_env
    for raw_dir in raw_path.split(os.pathsep):
        entry = raw_dir.strip()
        if len(entry) >= 2 and entry[0] == entry[-1] and entry[0] in {'"', "'"}:
            entry = entry[1:-1]
        if not entry:
            continue
        candidate = Path(entry) / clean
        if _acceptable(candidate):
            return candidate
    return None


def _kill_pgroup(pid: int, *, grace_seconds: float) -> list[dict[str, str]]:
    """Terminate POSIX process group cleanly (`SIGTERM` then `SIGKILL`)."""
    issues: list[dict[str, str]] = []
    try:
        os.killpg(pid, signal.SIGTERM)
    except ProcessLookupError:
        return issues
    except PermissionError as exc:
        issues.append({"stage": "sigterm_pg", "error_type": type(exc).__name__})
    except TimeoutError:
        raise
    except OSError as exc:
        if exc.errno != errno.ESRCH:
            issues.append({"stage": "sigterm_pg", "error_type": type(exc).__name__})

    wait_until = time.monotonic() + min(0.15, max(0.02, grace_seconds * 0.25))
    while time.monotonic() < wait_until:
        try:
            os.killpg(pid, 0)
        except ProcessLookupError:
            return issues
        except TimeoutError:
            raise
        except OSError:
            break
        time.sleep(0.01)

    try:
        os.killpg(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except TimeoutError:
        raise
    except OSError as exc:
        if exc.errno != errno.ESRCH:
            issues.append({"stage": "sigkill_pg", "error_type": type(exc).__name__})
    return issues


def run_posix(
    spec: ProcessSpec,
    *,
    deadline: Deadline,
    cancel: threading.Event | None = None,
) -> ProcessOutcome:
    """Spawn and supervise a POSIX process group with `selectors`-driven streaming."""
    started = time.monotonic()
    child_env = build_child_env(spec.env)
    spool_file: IO[bytes] | None = None
    spool_path: Path | None = None

    if spec.spool_dir is not None:
        spec.spool_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd, raw_spool = tempfile.mkstemp(prefix="stdout-", suffix=".spool", dir=str(spec.spool_dir))
        spool_path = Path(raw_spool)
        spool_file = os.fdopen(fd, "w+b")

    try:
        proc = subprocess.Popen(
            list(spec.argv),
            cwd=str(spec.cwd) if spec.cwd is not None else None,
            env=child_env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
            close_fds=True,
        )
    except TimeoutError:
        if spool_file is not None:
            spool_file.close()
        if spool_path is not None:
            spool_path.unlink(missing_ok=True)
        raise
    except OSError as exc:
        if spool_file is not None:
            spool_file.close()
        if spool_path is not None:
            spool_path.unlink(missing_ok=True)
        raise HarnessError(
            f"Failed to start {spec.argv[0]!r}: {exc}",
            stage="spawn",
            reason="spawn_failed",
            submission_state="not_sent",
            retryable=False,
            reportable=False,
            details={"errno": exc.errno, "error_type": type(exc).__name__},
        ) from exc

    assert proc.stdin is not None and proc.stdout is not None and proc.stderr is not None
    os.set_blocking(proc.stdout.fileno(), False)
    os.set_blocking(proc.stderr.fileno(), False)

    selector = selectors.DefaultSelector()
    selector.register(proc.stdout, selectors.EVENT_READ, "stdout")
    selector.register(proc.stderr, selectors.EVENT_READ, "stderr")

    stdin_view = memoryview(spec.stdin_bytes)
    stdin_offset = 0
    if stdin_view:
        os.set_blocking(proc.stdin.fileno(), False)
        selector.register(proc.stdin, selectors.EVENT_WRITE, "stdin")
    else:
        proc.stdin.close()

    stdout_buf = bytearray()
    stderr_buf = bytearray()
    total_captured = 0
    cleanup_issues: list[dict[str, str]] = []

    def _build_outcome(execution: str, returncode: int | None) -> ProcessOutcome:
        elapsed_ms = int((time.monotonic() - started) * 1000)
        if spool_file is not None:
            spool_file.flush()
            spool_file.seek(0)
            preview = spool_file.read(min(total_captured, spec.mcp_response_cap_bytes))
            out_text = preview.decode("utf-8", errors="replace")
            out_trunc = total_captured > len(preview)
        else:
            out_text = stdout_buf.decode("utf-8", errors="replace")
            out_trunc = False
        err_text = stderr_buf.decode("utf-8", errors="replace")
        return ProcessOutcome(
            execution=execution,  # type: ignore[arg-type]
            returncode=returncode,
            stdout=out_text,
            stderr=err_text,
            elapsed_ms=elapsed_ms,
            stdout_truncated=out_trunc,
            stderr_truncated=False,
            spooled_stdout_path=spool_path,
            cleanup_issues=tuple(cleanup_issues),
        )

    try:
        while selector.get_map() or proc.poll() is None:
            if cancel is not None and cancel.is_set():
                cleanup_issues.extend(_kill_pgroup(proc.pid, grace_seconds=deadline.cleanup_grace))
                try:
                    proc.wait(timeout=1.0)
                except subprocess.TimeoutExpired:
                    pass
                raise ProcessCancelledError(
                    "Process cancelled by caller",
                    _build_outcome("unknown", proc.poll()),
                )

            rem = deadline.remaining()
            if rem <= 0.0:
                cleanup_issues.extend(_kill_pgroup(proc.pid, grace_seconds=deadline.cleanup_grace))
                try:
                    proc.wait(timeout=1.0)
                except subprocess.TimeoutExpired:
                    pass
                err = TimeoutError("Owned process exceeded monotonic deadline")
                err.outcome = _build_outcome("unknown", proc.poll())  # type: ignore[attr-defined]
                raise err

            events = selector.select(timeout=min(0.05, rem))
            for key, _ in events:
                tag = key.data
                if tag == "stdin":
                    try:
                        written = os.write(proc.stdin.fileno(), stdin_view[stdin_offset : stdin_offset + _CHUNK_BYTES])
                        stdin_offset += written
                        if stdin_offset >= len(stdin_view):
                            selector.unregister(proc.stdin)
                            proc.stdin.close()
                    except BlockingIOError:
                        continue
                    except BrokenPipeError:
                        selector.unregister(proc.stdin)
                        proc.stdin.close()
                    continue

                try:
                    chunk = os.read(key.fileobj.fileno(), _CHUNK_BYTES)  # type: ignore[union-attr]
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                total_captured += len(chunk)
                if total_captured > spec.max_output_bytes:
                    cleanup_issues.extend(_kill_pgroup(proc.pid, grace_seconds=deadline.cleanup_grace))
                    try:
                        proc.wait(timeout=1.0)
                    except subprocess.TimeoutExpired:
                        pass
                    raise OutputLimitError(
                        spec.max_output_bytes,
                        _build_outcome("unknown", proc.poll()),
                    )
                if tag == "stdout":
                    if spool_file is not None:
                        spool_file.write(chunk)
                    else:
                        stdout_buf.extend(chunk)
                else:
                    stderr_buf.extend(chunk)

        proc.wait(timeout=max(0.1, deadline.cleanup_grace))
        _kill_pgroup(proc.pid, grace_seconds=0.05)
        return _build_outcome("completed", proc.returncode)
    finally:
        if spool_file is not None:
            try:
                spool_file.close()
            except TimeoutError:
                raise
            except OSError:
                pass
        try:
            selector.close()
        except TimeoutError:
            raise
        except OSError:
            pass
        for stream in (proc.stdin, proc.stdout, proc.stderr):
            try:
                if stream and not stream.closed:
                    stream.close()
            except TimeoutError:
                raise
            except OSError:
                pass
        if proc.poll() is None:
            _kill_pgroup(proc.pid, grace_seconds=0.1)
            try:
                proc.wait(timeout=0.5)
            except subprocess.TimeoutExpired:
                pass
