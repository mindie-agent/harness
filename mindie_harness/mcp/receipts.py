"""SQLite WAL replay receipts (`v1`+`v2`), one-shot `PreToolUse` binds, and Receipt Honesty.

[Role]
Implements `RemoteReceipts` (`mindie-remote-receipts/1` and `/2` dual-compatible),
`BindStore` (`mindie-mcp-binds/1`), PID-reuse-safe `process_boot_signature` /
`is_owner_alive` (eliminating hot-path `.owner.lock` directory sweeps, `AD-09`),
and `apply_receipt_honesty` (Principles 9 & 14).

[Invariants]
- Zero hot-path `.owner.lock` filesystem scans: liveness is checked via `(owner_pid, owner_boot_sig)`
  ONLY when `SELECT ... WHERE status='running'` finds in-flight mutation rows.
- Never calls unguarded `os.kill(pid, 0)` on Windows (`P8`); uses `OpenProcess` +
  `GetExitCodeProcess` + `GetProcessTimes` on Win32, `/proc/<pid>/stat` on Linux,
  and `os.kill(pid, 0)` + `ps -o lstart=` on macOS.
- Receipt Honesty: once a primary operation succeeds (`isError=False`), local receipt
  or bind accounting failures keep `isError=False` and attach `receipt_warning` +
  `receipt_unconfirmed=True`.

[Timeouts & Locks]
- Uses `paths.open_wal_database` (`WAL` + `busy_timeout=5000` configured once on open).

[Side-Effect Policy]
- Mutates only `remote-receipts.sqlite3` and `mcp-binds.sqlite3` under `<state_dir>`.
"""
from __future__ import annotations

from contextlib import contextmanager
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import threading
import time
from typing import Any, Iterator
import uuid

from ..paths import HarnessError, open_wal_database

RECEIPTS_SCHEMA_V1 = "mindie-remote-receipts/1"
RECEIPTS_SCHEMA_V2 = "mindie-remote-receipts/2"
BINDS_SCHEMA = "mindie-mcp-binds/1"
MAX_CONCURRENT_MUTATIONS_PER_SESSION = 4
BIND_TTL_SECONDS = 300.0

if os.name == "nt":
    import ctypes
    from ctypes import wintypes

    _PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    _STILL_ACTIVE = 259

    class _FILETIME(ctypes.Structure):
        _fields_ = [("dwLowDateTime", wintypes.DWORD), ("dwHighDateTime", wintypes.DWORD)]

    _k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    _k32.OpenProcess.restype = wintypes.HANDLE
    _k32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    _k32.GetExitCodeProcess.restype = wintypes.BOOL
    _k32.GetProcessTimes.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(_FILETIME),
        ctypes.POINTER(_FILETIME),
        ctypes.POINTER(_FILETIME),
        ctypes.POINTER(_FILETIME),
    ]
    _k32.GetProcessTimes.restype = wintypes.BOOL
    _k32.CloseHandle.argtypes = [wintypes.HANDLE]
    _k32.CloseHandle.restype = wintypes.BOOL


def process_boot_signature(pid: int) -> str | None:
    """Return a PID-reuse-safe creation signature for live `pid`, or `None` if dead."""
    if not isinstance(pid, int) or pid <= 0:
        return None
    if os.name == "nt":
        handle = _k32.OpenProcess(_PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not handle:
            err = ctypes.get_last_error()
            if err == 5:  # ERROR_ACCESS_DENIED -> process exists under another elevation
                return f"win:{pid}:elevated"
            return None
        try:
            code = wintypes.DWORD(0)
            if not _k32.GetExitCodeProcess(handle, ctypes.byref(code)) or int(code.value) != _STILL_ACTIVE:
                return None
            c_time, e_time, k_time, u_time = _FILETIME(), _FILETIME(), _FILETIME(), _FILETIME()
            if not _k32.GetProcessTimes(
                handle,
                ctypes.byref(c_time),
                ctypes.byref(e_time),
                ctypes.byref(k_time),
                ctypes.byref(u_time),
            ):
                return f"win:{pid}:alive"
            ticks = (int(c_time.dwHighDateTime) << 32) | int(c_time.dwLowDateTime)
            return f"win:{pid}:{ticks}"
        finally:
            _k32.CloseHandle(handle)

    if sys.platform.startswith("linux"):
        stat_file = Path(f"/proc/{pid}/stat")
        try:
            raw = stat_file.read_text(encoding="utf-8", errors="replace")
        except TimeoutError:
            raise
        except OSError:
            return None
        rparen = raw.rfind(")")
        if rparen < 0:
            return None
        fields = raw[rparen + 2 :].split()
        if len(fields) < 20 or fields[0] == "Z":
            return None
        return f"linux:{pid}:{fields[19]}"

    # POSIX / macOS: check existence via os.kill(pid, 0) first
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return None
    except PermissionError:
        return f"posix:{pid}:perm"
    except TimeoutError:
        raise
    except OSError:
        return None

    try:
        proc = subprocess.run(
            ["ps", "-o", "lstart=", "-p", str(pid)],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=2.0,
            check=False,
        )
        started = (proc.stdout or "").strip()
        if proc.returncode == 0 and started:
            return f"posix:{pid}:{started}"
    except (OSError, subprocess.TimeoutExpired):
        pass
    return f"posix:{pid}:alive"


_SELF_PID = os.getpid()
_SELF_BOOT_SIG = process_boot_signature(_SELF_PID) or f"self:{_SELF_PID}:{uuid.uuid4().hex[:8]}"


def is_owner_alive(owner_pid: int, owner_boot_sig: str) -> bool:
    """Fast PID-reuse-safe liveness check (`0` syscalls for current process)."""
    if owner_pid == _SELF_PID and owner_boot_sig == _SELF_BOOT_SIG:
        return True
    current_sig = process_boot_signature(owner_pid)
    if current_sig is None:
        return False
    return current_sig == owner_boot_sig


@contextmanager
def _hold_init_lock(lock: threading.Lock, *, deadline: float | None = None) -> Iterator[None]:
    if deadline is None:
        lock.acquire()
    else:
        rem = deadline - time.monotonic()
        if rem <= 0 or not lock.acquire(timeout=rem):
            raise TimeoutError("Timed out waiting for SQLite schema initialization lock")
    try:
        yield
    finally:
        lock.release()


class RemoteReceipts:
    """SQLite WAL ledger preventing duplicate replay of mutating MCP requests."""

    def __init__(
        self,
        db_path: str | Path,
        *,
        max_concurrent: int = MAX_CONCURRENT_MUTATIONS_PER_SESSION,
    ) -> None:
        self.db_path = Path(db_path)
        self.max_concurrent = max(1, int(max_concurrent))
        self.owner_pid = _SELF_PID
        self.owner_boot_sig = _SELF_BOOT_SIG
        self._init_lock = threading.Lock()
        self._initialized = False

    def _ensure_initialized(self, *, deadline: float | None = None) -> None:
        if self._initialized and self.db_path.is_file():
            return
        with _hold_init_lock(self._init_lock, deadline=deadline):
            if self._initialized and self.db_path.is_file():
                return
            init_conn = open_wal_database(self.db_path, create=True, deadline=deadline)
            assert init_conn is not None
            try:
                init_conn.isolation_level = None
                init_conn.execute("BEGIN IMMEDIATE")
                try:
                    init_conn.execute(
                        "CREATE TABLE IF NOT EXISTS authority("
                        "identity TEXT PRIMARY KEY, schema TEXT NOT NULL)"
                    )
                    row = init_conn.execute("SELECT identity, schema FROM authority LIMIT 1").fetchone()
                    if row is None:
                        init_conn.execute(
                            "INSERT INTO authority(identity, schema) VALUES(?, ?)",
                            (uuid.uuid4().hex, RECEIPTS_SCHEMA_V2),
                        )
                    elif row[1] not in {RECEIPTS_SCHEMA_V1, RECEIPTS_SCHEMA_V2}:
                        raise HarnessError(
                            f"Unsupported receipt schema {row[1]!r} in {self.db_path}",
                            stage="receipt_open",
                            reason="receipt_schema_mismatch",
                        )
                    init_conn.execute(
                        "CREATE TABLE IF NOT EXISTS receipts_v2("
                        "call_id TEXT PRIMARY KEY, "
                        "session TEXT NOT NULL, "
                        "tool TEXT NOT NULL, "
                        "args_sha256 TEXT NOT NULL, "
                        "status TEXT NOT NULL, "
                        "owner_pid INTEGER NOT NULL, "
                        "owner_boot_sig TEXT NOT NULL, "
                        "started REAL NOT NULL, "
                        "updated REAL NOT NULL)"
                    )
                    init_conn.execute(
                        "CREATE INDEX IF NOT EXISTS idx_receipts_v2_running "
                        "ON receipts_v2(session, status) WHERE status='running'"
                    )
                    # Reconcile any legacy v1 `attempts` running rows once on upgrade
                    has_v1 = init_conn.execute(
                        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='attempts'"
                    ).fetchone()
                    if has_v1:
                        init_conn.execute("UPDATE attempts SET status='unknown' WHERE status='running'")
                    init_conn.execute("COMMIT")
                except BaseException:
                    try:
                        init_conn.execute("ROLLBACK")
                    except sqlite3.Error:
                        pass
                    raise
            finally:
                init_conn.close()
            self._initialized = True

    def _connect(self, *, deadline: float | None = None) -> sqlite3.Connection:
        self._ensure_initialized(deadline=deadline)
        conn = open_wal_database(self.db_path, create=True, deadline=deadline)
        assert conn is not None
        return conn

    def claim(
        self,
        call_id: str,
        *,
        session: str,
        tool: str,
        args_sha256: str,
        deadline: float | None = None,
    ) -> bool:
        """Atomically claim `call_id`; returns `False` if already recorded."""
        conn = self._connect(deadline=deadline)
        try:
            conn.isolation_level = None
            conn.execute("BEGIN IMMEDIATE")
            try:
                running_owners = conn.execute(
                    "SELECT DISTINCT owner_pid, owner_boot_sig FROM receipts_v2 WHERE status='running'"
                ).fetchall()
                now = time.time()
                for opid, osig in running_owners:
                    if not is_owner_alive(int(opid), str(osig)):
                        conn.execute(
                            "UPDATE receipts_v2 SET status='unknown', updated=? "
                            "WHERE status='running' AND owner_pid=? AND owner_boot_sig=?",
                            (now, int(opid), str(osig)),
                        )

                if conn.execute("SELECT 1 FROM receipts_v2 WHERE call_id=?", (call_id,)).fetchone():
                    conn.execute("COMMIT")
                    return False

                in_flight = conn.execute(
                    "SELECT COUNT(*) FROM receipts_v2 WHERE session=? AND status='running'",
                    (session,),
                ).fetchone()[0]
                if int(in_flight) >= self.max_concurrent:
                    conn.execute("ROLLBACK")
                    raise HarnessError(
                        f"Session {session!r} already has {in_flight} running mutations (cap={self.max_concurrent})",
                        stage="admission",
                        reason="remote_concurrency_limit",
                        submission_state="not_sent",
                        retryable=True,
                        reportable=False,
                    )

                conn.execute(
                    "INSERT INTO receipts_v2("
                    "call_id, session, tool, args_sha256, status, owner_pid, owner_boot_sig, started, updated"
                    ") VALUES(?, ?, ?, ?, 'running', ?, ?, ?, ?)",
                    (
                        call_id,
                        session,
                        tool,
                        args_sha256,
                        self.owner_pid,
                        self.owner_boot_sig,
                        now,
                        now,
                    ),
                )
                conn.execute("COMMIT")
                return True
            except BaseException:
                try:
                    conn.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
                raise
        finally:
            conn.close()

    def finish(self, call_id: str, outcome: str, *, deadline: float | None = None) -> None:
        if outcome not in {"succeeded", "failed", "unknown"}:
            raise ValueError(f"Invalid receipt outcome: {outcome!r}")
        conn = self._connect(deadline=deadline)
        try:
            with conn:
                cur = conn.execute(
                    "UPDATE receipts_v2 SET status=?, updated=? "
                    "WHERE call_id=? AND status='running' AND owner_pid=? AND owner_boot_sig=?",
                    (outcome, time.time(), call_id, self.owner_pid, self.owner_boot_sig),
                )
                if cur.rowcount != 1:
                    raise HarnessError(
                        f"Receipt {call_id!r} is no longer owned by this running worker",
                        stage="receipt_finish",
                        reason="receipt_ownership_lost",
                    )
        finally:
            conn.close()


class BindStore:
    """Optional one-shot `PreToolUse` correlation ledger (`mcp-binds.sqlite3`)."""

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)
        self._init_lock = threading.Lock()
        self._initialized = False

    def _ensure_initialized(self, *, deadline: float | None = None) -> None:
        if self._initialized and self.db_path.is_file():
            return
        with _hold_init_lock(self._init_lock, deadline=deadline):
            if self._initialized and self.db_path.is_file():
                return
            init_conn = open_wal_database(self.db_path, create=True, deadline=deadline)
            assert init_conn is not None
            try:
                init_conn.isolation_level = None
                init_conn.execute("BEGIN IMMEDIATE")
                try:
                    init_conn.execute(
                        "CREATE TABLE IF NOT EXISTS binds("
                        "bind_id TEXT PRIMARY KEY, "
                        "session TEXT NOT NULL, "
                        "surface TEXT NOT NULL, "
                        "tool TEXT NOT NULL, "
                        "args_digest TEXT NOT NULL, "
                        "cwd TEXT, "
                        "status TEXT NOT NULL, "
                        "created REAL NOT NULL, "
                        "updated REAL NOT NULL)"
                    )
                    init_conn.execute(
                        "CREATE INDEX IF NOT EXISTS idx_binds_lookup "
                        "ON binds(tool, args_digest, status, created)"
                    )
                    init_conn.execute("COMMIT")
                except BaseException:
                    try:
                        init_conn.execute("ROLLBACK")
                    except sqlite3.Error:
                        pass
                    raise
            finally:
                init_conn.close()
            self._initialized = True

    def _connect(self, *, create: bool, deadline: float | None = None) -> sqlite3.Connection | None:
        if create:
            self._ensure_initialized(deadline=deadline)
        return open_wal_database(self.db_path, create=create, deadline=deadline)

    def publish_bind(
        self,
        bind_id: str,
        *,
        session: str,
        surface: str,
        tool: str,
        args_digest: str,
        cwd: str | None = None,
        deadline: float | None = None,
    ) -> None:
        conn = self._connect(create=True, deadline=deadline)
        assert conn is not None
        now = time.time()
        try:
            with conn:
                conn.execute(
                    "DELETE FROM binds WHERE bind_id IN ("
                    "SELECT bind_id FROM binds WHERE status != 'claimed' AND (? - updated) > ? LIMIT 64)",
                    (now, BIND_TTL_SECONDS),
                )
                conn.execute(
                    "INSERT OR REPLACE INTO binds("
                    "bind_id, session, surface, tool, args_digest, cwd, status, created, updated"
                    ") VALUES(?, ?, ?, ?, ?, ?, 'bound', ?, ?)",
                    (bind_id, session, surface, tool, args_digest, cwd, now, now),
                )
        finally:
            conn.close()

    def claim_bind(
        self,
        *,
        bind_id: str | None = None,
        session: str | None = None,
        tool: str,
        args_digest: str,
        deadline: float | None = None,
    ) -> dict[str, Any] | None:
        if not self.db_path.is_file():
            return None
        conn = self._connect(create=True, deadline=deadline)
        if conn is None:
            return None
        now = time.time()
        try:
            conn.isolation_level = None
            conn.execute("BEGIN IMMEDIATE")
            try:
                row = None
                if bind_id:
                    if session:
                        row = conn.execute(
                            "SELECT bind_id, session, cwd FROM binds "
                            "WHERE bind_id=? AND session=? AND status='bound' AND (? - created) <= ?",
                            (bind_id, session, now, BIND_TTL_SECONDS),
                        ).fetchone()
                    else:
                        row = conn.execute(
                            "SELECT bind_id, session, cwd FROM binds "
                            "WHERE bind_id=? AND status='bound' AND (? - created) <= ?",
                            (bind_id, now, BIND_TTL_SECONDS),
                        ).fetchone()
                elif session:
                    rows = conn.execute(
                        "SELECT bind_id, session, cwd FROM binds "
                        "WHERE session=? AND tool=? AND args_digest=? AND status='bound' AND (? - created) <= ? "
                        "ORDER BY created DESC LIMIT 2",
                        (session, tool, args_digest, now, BIND_TTL_SECONDS),
                    ).fetchall()
                    if len(rows) == 1 or (len(rows) == 2 and (rows[0][2] or "") == (rows[1][2] or "")):
                        row = rows[0]
                if row is None:
                    conn.execute("COMMIT")
                    return None
                conn.execute(
                    "UPDATE binds SET status='claimed', updated=? WHERE bind_id=?",
                    (now, row[0]),
                )
                conn.execute("COMMIT")
                return {"bind_id": str(row[0]), "session": str(row[1]), "cwd": row[2]}
            except BaseException:
                try:
                    conn.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
                raise
        finally:
            conn.close()

    def finish_bind(self, bind_id: str, status: str, *, deadline: float | None = None) -> None:
        conn = self._connect(create=True, deadline=deadline)
        assert conn is not None
        try:
            with conn:
                conn.execute(
                    "UPDATE binds SET status=?, updated=? WHERE bind_id=?",
                    (status, time.time(), bind_id),
                )
        finally:
            conn.close()


def apply_receipt_honesty(result: dict[str, Any], receipt_exc: BaseException) -> dict[str, Any]:
    """Attach `receipt_warning` + `receipt_unconfirmed=True` while preserving `isError=False`."""
    warning_msg = f"{type(receipt_exc).__name__}: {receipt_exc}"
    updated = dict(result)
    if updated.get("isError") is not True:
        updated["isError"] = False
    updated["receipt_unconfirmed"] = True
    updated["receipt_warning"] = warning_msg
    structured = updated.get("structuredContent")
    if isinstance(structured, dict):
        updated["structuredContent"] = {
            **structured,
            "receipt_unconfirmed": True,
            "receipt_warning": warning_msg,
        }
    else:
        updated["structuredContent"] = {
            "receipt_unconfirmed": True,
            "receipt_warning": warning_msg,
        }
    content = list(updated.get("content") or [])
    content.append(
        {
            "type": "text",
            "text": (
                f"Primary operation completed; local receipt accounting failed ({warning_msg}). "
                "Do not automatically replay this operation."
            ),
        }
    )
    updated["content"] = content
    return updated
