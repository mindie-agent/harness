"""Cross-platform file locks and Windows non-`FILE_SHARE_DELETE` `.inuse` generation leases.

[Role]
Provides bounded shared/exclusive OS file locks (`FileLock`, `exclusive_lock`,
`shared_lock`), `LockTimeoutError` (`reportable=False` contention classification),
and crash-safe runtime generation leases (`GenerationLease`, `acquire_generation_lease`,
`is_generation_leased`, `acquire_retirement_guard`).

[Invariants]
- On Windows (`os.name == "nt"`), `acquire_generation_lease` opens
  `<gen_dir>\\.inuse.<pid>.<uuid>.lease` via `CreateFileW` with
  `dwShareMode = FILE_SHARE_READ | FILE_SHARE_WRITE` (omitting `FILE_SHARE_DELETE`!).
  While the owning process lives, NTFS atomically blocks any `os.replace(gen_dir, .trash)`
  or `DeleteFileW` on the lease—even when `uv`'s `.venv\\Scripts\\python.exe` trampoline
  spawns a global base `python.exe` outside `<gen_dir>`. On crash, the kernel closes
  the handle automatically.
- `acquire_retirement_guard` on Windows locks ONLY the sibling `<parent>/.retire.lock`
  and holds ZERO descriptors inside `gen_dir` so NTFS directory rename can succeed.

[Timeouts & Locks]
- `exclusive_lock` / `shared_lock` poll non-blocking OS locks up to monotonic `timeout`
  (`default 5.0s`), raising `LockTimeoutError(TimeoutError)` when contended.

[Side-Effect Policy]
- Creates only `.lock` sidecars and `.inuse.<pid>.<uuid>.lease` files inside existing
  managed directories; cleans up `.lease` files on normal context exit.
"""
from __future__ import annotations

import contextlib
import errno
import os
from pathlib import Path
import stat
import time
import uuid
from typing import Iterator

from .atomic import TRASH_PREFIXES

if os.name == "nt":
    import ctypes
    from ctypes import wintypes
    import msvcrt

    _GENERIC_READ = 0x80000000
    _GENERIC_WRITE = 0x40000000
    _FILE_SHARE_READ = 0x00000001
    _FILE_SHARE_WRITE = 0x00000002
    # Intentionally omit FILE_SHARE_DELETE (0x00000004) for .inuse leases!
    _OPEN_ALWAYS = 4
    _FILE_ATTRIBUTE_NORMAL = 0x00000080
    _INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
    _LOCKFILE_FAIL_IMMEDIATELY = 0x00000001
    _LOCKFILE_EXCLUSIVE_LOCK = 0x00000002

    class _OVERLAPPED(ctypes.Structure):
        _fields_ = [
            ("Internal", ctypes.c_size_t),
            ("InternalHigh", ctypes.c_size_t),
            ("Offset", wintypes.DWORD),
            ("OffsetHigh", wintypes.DWORD),
            ("hEvent", wintypes.HANDLE),
        ]

    class _SECURITY_ATTRIBUTES(ctypes.Structure):
        _fields_ = [
            ("nLength", wintypes.DWORD),
            ("lpSecurityDescriptor", ctypes.c_void_p),
            ("bInheritHandle", wintypes.BOOL),
        ]

    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(_SECURITY_ATTRIBUTES),
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    _kernel32.CreateFileW.restype = wintypes.HANDLE
    _kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    _kernel32.CloseHandle.restype = wintypes.BOOL
    _kernel32.LockFileEx.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(_OVERLAPPED),
    ]
    _kernel32.LockFileEx.restype = wintypes.BOOL
    _kernel32.UnlockFileEx.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(_OVERLAPPED),
    ]
    _kernel32.UnlockFileEx.restype = wintypes.BOOL
else:
    import fcntl


LEASE_LOCK_NAME = ".inuse.lock"
SIBLING_RETIRE_LOCK_NAME = ".mindie-retire.lock"


class LockTimeoutError(TimeoutError):
    """Raised on lock contention; classified as `deferred` (`reportable=False`, `#362`)."""

    def __init__(self, path: str | Path, timeout: float) -> None:
        self.path = Path(path)
        self.timeout = float(timeout)
        self.stage = "lock"
        self.reason = "lock_timeout"
        self.retryable = True
        self.reportable = False
        super().__init__(
            f"{self.path} is locked by another process for more than {self.timeout:g}s"
        )


def _try_lock_fd(fd: int, *, exclusive: bool) -> bool:
    if os.name == "nt":
        handle = msvcrt.get_osfhandle(fd)
        flags = _LOCKFILE_FAIL_IMMEDIATELY | (_LOCKFILE_EXCLUSIVE_LOCK if exclusive else 0)
        overlapped = _OVERLAPPED()
        ok = _kernel32.LockFileEx(handle, flags, 0, 1, 0, ctypes.byref(overlapped))
        if ok:
            return True
        err = ctypes.get_last_error()
        if err in {5, 32, 33}:  # ACCESS_DENIED, SHARING_VIOLATION, LOCK_VIOLATION
            return False
        raise ctypes.WinError(err)
    flags = (fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH) | fcntl.LOCK_NB
    try:
        fcntl.flock(fd, flags)
        return True
    except BlockingIOError:
        return False
    except TimeoutError:
        raise
    except OSError as exc:
        if exc.errno in {errno.EACCES, errno.EAGAIN, errno.EWOULDBLOCK}:
            return False
        raise


def _unlock_fd(fd: int) -> None:
    if os.name == "nt":
        handle = msvcrt.get_osfhandle(fd)
        overlapped = _OVERLAPPED()
        _kernel32.UnlockFileEx(handle, 0, 1, 0, ctypes.byref(overlapped))
    else:
        fcntl.flock(fd, fcntl.LOCK_UN)


class FileLock:
    """Reusable cross-platform OS file lock."""

    def __init__(
        self,
        path: str | Path,
        *,
        exclusive: bool = True,
        timeout: float | None = 5.0,
    ) -> None:
        self.path = Path(path)
        self.exclusive = bool(exclusive)
        self.timeout = 0.0 if timeout is None else max(0.0, float(timeout))
        self._fd: int | None = None

    def acquire(self) -> "FileLock":
        if self._fd is not None:
            return self
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(str(self.path), os.O_CREAT | os.O_RDWR, 0o600)
        deadline = time.monotonic() + self.timeout
        sleep_step = 0.01
        try:
            while True:
                if _try_lock_fd(fd, exclusive=self.exclusive):
                    self._fd = fd
                    return self
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise LockTimeoutError(self.path, self.timeout)
                time.sleep(min(sleep_step, remaining))
                sleep_step = min(0.1, sleep_step * 1.5)
        except BaseException:
            os.close(fd)
            raise

    def release(self) -> None:
        fd, self._fd = self._fd, None
        if fd is None:
            return
        try:
            try:
                _unlock_fd(fd)
            except TimeoutError:
                raise
            except OSError:
                pass
        finally:
            os.close(fd)

    def __enter__(self) -> "FileLock":
        return self.acquire()

    def __exit__(self, *_exc: object) -> None:
        self.release()


@contextlib.contextmanager
def exclusive_lock(path: str | Path, *, timeout: float = 5.0) -> Iterator[FileLock]:
    """Acquire an exclusive lock on `path` (or `<target>.lock` when passed a lock path)."""
    lock_path = Path(path)
    with FileLock(lock_path, exclusive=True, timeout=timeout) as lock:
        yield lock


@contextlib.contextmanager
def shared_lock(path: str | Path, *, timeout: float = 5.0) -> Iterator[FileLock]:
    """Acquire a shared reader lock on `path`."""
    lock_path = Path(path)
    with FileLock(lock_path, exclusive=False, timeout=timeout) as lock:
        yield lock


class GenerationLease:
    """Crash-safe active lease on a runtime generation directory."""

    def __init__(
        self,
        directory: Path,
        *,
        lease_path: Path,
        win_handle: int | None = None,
        posix_fd: int | None = None,
    ) -> None:
        self.directory = directory
        self.lease_path = lease_path
        self._win_handle = win_handle
        self._posix_fd = posix_fd

    @property
    def active(self) -> bool:
        return self._win_handle is not None or self._posix_fd is not None

    def release(self) -> None:
        win_h, self._win_handle = self._win_handle, None
        pos_fd, self._posix_fd = self._posix_fd, None
        try:
            if win_h is not None and os.name == "nt":
                _kernel32.CloseHandle(win_h)
            if pos_fd is not None:
                try:
                    _unlock_fd(pos_fd)
                except TimeoutError:
                    raise
                except OSError:
                    pass
                os.close(pos_fd)
        finally:
            if win_h is not None or pos_fd is not None:
                try:
                    self.lease_path.unlink(missing_ok=True)
                except TimeoutError:
                    raise
                except OSError:
                    pass

    def __enter__(self) -> "GenerationLease":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.release()


def acquire_generation_lease(generation_dir: str | Path) -> GenerationLease:
    """Open a non-`FILE_SHARE_DELETE` (Win32) or `flock(LOCK_SH)` (POSIX) `.inuse` lease."""
    directory = Path(generation_dir)
    if any(directory.name.startswith(pref) for pref in TRASH_PREFIXES):
        raise RuntimeError(f"Refusing to acquire lease on retired directory {directory}")
    before = os.stat(directory)
    if not stat.S_ISDIR(before.st_mode):
        raise NotADirectoryError(str(directory))

    lease_name = f".inuse.{os.getpid()}.{uuid.uuid4().hex[:12]}.lease"
    lease_path = directory / lease_name

    if os.name == "nt":
        sec = _SECURITY_ATTRIBUTES()
        sec.nLength = ctypes.sizeof(_SECURITY_ATTRIBUTES)
        sec.lpSecurityDescriptor = None
        sec.bInheritHandle = False
        handle = _kernel32.CreateFileW(
            str(lease_path),
            _GENERIC_READ | _GENERIC_WRITE,
            _FILE_SHARE_READ | _FILE_SHARE_WRITE,  # NO FILE_SHARE_DELETE!
            ctypes.byref(sec),
            _OPEN_ALWAYS,
            _FILE_ATTRIBUTE_NORMAL,
            None,
        )
        if not handle or handle == _INVALID_HANDLE_VALUE:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            after = os.stat(directory)
            if not stat.S_ISDIR(after.st_mode):
                raise RuntimeError("Generation directory vanished during lease acquisition")
        except BaseException:
            _kernel32.CloseHandle(handle)
            try:
                lease_path.unlink(missing_ok=True)
            except TimeoutError:
                raise
            except OSError:
                pass
            raise
        return GenerationLease(directory, lease_path=lease_path, win_handle=int(handle))

    retire_guard = FileLock(
        directory.parent / SIBLING_RETIRE_LOCK_NAME,
        exclusive=False,
        timeout=5.0,
    )
    retire_guard.acquire()
    try:
        locked_stat = os.stat(directory)
        if not stat.S_ISDIR(locked_stat.st_mode) or (locked_stat.st_dev, locked_stat.st_ino) != (
            before.st_dev,
            before.st_ino,
        ):
            raise RuntimeError("Generation directory moved to .trash during lease acquisition")
        fd = os.open(str(lease_path), os.O_CREAT | os.O_RDWR, 0o600)
        try:
            if not _try_lock_fd(fd, exclusive=False):
                raise RuntimeError(f"Generation {directory} is currently retiring")
            after = os.stat(directory)
            if not stat.S_ISDIR(after.st_mode) or (after.st_dev, after.st_ino) != (
                before.st_dev,
                before.st_ino,
            ):
                raise RuntimeError("Generation directory moved to .trash during lease acquisition")
            return GenerationLease(directory, lease_path=lease_path, posix_fd=fd)
        except BaseException:
            os.close(fd)
            try:
                lease_path.unlink(missing_ok=True)
            except TimeoutError:
                raise
            except OSError:
                pass
            raise
    finally:
        retire_guard.release()


def is_generation_leased(generation_dir: str | Path) -> bool:
    """Return True if any live `.inuse.*.lease` or `.inuse.lock` is held in `generation_dir`, cleaning dead tombstones."""
    directory = Path(generation_dir)
    if not directory.is_dir():
        return False
    try:
        entries = [
            Path(e.path)
            for e in os.scandir(directory)
            if (e.name.startswith(".inuse.") and e.name.endswith(".lease"))
            or e.name == LEASE_LOCK_NAME
        ]
    except TimeoutError:
        raise
    except OSError:
        return True

    for item in entries:
        if os.name == "nt":
            if item.name == LEASE_LOCK_NAME:
                continue
            try:
                item.unlink()
            except FileNotFoundError:
                continue
            except TimeoutError:
                raise
            except OSError:
                # Non-FILE_SHARE_DELETE handle is still open in a live process!
                return True
        else:
            try:
                fd = os.open(str(item), os.O_RDWR)
            except FileNotFoundError:
                continue
            except TimeoutError:
                raise
            except OSError:
                return True
            try:
                if not _try_lock_fd(fd, exclusive=True):
                    return True
                try:
                    if item.name.endswith(".lease"):
                        item.unlink(missing_ok=True)
                finally:
                    _unlock_fd(fd)
            finally:
                os.close(fd)
    return False


@contextlib.contextmanager
def acquire_retirement_guard(generation_dir: str | Path) -> Iterator[bool]:
    """Acquire non-blocking retirement serialization without opening handles inside `generation_dir` on Windows."""
    directory = Path(generation_dir)
    sibling_lock = FileLock(
        directory.parent / SIBLING_RETIRE_LOCK_NAME,
        exclusive=True,
        timeout=0.0,
    )
    try:
        sibling_lock.acquire()
    except LockTimeoutError:
        yield False
        return
    try:
        if is_generation_leased(directory):
            yield False
            return
        yield True
    finally:
        sibling_lock.release()
