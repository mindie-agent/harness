"""Windows 11 zero-popup `CreateProcessW`, nested Job Objects, and PE `Subsystem == 2` guard.

[Role]
Implements cross-platform PE header inspection (`read_pe_subsystem`, `verify_gui_subsystem`,
`repair_venv_pythonw_if_needed`), current-process Job constraint probing (`probe_current_job`),
GUI null-stdio safety (`ensure_valid_stdio_streams`), and pure-`ctypes` `CreateProcessW`
supervision (`run_win32`) attaching a non-inheritable nested Job Object BEFORE `ResumeThread`.

[Invariants]
- `CreateProcessW` ALWAYS passes `CREATE_SUSPENDED | CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT | CREATE_NEW_PROCESS_GROUP`
  and NEVER passes `CREATE_NEW_CONSOLE` (`0x10`) or `DETACHED_PROCESS` (`0x08`), which
  would silently nullify `CREATE_NO_WINDOW` and flash `conhost.exe`.
- Every child is assigned while still suspended (`0` instructions run, `0` escaped
  grandchildren) to a nested Job with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, optional
  `JOB_OBJECT_LIMIT_JOB_MEMORY` (default `512 MiB`), optional `JOB_OBJECT_LIMIT_BREAKAWAY_OK`
  when `spec.allow_daemon_breakaway` is requested, `BELOW_NORMAL_PRIORITY_CLASS` for
  background maintenance, and best-effort `JobObjectCpuRateControlInformation`.
- `repair_venv_pythonw_if_needed` heals `uv <= 0.12.3` `Subsystem == 3` venv `pythonw.exe`
  launchers from base CPython `venvwlauncher.exe` (`Subsystem == 2`).

[Timeouts & Locks]
- Pipe handle creation + `CreateProcessW(bInheritHandles=True)` is serialized under
  `_SPAWN_LOCK` so concurrent threads never leak inheritable pipe handles across children.

[Side-Effect Policy]
- Any failure prior to `ResumeThread` immediately calls `TerminateProcess` and closes
  all Job, process, thread, and pipe handles (`0` zombie processes or handle leaks).
"""
from __future__ import annotations

import configparser
from dataclasses import dataclass
import io
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import threading
import time
from typing import IO, Any
import uuid

from ..paths import HarnessError
from .supervisor import (
    Deadline,
    OutputLimitError,
    ProcessCancelledError,
    ProcessOutcome,
    ProcessSpec,
    build_child_env,
)

IMAGE_SUBSYSTEM_WINDOWS_GUI = 2
IMAGE_SUBSYSTEM_WINDOWS_CUI = 3
_PE_OPT_MAGICS = frozenset({0x10B, 0x20B})  # PE32, PE32+
CREATE_SUSPENDED = 0x00000004
DETACHED_PROCESS = 0x00000008
CREATE_NEW_CONSOLE = 0x00000010
CREATE_NEW_PROCESS_GROUP = 0x00000200
CREATE_UNICODE_ENVIRONMENT = 0x00000400
CREATE_NO_WINDOW = 0x08000000
FORBIDDEN_CREATION_FLAGS = CREATE_NEW_CONSOLE | DETACHED_PROCESS

BELOW_NORMAL_PRIORITY_CLASS = 0x00004000
JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9
JOB_OBJECT_CPU_RATE_CONTROL_INFORMATION = 15
JOB_OBJECT_LIMIT_PRIORITY_CLASS = 0x00000020
JOB_OBJECT_LIMIT_JOB_MEMORY = 0x00000200
JOB_OBJECT_LIMIT_BREAKAWAY_OK = 0x00000800
JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK = 0x00001000
JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
JOB_OBJECT_CPU_RATE_CONTROL_ENABLE = 0x00000001
JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP = 0x00000004
STARTF_USESTDHANDLES = 0x00000100
HANDLE_FLAG_INHERIT = 0x00000001
WAIT_OBJECT_0 = 0x00000000
WAIT_TIMEOUT = 0x00000102
ERROR_BROKEN_PIPE = 109
ERROR_HANDLE_EOF = 38

_SPAWN_LOCK = threading.Lock()


@dataclass(frozen=True)
class JobConstraintReport:
    """Measured Job Object constraints on the current host process."""

    in_job: bool
    breakaway_ok: bool
    memory_limit_bytes: int | None
    cpu_rate_capped: bool


def read_pe_subsystem(exe_path: str | Path) -> int:
    """Read `IMAGE_OPTIONAL_HEADER.Subsystem` directly from a Windows PE executable."""
    target = Path(exe_path)
    try:
        with target.open("rb") as stream:
            dos = stream.read(64)
            if len(dos) < 64 or dos[:2] != b"MZ":
                raise ValueError("missing MZ DOS header")
            pe_offset = struct.unpack_from("<I", dos, 0x3C)[0]
            if pe_offset < 64 or pe_offset > 16 * 1024 * 1024:
                raise ValueError("invalid e_lfanew offset")
            stream.seek(pe_offset)
            pe_hdr = stream.read(24)
            if len(pe_hdr) < 24 or pe_hdr[:4] != b"PE\x00\x00":
                raise ValueError("missing PE\\0\\0 signature")
            opt_size = struct.unpack_from("<H", pe_hdr, 20)[0]
            if opt_size < 70:
                raise ValueError("PE OptionalHeader smaller than 70 bytes")
            optional = stream.read(70)
            if len(optional) < 70:
                raise ValueError("truncated PE OptionalHeader")
            magic = struct.unpack_from("<H", optional, 0)[0]
            if magic not in _PE_OPT_MAGICS:
                raise ValueError(f"unsupported PE OptionalHeader magic 0x{magic:04x}")
            return int(struct.unpack_from("<H", optional, 68)[0])
    except TimeoutError:
        raise
    except (OSError, ValueError) as exc:
        raise HarnessError(
            f"Executable {target} is not a valid Windows PE binary: {exc}",
            stage="pe_verify",
            reason="windowless_interpreter_invalid",
            retryable=False,
            reportable=False,
            details={"path": str(target)},
        ) from exc


def _resolve_pyvenv_base_pythonw(exe_path: Path) -> Path | None:
    """Locate base `home\\pythonw.exe` when `exe_path` lives inside a `uv`/venv `Scripts` dir."""
    for cfg in (exe_path.parent.parent / "pyvenv.cfg", exe_path.parent / "pyvenv.cfg"):
        try:
            if not cfg.is_file():
                continue
            raw = cfg.read_text(encoding="utf-8-sig", errors="replace")
        except TimeoutError:
            raise
        except OSError:
            continue
        parser = configparser.ConfigParser()
        try:
            parser.read_string("[pyvenv]\n" + raw)
            home_val = parser.get("pyvenv", "home", fallback="").strip()
        except configparser.Error:
            home_val = ""
        if home_val:
            return Path(home_val) / "pythonw.exe"
    return None


def repair_venv_pythonw_if_needed(
    venv_dir: str | Path,
    base_python: str | Path | None = None,
) -> Path | None:
    """Repair `uv <= 0.12.3` CUI (`Subsystem == 3`) `.venv\\Scripts\\pythonw.exe` using CPython `venvwlauncher.exe`."""
    if os.name != "nt":
        return None
    vdir = Path(venv_dir)
    pyw = vdir / "Scripts" / "pythonw.exe"
    if pyw.is_file():
        try:
            if read_pe_subsystem(pyw) == IMAGE_SUBSYSTEM_WINDOWS_GUI:
                return pyw
        except HarnessError:
            pass

    base_pyw = _resolve_pyvenv_base_pythonw(pyw)
    base_home = (
        base_pyw.parent
        if base_pyw is not None
        else (Path(base_python).parent if base_python is not None else Path(sys.base_prefix))
    )
    launcher = base_home / "Lib" / "venv" / "scripts" / "nt" / "venvwlauncher.exe"
    source_gui: Path | None = None
    if launcher.is_file() and read_pe_subsystem(launcher) == IMAGE_SUBSYSTEM_WINDOWS_GUI:
        source_gui = launcher

    tmp_dir_obj: tempfile.TemporaryDirectory[str] | None = None
    try:
        if source_gui is None:
            base_py = base_home / "python.exe"
            if base_py.is_file():
                tmp_dir_obj = tempfile.TemporaryDirectory(prefix="mindie-pyw-")
                donor_venv = Path(tmp_dir_obj.name) / "venv"
                subprocess.run(
                    [str(base_py), "-I", "-m", "venv", "--without-pip", str(donor_venv)],
                    stdin=subprocess.DEVNULL,
                    capture_output=True,
                    timeout=30.0,
                    check=False,
                    creationflags=CREATE_NO_WINDOW,
                )
                donor_pyw = donor_venv / "Scripts" / "pythonw.exe"
                if donor_pyw.is_file() and read_pe_subsystem(donor_pyw) == IMAGE_SUBSYSTEM_WINDOWS_GUI:
                    source_gui = donor_pyw

        if source_gui is None:
            return pyw if pyw.is_file() else None

        pyw.parent.mkdir(parents=True, exist_ok=True)
        tmp_pyw = pyw.with_name(f".pythonw.repair.{os.getpid()}.{uuid.uuid4().hex[:8]}.exe")
        try:
            shutil.copyfile(source_gui, tmp_pyw)
            os.replace(tmp_pyw, pyw)
        finally:
            tmp_pyw.unlink(missing_ok=True)
        return pyw
    finally:
        if tmp_dir_obj is not None:
            tmp_dir_obj.cleanup()


def verify_gui_subsystem(exe_path: str | Path) -> Path:
    """Verify `exe_path` (and any `pyvenv.cfg` base `pythonw.exe`) has `Subsystem == 2` (`WINDOWS_GUI`)."""
    target = Path(exe_path)
    if not target.is_file():
        raise HarnessError(
            f"Windowless GUI interpreter missing at {target}",
            stage="pe_verify",
            reason="windowless_interpreter_missing",
            retryable=False,
            reportable=False,
            details={"path": str(target)},
        )
    subsys = read_pe_subsystem(target)
    if subsys != IMAGE_SUBSYSTEM_WINDOWS_GUI:
        raise HarnessError(
            f"Interpreter {target} has PE Subsystem={subsys} (expected 2=WINDOWS_GUI; CUI=3 rejected)",
            stage="pe_verify",
            reason="windowless_interpreter_invalid",
            retryable=False,
            reportable=False,
            details={"path": str(target), "subsystem": subsys},
        )
    base_pythonw = _resolve_pyvenv_base_pythonw(target)
    if base_pythonw is not None:
        if not base_pythonw.is_file():
            raise HarnessError(
                f"Base pyvenv GUI interpreter missing at {base_pythonw}",
                stage="pe_verify",
                reason="windowless_interpreter_missing",
                retryable=False,
                reportable=False,
                details={"path": str(base_pythonw)},
            )
        base_subsys = read_pe_subsystem(base_pythonw)
        if base_subsys != IMAGE_SUBSYSTEM_WINDOWS_GUI:
            raise HarnessError(
                f"Base pyvenv interpreter {base_pythonw} has PE Subsystem={base_subsys} (expected 2=WINDOWS_GUI)",
                stage="pe_verify",
                reason="windowless_interpreter_invalid",
                retryable=False,
                reportable=False,
                details={"path": str(base_pythonw), "subsystem": base_subsys},
            )
    return target


def ensure_valid_stdio_streams() -> None:
    """Replace `None` `sys.stdin/stdout/stderr` in `pythonw.exe` GUI workers with safe null streams."""
    if sys.stdin is None:
        sys.stdin = io.StringIO("")
    if sys.stdout is None:
        sys.stdout = open(os.devnull, "w", encoding="utf-8")  # noqa: SIM115
    if sys.stderr is None:
        sys.stderr = open(os.devnull, "w", encoding="utf-8")  # noqa: SIM115


if os.name == "nt":
    import ctypes
    from ctypes import wintypes

    class _SECURITY_ATTRIBUTES(ctypes.Structure):
        _fields_ = [
            ("nLength", wintypes.DWORD),
            ("lpSecurityDescriptor", ctypes.c_void_p),
            ("bInheritHandle", wintypes.BOOL),
        ]

    class _STARTUPINFOW(ctypes.Structure):
        _fields_ = [
            ("cb", wintypes.DWORD),
            ("lpReserved", wintypes.LPWSTR),
            ("lpDesktop", wintypes.LPWSTR),
            ("lpTitle", wintypes.LPWSTR),
            ("dwX", wintypes.DWORD),
            ("dwY", wintypes.DWORD),
            ("dwXSize", wintypes.DWORD),
            ("dwYSize", wintypes.DWORD),
            ("dwXCountChars", wintypes.DWORD),
            ("dwYCountChars", wintypes.DWORD),
            ("dwFillAttribute", wintypes.DWORD),
            ("dwFlags", wintypes.DWORD),
            ("wShowWindow", wintypes.WORD),
            ("cbReserved2", wintypes.WORD),
            ("lpReserved2", ctypes.c_void_p),
            ("hStdInput", wintypes.HANDLE),
            ("hStdOutput", wintypes.HANDLE),
            ("hStdError", wintypes.HANDLE),
        ]

    class _PROCESS_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("hProcess", wintypes.HANDLE),
            ("hThread", wintypes.HANDLE),
            ("dwProcessId", wintypes.DWORD),
            ("dwThreadId", wintypes.DWORD),
        ]

    class _BASIC_LIMIT_INFO(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_int64),
            ("PerJobUserTimeLimit", ctypes.c_int64),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]

    class _IO_COUNTERS(ctypes.Structure):
        _fields_ = [
            ("ReadOperationCount", ctypes.c_uint64),
            ("WriteOperationCount", ctypes.c_uint64),
            ("OtherOperationCount", ctypes.c_uint64),
            ("ReadTransferCount", ctypes.c_uint64),
            ("WriteTransferCount", ctypes.c_uint64),
            ("OtherTransferCount", ctypes.c_uint64),
        ]

    class _EXTENDED_LIMIT_INFO(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", _BASIC_LIMIT_INFO),
            ("IoInfo", _IO_COUNTERS),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    class _CPU_RATE_CONTROL_INFO(ctypes.Structure):
        _fields_ = [("ControlFlags", wintypes.DWORD), ("CpuRate", wintypes.DWORD)]

    _k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _k32.GetCurrentProcess.argtypes = []
    _k32.GetCurrentProcess.restype = wintypes.HANDLE
    _k32.IsProcessInJob.argtypes = [wintypes.HANDLE, wintypes.HANDLE, ctypes.POINTER(wintypes.BOOL)]
    _k32.IsProcessInJob.restype = wintypes.BOOL
    _k32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
    _k32.CreateJobObjectW.restype = wintypes.HANDLE
    _k32.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    _k32.SetInformationJobObject.restype = wintypes.BOOL
    _k32.QueryInformationJobObject.argtypes = [
        wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
    ]
    _k32.QueryInformationJobObject.restype = wintypes.BOOL
    _k32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    _k32.AssignProcessToJobObject.restype = wintypes.BOOL
    _k32.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
    _k32.TerminateJobObject.restype = wintypes.BOOL
    _k32.CreatePipe.argtypes = [
        ctypes.POINTER(wintypes.HANDLE), ctypes.POINTER(wintypes.HANDLE), ctypes.POINTER(_SECURITY_ATTRIBUTES), wintypes.DWORD,
    ]
    _k32.CreatePipe.restype = wintypes.BOOL
    _k32.SetHandleInformation.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD]
    _k32.SetHandleInformation.restype = wintypes.BOOL
    _k32.CreateProcessW.argtypes = [
        wintypes.LPCWSTR, wintypes.LPWSTR, ctypes.c_void_p, ctypes.c_void_p, wintypes.BOOL,
        wintypes.DWORD, ctypes.c_void_p, wintypes.LPCWSTR, ctypes.POINTER(_STARTUPINFOW), ctypes.POINTER(_PROCESS_INFORMATION),
    ]
    _k32.CreateProcessW.restype = wintypes.BOOL
    _k32.ResumeThread.argtypes = [wintypes.HANDLE]
    _k32.ResumeThread.restype = wintypes.DWORD
    _k32.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
    _k32.TerminateProcess.restype = wintypes.BOOL
    _k32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    _k32.WaitForSingleObject.restype = wintypes.DWORD
    _k32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    _k32.GetExitCodeProcess.restype = wintypes.BOOL
    _k32.ReadFile.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
    _k32.ReadFile.restype = wintypes.BOOL
    _k32.WriteFile.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
    _k32.WriteFile.restype = wintypes.BOOL
    _k32.CloseHandle.argtypes = [wintypes.HANDLE]
    _k32.CloseHandle.restype = wintypes.BOOL


def probe_current_job() -> JobConstraintReport:
    """Query whether the current process runs inside a Windows Job Object and its limits."""
    if os.name != "nt":
        return JobConstraintReport(in_job=False, breakaway_ok=True, memory_limit_bytes=None, cpu_rate_capped=False)
    in_job = wintypes.BOOL(False)
    if not _k32.IsProcessInJob(_k32.GetCurrentProcess(), None, ctypes.byref(in_job)) or not in_job.value:
        return JobConstraintReport(in_job=False, breakaway_ok=True, memory_limit_bytes=None, cpu_rate_capped=False)
    ext = _EXTENDED_LIMIT_INFO()
    ret_len = wintypes.DWORD(0)
    breakaway_ok = False
    mem_limit: int | None = None
    if _k32.QueryInformationJobObject(
        None, JOB_OBJECT_EXTENDED_LIMIT_INFORMATION, ctypes.byref(ext), ctypes.sizeof(ext), ctypes.byref(ret_len),
    ):
        flags = int(ext.BasicLimitInformation.LimitFlags)
        breakaway_ok = bool(flags & (JOB_OBJECT_LIMIT_BREAKAWAY_OK | JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK))
        candidates = []
        if flags & 0x00000100 and ext.ProcessMemoryLimit:
            candidates.append(int(ext.ProcessMemoryLimit))
        if flags & JOB_OBJECT_LIMIT_JOB_MEMORY and ext.JobMemoryLimit:
            candidates.append(int(ext.JobMemoryLimit))
        if candidates:
            mem_limit = min(candidates)
    cpu_info = _CPU_RATE_CONTROL_INFO()
    cpu_capped = False
    if _k32.QueryInformationJobObject(
        None, JOB_OBJECT_CPU_RATE_CONTROL_INFORMATION, ctypes.byref(cpu_info), ctypes.sizeof(cpu_info), ctypes.byref(ret_len),
    ):
        cpu_capped = bool(int(cpu_info.ControlFlags) & JOB_OBJECT_CPU_RATE_CONTROL_ENABLE)
    return JobConstraintReport(in_job=True, breakaway_ok=breakaway_ok, memory_limit_bytes=mem_limit, cpu_rate_capped=cpu_capped)


def _encode_unicode_env_block(env: dict[str, str]) -> ctypes.Array[ctypes.c_wchar]:
    items = [f"{k}={v}" for k, v in sorted(env.items(), key=lambda kv: kv[0].upper()) if "\x00" not in k and "\x00" not in v]
    return ctypes.create_unicode_buffer("\x00".join(items) + "\x00\x00")


def _create_pipe_pair(*, child_reads: bool) -> tuple[int, int]:
    sec = _SECURITY_ATTRIBUTES()
    sec.nLength = ctypes.sizeof(_SECURITY_ATTRIBUTES)
    sec.lpSecurityDescriptor = None
    sec.bInheritHandle = True
    r_h = wintypes.HANDLE()
    w_h = wintypes.HANDLE()
    if not _k32.CreatePipe(ctypes.byref(r_h), ctypes.byref(w_h), ctypes.byref(sec), 65536):
        raise ctypes.WinError(ctypes.get_last_error())
    parent_h = int(w_h.value) if child_reads else int(r_h.value)
    child_h = int(r_h.value) if child_reads else int(w_h.value)
    if not _k32.SetHandleInformation(parent_h, HANDLE_FLAG_INHERIT, 0):
        err = ctypes.get_last_error()
        _k32.CloseHandle(r_h)
        _k32.CloseHandle(w_h)
        raise ctypes.WinError(err)
    return parent_h, child_h


def run_win32(
    spec: ProcessSpec,
    *,
    deadline: Deadline,
    cancel: threading.Event | None = None,
) -> ProcessOutcome:
    """Spawn a windowless Win32 child via `CreateProcessW`, attach nested Job before resume, and drain pipes."""
    if os.name != "nt":
        raise RuntimeError("run_win32 requires Windows (`os.name == 'nt'`)")
    if spec.effective_require_gui:
        verify_gui_subsystem(spec.argv[0])
    started = time.monotonic()
    child_env = build_child_env(spec.env)
    cmd_buf = ctypes.create_unicode_buffer(subprocess.list2cmdline(list(spec.argv)))
    env_buf = _encode_unicode_env_block(child_env)
    cwd_str = str(spec.cwd) if spec.cwd is not None else None
    creation_flags = CREATE_SUSPENDED | CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT | CREATE_NEW_PROCESS_GROUP
    if creation_flags & FORBIDDEN_CREATION_FLAGS:
        raise AssertionError("Forbidden Win32 console creation flags detected")
    spool_file: IO[bytes] | None = None
    spool_path: Path | None = None
    if spec.spool_dir is not None:
        spec.spool_dir.mkdir(parents=True, exist_ok=True)
        fd, raw_spool = tempfile.mkstemp(prefix="stdout-", suffix=".spool", dir=str(spec.spool_dir))
        spool_path = Path(raw_spool)
        spool_file = os.fdopen(fd, "w+b")
    stdin_w = stdout_r = stderr_r = 0
    stdin_r = stdout_w = stderr_w = 0
    proc_handle = thread_handle = job_handle = 0
    job_meta: dict[str, Any] = {}
    try:
        with _SPAWN_LOCK:
            stdin_w, stdin_r = _create_pipe_pair(child_reads=True)
            stdout_r, stdout_w = _create_pipe_pair(child_reads=False)
            stderr_r, stderr_w = _create_pipe_pair(child_reads=False)
            si = _STARTUPINFOW()
            si.cb = ctypes.sizeof(_STARTUPINFOW)
            si.dwFlags = STARTF_USESTDHANDLES
            si.hStdInput, si.hStdOutput, si.hStdError = stdin_r, stdout_w, stderr_w
            pi = _PROCESS_INFORMATION()
            ok = _k32.CreateProcessW(
                None, cmd_buf, None, None, True, creation_flags,
                ctypes.cast(env_buf, ctypes.c_void_p), cwd_str, ctypes.byref(si), ctypes.byref(pi),
            )
            _k32.CloseHandle(stdin_r)
            _k32.CloseHandle(stdout_w)
            _k32.CloseHandle(stderr_w)
            stdin_r = stdout_w = stderr_w = 0
            if not ok:
                raise ctypes.WinError(ctypes.get_last_error())
            proc_handle, thread_handle, child_pid = int(pi.hProcess), int(pi.hThread), int(pi.dwProcessId)

        job_handle = int(_k32.CreateJobObjectW(None, None) or 0)
        if not job_handle:
            raise ctypes.WinError(ctypes.get_last_error())
        ext = _EXTENDED_LIMIT_INFO()
        base_flags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if spec.memory_limit_bytes is not None:
            base_flags |= JOB_OBJECT_LIMIT_JOB_MEMORY
            ext.JobMemoryLimit = int(spec.memory_limit_bytes)
        if spec.effective_below_normal:
            base_flags |= JOB_OBJECT_LIMIT_PRIORITY_CLASS
            ext.BasicLimitInformation.PriorityClass = BELOW_NORMAL_PRIORITY_CLASS
        breakaway_applied = False
        if spec.allow_daemon_breakaway:
            ext.BasicLimitInformation.LimitFlags = base_flags | JOB_OBJECT_LIMIT_BREAKAWAY_OK
            breakaway_applied = bool(
                _k32.SetInformationJobObject(job_handle, JOB_OBJECT_EXTENDED_LIMIT_INFORMATION, ctypes.byref(ext), ctypes.sizeof(ext))
            )
        if not breakaway_applied:
            ext.BasicLimitInformation.LimitFlags = base_flags
            if not _k32.SetInformationJobObject(job_handle, JOB_OBJECT_EXTENDED_LIMIT_INFORMATION, ctypes.byref(ext), ctypes.sizeof(ext)):
                raise ctypes.WinError(ctypes.get_last_error())

        cpu_pct = spec.effective_cpu_rate_percent
        cpu_applied = False
        if cpu_pct is not None:
            cpu_ctl = _CPU_RATE_CONTROL_INFO()
            cpu_ctl.ControlFlags = JOB_OBJECT_CPU_RATE_CONTROL_ENABLE | JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP
            cpu_ctl.CpuRate = max(1, min(100, int(cpu_pct))) * 100
            cpu_applied = bool(
                _k32.SetInformationJobObject(job_handle, JOB_OBJECT_CPU_RATE_CONTROL_INFORMATION, ctypes.byref(cpu_ctl), ctypes.sizeof(cpu_ctl))
            )
        if not _k32.AssignProcessToJobObject(job_handle, proc_handle):
            raise ctypes.WinError(ctypes.get_last_error())
        if _k32.ResumeThread(thread_handle) == 0xFFFFFFFF:
            raise ctypes.WinError(ctypes.get_last_error())
        _k32.CloseHandle(thread_handle)
        thread_handle = 0
        job_meta = {
            "pid": child_pid,
            "kill_on_job_close": True,
            "allow_daemon_breakaway": breakaway_applied,
            "memory_limit_bytes": spec.memory_limit_bytes,
            "below_normal_priority": spec.effective_below_normal,
            "cpu_rate_percent": cpu_pct,
            "cpu_rate_applied": cpu_applied,
        }
    except TimeoutError:
        for h in (stdin_r, stdout_w, stderr_w, stdin_w, stdout_r, stderr_r):
            if h:
                _k32.CloseHandle(h)
        if proc_handle:
            _k32.TerminateProcess(proc_handle, 1)
            _k32.CloseHandle(proc_handle)
        if thread_handle:
            _k32.CloseHandle(thread_handle)
        if job_handle:
            _k32.TerminateJobObject(job_handle, 1)
            _k32.CloseHandle(job_handle)
        if spool_file is not None:
            spool_file.close()
        if spool_path is not None:
            spool_path.unlink(missing_ok=True)
        raise
    except OSError as exc:
        for h in (stdin_r, stdout_w, stderr_w, stdin_w, stdout_r, stderr_r):
            if h:
                _k32.CloseHandle(h)
        if proc_handle:
            _k32.TerminateProcess(proc_handle, 1)
            _k32.CloseHandle(proc_handle)
        if thread_handle:
            _k32.CloseHandle(thread_handle)
        if job_handle:
            _k32.TerminateJobObject(job_handle, 1)
            _k32.CloseHandle(job_handle)
        if spool_file is not None:
            spool_file.close()
        if spool_path is not None:
            spool_path.unlink(missing_ok=True)
        raise HarnessError(
            f"Win32 CreateProcessW / Job attach failed for {spec.argv[0]!r}: {exc}",
            stage="spawn",
            reason="spawn_failed",
            submission_state="not_sent",
            retryable=False,
            reportable=False,
            details={"winerror": getattr(exc, "winerror", None), "error_type": type(exc).__name__},
        ) from exc

    stdout_buf = bytearray()
    stderr_buf = bytearray()
    cap_lock = threading.Lock()
    total_captured = 0
    reader_error: list[BaseException] = []
    cleanup_issues: list[dict[str, str]] = []

    def _writer_worker(handle: int, payload: bytes) -> None:
        try:
            mv = memoryview(payload)
            offset = 0
            written = wintypes.DWORD(0)
            while offset < len(mv):
                chunk = bytes(mv[offset : offset + 65536])
                if not _k32.WriteFile(handle, chunk, len(chunk), ctypes.byref(written), None):
                    break
                offset += int(written.value)
        finally:
            _k32.CloseHandle(handle)

    def _reader_worker(handle: int, is_stdout: bool) -> None:
        nonlocal total_captured
        buf = ctypes.create_string_buffer(65536)
        n_read = wintypes.DWORD(0)
        while True:
            ok_read = _k32.ReadFile(handle, buf, 65536, ctypes.byref(n_read), None)
            if not ok_read:
                err = ctypes.get_last_error()
                if err in {ERROR_BROKEN_PIPE, ERROR_HANDLE_EOF, 0}:
                    return
                reader_error.append(ctypes.WinError(err))
                return
            count = int(n_read.value)
            if count == 0:
                return
            data = buf.raw[:count]
            with cap_lock:
                total_captured += count
                if total_captured > spec.max_output_bytes:
                    reader_error.append(RuntimeError("output_limit_exceeded"))
                    return
                if is_stdout:
                    if spool_file is not None:
                        spool_file.write(data)
                    else:
                        stdout_buf.extend(data)
                else:
                    stderr_buf.extend(data)

    if spec.stdin_bytes:
        stdin_thread: threading.Thread | None = threading.Thread(
            target=_writer_worker, args=(stdin_w, spec.stdin_bytes), daemon=True
        )
        stdin_w = 0
        stdin_thread.start()
    else:
        _k32.CloseHandle(stdin_w)
        stdin_w = 0
        stdin_thread = None

    t_out = threading.Thread(target=_reader_worker, args=(stdout_r, True), daemon=True)
    t_err = threading.Thread(target=_reader_worker, args=(stderr_r, False), daemon=True)
    t_out.start()
    t_err.start()

    def _terminate_job() -> None:
        if job_handle:
            _k32.TerminateJobObject(job_handle, 1)

    def _exit_code() -> int | None:
        code = wintypes.DWORD(0)
        if _k32.GetExitCodeProcess(proc_handle, ctypes.byref(code)):
            return None if int(code.value) == 259 else int(code.value)
        return None

    def _build_outcome(execution: str, returncode: int | None) -> ProcessOutcome:
        elapsed_ms = int((time.monotonic() - started) * 1000)
        with cap_lock:
            if spool_file is not None:
                spool_file.flush()
                spool_file.seek(0)
                preview = spool_file.read(min(total_captured, spec.mcp_response_cap_bytes))
                out_text = preview.decode("utf-8", errors="replace")
                out_trunc = total_captured > len(preview)
            else:
                out_text = bytes(stdout_buf).decode("utf-8", errors="replace")
                out_trunc = False
            err_text = bytes(stderr_buf).decode("utf-8", errors="replace")
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
            job_metadata=dict(job_meta),
        )

    try:
        while True:
            if cancel is not None and cancel.is_set():
                _terminate_job()
                _k32.WaitForSingleObject(proc_handle, 1000)
                t_out.join(timeout=1.0)
                t_err.join(timeout=1.0)
                raise ProcessCancelledError("Process cancelled by caller", _build_outcome("unknown", _exit_code()))
            if reader_error:
                first_err = reader_error[0]
                _terminate_job()
                _k32.WaitForSingleObject(proc_handle, 1000)
                t_out.join(timeout=1.0)
                t_err.join(timeout=1.0)
                if isinstance(first_err, RuntimeError) and str(first_err) == "output_limit_exceeded":
                    raise OutputLimitError(spec.max_output_bytes, _build_outcome("unknown", _exit_code()))
                raise first_err
            rem = deadline.remaining()
            if rem <= 0.0:
                _terminate_job()
                _k32.WaitForSingleObject(proc_handle, 1000)
                t_out.join(timeout=1.0)
                t_err.join(timeout=1.0)
                t_exc = TimeoutError("Owned Windows Job process exceeded monotonic deadline")
                t_exc.outcome = _build_outcome("unknown", _exit_code())  # type: ignore[attr-defined]
                raise t_exc
            wait_ms = max(1, min(25, int(rem * 1000)))
            state = _k32.WaitForSingleObject(proc_handle, wait_ms)
            if state == WAIT_OBJECT_0:
                if not t_out.is_alive() and not t_err.is_alive():
                    _terminate_job()
                    break
                t_out.join(timeout=min(0.025, rem))
                if not t_out.is_alive() and not t_err.is_alive():
                    _terminate_job()
                    break
        grace_join = max(0.2, min(2.0, deadline.cleanup_grace))
        t_out.join(timeout=grace_join)
        t_err.join(timeout=grace_join)
        if stdin_thread is not None:
            stdin_thread.join(timeout=0.5)
        if t_out.is_alive() or t_err.is_alive():
            cleanup_issues.append({"stage": "join_reader", "error_type": "ReaderStillRunning"})
        if reader_error:
            first_err = reader_error[0]
            if isinstance(first_err, RuntimeError) and str(first_err) == "output_limit_exceeded":
                raise OutputLimitError(spec.max_output_bytes, _build_outcome("unknown", _exit_code()))
            raise first_err
        rc = _exit_code()
        return _build_outcome("completed", 0 if rc is None else rc)
    finally:
        if spool_file is not None:
            try:
                spool_file.close()
            except TimeoutError:
                raise
            except OSError:
                pass
        if job_handle:
            _k32.TerminateJobObject(job_handle, 1)
            _k32.CloseHandle(job_handle)
        if proc_handle:
            _k32.CloseHandle(proc_handle)
        if stdout_r and not t_out.is_alive():
            _k32.CloseHandle(stdout_r)
        if stderr_r and not t_err.is_alive():
            _k32.CloseHandle(stderr_r)
        if stdin_w:
            _k32.CloseHandle(stdin_w)
