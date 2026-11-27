"""Standalone stdlib zipapp payload (`mindie-harness-seed.pyz`) and template generator.

[Role]
Serves as BOTH (1) the importable verifier/template module (`verify_seed_lock`,
`compute_seed_lock`, `render_plugin_bootstrap_template`) inside `mindie_harness.bootstrap`
AND (2) the standalone `__main__.py` inside `dist/mindie-harness-seed.pyz` (`< 60 KB`),
therefore importing ZERO sibling modules outside the Python standard library.

[Invariants]
- Verifies `mindie-harness-seed.pyz` SHA-256 and byte size in `64 KiB` chunks against
  `seed-lock.json` (`schema: "mindie-harness-seed/1"`).
- `render_plugin_bootstrap_template(host)` emits a `< 115`-line pure-stdlib plugin
  entrypoint that gates `Stop` / `SessionEnd` on saved sharing consent + authorized
  `project_roots` (`< 10ms` `{}` when disabled or out of scope), fast-paths cold
  `session-start` (`pending-update-check.json` marker only) and `pre-invocation`,
  and verifies `seed-lock.json` before executing `mindie-harness-seed.pyz`.
- Cold-start provisioning checks validated receipt reuse BEFORE enforcing the `2.5 GiB`
  disk floor, pins same-volume `UV_CACHE_DIR`, spawns Win32 build children suspended
  into a `KILL_ON_JOB_CLOSE` Job Object before `ResumeThread`, repairs `uv <= 0.12.3`
  `Subsystem == 3` `.venv\\Scripts\\pythonw.exe` launchers, and provisions the 9-domain
  knowledge catalog when `mindie_knowledge` is installed.

[Timeouts & Locks]
- Holds `<data_home>/.prepare-<host>.lock` across single-venv `uv` provisioning (`240s`).

[Side-Effect Policy]
- Provisions `<data_home>/runtimes/<host>/seed-<plat>/.venv` and atomically writes
  `<config_path>` only when no healthy runtime is active.
"""
from __future__ import annotations

from contextlib import contextmanager
import argparse, hashlib, json, os, shutil, signal, struct, subprocess, sys, tarfile, tempfile, threading, time, urllib.parse, urllib.request
from pathlib import Path
from typing import Any

SEED_LOCK_SCHEMA = "mindie-harness-seed/1"
SEED_VERSION = "0.1.9"
MIN_FREE_BYTES = int(2.5 * (1024 ** 3))
_CREATE_NO_WINDOW = 0x08000000 if os.name == "nt" else 0
_WIN_EXTS = (".exe", ".cmd", ".bat", ".com", ".ps1")


def _stream_sha256_and_size(path: Path) -> tuple[str, int]:
    h = hashlib.sha256()
    total = 0
    with path.open("rb") as fh:
        while chunk := fh.read(65536):
            h.update(chunk)
            total += len(chunk)
    return h.hexdigest(), total


def compute_seed_lock(pyz_path: str | Path, *, version: str = SEED_VERSION) -> dict[str, Any]:
    """Compute the `mindie-harness-seed/1` lock document for `pyz_path`."""
    target = Path(pyz_path)
    digest, size_bytes = _stream_sha256_and_size(target)
    return {"schema": SEED_LOCK_SCHEMA, "version": str(version), "artifact": target.name, "sha256": digest, "size_bytes": size_bytes}


def verify_seed_lock(pyz_path: str | Path, lock_path: str | Path) -> dict[str, Any]:
    """Verify `pyz_path` matches `lock_path` (`mindie-harness-seed/1`) byte-for-byte."""
    p_pyz, p_lock = Path(pyz_path), Path(lock_path)
    if not p_lock.is_file():
        raise ValueError(f"Missing seed lock file: {p_lock}")
    if not p_pyz.is_file():
        raise ValueError(f"Missing seed archive: {p_pyz}")
    lock_doc = json.loads(p_lock.read_bytes().decode("utf-8-sig"))
    if not isinstance(lock_doc, dict) or lock_doc.get("schema") != SEED_LOCK_SCHEMA:
        raise ValueError(f"Invalid seed-lock schema in {p_lock}")
    expected_sha = str(lock_doc.get("sha256") or "").strip().lower()
    expected_size = lock_doc.get("size_bytes")
    if len(expected_sha) != 64 or type(expected_size) is not int or expected_size <= 0:
        raise ValueError("Malformed sha256 or size_bytes in seed-lock.json")
    actual_sha, actual_size = _stream_sha256_and_size(p_pyz)
    if actual_size != expected_size or actual_sha != expected_sha:
        raise ValueError(
            f"Seed integrity mismatch for {p_pyz}: expected {expected_sha} ({expected_size}B), "
            f"got {actual_sha} ({actual_size}B)"
        )
    return lock_doc


def render_plugin_bootstrap_template(host: str, *, cli_module: str = "mindie_harness.cli") -> str:
    """Emit the `< 115`-line pure-stdlib host plugin cold-start forwarding script."""
    clean_host = str(host).strip().lower()
    if clean_host not in {"codex", "cc", "kimi", "dsh", "agy", "wb", "oc", "omp"}:
        raise ValueError(f"Unsupported host: {host!r}")
    raw_template = r'''#!/usr/bin/env python3
"""Deterministic stdlib cold-start launcher for MindIE (__HOST_LABEL__)."""
from __future__ import annotations
import hashlib, json, os, subprocess, sys, time
from pathlib import Path

HOST, CLI_MOD, PLUGIN_ROOT = __HOST__, __CLI_MOD__, Path(__file__).resolve().parents[1]
_NO_WIN = 0x08000000 if os.name == "nt" else 0

def _cfg_home() -> Path:
    if v := os.environ.get("MINDIE_CONFIG_HOME"):
        return Path(v)
    return Path(os.environ.get("APPDATA") or (Path.home() / "AppData/Roaming") if os.name == "nt" else os.environ.get("XDG_CONFIG_HOME") or (Path.home() / ".config")) / "mindie-agent"

def _data_home() -> Path:
    if v := os.environ.get("MINDIE_DATA_HOME"):
        return Path(v)
    return Path(os.environ.get("LOCALAPPDATA") or (Path.home() / "AppData/Local") if os.name == "nt" else os.environ.get("XDG_DATA_HOME") or (Path.home() / ".local/share")) / "mindie-agent"

def _read_json(p: Path) -> dict | None:
    try:
        return d if p.is_file() and isinstance(d := json.loads(p.read_bytes().decode("utf-8-sig")), dict) else None
    except TimeoutError:
        raise
    except (OSError, ValueError):
        return None

def _verify_seed(pyz: Path, lock: Path) -> None:
    doc = _read_json(lock)
    if not doc or doc.get("schema") != "mindie-harness-seed/1":
        raise SystemExit("Invalid seed-lock.json")
    h, sz = hashlib.sha256(), 0
    with pyz.open("rb") as fh:
        while blk := fh.read(65536):
            h.update(blk); sz += len(blk)
    if sz != doc.get("size_bytes") or h.hexdigest() != doc.get("sha256"):
        raise SystemExit("mindie-harness-seed.pyz SHA-256 mismatch")

def _stop_roots(cfg_path: Path) -> list[str]:
    cfg = _read_json(cfg_path) or {}
    cp = Path(c) if isinstance(c := cfg.get("community_config"), str) and os.path.isabs(c) else cfg_path.parent / "mindie-community.json"
    comm = _read_json(cp)
    sp = Path(s) if isinstance(s := ((comm or {}).get("consent_config") or cfg.get("consent_config")), str) and os.path.isabs(s) else cfg_path.parent / "mindie-consent.json"
    cons = _read_json(sp)
    if comm is not None:
        if comm.get("enabled") is not True or ((sp.exists() or isinstance(comm.get("consent_config"), str)) and (not cons or cons.get("enabled") is False or cons.get("choice", "contribute" if cons.get("enabled") is True else None) not in {"contribute", "local-only"})):
            return []
        roots = comm.get("project_roots")
    elif not cp.exists() and cons and cons.get("enabled") is not False and (cons.get("enabled") is True or cons.get("choice") in {"contribute", "local-only"}):
        roots = cons.get("project_roots")
    else:
        return []
    return [os.path.normcase(str(Path(r).resolve())) for r in roots] if isinstance(roots, list) and roots and all(isinstance(r, str) and os.path.isabs(r) for r in roots) else []

def _in_roots(raw: bytes, roots: list[str]) -> bool:
    try:
        ev = json.loads(raw.decode("utf-8-sig")) if 0 < len(raw) <= 1048576 and raw.strip() else None
    except ValueError:
        ev = None
    if not isinstance(ev, dict):
        return False
    cands = [ev.get(k) for k in ("cwd", "workspace", "workspace_root", "project_root", "directory")] + (wps if isinstance(wps := ev.get("workspacePaths"), list) else [])
    for ws in cands:
        if isinstance(ws, str) and os.path.isabs(ws):
            c = os.path.normcase(str(Path(ws).resolve()))
            if any(os.path.commonpath([c, r]) == r for r in roots if os.path.splitdrive(c)[0] == os.path.splitdrive(r)[0]):
                return True
    return False

def _active_python(cfg_path: Path) -> Path | None:
    if cfg := _read_json(cfg_path):
        if isinstance(rel := cfg.get("component_release"), str) and rel and (rj := _read_json(Path(rel) / "runtime.json")) and (rj.get("validation") or {}).get("status") == "validated" and Path(str(rj.get("python") or "")).is_file():
            return Path(str(rj["python"]))
        if isinstance(cfg.get("python"), str) and Path(cfg["python"]).is_file():
            return Path(cfg["python"])
    return None

def _enqueue_pending_check(state_dir: Path) -> None:
    state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = state_dir / f".pending.tmp.{os.getpid()}"
    tmp.write_text(json.dumps({"schema": "mindie-pending-update/1", "host": HOST, "reason": "session_start", "requested_at": time.time()}) + "\n", encoding="utf-8")
    os.replace(tmp, state_dir / "pending-update-check.json")

def _io(buf: bytes | None) -> dict:
    if buf is not None: return {"input": buf}
    try: sys.stdin.fileno(); sys.stdout.fileno(); sys.stderr.fileno(); return {"stdin": sys.stdin, "stdout": sys.stdout, "stderr": sys.stderr}
    except Exception: return {}

def main() -> int:
    argv, cfg_path, state_dir = sys.argv[1:], _cfg_home() / f"{HOST}.json", _data_home() / "state" / HOST
    op, stdin_buf = (argv[1].lower().replace("_", "-") if len(argv) >= 2 and argv[0] == "hook" else ""), None
    if op in {"stop", "session-end", "sessionend"}:
        roots = _stop_roots(cfg_path)
        if not roots or not _in_roots(stdin_buf := sys.stdin.buffer.read(1048577), roots):
            sys.stdout.buffer.write(b"{}\n"); sys.stdout.buffer.flush(); return 0
    if (py := _active_python(cfg_path)) is not None:
        return subprocess.run([str(py), "-I", "-X", "utf8", "-m", CLI_MOD, "--host", HOST, "--plugin-root", str(PLUGIN_ROOT), "--config", str(cfg_path), *argv], **_io(stdin_buf), creationflags=_NO_WIN).returncode
    if op in {"pre-invocation", "user-prompt-submit"}:
        sys.stdout.buffer.write(b"{}\n"); sys.stdout.buffer.flush(); return 0
    if op == "session-start" or "--offline" in os.environ.get("_MINDIE_UV_FLAGS", ""):
        try:
            _enqueue_pending_check(state_dir)
        except TimeoutError:
            raise
        except OSError:
            pass
        sys.stdout.buffer.write(b"{}\n"); sys.stdout.buffer.flush(); return 0
    pyz, lock = PLUGIN_ROOT / "assets" / "mindie-harness-seed.pyz", PLUGIN_ROOT / "assets" / "seed-lock.json"
    _verify_seed(pyz, lock)
    return subprocess.run([sys.executable, "-I", "-X", "utf8", str(pyz), "--host", HOST, "--plugin-root", str(PLUGIN_ROOT), "--config", str(cfg_path), "--cli-module", CLI_MOD, *argv], **_io(stdin_buf), creationflags=_NO_WIN).returncode

if __name__ == "__main__":
    raise SystemExit(main())
'''
    template = (
        raw_template.replace("__HOST_LABEL__", clean_host)
        .replace("__HOST__", repr(clean_host))
        .replace("__CLI_MOD__", repr(cli_module))
    )
    assert len(template.splitlines()) < 115, f"Template exceeded 115 lines: {len(template.splitlines())}"
    return template


def _seed_data_home() -> Path:
    if v := os.environ.get("MINDIE_DATA_HOME"):
        return Path(v).expanduser()
    if os.name == "nt":
        return Path(os.environ.get("LOCALAPPDATA") or (Path.home() / "AppData/Local")) / "mindie-agent"
    return Path(os.environ.get("XDG_DATA_HOME") or (Path.home() / ".local/share")) / "mindie-agent"


def _is_win_store_stub(cand: Path) -> bool:
    if "\\microsoft\\windowsapps\\" in str(cand).replace("/", "\\").lower():
        return True
    if os.name == "nt":
        try:
            return cand.stat().st_size == 0
        except TimeoutError:
            raise
        except OSError:
            return True
    return False


def _unwrap_base_python(py_path: Path) -> Path:
    for cfg in (py_path.parent.parent / "pyvenv.cfg", py_path.parent / "pyvenv.cfg"):
        try:
            if not cfg.is_file():
                continue
            home_dir: Path | None = None
            ver_prefix = ""
            for raw_line in cfg.read_text(encoding="utf-8-sig", errors="replace").splitlines():
                k, sep, v = raw_line.partition("=")
                if not sep:
                    continue
                key = k.strip().lower()
                val = v.strip()
                if key == "home" and val:
                    home_dir = Path(val)
                elif key in {"version_info", "version"} and val:
                    parts = val.split(".")
                    if len(parts) >= 2 and parts[0].isdigit() and parts[1].isdigit():
                        ver_prefix = f"{parts[0]}.{parts[1]}"
            if home_dir is not None:
                posix_names = ([f"python{ver_prefix}"] if ver_prefix else []) + ["python3", "python"]
                for name in (("python.exe", "python3.exe") if os.name == "nt" else tuple(posix_names)):
                    cand = home_dir / name
                    if cand.is_file() and not _is_win_store_stub(cand):
                        return cand
        except TimeoutError:
            raise
        except OSError:
            continue
    return py_path


def _pe_subsystem(exe_path: Path) -> int | None:
    try:
        with exe_path.open("rb") as fh:
            dos = fh.read(64)
            if len(dos) < 64 or dos[:2] != b"MZ":
                return None
            pe_off = struct.unpack_from("<I", dos, 0x3C)[0]
            if pe_off < 64 or pe_off > 16 * 1024 * 1024:
                return None
            fh.seek(pe_off)
            hdr = fh.read(24)
            if len(hdr) < 24 or hdr[:4] != b"PE\x00\x00":
                return None
            opt = fh.read(70)
            return int(struct.unpack_from("<H", opt, 68)[0]) if len(opt) >= 70 else None
    except TimeoutError:
        raise
    except OSError:
        return None


def _repair_and_verify_seed_pythonw(venv_dir: Path, base_py: Path) -> bool:
    if os.name != "nt":
        return True
    pyw = venv_dir / "Scripts" / "pythonw.exe"
    if pyw.is_file() and _pe_subsystem(pyw) == 2:
        return True
    launcher = _unwrap_base_python(base_py).parent / "Lib" / "venv" / "scripts" / "nt" / "venvwlauncher.exe"
    if launcher.is_file() and _pe_subsystem(launcher) == 2:
        tmp_pyw = pyw.with_name(f".pythonw.seed.{os.getpid()}.exe")
        try:
            shutil.copyfile(launcher, tmp_pyw)
            os.replace(tmp_pyw, pyw)
        finally:
            tmp_pyw.unlink(missing_ok=True)
    return bool(pyw.is_file() and _pe_subsystem(pyw) == 2)


def _which_native(name: str) -> str | None:
    if os.name == "nt":
        return shutil.which(name)
    for folder in os.environ.get("PATH", "").split(os.pathsep):
        clean = folder.strip().strip('"')
        if not clean:
            continue
        cand = Path(clean) / name
        if cand.suffix.lower() in _WIN_EXTS:
            continue
        try:
            if not cand.is_file() or not os.access(cand, os.X_OK):
                continue
            with cand.open("rb") as fh:
                if fh.read(2) == b"MZ":
                    continue
            return str(cand)
        except TimeoutError:
            raise
        except OSError:
            continue
    return None


def _resolve_python(uv_bin: str) -> str:
    if sys.executable and Path(sys.executable).is_file() and not _is_win_store_stub(Path(sys.executable)):
        return str(_unwrap_base_python(Path(sys.executable)))
    res = subprocess.run(
        [uv_bin, "python", "find", ">=3.11"],
        stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=10.0, check=False, creationflags=_CREATE_NO_WINDOW,
    )
    lines = (res.stdout or "").strip().splitlines()
    if res.returncode == 0 and lines:
        return str(_unwrap_base_python(Path(lines[-1].strip())))
    raise RuntimeError("No valid Python >=3.11 interpreter found for cold seed bootstrap")


def _same_volume_uv_cache(d_home: Path) -> str:
    fallback = str(d_home / ".uv-cache")
    explicit = os.environ.get("UV_CACHE_DIR")
    if not explicit:
        return fallback
    cand = Path(explicit).expanduser()
    probe = cand
    while not probe.exists() and probe.parent != probe:
        probe = probe.parent
    try:
        if os.name == "nt":
            d1 = os.path.splitdrive(os.path.abspath(str(probe)))[0].lower()
            d2 = os.path.splitdrive(os.path.abspath(str(d_home)))[0].lower()
            return str(cand) if d1 == d2 else fallback
        if os.stat(probe).st_dev == os.stat(d_home).st_dev:
            return str(cand)
    except OSError:
        pass
    return fallback


def _atomic_json(path: Path, doc: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, tmp_raw = tempfile.mkstemp(prefix=f".{path.name}.tmp.", dir=str(path.parent))
    tmp = Path(tmp_raw)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write((json.dumps(doc, sort_keys=True, indent=2) + "\n").encode("utf-8"))
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


def _read_seed_json(path: Path) -> dict[str, Any] | None:
    try:
        data = json.loads(path.read_bytes().decode("utf-8-sig")) if path.is_file() else None
        return data if isinstance(data, dict) else None
    except TimeoutError:
        raise
    except (OSError, ValueError):
        return None


def _config_has_usable_python(cfg: dict[str, Any] | None) -> bool:
    if not isinstance(cfg, dict):
        return False
    rel = cfg.get("component_release")
    if isinstance(rel, str) and rel:
        rj = _read_seed_json(Path(rel) / "runtime.json")
        if isinstance(rj, dict) and (rj.get("validation") or {}).get("status") == "validated":
            if Path(str(rj.get("python") or "")).is_file():
                return True
    py_raw = cfg.get("python")
    return isinstance(py_raw, str) and bool(py_raw) and Path(py_raw).is_file()


def _ensure_host_config(cfg_path: Path, *, host: str, venv_py: Path, gen_dir: Path, plugin_root: Path, validation: dict[str, Any]) -> None:
    existing = _read_seed_json(cfg_path)
    if _config_has_usable_python(existing):
        return
    merged = dict(existing) if isinstance(existing, dict) else {}
    merged.update({"host": host, "python": str(venv_py), "component_release": str(gen_dir), "source_root": str(plugin_root), "product_validation": dict(validation)})
    _atomic_json(cfg_path, merged)


def _run_owned_seed_cmd(cmd: list[str], *, env: dict[str, str], timeout: float) -> None:
    """Run a cold-seed build/probe command with suspended Win32 Job or POSIX session cleanup."""
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes

        k32 = ctypes.WinDLL("kernel32", use_last_error=True)

        class _SEC_ATTR(ctypes.Structure):
            _fields_ = [("nLength", wintypes.DWORD), ("lpSecurityDescriptor", ctypes.c_void_p), ("bInheritHandle", wintypes.BOOL)]

        class _STARTUPINFOW(ctypes.Structure):
            _fields_ = [
                ("cb", wintypes.DWORD), ("lpReserved", wintypes.LPWSTR), ("lpDesktop", wintypes.LPWSTR),
                ("lpTitle", wintypes.LPWSTR), ("dwX", wintypes.DWORD), ("dwY", wintypes.DWORD),
                ("dwXSize", wintypes.DWORD), ("dwYSize", wintypes.DWORD), ("dwXCountChars", wintypes.DWORD),
                ("dwYCountChars", wintypes.DWORD), ("dwFillAttribute", wintypes.DWORD), ("dwFlags", wintypes.DWORD),
                ("wShowWindow", wintypes.WORD), ("cbReserved2", wintypes.WORD), ("lpReserved2", ctypes.c_void_p),
                ("hStdInput", wintypes.HANDLE), ("hStdOutput", wintypes.HANDLE), ("hStdError", wintypes.HANDLE),
            ]

        class _PROC_INFO(ctypes.Structure):
            _fields_ = [("hProcess", wintypes.HANDLE), ("hThread", wintypes.HANDLE), ("dwProcessId", wintypes.DWORD), ("dwThreadId", wintypes.DWORD)]

        class _IO_COUNTERS(ctypes.Structure):
            _fields_ = [(f"f{i}", ctypes.c_uint64) for i in range(6)]

        class _BASIC_LIMITS(ctypes.Structure):
            _fields_ = [
                ("PerProcessUserTimeLimit", ctypes.c_int64), ("PerJobUserTimeLimit", ctypes.c_int64),
                ("LimitFlags", wintypes.DWORD), ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", wintypes.DWORD),
                ("Affinity", ctypes.c_size_t), ("PriorityClass", wintypes.DWORD), ("SchedulingClass", wintypes.DWORD),
            ]

        class _EXTENDED_LIMITS(ctypes.Structure):
            _fields_ = [
                ("BasicLimitInformation", _BASIC_LIMITS), ("IoInfo", _IO_COUNTERS),
                ("ProcessMemoryLimit", ctypes.c_size_t), ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryUsed", ctypes.c_size_t), ("PeakJobMemoryUsed", ctypes.c_size_t),
            ]

        k32.CreateJobObjectW.argtypes, k32.CreateJobObjectW.restype = [ctypes.c_void_p, wintypes.LPCWSTR], wintypes.HANDLE
        k32.SetInformationJobObject.argtypes, k32.SetInformationJobObject.restype = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD], wintypes.BOOL
        k32.AssignProcessToJobObject.argtypes, k32.AssignProcessToJobObject.restype = [wintypes.HANDLE, wintypes.HANDLE], wintypes.BOOL
        k32.CreatePipe.argtypes, k32.CreatePipe.restype = [ctypes.POINTER(wintypes.HANDLE), ctypes.POINTER(wintypes.HANDLE), ctypes.POINTER(_SEC_ATTR), wintypes.DWORD], wintypes.BOOL
        k32.SetHandleInformation.argtypes, k32.SetHandleInformation.restype = [wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD], wintypes.BOOL
        k32.CreateProcessW.argtypes, k32.CreateProcessW.restype = [
            wintypes.LPCWSTR, wintypes.LPWSTR, ctypes.c_void_p, ctypes.c_void_p, wintypes.BOOL,
            wintypes.DWORD, ctypes.c_void_p, wintypes.LPCWSTR, ctypes.POINTER(_STARTUPINFOW), ctypes.POINTER(_PROC_INFO),
        ], wintypes.BOOL
        k32.ResumeThread.argtypes, k32.ResumeThread.restype = [wintypes.HANDLE], wintypes.DWORD
        k32.WaitForSingleObject.argtypes, k32.WaitForSingleObject.restype = [wintypes.HANDLE, wintypes.DWORD], wintypes.DWORD
        k32.GetExitCodeProcess.argtypes, k32.GetExitCodeProcess.restype = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)], wintypes.BOOL
        k32.ReadFile.argtypes, k32.ReadFile.restype = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p], wintypes.BOOL
        k32.TerminateJobObject.argtypes, k32.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT], [wintypes.HANDLE, wintypes.UINT]
        k32.CloseHandle.argtypes = [wintypes.HANDLE]

        def _mk_pipe(child_reads: bool) -> tuple[int, int]:
            sa = _SEC_ATTR(ctypes.sizeof(_SEC_ATTR), None, True)
            rh, wh = wintypes.HANDLE(), wintypes.HANDLE()
            if not k32.CreatePipe(ctypes.byref(rh), ctypes.byref(wh), ctypes.byref(sa), 65536):
                raise ctypes.WinError(ctypes.get_last_error())
            ph, ch = (int(wh.value), int(rh.value)) if child_reads else (int(rh.value), int(wh.value))
            k32.SetHandleInformation(ph, 1, 0)
            return ph, ch

        in_w, in_r = _mk_pipe(True)
        out_r, out_w = _mk_pipe(False)
        err_r, err_w = _mk_pipe(False)
        k32.CloseHandle(in_w)
        si = _STARTUPINFOW()
        si.cb, si.dwFlags = ctypes.sizeof(_STARTUPINFOW), 0x00000100
        si.hStdInput, si.hStdOutput, si.hStdError = in_r, out_w, err_w
        pi = _PROC_INFO()
        cmd_buf = ctypes.create_unicode_buffer(subprocess.list2cmdline(cmd))
        env_items = [f"{k}={v}" for k, v in sorted(env.items(), key=lambda kv: kv[0].upper()) if "\x00" not in k and "\x00" not in v]
        env_buf = ctypes.create_unicode_buffer("\x00".join(env_items) + "\x00\x00")
        flags = 0x00000004 | _CREATE_NO_WINDOW | 0x00000400 | 0x00000200
        ok = k32.CreateProcessW(None, cmd_buf, None, None, True, flags, ctypes.cast(env_buf, ctypes.c_void_p), None, ctypes.byref(si), ctypes.byref(pi))
        for ch_h in (in_r, out_w, err_w):
            k32.CloseHandle(ch_h)
        if not ok:
            k32.CloseHandle(out_r); k32.CloseHandle(err_r)
            raise ctypes.WinError(ctypes.get_last_error())

        job = int(k32.CreateJobObjectW(None, None) or 0)
        err_chunks = bytearray()

        def _drain(handle: int, keep: bool) -> None:
            buf, n = ctypes.create_string_buffer(16384), wintypes.DWORD(0)
            while k32.ReadFile(handle, buf, 16384, ctypes.byref(n), None) and n.value:
                if keep and len(err_chunks) < 65536:
                    err_chunks.extend(buf.raw[: int(n.value)])
            k32.CloseHandle(handle)

        t_out = threading.Thread(target=_drain, args=(out_r, False), daemon=True)
        t_err = threading.Thread(target=_drain, args=(err_r, True), daemon=True)
        try:
            if job:
                ext = _EXTENDED_LIMITS()
                ext.BasicLimitInformation.LimitFlags = 0x00002000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
                k32.SetInformationJobObject(job, 9, ctypes.byref(ext), ctypes.sizeof(ext))
                if not k32.AssignProcessToJobObject(job, pi.hProcess):
                    raise ctypes.WinError(ctypes.get_last_error())
            if k32.ResumeThread(pi.hThread) == 0xFFFFFFFF:
                raise ctypes.WinError(ctypes.get_last_error())
            k32.CloseHandle(pi.hThread)
            pi.hThread = 0
            t_out.start(); t_err.start()
            deadline_ts = time.monotonic() + float(timeout)
            while True:
                rem = deadline_ts - time.monotonic()
                if rem <= 0:
                    raise subprocess.TimeoutExpired(cmd, timeout)
                if k32.WaitForSingleObject(pi.hProcess, max(1, min(50, int(rem * 1000)))) == 0:
                    break
            t_out.join(timeout=1.0); t_err.join(timeout=1.0)
            code = wintypes.DWORD(0)
            k32.GetExitCodeProcess(pi.hProcess, ctypes.byref(code))
            rc = int(code.value)
        except BaseException:
            if job:
                k32.TerminateJobObject(job, 1)
            k32.TerminateProcess(pi.hProcess, 1)
            raise
        finally:
            if pi.hThread:
                k32.CloseHandle(pi.hThread)
            if job:
                k32.TerminateJobObject(job, 1); k32.CloseHandle(job)
            k32.CloseHandle(pi.hProcess)
        if rc != 0:
            raise subprocess.CalledProcessError(rc, cmd, stderr=bytes(err_chunks))
        return

    proc = subprocess.Popen(cmd, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, start_new_session=True)
    try:
        _, err = proc.communicate(timeout=timeout)
    except BaseException:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            proc.kill()
        try:
            proc.wait(timeout=5.0)
        except subprocess.TimeoutExpired:
            pass
        raise
    finally:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
    if proc.returncode != 0:
        raise subprocess.CalledProcessError(proc.returncode, cmd, stderr=err)


@contextmanager
def _seed_lock(lock_path: Path, *, timeout: float = 300.0):
    deadline = time.monotonic() + timeout
    with lock_path.open("a+b") as lf:
        if os.name == "nt":
            import msvcrt
            lf.seek(0); lf.write(b"0"); lf.flush()
            while True:
                try: lf.seek(0); msvcrt.locking(lf.fileno(), msvcrt.LK_NBLCK, 1); break
                except OSError:
                    if time.monotonic() >= deadline: raise TimeoutError(f"Timed out waiting for {lock_path}") from None
                    time.sleep(0.2)
            try: yield
            finally: lf.seek(0); msvcrt.locking(lf.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl
            while True:
                try: fcntl.flock(lf.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB); break
                except BlockingIOError:
                    if time.monotonic() >= deadline: raise TimeoutError(f"Timed out waiting for {lock_path}") from None
                    time.sleep(0.2)
            try: yield
            finally: fcntl.flock(lf.fileno(), fcntl.LOCK_UN)


def _stage_local_channel_bundle(dest: Path) -> Path | None:
    raw = (os.environ.get("MINDIE_CHANNEL_BASE_URL") or "").strip()
    if not raw or raw.lower().startswith(("http://", "https://")):
        return None
    src = Path(urllib.request.url2pathname(urllib.parse.urlparse(raw).path)) if raw.lower().startswith("file://") else Path(raw)
    tar_p = src / "mindie-wheels-bundle.tar.gz"
    if not tar_p.is_file():
        return None
    dest.mkdir(parents=True, exist_ok=True, mode=0o700)
    with tarfile.open(tar_p, "r:gz") as tf:
        tf.extractall(dest, filter="data")
    return dest if (dest / "requirements.txt").is_file() else None


def _provision_cold(host: str, plugin_root: Path, cfg_path: Path, *, smoke_module: str = "mindie_harness") -> Path:
    d_home = _seed_data_home()
    d_home.mkdir(parents=True, exist_ok=True, mode=0o700)
    with _seed_lock(d_home / f".prepare-{host}.lock"):
        gen_dir = d_home / "runtimes" / host / f"seed-{sys.platform}"
        venv_dir = gen_dir / ".venv"
        venv_py = venv_dir / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        receipt_path = gen_dir / "runtime.json"
        existing_receipt = _read_seed_json(receipt_path)
        if (
            venv_py.is_file()
            and existing_receipt is not None
            and isinstance(existing_receipt.get("validation"), dict)
            and existing_receipt["validation"].get("status") == "validated"
            and _repair_and_verify_seed_pythonw(venv_dir, venv_py)
        ):
            _ensure_host_config(cfg_path, host=host, venv_py=venv_py, gen_dir=gen_dir, plugin_root=plugin_root, validation=existing_receipt["validation"])
            return venv_py

        free_bytes = shutil.disk_usage(d_home).free
        if free_bytes < MIN_FREE_BYTES:
            raise RuntimeError(f"Insufficient disk space ({free_bytes}B < 2.5GiB) for cold runtime build")
        if gen_dir.exists():
            shutil.rmtree(gen_dir, ignore_errors=True)

        uv_bin = _which_native("uv")
        if not uv_bin:
            raise RuntimeError("`uv` is required to provision the MindIE runtime")
        base_py = _resolve_python(uv_bin)
        env = dict(os.environ, UV_PROJECT_ENVIRONMENT=str(venv_dir), UV_CACHE_DIR=_same_volume_uv_cache(d_home), PYTHONUTF8="1")
        pyproject, req_file, wheelhouse = plugin_root / "pyproject.toml", plugin_root / "runtime-requirements.txt", plugin_root / "wheelhouse"
        if not pyproject.is_file() and not req_file.is_file() and not wheelhouse.is_dir():
            raise RuntimeError(f"Cannot provision runtime from {plugin_root}: missing pyproject.toml, runtime-requirements.txt, or wheelhouse")

        gen_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        bundle_wh = gen_dir / "_bundle_wh"
        try:
            staged_wh = _stage_local_channel_bundle(bundle_wh)
            if staged_wh is not None:
                _run_owned_seed_cmd([uv_bin, "venv", "--python", base_py, str(venv_dir)], env=env, timeout=120.0)
                req_b = staged_wh / "requirements.txt"
                off_flags = ["--offline", "--no-index"] if os.environ.get("UV_OFFLINE") == "1" else []
                _run_owned_seed_cmd([uv_bin, "--native-tls", "pip", "install", "--python", str(venv_py), *off_flags, "--find-links", str(staged_wh), "--override", str(req_b), "-r", str(req_b)], env=env, timeout=240.0)
                shutil.rmtree(bundle_wh, ignore_errors=True)
            elif pyproject.is_file():
                cmd = [uv_bin, "--native-tls", "sync", "--no-editable", "--no-dev", "--python", base_py, "--project", str(plugin_root)]
                if (plugin_root / "uv.lock").is_file():
                    cmd.append("--locked")
                if wheelhouse.is_dir():
                    cmd.extend(["--offline", "--find-links", str(wheelhouse)])
                _run_owned_seed_cmd(cmd, env=env, timeout=240.0)
            else:
                _run_owned_seed_cmd([uv_bin, "venv", "--python", base_py, str(venv_dir)], env=env, timeout=120.0)
                install_cmd = [uv_bin, "--native-tls", "pip", "install", "--python", str(venv_py)]
                if req_file.is_file():
                    install_cmd.extend(["-r", str(req_file)])
                    overrides = plugin_root / "runtime" / "active-overrides.txt"
                    if overrides.is_file():
                        install_cmd.extend(["-r", str(overrides), "--overrides", str(overrides)])
                else:
                    install_cmd.append("mindie-harness")
                if wheelhouse.is_dir():
                    install_cmd.extend(["--offline", "--find-links", str(wheelhouse)])
                _run_owned_seed_cmd(install_cmd, env=env, timeout=240.0)

            if not _repair_and_verify_seed_pythonw(venv_dir, Path(base_py)):
                raise RuntimeError("Windows GUI pythonw.exe (Subsystem == 2) verification failed")
            _run_owned_seed_cmd([str(venv_py), "-I", "-X", "utf8", "-c", f"import {smoke_module}"], env=env, timeout=30.0)
            validation = {"status": "validated", "validated_at": time.time()}
            _atomic_json(receipt_path, {"schema": "mindie-candidate-check/1", "key": gen_dir.name, "generation": str(gen_dir), "python": str(venv_py), "validation": validation})
            _ensure_host_config(cfg_path, host=host, venv_py=venv_py, gen_dir=gen_dir, plugin_root=plugin_root, validation=validation)
            site_dirs = [venv_dir / "Lib" / "site-packages", *(venv_dir / "lib").glob("python*/site-packages")]
            if any((s / "mindie_knowledge" / "loop" / "domain_catalog.py").is_file() for s in site_dirs if s.is_dir()):
                _run_owned_seed_cmd(
                    [
                        str(venv_py), "-I", "-X", "utf8", "-c",
                        "import sys; from mindie_harness.paths import ProfileRef; from mindie_harness.runtime.knowledge_binding import ensure_knowledge_binding; ensure_knowledge_binding(ProfileRef.resolve(sys.argv[1], plugin_root=sys.argv[2], config_path=sys.argv[3]), python_executable=sys.executable)",
                        host, str(plugin_root), str(cfg_path),
                    ],
                    env=env, timeout=30.0,
                )
            return venv_py
        except BaseException:
            shutil.rmtree(gen_dir, ignore_errors=True)
            raise


def _seed_stop_roots(cfg_path: Path) -> list[str]:
    cfg = _read_seed_json(cfg_path) or {}
    cp = Path(c) if isinstance(c := cfg.get("community_config"), str) and os.path.isabs(c) else cfg_path.parent / "mindie-community.json"
    comm = _read_seed_json(cp)
    sp_raw = (comm or {}).get("consent_config") or cfg.get("consent_config")
    sp = Path(sp_raw) if isinstance(sp_raw, str) and os.path.isabs(sp_raw) else cfg_path.parent / "mindie-consent.json"
    cons = _read_seed_json(sp)
    if comm is not None:
        if comm.get("enabled") is not True:
            return []
        if (sp.exists() or isinstance(comm.get("consent_config"), str)) and (
            not cons or cons.get("enabled") is False or cons.get("choice", "contribute" if cons.get("enabled") is True else None) not in {"contribute", "local-only"}
        ):
            return []
        roots = comm.get("project_roots")
    elif not cp.exists() and cons and cons.get("enabled") is not False and (cons.get("enabled") is True or cons.get("choice") in {"contribute", "local-only"}):
        roots = cons.get("project_roots")
    else:
        return []
    if not isinstance(roots, list) or not roots or not all(isinstance(r, str) and os.path.isabs(r) for r in roots):
        return []
    return [os.path.normcase(str(Path(r).resolve())) for r in roots]


def _seed_in_roots(raw: bytes, roots: list[str]) -> bool:
    if len(raw) > 1048576 or not raw.strip():
        return False
    try:
        ev = json.loads(raw.decode("utf-8-sig"))
    except ValueError:
        return False
    if not isinstance(ev, dict):
        return False
    wps = ev.get("workspacePaths")
    cands = [ev.get(k) for k in ("cwd", "workspace", "workspace_root", "project_root", "directory")] + (wps if isinstance(wps, list) else [])
    for ws in cands:
        if isinstance(ws, str) and os.path.isabs(ws):
            c = os.path.normcase(str(Path(ws).resolve()))
            if any(os.path.commonpath([c, r]) == r for r in roots if os.path.splitdrive(c)[0] == os.path.splitdrive(r)[0]):
                return True
    return False


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="mindie-harness-seed", add_help=False)
    parser.add_argument("--version", action="store_true")
    parser.add_argument("--emit-template")
    parser.add_argument("--verify-lock", nargs=2, metavar=("PYZ", "LOCK"))
    parser.add_argument("--host")
    parser.add_argument("--plugin-root"); parser.add_argument("--config"); parser.add_argument("--cli-module", default="mindie_harness.cli")
    known, rest = parser.parse_known_args(argv)
    if known.version: sys.stdout.write(f"mindie-harness-seed {SEED_VERSION}\n"); return 0
    if known.emit_template: sys.stdout.write(render_plugin_bootstrap_template(known.emit_template, cli_module=known.cli_module)); return 0
    if known.verify_lock: sys.stdout.write(json.dumps(verify_seed_lock(known.verify_lock[0], known.verify_lock[1]), sort_keys=True) + "\n"); return 0
    if not known.host or not known.plugin_root or not known.config:
        sys.stderr.write("Usage: mindie-harness-seed.pyz --host <host> --plugin-root <dir> --config <path> <args...>\n"); return 2

    cfg_path = Path(known.config).resolve()
    hook_op = rest[1].lower().replace("_", "-") if len(rest) >= 2 and rest[0] == "hook" else ""
    stdin_buf: bytes | None = None
    has_active_py = _config_has_usable_python(_read_seed_json(cfg_path))
    if hook_op in {"pre-invocation", "user-prompt-submit"} and not has_active_py:
        sys.stdout.buffer.write(b"{}\n"); sys.stdout.buffer.flush(); return 0
    if (hook_op == "session-start" or (hook_op and "--offline" in os.environ.get("_MINDIE_UV_FLAGS", ""))) and not has_active_py:
        try:
            clean_h = str(known.host).strip().lower()
            _atomic_json(_seed_data_home() / "state" / clean_h / "pending-update-check.json", {"schema": "mindie-pending-update/1", "host": clean_h, "reason": "session_start", "requested_at": time.time()})
        except TimeoutError: raise
        except OSError: pass
        sys.stdout.buffer.write(b"{}\n"); sys.stdout.buffer.flush(); return 0
    if hook_op in {"stop", "session-end", "sessionend"}:
        roots = _seed_stop_roots(cfg_path)
        if not roots or not _seed_in_roots(stdin_buf := sys.stdin.buffer.read(1048577), roots):
            sys.stdout.buffer.write(b"{}\n"); sys.stdout.buffer.flush(); return 0

    py = _provision_cold(known.host, Path(known.plugin_root).resolve(), cfg_path, smoke_module=str(known.cli_module).split(".", 1)[0])
    if not rest: sys.stdout.write(json.dumps({"status": "provisioned", "python": str(py)}, sort_keys=True) + "\n"); return 0
    stdio_kw: dict[str, object] = {"input": stdin_buf} if stdin_buf is not None else {}
    if stdin_buf is None:
        try: sys.stdin.fileno(); sys.stdout.fileno(); sys.stderr.fileno(); stdio_kw = {"stdin": sys.stdin, "stdout": sys.stdout, "stderr": sys.stderr}
        except Exception: pass
    return subprocess.run([str(py), "-I", "-X", "utf8", "-m", known.cli_module, "--host", known.host, "--plugin-root", known.plugin_root, "--config", known.config, *rest], **stdio_kw, creationflags=_CREATE_NO_WINDOW).returncode


if __name__ == "__main__":
    raise SystemExit(main())
