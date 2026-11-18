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
  `project_roots` (`< 10ms` `{}` when disabled or out of scope, never cold-starting
  runtimes on stale `admission.sqlite3`), fast-paths cold `pre-invocation` /
  `user-prompt-submit` without prompt scanning, and verifies `seed-lock.json` before
  executing `mindie-harness-seed.pyz`.
- Cold-start provisioning enforces a `2.5 GiB` disk floor, pins same-volume `UV_CACHE_DIR`,
  skips WSL2 `.exe`/`MZ` shims and Windows `WindowsApps` Store stubs, and serializes
  concurrent cold starts under `.prepare-<host>.lock`.

[Timeouts & Locks]
- Holds `<data_home>/.prepare-<host>.lock` across single-venv `uv` provisioning (`240s`).

[Side-Effect Policy]
- Provisions `<data_home>/runtimes/<host>/seed-<plat>/.venv` and atomically writes
  `<config_path>` only when no healthy runtime is active.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from typing import Any

SEED_LOCK_SCHEMA = "mindie-harness-seed/1"
SEED_VERSION = "0.1.2"
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
    return {
        "schema": SEED_LOCK_SCHEMA,
        "version": str(version),
        "artifact": target.name,
        "sha256": digest,
        "size_bytes": size_bytes,
    }


def verify_seed_lock(pyz_path: str | Path, lock_path: str | Path) -> dict[str, Any]:
    """Verify `pyz_path` matches `lock_path` (`mindie-harness-seed/1`) byte-for-byte."""
    p_pyz = Path(pyz_path)
    p_lock = Path(lock_path)
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
    if clean_host not in {"codex", "cc", "kimi", "dsh", "agy", "wb", "oc"}:
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
        if comm.get("enabled") is not True or ((sp.exists() or isinstance(comm.get("consent_config"), str)) and (not cons or cons.get("enabled") is False or cons.get("choice", "contribute" if cons.get("enabled") is True else None) != "contribute")):
            return []
        roots = comm.get("project_roots")
    elif not cp.exists() and cons and cons.get("enabled") is not False and (cons.get("enabled") is True or cons.get("choice") == "contribute"):
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

def main() -> int:
    argv, cfg_path, state_dir = sys.argv[1:], _cfg_home() / f"{HOST}.json", _data_home() / "state" / HOST
    op, stdin_buf = (argv[1].lower().replace("_", "-") if len(argv) >= 2 and argv[0] == "hook" else ""), None
    if op in {"stop", "session-end", "sessionend"}:
        roots = _stop_roots(cfg_path)
        if not roots or not _in_roots(stdin_buf := sys.stdin.buffer.read(1048577), roots):
            sys.stdout.buffer.write(b"{}\n"); sys.stdout.buffer.flush(); return 0
    if (py := _active_python(cfg_path)) is not None:
        return subprocess.run([str(py), "-I", "-X", "utf8", "-m", CLI_MOD, "--host", HOST, "--plugin-root", str(PLUGIN_ROOT), "--config", str(cfg_path), *argv], input=stdin_buf, creationflags=_NO_WIN).returncode
    if op in {"pre-invocation", "user-prompt-submit"}:
        sys.stdout.buffer.write(b"{}\n"); sys.stdout.buffer.flush(); return 0
    if op == "session-start" or "--offline" in os.environ.get("_MINDIE_UV_FLAGS", ""):
        try:
            _enqueue_pending_check(state_dir)
        except OSError:
            pass
        sys.stdout.buffer.write(b"{}\n"); sys.stdout.buffer.flush(); return 0
    pyz, lock = PLUGIN_ROOT / "assets" / "mindie-harness-seed.pyz", PLUGIN_ROOT / "assets" / "seed-lock.json"
    _verify_seed(pyz, lock)
    return subprocess.run([sys.executable, "-I", "-X", "utf8", str(pyz), "--host", HOST, "--plugin-root", str(PLUGIN_ROOT), "--config", str(cfg_path), "--cli-module", CLI_MOD, *argv], input=stdin_buf, creationflags=_NO_WIN).returncode

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
        except OSError:
            return True
    return False


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
        except OSError:
            continue
    return None


def _resolve_python(uv_bin: str) -> str:
    if sys.executable and Path(sys.executable).is_file() and not _is_win_store_stub(Path(sys.executable)):
        return sys.executable
    res = subprocess.run(
        [uv_bin, "python", "find", ">=3.11"],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=10.0,
        check=False,
        creationflags=_CREATE_NO_WINDOW,
    )
    lines = (res.stdout or "").strip().splitlines()
    if res.returncode == 0 and lines:
        return lines[-1].strip()
    raise RuntimeError("No valid Python >=3.11 interpreter found for cold seed bootstrap")


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
    except (OSError, ValueError):
        return None


def _config_has_usable_python(cfg: dict[str, Any] | None) -> bool:
    if not isinstance(cfg, dict):
        return False
    rel = cfg.get("component_release")
    if isinstance(rel, str) and rel:
        rj = _read_seed_json(Path(rel) / "runtime.json")
        if isinstance(rj, dict) and (rj.get("validation") or {}).get("status") == "validated":
            py = Path(str(rj.get("python") or ""))
            if py.is_file():
                return True
    py_raw = cfg.get("python")
    return isinstance(py_raw, str) and bool(py_raw) and Path(py_raw).is_file()


def _ensure_host_config(
    cfg_path: Path,
    *,
    host: str,
    venv_py: Path,
    gen_dir: Path,
    plugin_root: Path,
    validation: dict[str, Any],
) -> None:
    existing = _read_seed_json(cfg_path)
    if _config_has_usable_python(existing):
        return
    merged = dict(existing) if isinstance(existing, dict) else {}
    merged.update(
        {
            "host": host,
            "python": str(venv_py),
            "component_release": str(gen_dir),
            "source_root": str(plugin_root),
            "product_validation": dict(validation),
        }
    )
    _atomic_json(cfg_path, merged)


def _run_owned_seed_cmd(cmd: list[str], *, env: dict[str, str], timeout: float) -> None:
    """Run a cold-seed build/probe command with full POSIX session or Win32 Job tree cleanup."""
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

        class _IO_COUNTERS(ctypes.Structure):
            _fields_ = [(f"f{i}", ctypes.c_uint64) for i in range(6)]

        class _BASIC_LIMITS(ctypes.Structure):
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

        class _EXTENDED_LIMITS(ctypes.Structure):
            _fields_ = [
                ("BasicLimitInformation", _BASIC_LIMITS),
                ("IoInfo", _IO_COUNTERS),
                ("ProcessMemoryLimit", ctypes.c_size_t),
                ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryUsed", ctypes.c_size_t),
                ("PeakJobMemoryUsed", ctypes.c_size_t),
            ]

        job = kernel32.CreateJobObjectW(None, None)
        ext = _EXTENDED_LIMITS()
        ext.BasicLimitInformation.LimitFlags = 0x00002000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if job:
            kernel32.SetInformationJobObject(job, 9, ctypes.byref(ext), ctypes.sizeof(ext))
        proc = subprocess.Popen(
            cmd,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            creationflags=_CREATE_NO_WINDOW,
        )
        try:
            if job:
                kernel32.AssignProcessToJobObject(job, wintypes.HANDLE(int(proc._handle)))
            _, err = proc.communicate(timeout=timeout)
        except BaseException:
            if job:
                kernel32.TerminateJobObject(job, 1)
            proc.kill()
            try:
                proc.wait(timeout=5.0)
            except subprocess.TimeoutExpired:
                pass
            raise
        finally:
            if job:
                kernel32.TerminateJobObject(job, 1)
                kernel32.CloseHandle(job)
        if proc.returncode != 0:
            raise subprocess.CalledProcessError(proc.returncode, cmd, stderr=err)
        return

    proc = subprocess.Popen(
        cmd,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
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


def _provision_cold(host: str, plugin_root: Path, cfg_path: Path, *, smoke_module: str = "mindie_harness") -> Path:
    d_home = _seed_data_home()
    d_home.mkdir(parents=True, exist_ok=True, mode=0o700)
    free_bytes = shutil.disk_usage(d_home).free
    if free_bytes < MIN_FREE_BYTES:
        raise RuntimeError(f"Insufficient disk space ({free_bytes}B < 2.5GiB) for cold runtime build")

    lock_path = d_home / f".prepare-{host}.lock"
    with lock_path.open("a+b") as lf:
        if os.name == "nt":
            import msvcrt

            lf.seek(0)
            lf.write(b"0")
            lf.flush()
            lf.seek(0)
            msvcrt.locking(lf.fileno(), msvcrt.LK_LOCK, 1)
        else:
            import fcntl

            fcntl.flock(lf.fileno(), fcntl.LOCK_EX)

        gen_dir = d_home / "runtimes" / host / f"seed-{sys.platform}"
        venv_dir = gen_dir / ".venv"
        py_rel = "Scripts/python.exe" if os.name == "nt" else "bin/python"
        venv_py = venv_dir / py_rel
        receipt_path = gen_dir / "runtime.json"
        existing_receipt = _read_seed_json(receipt_path)
        if (
            venv_py.is_file()
            and existing_receipt is not None
            and isinstance(existing_receipt.get("validation"), dict)
            and existing_receipt["validation"].get("status") == "validated"
        ):
            _ensure_host_config(
                cfg_path,
                host=host,
                venv_py=venv_py,
                gen_dir=gen_dir,
                plugin_root=plugin_root,
                validation=existing_receipt["validation"],
            )
            return venv_py

        if gen_dir.exists():
            shutil.rmtree(gen_dir, ignore_errors=True)

        uv_bin = _which_native("uv")
        if not uv_bin:
            raise RuntimeError("`uv` is required to provision the MindIE runtime")
        base_py = _resolve_python(uv_bin)
        env = dict(
            os.environ,
            UV_PROJECT_ENVIRONMENT=str(venv_dir),
            UV_CACHE_DIR=os.environ.get("UV_CACHE_DIR") or str(d_home / ".uv-cache"),
            PYTHONUTF8="1",
        )
        pyproject = plugin_root / "pyproject.toml"
        req_file = plugin_root / "runtime-requirements.txt"
        wheelhouse = plugin_root / "wheelhouse"
        if not pyproject.is_file() and not req_file.is_file() and not wheelhouse.is_dir():
            raise RuntimeError(
                f"Cannot provision runtime from {plugin_root}: missing pyproject.toml, runtime-requirements.txt, or wheelhouse"
            )

        gen_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            if pyproject.is_file():
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

            _run_owned_seed_cmd(
                [str(venv_py), "-I", "-X", "utf8", "-c", f"import {smoke_module}"],
                env=env,
                timeout=30.0,
            )
            validation = {"status": "validated", "validated_at": time.time()}
            _atomic_json(receipt_path, {"schema": "mindie-candidate-check/1", "key": gen_dir.name, "generation": str(gen_dir), "python": str(venv_py), "validation": validation})
            _ensure_host_config(
                cfg_path,
                host=host,
                venv_py=venv_py,
                gen_dir=gen_dir,
                plugin_root=plugin_root,
                validation=validation,
            )
            return venv_py
        except BaseException:
            shutil.rmtree(gen_dir, ignore_errors=True)
            raise


def _seed_stop_roots(cfg_path: Path) -> list[str]:
    cfg = _read_seed_json(cfg_path) or {}
    cp = (
        Path(c)
        if isinstance(c := cfg.get("community_config"), str) and os.path.isabs(c)
        else cfg_path.parent / "mindie-community.json"
    )
    comm = _read_seed_json(cp)
    sp_raw = (comm or {}).get("consent_config") or cfg.get("consent_config")
    sp = (
        Path(sp_raw)
        if isinstance(sp_raw, str) and os.path.isabs(sp_raw)
        else cfg_path.parent / "mindie-consent.json"
    )
    cons = _read_seed_json(sp)
    if comm is not None:
        if comm.get("enabled") is not True:
            return []
        if (sp.exists() or isinstance(comm.get("consent_config"), str)) and (
            not cons
            or cons.get("enabled") is False
            or cons.get("choice", "contribute" if cons.get("enabled") is True else None) != "contribute"
        ):
            return []
        roots = comm.get("project_roots")
    elif not cp.exists() and cons and cons.get("enabled") is not False and (
        cons.get("enabled") is True or cons.get("choice") == "contribute"
    ):
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
    cands = [ev.get(k) for k in ("cwd", "workspace", "workspace_root", "project_root", "directory")] + (
        wps if isinstance(wps, list) else []
    )
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
    parser.add_argument("--plugin-root")
    parser.add_argument("--config")
    parser.add_argument("--cli-module", default="mindie_harness.cli")
    known, rest = parser.parse_known_args(argv)

    if known.version:
        sys.stdout.write(f"mindie-harness-seed {SEED_VERSION}\n")
        return 0
    if known.emit_template:
        sys.stdout.write(render_plugin_bootstrap_template(known.emit_template, cli_module=known.cli_module))
        return 0
    if known.verify_lock:
        doc = verify_seed_lock(known.verify_lock[0], known.verify_lock[1])
        sys.stdout.write(json.dumps(doc, sort_keys=True) + "\n")
        return 0
    if not known.host or not known.plugin_root or not known.config:
        sys.stderr.write("Usage: mindie-harness-seed.pyz --host <host> --plugin-root <dir> --config <path> <args...>\n")
        return 2

    cfg_path = Path(known.config).resolve()
    hook_op = rest[1].lower().replace("_", "-") if len(rest) >= 2 and rest[0] == "hook" else ""
    stdin_buf: bytes | None = None
    if hook_op in {"pre-invocation", "user-prompt-submit"} and not _config_has_usable_python(_read_seed_json(cfg_path)):
        sys.stdout.buffer.write(b"{}\n")
        sys.stdout.buffer.flush()
        return 0
    if hook_op in {"stop", "session-end", "sessionend"}:
        roots = _seed_stop_roots(cfg_path)
        if not roots or not _seed_in_roots(stdin_buf := sys.stdin.buffer.read(1048577), roots):
            sys.stdout.buffer.write(b"{}\n")
            sys.stdout.buffer.flush()
            return 0

    top_pkg = str(known.cli_module).split(".", 1)[0]
    py = _provision_cold(known.host, Path(known.plugin_root).resolve(), cfg_path, smoke_module=top_pkg)
    if not rest:
        sys.stdout.write(json.dumps({"status": "provisioned", "python": str(py)}, sort_keys=True) + "\n")
        return 0
    proc = subprocess.run(
        [str(py), "-I", "-X", "utf8", "-m", known.cli_module, "--host", known.host, "--plugin-root", known.plugin_root, "--config", known.config, *rest],
        input=stdin_buf,
        creationflags=_CREATE_NO_WINDOW,
    )
    return proc.returncode


if __name__ == "__main__":
    raise SystemExit(main())
