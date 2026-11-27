"""Host state root resolution, WSL2 DrvFS mount detection, and SQLite WAL open gate.

[Role]
Resolves canonical and legacy host profile paths (`ProfileRef`), isolates platform
virtual environments (`.venv-win32` vs `.venv-linux` / `.venv-darwin`), detects
WSL2 cross-OS `drvfs`/`9p` mounts from `/proc/self/mountinfo` regardless of mount
prefix, enforces Iron Rule 1 (`open_wal_database` / `open_database`), and resolves
real host Python interpreters while rejecting Windows `WindowsApps` Store stubs.

[Invariants]
- Read-only database checks (`create=False`) NEVER create empty SQLite files or
  `-wal`/`-shm` sidecars when the database file is absent.
- SQLite WAL databases are NEVER opened on WSL2 `drvfs`/`9p` (`aname=drvfs`)
  mounts (`HarnessError` with `reason="drvfs_unsafe_state_root"`).
- Existing `<host>.json` paths (`admission_path`, `engine_config`, `python`,
  `component_release`) are preserved in-place so live upgrades never strand user state.

[Timeouts & Locks]
- `open_wal_database` enforces a `5.0s` remaining-deadline floor (`busy_timeout=5000`)
  before entering SQLite and attaches a monotonic `progress_handler` when bounded.
- Fallback `uv python find` discovery on Windows is bounded to `10.0s` with `CREATE_NO_WINDOW`.

[Side-Effect Policy]
- Path resolution and mount inspection are pure read-only queries; only
  `open_wal_database(..., create=True)` creates its parent directory (`0o700`) and DB.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import subprocess
import sys
import time
from typing import Any, Mapping

HOSTS: tuple[str, ...] = ("codex", "cc", "kimi", "dsh", "agy", "wb", "oc", "omp")
SQLITE_BUSY_TIMEOUT_MS = 5000
SQLITE_MIN_BUDGET_SECONDS = 5.0
_OCTAL_ESCAPE_RE = re.compile(r"\\([0-7]{3})")
_CREATE_NO_WINDOW = 0x08000000 if os.name == "nt" else 0


class HarnessError(RuntimeError):
    """Structured substrate error carrying machine-stable stage and reason codes."""

    def __init__(
        self,
        message: str,
        *,
        stage: str = "internal",
        reason: str = "internal_error",
        submission_state: str = "not_sent",
        retryable: bool = False,
        reportable: bool = True,
        details: Mapping[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.stage = stage
        self.reason = reason
        self.submission_state = submission_state
        self.retryable = bool(retryable)
        self.reportable = bool(reportable)
        self.details: dict[str, Any] = dict(details or {})

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "stage": self.stage,
            "reason": self.reason,
            "submission_state": self.submission_state,
            "retryable": self.retryable,
            "reportable": self.reportable,
            "message": str(self),
        }
        if self.details:
            payload["details"] = dict(self.details)
        return payload


@dataclass(frozen=True)
class MountEntry:
    """Parsed row from Linux `/proc/self/mountinfo`."""

    mount_point: str
    fstype: str
    source: str
    mount_options: str
    super_options: str

    @property
    def is_drvfs(self) -> bool:
        fs = self.fstype.lower()
        if fs in {"drvfs", "wslfs"}:
            return True
        if fs == "9p":
            combined = f"{self.mount_options},{self.super_options},{self.source}".lower()
            if "aname=drvfs" in combined or "drvfs" in combined:
                return True
        return False


def _unescape_mount_field(raw: str) -> str:
    return _OCTAL_ESCAPE_RE.sub(lambda m: chr(int(m.group(1), 8)), raw)


def parse_mountinfo(text: str) -> list[MountEntry]:
    """Parse Linux `/proc/self/mountinfo` lines, including spaces (`\\040`) and `(x86)`."""
    entries: list[MountEntry] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or " - " not in line:
            continue
        left, right = line.split(" - ", 1)
        left_parts = left.split()
        right_parts = right.split()
        if len(left_parts) < 6 or len(right_parts) < 2:
            continue
        mount_point = _unescape_mount_field(left_parts[4])
        mount_opts = _unescape_mount_field(left_parts[5])
        fstype = _unescape_mount_field(right_parts[0])
        source = _unescape_mount_field(right_parts[1])
        super_opts = _unescape_mount_field(right_parts[2]) if len(right_parts) >= 3 else ""
        entries.append(
            MountEntry(
                mount_point=mount_point,
                fstype=fstype,
                source=source,
                mount_options=mount_opts,
                super_options=super_opts,
            )
        )
    return entries


def _existing_ancestor_resolved(path: Path) -> str:
    """Resolve symlinks on the deepest existing ancestor while keeping non-existent suffixes."""
    abs_path = Path(os.path.abspath(os.fspath(path)))
    tail: list[str] = []
    probe = abs_path
    while True:
        try:
            if probe.exists():
                resolved_base = probe.resolve()
                for part in reversed(tail):
                    resolved_base = resolved_base / part
                return os.path.normpath(str(resolved_base))
        except TimeoutError:
            raise
        except OSError:
            pass
        if probe.parent == probe:
            return os.path.normpath(str(abs_path))
        tail.append(probe.name)
        probe = probe.parent


def is_wsl_drvfs(path: str | Path, *, mountinfo_text: str | None = None) -> bool:
    """Return True when `path` resides on a WSL2 Windows `drvfs` / `9p` (`aname=drvfs`) mount."""
    if mountinfo_text is None:
        if sys.platform != "linux":
            return False
        mountinfo_path = Path("/proc/self/mountinfo")
        try:
            if not mountinfo_path.is_file():
                return False
            mountinfo_text = mountinfo_path.read_text(encoding="utf-8", errors="replace")
        except TimeoutError:
            raise
        except OSError:
            return False

    entries = parse_mountinfo(mountinfo_text)
    if not entries:
        return False
    raw_path = os.fspath(path)
    if (
        os.name == "nt"
        and mountinfo_text is not None
        and raw_path.startswith(("/", "\\"))
        and not raw_path.startswith("\\\\")
    ):
        import posixpath

        target = posixpath.normpath(raw_path.replace("\\", "/"))
    else:
        target = _existing_ancestor_resolved(Path(path))
    if not target.startswith("/"):
        return False

    best_match: MountEntry | None = None
    best_len = -1
    for entry in entries:
        mp = entry.mount_point.rstrip("/") or "/"
        if mp == "/":
            matched = True
        else:
            matched = target == mp or target.startswith(mp + "/")
        if matched and len(mp) >= best_len:
            best_match = entry
            best_len = len(mp)
    return bool(best_match is not None and best_match.is_drvfs)


def assert_wal_safe_path(path: str | Path, *, mountinfo_text: str | None = None) -> Path:
    """Reject WSL2 DrvFS paths before opening SQLite WAL state."""
    resolved = Path(path)
    if is_wsl_drvfs(resolved, mountinfo_text=mountinfo_text):
        raise HarnessError(
            f"Refusing to place SQLite WAL state on WSL2 DrvFS mount ({resolved}); "
            "move MINDIE_DATA_HOME / MINDIE_CONFIG_HOME to native Linux storage "
            "(e.g. ~/.local/share/mindie-agent).",
            stage="sqlite_open",
            reason="drvfs_unsafe_state_root",
            submission_state="not_sent",
            retryable=False,
            reportable=False,
            details={"path": str(resolved)},
        )
    return resolved


def open_wal_database(
    path: str | Path,
    *,
    create: bool = True,
    deadline: float | None = None,
    mountinfo_text: str | None = None,
) -> sqlite3.Connection | None:
    """Open a SQLite database with Iron Rule 1 WAL + `busy_timeout=5000` configured once."""
    db_path = Path(path)
    if not create and not db_path.is_file():
        return None
    assert_wal_safe_path(db_path.parent, mountinfo_text=mountinfo_text)
    if deadline is not None and (deadline - time.monotonic()) < SQLITE_MIN_BUDGET_SECONDS:
        raise TimeoutError(
            f"Remaining deadline is below {SQLITE_MIN_BUDGET_SECONDS:.1f}s SQLite WAL lock floor"
        )
    if create:
        db_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        conn = sqlite3.connect(str(db_path), timeout=SQLITE_MIN_BUDGET_SECONDS)
    else:
        try:
            conn = sqlite3.connect(
                f"{db_path.resolve().as_uri()}?mode=rw",
                uri=True,
                timeout=SQLITE_MIN_BUDGET_SECONDS,
            )
        except sqlite3.OperationalError:
            if not db_path.is_file():
                return None
            conn = sqlite3.connect(
                f"{db_path.resolve().as_uri()}?mode=ro",
                uri=True,
                timeout=SQLITE_MIN_BUDGET_SECONDS,
            )
    try:
        if create and os.name != "nt":
            try:
                os.chmod(db_path, 0o600)
            except TimeoutError:
                raise
            except OSError:
                pass
        conn.execute(f"PRAGMA busy_timeout={SQLITE_BUSY_TIMEOUT_MS}")
        if create:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA cache_size=-2048")
        if deadline is not None:
            def _check_deadline() -> int:
                return 1 if time.monotonic() >= deadline else 0

            conn.set_progress_handler(_check_deadline, 1000)
        return conn
    except BaseException:
        conn.close()
        raise


# Iron Rule 1 canonical alias
open_database = open_wal_database


def _home_dir(env: Mapping[str, str]) -> Path:
    if os.name == "nt":
        raw = env.get("USERPROFILE") or env.get("HOME")
    else:
        raw = env.get("HOME") or env.get("USERPROFILE")
    return Path(raw).expanduser() if raw else Path.home()


def config_home(env: Mapping[str, str] | None = None) -> Path:
    """Resolve `<MINDIE_CONFIG_HOME>` without creating directories."""
    environ = os.environ if env is None else env
    if explicit := environ.get("MINDIE_CONFIG_HOME"):
        return Path(explicit).expanduser()
    home = _home_dir(environ)
    if os.name == "nt":
        base = Path(environ.get("APPDATA") or (home / "AppData" / "Roaming"))
        return base / "mindie-agent"
    base = Path(environ.get("XDG_CONFIG_HOME") or (home / ".config"))
    return base / "mindie-agent"


def data_home(env: Mapping[str, str] | None = None) -> Path:
    """Resolve `<MINDIE_DATA_HOME>` without creating directories."""
    environ = os.environ if env is None else env
    if explicit := environ.get("MINDIE_DATA_HOME"):
        return Path(explicit).expanduser()
    home = _home_dir(environ)
    if os.name == "nt":
        base = Path(environ.get("LOCALAPPDATA") or (home / "AppData" / "Local"))
        return base / "mindie-agent"
    base = Path(environ.get("XDG_DATA_HOME") or (home / ".local" / "share"))
    return base / "mindie-agent"


def diagnostics_root(env: Mapping[str, str] | None = None) -> Path:
    """Resolve `<MINDIE_DIAGNOSTICS_ROOT>`."""
    environ = os.environ if env is None else env
    if explicit := environ.get("MINDIE_DIAGNOSTICS_ROOT"):
        return Path(explicit).expanduser()
    return data_home(environ) / "diagnostics"


def remote_state_dir(env: Mapping[str, str] | None = None) -> Path:
    """Resolve independent remote-dev receipt/job state directory."""
    environ = os.environ if env is None else env
    if explicit := environ.get("MINDIE_REMOTE_STATE_DIR"):
        return Path(explicit).expanduser()
    return data_home(environ) / "remote-dev"


def venv_dir_name(platform_name: str | None = None) -> str:
    """Isolate `.venv-win32` vs `.venv-linux` / `.venv-darwin` on shared worktrees."""
    plat = sys.platform if platform_name is None else platform_name
    if plat.startswith("win"):
        return ".venv-win32"
    if plat.startswith("linux"):
        return ".venv-linux"
    if plat == "darwin":
        return ".venv-darwin"
    return f".venv-{plat}"


def venv_python_path(venv_dir: str | Path, *, windowless: bool = False, is_windows: bool | None = None) -> Path:
    """Return the platform interpreter path inside `venv_dir`."""
    win = (os.name == "nt") if is_windows is None else is_windows
    base = Path(venv_dir)
    if win:
        return base / "Scripts" / ("pythonw.exe" if windowless else "python.exe")
    return base / "bin" / "python"


def is_windows_store_stub(candidate: str | Path) -> bool:
    """Detect Windows `Microsoft\\WindowsApps\\python*.exe` 0-byte App Execution Alias stubs."""
    raw = str(candidate)
    lowered = raw.replace("/", "\\").lower()
    if "\\microsoft\\windowsapps\\" in lowered:
        return True
    if os.name == "nt":
        try:
            st = os.stat(candidate)
            if st.st_size == 0:
                return True
        except TimeoutError:
            raise
        except OSError:
            return True
    return False


def resolve_host_python(env: Mapping[str, str] | None = None) -> Path:
    """Locate a real host Python >=3.11, skipping Windows Store stubs and falling back to `uv python find`."""
    environ = os.environ if env is None else env
    curr = Path(sys.executable) if sys.executable else None
    if curr and curr.is_file() and not is_windows_store_stub(curr):
        return curr

    path_str = environ.get("PATH", "")
    names = ("python.exe", "python3.exe") if os.name == "nt" else ("python3", "python")
    for folder in path_str.split(os.pathsep):
        folder_clean = folder.strip().strip('"')
        if not folder_clean:
            continue
        for name in names:
            cand = Path(folder_clean) / name
            if os.name != "nt" and is_wsl_drvfs(cand):
                continue
            try:
                if cand.is_file() and not is_windows_store_stub(cand):
                    return cand
            except TimeoutError:
                raise
            except OSError:
                continue

    uv_bin = shutil.which("uv", path=path_str or None)
    if uv_bin:
        try:
            proc = subprocess.run(
                [uv_bin, "python", "find", ">=3.11"],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=10.0,
                check=False,
                env=dict(environ),
                creationflags=_CREATE_NO_WINDOW,
            )
            found = (proc.stdout or "").strip().splitlines()
            if proc.returncode == 0 and found:
                py_path = Path(found[-1].strip())
                if py_path.is_file() and not is_windows_store_stub(py_path):
                    return py_path
        except TimeoutError:
            raise
        except (OSError, subprocess.TimeoutExpired):
            pass

    raise HarnessError(
        "No usable host Python (>=3.11) found on PATH or via `uv python find`",
        stage="bootstrap",
        reason="python_not_found",
        retryable=False,
        reportable=False,
    )


def same_interpreter(first: str | Path | None, second: str | Path | None) -> bool:
    """Compare two Python interpreter paths without collapsing venv symlinks onto base CPython."""
    if not first or not second:
        return False
    left = os.path.normcase(os.path.abspath(os.path.expanduser(str(first))))
    right = os.path.normcase(os.path.abspath(os.path.expanduser(str(second))))
    return left == right


def resolve_base_cpython(candidate: str | Path | None = None, env: Mapping[str, str] | None = None) -> Path:
    """Unwrap `pyvenv.cfg` `home` so new venv builds target real base CPython rather than nesting venvs."""
    py = Path(candidate) if candidate is not None else resolve_host_python(env)
    for cfg in (py.parent.parent / "pyvenv.cfg", py.parent / "pyvenv.cfg"):
        try:
            if not cfg.is_file():
                continue
            for raw_line in cfg.read_text(encoding="utf-8-sig", errors="replace").splitlines():
                key, sep, val = raw_line.partition("=")
                if sep and key.strip().lower() == "home" and val.strip():
                    home_dir = Path(val.strip())
                    names = ("python.exe", "python3.exe") if os.name == "nt" else ("python3", "python")
                    for name in names:
                        base_cand = home_dir / name
                        if base_cand.is_file() and not is_windows_store_stub(base_cand):
                            return base_cand
        except TimeoutError:
            raise
        except OSError:
            continue
    base_exec = getattr(sys, "_base_executable", None)
    if candidate is None and isinstance(base_exec, str) and base_exec:
        bp = Path(base_exec)
        if bp.is_file() and not is_windows_store_stub(bp):
            return bp
    return py


def _norm_abs(path: str | Path) -> Path:
    """Normalize `path` to an absolute path without dereferencing leaf venv symlinks."""
    return Path(os.path.abspath(os.path.expanduser(str(path))))


def _load_existing_dict(path: Path) -> dict[str, Any]:
    try:
        if not path.is_file():
            return {}
        data = json.loads(path.read_bytes().decode("utf-8-sig"))
        return data if isinstance(data, dict) else {}
    except TimeoutError:
        raise
    except (OSError, ValueError):
        return {}


@dataclass(frozen=True)
class ProfileRef:
    """Canonical + legacy-compatible path bundle for one host plugin installation."""

    host: str
    plugin_root: Path
    config_path: Path
    consent_path: Path
    data_dir: Path
    state_dir: Path
    generations_dir: Path
    admission_db: Path
    binds_db: Path
    receipts_db: Path
    pending_update_path: Path

    @classmethod
    def resolve(
        cls,
        host: str,
        *,
        plugin_root: str | Path | None = None,
        config_path: str | Path | None = None,
        data_dir: str | Path | None = None,
        env: Mapping[str, str] | None = None,
    ) -> "ProfileRef":
        clean_host = str(host or "").strip().lower()
        if clean_host not in HOSTS:
            raise HarnessError(
                f"Unsupported MindIE host {host!r}; expected one of {HOSTS}",
                stage="cli_input",
                reason="invalid_host",
                reportable=False,
            )
        environ = os.environ if env is None else env
        cfg_root = _norm_abs(config_home(environ))
        dat_root = _norm_abs(data_home(environ))
        cfg_file = _norm_abs(config_path) if config_path else (
            _norm_abs(environ["MINDIE_AGENT_CONFIG"])
            if environ.get("MINDIE_AGENT_CONFIG")
            else cfg_root / f"{clean_host}.json"
        )
        existing = _load_existing_dict(cfg_file)
        resolved_plugin_root = (
            _norm_abs(plugin_root)
            if plugin_root
            else _norm_abs(existing.get("source_root") or Path.cwd())
        )
        resolved_data = _norm_abs(data_dir) if data_dir else dat_root
        state_dir = resolved_data / "state" / clean_host
        generations_dir = resolved_data / "runtimes" / clean_host

        # Preserve pre-upgrade admission_path if recorded in <host>.json or engine_config
        admission_db = state_dir / "admission.sqlite3"
        if isinstance(existing.get("admission_path"), str) and existing["admission_path"].strip():
            admission_db = _norm_abs(existing["admission_path"])
        elif isinstance(existing.get("engine_config"), str) and existing["engine_config"].strip():
            eng = _load_existing_dict(_norm_abs(existing["engine_config"]))
            if isinstance(eng.get("admission_path"), str) and eng["admission_path"].strip():
                admission_db = _norm_abs(eng["admission_path"])

        consent_path = cfg_file.parent / "mindie-consent.json"
        if isinstance(existing.get("consent_config"), str) and existing["consent_config"].strip():
            consent_path = _norm_abs(existing["consent_config"])

        return cls(
            host=clean_host,
            plugin_root=resolved_plugin_root,
            config_path=cfg_file,
            consent_path=consent_path,
            data_dir=resolved_data,
            state_dir=state_dir,
            generations_dir=generations_dir,
            admission_db=admission_db,
            binds_db=state_dir / "mcp-binds.sqlite3",
            receipts_db=state_dir / "remote-receipts.sqlite3",
            pending_update_path=state_dir / "pending-update-check.json",
        )
