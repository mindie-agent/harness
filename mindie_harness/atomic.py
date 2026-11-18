"""Same-volume atomic writes, UV cache volume pinning, and two-stage `.trash` retirement.

[Role]
Implements crash-safe atomic file publication (`atomic_write_bytes`, `atomic_write_text`,
`atomic_write_json`), UTF-8 BOM-tolerant JSON reading (`read_json_safe`), same-volume
`UV_CACHE_DIR` selection for zero-copy hardlinks (`configure_same_volume_uv_cache`),
and two-stage directory retirement (`stage_retire_directory`, `sweep_trash_directories`).

[Invariants]
- Every `tempfile.mkstemp` file is created in `path.parent` (same volume), synced
  via `os.fsync`, promoted via `os.replace`, and unlinked in `except BaseException:`
  on any failure (`P8` zero temp leak, Iron Rule 3 zero Win32 ACL ceremonies).
- Stage-1 directory retirement (`os.replace(target_dir, .trash.<name>.<uuid8>)`) is
  an $O(1)$ atomic rename probe: on Windows NTFS, any open `.lease`/`.exe`/`.pyd`
  handle inside `target_dir` fails the rename before touching a single child file.

[Timeouts & Locks]
- `sweep_trash_directories` enforces a monotonic `budget_seconds` deadline (`default 2.0s`),
  leaving remaining `.trash.*` fragments for the next maintenance cycle if time expires.

[Side-Effect Policy]
- Writes only to caller-specified target paths, temporary siblings, and `.trash.*`
  siblings inside managed generation directories.
"""
from __future__ import annotations

import errno
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import time
import uuid
from typing import Any, Mapping

TRASH_PREFIXES: tuple[str, ...] = (".trash.", ".trash-")
UV_CACHE_DIRNAME = ".uv-cache"
_WIN_LOCK_WINERRORS = frozenset({5, 32})  # ERROR_ACCESS_DENIED, ERROR_SHARING_VIOLATION


def atomic_write_bytes(path: str | Path, payload: bytes, *, mode: int = 0o600) -> Path:
    """Write `payload` to a same-volume sibling temp file, `fsync`, and `os.replace`."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, tmp_name = tempfile.mkstemp(
        prefix=f".{target.name}.tmp.",
        dir=str(target.parent),
    )
    tmp_path = Path(tmp_name)
    try:
        try:
            if os.name != "nt":
                os.fchmod(fd, mode)
            with os.fdopen(fd, "wb") as handle:
                fd = -1
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
        finally:
            if fd >= 0:
                os.close(fd)
        os.replace(tmp_path, target)
        return target
    except BaseException:
        try:
            tmp_path.unlink(missing_ok=True)
        except TimeoutError:
            raise
        except OSError:
            pass
        raise


def atomic_write_text(path: str | Path, text: str, *, mode: int = 0o600) -> Path:
    """Write UTF-8 text with Unix LF (`\\n`) line endings atomically."""
    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    return atomic_write_bytes(path, normalized.encode("utf-8"), mode=mode)


def atomic_write_json(path: str | Path, data: Any, *, mode: int = 0o600, indent: int = 2) -> Path:
    """Serialize `data` as sorted-key UTF-8 JSON with trailing newline atomically."""
    rendered = json.dumps(data, ensure_ascii=False, indent=indent, sort_keys=True) + "\n"
    return atomic_write_text(path, rendered, mode=mode)


def read_json_safe(path: str | Path) -> Any | None:
    """Read JSON tolerating UTF-8 BOM (`utf-8-sig`); returns `None` when absent."""
    target = Path(path)
    try:
        if not target.is_file():
            return None
        raw = target.read_bytes()
    except TimeoutError:
        raise
    except OSError:
        return None
    try:
        return json.loads(raw.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None


def _existing_device(path: Path) -> int | None:
    probe = Path(path)
    while True:
        try:
            return os.stat(probe).st_dev
        except FileNotFoundError:
            if probe.parent == probe:
                return None
            probe = probe.parent
        except TimeoutError:
            raise
        except OSError:
            return None


def _default_uv_cache(env: Mapping[str, str]) -> Path:
    if xdg := env.get("XDG_CACHE_HOME"):
        if xdg.strip():
            return Path(xdg) / "uv"
    if os.name == "nt":
        local_app = env.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        return Path(local_app) / "uv" / "cache"
    if sys.platform == "darwin":
        legacy = Path.home() / ".cache" / "uv"
        if legacy.exists():
            return legacy
        return Path.home() / "Library" / "Caches" / "uv"
    return Path.home() / ".cache" / "uv"


def configure_same_volume_uv_cache(
    target_dir: str | Path,
    env: Mapping[str, str] | None = None,
    *,
    preferred: str | Path | None = None,
) -> dict[str, str]:
    """Return a copy of `env` with `UV_CACHE_DIR` pinned to `target_dir`'s volume."""
    out = dict(os.environ if env is None else env)
    explicit = out.get("UV_CACHE_DIR")
    if isinstance(explicit, str) and explicit.strip():
        return out
    target = Path(target_dir)
    target_dev = _existing_device(target)
    if target_dev is None:
        return out
    default_cache = _default_uv_cache(out)
    if _existing_device(default_cache) == target_dev:
        return out

    candidates: list[Path] = []
    if preferred is not None:
        candidates.append(Path(preferred))
    resolved = target.absolute()
    candidates.extend((resolved.parent / UV_CACHE_DIRNAME, resolved / UV_CACHE_DIRNAME))
    for cand in candidates:
        if _existing_device(cand) == target_dev:
            out["UV_CACHE_DIR"] = str(cand)
            return out
    return out


def _is_in_use_oserror(exc: OSError) -> bool:
    winerr = getattr(exc, "winerror", None)
    if winerr in _WIN_LOCK_WINERRORS:
        return True
    return exc.errno in {errno.EACCES, errno.EPERM, errno.EBUSY, errno.ENOTEMPTY}


def stage_retire_directory(
    target_dir: str | Path,
    *,
    trash_prefix: str = ".trash.",
) -> tuple[str, Path | None]:
    """Atomically rename `target_dir` to a same-volume `.trash.<name>.<uuid8>` directory.

    Returns `("retired", trash_path)`, `("deferred_in_use", None)`, or `("absent", None)`.
    """
    target = Path(target_dir)
    if not target.exists() and not target.is_symlink():
        return "absent", None
    trash_name = f"{trash_prefix}{target.name}.{uuid.uuid4().hex[:8]}"
    trash_path = target.parent / trash_name
    try:
        os.replace(target, trash_path)
        return "retired", trash_path
    except FileNotFoundError:
        return "absent", None
    except TimeoutError:
        raise
    except OSError as exc:
        if _is_in_use_oserror(exc):
            return "deferred_in_use", None
        raise


def _unlink_clearing_readonly(entry_path: Path, *, is_dir: bool) -> bool:
    """Remove a single file or empty directory inside `.trash.*`, clearing readonly bits."""
    try:
        if is_dir:
            os.rmdir(entry_path)
        else:
            os.unlink(entry_path)
        return True
    except FileNotFoundError:
        return True
    except PermissionError:
        try:
            os.chmod(entry_path, stat.S_IWRITE | stat.S_IREAD | (stat.S_IEXEC if is_dir else 0))
            if is_dir:
                os.rmdir(entry_path)
            else:
                os.unlink(entry_path)
            return True
        except TimeoutError:
            raise
        except OSError:
            return False
    except TimeoutError:
        raise
    except OSError:
        return False


def _remove_trash_tree_bounded(trash_dir: Path, deadline: float) -> bool:
    """Bottom-up bounded removal of one `.trash.*` tree; never follows directory symlinks."""
    if trash_dir.is_symlink():
        return _unlink_clearing_readonly(trash_dir, is_dir=False)
    stack: list[tuple[Path, bool]] = [(trash_dir, False)]
    all_removed = True
    while stack:
        if time.monotonic() >= deadline:
            return False
        current, visited = stack.pop()
        if visited:
            if not _unlink_clearing_readonly(current, is_dir=True):
                all_removed = False
            continue
        stack.append((current, True))
        try:
            with os.scandir(current) as it:
                for entry in it:
                    if time.monotonic() >= deadline:
                        return False
                    entry_path = Path(entry.path)
                    try:
                        is_real_dir = entry.is_dir(follow_symlinks=False)
                    except TimeoutError:
                        raise
                    except OSError:
                        is_real_dir = False
                    if is_real_dir:
                        stack.append((entry_path, False))
                    else:
                        if not _unlink_clearing_readonly(entry_path, is_dir=False):
                            all_removed = False
        except FileNotFoundError:
            continue
        except TimeoutError:
            raise
        except OSError:
            all_removed = False
    return all_removed


def sweep_trash_directories(
    root_dir: str | Path,
    *,
    budget_seconds: float = 2.0,
    trash_prefixes: tuple[str, ...] = TRASH_PREFIXES,
) -> dict[str, Any]:
    """Best-effort, time-boxed Stage-2 sweep of `.trash.*` directories under `root_dir`."""
    root = Path(root_dir)
    deadline = time.monotonic() + max(0.05, float(budget_seconds))
    reclaimed = 0
    deferred = 0
    partial = False
    if not root.is_dir():
        return {"reclaimed_trash": 0, "deferred_trash": 0, "partial": False}

    try:
        with os.scandir(root) as it:
            trash_entries = [
                Path(e.path)
                for e in it
                if any(e.name.startswith(pref) for pref in trash_prefixes)
            ]
    except TimeoutError:
        raise
    except OSError:
        return {"reclaimed_trash": 0, "deferred_trash": 0, "partial": True}

    for trash_path in sorted(trash_entries, key=lambda p: p.name):
        if time.monotonic() >= deadline:
            partial = True
            deferred += 1
            continue
        if _remove_trash_tree_bounded(trash_path, deadline):
            reclaimed += 1
        else:
            deferred += 1
            if time.monotonic() >= deadline:
                partial = True
    return {
        "reclaimed_trash": reclaimed,
        "deferred_trash": deferred,
        "partial": partial,
    }
