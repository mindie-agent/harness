"""SHA-256 streaming, local/HTTP asset sourcing, and hardened wheel bundle extraction.

[Role]
Supplies the zero-Git asset primitives used by `mindie_harness.runtime.wheelhouse`:
`parse_sha256sums`, `download_verified` (sibling temp file + `64 KiB` SHA-256
streaming + `os.replace`), `fetch_checksums`, `extract_wheel_bundle_safely`, and
`check_component_version_floors` (the under-`update_lock` downgrade guard).

[Invariants]
- Assets are never accepted in place: each download is written to a sibling
  `.part.<pid>.<uuid>` file, verified, then atomically promoted, and the temp
  file is removed in `finally:` on every failure path.
- Tar extraction rejects absolute member names, `..` traversal, symlinks,
  hardlinks, FIFOs, character/block devices, and any path escaping `dest_dir`;
  only `.whl`, `requirements.lock`, and `SHA256SUMS` regular files are written.
- `file://` sources preserve `//server/share/...` UNC hosts via `url2pathname`
  instead of discarding `urlparse().netloc`.
- HTTP 404 and missing local files are reported as absence, never as poison state.

[Timeouts & Locks]
- Every network read is bounded by the caller's `timeout` (default `30.0s`) and an
  optional outer `Deadline`; an expired `Deadline` re-raises `TimeoutError`, while a
  lone socket read timeout becomes retryable `HarnessError(stage="asset_fetch")`.
- No locks or global state are held.

[Side-Effect Policy]
- Writes only caller-supplied destination files, `.part.*` siblings, and the
  extracted wheelhouse directory.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import shutil
import tarfile
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import url2pathname, urlopen
import uuid

from ..atomic import read_json_safe
from ..component_commands import STANDARD_COMPONENT_COMMANDS, is_standard_module_command, command_argv
from ..paths import HarnessError, ProfileRef
from ..process.supervisor import Deadline, ProcessSpec, run_owned
from .registry import RuntimeSelection, parse_version_key

BUNDLE_NAME = "mindie-wheels-bundle.tar.gz"
CHECKSUM_NAME = "SHA256SUMS"
CHUNK_BYTES = 65536


def _fail(reason: str, message: str, *, stage: str = "wheelhouse", retryable: bool = True, details: dict[str, object] | None = None) -> HarnessError:
    return HarnessError(message, stage=stage, reason=reason, submission_state="not_sent", retryable=retryable, reportable=False, details=details)


def _raise_http_timeout(exc: BaseException, deadline: Deadline | None, source: object) -> None:
    """Re-raise an expired outer deadline; otherwise classify a socket read timeout."""
    if deadline is not None and deadline.expired():
        raise exc
    raise _fail(
        "http_timeout",
        f"HTTP request timed out for {source}",
        stage="asset_fetch",
        retryable=True,
    ) from exc


def parse_sha256sums(text: str) -> dict[str, str]:
    """Parse `<64hex>  <filename>` and `<64hex> *<filename>` `SHA256SUMS` lines."""
    out: dict[str, str] = {}
    for raw_line in str(text or "").splitlines():
        parts = raw_line.strip().split(None, 1)
        if len(parts) != 2:
            continue
        digest, filename = parts[0].strip().lower(), parts[1].strip()
        if filename.startswith("*"):
            filename = filename[1:].strip()
        if len(digest) == 64 and all(ch in "0123456789abcdef" for ch in digest) and filename:
            out[filename] = digest
    return out


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        while chunk := handle.read(CHUNK_BYTES):
            digest.update(chunk)
    return digest.hexdigest()


def asset_source(base: str, name: str) -> str | Path:
    """Resolve `name` under an HTTP(S), `file://` (including UNC), or local-dir base."""
    text = str(base)
    if text.lower().startswith(("http://", "https://")):
        return f"{text.rstrip('/')}/{name}"
    parsed = urlparse(text)
    if parsed.scheme == "file":
        local = url2pathname(parsed.path)
        if parsed.netloc and parsed.netloc.lower() != "localhost":
            local = f"\\\\{parsed.netloc}{local}" if os.name == "nt" else f"//{parsed.netloc}{local}"
        return Path(local) / name
    return Path(text).expanduser() / name


def _stream_copy(source: str | Path, dest: Path, *, timeout: float, deadline: Deadline | None = None) -> None:
    if isinstance(source, Path):
        with source.open("rb") as src, dest.open("wb") as dst:
            while chunk := src.read(CHUNK_BYTES):
                dst.write(chunk)
        return
    try:
        with urlopen(str(source), timeout=timeout) as response, dest.open("wb") as dst:
            while chunk := response.read(CHUNK_BYTES):
                dst.write(chunk)
    except TimeoutError as exc:
        _raise_http_timeout(exc, deadline, source)


def download_verified(source: str | Path, dest: Path, expected: str | None, *, timeout: float, deadline: Deadline | None = None) -> bool:
    """Stream `source` into a sibling temp file, verify SHA-256, then `os.replace`."""
    dest.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = dest.parent / f".{dest.name}.part.{os.getpid()}.{uuid.uuid4().hex[:8]}"
    try:
        _stream_copy(source, tmp, timeout=timeout, deadline=deadline)
        actual = sha256_file(tmp)
        if expected and actual != str(expected).strip().lower():
            raise _fail(
                "checksum_mismatch",
                f"SHA-256 mismatch for {dest.name}",
                details={"asset": dest.name, "expected": str(expected), "actual": actual},
            )
        os.replace(tmp, dest)
        return bool(expected)
    finally:
        try:
            tmp.unlink(missing_ok=True)
        except TimeoutError:
            raise
        except OSError:
            pass


def read_asset_text(source: str | Path, *, timeout: float, deadline: Deadline | None = None) -> str:
    if isinstance(source, Path):
        return source.read_text(encoding="utf-8", errors="replace")
    try:
        with urlopen(str(source), timeout=timeout) as response:
            return response.read(2 * 1024 * 1024).decode("utf-8", errors="replace")
    except TimeoutError as exc:
        _raise_http_timeout(exc, deadline, source)
        raise  # pragma: no cover - _raise_http_timeout always raises


def fetch_checksums(base: str, *, timeout: float, deadline: Deadline | None = None) -> tuple[dict[str, str], bool]:
    try:
        return parse_sha256sums(read_asset_text(asset_source(base, CHECKSUM_NAME), timeout=timeout, deadline=deadline)), True
    except TimeoutError:
        raise
    except FileNotFoundError:
        return {}, False
    except HTTPError as exc:
        if int(getattr(exc, "code", 0) or 0) == 404:
            return {}, False
        raise
    except URLError:
        return {}, False


def _unsafe_member(name: str, member: tarfile.TarInfo) -> bool:
    normalized = name.replace("\\", "/")
    parts = [part for part in normalized.split("/") if part not in {"", "."}]
    return (
        not name or Path(name).is_absolute() or normalized.startswith("/")
        or (len(name) >= 2 and name[1] == ":")
        or any(part == ".." for part in parts)
        or member.issym() or member.islnk() or member.isfifo()
        or member.ischr() or member.isblk() or member.isdev()
    )


def extract_wheel_bundle_safely(tar_path: Path, dest_dir: Path) -> Path:
    """Extract only `.whl`, `requirements.lock`, and `SHA256SUMS` with strict path checks."""
    root = Path(dest_dir).resolve()
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    with tarfile.open(tar_path, "r:gz") as archive:
        for member in archive.getmembers():
            name = str(member.name or "")
            if _unsafe_member(name, member):
                raise _fail("unsafe_archive_member", f"Unsafe tar member rejected: {name!r}", stage="wheelhouse_extract", retryable=False)
            if not member.isfile() or not (name.endswith(".whl") or name in {CHECKSUM_NAME, "requirements.lock"}):
                continue
            destination = (root / name).resolve()
            try:
                destination.relative_to(root)
            except ValueError as exc:
                raise _fail("unsafe_archive_member", f"Tar member escapes destination: {name!r}", stage="wheelhouse_extract", retryable=False) from exc
            source = archive.extractfile(member)
            if source is None:
                continue
            destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            tmp = destination.parent / f".{destination.name}.part.{os.getpid()}.{uuid.uuid4().hex[:8]}"
            try:
                with source, tmp.open("wb") as handle:
                    shutil.copyfileobj(source, handle, length=CHUNK_BYTES)
                os.replace(tmp, destination)
            finally:
                try:
                    tmp.unlink(missing_ok=True)
                except TimeoutError:
                    raise
                except OSError:
                    pass
    return root


def installed_package_version(python_exe: str, package: str) -> str | None:
    """Return the package version importable by `python_exe`, bounded to `10s`."""
    statement = f"import importlib.metadata as m; print(m.version({package!r}))"
    try:
        outcome = run_owned(ProcessSpec(argv=(python_exe, "-I", "-X", "utf8", "-c", statement), role="background_maintenance", memory_limit_bytes=None, allowed_returncodes=None), deadline=Deadline.from_timeout(10.0))
    except TimeoutError:
        raise
    except (OSError, HarnessError):
        return None
    text = (outcome.stdout or "").strip()
    return text if outcome.returncode == 0 and text else None


def check_component_version_floors(profile: ProfileRef, selection: RuntimeSelection) -> None:
    """Refuse a candidate that would downgrade an installed standard component CLI."""
    cfg = read_json_safe(profile.config_path)
    if not isinstance(cfg, dict) or not isinstance(cfg.get("component_commands"), dict):
        return
    for key, (package, module) in STANDARD_COMPONENT_COMMANDS.items():
        argv = command_argv(cfg["component_commands"].get(key))
        if not argv or not is_standard_module_command(argv, module):
            continue
        installed = installed_package_version(argv[0], package)
        target = str((selection.components.get(package) or selection.components.get(key) or {}).get("version") or "")
        if installed and target:
            try:
                if parse_version_key(target) < parse_version_key(installed):
                    raise _fail(
                        "component_downgrade_blocked",
                        f"Candidate {package} {target} would downgrade installed {installed}",
                        retryable=False,
                        stage="component_floor",
                        details={"component": package, "installed": installed, "candidate": target},
                    )
            except ValueError:
                continue


__all__ = [
    "BUNDLE_NAME", "CHECKSUM_NAME", "CHUNK_BYTES", "asset_source",
    "check_component_version_floors", "download_verified", "extract_wheel_bundle_safely",
    "fetch_checksums", "installed_package_version", "parse_sha256sums", "read_asset_text", "sha256_file",
]
