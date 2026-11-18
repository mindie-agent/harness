"""Zero-Git prebuilt wheelhouse discovery, SHA-256 verification, and backoff updates.
[Role]
Implements `parse_sha256sums`, `extract_wheel_bundle_safely`, `discover_channel`,
`stage_wheelhouse`, and `update_runtime`: deterministic prebuilt-wheel provisioning
from GitHub Releases (or a local `file://` / directory mirror) without any
version-control subprocess or VCS-URL requirement.
[Invariants]
- Every downloaded `release-channel.json`, `mindie-wheels-bundle.tar.gz`, and `.whl`
  is streamed into a sibling temporary file, hashed in `64 KiB` chunks, verified
  against `SHA256SUMS` when present, and only then promoted with `os.replace`.
- Tar extraction rejects absolute paths, `..` traversal, symlinks, hardlinks, FIFOs,
  and device nodes; only `.whl`, `requirements.lock`, and `SHA256SUMS` are accepted.
- `reportable=False` for every network, checksum, `uv`, disk, and lock failure;
  transient failures persist a bounded `1h -> 2h -> 4h -> 6h` backoff.
- `offline=True` (or `--offline` in `_MINDIE_UV_FLAGS`) with an `http(s)` channel and
  no fresh `channel-cache.json` fails fast as `offline_channel_unavailable`.
- `on_before_commit` re-verifies component version floors under `activate_generation`'s
  `update_lock` and passes an `expected_binding` CAS snapshot, so a slower older build
  can never downgrade a newer active runtime.

[Timeouts & Locks]
- Network reads are bounded (`DEFAULT_NETWORK_TIMEOUT_SECONDS = 30.0`), child builds
  run under `Deadline`, and generation serialization remains owned by
  `prepare_candidate_runtime` / `activate_generation`.
- Respects `<state_dir>/update-backoff.json` unless `force=True`, and the `6h`
  `<state_dir>/channel-cache.json` cache unless `force=True`.
[Side-Effect Policy]
- Writes `channel-cache.json`, `update-backoff.json`, a temporary wheelhouse under
  `<state_dir>`, and (through the runtime builder/activator) a validated generation.
"""
from __future__ import annotations
from collections.abc import Mapping
import json
import os
from pathlib import Path
import shutil
import tarfile
import tempfile
import time
from typing import Any
from urllib.error import HTTPError, URLError
import uuid

from ..atomic import atomic_write_json, read_json_safe
from ..component_commands import rebind_component_commands
from ..paths import HarnessError, ProfileRef, resolve_host_python, venv_python_path
from ..process.posix import which_posix_binary
from ..process.supervisor import Deadline, ProcessSpec, run_owned
from .activation import activate_generation
from .wheelhouse_assets import (
    BUNDLE_NAME, CHECKSUM_NAME, asset_source, check_component_version_floors,
    download_verified, extract_wheel_bundle_safely, fetch_checksums, parse_sha256sums, read_asset_text,
)
from .builder import PreparedGeneration, prepare_candidate_runtime
from .registry import RuntimeSelection

DEFAULT_CHANNEL_BASE_URL = "https://github.com/mindie-agent/mindie-agent/releases/latest/download"
DEFAULT_GITHUB_BASE_URL = "https://github.com"
CHANNEL_CACHE_TTL_SECONDS = 21600.0
BACKOFF_BASE_SECONDS = 3600.0
BACKOFF_MAX_SECONDS = 21600.0
DEFAULT_NETWORK_TIMEOUT_SECONDS = 30.0
CHANNEL_MANIFEST_NAME = "release-channel.json"
CACHE_SCHEMA = "mindie-channel-cache/1"
BACKOFF_SCHEMA = "mindie-update-backoff/1"
_SMOKE_MODULES = {
    "mindie-harness": "mindie_harness", "mindie-knowledge": "mindie_knowledge",
    "remote-dev": "remote_dev", "mindie-diagnostics": "mindie_diagnostics",
    "mindie-debugger": "mindie_debugger", "mindie-profiler": "mindie_profiler",
    "mindie-sim": "mindie_sim", "npu-top": "npu_top", "mindie-coordinator": "mindie_coordinator",
}
_ERR_STAGE = "wheelhouse"
# Backward-compatible private aliases for helpers now shared with `wheelhouse_assets`.
_component_floor_check = check_component_version_floors
_rebind_component_commands = rebind_component_commands

def _fail(reason: str, message: str, *, retryable: bool = True, stage: str = _ERR_STAGE, details: Mapping[str, Any] | None = None) -> HarnessError:
    return HarnessError(message, stage=stage, reason=reason, submission_state="not_sent", retryable=retryable, reportable=False, details=details)

def channel_cache_path(profile: ProfileRef) -> Path:
    return profile.state_dir / "channel-cache.json"


def update_backoff_path(profile: ProfileRef) -> Path:
    return profile.state_dir / "update-backoff.json"

def resolve_channel_base_url(channel_base_url: str | None = None, env: Mapping[str, str] | None = None) -> str:
    environ = os.environ if env is None else env
    return str(channel_base_url or environ.get("MINDIE_CHANNEL_BASE_URL") or DEFAULT_CHANNEL_BASE_URL).strip().rstrip("/")

def resolve_github_base_url(github_base_url: str | None = None, env: Mapping[str, str] | None = None) -> str:
    environ = os.environ if env is None else env
    return str(github_base_url or environ.get("MINDIE_GITHUB_BASE_URL") or DEFAULT_GITHUB_BASE_URL).strip().rstrip("/")


def _normalize_components(raw: Any) -> dict[str, dict[str, str]]:
    if not isinstance(raw, Mapping):
        return {}
    out: dict[str, dict[str, str]] = {}
    for name, meta in raw.items():
        if isinstance(meta, str):
            meta = {"version": meta}
        if isinstance(meta, Mapping):
            entry = {"version": str(meta.get("version") or ""), "revision": str(meta.get("revision") or "")}
            if meta.get("repository"):
                entry["repository"] = str(meta["repository"])
            out[str(name)] = entry
    return out

def _read_backoff(profile: ProfileRef) -> dict[str, Any] | None:
    raw = read_json_safe(update_backoff_path(profile))
    return raw if isinstance(raw, dict) and raw.get("schema") == BACKOFF_SCHEMA else None

def _record_backoff(profile: ProfileRef, reason: str, *, now: float | None = None) -> dict[str, Any]:
    current = _read_backoff(profile) or {}
    failures = max(0, int(current.get("failures") or 0)) + 1
    delay = min(BACKOFF_MAX_SECONDS, BACKOFF_BASE_SECONDS * (2 ** (failures - 1)))
    stamp = time.time() if now is None else float(now)
    next_retry_at = stamp + delay
    atomic_write_json(
        update_backoff_path(profile),
        {"schema": BACKOFF_SCHEMA, "failures": failures, "reason": str(reason), "delay_seconds": delay, "next_retry_at": next_retry_at, "updated_at": stamp},
        mode=0o600,
    )
    return {"status": "backoff", "reason": str(reason), "reportable": False, "next_retry_at": next_retry_at, "failures": failures}

def _clear_backoff(profile: ProfileRef) -> None:
    try:
        update_backoff_path(profile).unlink(missing_ok=True)
    except TimeoutError:
        raise
    except OSError:
        pass

def is_channel_cache_stale(profile: ProfileRef, *, now: float | None = None) -> bool:
    """Return True when `channel-cache.json` is absent or older than `6h` (read-only)."""
    raw = read_json_safe(channel_cache_path(profile))
    if not isinstance(raw, dict) or raw.get("schema") != CACHE_SCHEMA or type(raw.get("fetched_at")) not in (int, float):
        return True
    return ((time.time() if now is None else float(now)) - float(raw["fetched_at"])) >= CHANNEL_CACHE_TTL_SECONDS

def discover_channel(
    profile: ProfileRef,
    *,
    channel_base_url: str | None = None,
    github_base_url: str | None = None,
    force: bool = False,
    offline: bool = False,
    env: Mapping[str, str] | None = None,
    now: float | None = None,
    timeout: float = DEFAULT_NETWORK_TIMEOUT_SECONDS,
    deadline: Deadline | None = None,
) -> dict[str, Any]:
    """Discover `release-channel.json` with backoff, `6h` cache, and an offline guard."""
    current = time.time() if now is None else float(now)
    backoff = _read_backoff(profile)
    if not force and backoff is not None and float(backoff.get("next_retry_at") or 0) > current:
        return {"status": "backoff", "reason": str(backoff.get("reason") or "update_backoff"), "reportable": False, "next_retry_at": float(backoff["next_retry_at"]), "failures": int(backoff.get("failures") or 0)}
    base = resolve_channel_base_url(channel_base_url, env)
    explicit_base = bool(channel_base_url or (env or os.environ).get("MINDIE_CHANNEL_BASE_URL"))
    github_base = resolve_github_base_url(github_base_url, env)
    if not github_base_url and not (env or os.environ).get("MINDIE_GITHUB_BASE_URL") and not str(base).lower().startswith(("http://", "https://")):
        github_base = base
    offline = _effective_offline(offline, env)
    cached = read_json_safe(channel_cache_path(profile))
    cache_usable = False
    if isinstance(cached, dict) and cached.get("schema") == CACHE_SCHEMA and cached.get("channel_base_url") == base:
        fetched_at = cached.get("fetched_at")
        cache_usable = (
            type(fetched_at) in (int, float)
            and current - float(fetched_at) < CHANNEL_CACHE_TTL_SECONDS
            and isinstance(cached.get("channel"), dict)
        )
        if cache_usable and (not force or offline):
            channel = dict(cached["channel"])
            channel.update({"channel_base_url": base, "channel_base_explicit": explicit_base, "github_base_url": github_base, "checksum_verified": bool(cached.get("checksum_verified")), "cache_hit": True})
            return channel
    if offline and str(base).lower().startswith(("http://", "https://")):
        raise _fail(
            "offline_channel_unavailable",
            f"Offline mode has no fresh channel cache for {base}; refusing any network call",
            stage="channel_discover",
            retryable=True,
        )

    checksums, checksum_available = fetch_checksums(base, timeout=timeout, deadline=deadline)
    if checksum_available and not checksums.get(CHANNEL_MANIFEST_NAME):
        raise _fail("checksum_missing", "SHA256SUMS is missing the release-channel.json entry")
    tmp_manifest = profile.state_dir / f".{CHANNEL_MANIFEST_NAME}.{os.getpid()}.{uuid.uuid4().hex[:8]}"
    try:
        verified = download_verified(asset_source(base, CHANNEL_MANIFEST_NAME), tmp_manifest, checksums.get(CHANNEL_MANIFEST_NAME), timeout=timeout, deadline=deadline)
        raw = json.loads(tmp_manifest.read_text(encoding="utf-8-sig"))
    finally:
        try:
            tmp_manifest.unlink(missing_ok=True)
        except TimeoutError:
            raise
        except OSError:
            pass
    if not isinstance(raw, dict):
        raise _fail("invalid_channel_manifest", "release-channel.json must contain a JSON object")
    components = _normalize_components(raw.get("components") or raw.get("repositories") or {})
    channel = {
        "status": "ok",
        "product_version": str(raw.get("product_version") or raw.get("version") or ""),
        "components": components,
        "repositories": _normalize_components(raw.get("repositories") or raw.get("components") or {}),
        "checksums": checksums,
        "checksum_available": checksum_available,
        "checksum_verified": bool(verified),
        "channel_base_url": base,
        "channel_base_explicit": explicit_base,
        "github_base_url": github_base,
        "cache_hit": False,
        "manifest": raw,
    }
    atomic_write_json(
        channel_cache_path(profile),
        {"schema": CACHE_SCHEMA, "fetched_at": current, "channel_base_url": base, "github_base_url": github_base, "checksum_verified": bool(verified), "channel": channel},
        mode=0o600,
    )
    return channel

def _effective_offline(offline: bool, env: Mapping[str, str] | None = None) -> bool:
    """Return True when `--offline` was requested explicitly, in env, or via uv flags."""
    if offline:
        return True
    environ = os.environ if env is None else env
    flags = str(environ.get("_MINDIE_UV_FLAGS") or "")
    return "--offline" in flags.split()

def _bundle_base(channel: Mapping[str, Any]) -> str:
    base = str(channel.get("channel_base_url") or "")
    version = str(channel.get("product_version") or "").strip()
    if version and not channel.get("channel_base_explicit") and "/releases/latest/download" in base:
        prefix = base.split("/releases/")[0]
        return f"{prefix}/releases/download/{version if version.startswith('v') else 'v' + version}"
    return base

def _stage_bundle(channel: Mapping[str, Any], dest: Path, *, timeout: float, allow_remote: bool = True, deadline: Deadline | None = None) -> bool:
    source = asset_source(_bundle_base(channel), BUNDLE_NAME)
    checksums = channel.get("checksums") if isinstance(channel.get("checksums"), Mapping) else {}
    expected = str(checksums.get(BUNDLE_NAME) or "") if isinstance(checksums, Mapping) else ""
    if checksums and not expected:
        return False
    if not allow_remote and not isinstance(source, Path):
        return False
    if isinstance(source, Path) and not source.is_file():
        return False
    tmp_tar = dest.parent / f".{BUNDLE_NAME}.{os.getpid()}.{uuid.uuid4().hex[:8]}"
    try:
        download_verified(source, tmp_tar, expected or None, timeout=timeout, deadline=deadline)
        extract_wheel_bundle_safely(tmp_tar, dest)
        return True
    except TimeoutError:
        raise
    except FileNotFoundError:
        return False
    except HTTPError as exc:
        if int(getattr(exc, "code", 0) or 0) == 404:
            return False
        raise
    finally:
        try:
            tmp_tar.unlink(missing_ok=True)
        except TimeoutError:
            raise
        except OSError:
            pass

def _release_base(github_base: str, repository: str, version: str) -> str:
    repo = str(repository).strip().strip("/")
    if not repo or ".." in repo.split("/"):
        raise _fail("invalid_component_repository", f"Invalid component repository {repository!r}", retryable=False)
    version = str(version).strip()
    tag = version if version.startswith("v") else f"v{version}"
    return f"{github_base}/{repo}/releases/download/{tag}"

def _stage_component_wheels(channel: Mapping[str, Any], target: Mapping[str, Mapping[str, str]], dest: Path, *, timeout: float, allow_remote: bool = True, deadline: Deadline | None = None) -> int:
    github_base = str(channel.get("github_base_url") or DEFAULT_GITHUB_BASE_URL)
    if not allow_remote and github_base.lower().startswith(("http://", "https://")):
        return 0
    staged = 0
    for _name, meta in sorted(target.items()):
        repository, version = str(meta.get("repository") or ""), str(meta.get("version") or "")
        if not repository or not version:
            continue
        release_base = _release_base(github_base, repository, version)
        try:
            sums = parse_sha256sums(read_asset_text(asset_source(release_base, CHECKSUM_NAME), timeout=timeout, deadline=deadline))
        except TimeoutError:
            raise
        except (FileNotFoundError, HTTPError, URLError):
            continue
        wheel = next((n for n in sorted(sums) if n.endswith("-py3-none-any.whl")), next((n for n in sorted(sums) if n.endswith(".whl")), None))
        if wheel is None:
            continue
        download_verified(asset_source(release_base, wheel), dest / Path(wheel).name, sums[wheel], timeout=timeout, deadline=deadline)
        staged += 1
    return staged

def stage_wheelhouse(
    profile: ProfileRef,
    *,
    channel: Mapping[str, Any] | None = None,
    selection: RuntimeSelection | None = None,
    channel_base_url: str | None = None,
    github_base_url: str | None = None,
    offline: bool = False,
    env: Mapping[str, str] | None = None,
    dest_dir: str | Path | None = None,
    timeout: float = DEFAULT_NETWORK_TIMEOUT_SECONDS,
    deadline: Deadline | None = None,
) -> Path:
    """Download a verified bundle (or per-component wheels) into a wheelhouse directory."""
    offline = _effective_offline(offline, env)
    payload: Mapping[str, Any] = channel or discover_channel(profile, channel_base_url=channel_base_url, github_base_url=github_base_url, offline=offline, env=env, timeout=timeout, deadline=deadline)
    if payload.get("status") != "ok":
        raise _fail(str(payload.get("reason") or "channel_unavailable"), f"Channel discovery is {payload.get('status')}", details={"next_retry_at": payload.get("next_retry_at")})
    if dest_dir is None:
        profile.state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        dest = Path(tempfile.mkdtemp(prefix="wheelhouse-", dir=str(profile.state_dir)))
    else:
        dest = Path(dest_dir)
        dest.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        used_bundle = _stage_bundle(payload, dest, timeout=timeout, allow_remote=not offline, deadline=deadline)
        channel_components = _normalize_components(payload.get("components"))
        target = selection.components if selection is not None else channel_components
        if selection is not None:
            target = {name: {**channel_components.get(name, {}), **meta} for name, meta in target.items()}
        if not used_bundle:
            _stage_component_wheels(payload, target, dest, timeout=timeout, allow_remote=not offline, deadline=deadline)
        wheels = list(dest.glob("*.whl"))
        if not wheels:
            raise _fail("wheelhouse_unavailable", "No prebuilt wheel bundle or per-component release wheel was available")
        return dest
    except BaseException:
        if dest_dir is None:
            shutil.rmtree(dest, ignore_errors=True)
        raise

def _resolve_uv(env: Mapping[str, str]) -> str:
    found = shutil.which("uv", path=env.get("PATH")) if os.name == "nt" else which_posix_binary("uv", path_env=env.get("PATH"))
    if not found:
        raise _fail("uv_not_found", "Executable `uv` not found on native PATH", stage="runtime_build")
    return str(found)

def _wheelhouse_builder(profile: ProfileRef, wheelhouse: Path, *, offline: bool):
    def _builder(gen_dir: Path, venv_dir: Path, build_env: dict[str, str], deadline: Deadline) -> None:
        uv_bin = _resolve_uv(build_env)
        run_owned(ProcessSpec(argv=(uv_bin, "venv", "--python", str(resolve_host_python(build_env)), str(venv_dir)), env=build_env, role="background_maintenance", memory_limit_bytes=None), deadline=deadline)
        cmd = [uv_bin, "--native-tls", "pip", "install", "--python", str(venv_python_path(venv_dir)), "--find-links", str(wheelhouse)]
        lock_file = wheelhouse / "requirements.lock"
        cmd.extend(["-r", str(lock_file)] if lock_file.is_file() else [str(p) for p in sorted(wheelhouse.glob("*.whl"))])
        if offline or "--offline" in str(build_env.get("_MINDIE_UV_FLAGS") or ""):
            cmd.extend(["--offline", "--no-index"])
        run_owned(ProcessSpec(argv=tuple(cmd), cwd=profile.plugin_root if profile.plugin_root.is_dir() else None, env=build_env, role="background_maintenance", memory_limit_bytes=None), deadline=deadline)
    return _builder

def _current_components(cfg: Mapping[str, Any] | None) -> dict[str, dict[str, str]]:
    if not isinstance(cfg, Mapping):
        return {}
    validation = cfg.get("product_validation")
    return _normalize_components((validation.get("components") if isinstance(validation, Mapping) else None) or cfg.get("components"))


def _same_components(left: Mapping[str, Mapping[str, str]], right: Mapping[str, Mapping[str, str]]) -> bool:
    clean = lambda raw: {n: {"version": str(m.get("version") or ""), "revision": str(m.get("revision") or "")} for n, m in raw.items()}
    return clean(left) == clean(right)

def update_runtime(
    profile: ProfileRef,
    *,
    force: bool = False,
    offline: bool = False,
    channel_base_url: str | None = None,
    github_base_url: str | None = None,
    background: bool = False,
    selection: RuntimeSelection | None = None,
    env: Mapping[str, str] | None = None,
    timeout: float = DEFAULT_NETWORK_TIMEOUT_SECONDS,
    deadline: Deadline | None = None,
) -> dict[str, Any]:
    """Discover, stage, build, and atomically activate a prebuilt runtime generation."""
    offline = _effective_offline(offline, env)
    current = time.time()
    backoff = _read_backoff(profile)
    if not force and backoff is not None and float(backoff.get("next_retry_at") or 0) > current:
        return {"status": "backoff", "reason": str(backoff.get("reason") or "update_backoff"), "reportable": False, "next_retry_at": float(backoff["next_retry_at"]), "failures": int(backoff.get("failures") or 0)}
    wheelhouse: Path | None = None
    try:
        discovered = discover_channel(profile, channel_base_url=channel_base_url, github_base_url=github_base_url, force=force, offline=offline, env=env, timeout=timeout, deadline=deadline)
        if discovered.get("status") != "ok":
            return discovered
        channel = discovered
        target = _normalize_components(channel.get("components"))
        chosen = selection or RuntimeSelection.from_pins(target, plugin_version=str(channel.get("product_version") or "") or None, source_sha256=str((channel.get("checksums") or {}).get(CHANNEL_MANIFEST_NAME) or "") or None)
        cfg = read_json_safe(profile.config_path)
        cfg_python = cfg.get("python") if isinstance(cfg, dict) else None
        if _same_components(_current_components(cfg if isinstance(cfg, dict) else None), chosen.components) and isinstance(cfg_python, str) and Path(cfg_python).is_file():
            _clear_backoff(profile)
            return {"status": "up_to_date", "reportable": False, "components": dict(chosen.components), "python": cfg_python, "checked_at": current}
        wheelhouse = stage_wheelhouse(profile, channel=channel, selection=chosen, offline=offline, env=env, timeout=timeout, deadline=deadline)
        check_component_version_floors(profile, chosen)
        smoke = tuple(sorted({_SMOKE_MODULES[name] for name in chosen.components if name in _SMOKE_MODULES}))
        prepared = prepare_candidate_runtime(profile, selection=chosen, builder_fn=_wheelhouse_builder(profile, wheelhouse, offline=offline), smoke_imports=smoke or ("mindie_harness",), lock_timeout=0.0)
        if prepared.status == "deferred":
            return {"status": "deferred", "reason": prepared.reason or "candidate_deferred", "reportable": False, "generation": str(prepared.generation_dir), "python": str(prepared.python_path)}

        expected_binding = {
            "python": cfg.get("python") if isinstance(cfg, Mapping) else None,
            "component_release": cfg.get("component_release") if isinstance(cfg, Mapping) else None,
        }

        def _before_commit(_profile: ProfileRef, prep: PreparedGeneration, new_cfg: dict[str, Any]) -> None:
            # Re-verify downgrade floors under `activate_generation`'s update_lock so
            # a slower older build can never replace a newer active runtime.
            check_component_version_floors(_profile, chosen)
            validation = dict(new_cfg.get("product_validation") or {})
            prior = cfg.get("product_validation") if isinstance(cfg, dict) else None
            if isinstance(prior, Mapping) and prior.get("native_version"):
                validation.setdefault("native_version", prior["native_version"])
            validation["components"] = dict(chosen.components)
            new_cfg["product_validation"] = validation
            new_cfg["channel_base_url"] = channel.get("channel_base_url")
            rebind_component_commands(new_cfg, str(prep.python_path))

        activated = activate_generation(profile, prepared, expected_binding=expected_binding, on_before_commit=_before_commit, lock_timeout=5.0)
        if activated.status == "deferred":
            return {"status": "deferred", "reason": activated.reason or "lock_timeout", "reportable": False, "generation": str(prepared.generation_dir), "python": str(prepared.python_path)}
        _clear_backoff(profile)
        if activated.status == "noop":
            return {"status": "up_to_date", "reportable": False, "components": dict(chosen.components), "python": str(prepared.python_path), "checked_at": current}
        return {"status": "active", "reportable": False, "generation": str(prepared.generation_dir), "python": str(prepared.python_path), "components": dict(chosen.components), "channel_base_url": channel.get("channel_base_url"), "checked_at": current}
    except TimeoutError:
        raise
    except OSError as exc:
        if isinstance(exc, (HTTPError, URLError)):
            if background:
                return _record_backoff(profile, "network_unavailable", now=current)
            raise _fail("network_unavailable", f"Runtime update network failure ({type(exc).__name__})", stage="wheelhouse_network") from exc
        if background:
            return _record_backoff(profile, "runtime_update_os_error", now=current)
        raise _fail("runtime_update_os_error", f"Runtime update filesystem/process failure ({type(exc).__name__})") from exc
    except HarnessError as exc:
        exc.reportable = False
        if background and exc.retryable:
            return _record_backoff(profile, exc.reason, now=current)
        raise
    except (tarfile.TarError, ValueError, json.JSONDecodeError) as exc:
        if background:
            return _record_backoff(profile, "invalid_release_asset", now=current)
        raise _fail("invalid_release_asset", f"Invalid prebuilt release asset ({type(exc).__name__})") from exc
    finally:
        if wheelhouse is not None:
            shutil.rmtree(wheelhouse, ignore_errors=True)

__all__ = [
    "BACKOFF_BASE_SECONDS", "BACKOFF_MAX_SECONDS", "BUNDLE_NAME", "CHANNEL_CACHE_TTL_SECONDS",
    "DEFAULT_CHANNEL_BASE_URL", "DEFAULT_GITHUB_BASE_URL", "channel_cache_path", "discover_channel",
    "extract_wheel_bundle_safely", "is_channel_cache_stale", "parse_sha256sums",
    "resolve_channel_base_url", "resolve_github_base_url", "stage_wheelhouse",
    "update_backoff_path", "update_runtime",
]
