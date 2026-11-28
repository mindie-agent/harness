"""Host detection, bounded `gh` recommendation probing, and deterministic onboarding.

[Role]
Implements `detect_installed_hosts`, `probe_gh_recommendation`, and `run_install`:
discover installed native hosts without mutating their config, read the GitHub CLI
account through a disposable state directory, then provision the shared runtime from
a prebuilt channel wheelhouse (or a local plugin `pyproject.toml` / `wheelhouse`)
and return deterministic onboarding JSON.

[Invariants]
- `detect_installed_hosts` is strictly read-only and probes `$PATH`, standard
  per-host config paths, and the OMP session marker.
- `probe_gh_recommendation` is bounded (`2.5s` default), windowless through
  `run_owned`, sets `GH_PROMPT_DISABLED=1`, and uses a disposable `XDG_STATE_HOME`
  so an unauthenticated install creates zero real user state.
- `run_install(auto)` with zero detected hosts returns a clean status carrying
  `detected_hosts=[]` and `recommended_tier` instead of fabricating Codex.
- Runtime failures are `reportable=False`/`deferred`, never permanent poison state.

[Timeouts & Locks]
- `gh` runs under a `2.5s` `Deadline`; runtime builds delegate their own bounded
  deadlines and locks to `wheelhouse.update_runtime` / `prepare_runtime`.

[Side-Effect Policy]
- Detection is read-only; install may create the managed runtime generation via the
  shared builder/activator and writes no host plugin files.
"""
from __future__ import annotations

import os
from pathlib import Path
import shutil
import socket
import tempfile
from typing import Any, Mapping

from .paths import HOSTS, HarnessError, ProfileRef, config_home
from .process.supervisor import Deadline, ProcessSpec, run_owned

HOST_ALIASES: dict[str, str] = {
    "codex": "codex", "cc": "cc", "claude": "cc", "kimi": "kimi", "dsh": "dsh",
    "agy": "agy", "antigravity": "agy", "wb": "wb", "workbuddy": "wb", "oc": "oc", "opencode": "oc",
    "omp": "omp", "oh-my-pi": "omp",
}
_HOST_SESSION_MARKERS: dict[str, tuple[str, ...]] = {
    "omp": ("PI_SESSION_ID",),
}
_ONBOARDING_QUESTIONS = ["workspace_roots", "privacy_tier", "optional_ssh_npu_host"]
_GH_STATE_PREFIX = "mindie-gh-state-"


def _home(env: Mapping[str, str]) -> Path:
    raw = env.get("USERPROFILE") or env.get("HOME")
    return Path(raw).expanduser() if raw else Path.home()


def _which(name: str, env: Mapping[str, str]) -> str | None:
    path = env.get("PATH", "")
    for folder in path.split(os.pathsep):
        clean = folder.strip().strip('"')
        if not clean:
            continue
        for candidate in (Path(clean) / name, Path(clean) / f"{name}.exe", Path(clean) / f"{name}.cmd", Path(clean) / f"{name}.bat"):
            try:
                if candidate.is_file() and os.access(candidate, os.X_OK):
                    return str(candidate)
            except TimeoutError:
                raise
            except OSError:
                continue
    return shutil.which(name, path=path)


def detect_installed_hosts(env: Mapping[str, str] | None = None) -> list[str]:
    """Return canonical installed host IDs in `HOSTS` order (read-only probes)."""
    environ = os.environ if env is None else env
    home = _home(environ)
    cfg_root = config_home(environ)
    found: set[str] = set()
    probes = {
        "codex": ("codex", (home / ".codex", cfg_root / "codex.json")),
        "cc": ("claude", (home / ".claude", home / ".config" / "claude", cfg_root / "cc.json")),
        "kimi": ("kimi", (home / ".kimi", home / ".config" / "kimi", cfg_root / "kimi.json")),
        "dsh": ("dsh", (home / ".dsh", home / ".config" / "dsh", cfg_root / "dsh.json")),
        "agy": ("antigravity", (home / ".gemini" / "antigravity", cfg_root / "agy.json")),
        "wb": ("workbuddy", (home / ".workbuddy", cfg_root / "wb.json")),
        "oc": ("opencode", (home / ".config" / "opencode", home / ".opencode", cfg_root / "oc.json")),
        "omp": ("omp", (home / ".omp", cfg_root / "omp.json")),
    }
    for host, (binary, directories) in probes.items():
        if _which(binary, environ):
            found.add(host)
            continue
        if any(environ.get(marker, "").strip() for marker in _HOST_SESSION_MARKERS.get(host, ())):
            found.add(host)
            continue
        if host == "agy" and _which("agy", environ):
            found.add(host)
            continue
        if host == "wb" and _which("wb", environ):
            found.add(host)
            continue
        for directory in directories:
            try:
                if directory.exists():
                    found.add(host)
                    break
            except TimeoutError:
                raise
            except OSError:
                continue
    return [host for host in HOSTS if host in found]


def probe_gh_recommendation(env: Mapping[str, str] | None = None, timeout: float = 2.5) -> dict[str, Any]:
    """Return bounded `gh` installation/authentication facts and a recommended tier."""
    environ = os.environ if env is None else env
    gh = _which("gh", environ)
    if not gh:
        return {"gh_installed": False, "gh_authenticated": False, "account": None, "recommended_tier": "local-only"}
    state_dir = tempfile.mkdtemp(prefix=_GH_STATE_PREFIX)
    run_env = dict(environ)
    run_env.update({"XDG_STATE_HOME": state_dir, "GH_PROMPT_DISABLED": "1", "GH_NO_UPDATE_NOTIFIER": "1"})
    account: str | None = None
    authenticated = False
    try:
        outcome = run_owned(
            ProcessSpec(
                argv=(gh, "api", "user", "--jq", ".login"),
                env=run_env,
                role="foreground",
                max_output_bytes=65536,
                allowed_returncodes=None,
            ),
            deadline=Deadline.from_timeout(max(0.25, float(timeout))),
        )
        text = (outcome.stdout or "").strip()
        if outcome.returncode == 0 and text and "\n" not in text:
            account = text
            authenticated = True
    except (TimeoutError, OSError):
        pass
    finally:
        shutil.rmtree(state_dir, ignore_errors=True)
    return {
        "gh_installed": True,
        "gh_authenticated": authenticated,
        "account": account,
        "recommended_tier": "contribute" if authenticated else "local-only",
    }


def _network_available(timeout: float = 0.35) -> bool:
    try:
        with socket.create_connection(("github.com", 443), timeout=timeout):
            return True
    except (TimeoutError, OSError):
        return False


def _normalize_host(host: str) -> str | None:
    clean = str(host or "").strip().lower()
    return HOST_ALIASES.get(clean)


def _configured(profile: ProfileRef, plugin_root: str | Path | None, channel_base_url: str | None, offline: bool, skip_runtime: bool, env: Mapping[str, str]) -> dict[str, Any]:
    if skip_runtime:
        return {"status": "skipped", "reportable": False}
    try:
        from .runtime.wheelhouse import update_runtime  # type: ignore[import-not-found]

        if channel_base_url or (not offline and _network_available()):
            return update_runtime(profile, channel_base_url=channel_base_url, offline=offline, env=env)
        root = Path(plugin_root) if plugin_root else profile.plugin_root
        if (root / "pyproject.toml").is_file() or (root / "runtime-requirements.txt").is_file() or (root / "wheelhouse").is_dir():
            from .api import activate_runtime, prepare_runtime  # type: ignore[import-not-found]

            prepared = prepare_runtime(profile)
            activated = activate_runtime(profile, prepared)
            if activated.status == "deferred":
                return {
                    "status": "deferred",
                    "reason": activated.reason or "candidate_deferred",
                    "reportable": False,
                    "python": str(prepared.python_path),
                    "generation": str(activated.generation_dir or prepared.generation_dir),
                }
            return {
                "status": "active" if activated.status == "active" else "up_to_date",
                "reportable": False,
                "python": str(prepared.python_path),
                "generation": str(prepared.generation_dir),
                "config_path": str(activated.config_path),
            }
    except TimeoutError:
        raise
    except HarnessError as exc:
        return {"status": "deferred", "reason": exc.reason, "reportable": False}
    except Exception as exc:
        return {"status": "deferred", "reason": type(exc).__name__, "reportable": False}
    return {"status": "deferred", "reason": "no_bootstrap_source", "reportable": False}


def run_install(
    *,
    host: str = "auto",
    plugin_root: str | Path | None = None,
    channel_base_url: str | None = None,
    offline: bool = False,
    env: Mapping[str, str] | None = None,
    skip_runtime: bool = False,
) -> dict[str, Any]:
    """Resolve target hosts, provision the shared runtime, and return onboarding JSON."""
    environ = os.environ if env is None else env
    detected = detect_installed_hosts(environ)
    requested = str(host or "auto").strip().lower()
    if requested == "auto":
        targets = detected
    else:
        normalized = _normalize_host(requested)
        if normalized is None:
            raise HarnessError(
                f"Unsupported install host {host!r}",
                stage="install",
                reason="invalid_host",
                retryable=False,
                reportable=False,
            )
        targets = [normalized]
    gh = probe_gh_recommendation(environ)
    result: dict[str, Any] = {
        "status": "no_hosts" if not targets else "installed",
        "detected_hosts": detected,
        "configured_hosts": [],
        "gh_channel": gh,
        "recommended_tier": gh["recommended_tier"],
        "onboarding_questions": list(_ONBOARDING_QUESTIONS),
        "reportable": False,
    }
    if not targets:
        return result
    runtimes: dict[str, Any] = {}
    configured: list[str] = []
    for target in targets:
        try:
            profile = ProfileRef.resolve(target, plugin_root=plugin_root, env=environ)
        except HarnessError as exc:
            runtimes[target] = {"status": "deferred", "reason": exc.reason, "reportable": False}
            continue
        runtime = _configured(profile, plugin_root, channel_base_url, offline, skip_runtime, environ)
        runtimes[target] = runtime
        if runtime.get("status") in {"active", "up_to_date", "validated", "reused", "skipped"}:
            configured.append(target)
    result["configured_hosts"] = configured
    result["runtimes"] = runtimes
    result["status"] = "installed" if configured else "deferred"
    return result


__all__ = ["HOST_ALIASES", "detect_installed_hosts", "probe_gh_recommendation", "run_install"]
