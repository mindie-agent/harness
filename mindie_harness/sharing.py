"""Sharing/consent tier configuration and read-only status for all 7 host plugins.

[Role]
Implements `configure_sharing(profile, choice=...)` and `sharing_status(profile)`:
delegates to locked `mindie_knowledge.consent_store` / `CommunityWriteContext` /
`activate_reporting` writers when `mindie_knowledge` is available (in-process or via
`cfg["python"]` child IPC), and provides a locked pure-stdlib fallback when running
standalone without optional sibling wheels.

[Invariants]
- Zero `TypeError` signature probing and zero unlocked post-write clobbers.
- `local-only` authorizes local `Stop`/`SessionEnd` transcript capture with
  `enabled=True`, `local_only=True`, `repository=None`, and diagnostics disabled.
- `fork` and `account` are persisted on `mindie-community.json` (`CommunityWriteContext`),
  and `diagnostics.json["revision"]` is preserved across idempotent repeats.
- Corrupt consent or community files fail closed with `HarnessError` and are never
  silently overwritten.
- `sharing_status` is strictly read-only (`< 5ms`) and spawns zero `gh` subprocesses
  by default (`probe_gh=False`).

[Timeouts & Locks]
- Acquires cross-process locks (`<= 5.0s`) for all policy mutations; cross-interpreter
  delegation runs under `run_owned` (`<= 25.0s`).

[Side-Effect Policy]
- `configure_sharing` writes only the three profile-owned policy documents;
  `sharing_status` performs zero writes.
"""
from __future__ import annotations

import importlib.util
import json
import math
import os
from pathlib import Path
import secrets
import shutil
import sys
import time
from typing import Any, Literal, Mapping, Sequence
import uuid

from .atomic import atomic_write_json, read_json_safe
from .locks import FileLock, LockTimeoutError
from .paths import HarnessError, ProfileRef, config_home, same_interpreter
from .process.posix import which_posix_binary
from .process.supervisor import Deadline, ProcessSpec, run_owned
from .runtime.knowledge_binding import has_knowledge_package

FRAME_PREFIX = "MINDIE_SHARING_JSON:"
SharingChoice = Literal["contribute", "local-only", "read-only", "later", "disabled"]
CHOICES: frozenset[str] = frozenset({"contribute", "local-only", "read-only", "later", "disabled"})
CONSENT_SCHEMA = "mindie-consent/1"
COMMUNITY_SCHEMA = "mindie-community-config/1"
REPORTING_SCHEMA = "mindie.diagnostics.reporting.v1"


def _normalize_roots(project_roots: Sequence[str | Path]) -> list[str]:
    out: list[str] = []
    for raw in project_roots:
        if not isinstance(raw, (str, Path)) or not str(raw).strip():
            continue
        path = str(Path(raw).expanduser().resolve(strict=False))
        if path not in out:
            out.append(path)
    return out


def community_path(profile: ProfileRef) -> Path:
    return profile.config_path.parent / "mindie-community.json"


def diagnostics_policy_path(env: Mapping[str, str] | None = None, profile: ProfileRef | None = None) -> Path:
    environ = os.environ if env is None else env
    explicit = environ.get("MINDIE_DIAGNOSTICS_CONFIG")
    if explicit:
        return Path(explicit).expanduser()
    if profile is not None:
        return profile.config_path.parent / "diagnostics.json"
    return config_home(environ) / "diagnostics.json"


def _read_uncorrupted_dict(path: Path, *, stage_reason: str) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        raw = path.read_bytes()
    except TimeoutError:
        raise
    except OSError as exc:
        raise HarnessError(
            f"{path.name} is unreadable ({type(exc).__name__})",
            stage="sharing",
            reason=f"{stage_reason}_unreadable",
            retryable=False,
            reportable=False,
        ) from exc
    try:
        parsed = json.loads(raw.decode("utf-8-sig"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise HarnessError(
            f"{path.name} is damaged; explicit repair is required before overwriting",
            stage="sharing",
            reason=f"{stage_reason}_corrupt",
            retryable=False,
            reportable=False,
        ) from exc
    if not isinstance(parsed, dict):
        raise HarnessError(
            f"{path.name} must be a JSON object",
            stage="sharing",
            reason=f"{stage_reason}_corrupt",
            retryable=False,
            reportable=False,
        )
    return parsed


def _write_diagnostics_policy_stdlib(
    diag_path: Path,
    *,
    consent_path: Path,
    revision: str,
    choice: str,
    effective_repo: str | None,
    roots: list[str],
) -> None:
    decision = "enabled" if choice == "contribute" else "disabled"
    repo = effective_repo or "mindie-agent/mindie-agent"
    prior = _read_uncorrupted_dict(diag_path, stage_reason="diagnostics_policy")
    same_policy = (
        prior.get("schema") == REPORTING_SCHEMA
        and prior.get("decision") == decision
        and prior.get("consent_revision") == revision
        and prior.get("repository") == repo
        and prior.get("roots") == roots
        and isinstance(prior.get("revision"), str)
        and len(prior["revision"]) == 32
    )
    policy_rev = str(prior["revision"]) if same_policy else uuid.uuid4().hex
    reporting = {
        "schema": REPORTING_SCHEMA,
        "purpose": "tool_fault_reporting",
        "decision": decision,
        "consent_config": str(consent_path),
        "consent_revision": revision,
        "repository": repo,
        "revision": policy_rev,
        "roots": roots,
        "updated_at": prior.get("updated_at") if same_policy and isinstance(prior.get("updated_at"), (int, float)) else time.time(),
    }
    if not same_policy or prior != reporting:
        atomic_write_json(diag_path, reporting)


def _configure_with_providers(
    profile: ProfileRef,
    *,
    clean: str,
    roots: list[str],
    effective_repo: str | None,
    fork: str | None,
    account: str | None,
) -> tuple[str, Path, Path, Path] | None:
    try:
        from mindie_knowledge import consent_store  # type: ignore[import-not-found]
        from mindie_knowledge.loop import settings as community_settings  # type: ignore[import-not-found]
    except ImportError:
        return None

    consent_path = profile.consent_path
    comm_path = community_path(profile)
    diag_path = diagnostics_policy_path()
    enabled = clean in {"contribute", "local-only"}

    try:
        consent_res = consent_store.record_choice(consent_path, clean)
    except consent_store.ConsentError as exc:
        raise HarnessError(
            str(exc),
            stage="sharing",
            reason=f"consent_{exc.state}",
            retryable=exc.state == "locked",
            reportable=False,
        ) from exc

    revision = str(consent_res.get("choice_revision") or "")
    try:
        with community_settings.CommunityWriteContext(comm_path) as ctx:
            ctx.write(
                comm_path,
                enabled=enabled,
                repository=effective_repo,
                project_roots=roots,
                local_only=(clean == "local-only"),
                consent_config=str(consent_path),
                fork=(fork if clean == "contribute" else None),
                account=(account if clean == "contribute" else None),
                deferred=(True if clean == "later" else None),
            )
    except consent_store.ConsentError as exc:
        raise HarnessError(
            str(exc),
            stage="sharing",
            reason=f"community_{exc.state}",
            retryable=exc.state == "locked",
            reportable=False,
        ) from exc
    except ValueError as exc:
        raise HarnessError(
            str(exc),
            stage="sharing",
            reason="community_corrupt",
            retryable=False,
            reportable=False,
        ) from exc

    has_diag = False
    try:
        has_diag = importlib.util.find_spec("mindie_diagnostics.integration") is not None
    except (ImportError, AttributeError, ValueError):
        has_diag = False

    if has_diag:
        diag_res = consent_store.activate_reporting(
            consent_path,
            config=diag_path,
            roots=roots,
            repository=effective_repo or "mindie-agent/mindie-agent",
            ensure=False,
        )
        if diag_res.get("status") == "configuration_unavailable":
            raise HarnessError(
                "Diagnostics reporting policy could not be updated.",
                stage="sharing",
                reason="diagnostics_policy_unavailable",
                retryable=False,
                reportable=False,
                details={"diagnostics": diag_res},
            )
    else:
        _write_diagnostics_policy_stdlib(
            diag_path,
            consent_path=consent_path,
            revision=revision,
            choice=clean,
            effective_repo=effective_repo,
            roots=roots,
        )

    return revision, consent_path, comm_path, diag_path


def _configure_stdlib(
    profile: ProfileRef,
    *,
    clean: str,
    roots: list[str],
    effective_repo: str | None,
    fork: str | None,
    account: str | None,
) -> tuple[str, Path, Path, Path]:
    consent_path = profile.consent_path
    comm_path = community_path(profile)
    diag_path = diagnostics_policy_path(profile=profile)
    enabled = clean in {"contribute", "local-only"}
    local_only = clean == "local-only"

    consent_lock = FileLock(consent_path.with_name(f"{consent_path.name}.lock"), exclusive=True, timeout=5.0)
    comm_lock = FileLock(comm_path.with_name(f"{comm_path.name}.lock"), exclusive=True, timeout=5.0)
    try:
        consent_lock.acquire()
    except LockTimeoutError as exc:
        raise HarnessError(
            "Consent update lock is held by another process",
            stage="sharing",
            reason="consent_locked",
            retryable=True,
            reportable=False,
        ) from exc
    try:
        prior_consent = _read_uncorrupted_dict(consent_path, stage_reason="consent")
        if prior_consent and prior_consent.get("schema") != CONSENT_SCHEMA:
            raise HarnessError(
                "Consent file declares an unsupported schema",
                stage="sharing",
                reason="consent_corrupt",
                retryable=False,
                reportable=False,
            )
        prior_choice = prior_consent.get("choice")
        prior_rev = prior_consent.get("choice_revision")
        revision = (
            str(prior_rev)
            if isinstance(prior_rev, str) and len(prior_rev) == 32 and prior_choice == clean
            else uuid.uuid4().hex
        )
        consent = dict(prior_consent)
        consent.pop("enabled", None)
        consent.update(
            {
                "schema": CONSENT_SCHEMA,
                "choice": clean,
                "choice_revision": revision,
                "choice_at": prior_consent.get("choice_at")
                if prior_choice == clean and isinstance(prior_consent.get("choice_at"), (int, float))
                else time.time(),
            }
        )
        if consent != prior_consent:
            atomic_write_json(consent_path, consent)
    finally:
        consent_lock.release()

    try:
        comm_lock.acquire()
    except LockTimeoutError as exc:
        raise HarnessError(
            "Community settings lock is held by another process",
            stage="sharing",
            reason="community_locked",
            retryable=True,
            reportable=False,
        ) from exc
    try:
        prior_comm = _read_uncorrupted_dict(comm_path, stage_reason="community")
        if prior_comm and prior_comm.get("schema") != COMMUNITY_SCHEMA:
            raise HarnessError(
                "Community settings file declares an unsupported schema",
                stage="sharing",
                reason="community_corrupt",
                retryable=False,
                reportable=False,
            )
        prior_generation = prior_comm.get("generation")
        prior_enabled_at = prior_comm.get("enabled_at")
        policy_unchanged = (
            prior_comm.get("schema") == COMMUNITY_SCHEMA
            and prior_comm.get("enabled") is enabled
            and prior_comm.get("local_only") is local_only
            and prior_comm.get("repository") == effective_repo
            and prior_comm.get("project_roots") == roots
        )
        generation = (
            prior_generation
            if policy_unchanged and isinstance(prior_generation, str) and prior_generation
            else secrets.token_hex(16)
        )
        enabled_at: float | None = None
        if enabled:
            enabled_at = (
                float(prior_enabled_at)
                if policy_unchanged
                and type(prior_enabled_at) in (int, float)
                and math.isfinite(prior_enabled_at)
                and prior_enabled_at > 0
                else time.time()
            )
        community = dict(prior_comm)
        community.pop("deferred", None)
        community.update(
            {
                "schema": COMMUNITY_SCHEMA,
                "enabled": enabled,
                "local_only": local_only,
                "repository": effective_repo,
                "project_roots": roots,
                "consent_config": str(consent_path),
                "generation": generation,
                "enabled_at": enabled_at,
                "branch": str(prior_comm.get("branch") or "main"),
                "idle_seconds": int(prior_comm.get("idle_seconds") or 300),
                "updated_at": time.time(),
            }
        )
        if fork and clean == "contribute":
            community["fork"] = fork
        else:
            community.pop("fork", None)
        if account and clean == "contribute":
            community["account"] = account
        else:
            community.pop("account", None)
        if clean == "later":
            community["deferred"] = True
        if community != prior_comm:
            atomic_write_json(comm_path, community)
    finally:
        comm_lock.release()

    _write_diagnostics_policy_stdlib(
        diag_path,
        consent_path=consent_path,
        revision=revision,
        choice=clean,
        effective_repo=effective_repo,
        roots=roots,
    )
    return revision, consent_path, comm_path, diag_path


def _delegate_to_profile_python(
    target_py: Path,
    profile: ProfileRef,
    *,
    clean: str,
    roots: list[str],
    repository: str | None,
    fork: str | None,
    account: str | None,
) -> dict[str, Any]:
    venv_root = target_py.parent.parent
    sites = [venv_root / "Lib" / "site-packages"]
    lib_dir = venv_root / "lib"
    if lib_dir.is_dir():
        sites.extend(lib_dir.glob("python*/site-packages"))
    has_harness = any((s / "mindie_harness" / "sharing.py").is_file() for s in sites if s.is_dir())
    if has_harness:
        argv: tuple[str, ...] = (str(target_py), "-I", "-X", "utf8", "-m", "mindie_harness.sharing")
    else:
        caller_root = str(Path(__file__).resolve().parents[1])
        argv = (
            str(target_py),
            "-I",
            "-X",
            "utf8",
            "-c",
            "import runpy,sys; sys.path.append(sys.argv.pop(1)); runpy.run_module('mindie_harness.sharing', run_name='__main__')",
            caller_root,
        )
    req = {
        "host": profile.host,
        "plugin_root": str(profile.plugin_root),
        "config_path": str(profile.config_path),
        "data_dir": str(profile.data_dir),
        "choice": clean,
        "project_roots": roots,
        "repository": repository,
        "fork": fork,
        "account": account,
    }
    outcome = run_owned(
        ProcessSpec(
            argv=argv,
            env=dict(os.environ, MINDIE_SHARING_CHILD="1"),
            stdin_bytes=(json.dumps(req, ensure_ascii=True) + "\n").encode("utf-8"),
            role="foreground",
            allowed_returncodes=None,
        ),
        deadline=Deadline.from_timeout(25.0, cleanup_grace=5.0),
    )
    for line in reversed((outcome.stdout or "").splitlines()):
        if line.startswith(FRAME_PREFIX):
            parsed = json.loads(line[len(FRAME_PREFIX) :])
            if isinstance(parsed, dict):
                if parsed.get("_harness_error"):
                    err = parsed["_harness_error"]
                    raise HarnessError(
                        str(err.get("message") or "sharing configuration failed"),
                        stage=str(err.get("stage") or "sharing"),
                        reason=str(err.get("reason") or "sharing_failed"),
                        retryable=bool(err.get("retryable", False)),
                        reportable=False,
                    )
                return parsed
    raise HarnessError(
        f"Sharing helper exited {outcome.returncode}: {(outcome.stderr or outcome.stdout or '')[:300]}",
        stage="sharing",
        reason="sharing_helper_failed",
        retryable=True,
        reportable=False,
    )


def configure_sharing(
    profile: ProfileRef,
    *,
    choice: SharingChoice,
    project_roots: Sequence[str | Path] = (),
    repository: str | None = None,
    fork: str | None = None,
    account: str | None = None,
) -> dict[str, Any]:
    """Persist one explicit sharing tier and its local/community/diagnostics policies."""
    clean = str(choice or "").strip().lower()
    if clean not in CHOICES:
        raise HarnessError(
            f"Unsupported sharing choice {choice!r}; expected one of {sorted(CHOICES)}",
            stage="sharing",
            reason="invalid_sharing_choice",
            retryable=False,
            reportable=False,
        )

    roots = _normalize_roots(project_roots)
    previous = read_json_safe(profile.consent_path)
    prior_community = read_json_safe(community_path(profile))
    if not roots:
        prior_roots = (prior_community or {}).get("project_roots") if isinstance(prior_community, Mapping) else None
        if not isinstance(prior_roots, list) and isinstance(previous, Mapping):
            prior_roots = previous.get("project_roots")
        roots = _normalize_roots(
            [item for item in prior_roots if isinstance(item, (str, Path))]
            if isinstance(prior_roots, list)
            else []
        )
    if repository is None and isinstance(prior_community, Mapping) and isinstance(prior_community.get("repository"), str):
        repository = str(prior_community["repository"])

    if os.environ.get("MINDIE_SHARING_CHILD") != "1":
        cfg = read_json_safe(profile.config_path)
        py_raw = cfg.get("python") if isinstance(cfg, Mapping) else None
        if (
            isinstance(py_raw, str)
            and py_raw.strip()
            and Path(py_raw).is_file()
            and not same_interpreter(py_raw, sys.executable)
            and has_knowledge_package(py_raw)
        ):
            return _delegate_to_profile_python(
                Path(py_raw),
                profile,
                clean=clean,
                roots=roots,
                repository=repository,
                fork=fork,
                account=account,
            )

    effective_repo = (repository or "mindie-agent/mindie-agent") if clean == "contribute" else None
    provider_res = _configure_with_providers(
        profile,
        clean=clean,
        roots=roots,
        effective_repo=effective_repo,
        fork=fork,
        account=account,
    )
    if provider_res is not None:
        revision, consent_path, comm_path, diag_path = provider_res
    else:
        revision, consent_path, comm_path, diag_path = _configure_stdlib(
            profile,
            clean=clean,
            roots=roots,
            effective_repo=effective_repo,
            fork=fork,
            account=account,
        )

    return {
        "status": "configured",
        "choice": clean,
        "tier": clean,
        "enabled": clean in {"contribute", "local-only"},
        "local_only": clean == "local-only",
        "project_roots": roots,
        "choice_revision": revision,
        "repository": effective_repo,
        "fork": fork if clean == "contribute" else None,
        "account": account if clean == "contribute" else None,
        "consent_path": str(consent_path),
        "community_path": str(comm_path),
        "diagnostics_policy_path": str(diag_path),
        "config_path": str(profile.config_path),
        "reportable": False,
    }


def _tier(consent: Mapping[str, Any] | None, community: Mapping[str, Any] | None) -> str:
    clean = str((consent or {}).get("choice") or "").strip().lower()
    if clean in {"local-only", "contribute"}:
        if community is None:
            return clean
        return clean if community.get("enabled") is True else "disabled"
    if clean in {"read-only", "disabled", "later"}:
        return clean
    if (community or {}).get("enabled") is True:
        return "local-only" if (community or {}).get("local_only") is True else "contribute"
    return "unset"


def sharing_status(
    profile: ProfileRef,
    *,
    cwd: str | Path | None = None,
    probe_gh: bool = False,
) -> dict[str, Any]:
    """Read-only tier/project-root snapshot (`< 5ms`; zero `gh` subprocess unless `probe_gh=True`)."""
    consent = read_json_safe(profile.consent_path)
    community = read_json_safe(community_path(profile))
    consent_doc = consent if isinstance(consent, Mapping) else None
    community_doc = community if isinstance(community, Mapping) else None
    roots_raw = (community_doc or {}).get("project_roots")
    if not isinstance(roots_raw, list):
        roots_raw = (consent_doc or {}).get("project_roots")
    roots = _normalize_roots(
        [item for item in roots_raw if isinstance(item, (str, Path))]
        if isinstance(roots_raw, list)
        else []
    )
    if probe_gh:
        try:
            from .installer import probe_gh_recommendation

            gh = probe_gh_recommendation()
        except TimeoutError:
            raise
        except Exception:
            gh = {
                "gh_installed": False,
                "gh_authenticated": False,
                "account": None,
                "recommended_tier": "local-only",
            }
    else:
        gh_bin = shutil.which("gh") if os.name == "nt" else which_posix_binary("gh")
        saved_account = (community_doc or {}).get("account") or (consent_doc or {}).get("account")
        gh = {
            "gh_installed": bool(gh_bin),
            "gh_authenticated": bool(saved_account),
            "account": str(saved_account) if isinstance(saved_account, str) and saved_account else None,
            "recommended_tier": "contribute" if saved_account else "local-only",
        }

    in_scope = False
    if cwd is not None and roots:
        candidate = os.path.normcase(str(Path(cwd).expanduser().resolve(strict=False)))
        for root in roots:
            r_norm = os.path.normcase(str(Path(root).expanduser().resolve(strict=False)))
            try:
                if os.path.splitdrive(candidate)[0] == os.path.splitdrive(r_norm)[0] and os.path.commonpath(
                    (candidate, r_norm)
                ) == r_norm:
                    in_scope = True
                    break
            except ValueError:
                continue
    return {
        "status": "ok",
        "tier": _tier(consent_doc, community_doc),
        "choice": (consent_doc or {}).get("choice"),
        "enabled": (community_doc or {}).get("enabled") is True,
        "local_only": (community_doc or {}).get("local_only") is True,
        "project_roots": roots,
        "cwd_in_scope": in_scope,
        "gh_installed": bool(gh.get("gh_installed")),
        "gh_authenticated": bool(gh.get("gh_authenticated")),
        "gh_account": gh.get("account"),
        "recommended_tier": gh.get("recommended_tier")
        or ("contribute" if gh.get("gh_authenticated") else "local-only"),
        "consent_path": str(profile.consent_path),
        "community_path": str(community_path(profile)),
        "reportable": False,
    }


def _cli_main() -> int:
    raw = sys.stdin.buffer.read(2 * 1024 * 1024)
    req = json.loads(raw.decode("utf-8-sig"))
    profile = ProfileRef.resolve(
        str(req["host"]),
        plugin_root=req.get("plugin_root"),
        config_path=req.get("config_path"),
        data_dir=req.get("data_dir"),
    )
    try:
        res = configure_sharing(
            profile,
            choice=req["choice"],
            project_roots=req.get("project_roots") or (),
            repository=req.get("repository"),
            fork=req.get("fork"),
            account=req.get("account"),
        )
    except HarnessError as exc:
        res = {"_harness_error": exc.to_dict()}
    sys.stdout.buffer.write((FRAME_PREFIX + json.dumps(res, ensure_ascii=True) + "\n").encode("utf-8"))
    sys.stdout.buffer.flush()
    return 0


__all__ = [
    "CHOICES",
    "COMMUNITY_SCHEMA",
    "CONSENT_SCHEMA",
    "REPORTING_SCHEMA",
    "SharingChoice",
    "community_path",
    "configure_sharing",
    "diagnostics_policy_path",
    "sharing_status",
]

if __name__ == "__main__":
    raise SystemExit(_cli_main())
