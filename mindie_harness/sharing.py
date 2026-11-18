"""Sharing/consent tier configuration and read-only status for all 7 host plugins.

[Role]
Implements `configure_sharing(profile, choice=...)` and `sharing_status(profile)`:
persists `mindie-consent.json` (`mindie-consent/1`), `mindie-community.json`
(`mindie-community-config/1`), and the diagnostics policy
(`mindie.diagnostics.reporting.v1`) with pure-stdlib atomic writers, while
optionally integrating `mindie_knowledge.consent_store` / `loop.settings` when the
package is importable.

[Invariants]
- `local-only` authorizes local `Stop`/`SessionEnd` transcript capture with
  `enabled=True`, `local_only=True`, `repository=None`, and diagnostics disabled.
- `read-only` / `disabled` set `mindie-community.json` `enabled=False` and
  diagnostics `decision="disabled"`; `contribute` is the only reporting tier.
- `choice_revision` is a stable 32-hex value across idempotent repeats and rotates
  when the effective choice changes.
- The stdlib `mindie-community-config/1` writer always emits `generation`
  (`token_hex(16)`, preserved while the policy is unchanged), `enabled_at`,
  `branch="main"`, and `idle_seconds=300` so `CommunitySettings.normalize()` accepts it.
- `sharing_status` is strictly read-only and never creates a file or directory.

[Timeouts & Locks]
- Small atomic JSON writes only (`< 5ms`); optional `gh` probing is delegated to
  the bounded `installer.probe_gh_recommendation` (`2.5s`).

[Side-Effect Policy]
- `configure_sharing` writes only the three profile-owned policy documents;
  `sharing_status` performs zero writes.
"""
from __future__ import annotations

import math
import os
from pathlib import Path
import secrets
import time
from typing import Any, Literal, Mapping, Sequence
import uuid

from .atomic import atomic_write_json, read_json_safe
from .paths import HarnessError, ProfileRef, config_home

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


def diagnostics_policy_path(env: Mapping[str, str] | None = None) -> Path:
    environ = os.environ if env is None else env
    explicit = environ.get("MINDIE_DIAGNOSTICS_CONFIG")
    return Path(explicit).expanduser() if explicit else config_home(environ) / "diagnostics.json"


def _integrate_knowledge(profile: ProfileRef, choice: str, roots: list[str], repository: str | None, fork: str | None, account: str | None) -> None:
    """Best-effort integration with an importable `mindie_knowledge` (never fatal)."""
    try:
        from mindie_knowledge import consent_store  # type: ignore[import-not-found]
    except TimeoutError:
        raise
    except Exception:
        return
    try:
        consent_store.record_choice(profile.consent_path, choice)
    except TimeoutError:
        raise
    except Exception:
        pass
    try:
        from mindie_knowledge.loop import settings as community_settings  # type: ignore[import-not-found]

        with community_settings.CommunityWriteContext(community_path(profile)) as ctx:
            try:
                ctx.write(
                    community_path(profile),
                    enabled=choice in {"contribute", "local-only"},
                    repository=repository if choice == "contribute" else None,
                    project_roots=roots,
                    local_only=choice == "local-only",
                    fork=fork,
                    account=account,
                )
            except TypeError:
                ctx.write(
                    community_path(profile),
                    enabled=choice in {"contribute", "local-only"},
                    repository=repository if choice == "contribute" else None,
                    project_roots=roots,
                )
    except TimeoutError:
        raise
    except Exception:
        pass
    try:
        try:
            consent_store.activate_reporting(profile.consent_path, config=diagnostics_policy_path(), roots=roots, repository=repository or "mindie-agent/mindie-agent", ensure=False)
        except TypeError:
            consent_store.activate_reporting(profile.consent_path, config=diagnostics_policy_path(), roots=roots, repository=repository or "mindie-agent/mindie-agent")
    except TimeoutError:
        raise
    except Exception:
        pass


def _write_reports(
    profile: ProfileRef,
    *,
    choice: str,
    roots: list[str],
    repository: str | None,
    fork: str | None,
    account: str | None,
    revision: str,
) -> tuple[Path, Path, Path, Path]:
    consent_path = profile.consent_path
    comm_path = community_path(profile)
    diag_path = diagnostics_policy_path()
    enabled = choice in {"contribute", "local-only"}
    effective_repo = (repository or "mindie-agent/mindie-agent") if choice == "contribute" else None
    prior_consent = read_json_safe(consent_path)
    consent = dict(prior_consent) if isinstance(prior_consent, Mapping) else {}
    consent.update({
        "schema": CONSENT_SCHEMA,
        "choice": choice,
        "enabled": enabled,
        "choice_revision": revision,
        "choice_at": time.time(),
        "project_roots": roots,
        "community_config": str(comm_path),
    })
    if effective_repo:
        consent["repository"] = effective_repo
    else:
        consent.pop("repository", None)
    if fork and choice == "contribute":
        consent["fork"] = fork
    else:
        consent.pop("fork", None)
    if account and choice == "contribute":
        consent["account"] = account
    else:
        consent.pop("account", None)
    atomic_write_json(consent_path, consent)
    prior_community = read_json_safe(comm_path)
    community = dict(prior_community) if isinstance(prior_community, Mapping) else {}
    local_only = choice == "local-only"
    prior_generation = community.get("generation")
    prior_enabled_at = community.get("enabled_at")
    policy_unchanged = (
        community.get("schema") == COMMUNITY_SCHEMA
        and community.get("enabled") is enabled
        and community.get("local_only") is local_only
        and community.get("repository") == effective_repo
        and community.get("project_roots") == roots
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
            if policy_unchanged and type(prior_enabled_at) in (int, float) and math.isfinite(prior_enabled_at) and prior_enabled_at > 0
            else time.time()
        )
    branch = "main"
    idle_seconds = 300
    community.pop("deferred", None)
    community.update({
        "schema": COMMUNITY_SCHEMA,
        "enabled": enabled,
        "local_only": local_only,
        "repository": effective_repo,
        "project_roots": roots,
        "consent_config": str(consent_path),
        "generation": generation,
        "enabled_at": enabled_at,
        "branch": branch,
        "idle_seconds": idle_seconds,
        "updated_at": time.time(),
    })
    if choice == "later":
        community["deferred"] = True
    atomic_write_json(comm_path, community)
    reporting = {
        "schema": REPORTING_SCHEMA,
        "purpose": "tool_fault_reporting",
        "decision": "enabled" if choice == "contribute" else "disabled",
        "consent_config": str(consent_path),
        "consent_revision": revision,
        "repository": effective_repo or "mindie-agent/mindie-agent",
        "revision": uuid.uuid4().hex,
        "roots": roots,
        "updated_at": time.time(),
    }
    atomic_write_json(diag_path, reporting)
    return consent_path, comm_path, diag_path, Path(str(profile.config_path))


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
        roots = _normalize_roots([item for item in prior_roots if isinstance(item, (str, Path))] if isinstance(prior_roots, list) else [])
    if repository is None and isinstance(prior_community, Mapping) and isinstance(prior_community.get("repository"), str):
        repository = str(prior_community["repository"])
    prior_choice = previous.get("choice") if isinstance(previous, dict) else None
    prior_revision = previous.get("choice_revision") if isinstance(previous, dict) else None
    revision = (
        str(prior_revision)
        if isinstance(prior_revision, str) and len(prior_revision) == 32 and prior_choice == clean
        else uuid.uuid4().hex
    )
    _integrate_knowledge(profile, clean, roots, repository if clean == "contribute" else None, fork if clean == "contribute" else None, account if clean == "contribute" else None)
    consent_path, comm_path, diag_path, cfg_path = _write_reports(
        profile, choice=clean, roots=roots, repository=repository, fork=fork, account=account, revision=revision
    )
    return {
        "status": "configured",
        "choice": clean,
        "tier": clean,
        "enabled": clean in {"contribute", "local-only"},
        "local_only": clean == "local-only",
        "project_roots": roots,
        "choice_revision": revision,
        "repository": (repository or "mindie-agent/mindie-agent") if clean == "contribute" else None,
        "fork": fork if clean == "contribute" else None,
        "account": account if clean == "contribute" else None,
        "consent_path": str(consent_path),
        "community_path": str(comm_path),
        "diagnostics_policy_path": str(diag_path),
        "config_path": str(cfg_path),
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


def sharing_status(profile: ProfileRef, *, cwd: str | Path | None = None) -> dict[str, Any]:
    """Read-only tier/project-root/gh-authentication snapshot (never creates files)."""
    consent = read_json_safe(profile.consent_path)
    community = read_json_safe(community_path(profile))
    consent_doc = consent if isinstance(consent, Mapping) else None
    community_doc = community if isinstance(community, Mapping) else None
    roots_raw = (community_doc or {}).get("project_roots")
    if not isinstance(roots_raw, list):
        roots_raw = (consent_doc or {}).get("project_roots")
    roots = _normalize_roots([item for item in roots_raw if isinstance(item, (str, Path))] if isinstance(roots_raw, list) else [])
    try:
        from .installer import probe_gh_recommendation  # type: ignore[import-not-found]

        gh = probe_gh_recommendation()
    except TimeoutError:
        raise
    except Exception:
        gh = {"gh_installed": False, "gh_authenticated": False, "account": None, "recommended_tier": "local-only"}
    in_scope = False
    if cwd is not None and roots:
        candidate = Path(cwd).expanduser().resolve(strict=False)
        for root in roots:
            try:
                candidate.relative_to(Path(root))
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
        "recommended_tier": gh.get("recommended_tier") or ("contribute" if gh.get("gh_authenticated") else "local-only"),
        "consent_path": str(profile.consent_path),
        "community_path": str(community_path(profile)),
        "reportable": False,
    }


__all__ = [
    "CHOICES", "COMMUNITY_SCHEMA", "CONSENT_SCHEMA", "REPORTING_SCHEMA", "SharingChoice",
    "community_path", "configure_sharing", "diagnostics_policy_path", "sharing_status",
]
