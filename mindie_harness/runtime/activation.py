"""Authoritative host binding commit, hook update handoff, and `Active + Rollback` GC.

[Role]
Commits validated candidate runtimes to `<host>.json` LAST (`activate_generation`),
writes `<5ms` `pending-update-check.json` markers for short-lived hooks
(`write_pending_update_check`), and reclaims obsolete runtime generations
(`reclaim_generations`, `maintain_generations`) down to `Active + Rollback (<= 2)`.

[Invariants]
- `<host>.json` is committed atomically LAST: if `on_before_commit` (e.g., OS
  scheduler migration or native host package staging) raises, `<host>.json` stays
  on the working active generation.
- `mindie-consent.json` is NEVER modified or deleted during activation or GC.
- `reclaim_generations` protects: (1) `Active` generation, (2) newest validated
  `Rollback` generation (`<= 2` total), (3) cross-plugin `<other_host>.json`
  references, (4) `sys.prefix`/`sys.executable`, (5) OS Scheduled Task / LaunchAgent
  referenced interpreters, and (6) live `.inuse` leased generations.

[Timeouts & Locks]
- Update lock contention (`LockTimeoutError`) returns `ActivationResult(status="deferred", reportable=False)`.
- `reclaim_generations` enforces a bounded `budget_seconds` (`default 2.0s`).

[Side-Effect Policy]
- Writes `<host>.json` and `pending-update-check.json` atomically; retires non-protected
  generation directories via two-stage `.trash.*` renames.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import os
from pathlib import Path
import sys
import time
from typing import Any, Literal, Mapping, Sequence

from ..atomic import (
    TRASH_PREFIXES,
    atomic_write_json,
    read_json_safe,
    stage_retire_directory,
    sweep_trash_directories,
)
from ..locks import FileLock, LockTimeoutError, acquire_retirement_guard
from ..paths import HOSTS, HarnessError, ProfileRef
from .builder import BUILDING_SENTINEL, CANDIDATE_RECEIPT_SCHEMA, PreparedGeneration
from .scheduler import discover_scheduled_executables

PENDING_UPDATE_SCHEMA = "mindie-pending-update/1"
WARN_FOOTPRINT_BYTES: int = int(1.2 * (1024 ** 3))  # 1.2 GiB per-plugin warning threshold
STALE_BUILDING_SECONDS = 900.0


@dataclass(frozen=True)
class ActivationResult:
    """Outcome of flipping `<host>.json` to a validated generation."""

    status: Literal["active", "deferred", "noop"]
    config_path: Path
    generation_dir: Path | None
    python_path: Path | None
    previous_python: str | None = None
    reason: str | None = None
    reportable: bool = False
    gc_summary: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "status": self.status,
            "config_path": str(self.config_path),
            "generation_dir": str(self.generation_dir) if self.generation_dir else None,
            "python": str(self.python_path) if self.python_path else None,
            "reportable": self.reportable,
        }
        if self.previous_python:
            out["previous_python"] = self.previous_python
        if self.reason:
            out["reason"] = self.reason
        if self.gc_summary is not None:
            out["gc"] = dict(self.gc_summary)
        return out


def write_pending_update_check(
    profile: ProfileRef,
    *,
    reason: str = "hook_handoff",
    extra: Mapping[str, Any] | None = None,
) -> Path:
    """Atomically enqueue `pending-update-check.json` (`<5ms`, zero `uv` spawn in hooks)."""
    payload: dict[str, Any] = {
        "schema": PENDING_UPDATE_SCHEMA,
        "host": profile.host,
        "reason": str(reason),
        "requested_at": time.time(),
    }
    if extra:
        payload["extra"] = dict(extra)
    return atomic_write_json(profile.pending_update_path, payload)


def read_pending_update_check(profile: ProfileRef) -> dict[str, Any] | None:
    raw = read_json_safe(profile.pending_update_path)
    if isinstance(raw, dict) and raw.get("schema") == PENDING_UPDATE_SCHEMA:
        return raw
    return None


def clear_pending_update_check(profile: ProfileRef) -> None:
    try:
        profile.pending_update_path.unlink(missing_ok=True)
    except TimeoutError:
        raise
    except OSError:
        pass


def _owning_generation_dir(target: str | Path | None, generations_root: Path) -> Path | None:
    if not target:
        return None
    try:
        cand = Path(os.path.abspath(str(target)))
        root = Path(os.path.abspath(str(generations_root)))
        common = os.path.commonpath((str(cand), str(root)))
        if os.path.normcase(common) != os.path.normcase(str(root)):
            return None
        rel = os.path.relpath(str(cand), str(root))
        first = rel.split(os.sep)[0]
        if not first or first in {".", ".."} or any(first.startswith(p) for p in TRASH_PREFIXES):
            return None
        return root / first
    except (OSError, ValueError):
        return None


def _directory_size_bounded(root: Path, deadline: float) -> int:
    total = 0
    stack = [root]
    while stack and time.monotonic() < deadline:
        curr = stack.pop()
        try:
            with os.scandir(curr) as it:
                for entry in it:
                    if time.monotonic() >= deadline:
                        break
                    try:
                        if entry.is_symlink():
                            continue
                        if entry.is_dir(follow_symlinks=False):
                            stack.append(Path(entry.path))
                        else:
                            total += entry.stat(follow_symlinks=False).st_size
                    except TimeoutError:
                        raise
                    except OSError:
                        continue
        except TimeoutError:
            raise
        except OSError:
            continue
    return total


def _collect_protected_generations(
    profile: ProfileRef,
    *,
    keep_paths: Sequence[str | Path] = (),
    scheduled_tasks: Sequence[str] = (),
) -> set[Path]:
    gen_root = profile.generations_dir
    protected: set[Path] = set()

    def _protect(raw: str | Path | None) -> None:
        owner = _owning_generation_dir(raw, gen_root)
        if owner is not None:
            protected.add(owner)

    # 1. Current interpreter & explicit keep paths
    _protect(sys.executable)
    _protect(sys.prefix)
    for item in keep_paths:
        _protect(item)

    # 2. Active host config + cross-plugin sibling configs (<MINDIE_CONFIG_HOME>/*.json)
    cfg_candidates = [profile.config_path]
    if profile.config_path.parent.is_dir():
        for h in HOSTS:
            sib = profile.config_path.parent / f"{h}.json"
            if sib != profile.config_path:
                cfg_candidates.append(sib)

    active_gen: Path | None = None
    for cfg_file in cfg_candidates:
        doc = read_json_safe(cfg_file)
        if not isinstance(doc, dict):
            continue
        for field_name in ("python", "component_release", "runtime_scripts"):
            val = doc.get(field_name)
            if isinstance(val, str) and val.strip():
                owner = _owning_generation_dir(val, gen_root)
                if owner is not None:
                    protected.add(owner)
                    if cfg_file == profile.config_path and active_gen is None:
                        active_gen = owner
        current_ptr = doc.get("current_path")
        if isinstance(current_ptr, str) and current_ptr.strip():
            cur_doc = read_json_safe(current_ptr)
            if isinstance(cur_doc, dict):
                _protect(cur_doc.get("generation"))
                _protect(cur_doc.get("python"))

    # 3. Single newest validated Rollback generation (Active + 1 Rollback <= 2)
    validated_candidates: list[tuple[float, Path]] = []
    if gen_root.is_dir():
        try:
            with os.scandir(gen_root) as it:
                for entry in it:
                    if not entry.is_dir(follow_symlinks=False):
                        continue
                    if entry.name.startswith(".") or any(entry.name.startswith(p) for p in TRASH_PREFIXES):
                        continue
                    cand_dir = Path(os.path.abspath(entry.path))
                    b_sentinel = cand_dir / BUILDING_SENTINEL
                    if b_sentinel.is_file():
                        try:
                            age = time.time() - b_sentinel.stat().st_mtime
                            if age < STALE_BUILDING_SECONDS:
                                protected.add(cand_dir)
                        except TimeoutError:
                            raise
                        except OSError:
                            protected.add(cand_dir)
                        continue
                    receipt = read_json_safe(cand_dir / "runtime.json")
                    if (
                        isinstance(receipt, dict)
                        and receipt.get("schema") == CANDIDATE_RECEIPT_SCHEMA
                        and isinstance(receipt.get("validation"), dict)
                        and receipt["validation"].get("status") == "validated"
                    ):
                        ts = float(receipt["validation"].get("validated_at") or entry.stat().st_mtime)
                        validated_candidates.append((ts, cand_dir))
        except TimeoutError:
            raise
        except OSError:
            pass

    validated_candidates.sort(key=lambda pair: pair[0], reverse=True)
    if active_gen is not None:
        rollbacks = [d for _, d in validated_candidates if d != active_gen]
        if rollbacks:
            protected.add(rollbacks[0])
    else:
        for _, d in validated_candidates[:2]:
            protected.add(d)

    # 4. OS Scheduled Task / LaunchAgent / systemd user unit executable closure
    for exe_path in discover_scheduled_executables(profile=profile, task_names=scheduled_tasks):
        _protect(exe_path)

    return protected


def _update_lock_for(profile: ProfileRef, *, timeout: float) -> FileLock:
    return FileLock(
        profile.config_path.with_name(f".{profile.config_path.name}.update.lock"),
        exclusive=True,
        timeout=timeout,
    )


def _is_prepare_lock_held(cand_dir: Path) -> bool:
    prep_lock_path = cand_dir.parent / f".prepare.{cand_dir.name}.lock"
    if not prep_lock_path.exists():
        return False
    probe = FileLock(prep_lock_path, exclusive=True, timeout=0.0)
    try:
        probe.acquire()
    except LockTimeoutError:
        return True
    except TimeoutError:
        raise
    except OSError:
        return True
    probe.release()
    return False


def _verify_validated_receipt(prepared: PreparedGeneration) -> dict[str, Any]:
    receipt = read_json_safe(prepared.receipt_path)
    if (
        not isinstance(receipt, dict)
        or receipt.get("schema") != CANDIDATE_RECEIPT_SCHEMA
        or (receipt.get("validation") or {}).get("status") != "validated"
        or not prepared.python_path.is_file()
    ):
        raise HarnessError(
            f"Refusing to activate unvalidated candidate generation {prepared.generation_dir}",
            stage="activation_verify",
            reason="candidate_not_validated",
            submission_state="not_sent",
            retryable=False,
        )
    return receipt


def reclaim_generations(
    profile: ProfileRef,
    *,
    keep_paths: Sequence[str | Path] = (),
    scheduled_tasks: Sequence[str] = (),
    budget_seconds: float = 2.0,
) -> dict[str, Any]:
    """Retain `Active + Rollback (<= 2)` plus live-leased/scheduled dirs; two-stage `.trash` GC the rest."""
    started = time.monotonic()
    deadline = started + max(0.1, float(budget_seconds))
    gen_root = Path(os.path.abspath(str(profile.generations_dir)))
    if not gen_root.is_dir():
        return {
            "status": "completed",
            "reclaimed_dirs": 0,
            "deferred_dirs": 0,
            "kept_dirs": 0,
            "reclaimed_trash": 0,
            "deferred_trash": 0,
            "footprint_bytes": 0,
            "footprint_warning": False,
        }

    # Synchronize Stage-1 snapshot + atomic `.trash` rename with `activate_generation`'s update_lock
    # so GC can NEVER retire a generation committed concurrently to `<host>.json`.
    update_lock = _update_lock_for(profile, timeout=0.0)
    try:
        update_lock.acquire()
    except LockTimeoutError:
        return {
            "status": "deferred_in_use",
            "reason": "activation_in_progress",
            "reclaimed_dirs": 0,
            "deferred_dirs": 1,
            "kept_dirs": 0,
            "reclaimed_trash": 0,
            "deferred_trash": 0,
            "footprint_bytes": 0,
            "footprint_warning": False,
            "elapsed_ms": int((time.monotonic() - started) * 1000),
        }

    reclaimed = 0
    deferred = 0
    kept = 0
    try:
        protected = _collect_protected_generations(
            profile,
            keep_paths=keep_paths,
            scheduled_tasks=scheduled_tasks,
        )

        try:
            entries = [
                Path(os.path.abspath(e.path))
                for e in os.scandir(gen_root)
                if e.is_dir(follow_symlinks=False)
                and not e.name.startswith(".")
                and not any(e.name.startswith(p) for p in TRASH_PREFIXES)
            ]
        except TimeoutError:
            raise
        except OSError:
            entries = []

        for cand in sorted(entries, key=lambda p: p.name):
            if cand in protected:
                kept += 1
                continue
            if time.monotonic() >= deadline or _is_prepare_lock_held(cand):
                deferred += 1
                continue
            with acquire_retirement_guard(cand) as can_retire:
                if not can_retire:
                    deferred += 1
                    continue
                outcome, _ = stage_retire_directory(cand)
                if outcome == "retired":
                    reclaimed += 1
                elif outcome == "deferred_in_use":
                    deferred += 1
    finally:
        update_lock.release()

    remaining_budget = max(0.05, deadline - time.monotonic())
    trash_res = sweep_trash_directories(gen_root, budget_seconds=remaining_budget)
    size_deadline = time.monotonic() + min(0.25, max(0.05, deadline - time.monotonic()))
    footprint = _directory_size_bounded(gen_root, size_deadline)

    return {
        "status": "deferred_in_use" if deferred else "completed",
        "reclaimed_dirs": reclaimed,
        "deferred_dirs": deferred,
        "kept_dirs": kept,
        "reclaimed_trash": trash_res["reclaimed_trash"],
        "deferred_trash": trash_res["deferred_trash"],
        "footprint_bytes": footprint,
        "footprint_warning": footprint > WARN_FOOTPRINT_BYTES,
        "elapsed_ms": int((time.monotonic() - started) * 1000),
    }


def activate_generation(
    profile: ProfileRef,
    prepared: PreparedGeneration,
    *,
    expected_binding: Mapping[str, Any] | None = None,
    on_before_commit: Callable[[ProfileRef, PreparedGeneration, dict[str, Any]], None] | None = None,
    lock_timeout: float = 5.0,
    run_gc: bool = True,
    gc_budget_seconds: float = 2.0,
) -> ActivationResult:
    """Validate `prepared`, run pre-commit hooks, and atomically flip `<host>.json` LAST."""
    if prepared.status == "deferred":
        return ActivationResult(
            status="deferred",
            config_path=profile.config_path,
            generation_dir=prepared.generation_dir,
            python_path=prepared.python_path,
            reason=prepared.reason or "candidate_deferred",
            reportable=False,
        )
    _verify_validated_receipt(prepared)

    update_lock = _update_lock_for(profile, timeout=lock_timeout)
    try:
        update_lock.acquire()
    except LockTimeoutError:
        return ActivationResult(
            status="deferred",
            config_path=profile.config_path,
            generation_dir=prepared.generation_dir,
            python_path=prepared.python_path,
            reason="lock_timeout",
            reportable=False,
        )

    try:
        # Re-verify inside update_lock so an earlier GC pass could not have retired `prepared`.
        receipt = _verify_validated_receipt(prepared)
        current_doc = read_json_safe(profile.config_path)
        current_cfg = dict(current_doc) if isinstance(current_doc, dict) else {}
        prev_python = current_cfg.get("python") if isinstance(current_cfg.get("python"), str) else None

        if expected_binding is not None:
            for key, expected_val in expected_binding.items():
                if current_cfg.get(key) != expected_val:
                    return ActivationResult(
                        status="deferred",
                        config_path=profile.config_path,
                        generation_dir=prepared.generation_dir,
                        python_path=prepared.python_path,
                        previous_python=prev_python,
                        reason="binding_changed",
                        reportable=False,
                    )

        if (
            prev_python == str(prepared.python_path)
            and current_cfg.get("component_release") == str(prepared.generation_dir)
        ):
            return ActivationResult(
                status="noop",
                config_path=profile.config_path,
                generation_dir=prepared.generation_dir,
                python_path=prepared.python_path,
                previous_python=prev_python,
                reportable=False,
            )

        new_cfg = dict(current_cfg)
        new_cfg.update(
            {
                "host": profile.host,
                "python": str(prepared.python_path),
                "component_release": str(prepared.generation_dir),
                "source_root": str(profile.plugin_root),
                "product_validation": dict(receipt["validation"]),
                "updated_at": time.time(),
            }
        )
        new_cfg.setdefault("admission_path", str(profile.admission_db))
        new_cfg.setdefault("consent_config", str(profile.consent_path))

        # Execute pre-commit migration (e.g., OS Scheduled Task or host package) BEFORE flipping <host>.json!
        if on_before_commit is not None:
            on_before_commit(profile, prepared, new_cfg)

        # Authoritative host pointer commits LAST!
        atomic_write_json(profile.config_path, new_cfg)
        clear_pending_update_check(profile)
    finally:
        update_lock.release()

    gc_summary = None
    if run_gc:
        keep = [prepared.generation_dir]
        if prev_python:
            keep.append(Path(prev_python))
        gc_summary = reclaim_generations(profile, keep_paths=keep, budget_seconds=gc_budget_seconds)

    return ActivationResult(
        status="active",
        config_path=profile.config_path,
        generation_dir=prepared.generation_dir,
        python_path=prepared.python_path,
        previous_python=prev_python,
        reportable=False,
        gc_summary=gc_summary,
    )


def maintain_generations(
    profile: ProfileRef,
    *,
    keep_paths: Sequence[str | Path] = (),
    scheduled_tasks: Sequence[str] = (),
    budget_seconds: float = 2.0,
    consume_pending_check: bool = True,
    builder_callback: Callable[[ProfileRef, dict[str, Any]], ActivationResult | dict[str, Any] | None] | None = None,
) -> dict[str, Any]:
    """Consume `pending-update-check.json` (if due) and run bounded `Active + Rollback` GC."""
    pending = read_pending_update_check(profile) if consume_pending_check else None
    update_outcome: Any = None
    if pending is not None and builder_callback is not None:
        update_outcome = builder_callback(profile, pending)
        clear_pending_update_check(profile)
    gc_res = reclaim_generations(
        profile,
        keep_paths=keep_paths,
        scheduled_tasks=scheduled_tasks,
        budget_seconds=budget_seconds,
    )
    return {
        "pending_check": pending,
        "update_outcome": update_outcome.to_dict() if hasattr(update_outcome, "to_dict") else update_outcome,
        "gc": gc_res,
    }
