"""Runtime registry, candidate venv builder, atomic activation, GC, and OS scheduler migration.

[Role]
Re-exports `SHARED_COMPONENTS`, `RuntimeSelection`, `PreparedGeneration`,
`ActivationResult`, `prepare_candidate_runtime`, `activate_generation`,
`reclaim_generations`, `maintain_generations`, and OS scheduler helpers.

[Invariants]
- Enforces a `2.5 GiB` disk free-space floor on candidate runtime builds only
  (never blocking small receipt or marker writes).
- Commits the authoritative `<host>.json` pointer LAST and retains at most
  `Active + Rollback (<= 2)` generations plus live-leased and scheduled closures.

[Timeouts & Locks]
- Classifies `LockTimeoutError` contention as `status="deferred"` (`reportable=False`).

[Side-Effect Policy]
- Pure module imports; disk/process operations run only on explicit function calls.
"""
from __future__ import annotations

from .activation import (
    WARN_FOOTPRINT_BYTES,
    ActivationResult,
    activate_generation,
    clear_pending_update_check,
    maintain_generations,
    read_pending_update_check,
    reclaim_generations,
    write_pending_update_check,
)
from .builder import (
    CANDIDATE_RECEIPT_SCHEMA,
    MIN_BUILD_FREE_BYTES,
    PreparedGeneration,
    check_disk_floor,
    prepare_candidate_runtime,
)
from .registry import (
    RETIRED_COMPONENTS,
    SHARED_COMPONENTS,
    RuntimeSelection,
    compute_generation_key,
    parse_version_key,
    select_compatible_release,
    select_python_abi,
    version_satisfies,
)
from .scheduler import (
    discover_scheduled_executables,
    migrate_schedule,
    render_windows_gui_wrapper,
    retire_schedule,
)

__all__ = [
    "CANDIDATE_RECEIPT_SCHEMA",
    "MIN_BUILD_FREE_BYTES",
    "RETIRED_COMPONENTS",
    "SHARED_COMPONENTS",
    "WARN_FOOTPRINT_BYTES",
    "ActivationResult",
    "PreparedGeneration",
    "RuntimeSelection",
    "activate_generation",
    "check_disk_floor",
    "clear_pending_update_check",
    "compute_generation_key",
    "discover_scheduled_executables",
    "maintain_generations",
    "migrate_schedule",
    "parse_version_key",
    "prepare_candidate_runtime",
    "read_pending_update_check",
    "reclaim_generations",
    "render_windows_gui_wrapper",
    "retire_schedule",
    "select_compatible_release",
    "select_python_abi",
    "version_satisfies",
    "write_pending_update_check",
    "discover_channel",
    "extract_wheel_bundle_safely",
    "parse_sha256sums",
    "stage_wheelhouse",
    "update_runtime",
]


def __getattr__(name: str):
    """Lazily expose wheelhouse helpers without adding import-time cost."""
    if name in {"discover_channel", "extract_wheel_bundle_safely", "parse_sha256sums", "stage_wheelhouse", "update_runtime"}:
        from . import wheelhouse

        return getattr(wheelhouse, name)
    raise AttributeError(name)
