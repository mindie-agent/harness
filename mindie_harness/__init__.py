"""MindIE Harness (`mindie_harness`): pure-stdlib shared substrate for all 7 host plugins.

[Role]
Root package exporting `API_VERSION = 1`, `__version__ = "0.1.4"`, and the stable
public facade from `mindie_harness.api`. Placed at repository root (`harness/mindie_harness/`)
so `mindie_diagnostics/triage_card.py` (`layout == "package"`) resolves GitHub
source permalinks cleanly.

[Invariants]
- 100% pure Python stdlib; zero top-level imports of `mindie_knowledge`,
  `mindie_diagnostics`, `torch`, `torch_npu`, or host plugins.

[Timeouts & Locks]
- Zero locks or I/O on package import.

[Side-Effect Policy]
- Pure symbol exports only.
"""
from __future__ import annotations

from typing import Final

__version__: Final[str] = "0.1.4"
API_VERSION: Final[int] = 1

from .api import (
    HOSTS,
    SHARED_COMPONENTS,
    ActivationResult,
    Deadline,
    DefaultHostAdapter,
    HarnessError,
    HostAdapter,
    LockTimeoutError,
    OutputLimitError,
    PreparedGeneration,
    ProcessCancelledError,
    ProcessExecutionError,
    ProcessOutcome,
    ProcessSpec,
    ProfileRef,
    RuntimeSelection,
    activate_runtime,
    inspect_profile,
    maintain_runtime,
    open_database,
    open_wal_database,
    prepare_runtime,
    run_host,
    run_owned,
    serve_mcp,
)

__all__ = [
    "API_VERSION",
    "HOSTS",
    "SHARED_COMPONENTS",
    "ActivationResult",
    "Deadline",
    "DefaultHostAdapter",
    "HarnessError",
    "HostAdapter",
    "LockTimeoutError",
    "ManagedMCPAdapter",
    "OutputLimitError",
    "PreparedGeneration",
    "ProcessCancelledError",
    "ProcessExecutionError",
    "ProcessOutcome",
    "ProcessSpec",
    "ProfileRef",
    "RuntimeSelection",
    "__version__",
    "activate_runtime",
    "configure_sharing",
    "inspect_profile",
    "maintain_runtime",
    "open_database",
    "open_wal_database",
    "prepare_runtime",
    "run_host",
    "run_owned",
    "serve_mcp",
    "sharing_status",
    "update_runtime",
]


def __getattr__(name: str):
    """Lazily expose sharing/update symbols to keep cold import stdlib-only."""
    if name == "ManagedMCPAdapter":
        from .mcp.gateway import ManagedMCPAdapter

        return ManagedMCPAdapter
    if name in {"configure_sharing", "sharing_status"}:
        from .sharing import configure_sharing, sharing_status

        return {"configure_sharing": configure_sharing, "sharing_status": sharing_status}[name]
    if name == "update_runtime":
        from .runtime.wheelhouse import update_runtime

        return update_runtime
    raise AttributeError(name)
