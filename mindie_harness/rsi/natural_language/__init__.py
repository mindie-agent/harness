"""Host-neutral natural-language RSI planning and execution package.

[Role] Exposes plan validation and bounded candidate execution on top of the
       shared harness RSI ledger.
[Invariants] Customer commands remain argv-based and unknown external effects
             never become successful evidence.
[Timeouts & Locks] State and ledger ownership stays with harness RSI modules.
[Side-Effect Policy] Submodules perform explicit CLI or runtime operations only.
"""

SCHEMA = "mindie-agent/rsi-plan/v1"

__all__ = ["SCHEMA"]
