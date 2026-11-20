"""RSI explore-mode MCP argument shaping for `knowledge_query` and `knowledge_explain`.

[Role]
Declares the optional `mode`, `ledger_entries`, `bottleneck_summary`,
`native_subcontext`, and `goal` MCP properties and normalizes them at the
protocol boundary across all 7 host plugins before forwarding to `knowledge`.

[Invariants]
- `mode` is strictly `reuse`, `diagnose`, or `explore`; unknown modes, malformed
  `ledger_entries` / `bottleneck_summary`, string booleans (`"false"`), and
  non-string `goal` values are rejected before any lease or RPC call.
- Normalization populates optional keys with declared defaults without inventing a mode.

[Timeouts & Locks]
- Pure in-memory argument validation (`< 0.1ms`); no I/O, sleep, or locks.

[Side-Effect Policy]
- Returns a normalized shallow copy of caller arguments; mutates nothing.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

MODES: frozenset[str] = frozenset({"reuse", "diagnose", "explore"})
OPTIONAL_KEYS: tuple[str, ...] = (
    "ledger_entries",
    "bottleneck_summary",
    "native_subcontext",
    "goal",
)


def schema_properties() -> dict[str, Any]:
    """Return the shared optional MCP JSON Schema properties for query and explain."""
    return {
        "mode": {"type": "string", "enum": ["reuse", "diagnose", "explore"]},
        "ledger_entries": {"type": "array", "items": {"type": "object"}},
        "bottleneck_summary": {"type": "object"},
        "native_subcontext": {"type": "boolean"},
        "goal": {"type": "string"},
    }


def parse_args(arguments: Mapping[str, Any] | None) -> dict[str, Any]:
    """Validate RSI arguments and return a normalized copy."""
    body = dict(arguments or {})
    raw_mode = body.get("mode", "reuse")
    if raw_mode is not None and not isinstance(raw_mode, str):
        raise ValueError("mode must be one of reuse, diagnose or explore")
    mode = raw_mode if isinstance(raw_mode, str) and raw_mode else "reuse"
    if mode not in MODES:
        raise ValueError("mode must be one of reuse, diagnose or explore")
    ledger = body.get("ledger_entries")
    if ledger is not None and (
        not isinstance(ledger, list)
        or any(not isinstance(item, dict) for item in ledger)
    ):
        raise ValueError("ledger_entries must be an array of objects")
    bottleneck = body.get("bottleneck_summary")
    if bottleneck is not None and not isinstance(bottleneck, dict):
        raise ValueError("bottleneck_summary must be an object")
    raw_subctx = body.get("native_subcontext", False)
    if raw_subctx is None:
        subctx = False
    elif isinstance(raw_subctx, bool):
        subctx = raw_subctx
    elif type(raw_subctx) is int and raw_subctx in {0, 1}:
        subctx = bool(raw_subctx)
    else:
        raise ValueError("native_subcontext must be a boolean")
    raw_goal = body.get("goal", "")
    if raw_goal is not None and not isinstance(raw_goal, str):
        raise ValueError("goal must be a string")
    body["mode"] = mode
    body["ledger_entries"] = ledger
    body["bottleneck_summary"] = bottleneck
    body["native_subcontext"] = subctx
    body["goal"] = raw_goal or ""
    return body


def forwarded(arguments: Mapping[str, Any] | None) -> dict[str, Any]:
    """Validate and normalize RSI arguments for downstream knowledge RPC dispatch."""
    return parse_args(arguments)


__all__ = ["MODES", "OPTIONAL_KEYS", "forwarded", "parse_args", "schema_properties"]
