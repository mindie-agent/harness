"""Canonical `knowledge_*` MCP tool schemas shared by every thin host plugin.

[Role]
Declares `KNOWLEDGE_NAMES` and the 5 canonical `KNOWLEDGE_TOOL_SCHEMAS`
(`knowledge_query`, `knowledge_explain`, `knowledge_feedback`, `knowledge_distill`,
`knowledge_sync`) with `readOnlyHint` / `openWorldHint` annotations.

[Invariants]
- Pure data: zero imports of `mindie_knowledge`, `mindie_diagnostics`, or host code.
- Read tools (`knowledge_query`, `knowledge_explain`) set `readOnlyHint=True`;
  network-writing tools (`knowledge_sync`) set `openWorldHint=True`.
- Every schema keeps `additionalProperties=False`; the MCP router strips legacy
  correlation keys before validation, and `rsi.rsi_explore.schema_properties()` is
  the single source of truth for RSI explore properties.

[Timeouts & Locks]
- Pure in-memory constants (`< 0.1ms`); no I/O, locks, or deadlines.

[Side-Effect Policy]
- Immutable-at-import data only; never writes files or environment state.
"""
from __future__ import annotations

from typing import Any

from ..rsi.rsi_explore import schema_properties

KNOWLEDGE_NAMES: tuple[str, ...] = (
    "knowledge_query",
    "knowledge_explain",
    "knowledge_feedback",
    "knowledge_distill",
    "knowledge_sync",
)

_RSI_PROPS: dict[str, Any] = schema_properties()

KNOWLEDGE_TOOL_SCHEMAS: list[dict[str, Any]] = [
    {
        "name": "knowledge_query",
        "description": "Search graded MindIE knowledge units and workflows (read-only).",
        "annotations": {"readOnlyHint": True, "openWorldHint": True},
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "query": {"type": "string"},
                "domain": {"type": "string"},
                "domain_path": {"type": "string"},
                "conditions": {"type": "object"},
                "intent": {"type": "string", "enum": ["apply", "reference"],
                           "description": "Use reference to look up or read graded cards for background."},
                "token_budget": {"type": "integer", "minimum": 1, "maximum": 64000},
                "limit": {"type": "integer", "minimum": 1, "maximum": 20},
                "continuation": {"type": "string"},
                "navigation_only": {"type": "boolean"},
                "include_unknown": {"type": "boolean"},
                "include_archived": {"type": "boolean"},
                "known_refs": {"type": "array", "items": {"type": "string"}},
                "run_id": {"type": "string"},
                **_RSI_PROPS,
            },
            "required": [],
        },
    },
    {
        "name": "knowledge_explain",
        "description": "Load graded units or a task reference with prerequisite closure (read-only).",
        "annotations": {"readOnlyHint": True, "openWorldHint": False},
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "ref": {"type": "string"},
                "refs": {"type": "array", "items": {"type": "string"}},
                "domain": {"type": "string"},
                "conditions": {"type": "object"},
                "intent": {"type": "string", "enum": ["apply", "reference"],
                           "description": "Use reference to look up or read graded cards for background."},
                "known_refs": {"type": "array", "items": {"type": "string"}},
                "token_budget": {"type": "integer", "minimum": 1, "maximum": 64000},
                "run_id": {"type": "string"},
                **_RSI_PROPS,
            },
            "required": [],
        },
    },
    {
        "name": "knowledge_feedback",
        "description": "Record a rating or 4-stage usage event for a knowledge unit.",
        "annotations": {"readOnlyHint": False, "openWorldHint": False},
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "ref": {"type": "string"},
                "domain": {"type": "string"},
                "rating": {"type": "string", "enum": ["up", "down"]},
                "reason": {"type": "string"},
                "event_type": {"type": "string", "enum": ["discovered", "loaded", "applied", "evaluated"]},
                "run_id": {"type": "string"},
                "step_id": {"type": "string"},
                "outcome": {"type": "string", "enum": ["supported", "refuted", "inconclusive"]},
                "evidence_source": {"type": "string", "enum": ["agent_declared", "run_manifest_verified", "ablation_verified"]},
            },
            "required": ["ref"],
        },
    },
    {
        "name": "knowledge_distill",
        "description": "Distill verified milestone or completed task evidence into graded units.",
        "annotations": {"readOnlyHint": False, "openWorldHint": False},
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "inputs": {"type": "array", "items": {"type": "object"}},
                "task_state": {"type": "string", "enum": ["in_flight", "verified_milestone", "completed"]},
                "proposal": {"type": "object"},
                "related_refs": {"type": "array", "items": {"type": "string"}},
                "domain": {"type": "string"},
                "topic": {"type": "string"},
                "target_signature": {"type": "string"},
            },
            "required": ["inputs", "task_state"],
        },
    },
    {
        "name": "knowledge_sync",
        "description": "Synchronize the configured public knowledge feed (mutation, network).",
        "annotations": {"readOnlyHint": False, "openWorldHint": True},
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {"domain": {"type": "string"}},
            "required": [],
        },
    },
]

__all__ = ["KNOWLEDGE_NAMES", "KNOWLEDGE_TOOL_SCHEMAS"]
