"""Concurrent dual-framing stdio MCP server, silent default-on (`P2.7`/`P2.8`) router, and honest receipts.

[Role]
Re-exports `RemoteReceipts`, `BindStore`, `apply_receipt_honesty`, `RequestContext`,
`MCPRouter`, `MCPStdioServer`, `read_mcp_message`, `write_mcp_message`, `serve_stdio`,
the read-only `mindie_doctor` tool definition/dispatcher, and lazily the canonical
`ManagedMCPAdapter` / `knowledge_*` schemas so `import mindie_harness` stays stdlib-only.

[Invariants]
- All MCP surfaces (`remote`, `tools`, `components`, `knowledge`, `all`) execute over
  standard `tools/call` with ZERO pre-call session binding (`P2.7` / `P2.8`), falling
  back to `{host}-conn-{connection_id[:12]}` when host session metadata is absent.
- Parallel read-only/status/cancel requests (including `mindie_doctor`,
  `knowledge_query`, and `knowledge_explain`) are NEVER blocked by foreground tools.

[Timeouts & Locks]
- Enforces `outer_timeout >= inner_budget + cleanup_grace` per tool surface.

[Side-Effect Policy]
- Pure imports on load; stdio/SQLite activity occurs only when a server/router runs.
"""
from __future__ import annotations

from .doctor import DOCTOR_TOOL_NAME, doctor_tool_definition, run_doctor_tool
from .receipts import (
    RECEIPTS_SCHEMA_V1,
    RECEIPTS_SCHEMA_V2,
    BindStore,
    RemoteReceipts,
    apply_receipt_honesty,
    is_owner_alive,
    process_boot_signature,
)
from .router import (
    CORRELATION_STRIP_KEYS,
    FORGED_IDENTITY_KEYS,
    MCPRouter,
    RequestContext,
    compute_tool_deadline,
    is_readonly_or_control_tool,
    is_readonly_tool_call,
)
from .server import MCPStdioServer, read_mcp_message, serve_stdio, write_mcp_message

__all__ = [
    "CORRELATION_STRIP_KEYS",
    "DOCTOR_TOOL_NAME",
    "FORGED_IDENTITY_KEYS",
    "RECEIPTS_SCHEMA_V1",
    "RECEIPTS_SCHEMA_V2",
    "BindStore",
    "MCPRouter",
    "MCPStdioServer",
    "ManagedMCPAdapter",
    "RemoteReceipts",
    "RequestContext",
    "KNOWLEDGE_NAMES",
    "KNOWLEDGE_TOOL_SCHEMAS",
    "apply_receipt_honesty",
    "compute_tool_deadline",
    "doctor_tool_definition",
    "invoke_knowledge_tool",
    "is_owner_alive",
    "is_readonly_or_control_tool",
    "is_readonly_tool_call",
    "process_boot_signature",
    "read_mcp_message",
    "run_doctor_tool",
    "serve_stdio",
    "write_mcp_message",
]


def __getattr__(name: str):
    """Lazily expose gateway/knowledge symbols without importing optional packages."""
    if name == "ManagedMCPAdapter":
        from .gateway import ManagedMCPAdapter

        return ManagedMCPAdapter
    if name in {"KNOWLEDGE_NAMES", "KNOWLEDGE_TOOL_SCHEMAS"}:
        from .knowledge_schemas import KNOWLEDGE_NAMES, KNOWLEDGE_TOOL_SCHEMAS

        return {"KNOWLEDGE_NAMES": KNOWLEDGE_NAMES, "KNOWLEDGE_TOOL_SCHEMAS": KNOWLEDGE_TOOL_SCHEMAS}[name]
    if name == "invoke_knowledge_tool":
        from .knowledge_rpc import invoke_knowledge_tool

        return invoke_knowledge_tool
    raise AttributeError(name)
