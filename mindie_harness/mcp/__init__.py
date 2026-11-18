"""Concurrent dual-framing stdio MCP server, silent default-on (`P2.7`/`P2.8`) router, and honest receipts.

[Role]
Re-exports `RemoteReceipts`, `BindStore`, `apply_receipt_honesty`, `RequestContext`,
`MCPRouter`, `MCPStdioServer`, `read_mcp_message`, `write_mcp_message`, and `serve_stdio`.

[Invariants]
- All MCP surfaces (`remote`, `tools`, `components`, `knowledge`, `all`) execute over
  standard `tools/call` with ZERO pre-call session binding (`P2.7` / `P2.8`), falling
  back to `{host}-conn-{connection_id[:12]}` when host session metadata is absent.
- Parallel read-only/status/cancel requests (including `knowledge_query` and
  `knowledge_explain`) are NEVER blocked by in-flight foreground tools.

[Timeouts & Locks]
- Enforces `outer_timeout >= inner_budget + cleanup_grace` per tool surface.

[Side-Effect Policy]
- Pure imports on load; stdio/SQLite activity occurs only when a server/router runs.
"""
from __future__ import annotations

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
)
from .server import MCPStdioServer, read_mcp_message, serve_stdio, write_mcp_message

__all__ = [
    "CORRELATION_STRIP_KEYS",
    "FORGED_IDENTITY_KEYS",
    "RECEIPTS_SCHEMA_V1",
    "RECEIPTS_SCHEMA_V2",
    "BindStore",
    "MCPRouter",
    "MCPStdioServer",
    "RemoteReceipts",
    "RequestContext",
    "apply_receipt_honesty",
    "compute_tool_deadline",
    "is_owner_alive",
    "is_readonly_or_control_tool",
    "process_boot_signature",
    "read_mcp_message",
    "serve_stdio",
    "write_mcp_message",
]
