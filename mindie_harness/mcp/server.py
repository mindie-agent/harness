"""Dual-framing (`Content-Length` + JSONL) resident concurrent stdio MCP server.

[Role]
Implements `read_mcp_message`, `write_mcp_message`, `MCPStdioServer`, and
`serve_stdio`—serving long-lived MCP stdio connections with zero cold `--once`
spawns (`AD-03` fixed), separate read-only vs mutation worker pools (`AD-09` fixed),
runtime `.inuse` generation leasing, and async `pending-update-check.json` consumption.

[Invariants]
- Auto-detects `Content-Length: N\\r\\n\\r\\n` headers vs JSONL newline framing per
  message and replies in the caller's exact framing format.
- `initialize`, `ping`, `tools/list`, `notifications/cancelled`, and `mindie_interrupt`
  execute inline (`< 2ms`) on the reader loop without waiting behind any tool worker.
- Read-only / status / cancel `tools/call` requests run on `read_executor` (`16` workers,
  zero `>=4` cap) and NEVER queue behind long-running foreground mutations (`remote_bash`).
- Holds a `GenerationLease` on its active runtime directory until stdio EOF.

[Timeouts & Locks]
- Outbound stdio writes serialize through `self._write_lock`; incoming payloads are
  bounded at `32 MiB` (`MAX_FRAME_BYTES`).

[Side-Effect Policy]
- Reads `stdin`, writes `stdout`, holds one `.inuse` generation lease if applicable,
  and optionally runs background `maintain_generations` when `pending-update-check.json` exists.
"""
from __future__ import annotations

from concurrent.futures import Future, ThreadPoolExecutor
from contextlib import ExitStack
import json
from pathlib import Path
import sys
import threading
from typing import Any, BinaryIO, Callable

from .. import __version__
from ..locks import acquire_generation_lease
from ..paths import HarnessError
from ..runtime.activation import maintain_generations, read_pending_update_check
from .router import MCPRouter

MAX_FRAME_BYTES = 32 * 1024 * 1024
PROTOCOL_VERSION = "2025-11-25"
INTERRUPT_TOOL_NAME = "mindie_interrupt"


def read_mcp_message(stream: BinaryIO) -> tuple[dict[str, Any] | None, str]:
    """Read one JSON-RPC message supporting both `Content-Length` LSP framing and JSONL."""
    while True:
        first_line = stream.readline(MAX_FRAME_BYTES + 1)
        if not first_line:
            return None, "jsonl"
        if len(first_line) > MAX_FRAME_BYTES:
            raise HarnessError("MCP input line exceeds 32 MiB limit", stage="cli_input", reason="input_too_large")
        stripped = first_line.strip()
        if not stripped:
            continue

        if stripped.lower().startswith(b"content-length:"):
            content_length: int | None = None
            hdr_line = first_line
            while True:
                clean_hdr = hdr_line.strip()
                if not clean_hdr:
                    break
                key, sep, val = clean_hdr.partition(b":")
                if not sep:
                    raise ValueError("Malformed MCP header line")
                if key.strip().lower() == b"content-length":
                    content_length = int(val.strip().decode("ascii"))
                hdr_line = stream.readline(8192)
                if not hdr_line:
                    return None, "content-length"

            if content_length is None or content_length < 0 or content_length > MAX_FRAME_BYTES:
                raise ValueError(f"Invalid Content-Length: {content_length}")

            chunks: list[bytes] = []
            remaining = content_length
            while remaining > 0:
                piece = stream.read(remaining)
                if not piece:
                    raise EOFError("Unexpected EOF inside Content-Length body")
                chunks.append(piece)
                remaining -= len(piece)
            raw_body = b"".join(chunks)
            parsed = json.loads(raw_body.decode("utf-8-sig"))
            if not isinstance(parsed, dict):
                raise ValueError("JSON-RPC payload must be an object")
            return parsed, "content-length"

        parsed = json.loads(stripped.decode("utf-8-sig"))
        if not isinstance(parsed, dict):
            raise ValueError("JSON-RPC payload must be an object")
        return parsed, "jsonl"


def write_mcp_message(stream: BinaryIO, payload: dict[str, Any], framing: str) -> None:
    """Write one JSON-RPC message in `"content-length"` or `"jsonl"` framing."""
    encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if framing == "content-length":
        header = f"Content-Length: {len(encoded)}\r\n\r\n".encode("ascii")
        stream.write(header)
        stream.write(encoded)
    else:
        stream.write(encoded + b"\n")
    stream.flush()


class MCPStdioServer:
    """Resident concurrent stdio JSON-RPC 2.0 MCP server."""

    def __init__(
        self,
        router: MCPRouter,
        *,
        server_name: str | None = None,
        server_version: str = __version__,
        maintenance_callback: Callable[[], None] | None = None,
        read_workers: int = 16,
        mutation_workers: int = 8,
        max_mutation_workers: int | None = None,
    ) -> None:
        self.router = router
        self.server_name = server_name or f"mindie-{router.surface}"
        self.server_version = server_version
        self._maintenance_callback = maintenance_callback
        self._write_lock = threading.Lock()
        self._inflight_lock = threading.Lock()
        self._inflight: dict[str | int, threading.Event] = {}
        self._read_workers = max(4, int(read_workers))
        eff_mut = mutation_workers if max_mutation_workers is None else max_mutation_workers
        self._mutation_workers = max(2, int(eff_mut))
        self._maint_busy = threading.Lock()

    def _acquire_own_lease(self, stack: ExitStack) -> None:
        exe = Path(sys.executable).absolute()
        gen_root = self.router.profile.generations_dir.absolute()
        try:
            rel = exe.relative_to(gen_root)
            gen_dir = gen_root / rel.parts[0]
            if gen_dir.is_dir():
                stack.enter_context(acquire_generation_lease(gen_dir))
        except (ValueError, OSError, RuntimeError):
            pass

    def _maybe_schedule_maintenance(self, maint_pool: ThreadPoolExecutor) -> None:
        if read_pending_update_check(self.router.profile) is None:
            return
        if not self._maint_busy.acquire(blocking=False):
            return

        def _bg_task() -> None:
            try:
                if self._maintenance_callback is not None:
                    self._maintenance_callback()
                else:
                    maintain_generations(self.router.profile, budget_seconds=2.0)
            except Exception:
                pass
            finally:
                self._maint_busy.release()

        maint_pool.submit(_bg_task)

    def serve(
        self,
        *,
        stdin: BinaryIO | None = None,
        stdout: BinaryIO | None = None,
    ) -> int:
        in_stream = sys.stdin.buffer if stdin is None else stdin
        out_stream = sys.stdout.buffer if stdout is None else stdout

        def _send(msg: dict[str, Any], framing: str) -> None:
            with self._write_lock:
                write_mcp_message(out_stream, msg, framing)

        def _respond(req_id: str | int, result: dict[str, Any], framing: str) -> None:
            _send({"jsonrpc": "2.0", "id": req_id, "result": result}, framing)

        def _error(req_id: str | int | None, code: int, message: str, framing: str) -> None:
            _send({"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}, framing)

        read_pool = ThreadPoolExecutor(max_workers=self._read_workers, thread_name_prefix="mindie-mcp-read")
        mut_pool = ThreadPoolExecutor(max_workers=self._mutation_workers, thread_name_prefix="mindie-mcp-mut")
        maint_pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="mindie-mcp-maint")
        futures: set[Future[None]] = set()
        futures_lock = threading.Lock()

        def _run_tool_call(req_id: str | int, message: dict[str, Any], cancel_ev: threading.Event, framing: str) -> None:
            try:
                res = self.router.call_tool(message, cancel=cancel_ev)
                _respond(req_id, res, framing)
            except Exception as exc:
                _respond(
                    req_id,
                    {
                        "content": [{"type": "text", "text": f"MCP server dispatch error: {type(exc).__name__}"}],
                        "isError": True,
                    },
                    framing,
                )
            finally:
                with self._inflight_lock:
                    self._inflight.pop(req_id, None)

        with ExitStack() as stack:
            self._acquire_own_lease(stack)
            default_framing = "jsonl"
            try:
                while True:
                    try:
                        message, framing = read_mcp_message(in_stream)
                    except (ValueError, UnicodeDecodeError, HarnessError):
                        _error(None, -32700, "Parse error / invalid MCP request", default_framing)
                        continue
                    except EOFError:
                        break

                    if message is None:
                        break
                    default_framing = framing
                    method = message.get("method")
                    has_id = "id" in message and message.get("id") is not None
                    req_id = message.get("id")

                    if method == "notifications/cancelled":
                        target_id = (message.get("params") or {}).get("requestId")
                        with self._inflight_lock:
                            ev = self._inflight.get(target_id)
                            if ev is not None:
                                ev.set()
                        continue

                    if not has_id:
                        # Notifications (e.g., notifications/initialized) produce no response
                        continue

                    if not isinstance(req_id, (str, int)) or isinstance(req_id, bool) or (
                        isinstance(req_id, str) and len(req_id) > 256
                    ):
                        _error(None, -32600, "Invalid JSON-RPC request id", framing)
                        continue

                    if method == "initialize":
                        _respond(
                            req_id,
                            {
                                "protocolVersion": PROTOCOL_VERSION,
                                "capabilities": {"tools": {"listChanged": True}},
                                "serverInfo": {
                                    "name": self.server_name,
                                    "version": self.server_version,
                                },
                            },
                            framing,
                        )
                        self._maybe_schedule_maintenance(maint_pool)
                        continue

                    if method == "ping":
                        _respond(req_id, {}, framing)
                        continue

                    if method == "tools/list":
                        _respond(req_id, {"tools": self.router.list_tools()}, framing)
                        continue

                    if method == "tools/call":
                        params = message.get("params") or {}
                        tname = params.get("name") if isinstance(params, dict) else None
                        if tname == INTERRUPT_TOOL_NAME:
                            cancelled_ids: list[str | int] = []
                            with self._inflight_lock:
                                for active_id, active_ev in list(self._inflight.items()):
                                    active_ev.set()
                                    cancelled_ids.append(active_id)
                            _respond(
                                req_id,
                                {
                                    "content": [
                                        {
                                            "type": "text",
                                            "text": json.dumps({"interrupted": cancelled_ids}),
                                        }
                                    ],
                                    "isError": False,
                                },
                                framing,
                            )
                            continue

                        cancel_ev = threading.Event()
                        with self._inflight_lock:
                            if req_id in self._inflight:
                                _respond(
                                    req_id,
                                    {
                                        "content": [
                                            {
                                                "type": "text",
                                                "text": "Duplicate in-flight MCP request id; not executed again.",
                                            }
                                        ],
                                        "isError": True,
                                    },
                                    framing,
                                )
                                continue
                            self._inflight[req_id] = cancel_ev

                        self._maybe_schedule_maintenance(maint_pool)
                        pool = read_pool if self.router.is_fast_lane_call(message) else mut_pool
                        fut = pool.submit(_run_tool_call, req_id, message, cancel_ev, framing)
                        with futures_lock:
                            futures.add(fut)
                        fut.add_done_callback(lambda done: futures.discard(done))
                        continue

                    _error(req_id, -32601, f"Unsupported method: {method}", framing)
            finally:
                with self._inflight_lock:
                    for ev in self._inflight.values():
                        ev.set()
                read_pool.shutdown(wait=True)
                mut_pool.shutdown(wait=True)
                maint_pool.shutdown(wait=True)
        return 0


def serve_stdio(
    router: MCPRouter,
    *,
    stdin: BinaryIO | None = None,
    stdout: BinaryIO | None = None,
    server_name: str | None = None,
) -> int:
    """Convenience entry for serving `router` on stdio."""
    server = MCPStdioServer(router, server_name=server_name)
    return server.serve(stdin=stdin, stdout=stdout)
