"""Canonical thin-host MCP gateway (`ManagedMCPAdapter`) and native plugin rebinding.

[Role]
Provides `HOST_REMOTE_PROFILES`, `resolve_remote_profile`,
`rebind_native_plugin_if_needed`, and `ManagedMCPAdapter(DefaultHostAdapter)` so any
of the 7 thin host plugins can delete its bespoke `mcp_server.py` / `knowledge_cli.py`
/ `diagnostic_support.py` while keeping `remote`, `tools`, `components`, `knowledge`,
and `all` surfaces identical.

[Invariants]
- Zero top-level imports of `remote_dev`, `mindie_knowledge`, `mindie_diagnostics`, or host plugins; optional packages load lazily.
- `extract_session_identity` NEVER raises and NEVER fails closed: it reads `_meta`
  first, then host environment IDs, then returns `None` so `MCPRouter` assigns the
  connection-scoped `{host}-conn-{connection_id[:12]}` fallback.
- Component CLI tools prefer `<host>.json` `component_commands[<name>]` (custom
  wrappers survive) and otherwise run `[python, "-I", "-X", "utf8", "-m", <module>]`;
  timeouts clamp to `1..300000ms` (default `120000`) and output tokens to
  `1..262144` (default `16384`).
- `<host>.json` rebinding and the native version stamp commit atomically under
  `<host>.json.update.lock`; only standard `-m <module>` argv entries are rebound and
  custom wrapper scripts stay byte-for-byte intact.

[Timeouts & Locks]
- Component tools run under `run_owned` (`outer = timeout + cleanup_grace`).
- `rebind_native_plugin_if_needed` holds `.update.lock` `<= 5.0s`, classifies contention
  as `deferred`, and a stale `<6h` cache only enqueues a `< 5ms` marker.

[Side-Effect Policy]
- Dispatches bounded child processes and optional remote-dev calls.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import time
from typing import Any, Mapping, Sequence

from ..api import DefaultHostAdapter, inspect_profile
from ..atomic import atomic_write_json, read_json_safe
from ..component_commands import STANDARD_COMPONENT_COMMANDS, command_argv, is_standard_module_command
from ..locks import FileLock, LockTimeoutError
from ..paths import ProfileRef
from ..runtime.registry import parse_version_key
from .doctor import DOCTOR_TOOL_NAME, doctor_tool_definition, run_doctor_tool
from .gateway_dispatch import (
    COMPONENT_MODULES,
    HOST_REMOTE_PROFILES,
    dispatch_remote_tool,
    error_result as _error,
    list_remote_tools,
    mcp_result as _mcp_result,
    resolve_remote_profile,
    run_component_tool,
    run_diagnostics_tool,
)
from .knowledge_rpc import KNOWLEDGE_NAMES, KNOWLEDGE_TOOL_SCHEMAS, invoke_knowledge_tool
from .router import RequestContext

_SESSION_ENV_KEYS: tuple[str, ...] = (
    "CODEX_THREAD_ID", "CLAUDE_SESSION_ID", "KIMI_SESSION_ID", "AGY_CONVERSATION_ID",
    "WORKBUDDY_SESSION_ID", "OPENCODE_SESSION_ID", "DSH_SESSION_ID",
    "MINDIE_SESSION_ID", "REMOTE_DEV_SESSION_ID",
)
_COMPONENT_MODULES = COMPONENT_MODULES


def _read_native_version(plugin_root: Path) -> str | None:
    for name in ("plugin.json", "kimi.plugin.json", "package.json"):
        raw = read_json_safe(Path(plugin_root) / name)
        if isinstance(raw, dict) and isinstance(raw.get("version"), str) and raw["version"].strip():
            return raw["version"].strip()
    return None


def rebind_native_plugin_if_needed(
    profile: ProfileRef,
    *,
    native_version: str | None = None,
    runtime_scripts: Path | None = None,
) -> dict[str, Any] | None:
    """Stamp a newer native plugin version and rebind standard component commands."""
    cfg = read_json_safe(profile.config_path)
    if not isinstance(cfg, dict):
        return None
    python_raw = cfg.get("python")
    if not isinstance(python_raw, str) or not Path(python_raw).is_file():
        return None
    discovered = native_version or _read_native_version(profile.plugin_root)
    desired_scripts = runtime_scripts or (profile.plugin_root / "scripts" if (profile.plugin_root / "scripts").is_dir() else None)
    validation = cfg.get("product_validation") if isinstance(cfg.get("product_validation"), Mapping) else {}
    current_native = str(validation.get("native_version") or "")
    current_scripts = cfg.get("runtime_scripts")
    needs_version = bool(discovered and discovered != current_native)
    if discovered and current_native:
        try:
            needs_version = needs_version or parse_version_key(discovered) > parse_version_key(current_native)
        except ValueError:
            needs_version = True
    needs_scripts = bool(desired_scripts and str(desired_scripts) != str(current_scripts))
    if not needs_version and not needs_scripts:
        return None
    lock = FileLock(profile.config_path.with_name(f".{profile.config_path.name}.update.lock"), exclusive=True, timeout=5.0)
    try:
        lock.acquire()
    except LockTimeoutError:
        return {"status": "deferred", "reason": "lock_timeout", "reportable": False, "config_path": str(profile.config_path)}
    try:
        current = read_json_safe(profile.config_path)
        new_cfg = dict(current) if isinstance(current, dict) else dict(cfg)
        new_cfg["source_root"] = str(profile.plugin_root)
        if desired_scripts is not None:
            new_cfg["runtime_scripts"] = str(desired_scripts)
        new_validation = dict(new_cfg.get("product_validation") or {})
        if discovered:
            new_validation["native_version"] = discovered
        new_cfg["product_validation"] = new_validation
        commands = new_cfg.get("component_commands")
        if isinstance(commands, Mapping):
            rebound = dict(commands)
            for key, (_package, module) in STANDARD_COMPONENT_COMMANDS.items():
                if key in rebound and is_standard_module_command(command_argv(rebound.get(key)), module):
                    rebound[key] = [str(new_cfg["python"]), "-I", "-X", "utf8", "-m", module]
            new_cfg["component_commands"] = rebound
        new_cfg["updated_at"] = time.time()
        atomic_write_json(profile.config_path, new_cfg)
    except TimeoutError:
        raise
    except OSError as exc:
        return {"status": "deferred", "reason": "config_write_failed", "reportable": False, "message": type(exc).__name__}
    finally:
        lock.release()
    return {
        "status": "rebound",
        "config_path": str(profile.config_path),
        "native_version": discovered,
        "runtime_scripts": str(desired_scripts) if desired_scripts else None,
        "reportable": False,
    }


def _tool(name: str, description: str, properties: Mapping[str, Any], required: Sequence[str] = ()) -> dict[str, Any]:
    return {
        "name": name,
        "description": description,
        "inputSchema": {"type": "object", "properties": dict(properties), "required": list(required)},
    }


def _component_tools() -> list[dict[str, Any]]:
    component_props = {
        "argv": {"type": "array", "items": {"type": "string"}},
        "timeout_ms": {"type": "integer", "minimum": 1, "maximum": 300000, "default": 120000},
        "max_output_tokens": {"type": "integer", "minimum": 1, "maximum": 262144, "default": 16384},
    }
    return [
        {**_tool("mindie_status", "Inspect active MindIE Harness runtime and profile state.", {}), "annotations": {"readOnlyHint": True}},
        doctor_tool_definition(),
        _tool("profiler", "Run the bound MindIE profiler CLI.", component_props),
        _tool("sim", "Run the bound MindIE simulator CLI.", component_props),
        _tool("coordinator", "Run the bound MindIE coordinator CLI.", component_props),
        _tool("npu_top", "Run the bound NPU topology probe.", component_props),
        _tool("debugger", "Run the bound MindIE debugger CLI.", component_props),
        _tool("rsi_loop", "Run the bound RSI experiment loop CLI.", component_props),
        _tool("experiment_ledger", "Run the bound RSI experiment ledger CLI.", component_props),
        {**_tool("diagnostics_status", "Read local diagnostics status.", {"argv": component_props["argv"]}), "annotations": {"readOnlyHint": True}},
        _tool("diagnostics_bundle", "Export a bounded sanitized diagnostics bundle.", {"argv": component_props["argv"]}),
    ]


def _channel_cache_stale(profile: ProfileRef, *, ttl: float = 21600.0) -> bool:
    raw = read_json_safe(profile.state_dir / "channel-cache.json")
    if not isinstance(raw, dict) or type(raw.get("fetched_at")) not in (int, float):
        return True
    return (time.time() - float(raw["fetched_at"])) >= ttl


def _maybe_enqueue_update_check(profile: ProfileRef) -> None:
    try:
        if not _channel_cache_stale(profile):
            return
        marker = profile.pending_update_path
        if isinstance(read_json_safe(marker), dict):
            return
        atomic_write_json(marker, {"schema": "mindie-pending-update/1", "host": profile.host, "reason": "mcp_tools_call", "requested_at": time.time()})
    except Exception:
        pass


class ManagedMCPAdapter(DefaultHostAdapter):
    """Thin-host adapter registering and dispatching every canonical MindIE tool."""

    def __init__(
        self,
        host: str = "codex",
        *,
        plugin_root: str | Path | None = None,
        config_path: str | Path | None = None,
        data_dir: str | Path | None = None,
        include_knowledge: bool | None = None,
    ) -> None:
        super().__init__(host, plugin_root=plugin_root, config_path=config_path, data_dir=data_dir)
        self.include_knowledge = include_knowledge

    def extract_session_identity(self, request: Mapping[str, Any], env: Mapping[str, str]) -> str | None:
        try:
            params = request.get("params")
            meta = params.get("_meta") if isinstance(params, Mapping) else None
            if isinstance(meta, Mapping):
                for key in ("session_id", "sessionId", "threadId", "claudecode/sessionId"):
                    value = meta.get(key)
                    if isinstance(value, str) and value.strip():
                        return value.strip()
            for key in _SESSION_ENV_KEYS:
                value = env.get(key)
                if isinstance(value, str) and value.strip():
                    return value.strip()
        except Exception:
            return None
        return None

    def mcp_tools(self, surface: str, profile: ProfileRef) -> list[dict[str, Any]]:
        clean = str(surface or "all").strip().lower()
        if clean == "knowledge":
            return [dict(item) for item in KNOWLEDGE_TOOL_SCHEMAS]
        if clean == "remote":
            return list_remote_tools(profile, dict(os.environ), self.host)
        components = _component_tools()
        include_knowledge = self.include_knowledge if self.include_knowledge is not None else clean in {"tools", "all"}
        if clean == "components":
            return components + ([dict(item) for item in KNOWLEDGE_TOOL_SCHEMAS] if include_knowledge else [])
        tools = components + [dict(item) for item in KNOWLEDGE_TOOL_SCHEMAS] if include_knowledge else components
        merged = list_remote_tools(profile, dict(os.environ), self.host) + tools if clean == "all" else tools
        seen: set[str] = set()
        unique: list[dict[str, Any]] = []
        for item in merged:
            name = str(item.get("name") or "")
            if name and name not in seen:
                seen.add(name)
                unique.append(item)
        return unique

    def dispatch_tool(self, ctx: RequestContext, arguments: dict[str, Any], profile: ProfileRef) -> dict[str, Any]:
        arguments = arguments or {}
        _maybe_enqueue_update_check(profile)
        name = ctx.tool_name
        if name == "mindie_status":
            body = inspect_profile(profile)
            body["status"] = "ok"
            body["session_id"] = ctx.session_id
            return _mcp_result(json.dumps(body, sort_keys=True, default=str), structured=body)
        if name == DOCTOR_TOOL_NAME:
            doctor_args = dict(arguments)
            if "cwd" not in doctor_args and ctx.cwd is not None:
                doctor_args["cwd"] = str(ctx.cwd)
            return run_doctor_tool(doctor_args, deadline=ctx.deadline, cancel=ctx.cancel, env=ctx.env)
        if name in KNOWLEDGE_NAMES:
            return invoke_knowledge_tool(name, arguments, profile=profile, session_id=ctx.session_id, cwd=ctx.cwd, deadline=ctx.deadline)
        if name in COMPONENT_MODULES:
            return run_component_tool(ctx, name, arguments, profile)
        if name in {"diagnostics_status", "diagnostics_bundle"}:
            return run_diagnostics_tool(ctx, name, arguments, profile)
        if name.startswith("remote_"):
            return dispatch_remote_tool(ctx, arguments, profile, self.host)
        return _error("unknown_operation", f"Unknown MindIE tool {name!r}.")


__all__ = ["HOST_REMOTE_PROFILES", "ManagedMCPAdapter", "rebind_native_plugin_if_needed", "resolve_remote_profile"]
