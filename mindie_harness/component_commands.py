"""Shared component CLI table, wrapper-preserving rebinding, and command resolution.

[Role]
Defines `STANDARD_COMPONENT_COMMANDS`, `COMPONENT_MODULES`, `command_argv`,
`is_standard_module_command`, `resolve_component_command`, and
`rebind_component_commands` so the MCP gateway and the offline wheelhouse agree on
which `<host>.json` `component_commands` entries are standard `-m` module launches
(rebindable) versus user-authored wrapper scripts (never touched).

[Invariants]
- `is_standard_module_command` accepts only the exact launcher prefixes the
  substrate itself writes (`["-I"]`, `["-I", "-X", "utf8"]`,
  `["-I", "-B", "-X", "utf8"]`, or none) before `-m <module>` (including migrating
  legacy `-m mindie_sim` to `-m mindie_sim.cli`); anything else is a custom wrapper
  and MUST survive rebinding byte-for-byte.
- `resolve_component_command` prefers a non-empty `<host>.json`
  `component_commands[<component>]` argv of non-empty strings (automatically upgrading
  legacy standard `-m mindie_sim` to `-m mindie_sim.cli`) and falls back to
  `[python, "-I", "-X", "utf8", "-m", <module>]`.
- Pure functions: no imports of `remote_dev`, `mindie_knowledge`, or host plugins.

[Timeouts & Locks]
- Pure in-memory list/dict inspection (`< 1ms`); no locks or I/O.

[Side-Effect Policy]
- Never mutates its arguments; `rebind_component_commands` edits the caller's `cfg`.
"""
from __future__ import annotations

from typing import Any, Mapping

STANDARD_COMPONENT_COMMANDS: dict[str, tuple[str, str]] = {
    "profiler": ("mindie-profiler", "mindie_profiler"),
    "sim": ("mindie-sim", "mindie_sim.cli"),
    "coordinator": ("mindie-coordinator", "mindie_coordinator.cli"),
    "npu_top": ("npu-top", "npu_top"),
    "diagnostics": ("mindie-diagnostics", "mindie_diagnostics.cli"),
    "debugger": ("mindie-debugger", "mindie_debugger.cli"),
    "rsi_loop": ("mindie-harness", "mindie_harness.rsi.rsi_loop"),
    "experiment_ledger": ("mindie-harness", "mindie_harness.rsi.experiment_ledger"),
}
COMPONENT_MODULES: dict[str, str] = {
    key: module for key, (_package, module) in STANDARD_COMPONENT_COMMANDS.items()
}
_LEGACY_MODULE_ALIASES: dict[str, frozenset[str]] = {
    "mindie_sim.cli": frozenset({"mindie_sim"}),
}
_STANDARD_PREFIXES: tuple[list[str], ...] = (
    [],
    ["-I"],
    ["-I", "-X", "utf8"],
    ["-I", "-B", "-X", "utf8"],
)


def command_argv(command: Any) -> list[str]:
    """Normalize a `component_commands` value (`list`, `{"argv": [...]}`, or `str`)."""
    if isinstance(command, str):
        return [command] if command.strip() else []
    if isinstance(command, (list, tuple)):
        return [str(item) for item in command]
    if isinstance(command, Mapping):
        raw = command.get("argv") or command.get("command")
        if isinstance(raw, (list, tuple)):
            return [str(item) for item in raw]
        if isinstance(raw, str) and raw.strip():
            return [raw]
    return []


def is_standard_module_command(argv: Any, module: str) -> bool:
    """Return True only for a substrate-standard `... -m <module>` launch argv."""
    items = [str(item) for item in argv] if isinstance(argv, (list, tuple)) else []
    accepted = {str(module)} | set(_LEGACY_MODULE_ALIASES.get(str(module), ()))
    return (
        len(items) >= 3
        and items[-2] == "-m"
        and items[-1] in accepted
        and items[1:-2] in _STANDARD_PREFIXES
    )


def resolve_component_command(cfg: Mapping[str, Any] | None, python: str, component: str) -> list[str]:
    """Return the configured wrapper argv or the canonical `-m <module>` fallback."""
    module = COMPONENT_MODULES.get(component)
    commands = cfg.get("component_commands") if isinstance(cfg, Mapping) else None
    raw = commands.get(component) if isinstance(commands, Mapping) else None
    argv = command_argv(raw)
    if argv and all(item.strip() for item in argv):
        if module is not None and is_standard_module_command(argv, module) and argv[-1] != module:
            return [*argv[:-1], module]
        return argv
    if module is None:
        raise ValueError(f"unknown MindIE component {component!r}")
    return [str(python), "-I", "-X", "utf8", "-m", module]


def rebind_component_commands(cfg: dict[str, Any], python_path: str) -> None:
    """Rebind standard module launches to `python_path`, preserving custom wrappers."""
    commands = cfg.get("component_commands")
    if not isinstance(commands, Mapping):
        return
    rebound = dict(commands)
    for key, (_package, module) in STANDARD_COMPONENT_COMMANDS.items():
        argv = command_argv(rebound.get(key))
        if argv and is_standard_module_command(argv, module):
            rebound[key] = [str(python_path), "-I", "-X", "utf8", "-m", module]
    cfg["component_commands"] = rebound


__all__ = [
    "COMPONENT_MODULES",
    "STANDARD_COMPONENT_COMMANDS",
    "command_argv",
    "is_standard_module_command",
    "rebind_component_commands",
    "resolve_component_command",
]
