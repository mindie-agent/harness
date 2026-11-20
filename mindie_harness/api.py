"""Stable `API_VERSION = 1` public facade and `mindie-harness` CLI for all 7 host plugins.

[Role]
Exposes the single authoritative public contract (`API_VERSION = 1`) consumed by
`mindie-agent-{codex,cc,kimi,dsh,agy,wb,oc}`: `HostAdapter`, `DefaultHostAdapter`,
`ProfileRef`, `Deadline`, `ProcessSpec`, `ProcessOutcome`, `RuntimeSelection`,
`PreparedGeneration`, `ActivationResult`, `run_owned`, `prepare_runtime`,
`activate_runtime`, `maintain_runtime`, `serve_mcp`, `ensure_knowledge_binding`,
`run_stop_capture`, `run_selftest`, and `run_host`.

[Invariants]
- 100% pure Python stdlib at top-level import (`< 15ms` cold import, zero device
  context, zero `mindie_knowledge` / `mindie_diagnostics` / `torch` imports).
- CLI subcommands (`inspect`, `prepare`, `activate`, `maintain`, `hook`, `run`,
  `mcp`, `doctor`, `sharing`, `update`, `install`, `selftest`) accept `--host`,
  `--plugin-root`, `--config`, and `--data-dir` before OR after the subcommand name.
- `mindie-harness mcp <surface>` defaults to `ManagedMCPAdapter` (pass `--unmanaged`
  only for minimal two-tool `DefaultHostAdapter` testing), and background
  `pending-update-check.json` maintenance delegates to `update_runtime(..., background=True)`.

[Timeouts & Locks]
- Delegates process supervision, candidate builds, atomic switches, GC, and MCP
  routing to their respective bounded subsystem modules.

[Side-Effect Policy]
- `inspect`, `doctor`, and `--version` are strictly read-only; mutating subcommands
  act only within the resolved `ProfileRef`.
"""
from __future__ import annotations

import argparse
from collections.abc import Callable, Mapping, Sequence
import json
import os
from pathlib import Path
import sys
from typing import Any, BinaryIO, Final, Protocol, runtime_checkable

from .atomic import read_json_safe
from .locks import LockTimeoutError
from .mcp.doctor import DOCTOR_TOOL_NAME, doctor_tool_definition, run_doctor_tool
from .mcp.router import MCPRouter, RequestContext
from .mcp.server import MCPStdioServer
from .paths import (
    HOSTS,
    HarnessError,
    ProfileRef,
    is_wsl_drvfs,
    open_database,
    open_wal_database,
    resolve_host_python,
    venv_dir_name,
)
from .process.posix import which_posix_binary
from .process.supervisor import (
    Deadline,
    OutputLimitError,
    ProcessCancelledError,
    ProcessExecutionError,
    ProcessOutcome,
    ProcessSpec,
    run_owned,
)
from .runtime.activation import (
    ActivationResult,
    activate_generation,
    maintain_generations,
    read_pending_update_check,
    write_pending_update_check,
)
from .runtime.builder import PreparedGeneration, prepare_candidate_runtime
from .runtime.registry import SHARED_COMPONENTS, RuntimeSelection

__version__: Final[str] = "0.1.6"
API_VERSION: Final[int] = 1


@runtime_checkable
class HostAdapter(Protocol):
    """Protocol implemented by each of the 7 thin host plugins (`codex..oc`)."""

    host: str

    def resolve_profile(self, config_path: str | Path | None = None) -> ProfileRef:
        """Resolve the host's canonical + legacy-compatible `ProfileRef`."""

    def extract_session_identity(
        self,
        request: Mapping[str, Any],
        env: Mapping[str, str],
    ) -> str | None:
        """Extract verified native session ID from an MCP request/env, if present."""

    def mcp_tools(self, surface: str, profile: ProfileRef) -> list[dict[str, Any]]:
        """Return MCP tool definitions for `surface` (`remote | tools | components | knowledge | all`)."""

    def dispatch_tool(
        self,
        ctx: RequestContext,
        arguments: dict[str, Any],
        profile: ProfileRef,
    ) -> dict[str, Any]:
        """Execute a validated MCP tool call within `ctx`."""


class DefaultHostAdapter:
    """Zero-boilerplate `HostAdapter` for CLI usage and standard plugin delegation."""

    def __init__(
        self,
        host: str = "codex",
        *,
        plugin_root: str | Path | None = None,
        config_path: str | Path | None = None,
        data_dir: str | Path | None = None,
        tools: Sequence[dict[str, Any]] = (),
        tool_dispatcher: Callable[[RequestContext, dict[str, Any], ProfileRef], dict[str, Any]] | None = None,
    ) -> None:
        self.host = host
        self._plugin_root = plugin_root
        self._config_path = config_path
        self._data_dir = data_dir
        self._tools = list(tools)
        self._dispatcher = tool_dispatcher

    def resolve_profile(self, config_path: str | Path | None = None) -> ProfileRef:
        return ProfileRef.resolve(
            self.host,
            plugin_root=self._plugin_root,
            config_path=config_path or self._config_path,
            data_dir=self._data_dir,
        )

    def extract_session_identity(
        self,
        request: Mapping[str, Any],
        env: Mapping[str, str],
    ) -> str | None:
        params = request.get("params")
        meta = params.get("_meta") if isinstance(params, Mapping) else None
        if isinstance(meta, Mapping):
            for key in ("session_id", "sessionId", "threadId", "conversationId", "claudecode/sessionId"):
                val = meta.get(key)
                if isinstance(val, str) and val.strip():
                    return val.strip()
        return env.get("MINDIE_SESSION_ID") or env.get("REMOTE_DEV_SESSION_ID")

    def mcp_tools(self, surface: str, profile: ProfileRef) -> list[dict[str, Any]]:
        if self._tools:
            return list(self._tools)
        return [
            {
                "name": "mindie_status",
                "description": "Inspect active MindIE Harness runtime and profile state.",
                "annotations": {"readOnlyHint": True},
                "inputSchema": {"type": "object", "properties": {}, "required": []},
            },
            doctor_tool_definition(),
        ]

    def dispatch_tool(
        self,
        ctx: RequestContext,
        arguments: dict[str, Any],
        profile: ProfileRef,
    ) -> dict[str, Any]:
        if self._dispatcher is not None:
            return self._dispatcher(ctx, arguments, profile)
        if ctx.tool_name == "mindie_status":
            body = inspect_profile(profile)
            body["session_id"] = ctx.session_id
            return {
                "content": [{"type": "text", "text": json.dumps(body, sort_keys=True)}],
                "isError": False,
            }
        if ctx.tool_name == DOCTOR_TOOL_NAME:
            doctor_args = dict(arguments)
            if "cwd" not in doctor_args and ctx.cwd is not None:
                doctor_args["cwd"] = str(ctx.cwd)
            return run_doctor_tool(
                doctor_args,
                profile=profile,
                deadline=ctx.deadline,
                cancel=ctx.cancel,
                env=ctx.env,
            )
        raise HarnessError(
            f"No tool dispatcher configured for {ctx.tool_name!r}",
            stage="dispatch",
            reason="handler_unavailable",
            reportable=False,
        )

    def run_hook(
        self,
        profile: ProfileRef,
        event: str,
        argv: Sequence[str] = (),
    ) -> Mapping[str, Any] | int:
        """Handle a host lifecycle hook (`session-start`, `user-prompt-submit`, `pre-tool-use`, `stop`)."""
        clean_event = str(event or "").strip().lower()
        if clean_event in {"stop", "session-end"}:
            from .runtime.knowledge_binding import run_stop_capture

            payload: dict[str, Any] = {}
            if argv and argv[0] != "--":
                try:
                    parsed_arg = json.loads(argv[0])
                    if isinstance(parsed_arg, dict):
                        payload = parsed_arg
                except ValueError:
                    pass
            if not payload:
                try:
                    if not sys.stdin.isatty():
                        raw_stdin = sys.stdin.buffer.read(1 * 1024 * 1024)
                        if raw_stdin.strip():
                            parsed_in = json.loads(raw_stdin.decode("utf-8-sig"))
                            if isinstance(parsed_in, dict):
                                payload = parsed_in
                except (OSError, ValueError, UnicodeDecodeError):
                    payload = {}
            return run_stop_capture(profile, payload)
        return {}


def _default_update_builder(profile: ProfileRef, _pending: dict[str, Any]) -> dict[str, Any]:
    from .runtime.wheelhouse import update_runtime

    return update_runtime(profile, background=True)


def prepare_runtime(
    profile: ProfileRef,
    *,
    selection: RuntimeSelection | None = None,
    python: str | Path | None = None,
    deadline: Deadline | float | None = None,
    lock_timeout: float = 0.0,
    builder_fn: Callable[[Path, Path, dict[str, str], Deadline], None] | None = None,
    smoke_imports: Sequence[str] = (),
) -> PreparedGeneration:
    """Build or reuse a validated candidate runtime generation (`2.5 GiB` disk floor)."""
    return prepare_candidate_runtime(
        profile,
        selection=selection,
        python=python,
        deadline=deadline,
        lock_timeout=lock_timeout,
        builder_fn=builder_fn,
        smoke_imports=smoke_imports,
    )


def activate_runtime(
    profile: ProfileRef,
    prepared: PreparedGeneration,
    *,
    expected_binding: Mapping[str, Any] | None = None,
    on_before_commit: Callable[[ProfileRef, PreparedGeneration, dict[str, Any]], None] | None = None,
    lock_timeout: float = 5.0,
    run_gc: bool = True,
) -> ActivationResult:
    """Atomically commit `<host>.json` to `prepared` LAST and run `Active + Rollback` GC."""
    return activate_generation(
        profile,
        prepared,
        expected_binding=expected_binding,
        on_before_commit=on_before_commit,
        lock_timeout=lock_timeout,
        run_gc=run_gc,
    )


def maintain_runtime(
    profile: ProfileRef,
    *,
    keep_paths: Sequence[str | Path] = (),
    scheduled_tasks: Sequence[str] = (),
    budget_seconds: float = 2.0,
    consume_pending_check: bool = True,
    builder_callback: Callable[[ProfileRef, dict[str, Any]], ActivationResult | dict[str, Any] | None] | None = None,
) -> dict[str, Any]:
    """Run bounded `Active + Rollback (<= 2)` GC and optionally consume `pending-update-check.json`."""
    return maintain_generations(
        profile,
        keep_paths=keep_paths,
        scheduled_tasks=scheduled_tasks,
        budget_seconds=budget_seconds,
        consume_pending_check=consume_pending_check,
        builder_callback=builder_callback,
    )


def serve_mcp(
    surface: str,
    *,
    profile: ProfileRef,
    adapter: HostAdapter | None = None,
    managed: bool = True,
    stdin: BinaryIO | None = None,
    stdout: BinaryIO | None = None,
) -> int:
    """Start the resident concurrent dual-framing stdio MCP server for `surface`."""
    if adapter is None and managed:
        from .mcp.gateway import ManagedMCPAdapter

        eff_adapter: HostAdapter = ManagedMCPAdapter(
            profile.host,
            plugin_root=profile.plugin_root,
            config_path=profile.config_path,
            data_dir=profile.data_dir,
        )
    else:
        eff_adapter = adapter or DefaultHostAdapter(
            profile.host,
            plugin_root=profile.plugin_root,
            config_path=profile.config_path,
            data_dir=profile.data_dir,
        )
    tools = eff_adapter.mcp_tools(surface, profile)
    router = MCPRouter(
        profile,
        surface=surface,
        tools=tools,
        handler=lambda ctx, args: eff_adapter.dispatch_tool(ctx, args, profile),
        session_extractor=eff_adapter.extract_session_identity,
    )
    server = MCPStdioServer(
        router,
        server_name=f"mindie-{surface}",
        server_version=__version__,
        maintenance_callback=lambda: maintain_generations(
            profile,
            budget_seconds=60.0,
            builder_callback=_default_update_builder,
        ),
    )
    return server.serve(stdin=stdin, stdout=stdout)


def inspect_profile(profile: ProfileRef) -> dict[str, Any]:
    """Read-only diagnostic snapshot of `profile` without creating directories or DBs."""
    active_cfg = read_json_safe(profile.config_path)
    try:
        host_py = str(resolve_host_python())
    except HarnessError:
        host_py = None
    uv_bin = str(which_posix_binary("uv")) if os.name != "nt" else None
    return {
        "api_version": API_VERSION,
        "version": __version__,
        "host": profile.host,
        "plugin_root": str(profile.plugin_root),
        "config_path": str(profile.config_path),
        "consent_path": str(profile.consent_path),
        "state_dir": str(profile.state_dir),
        "generations_dir": str(profile.generations_dir),
        "venv_dir_name": venv_dir_name(),
        "drvfs_state_root": is_wsl_drvfs(profile.state_dir),
        "active_config": active_cfg if isinstance(active_cfg, dict) else None,
        "pending_update": read_pending_update_check(profile),
        "host_python": host_py,
        "posix_uv": uv_bin,
        "shared_components": dict(SHARED_COMPONENTS),
    }


def _add_profile_flags(p: argparse.ArgumentParser, *, subparser: bool = False) -> None:
    if subparser:
        p.add_argument("--host", choices=HOSTS, default=argparse.SUPPRESS)
        p.add_argument("--plugin-root", default=argparse.SUPPRESS)
        p.add_argument("--config", default=argparse.SUPPRESS)
        p.add_argument("--data-dir", default=argparse.SUPPRESS)
    else:
        p.add_argument("--host", choices=HOSTS, default=None)
        p.add_argument("--plugin-root", default=None)
        p.add_argument("--config", default=None)
        p.add_argument("--data-dir", default=None)


def _build_cli_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="mindie-harness")
    parser.add_argument("--version", action="store_true", help="Print mindie-harness version and exit.")
    _add_profile_flags(parser, subparser=False)
    sub = parser.add_subparsers(dest="subcommand")

    p_inspect = sub.add_parser("inspect", help="Read-only profile and runtime health inspection.")
    _add_profile_flags(p_inspect, subparser=True)

    p_prep = sub.add_parser("prepare", help="Prepare and validate a candidate runtime generation.")
    _add_profile_flags(p_prep, subparser=True)
    p_prep.add_argument("--python", help="Explicit base Python interpreter.")
    p_prep.add_argument("--plugin-version")
    p_prep.add_argument("--timeout", type=float, default=300.0)

    p_act = sub.add_parser("activate", help="Atomically activate a prepared runtime generation.")
    _add_profile_flags(p_act, subparser=True)
    p_act.add_argument("--generation-dir", required=True, type=Path)
    p_act.add_argument("--no-gc", action="store_true")

    p_maint = sub.add_parser("maintain", help="Run Active+Rollback GC or enqueue pending update check.")
    _add_profile_flags(p_maint, subparser=True)
    p_maint.add_argument("--enqueue-check", action="store_true", help="Write <5ms pending-update-check.json marker and exit.")
    p_maint.add_argument("--reason", default="cli_maintain")
    p_maint.add_argument("--budget", type=float, default=60.0)

    p_hook = sub.add_parser("hook", help="Execute a bounded host lifecycle hook.")
    _add_profile_flags(p_hook, subparser=True)
    p_hook.add_argument("event", help="Hook event name (e.g., session-start, user-prompt-submit, pre-tool-use, stop).")
    p_hook.add_argument("hook_args", nargs=argparse.REMAINDER)

    p_run = sub.add_parser("run", help="Execute an owned bounded child command.")
    _add_profile_flags(p_run, subparser=True)
    p_run.add_argument("--timeout", type=float, default=60.0)
    p_run.add_argument("--role", choices=("foreground", "background_maintenance", "gui_worker", "mcp_server"), default="foreground")
    p_run.add_argument("--passthrough", action="store_true", help="Forward child stdout/stderr and exit code directly.")
    p_run.add_argument("cmd", nargs=argparse.REMAINDER)

    p_mcp = sub.add_parser("mcp", help="Serve resident concurrent stdio MCP gateway.")
    _add_profile_flags(p_mcp, subparser=True)
    p_mcp.add_argument("surface", nargs="?", default="all", choices=("remote", "tools", "components", "knowledge", "all"))
    p_mcp.add_argument(
        "--managed",
        nargs="?",
        const=True,
        default=True,
        choices=("remote", "tools", "components", "knowledge", "all"),
        help="Use ManagedMCPAdapter (default; optional surface override).",
    )
    p_mcp.add_argument(
        "--unmanaged",
        action="store_true",
        help="Serve minimal DefaultHostAdapter instead of ManagedMCPAdapter.",
    )

    p_doctor = sub.add_parser("doctor", help="Run the read-only MindIE diagnostics doctor.")
    _add_profile_flags(p_doctor, subparser=True)
    p_doctor.add_argument("--probe-remote", action="store_true")
    p_doctor.add_argument("--cwd", default=None)
    p_doctor.add_argument("--timeout", type=float, default=None)

    p_sharing = sub.add_parser("sharing", help="Configure or inspect local/community sharing consent.")
    _add_profile_flags(p_sharing, subparser=True)
    p_sharing.add_argument("--status", action="store_true")
    p_sharing.add_argument("--probe-gh", action="store_true", help="Opt in to live `gh auth status` check during --status.")
    p_sharing.add_argument("--enable", action="store_true", help="Select the contribute tier.")
    p_sharing.add_argument("--local-only", action="store_true", help="Capture local transcripts without reporting.")
    p_sharing.add_argument("--disable", action="store_true")
    p_sharing.add_argument("--project-root", action="append", default=[])
    p_sharing.add_argument("--repository")
    p_sharing.add_argument("--fork")
    p_sharing.add_argument("--account")

    p_update = sub.add_parser("update", help="Provision the zero-Git prebuilt runtime wheelhouse.")
    _add_profile_flags(p_update, subparser=True)
    p_update.add_argument("--force", action="store_true")
    p_update.add_argument("--offline", action="store_true")
    p_update.add_argument("--channel-base-url")
    p_update.add_argument("--background", action="store_true")

    p_selftest = sub.add_parser("selftest", help="Run Gate Layer 1 substrate or fullstack contract selftest.")
    _add_profile_flags(p_selftest, subparser=True)
    p_selftest.add_argument("--mode", choices=("candidate", "full"), default="candidate")
    p_selftest.add_argument("--python", default=None, help="Explicit Python interpreter to test.")
    p_selftest.add_argument("--timeout", type=float, default=None)
    p_selftest.add_argument("--json", action="store_true")

    p_install = sub.add_parser("install", help="Detect native hosts and provision the shared runtime.")
    p_install.add_argument("--host", choices=("auto", *HOSTS), default=argparse.SUPPRESS)
    p_install.add_argument("--plugin-root", default=argparse.SUPPRESS)
    p_install.add_argument("--config", default=argparse.SUPPRESS)
    p_install.add_argument("--data-dir", default=argparse.SUPPRESS)
    p_install.add_argument("--channel-base-url")
    p_install.add_argument("--offline", action="store_true")
    p_install.add_argument("--skip-runtime", action="store_true")

    return parser


def _emit_json(data: Mapping[str, Any]) -> None:
    sys.stdout.buffer.write((json.dumps(data, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8"))
    sys.stdout.buffer.flush()


def run_host(
    argv: Sequence[str] | None = None,
    *,
    adapter: HostAdapter | None = None,
) -> int:
    """CLI and thin-plugin host dispatcher (`mindie-harness` / `python -m mindie_harness.cli`)."""
    parser = _build_cli_parser()
    raw_args = list(sys.argv[1:] if argv is None else argv)
    args = parser.parse_args(raw_args)

    if args.version:
        sys.stdout.write(f"mindie-harness {__version__}\n")
        sys.stdout.flush()
        return 0

    if not args.subcommand:
        parser.print_help(sys.stderr)
        return 2

    if args.subcommand == "install":
        try:
            from .installer import run_install

            install_env = dict(os.environ)
            install_config = args.__dict__.get("config")
            install_data_dir = args.__dict__.get("data_dir")
            if install_config:
                install_env["MINDIE_AGENT_CONFIG"] = str(install_config)
            if install_data_dir:
                install_env["MINDIE_DATA_HOME"] = str(install_data_dir)
            install_res = run_install(
                host=args.__dict__.get("host") or "auto",
                plugin_root=args.__dict__.get("plugin_root"),
                channel_base_url=args.channel_base_url,
                offline=args.offline,
                env=install_env,
                skip_runtime=args.skip_runtime,
            )
            _emit_json(install_res)
            return 0 if install_res.get("status") != "error" else 1
        except HarnessError as exc:
            _emit_json({"status": "error", **exc.to_dict()})
            return 1
        except TimeoutError as exc:
            _emit_json({"status": "error", "stage": "timeout", "reason": "deadline_exceeded", "message": str(exc)})
            return 1

    eff_host = args.host or (adapter.host if adapter is not None else "codex")
    try:
        if adapter is not None and not args.plugin_root and not args.data_dir:
            profile = adapter.resolve_profile(args.config)
        else:
            profile = ProfileRef.resolve(
                eff_host,
                plugin_root=args.plugin_root,
                config_path=args.config,
                data_dir=args.data_dir,
            )

        if args.subcommand == "inspect":
            _emit_json(inspect_profile(profile))
            return 0

        if args.subcommand == "prepare":
            sel = RuntimeSelection.from_pins({}, plugin_version=args.plugin_version)
            prep = prepare_runtime(profile, selection=sel, python=args.python, deadline=args.timeout)
            _emit_json(prep.to_dict())
            return 0

        if args.subcommand == "activate":
            gen_dir = args.generation_dir.resolve()
            receipt = read_json_safe(gen_dir / "runtime.json")
            if not isinstance(receipt, dict) or not receipt.get("python"):
                raise HarnessError(f"Missing validated runtime.json in {gen_dir}", stage="activate", reason="candidate_not_validated")
            prep = PreparedGeneration(
                status="validated",
                generation_key=str(receipt.get("key") or gen_dir.name),
                generation_dir=gen_dir,
                python_path=Path(str(receipt["python"])),
                receipt_path=gen_dir / "runtime.json",
                components=dict(receipt.get("components") or {}),
            )
            act = activate_runtime(profile, prep, run_gc=not args.no_gc)
            _emit_json(act.to_dict())
            return 0

        if args.subcommand == "maintain":
            if args.enqueue_check:
                marker = write_pending_update_check(profile, reason=args.reason)
                _emit_json({"status": "enqueued", "path": str(marker)})
                return 0
            summary = maintain_runtime(
                profile,
                budget_seconds=args.budget,
                builder_callback=_default_update_builder,
            )
            _emit_json({"status": "ok", **summary})
            return 0

        if args.subcommand == "hook":
            if args.event == "session-start":
                try:
                    write_pending_update_check(profile, reason="session_start")
                except TimeoutError:
                    raise
                except OSError:
                    pass
            eff_hook_adapter = adapter or DefaultHostAdapter(
                profile.host,
                plugin_root=profile.plugin_root,
                config_path=profile.config_path,
                data_dir=profile.data_dir,
            )
            if hasattr(eff_hook_adapter, "run_hook"):
                hook_res = eff_hook_adapter.run_hook(profile, args.event, tuple(args.hook_args))
                if isinstance(hook_res, int):
                    return hook_res
                if isinstance(hook_res, Mapping):
                    _emit_json(hook_res)
                    return 0
            _emit_json({})
            return 0

        if args.subcommand == "run":
            cmd = list(args.cmd)
            if cmd and cmd[0] == "--":
                cmd = cmd[1:]
            if not cmd:
                raise HarnessError("`mindie-harness run` requires a command after `--`", stage="cli_input", reason="argv_invalid", reportable=False)
            spec = ProcessSpec(
                argv=tuple(cmd),
                role=args.role,
                allowed_returncodes=None,
            )
            outcome = run_owned(spec, deadline=args.timeout)
            if args.passthrough:
                if outcome.stdout:
                    sys.stdout.buffer.write(outcome.stdout.encode("utf-8"))
                    sys.stdout.flush()
                if outcome.stderr:
                    sys.stderr.buffer.write(outcome.stderr.encode("utf-8"))
                    sys.stderr.flush()
                return int(outcome.returncode or 0)
            _emit_json(
                {
                    "execution": outcome.execution,
                    "returncode": outcome.returncode,
                    "stdout": outcome.stdout,
                    "stderr": outcome.stderr,
                    "elapsed_ms": outcome.elapsed_ms,
                    "job_metadata": outcome.job_metadata,
                }
            )
            return 0 if outcome.returncode == 0 else int(outcome.returncode or 1)

        if args.subcommand == "doctor":
            if args.timeout is not None and args.timeout <= 0:
                raise HarnessError("doctor --timeout must be positive", stage="cli_input", reason="invalid_timeout_budget", reportable=False)
            doctor_args: dict[str, Any] = {"probe_remote": bool(args.probe_remote)}
            if args.cwd:
                doctor_args["cwd"] = args.cwd
            doctor_deadline = (
                Deadline.from_timeout(args.timeout, cleanup_grace=5.0)
                if args.timeout is not None
                else Deadline.from_timeout(20.0 if args.probe_remote else 15.0, cleanup_grace=5.0)
            )
            doc_res = run_doctor_tool(doctor_args, profile=profile, deadline=doctor_deadline)
            _emit_json(doc_res)
            return 1 if doc_res.get("isError") is True else 0

        if args.subcommand == "sharing":
            from .sharing import configure_sharing, sharing_status

            if args.status or not (args.enable or args.local_only or args.disable):
                _emit_json(sharing_status(profile, cwd=Path.cwd(), probe_gh=bool(args.probe_gh)))
                return 0
            selected = "contribute" if args.enable else ("local-only" if args.local_only else "disabled")
            _emit_json(
                configure_sharing(
                    profile,
                    choice=selected,
                    project_roots=args.project_root,
                    repository=args.repository,
                    fork=args.fork,
                    account=args.account,
                )
            )
            return 0

        if args.subcommand == "update":
            from .runtime.wheelhouse import update_runtime

            _emit_json(
                update_runtime(
                    profile,
                    force=args.force,
                    offline=args.offline,
                    channel_base_url=args.channel_base_url,
                    background=args.background,
                )
            )
            return 0

        if args.subcommand == "selftest":
            from .selftest import run_selftest

            selftest_res = run_selftest(
                args.mode,
                profile=profile,
                venv_python=args.python,
                timeout_sec=args.timeout,
            )
            _emit_json(selftest_res)
            return 0 if selftest_res.get("status") == "passed" else 1

        if args.subcommand == "mcp":
            managed_surface = args.managed
            if isinstance(managed_surface, str):
                args.surface = managed_surface
            use_managed = (not bool(args.unmanaged)) and bool(managed_surface)
            return serve_mcp(args.surface, profile=profile, adapter=adapter, managed=use_managed)

        return 2
    except HarnessError as exc:
        _emit_json({"status": "error", **exc.to_dict()})
        return 1
    except TimeoutError as exc:
        _emit_json({"status": "error", "stage": "timeout", "reason": "deadline_exceeded", "message": str(exc)})
        return 1


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
    "ensure_knowledge_binding",
    "inspect_profile",
    "maintain_runtime",
    "open_database",
    "open_wal_database",
    "prepare_runtime",
    "run_host",
    "run_owned",
    "run_selftest",
    "run_stop_capture",
    "serve_mcp",
    "sharing_status",
    "update_runtime",
]


def __getattr__(name: str):
    """Lazily expose optional management symbols without slowing cold import."""
    if name == "ManagedMCPAdapter":
        from .mcp.gateway import ManagedMCPAdapter

        return ManagedMCPAdapter
    if name in {"configure_sharing", "sharing_status"}:
        from .sharing import configure_sharing, sharing_status

        return {"configure_sharing": configure_sharing, "sharing_status": sharing_status}[name]
    if name == "update_runtime":
        from .runtime.wheelhouse import update_runtime

        return update_runtime
    if name in {"ensure_knowledge_binding", "run_stop_capture"}:
        from .runtime.knowledge_binding import ensure_knowledge_binding, run_stop_capture

        return {
            "ensure_knowledge_binding": ensure_knowledge_binding,
            "run_stop_capture": run_stop_capture,
        }[name]
    if name == "run_selftest":
        from .selftest import run_selftest

        return run_selftest
    raise AttributeError(name)


if __name__ == "__main__":
    raise SystemExit(run_host())
