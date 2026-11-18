"""Tier 0 routing tests for `mindie_doctor`, 7-host native read lanes, and native wait deadlines."""
from __future__ import annotations

from pathlib import Path

import pytest

from mindie_harness import Deadline, ProfileRef
from mindie_harness.api import DefaultHostAdapter
from mindie_harness.mcp.router import (
    READONLY_TOOL_PREFIXES,
    REMOTE_NATIVE_MAX_WAIT_MS,
    MCPRouter,
    compute_tool_deadline,
    is_readonly_or_control_tool,
    is_readonly_tool_call,
)

NATIVE_READ_TOOLS = (
    "remote_Read",
    "remote_Glob",
    "remote_Grep",
    "remote_TaskOutput",
    "remote_TaskList",
    "remote_TaskStop",
    "remote_ViewImage",
    "remote_ReadMediaFile",
    "remote_view_image",
    "remote_probe",
    "remote_read_file",
    "remote_find_by_name",
    "remote_grep_search",
    "remote_list_dir",
)

MUTATION_TOOLS = (
    "remote_Write",
    "remote_Edit",
    "remote_write_file",
    "remote_edit_file",
    "remote_run_command",
    "remote_Bash",
    "remote_bash",
    "remote_write_stdin",
    "remote_exec_command",
)


@pytest.mark.tier0
def test_doctor_and_all_seven_host_native_read_tools_use_readonly_lane() -> None:
    assert "mindie_doctor" in READONLY_TOOL_PREFIXES
    assert is_readonly_or_control_tool("mindie_doctor") is True
    assert is_readonly_or_control_tool("mindie_status") is True
    assert is_readonly_or_control_tool("diagnostics_status") is True

    for tool_name in NATIVE_READ_TOOLS:
        assert is_readonly_or_control_tool(tool_name) is True, tool_name
        assert is_readonly_or_control_tool(tool_name, {"annotations": {"readOnlyHint": False}}) is True, tool_name

    for tool_name in MUTATION_TOOLS:
        assert is_readonly_or_control_tool(tool_name) is False, tool_name

    # `remote_auth` and `remote_manage_task` are action-multiplexed, even if a misleading readOnlyHint is passed.
    misleading_ro = {"annotations": {"readOnlyHint": True}}
    assert "remote_auth" not in READONLY_TOOL_PREFIXES
    assert is_readonly_or_control_tool("remote_auth") is False
    assert is_readonly_tool_call("remote_auth", {"action": "status"}) is True
    assert is_readonly_tool_call("remote_auth", {"action": "setup"}, misleading_ro) is False
    assert is_readonly_tool_call("remote_auth", {"action": "forget"}, misleading_ro) is False
    assert is_readonly_tool_call("remote_auth", {}, misleading_ro) is False

    assert "remote_manage_task" not in READONLY_TOOL_PREFIXES
    assert is_readonly_tool_call("remote_manage_task", {"Action": "list"}) is True
    assert is_readonly_tool_call("remote_manage_task", {"Action": "status"}) is True
    assert is_readonly_tool_call("remote_manage_task", {"Action": "kill"}) is True
    assert is_readonly_tool_call("remote_manage_task", {"Action": "send_input"}, misleading_ro) is False
    assert is_readonly_tool_call("remote_manage_task", {}, misleading_ro) is False


@pytest.mark.tier0
def test_router_fast_lane_is_action_aware_for_remote_auth(tmp_path: Path) -> None:
    profile = ProfileRef.resolve(
        "codex",
        plugin_root=tmp_path / "plugin",
        config_path=tmp_path / "cfg" / "codex.json",
        data_dir=tmp_path / "data",
    )
    router = MCPRouter(
        profile,
        surface="remote",
        tools=[{"name": "remote_auth", "inputSchema": {"type": "object", "properties": {"action": {"type": "string"}}}}],
        base_env={},
    )

    def _call(action: str) -> bool:
        return router.is_fast_lane_call(
            {
                "jsonrpc": "2.0",
                "id": f"auth-{action}",
                "method": "tools/call",
                "params": {"name": "remote_auth", "arguments": {"action": action}},
            }
        )

    assert _call("status") is True
    assert _call("setup") is False
    assert _call("forget") is False


@pytest.mark.tier0
def test_doctor_deadline_covers_local_and_probe_budgets(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: list[tuple[float, float]] = []
    real_from_timeout = Deadline.from_timeout

    def _capture(timeout_seconds: float, *, cleanup_grace: float = 0.0, now: float | None = None) -> Deadline:
        captured.append((float(timeout_seconds), float(cleanup_grace)))
        return real_from_timeout(timeout_seconds, cleanup_grace=cleanup_grace, now=now)

    monkeypatch.setattr(Deadline, "from_timeout", staticmethod(_capture))

    def _doctor_deadline(probe_remote: object, explicit: float | None = None) -> tuple[float, float]:
        captured.clear()
        compute_tool_deadline(
            "all",
            "mindie_doctor",
            {"probe_remote": probe_remote},
            explicit_timeout=explicit,
        )
        assert len(captured) == 1
        return captured[0]

    local_outer, local_grace = _doctor_deadline(False)
    assert local_outer == 10.0 + local_grace
    assert local_outer >= 5.0 + local_grace

    probe_outer, probe_grace = _doctor_deadline(True)
    assert probe_outer == 20.0 + probe_grace
    assert probe_outer >= 15.0 + probe_grace
    assert probe_grace == local_grace

    # String `"false"` never enables probe_remote budget inflation.
    assert _doctor_deadline("false")[0] == local_outer

    # An explicit router timeout may extend the deadline, never shrink it.
    assert _doctor_deadline(False, explicit=120.0)[0] == 120.0
    assert _doctor_deadline(True, explicit=1.0)[0] == probe_outer


@pytest.mark.tier0
def test_remote_native_wait_deadlines_read_antigravity_and_claude_keys(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: list[tuple[float, float]] = []
    real_from_timeout = Deadline.from_timeout

    def _capture(timeout_seconds: float, *, cleanup_grace: float = 0.0, now: float | None = None) -> Deadline:
        captured.append((float(timeout_seconds), float(cleanup_grace)))
        return real_from_timeout(timeout_seconds, cleanup_grace=cleanup_grace, now=now)

    monkeypatch.setattr(Deadline, "from_timeout", staticmethod(_capture))

    def _remote(tool_name: str, args: dict[str, object]) -> tuple[float, float]:
        captured.clear()
        compute_tool_deadline("remote", tool_name, args)
        assert len(captured) == 1
        return captured[0]

    # Native tables: `remote_Bash` and `remote_TaskOutput` add the 600s long-poll ceiling.
    assert REMOTE_NATIVE_MAX_WAIT_MS["remote_Bash"] == 600_000
    assert REMOTE_NATIVE_MAX_WAIT_MS["remote_TaskOutput"] == 600_000
    assert _remote("remote_Bash", {}) == (660.0, 60.0)
    assert _remote("remote_TaskOutput", {}) == (660.0, 60.0)

    # Antigravity `remote_run_command` WaitMsBeforeAsync is milliseconds and may extend the native cap.
    assert _remote("remote_run_command", {"WaitMsBeforeAsync": 900_000}) == (960.0, 60.0)
    assert _remote("remote_run_command", {"WaitMsBeforeAsync": 120_000}) == (660.0, 60.0)

    # Claude/WB `remote_Bash.timeout` is also milliseconds and may extend the native cap.
    assert _remote("remote_Bash", {"timeout": 900_000}) == (960.0, 60.0)
    assert _remote("remote_Bash", {"timeout": 120_000}) == (660.0, 60.0)

    # Invalid / false / non-finite / non-positive values never inflate the deadline.
    for invalid in (True, "900000", float("nan"), float("inf"), 0, -1):
        assert _remote("remote_exec_command", {"WaitMsBeforeAsync": invalid, "timeout": invalid}) == (180.0, 60.0), invalid


@pytest.mark.tier0
def test_doctor_call_skips_mutation_receipts_and_cap(tmp_path: Path) -> None:
    profile = ProfileRef.resolve(
        "oc",
        plugin_root=tmp_path / "plugin",
        config_path=tmp_path / "cfg" / "oc.json",
        data_dir=tmp_path / "data",
    )
    seen: list[str] = []

    def _handler(ctx: object, _args: dict[str, object]) -> dict[str, object]:
        seen.append(str(getattr(ctx, "tool_name", "")))
        return {"content": [{"type": "text", "text": "doctor:ok"}], "isError": False}

    router = MCPRouter(profile, surface="all", tools=None, handler=_handler, base_env={})
    result = router.call_tool(
        {
            "jsonrpc": "2.0",
            "id": "doctor-read-lane",
            "method": "tools/call",
            "params": {"name": "mindie_doctor", "arguments": {"probe_remote": False}},
        }
    )
    assert result["isError"] is False
    assert seen == ["mindie_doctor"]
    assert not profile.receipts_db.exists()
    assert not profile.binds_db.exists()


@pytest.mark.tier0
def test_default_adapter_registers_readonly_doctor_tool(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile = ProfileRef.resolve(
        "codex",
        plugin_root=tmp_path / "plugin",
        config_path=tmp_path / "cfg" / "codex.json",
        data_dir=tmp_path / "data",
    )
    tools = DefaultHostAdapter(
        "codex",
        plugin_root=tmp_path / "plugin",
        config_path=tmp_path / "cfg" / "codex.json",
        data_dir=tmp_path / "data",
    ).mcp_tools("components", profile)
    doctor = next(tool for tool in tools if tool["name"] == "mindie_doctor")
    assert doctor["annotations"]["readOnlyHint"] is True
    assert doctor["inputSchema"]["required"] == []
    assert set(doctor["inputSchema"]["properties"]) == {"cwd", "probe_remote"}
    assert doctor["inputSchema"]["properties"]["probe_remote"]["default"] is False

    # Direct helper dispatch stays honest and bounded even when diagnostics is absent.
    from mindie_harness.mcp import doctor as doctor_module

    def _missing_import(_name: str) -> None:
        raise ImportError("simulated older rollback generation without doctor")

    monkeypatch.setattr(doctor_module.importlib, "import_module", _missing_import)
    monkeypatch.setattr(doctor_module, "_doctor_cli_argv", lambda _probe: None)
    result = doctor_module.run_doctor_tool({"probe_remote": False})
    assert isinstance(result, dict)
    assert result["isError"] is True
    assert result["structuredContent"]["reason"] == "doctor_unavailable"
