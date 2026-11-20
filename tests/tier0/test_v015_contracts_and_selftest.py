"""Orthogonal contract tests for `mindie-harness v0.1.5` fixes and Gate Layer 1 `selftest`.

[Role]
Verifies systemic v0.1.5 contract closures: schema-declared `remote_*` `session_id`
handling, zero-`claim_bind` read lane, multi-session `remote` stdin child isolation,
`knowledge_schemas` / `knowledge_rpc` framed child IPC & sync failure honesty, SemVer
monotonicity, `stdin_json`/`stdin_text` piping, `sharing` revision preservation,
`noop_transcript_adapter`, Windows `pythonw.exe` PE repair, and `run_selftest`.

[Invariants]
- Strictly isolated inside `tmp_path`; zero host config or real user state touched.

[Timeouts & Locks]
- Bounded Tier 0 / fast Tier 1 checks (`< 10s` total).

[Side-Effect Policy]
- Writes only inside `tmp_path` sandboxes.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import sys
import threading
from types import ModuleType

import pytest

from mindie_harness.atomic import atomic_write_json, atomic_write_text
from mindie_harness.mcp import gateway_dispatch, noop_transcript_adapter
from mindie_harness.mcp.gateway import ManagedMCPAdapter, rebind_native_plugin_if_needed
from mindie_harness.mcp.knowledge_rpc import invoke_knowledge_tool
from mindie_harness.mcp.knowledge_schemas import KNOWLEDGE_TOOL_SCHEMAS
from mindie_harness.mcp.router import (
    MCPRouter,
    RequestContext,
    compute_tool_deadline,
    is_readonly_tool_call,
)
from mindie_harness.paths import HarnessError, ProfileRef, open_wal_database
from mindie_harness.process.supervisor import Deadline, OutputLimitError, ProcessOutcome
from mindie_harness.process.win32 import (
    read_pe_subsystem,
    repair_venv_pythonw_if_needed,
    verify_gui_subsystem,
)
from mindie_harness.rsi import rsi_explore
from mindie_harness.runtime.knowledge_binding import (
    deterministic_redactor_path,
    ensure_knowledge_binding,
    run_stop_capture,
)
from mindie_harness.selftest import run_selftest
from mindie_harness.sharing import configure_sharing, sharing_status


def _profile(tmp_path: Path, host: str = "codex") -> ProfileRef:
    return ProfileRef.resolve(
        host,
        plugin_root=tmp_path / "plugin",
        config_path=tmp_path / "cfg" / f"{host}.json",
        data_dir=tmp_path / "data",
    )


def test_router_allows_schema_declared_remote_session_id_and_classifies_lanes(tmp_path: Path) -> None:
    profile = _profile(tmp_path)
    tools = [
        {
            "name": "remote_write_stdin",
            "inputSchema": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "session_id": {"type": "integer"},
                    "chars": {"type": "string"},
                    "eof": {"type": "boolean"},
                },
                "required": ["session_id"],
            },
        },
        {
            "name": "coordinator",
            "inputSchema": {
                "type": "object",
                "additionalProperties": False,
                "properties": {"argv": {"type": "array", "items": {"type": "string"}}},
                "required": [],
            },
        },
        *KNOWLEDGE_TOOL_SCHEMAS,
    ]
    router = MCPRouter(
        profile,
        surface="all",
        tools=tools,
        handler=lambda _ctx, args: {"content": [{"type": "text", "text": "ok"}], "isError": False, "structuredContent": args},
    )

    ok_poll = router.call_tool({"id": "ws-1", "params": {"name": "remote_write_stdin", "arguments": {"session_id": 42, "chars": ""}}})
    assert ok_poll["isError"] is False and ok_poll["structuredContent"]["session_id"] == 42
    assert not profile.receipts_db.exists(), "Empty-chars remote_write_stdin poll must stay on lock-free read lane"

    bad_type = router.call_tool({"id": "ws-bad", "params": {"name": "remote_write_stdin", "arguments": {"session_id": "not-an-int"}}})
    assert bad_type["isError"] is True and bad_type["structuredContent"]["reason"] == "invalid_argument_type"

    still_forged = router.call_tool({"id": "ws-forged", "params": {"name": "remote_write_stdin", "arguments": {"session_id": 42, "token": "evil"}}})
    assert still_forged["isError"] is True and still_forged["structuredContent"]["reason"] == "forged_identity_argument"

    non_remote = router.call_tool({"id": "coord-forged", "params": {"name": "coordinator", "arguments": {"session_id": "evil"}}})
    assert non_remote["isError"] is True and non_remote["structuredContent"]["reason"] == "forged_identity_argument"

    # Batch `refs` without `ref` and `continuation` without `query` pass schema validation!
    ke = router.call_tool({"id": "ke-batch", "params": {"name": "knowledge_explain", "arguments": {"refs": ["unit-a@1"]}}})
    kq = router.call_tool({"id": "kq-cont", "params": {"name": "knowledge_query", "arguments": {"continuation": "page-2"}}})
    assert ke["isError"] is False and kq["isError"] is False

    # Action-multiplexed lane classification
    assert is_readonly_tool_call("remote_job_stop", {"job_id": "j1"}) is True
    assert is_readonly_tool_call("remote_job_kill", {"job_id": "j1"}) is True
    assert is_readonly_tool_call("remote_job_status", {"job_id": "j1"}) is True
    assert is_readonly_tool_call("remote_job_status", {"job_id": "j1", "action": "send_input"}) is False
    assert is_readonly_tool_call("remote_write_stdin", {"session_id": 1, "chars": ""}) is True
    assert is_readonly_tool_call("remote_write_stdin", {"session_id": 1, "chars": "ls\n"}) is False
    assert is_readonly_tool_call("npu_top", {}) is True
    assert is_readonly_tool_call("npu_top", {"argv": ["inventory", "sync"]}) is False
    assert is_readonly_tool_call("debugger", {"argv": ["triage"]}) is True
    assert is_readonly_tool_call("debugger", {"argv": ["replay"]}) is False


def test_deadlines_rsi_strict_bool_and_unknown_receipt_outcomes(tmp_path: Path) -> None:
    dl_sync = compute_tool_deadline("knowledge", "knowledge_sync", {})
    assert dl_sync.cleanup_grace == 60.0 and dl_sync.remaining() > 495.0
    dl_kimi = compute_tool_deadline("remote", "remote_Bash", {"timeout": 250})
    assert dl_kimi.remaining() > 295.0
    dl_dsh = compute_tool_deadline("remote", "remote_bash", {"timeoutMs": 240_000})
    assert dl_dsh.remaining() > 285.0

    with pytest.raises(ValueError, match="native_subcontext must be a boolean"):
        rsi_explore.parse_args({"native_subcontext": "false"})
    with pytest.raises(ValueError, match="goal must be a string"):
        rsi_explore.parse_args({"goal": 123})

    profile = _profile(tmp_path)
    mode = {"kind": "sent_err"}

    def _handler(_ctx: RequestContext, _args: dict) -> dict:
        if mode["kind"] == "out_limit":
            raise OutputLimitError(1024, ProcessOutcome(execution="unknown", returncode=None))
        return {
            "content": [{"type": "text", "text": "err"}],
            "isError": True,
            "structuredContent": {"submission_state": "sent", "reason": "rpc_err"},
        }

    router = MCPRouter(
        profile,
        surface="knowledge",
        tools=KNOWLEDGE_TOOL_SCHEMAS,
        handler=_handler,
    )
    r1 = router.call_tool({"id": "m-sent", "params": {"name": "knowledge_feedback", "arguments": {"ref": "r1", "rating": "up"}}})
    assert r1["isError"] is True
    mode["kind"] = "out_limit"
    r2 = router.call_tool({"id": "m-out", "params": {"name": "knowledge_feedback", "arguments": {"ref": "r1", "rating": "up"}}})
    assert r2["isError"] is True and r2["structuredContent"]["submission_state"] == "uncertain"

    conn = open_wal_database(profile.receipts_db, create=False)
    assert conn is not None
    try:
        rows = [row[0] for row in conn.execute("SELECT status FROM receipts_v2").fetchall()]
        assert rows == ["unknown", "unknown"]
    finally:
        conn.close()


def test_knowledge_rpc_validation_sync_failure_and_framed_child_ipc(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    profile = _profile(tmp_path)
    # Argument validations before service startup
    assert invoke_knowledge_tool("knowledge_query", {}, profile=profile, session_id="s1")["isError"] is True
    assert invoke_knowledge_tool("knowledge_query", {"query": "a", "continuation": "b"}, profile=profile, session_id="s1")["isError"] is True
    assert invoke_knowledge_tool("knowledge_explain", {"refs": "not-a-list"}, profile=profile, session_id="s1")["isError"] is True
    assert invoke_knowledge_tool("knowledge_feedback", {"ref": "u1"}, profile=profile, session_id="s1")["isError"] is True
    assert invoke_knowledge_tool("knowledge_feedback", {"ref": "u1", "event_type": "evaluated"}, profile=profile, session_id="s1")["isError"] is True

    # Framed stdin child IPC (`MINDIE_KRPC_JSON:`) when `mindie_knowledge` absent in-process
    fake_py = tmp_path / "fake_python.py"
    captured_stdin = tmp_path / "child_stdin.json"
    captured_argv = tmp_path / "child_argv.json"
    helper_runner = tmp_path / "run_fake.py"
    helper_runner.write_text(
        "import json, pathlib, sys\n"
        f"pathlib.Path({str(captured_argv)!r}).write_text(json.dumps(sys.argv), encoding='utf-8')\n"
        "raw = sys.stdin.buffer.read().decode('utf-8')\n"
        f"pathlib.Path({str(captured_stdin)!r}).write_text(raw, encoding='utf-8')\n"
        "print('MINDIE_KRPC_JSON:' + json.dumps({'content': [{'type': 'text', 'text': 'child-ok'}], 'isError': False, 'structuredContent': {'via': 'stdin-frame'}}))\n",
        encoding="utf-8",
    )
    fake_py.write_text("placeholder", encoding="utf-8")
    atomic_write_json(profile.config_path, {"host": "codex", "python": str(fake_py)})

    from mindie_harness.mcp import knowledge_rpc

    def _fake_run_owned(spec, *, deadline, cancel=None):
        assert "secret-query-token" not in " ".join(spec.argv), "Arguments leaked onto child argv!"
        out = subprocess.run(
            [sys.executable, "-I", str(helper_runner), *spec.argv],
            input=spec.stdin_bytes,
            capture_output=True,
            check=True,
        )
        return ProcessOutcome(execution="completed", returncode=0, stdout=out.stdout.decode("utf-8"), stderr="")

    import subprocess

    monkeypatch.setattr(knowledge_rpc, "run_owned", _fake_run_owned)
    res = invoke_knowledge_tool("knowledge_query", {"query": "secret-query-token"}, profile=profile, session_id="sess-ipc")
    assert res["isError"] is False and res["structuredContent"]["via"] == "stdin-frame"
    stdin_doc = json.loads(captured_stdin.read_text(encoding="utf-8"))
    assert stdin_doc["arguments"]["query"] == "secret-query-token"


def test_gateway_semver_monotonicity_component_stdin_and_multisession_remote(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    profile = _profile(tmp_path)
    plugin = tmp_path / "plugin"
    plugin.mkdir(parents=True, exist_ok=True)
    atomic_write_json(plugin / "plugin.json", {"version": "0.1.30"})
    atomic_write_json(
        profile.config_path,
        {"host": "codex", "python": sys.executable, "product_validation": {"native_version": "0.1.40"}},
    )
    # Older plugin.json version must NOT downgrade native_version!
    assert rebind_native_plugin_if_needed(profile) is None

    # Component stdin_json, stdin_text, npu_top default argv, coordinator env + breakaway
    seen_specs: list[object] = []

    def _capture_run(spec, *, deadline, cancel=None):
        seen_specs.append(spec)
        return ProcessOutcome(execution="completed", returncode=0, stdout='{"status":"ok"}', stderr="", elapsed_ms=1)

    monkeypatch.setattr(gateway_dispatch, "run_owned", _capture_run)
    ctx = RequestContext("1", "tools", "npu_top", "s1", tmp_path, dict(os.environ), Deadline.from_timeout(30.0), threading.Event())
    gateway_dispatch.run_component_tool(ctx, "npu_top", {}, profile)
    assert seen_specs[-1].argv[-2:] == ("--json", "servers")

    gateway_dispatch.run_component_tool(ctx, "coordinator", {"argv": ["hosts"]}, profile)
    assert seen_specs[-1].allow_daemon_breakaway is True
    assert seen_specs[-1].env["MINDIE_COORDINATOR_NATIVE_CALL"] == "1"

    gateway_dispatch.run_component_tool(ctx, "debugger", {"argv": ["triage"], "stdin_text": "ERR 507015"}, profile)
    assert seen_specs[-1].stdin_bytes == b"ERR 507015"
    assert seen_specs[-1].memory_limit_bytes is None

    too_big = gateway_dispatch.run_component_tool(ctx, "debugger", {"argv": ["triage"], "stdin_text": "x" * (1024 * 1024 + 5)}, profile)
    assert too_big["isError"] is True and too_big["structuredContent"]["reason"] == "input_too_large"

    # Multi-session remote_dev isolation on the same state_dir
    fake_remote = ModuleType("remote_dev")
    fake_tools = ModuleType("remote_dev.mcp.tools")
    seen_inproc_env: list[str] = []
    fake_tools.call_tool = lambda name, args, profile=None: (
        seen_inproc_env.append(os.environ.get("REMOTE_DEV_SESSION_ID", ""))
        or {"text": "inproc", "result": {"outcome": "success", "who": os.environ.get("REMOTE_DEV_SESSION_ID")}}
    )
    monkeypatch.setitem(sys.modules, "remote_dev", fake_remote)
    monkeypatch.setitem(sys.modules, "remote_dev.mcp", ModuleType("remote_dev.mcp"))
    monkeypatch.setitem(sys.modules, "remote_dev.mcp.tools", fake_tools)

    child_calls: list[dict[str, object]] = []

    def _fake_remote_child(ctx_arg, args_arg, target_py, rprof, sdir):
        child_calls.append({"session": ctx_arg.session_id, "state_dir": sdir, "args": dict(args_arg)})
        return {"content": [{"type": "text", "text": "child"}], "isError": False, "structuredContent": {"outcome": "success", "who": ctx_arg.session_id}}

    monkeypatch.setattr(gateway_dispatch, "_remote_via_python", _fake_remote_child)
    shared_state = str(tmp_path / "shared-remote-state")
    c_a = RequestContext("a", "remote", "remote_auth", "session-A", None, {"REMOTE_DEV_STATE_DIR": shared_state}, Deadline.from_timeout(30.0), threading.Event())
    c_b = RequestContext("b", "remote", "remote_auth", "session-B", None, {"REMOTE_DEV_STATE_DIR": shared_state}, Deadline.from_timeout(30.0), threading.Event())

    res_a = gateway_dispatch.dispatch_remote_tool(c_a, {"action": "status"}, profile)
    res_b = gateway_dispatch.dispatch_remote_tool(c_b, {"action": "status"}, profile)
    assert res_a["structuredContent"]["who"] == "session-A"
    assert res_b["structuredContent"]["who"] == "session-B"
    assert seen_inproc_env == ["session-A"]
    assert len(child_calls) == 1 and child_calls[0]["session"] == "session-B"

    # When remote_dev >= 0.11.15 exposes state_store.session_scope, ALL sessions run concurrently in-process!
    import contextlib

    scoped_calls: list[tuple[str | None, str | None, str | None]] = []
    fake_state_store = ModuleType("remote_dev.core.state_store")

    @contextlib.contextmanager
    def _fake_session_scope(session_id: str | None, *, state_dir: object = None, auth_dir: object = None):
        scoped_calls.append((session_id, str(state_dir), str(auth_dir)))
        yield

    fake_state_store.session_scope = _fake_session_scope
    fake_errors = ModuleType("remote_dev.core.errors")
    fake_errors.error_details = lambda exc: {
        "type": type(exc).__name__,
        "category": "authentication_rejected",
        "authentication": True,
        "stderr_tail": "SECRET_SSH_STDERR",
        "bootstrap": {"status": "failed", "credential_ref": "SECRET_CRED_REF", "key_verified": False},
        "retryable": False,
    }
    fake_errors.safe_auth_error_details = lambda details: {
        "category": "authentication_rejected",
        "hint": "Check SSH password",
        "retryable": False,
        "bootstrap": {"status": "failed", "key_verified": False},
    }
    monkeypatch.setitem(sys.modules, "remote_dev.core", ModuleType("remote_dev.core"))
    monkeypatch.setitem(sys.modules, "remote_dev.core.state_store", fake_state_store)
    monkeypatch.setitem(sys.modules, "remote_dev.core.errors", fake_errors)

    c_c = RequestContext("c", "remote", "remote_auth", "session-C", None, {"REMOTE_DEV_STATE_DIR": shared_state, "REMOTE_DEV_AUTH_DIR": str(tmp_path / "auth")}, Deadline.from_timeout(30.0), threading.Event())
    res_c = gateway_dispatch.dispatch_remote_tool(c_c, {"action": "status"}, profile)
    assert res_c["isError"] is False
    assert scoped_calls == [("session-C", shared_state, str(tmp_path / "auth"))]
    assert len(child_calls) == 1  # Did NOT spawn child IPC when session_scope is available!

    # Auth exception must strip raw stderr_tail & credential_ref via safe_auth_error_details
    fake_tools.call_tool = lambda *_a, **_kw: (_ for _ in ()).throw(RuntimeError("ssh boom"))
    err_env = gateway_dispatch.dispatch_remote_tool(c_c, {"action": "setup"}, profile)
    assert err_env["isError"] is True
    dumped_err = json.dumps(err_env)
    assert "SECRET_SSH_STDERR" not in dumped_err and "SECRET_CRED_REF" not in dumped_err
    assert err_env["structuredContent"]["auth"]["category"] == "authentication_rejected"


def test_sharing_revision_noop_adapter_stop_gate_and_selftest(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MINDIE_CONFIG_HOME", str(tmp_path / "cfg"))
    monkeypatch.setenv("MINDIE_DATA_HOME", str(tmp_path / "data"))
    profile = _profile(tmp_path)
    ws = tmp_path / "ws"
    ws.mkdir()

    r1 = configure_sharing(profile, choice="contribute", project_roots=[ws], repository="mindie-agent/mindie-agent", fork="alice/mindie-agent", account="alice")
    diag1 = json.loads(Path(r1["diagnostics_policy_path"]).read_text(encoding="utf-8"))
    comm1 = json.loads(Path(r1["community_path"]).read_text(encoding="utf-8"))
    assert comm1["fork"] == "alice/mindie-agent" and comm1["account"] == "alice"

    r2 = configure_sharing(profile, choice="contribute", project_roots=[ws], repository="mindie-agent/mindie-agent", fork="alice/mindie-agent", account="alice")
    diag2 = json.loads(Path(r2["diagnostics_policy_path"]).read_text(encoding="utf-8"))
    assert diag2["revision"] == diag1["revision"]

    st = sharing_status(profile, cwd=ws)
    assert st["tier"] == "contribute" and st["gh_account"] == "alice"

    # Corrupt consent file must fail closed without overwriting
    atomic_write_text(profile.consent_path, "{corrupt-json")
    with pytest.raises(HarnessError) as exc_info:
        configure_sharing(profile, choice="local-only", project_roots=[ws])
    assert exc_info.value.reason == "consent_corrupt"
    assert profile.consent_path.read_text(encoding="utf-8") == "{corrupt-json"

    # noop_transcript_adapter contract
    sample = tmp_path / "transcript.jsonl"
    sample.write_text("{}\n", encoding="utf-8")
    assert noop_transcript_adapter.identify(sample) is None
    assert noop_transcript_adapter.same_file(None, None) is False
    mat_text, mat_meta = noop_transcript_adapter.read_material(sample)
    assert mat_text == "" and mat_meta["more"] is False

    # Stop capture fast-exits without creating SQLite when consent is corrupt/disabled or out of scope
    stop_res = run_stop_capture(profile, {"session_id": "s1", "cwd": str(tmp_path / "outside")})
    assert stop_res["stage"] == "inert"
    assert not profile.admission_db.exists()

    # Candidate selftest passes standalone & fails closed when MINDIE_REQUIRE_FULLSTACK=1 and a module is missing
    cand_report = run_selftest("candidate")
    assert cand_report["schema"] == "mindie-selftest/1" and cand_report["status"] == "passed"

    monkeypatch.setenv("MINDIE_REQUIRE_FULLSTACK", "1")
    from mindie_harness import selftest as selftest_mod

    monkeypatch.setattr(selftest_mod, "_has_mod", lambda mod: False if mod == "mindie_sim" else True)
    failed_fs = run_selftest("candidate")
    assert failed_fs["status"] == "failed"

    if os.name == "nt":
        fake_venv = tmp_path / "fake-venv"
        scripts_dir = fake_venv / "Scripts"
        scripts_dir.mkdir(parents=True)
        base_py = Path(sys.base_prefix) / "python.exe"
        if base_py.is_file():
            (fake_venv / "pyvenv.cfg").write_text(f"home = {base_py.parent}\n", encoding="utf-8")
            shutil.copy2(base_py, scripts_dir / "pythonw.exe")
            assert read_pe_subsystem(scripts_dir / "pythonw.exe") == 3
            repaired = repair_venv_pythonw_if_needed(fake_venv, base_py)
            assert repaired is not None
            verify_gui_subsystem(repaired)
            assert read_pe_subsystem(repaired) == 2


def test_knowledge_binding_disabled_capture_mode_and_automatic_upgrade(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Standalone (`noop_transcript_adapter`) or missing `gitleaks` sets `capture_mode == 'disabled'`,
    and automatically upgrades to `'public-transcript'` once both host adapter and redactor exist."""
    import hashlib
    from mindie_harness.runtime import knowledge_binding as kb_mod

    monkeypatch.setenv("MINDIE_CONFIG_HOME", str(tmp_path / "cfg"))
    monkeypatch.setenv("MINDIE_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("PATH", "")

    fake_mk = ModuleType("mindie_knowledge")
    fake_mk.package_version = lambda: "0.13.25"
    fake_loop = ModuleType("mindie_knowledge.loop")
    fake_cat = ModuleType("mindie_knowledge.loop.domain_catalog")
    fake_cli = ModuleType("mindie_knowledge.loop.cli")
    fake_ho = ModuleType("mindie_knowledge.loop.handoff")
    fake_lc = ModuleType("mindie_knowledge.loop.lifecycle")

    fake_cat.SCHEMA = "mindie-domain-catalog/1"
    fake_cat.DOMAIN_CONFIGS = {"vllm-ascend": object(), "operators": object()}

    def _validate(cfg: dict) -> dict:
        assert cfg.get("capture_mode") in {"disabled", "public-transcript"}
        if cfg.get("capture_mode") == "public-transcript":
            assert Path(cfg["transcript_adapter"]).name != "noop_transcript_adapter.py"
            assert Path(cfg["redactor_executable"]).is_absolute()
        return cfg

    fake_cli.validate_config = _validate
    fake_cli.config_at = lambda p: _validate(json.loads(Path(p).read_text(encoding="utf-8")))
    fake_ho.prepare_schema = lambda _p: None
    retired_paths: list[str] = []
    fake_lc.inspect_retirement = lambda p: {"status": "retired"} if Path(f"{p}.retired").is_file() else None

    def _prepare(adapter: dict, engine: dict, *, config_directory: str, **_kw: object) -> dict:
        sec = dict(engine, domain="operators")
        text = json.dumps(sec, sort_keys=True, indent=2) + "\n"
        h = hashlib.sha256(text.encode("utf-8")).hexdigest()[:20]
        sec_path = Path(config_directory) / h / "operators.engine.json"
        atomic_write_text(sec_path, text)
        return {"schema": fake_cat.SCHEMA, "domain_configs": {"vllm-ascend": adapter["engine_config"], "operators": str(sec_path)}}

    def _retire_changed(old_doc: dict, new_doc: dict, **_kw: object) -> dict:
        rows = []
        old_eng = old_doc.get("engine_config")
        if old_eng and old_eng != new_doc.get("engine_config"):
            retired_paths.append(str(old_eng))
            atomic_write_json(Path(f"{old_eng}.retired"), {"status": "retired"})
            rows.append({"domain": "vllm-ascend", "config_path": str(old_eng), "restore_required": True})
        return {"status": "retired", "domains": rows}

    restored_paths: list[str] = []

    def _restore_changed(report: dict, **_kw: object) -> dict:
        for row in report.get("domains", ()):
            cp = row["config_path"]
            restored_paths.append(cp)
            Path(f"{cp}.retired").unlink(missing_ok=True)
        return {"status": "restored", "domains": list(report.get("domains", ()))}

    fake_cat.prepare = _prepare
    fake_cat.retire_changed = _retire_changed
    fake_cat.restore_changed = _restore_changed

    monkeypatch.setitem(sys.modules, "mindie_knowledge", fake_mk)
    monkeypatch.setitem(sys.modules, "mindie_knowledge.loop", fake_loop)
    monkeypatch.setitem(sys.modules, "mindie_knowledge.loop.domain_catalog", fake_cat)
    monkeypatch.setitem(sys.modules, "mindie_knowledge.loop.cli", fake_cli)
    monkeypatch.setitem(sys.modules, "mindie_knowledge.loop.handoff", fake_ho)
    monkeypatch.setitem(sys.modules, "mindie_knowledge.loop.lifecycle", fake_lc)
    monkeypatch.setattr(kb_mod, "has_knowledge_package", lambda _py=None: True)

    profile = _profile(tmp_path)
    redactor = deterministic_redactor_path(profile)

    # Combo 0: standalone (no host transcript_adapter) + gitleaks absent -> disabled
    res_none = ensure_knowledge_binding(profile, python_executable=sys.executable)
    assert res_none["status"] == "configured" and res_none["capture_mode"] == "disabled"

    # Combo 1: gitleaks exists, but standalone (no host transcript_adapter in plugin_root) -> disabled
    atomic_write_text(redactor, "fake-gitleaks-binary")
    res_standalone = ensure_knowledge_binding(profile, python_executable=sys.executable)
    assert res_standalone["status"] == "configured" and res_standalone["capture_mode"] == "disabled"
    eng1 = json.loads(Path(res_standalone["engine_config"]).read_text(encoding="utf-8"))
    sec1 = json.loads(Path(res_standalone["domain_configs"]["operators"]).read_text(encoding="utf-8"))
    assert eng1["capture_mode"] == "disabled" and sec1["capture_mode"] == "disabled"

    # Combo 2: host transcript_adapter exists, but gitleaks missing (install_redactor=False) -> disabled
    redactor.unlink()
    adapter_script = profile.plugin_root / "scripts" / "codex_transcript.py"
    atomic_write_text(adapter_script, "# host transcript adapter\n")
    res_no_red = ensure_knowledge_binding(profile, plugin_root=profile.plugin_root, python_executable=sys.executable)
    assert res_no_red["status"] == "configured" and res_no_red["capture_mode"] == "disabled"

    # Combo 3: both host transcript_adapter AND gitleaks binary present -> upgrades to public-transcript!
    atomic_write_text(redactor, "fake-gitleaks-binary")
    res_ready = ensure_knowledge_binding(
        profile,
        plugin_root=profile.plugin_root,
        python_executable=sys.executable,
        retire_previous=True,
    )
    assert res_ready["status"] == "configured" and res_ready["capture_mode"] == "public-transcript"
    assert res_ready["engine_config"] != res_no_red["engine_config"]
    assert res_no_red["engine_config"] in retired_paths
    eng3 = json.loads(Path(res_ready["engine_config"]).read_text(encoding="utf-8"))
    sec3 = json.loads(Path(res_ready["domain_configs"]["operators"]).read_text(encoding="utf-8"))
    assert eng3["capture_mode"] == "public-transcript" and sec3["capture_mode"] == "public-transcript"

    # RC-1 rollback: if final adapter write raises after retire_changed succeeded, restore_changed unretires previous owner!
    redactor.unlink()  # force a distinct candidate hash
    real_write = kb_mod.atomic_write_json
    monkeypatch.setattr(kb_mod, "atomic_write_json", lambda *_a, **_kw: (_ for _ in ()).throw(OSError("disk full")))
    with pytest.raises(OSError, match="disk full"):
        ensure_knowledge_binding(profile, plugin_root=profile.plugin_root, python_executable=sys.executable, retire_previous=True)
    assert res_ready["engine_config"] in restored_paths
    assert not Path(f"{res_ready['engine_config']}.retired").exists()
    monkeypatch.setattr(kb_mod, "atomic_write_json", real_write)

    # RC-2 Stop fast-exit: zero sqlite3 opens on both sharing-disabled and out-of-scope cwd
    import sqlite3

    sqlite_opens: list[object] = []
    real_connect = sqlite3.connect
    monkeypatch.setattr(sqlite3, "connect", lambda *a, **kw: sqlite_opens.append(a) or real_connect(*a, **kw))
    s_disabled = run_stop_capture(profile, {"session_id": "s-fast", "cwd": str(tmp_path / "ws")})
    assert s_disabled == {"stage": "inert", "reason": "sharing-disabled"} and sqlite_opens == []

    ws_auth = tmp_path / "authorized-ws"
    ws_auth.mkdir()
    configure_sharing(profile, choice="local-only", project_roots=[ws_auth])
    s_out = run_stop_capture(profile, {"session_id": "s-fast", "cwd": str(tmp_path / "outside-ws")})
    assert s_out == {"stage": "inert", "reason": "out-of-scope"} and sqlite_opens == []
