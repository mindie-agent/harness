"""Tier 0 substrate-extension tests for local-only Stop, wheelhouse, sharing, and gateway.

[Role]
Verifies the v0.1.3 Great Subtraction deliverables with pure local fixtures: the
`local-only` cold Stop gate, zero-Git wheelhouse checksum/extraction/backoff,
sharing tier documents, native plugin rebinding, and managed MCP surfaces.

[Invariants]
- Zero network, zero `uv` builds, zero real-host mutation; every path lives under
  the pytest sandbox and every optional package interaction is tolerated.
- Tests remain deterministic cross-platform (`< 2s` total).

[Timeouts & Locks]
- No test waits on a lock or child process beyond the bounded process helpers.

[Side-Effect Policy]
- Writes only to `tmp_path` sandbox directories created by the fixtures.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import tarfile
import sys
import threading
import time
from pathlib import Path

import pytest

from mindie_harness.atomic import atomic_write_json
from mindie_harness.bootstrap.seed_main import _seed_stop_roots, render_plugin_bootstrap_template
from mindie_harness.component_commands import rebind_component_commands
from mindie_harness.installer import _configured, detect_installed_hosts, run_install
from mindie_harness.mcp.gateway import ManagedMCPAdapter, rebind_native_plugin_if_needed, resolve_remote_profile
from mindie_harness.api import DefaultHostAdapter
from mindie_harness.mcp import gateway_dispatch
from mindie_harness.mcp.gateway_dispatch import COMPONENT_MODULES, dispatch_remote_tool, run_component_tool, run_diagnostics_tool
from mindie_harness.mcp.router import MCPRouter, RequestContext
from mindie_harness.paths import HOSTS, HarnessError, ProfileRef, venv_python_path
from mindie_harness.process.supervisor import Deadline, ProcessOutcome
from mindie_harness.runtime import wheelhouse as wheelhouse_mod
from mindie_harness.runtime import wheelhouse_assets
from mindie_harness.runtime.builder import PreparedGeneration
from mindie_harness.runtime.registry import RuntimeSelection
from mindie_harness.runtime.wheelhouse import (
    BACKOFF_BASE_SECONDS,
    discover_channel,
    extract_wheel_bundle_safely,
    parse_sha256sums,
    stage_wheelhouse,
    update_runtime,
)
from mindie_harness.runtime.wheelhouse_assets import (
    asset_source,
    check_component_version_floors,
    download_verified,
)
from mindie_harness.sharing import configure_sharing, sharing_status


def _profile(tmp_path: Path, host: str = "codex") -> ProfileRef:
    return ProfileRef.resolve(
        host,
        plugin_root=tmp_path / "plugin",
        config_path=tmp_path / "cfg" / f"{host}.json",
        data_dir=tmp_path / "data",
    )


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_local_only_seed_stop_gate_and_template_budget(tmp_path: Path) -> None:
    cfg_dir = tmp_path / "cfg"
    root = tmp_path / "project"
    root.mkdir()
    atomic_write_json(
        cfg_dir / "mindie-consent.json",
        {"schema": "mindie-consent/1", "choice": "local-only", "choice_revision": "a" * 32, "project_roots": [str(root)]},
    )
    atomic_write_json(
        cfg_dir / "mindie-community.json",
        {"schema": "mindie-community-config/1", "enabled": True, "local_only": True, "repository": None, "project_roots": [str(root)], "consent_config": str(cfg_dir / "mindie-consent.json")},
    )
    atomic_write_json(cfg_dir / "codex.json", {"host": "codex"})
    assert _seed_stop_roots(cfg_dir / "codex.json") == [os.path.normcase(str(root.resolve()))]
    for host in HOSTS:
        assert len(render_plugin_bootstrap_template(host).splitlines()) < 115


@pytest.mark.parametrize("marker", ["binary", "host-config", "mindie-config", "session"])
def test_omp_installer_detects_native_host(tmp_path: Path, marker: str) -> None:
    env = {"HOME": str(tmp_path), "PATH": str(tmp_path), "MINDIE_CONFIG_HOME": str(tmp_path / "cfg")}
    assert detect_installed_hosts(env) == []

    if marker == "binary":
        exe = tmp_path / ("omp.exe" if os.name == "nt" else "omp")
        exe.touch()
        exe.chmod(0o755)
    elif marker == "host-config":
        (tmp_path / ".omp").mkdir()
    elif marker == "mindie-config":
        (tmp_path / "cfg").mkdir()
        (tmp_path / "cfg" / "omp.json").touch()
    else:
        env["PI_SESSION_ID"] = "omp-session"
    assert detect_installed_hosts(env) == ["omp"]


def test_omp_installer_alias_and_profile_isolation(tmp_path: Path) -> None:
    cfg = tmp_path / "cfg"
    data = tmp_path / "data"
    env = {"HOME": str(tmp_path), "PATH": str(tmp_path), "MINDIE_CONFIG_HOME": str(cfg), "MINDIE_DATA_HOME": str(data)}
    original = {"host": "codex", "admission_path": str(data / "legacy-admission.sqlite3")}
    atomic_write_json(cfg / "codex.json", original)
    profile = ProfileRef.resolve("omp", env=env)
    assert profile.config_path == cfg / "omp.json"
    assert profile.state_dir == data / "state" / "omp"
    assert profile.generations_dir == data / "runtimes" / "omp"
    assert profile.admission_db == profile.state_dir / "admission.sqlite3"

    result = run_install(host="oh-my-pi", env=env, skip_runtime=True)
    assert result["detected_hosts"] == ["codex"]
    assert result["configured_hosts"] == ["omp"]
    assert result["runtimes"] == {"omp": {"status": "skipped", "reportable": False}}
    assert json.loads((cfg / "codex.json").read_text(encoding="utf-8")) == original
    assert not profile.config_path.exists()


def test_wheelhouse_checksum_cache_staging_and_backoff(tmp_path: Path) -> None:
    channel_dir = tmp_path / "channel"
    channel_dir.mkdir()
    wheel = b"piece"
    bundle = channel_dir / "mindie-wheels-bundle.tar.gz"
    with tarfile.open(bundle, "w:gz") as archive:
        member = tarfile.TarInfo("mindie_harness-0.1.3-py3-none-any.whl")
        member.size = len(wheel)
        archive.addfile(member, io.BytesIO(wheel))
    atomic_write_json(channel_dir / "release-channel.json", {"product_version": "0.1.3", "components": {"mindie-harness": {"repository": "mindie-agent/harness", "version": "0.1.3", "revision": "a" * 40}}})
    (channel_dir / "SHA256SUMS").write_text(
        f"{_sha(channel_dir / 'release-channel.json')}  release-channel.json\n{_sha(bundle)}  mindie-wheels-bundle.tar.gz\n",
        encoding="utf-8",
    )

    profile = _profile(tmp_path)
    discovered = discover_channel(profile, channel_base_url=str(channel_dir))
    assert discovered["status"] == "ok" and discovered["checksum_verified"] is True
    assert discover_channel(profile, channel_base_url=str(channel_dir))["cache_hit"] is True
    assert parse_sha256sums("a" * 64 + " *demo.whl\n") == {"demo.whl": "a" * 64}
    wheelhouse = stage_wheelhouse(profile, channel=discovered, offline=True)
    assert (wheelhouse / "mindie_harness-0.1.3-py3-none-any.whl").is_file()

    profile2 = _profile(tmp_path / "second")
    failed = update_runtime(profile2, channel_base_url=str(tmp_path / "missing"), background=True)
    assert failed["status"] == "backoff" and failed["reportable"] is False
    assert failed["next_retry_at"] > 0 and BACKOFF_BASE_SECONDS == 3600.0
    blocked = discover_channel(profile2, channel_base_url=str(channel_dir))
    assert blocked["status"] == "backoff"


def test_wheelhouse_rejects_unsafe_tar_members(tmp_path: Path) -> None:
    archive_path = tmp_path / "evil.tar.gz"
    with tarfile.open(archive_path, "w:gz") as archive:
        member = tarfile.TarInfo("../escape.whl")
        member.size = 1
        archive.addfile(member, io.BytesIO(b"x"))
    with pytest.raises(HarnessError) as exc:
        extract_wheel_bundle_safely(archive_path, tmp_path / "out")
    assert exc.value.reason == "unsafe_archive_member"


def test_sharing_local_only_and_status(tmp_path: Path) -> None:
    profile = _profile(tmp_path)
    root = tmp_path / "workspace"
    root.mkdir()
    result = configure_sharing(profile, choice="local-only", project_roots=[root])
    consent = json.loads(profile.consent_path.read_text(encoding="utf-8"))
    community = json.loads((profile.config_path.parent / "mindie-community.json").read_text(encoding="utf-8"))
    policy = json.loads(Path(result["diagnostics_policy_path"]).read_text(encoding="utf-8"))
    assert consent["choice"] == "local-only" and len(consent["choice_revision"]) == 32
    assert community["enabled"] is True and community["local_only"] is True and community["repository"] is None
    assert policy["decision"] == "disabled" and policy["schema"] == "mindie.diagnostics.reporting.v1"
    status = sharing_status(profile, cwd=root)
    assert status["tier"] == "local-only" and status["cwd_in_scope"] is True
    assert status["recommended_tier"] in {"contribute", "local-only"}


def test_gateway_identity_surfaces_and_rebind(tmp_path: Path) -> None:
    profile = _profile(tmp_path)
    adapter = ManagedMCPAdapter("codex")
    tools = adapter.mcp_tools("tools", profile)
    names = [tool["name"] for tool in tools]
    assert names[:2] == ["mindie_status", "mindie_doctor"]
    assert "knowledge_query" in names and len(tools) == 16
    assert "rsi_loop" in names and "experiment_ledger" in names
    assert COMPONENT_MODULES["rsi_loop"] == "mindie_harness.rsi.rsi_loop"
    assert COMPONENT_MODULES["experiment_ledger"] == "mindie_harness.rsi.experiment_ledger"
    assert [tool["name"] for tool in adapter.mcp_tools("components", profile)][-1] == "diagnostics_bundle"
    assert adapter.extract_session_identity({"params": {"_meta": {"threadId": "t-1"}}}, {}) == "t-1"
    assert adapter.extract_session_identity({}, {"KIMI_SESSION_ID": "k-1"}) == "k-1"
    assert adapter.extract_session_identity({}, {}) is None
    assert resolve_remote_profile("cc", {}) == "claude"

    plugin = tmp_path / "plugin"
    plugin.mkdir(exist_ok=True)
    atomic_write_json(plugin / "plugin.json", {"version": "2.0.0"})
    atomic_write_json(
        profile.config_path,
        {"host": "codex", "python": sys.executable, "product_validation": {"native_version": "1.0.0"}, "component_commands": {"profiler": ["/old/python", "-m", "mindie_profiler"], "custom": ["keep"]}},
    )
    rebound = rebind_native_plugin_if_needed(profile)
    assert rebound is not None and rebound["status"] == "rebound"
    updated = json.loads(profile.config_path.read_text(encoding="utf-8"))
    assert updated["component_commands"]["profiler"] == [sys.executable, "-I", "-X", "utf8", "-m", "mindie_profiler"]
    assert updated["component_commands"]["custom"] == ["keep"]
    assert rebind_native_plugin_if_needed(profile) is None


def test_omp_gateway_session_isolation_and_canonical_remote_profile(tmp_path: Path) -> None:
    profile = _profile(tmp_path, "omp")
    adapter = ManagedMCPAdapter("omp")
    inherited = {"CODEX_THREAD_ID": "codex-thread", "CLAUDE_SESSION_ID": "claude-session"}
    request = {"id": 1, "params": {"name": "mindie_status"}}
    with_meta = {"id": 2, "params": {"name": "mindie_status", "_meta": {"sessionId": "omp-meta"}}}
    assert resolve_remote_profile("omp", {}) == "canonical"
    assert DefaultHostAdapter("omp").extract_session_identity(request, inherited) is None
    assert DefaultHostAdapter("omp").extract_session_identity(request, {**inherited, "PI_SESSION_ID": " omp-session "}) == "omp-session"
    assert adapter.extract_session_identity(request, inherited) is None
    assert adapter.extract_session_identity(request, {**inherited, "PI_SESSION_ID": " omp-session "}) == "omp-session"
    assert adapter.extract_session_identity(with_meta, {"PI_SESSION_ID": "omp-session"}) == "omp-meta"

    router = MCPRouter(profile, session_extractor=adapter.extract_session_identity, base_env=inherited)
    result = router.call_tool(request)
    assert result["isError"] is False
    assert json.loads(result["content"][0]["text"])["session_id"] == f"omp-conn-{router.connection_id[:12]}"
    assert not profile.binds_db.exists()
    assert not profile.receipts_db.exists()


def _context(tool_name: str = "remote_bash", *, env: dict[str, str] | None = None, session: str = "unit-session") -> RequestContext:
    return RequestContext(
        request_id="req-1",
        surface="remote",
        tool_name=tool_name,
        session_id=session,
        cwd=None,
        env=dict(os.environ if env is None else env),
        deadline=Deadline.from_timeout(60.0),
        cancel=threading.Event(),
    )


def test_remote_mcp_envelope_and_error_outcome(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    tools = pytest.importorskip("remote_dev.mcp.tools")
    monkeypatch.setenv("REMOTE_DEV_STATE_DIR", str(tmp_path / "remote-state"))
    monkeypatch.setenv("REMOTE_DEV_SESSION_ID", "envelope-session")
    profile = _profile(tmp_path)

    monkeypatch.setattr(tools, "call_tool", lambda name, args, profile=None: {"text": "hello", "result": {"outcome": "success", "kind": "foreground"}})
    ok = dispatch_remote_tool(_context(), {"cmd": "echo"}, profile, "codex")
    assert ok["isError"] is False
    assert isinstance(ok["content"], list) and ok["content"][0]["type"] == "text"
    assert ok["structuredContent"]["outcome"] == "success"

    monkeypatch.setattr(tools, "call_tool", lambda name, args, profile=None: {"text": "failed", "result": {"outcome": "failed", "error": "boom"}})
    bad = dispatch_remote_tool(_context(), {}, profile, "codex")
    assert bad["isError"] is True
    assert bad["structuredContent"]["error"] == "boom"

    def explode(name, args, profile=None):
        raise RuntimeError("ssh exploded")

    monkeypatch.setattr(tools, "call_tool", explode)
    failed = dispatch_remote_tool(_context(), {}, profile, "codex")
    assert failed["isError"] is True
    assert failed["structuredContent"]["reason"] == "remote_tool_failed"
    assert failed["structuredContent"]["error_details"]["type"] == "RuntimeError"


def test_remote_calls_are_not_serialized_by_a_global_env_lock(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    tools = pytest.importorskip("remote_dev.mcp.tools")
    monkeypatch.setenv("REMOTE_DEV_STATE_DIR", str(tmp_path / "remote-state"))
    monkeypatch.setenv("REMOTE_DEV_SESSION_ID", "concurrent-session")
    profile = _profile(tmp_path)
    first_started = threading.Event()
    release_first = threading.Event()
    counter_lock = threading.Lock()
    order: list[str] = []
    results: dict[str, dict] = {}

    def fake_call(name, args, profile=None):
        with counter_lock:
            order.append(str(args.get("tag")))
            index = len(order)
        if index == 1:
            first_started.set()
            assert release_first.wait(5.0)
        return {"text": f"ok-{index}", "result": {"outcome": "success"}}

    monkeypatch.setattr(tools, "call_tool", fake_call)

    def run(tool_name: str, tag: str) -> None:
        results[tag] = dispatch_remote_tool(_context(tool_name), {"tag": tag}, profile, "codex")

    long_call = threading.Thread(target=run, args=("remote_bash", "long"))
    control_call = threading.Thread(target=run, args=("remote_job_status", "control"))
    long_call.start()
    assert first_started.wait(5.0)
    control_call.start()
    control_call.join(2.0)
    overlapped = not control_call.is_alive()
    release_first.set()
    long_call.join(5.0)
    control_call.join(5.0)
    assert overlapped, "a control call queued behind a long-running remote call"
    assert results["long"]["isError"] is False and results["control"]["isError"] is False


def test_component_token_cap_truncates_without_killing_child(tmp_path: Path) -> None:
    profile = _profile(tmp_path)
    script = tmp_path / "emit.py"
    script.write_text("import sys\nsys.stdout.write('x' * (100 * 1024))\n", encoding="utf-8")
    atomic_write_json(profile.config_path, {"python": sys.executable, "component_commands": {"profiler": [sys.executable, "-I", str(script)]}})
    result = run_component_tool(_context("profiler"), "profiler", {"max_output_tokens": 16}, profile)
    body = result["structuredContent"]
    assert result["isError"] is False
    assert body["returncode"] == 0
    assert body["output_truncated"] is True
    assert len(result["content"][0]["text"].encode("utf-8")) < 1000


def test_diagnostics_status_invokes_reporting_status(tmp_path: Path) -> None:
    profile = _profile(tmp_path)
    argv_file = tmp_path / "diagnostics-argv.json"
    recorder = tmp_path / "record.py"
    recorder.write_text(
        "import json, pathlib, sys\npathlib.Path(sys.argv[1]).write_text(json.dumps(sys.argv[2:]), encoding='utf-8')\nprint('{\"status\": \"ok\"}')\n",
        encoding="utf-8",
    )
    atomic_write_json(profile.config_path, {"python": sys.executable, "component_commands": {"diagnostics": [sys.executable, "-I", str(recorder), str(argv_file)]}})
    result = run_diagnostics_tool(_context("diagnostics_status"), "diagnostics_status", {}, profile)
    assert result["isError"] is False
    assert json.loads(argv_file.read_text(encoding="utf-8")) == [
        "reporting", "status", "--config", str(profile.config_path.parent / "diagnostics.json"),
    ]


def test_component_rebind_preserves_custom_wrappers(tmp_path: Path) -> None:
    profile = _profile(tmp_path)
    plugin = tmp_path / "plugin"
    plugin.mkdir(exist_ok=True)
    atomic_write_json(plugin / "plugin.json", {"version": "3.0.0"})
    custom = [sys.executable, "-I", str(tmp_path / "custom-wrapper.py")]
    atomic_write_json(
        profile.config_path,
        {
            "host": "codex",
            "python": sys.executable,
            "component_commands": {
                "profiler": custom,
                "sim": ["/old/python", "-I", "-m", "mindie_sim"],
                "coordinator": ["/old/python", "-I", "-B", "-X", "utf8", "-m", "mindie_coordinator.cli"],
                "custom": ["keep"],
            },
        },
    )
    assert rebind_native_plugin_if_needed(profile) is not None
    cfg = json.loads(profile.config_path.read_text(encoding="utf-8"))
    assert cfg["component_commands"]["profiler"] == custom
    assert cfg["component_commands"]["sim"] == [sys.executable, "-I", "-X", "utf8", "-m", "mindie_sim.cli"]
    assert cfg["component_commands"]["coordinator"] == [sys.executable, "-I", "-X", "utf8", "-m", "mindie_coordinator.cli"]
    assert cfg["component_commands"]["custom"] == ["keep"]

    wheelhouse_cfg = {
        "component_commands": {
            "profiler": custom,
            "sim": ["/old/python", "-m", "mindie_sim"],
            "debugger": ["/old/python", "-I", "-B", "-X", "utf8", "-m", "mindie_debugger.cli"],
        }
    }
    rebind_component_commands(wheelhouse_cfg, "/new/python")
    assert wheelhouse_cfg["component_commands"]["profiler"] == custom
    assert wheelhouse_cfg["component_commands"]["sim"] == ["/new/python", "-I", "-X", "utf8", "-m", "mindie_sim.cli"]
    assert wheelhouse_cfg["component_commands"]["debugger"] == ["/new/python", "-I", "-X", "utf8", "-m", "mindie_debugger.cli"]


def test_sharing_writer_is_community_settings_valid(tmp_path: Path) -> None:
    settings = pytest.importorskip("mindie_knowledge.loop.settings")
    profile = _profile(tmp_path)
    root = tmp_path / "workspace"
    root.mkdir()
    configure_sharing(profile, choice="local-only", project_roots=[root])
    community_file = profile.config_path.parent / "mindie-community.json"
    document = json.loads(community_file.read_text(encoding="utf-8"))
    normalized = settings.normalize(document)
    assert normalized["generation"] == document["generation"]
    assert isinstance(document["generation"], str) and len(document["generation"]) == 32
    loaded = settings.load(community_file)
    assert loaded.valid is True and loaded.enabled is True
    assert loaded.generation == document["generation"]
    assert loaded.enabled_at is not None and loaded.enabled_at > 0
    assert loaded.branch == "main" and loaded.idle_seconds == 300

    configure_sharing(profile, choice="local-only", project_roots=[root])
    repeated = json.loads(community_file.read_text(encoding="utf-8"))
    assert repeated["generation"] == document["generation"]
    assert repeated["enabled_at"] == document["enabled_at"]

    configure_sharing(profile, choice="disabled")
    disabled = json.loads(community_file.read_text(encoding="utf-8"))
    assert settings.load(community_file).valid is True
    assert disabled["enabled"] is False and disabled["enabled_at"] is None


def test_installer_local_source_activates_host_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import mindie_harness.api as api

    profile = _profile(tmp_path)
    plugin = tmp_path / "plugin"
    plugin.mkdir(exist_ok=True)
    (plugin / "pyproject.toml").write_text("[project]\nname = 'mindie-demo'\nversion = '0.1.0'\n", encoding="utf-8")
    generation = profile.generations_dir / "gen-test"
    python_path = venv_python_path(generation / ".venv")
    python_path.parent.mkdir(parents=True, exist_ok=True)
    python_path.write_bytes(b"")
    receipt = generation / "runtime.json"
    atomic_write_json(receipt, {"schema": "mindie-candidate-check/1", "validation": {"status": "validated"}})
    prepared = PreparedGeneration("validated", "gen-test", generation, python_path, receipt, {})
    monkeypatch.setattr(api, "prepare_runtime", lambda profile, **kwargs: prepared)

    result = _configured(profile, plugin, None, True, False, dict(os.environ))
    assert result["status"] == "active"
    config = json.loads(profile.config_path.read_text(encoding="utf-8"))
    assert config["host"] == "codex"
    assert config["python"] == str(python_path)
    assert config["component_release"] == str(generation)


def test_wheelhouse_offline_guard_and_unc_file_source(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    profile = _profile(tmp_path)
    network_calls: list[object] = []

    def explode(*args, **kwargs):
        network_calls.append(args)
        raise AssertionError("network must not be touched while offline")

    monkeypatch.setattr(wheelhouse_assets, "urlopen", explode)
    with pytest.raises(HarnessError) as exc:
        update_runtime(profile, channel_base_url="https://example.invalid/channel", offline=True)
    assert (exc.value.stage, exc.value.reason) == ("channel_discover", "offline_channel_unavailable")
    assert exc.value.retryable is True and exc.value.reportable is False
    assert network_calls == []

    second = _profile(tmp_path / "second")
    with pytest.raises(HarnessError) as exc2:
        update_runtime(second, channel_base_url="http://example.invalid/channel", env={"_MINDIE_UV_FLAGS": "--offline --no-index"})
    assert exc2.value.reason == "offline_channel_unavailable"
    assert network_calls == []

    source = str(asset_source("file://server/share/channel", "release-channel.json")).replace("\\", "/")
    assert source == "//server/share/channel/release-channel.json"
    assert "%20" not in str(asset_source("file:///tmp/mindie%20cache", "SHA256SUMS"))


def test_wheelhouse_http_timeout_and_backoff(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    profile = _profile(tmp_path)

    def timed_out(*args, **kwargs):
        raise TimeoutError("socket read timed out")

    monkeypatch.setattr(wheelhouse_assets, "urlopen", timed_out)
    destination = tmp_path / "asset.bin"
    with pytest.raises(HarnessError) as exc:
        download_verified("https://example.invalid/asset", destination, None, timeout=0.5, deadline=Deadline.from_timeout(30.0))
    assert (exc.value.stage, exc.value.reason) == ("asset_fetch", "http_timeout")
    assert exc.value.retryable is True and exc.value.reportable is False
    assert not destination.exists()

    with pytest.raises(TimeoutError):
        download_verified("https://example.invalid/asset", destination, None, timeout=0.5, deadline=Deadline(expires_at=time.monotonic() - 1.0))

    background = _profile(tmp_path / "background")
    outcome = update_runtime(background, channel_base_url="https://example.invalid/channel", background=True, timeout=0.5)
    assert outcome["status"] == "backoff" and outcome["reason"] == "http_timeout"
    assert outcome["reportable"] is False


def test_component_floor_blocks_downgrade_but_skips_custom_wrapper(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    profile = _profile(tmp_path)
    atomic_write_json(
        profile.config_path,
        {"python": sys.executable, "component_commands": {"profiler": [sys.executable, "-I", "-X", "utf8", "-m", "mindie_profiler"]}},
    )
    monkeypatch.setattr(wheelhouse_assets, "installed_package_version", lambda python, package: "9.9.9")
    selection = RuntimeSelection.from_pins({"mindie-profiler": {"version": "1.0.0"}})
    with pytest.raises(HarnessError) as exc:
        check_component_version_floors(profile, selection)
    assert exc.value.reason == "component_downgrade_blocked" and exc.value.reportable is False

    atomic_write_json(
        profile.config_path,
        {"python": sys.executable, "component_commands": {"profiler": [sys.executable, "-I", str(tmp_path / "wrapper.py")]}},
    )
    check_component_version_floors(profile, selection)


def test_component_default_command_and_spool_cap(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    profile = _profile(tmp_path)
    captured: dict[str, object] = {}

    def fake_run(spec, *, deadline, cancel=None):
        captured["argv"] = tuple(spec.argv)
        captured["max_output_bytes"] = spec.max_output_bytes
        return ProcessOutcome(execution="completed", returncode=0, stdout="ok", stderr="", elapsed_ms=1)

    monkeypatch.setattr(gateway_dispatch, "run_owned", fake_run)
    result = run_component_tool(_context("sim"), "sim", {}, profile)
    assert result["isError"] is False
    assert captured["max_output_bytes"] == 16 * 1024 * 1024
    assert captured["argv"] == (sys.executable, "-I", "-X", "utf8", "-m", "mindie_sim.cli")


def test_product_channel_normalization_bundle_members_and_override_builder(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    profile = _profile(tmp_path)
    channel_dir = tmp_path / "channel"
    channel_dir.mkdir(parents=True, exist_ok=True)
    bundle_path = channel_dir / "mindie-wheels-bundle.tar.gz"
    req_bytes = b"mindie-harness==0.1.4\nreme-ai[as]==0.1.0\n"
    manifest_bytes = b'{"schema_version":"mindie-wheels-bundle/1","product_version":"0.1.16"}\n'
    wheel_bytes = b"wheel-bytes"
    with tarfile.open(bundle_path, "w:gz") as archive:
        for member_name, payload in (
            ("mindie_harness-0.1.4-py3-none-any.whl", wheel_bytes),
            ("requirements.txt", req_bytes),
            ("bundle-manifest.json", manifest_bytes),
        ):
            info = tarfile.TarInfo(member_name)
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))
    channel_doc = {
        "schema": "mindie-release-channel/1",
        "current_patch_version": "0.1.16",
        "components": {
            "harness": {
                "role": "shared_component",
                "repository": "mindie-agent/harness",
                "package": "mindie-harness",
                "version": "0.1.4",
                "commit": "a" * 40,
            },
            "mindie-bench": {
                "role": "evaluation_component",
                "repository": "mindie-agent/mindie-bench",
                "package": "mindie-bench",
                "version": "0.4.13",
                "commit": "b" * 40,
            },
            "mindie-agent-codex": {
                "role": "harness_plugin",
                "repository": "mindie-agent/mindie-agent-codex",
                "version": "0.1.38",
                "commit": "c" * 40,
            },
        },
    }
    atomic_write_json(channel_dir / "release-channel.json", channel_doc)
    sums = "\n".join(
        f"{hashlib.sha256((channel_dir / name).read_bytes()).hexdigest()}  {name}"
        for name in ("release-channel.json", "mindie-wheels-bundle.tar.gz")
    ) + "\n"
    (channel_dir / "SHA256SUMS").write_text(sums, encoding="utf-8")

    discovered = discover_channel(profile, channel_base_url=str(channel_dir))
    assert discovered["product_version"] == "0.1.16"
    assert set(discovered["components"]) == {"mindie-harness"}
    assert discovered["components"]["mindie-harness"]["revision"] == "a" * 40

    staged = stage_wheelhouse(profile, channel=discovered, dest_dir=tmp_path / "wh")
    assert (staged / "requirements.txt").read_bytes() == req_bytes
    assert (staged / "bundle-manifest.json").read_bytes() == manifest_bytes

    calls: list[tuple[str, ...]] = []

    def fake_run(spec, *, deadline, cancel=None):
        calls.append(tuple(spec.argv))
        return ProcessOutcome(execution="completed", returncode=0, stdout="", stderr="", elapsed_ms=1)

    monkeypatch.setattr(wheelhouse_mod, "run_owned", fake_run)
    monkeypatch.setattr(wheelhouse_mod, "_resolve_uv", lambda env: "/usr/bin/uv")
    builder = wheelhouse_mod._wheelhouse_builder(profile, staged, offline=True)
    builder(tmp_path / "gen", tmp_path / "gen" / "venv", {}, Deadline.from_timeout(30.0))
    pip_call = calls[1]
    assert "--override" in pip_call and "-r" in pip_call
    assert str(staged / "requirements.txt") in pip_call
    assert "--offline" in pip_call and "--no-index" in pip_call
