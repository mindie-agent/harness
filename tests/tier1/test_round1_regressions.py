"""Orthogonal behavioral tests covering CLI flag ordering, hook lifecycle, cold seed, cross-session binds, POSIX lease/GC synchronization, and systemd schedule discovery."""
from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import threading

import pytest

from mindie_harness.api import DefaultHostAdapter, ProfileRef, __version__, run_host
from mindie_harness.atomic import atomic_write_json, stage_retire_directory
from mindie_harness.bootstrap.seed_main import (
    _provision_cold,
    _run_owned_seed_cmd,
    render_plugin_bootstrap_template,
)
from mindie_harness.locks import FileLock, acquire_generation_lease, acquire_retirement_guard
from mindie_harness.mcp.router import MCPRouter
from mindie_harness.runtime.activation import (
    CANDIDATE_RECEIPT_SCHEMA,
    PreparedGeneration,
    activate_generation,
    reclaim_generations,
)
from mindie_harness.runtime.scheduler import discover_scheduled_executables, migrate_schedule


REPO_ROOT = Path(__file__).resolve().parents[2]


def test_cli_profile_flags_preserved_before_and_after_subcommand(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    cfg_path = tmp_path / "custom-cfg" / "kimi.json"
    data_dir = tmp_path / "custom-data"
    plugin_root = tmp_path / "kimi-plugin"
    plugin_root.mkdir(parents=True)

    rc = run_host(
        [
            "--host",
            "kimi",
            "--plugin-root",
            str(plugin_root),
            "--config",
            str(cfg_path),
            "--data-dir",
            str(data_dir),
            "maintain",
            "--enqueue-check",
            "--reason",
            "flag_order_before",
        ]
    )
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    marker = Path(out["path"])
    assert marker == data_dir / "state" / "kimi" / "pending-update-check.json"
    doc = json.loads(marker.read_text(encoding="utf-8"))
    assert doc["host"] == "kimi"
    assert doc["reason"] == "flag_order_before"

    rc2 = run_host(
        [
            "inspect",
            "--host",
            "kimi",
            "--config",
            str(cfg_path),
            "--data-dir",
            str(data_dir),
        ]
    )
    assert rc2 == 0
    inspected = json.loads(capsys.readouterr().out)
    assert inspected["host"] == "kimi"
    assert inspected["config_path"] == str(cfg_path.resolve())


def test_launcher_session_start_hook_succeeds_before_and_after_runtime_exists(tmp_path: Path) -> None:
    plugin_root = tmp_path / "plugin"
    scripts_dir = plugin_root / "scripts"
    scripts_dir.mkdir(parents=True)
    launcher = scripts_dir / "mindie_launch.py"
    launcher.write_text(render_plugin_bootstrap_template("kimi"), encoding="utf-8")

    env = dict(os.environ)
    env["PYTHONPATH"] = str(REPO_ROOT)

    # 1. Before any runtime exists -> enqueues pending-update-check.json and exits 0 with `{}`
    cold = subprocess.run(
        [sys.executable, str(launcher), "hook", "session-start"],
        env=env,
        capture_output=True,
        text=True,
        timeout=15.0,
        check=True,
    )
    assert json.loads(cold.stdout) == {}
    pending = Path(os.environ["MINDIE_DATA_HOME"]) / "state" / "kimi" / "pending-update-check.json"
    assert pending.is_file()
    pending.unlink()

    # 2. Once an active runtime is configured in kimi.json -> forwards to mindie_harness.cli hook session-start
    # Note: `-I` isolates PYTHONPATH, so test against DefaultHostAdapter/run_host AND installed wheel or site python.
    rc = run_host(
        ["--host", "kimi", "--plugin-root", str(plugin_root), "hook", "session-start"],
        adapter=DefaultHostAdapter("kimi", plugin_root=plugin_root),
    )
    assert rc == 0
    assert pending.is_file()


def test_launcher_and_seed_stop_consent_gate_and_cold_prompt_noop(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from mindie_harness.bootstrap import seed_main

    plugin_root = tmp_path / "plugin"
    scripts_dir = plugin_root / "scripts"
    scripts_dir.mkdir(parents=True)
    launcher = scripts_dir / "mindie_launch.py"
    launcher.write_text(render_plugin_bootstrap_template("kimi"), encoding="utf-8")

    cfg_dir = Path(os.environ["MINDIE_CONFIG_HOME"])
    state_dir = Path(os.environ["MINDIE_DATA_HOME"]) / "state" / "kimi"
    state_dir.mkdir(parents=True, exist_ok=True)
    # Plant a stale `admission.sqlite3`: disabled / out-of-scope Stop MUST STILL exit `{}` without cold provisioning!
    (state_dir / "admission.sqlite3").write_bytes(b"stale-db")

    allowed_proj = tmp_path / "allowed-proj"
    allowed_proj.mkdir()
    outside_proj = tmp_path / "outside-proj"
    outside_proj.mkdir()

    # 1. Cold `pre-invocation` and `user-prompt-submit` immediately return `{}` without scanning stdin or provisioning `.pyz`.
    for hook_op in ("pre-invocation", "user-prompt-submit"):
        res_prompt = subprocess.run(
            [sys.executable, str(launcher), "hook", hook_op],
            input=json.dumps({"prompt": "/mindie-agent optimize kernel"}),
            capture_output=True,
            text=True,
            timeout=10.0,
            check=True,
        )
        assert json.loads(res_prompt.stdout) == {}

    # 2. Stale `admission.sqlite3` with sharing unconfigured or `enabled=False` exits `{}` without cold provisioning.
    atomic_write_json(
        cfg_dir / "mindie-community.json",
        {"schema": "mindie-community-config/1", "enabled": False, "project_roots": [str(allowed_proj)]},
    )
    atomic_write_json(cfg_dir / "mindie-consent.json", {"schema": "mindie-consent/1", "choice": "disabled"})
    for stop_op in ("stop", "session-end"):
        res_dis = subprocess.run(
            [sys.executable, str(launcher), "hook", stop_op],
            input=json.dumps({"cwd": str(allowed_proj)}),
            capture_output=True,
            text=True,
            timeout=10.0,
            check=True,
        )
        assert json.loads(res_dis.stdout) == {}

    # 3. Sharing enabled (`enabled=True` + `choice='contribute'`), out-of-scope `cwd` exits `{}` without cold provisioning.
    atomic_write_json(
        cfg_dir / "mindie-consent.json",
        {"schema": "mindie-consent/1", "choice": "contribute"},
    )
    atomic_write_json(
        cfg_dir / "mindie-community.json",
        {
            "schema": "mindie-community-config/1",
            "enabled": True,
            "project_roots": [str(allowed_proj)],
            "consent_config": str((cfg_dir / "mindie-consent.json").resolve()),
        },
    )
    res_out = subprocess.run(
        [sys.executable, str(launcher), "hook", "stop"],
        input=json.dumps({"cwd": str(outside_proj)}),
        capture_output=True,
        text=True,
        timeout=10.0,
        check=True,
    )
    assert json.loads(res_out.stdout) == {}

    # Direct `seed_main.main` also short-circuits out-of-scope `stop` before `_provision_cold`!
    monkeypatch.setattr(seed_main, "_provision_cold", lambda *a, **kw: pytest.fail("_provision_cold must not run"))
    monkeypatch.setattr(sys, "stdin", type("FakeIn", (), {"buffer": io.BytesIO(json.dumps({"cwd": str(outside_proj)}).encode("utf-8"))})())
    assert seed_main.main(["--host", "kimi", "--plugin-root", str(plugin_root), "--config", str(cfg_dir / "kimi.json"), "hook", "stop"]) == 0

    # 4. Fresh opted-in project WITHOUT `admission.sqlite3` and in-scope `cwd`/`workspacePaths` is NOT short-circuited!
    (state_dir / "admission.sqlite3").unlink()
    forwarded_file = tmp_path / "forwarded_stop.json"
    fake_cli_pkg = tmp_path / "fake_pkg"
    fake_cli_pkg.mkdir()
    (fake_cli_pkg / "echo_cli.py").write_text(
        "import json, sys\n"
        "from pathlib import Path\n"
        "raw = sys.stdin.buffer.read().decode('utf-8')\n"
        f"Path({str(forwarded_file)!r}).write_text(json.dumps({{'argv': sys.argv[1:], 'stdin': json.loads(raw)}}), encoding='utf-8')\n"
        "sys.stdout.write('{}\\n')\n",
        encoding="utf-8",
    )
    shim_py = tmp_path / ("shim.cmd" if os.name == "nt" else "shim_py")
    if os.name != "nt":
        shim_py.write_text(
            f"#!/bin/sh\nPYTHONPATH={str(fake_cli_pkg)!r} exec \"{sys.executable}\" \"$@\" 2>&1\n",
            encoding="utf-8",
        )
        shim_py.chmod(0o755)
        launcher_custom = scripts_dir / "mindie_launch_custom.py"
        launcher_custom.write_text(render_plugin_bootstrap_template("kimi", cli_module="echo_cli"), encoding="utf-8")
        atomic_write_json(cfg_dir / "kimi.json", {"host": "kimi", "python": str(shim_py)})
        sub_ws = allowed_proj / "nested"
        sub_ws.mkdir()
        # Notice `-I` ignores PYTHONPATH env var, so verify via a sitecustomize-free wrapper script that strips `-I`:
        shim_py.write_text(
            "#!/bin/sh\n"
            "shift; shift; shift\n"  # drop `-I -X utf8`
            f"PYTHONPATH={str(fake_cli_pkg)!r} exec \"{sys.executable}\" \"$@\"\n",
            encoding="utf-8",
        )
        res_in = subprocess.run(
            [sys.executable, str(launcher_custom), "hook", "session-end"],
            input=json.dumps({"workspacePaths": [str(sub_ws)], "session_id": "s-fresh"}),
            capture_output=True,
            text=True,
            timeout=10.0,
            check=True,
        )
        assert json.loads(res_in.stdout) == {}
        forwarded = json.loads(forwarded_file.read_text(encoding="utf-8"))
        assert forwarded["stdin"]["session_id"] == "s-fresh"
        assert forwarded["argv"][-2:] == ["hook", "session-end"]


def test_cold_seed_provisions_requirements_plugin_with_wheelhouse_and_rejects_broken_plugin(tmp_path: Path) -> None:
    # 1. Broken plugin without manifests fails cleanly and does NOT publish runtime.json
    empty_plugin = tmp_path / "empty-plugin"
    empty_plugin.mkdir()
    bad_cfg = tmp_path / "cfg" / "oc.json"
    with pytest.raises(RuntimeError, match="missing pyproject.toml"):
        _provision_cold("oc", empty_plugin, bad_cfg)
    assert not (Path(os.environ["MINDIE_DATA_HOME"]) / "runtimes" / "oc" / f"seed-{sys.platform}" / "runtime.json").exists()

    # 2. Plugin using runtime-requirements.txt + wheelhouse (like mindie-agent-kimi) installs mindie-harness and validates
    wheelhouse = tmp_path / "kimi-plugin" / "wheelhouse"
    wheelhouse.mkdir(parents=True)
    subprocess.run(
        ["uv", "build", "--wheel", "--out-dir", str(wheelhouse), str(REPO_ROOT)],
        check=True,
        capture_output=True,
        timeout=60.0,
    )
    req_plugin = tmp_path / "kimi-plugin"
    (req_plugin / "runtime-requirements.txt").write_text(f"mindie-harness=={__version__}\n", encoding="utf-8")
    kimi_cfg = tmp_path / "cfg" / "kimi.json"

    venv_py = _provision_cold("kimi", req_plugin, kimi_cfg)
    assert venv_py.is_file()
    assert kimi_cfg.is_file()
    # Dispatching `-I -m mindie_harness.cli --host kimi ... hook session-start` inside the provisioned venv succeeds!
    res = subprocess.run(
        [
            str(venv_py),
            "-I",
            "-X",
            "utf8",
            "-m",
            "mindie_harness.cli",
            "--host",
            "kimi",
            "--plugin-root",
            str(req_plugin),
            "--config",
            str(kimi_cfg),
            "hook",
            "session-start",
        ],
        env=dict(os.environ),
        capture_output=True,
        text=True,
        timeout=20.0,
        check=True,
    )
    assert json.loads(res.stdout) == {}


def test_concurrent_sessions_never_cross_contaminate_bound_cwd(tmp_path: Path) -> None:
    profile = ProfileRef.resolve("cc")
    cwd_a = tmp_path / "project-A"
    cwd_b = tmp_path / "project-B"
    cwd_a.mkdir()
    cwd_b.mkdir()

    observed_cwds: dict[str, str] = {}

    def handler(ctx, args):
        observed_cwds[ctx.session_id] = str(ctx.cwd)
        return {"content": [{"type": "text", "text": str(ctx.cwd)}], "isError": False}

    tools = [
        {
            "name": "remote_exec",
            "annotations": {"readOnlyHint": False},
            "inputSchema": {"type": "object", "properties": {"cmd": {"type": "string"}}, "required": ["cmd"]},
        }
    ]
    router = MCPRouter(profile, surface="remote", tools=tools, handler=handler)

    args = {"cmd": "git status"}
    digest = hashlib.sha256(json.dumps(args, sort_keys=True).encode("utf-8")).hexdigest()
    # Session B records a PreToolUse bind in project-B
    router.binds.publish_bind(
        "bind-sess-B",
        session="sess-B",
        surface="remote",
        tool="remote_exec",
        args_digest=digest,
        cwd=str(cwd_b),
    )

    # Session A calls the identical tool + arguments WITHOUT a bind row for sess-A
    res_a = router.call_tool(
        {
            "jsonrpc": "2.0",
            "id": "call-a",
            "method": "tools/call",
            "params": {
                "name": "remote_exec",
                "arguments": dict(args),
                "_meta": {"claudecode/sessionId": "sess-A"},
            },
        }
    )
    assert res_a["isError"] is False
    assert Path(observed_cwds["sess-A"]).resolve() != cwd_b.resolve()

    # Session B's bind is STILL intact and claimed when Session B executes!
    res_b = router.call_tool(
        {
            "jsonrpc": "2.0",
            "id": "call-b",
            "method": "tools/call",
            "params": {
                "name": "remote_exec",
                "arguments": dict(args),
                "_meta": {"claudecode/sessionId": "sess-B"},
            },
        }
    )
    assert res_b["isError"] is False
    assert Path(observed_cwds["sess-B"]).resolve() == cwd_b.resolve()


@pytest.mark.skipif(os.name == "nt", reason="POSIX sibling flock serialization test")
def test_posix_retirement_guard_serializes_against_concurrent_lease_acquisition(tmp_path: Path) -> None:
    gen_dir = tmp_path / "runtimes" / "codex" / "gen-race"
    gen_dir.mkdir(parents=True)
    (gen_dir / "marker.txt").write_text("ok\n", encoding="utf-8")

    # 1. While retirement guard holds exclusive sibling lock and retires `gen_dir`,
    # concurrent `acquire_generation_lease` waits and fails cleanly instead of leasing a retired dir.
    entered = threading.Event()
    proceed = threading.Event()
    lease_outcomes: list[str] = []

    def retire_worker() -> None:
        with acquire_retirement_guard(gen_dir) as can_retire:
            assert can_retire is True
            entered.set()
            proceed.wait(timeout=5.0)
            outcome, _ = stage_retire_directory(gen_dir)
            assert outcome == "retired"

    t = threading.Thread(target=retire_worker)
    t.start()
    assert entered.wait(timeout=5.0)

    def lease_worker() -> None:
        try:
            lease = acquire_generation_lease(gen_dir)
            lease.close()
            lease_outcomes.append("leased")
        except (OSError, RuntimeError):
            lease_outcomes.append("rejected")

    lt = threading.Thread(target=lease_worker)
    lt.start()
    proceed.set()
    t.join(timeout=5.0)
    lt.join(timeout=5.0)
    assert lease_outcomes == ["rejected"]
    assert not gen_dir.exists()


def test_gc_update_lock_prevents_deleting_concurrently_activated_generation(tmp_path: Path) -> None:
    profile = ProfileRef.resolve("codex")
    created: list[PreparedGeneration] = []
    for idx, name in enumerate(("gen-A", "gen-B", "gen-C")):
        gdir = profile.generations_dir / name
        py = gdir / ".venv" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        py.parent.mkdir(parents=True, exist_ok=True)
        py.write_text("#!/bin/sh\n", encoding="utf-8")
        receipt = gdir / "runtime.json"
        atomic_write_json(
            receipt,
            {
                "schema": CANDIDATE_RECEIPT_SCHEMA,
                "key": name,
                "generation": str(gdir),
                "python": str(py),
                "validation": {"status": "validated", "validated_at": 1000.0 + idx},
            },
        )
        created.append(
            PreparedGeneration(
                status="validated",
                generation_key=name,
                generation_dir=gdir,
                python_path=py,
                receipt_path=receipt,
                components={},
            )
        )

    # Activate A, then B (so Active=B, Rollback=C or A). Now hold update_lock as if C is mid-activation:
    activate_generation(profile, created[0], run_gc=False)
    activate_generation(profile, created[1], run_gc=False)

    entered_commit = threading.Event()
    finish_commit = threading.Event()
    gc_during_commit: list[dict] = []

    def pre_commit_hook(_prof, _prep, _cfg) -> None:
        entered_commit.set()
        gc_during_commit.append(reclaim_generations(profile))
        finish_commit.set()

    res = activate_generation(profile, created[2], on_before_commit=pre_commit_hook, run_gc=True)
    assert entered_commit.is_set() and finish_commit.is_set()
    assert gc_during_commit[0]["status"] == "deferred_in_use"
    assert gc_during_commit[0]["reason"] == "activation_in_progress"
    assert res.status == "active"
    assert created[2].generation_dir.is_dir()


def test_systemd_generated_service_paths_discovered_unquoted_and_quoted(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    systemd_dir = tmp_path / "systemd" / "user"
    monkeypatch.setattr("mindie_harness.runtime.scheduler.run_owned", lambda *a, **kw: None)

    py_unquoted = tmp_path / "runtimes" / "kimi" / "gen-1" / ".venv" / "bin" / "python"
    worker_spaced = tmp_path / "kimi scripts" / "update_worker.py"

    res = migrate_schedule(
        name="mindie-kimi-update",
        command=[str(py_unquoted), str(worker_spaced)],
        work_dir=tmp_path,
        interval_seconds=3600,
        systemd_dir=systemd_dir,
        backend="systemd-user",
    )
    assert res["status"] == "scheduled"

    discovered = discover_scheduled_executables(extra_dirs=[systemd_dir])
    assert py_unquoted in discovered
    assert worker_spaced in discovered

    timer_text = (systemd_dir / "mindie-kimi-update.timer").read_text(encoding="utf-8")
    assert "OnStartupSec=" in timer_text
    assert "OnActiveSec=" in timer_text
    assert "OnUnitActiveSec=3600s" in timer_text


def test_relative_data_dir_gc_never_retires_active_generation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    profile = ProfileRef.resolve("codex", config_path="cfg/codex.json", data_dir="rel-data")
    gens: list[PreparedGeneration] = []
    for idx, name in enumerate(("gen-A", "gen-B", "gen-C")):
        gdir = profile.generations_dir / name
        py = gdir / ".venv" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        py.parent.mkdir(parents=True, exist_ok=True)
        py.write_text("#!/bin/sh\n", encoding="utf-8")
        receipt = gdir / "runtime.json"
        atomic_write_json(
            receipt,
            {
                "schema": CANDIDATE_RECEIPT_SCHEMA,
                "key": name,
                "generation": str(gdir),
                "python": str(py),
                "validation": {"status": "validated", "validated_at": 2000.0 + idx},
            },
        )
        gens.append(
            PreparedGeneration(
                status="validated",
                generation_key=name,
                generation_dir=gdir,
                python_path=py,
                receipt_path=receipt,
                components={},
            )
        )

    # Activate oldest generation A while newer B & C exist on disk under relative `--data-dir rel-data`
    activate_generation(profile, gens[0], run_gc=False)
    gc_res = reclaim_generations(profile)
    assert gens[0].generation_dir.is_dir(), "Active generation A must NEVER be retired under relative data_dir!"
    assert gens[2].generation_dir.is_dir(), "Newest rollback generation C must be retained!"
    assert not gens[1].generation_dir.exists()
    assert gc_res["reclaimed_dirs"] == 1


def test_anonymous_mcp_call_does_not_steal_single_pending_bind(tmp_path: Path) -> None:
    profile = ProfileRef.resolve("cc")
    cwd_b = tmp_path / "project-B"
    cwd_b.mkdir()
    seen: list[tuple[str, str]] = []

    def handler(ctx, args):
        seen.append((ctx.session_id, str(ctx.cwd)))
        return {"content": [{"type": "text", "text": "ok"}], "isError": False}

    tools = [
        {
            "name": "remote_exec",
            "annotations": {"readOnlyHint": False},
            "inputSchema": {"type": "object", "properties": {"cmd": {"type": "string"}}, "required": ["cmd"]},
        }
    ]
    router = MCPRouter(profile, surface="remote", tools=tools, handler=handler)
    args = {"cmd": "pwd"}
    digest = hashlib.sha256(json.dumps(args, sort_keys=True).encode("utf-8")).hexdigest()
    router.binds.publish_bind(
        "only-bind-B",
        session="sess-B",
        surface="remote",
        tool="remote_exec",
        args_digest=digest,
        cwd=str(cwd_b),
    )

    # Anonymous connection call (no session metadata, no bind_id) must NOT steal `only-bind-B`
    anon_res = router.call_tool(
        {
            "jsonrpc": "2.0",
            "id": "anon-1",
            "method": "tools/call",
            "params": {"name": "remote_exec", "arguments": dict(args)},
        }
    )
    assert anon_res["isError"] is False
    assert seen[0][0].startswith("cc-conn-")
    assert Path(seen[0][1]).resolve() != cwd_b.resolve()

    # Session B can still claim its own bind afterwards
    b_res = router.call_tool(
        {
            "jsonrpc": "2.0",
            "id": "b-1",
            "method": "tools/call",
            "params": {
                "name": "remote_exec",
                "arguments": dict(args),
                "_meta": {"claudecode/sessionId": "sess-B"},
            },
        }
    )
    assert b_res["isError"] is False
    assert seen[1] == ("sess-B", str(cwd_b))


def test_cold_seed_repairs_missing_and_stale_host_config_on_reuse(tmp_path: Path) -> None:
    wheelhouse = tmp_path / "kimi-plugin" / "wheelhouse"
    wheelhouse.mkdir(parents=True)
    subprocess.run(
        ["uv", "build", "--wheel", "--out-dir", str(wheelhouse), str(REPO_ROOT)],
        check=True,
        capture_output=True,
        timeout=60.0,
    )
    req_plugin = tmp_path / "kimi-plugin"
    (req_plugin / "runtime-requirements.txt").write_text(f"mindie-harness=={__version__}\n", encoding="utf-8")
    cfg_path = tmp_path / "cfg" / "kimi.json"

    # Initial build writes cfg_path
    py1 = _provision_cold("kimi", req_plugin, cfg_path)
    assert cfg_path.is_file()

    # 1. Simulate crash before cfg_path write (delete cfg_path while keeping validated seed venv)
    cfg_path.unlink()
    py2 = _provision_cold("kimi", req_plugin, cfg_path)
    assert py2 == py1
    assert cfg_path.is_file()

    # 2. Simulate stale cfg_path pointing to a deleted python while preserving user fields (`feeds`)
    atomic_write_json(
        cfg_path,
        {
            "host": "kimi",
            "python": str(tmp_path / "deleted" / "python"),
            "component_release": str(tmp_path / "deleted"),
            "feeds": {"custom": "https://example.invalid/feed.json"},
        },
    )
    py3 = _provision_cold("kimi", req_plugin, cfg_path)
    assert py3 == py1
    repaired = json.loads(cfg_path.read_text(encoding="utf-8"))
    assert repaired["python"] == str(py1)
    assert repaired["feeds"] == {"custom": "https://example.invalid/feed.json"}


def test_seed_owned_cmd_kills_grandchild_on_timeout(tmp_path: Path) -> None:
    pid_file = tmp_path / "grandchild.pid"
    script = tmp_path / "spawn_tree.py"
    script.write_text(
        "import subprocess, sys, time\n"
        "from pathlib import Path\n"
        f"p = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])\n"
        f"Path({str(pid_file)!r}).write_text(str(p.pid), encoding='utf-8')\n"
        "time.sleep(60)\n",
        encoding="utf-8",
    )
    with pytest.raises(subprocess.TimeoutExpired):
        _run_owned_seed_cmd([sys.executable, str(script)], env=dict(os.environ), timeout=0.6)

    assert pid_file.is_file()
    grand_pid = int(pid_file.read_text(encoding="utf-8").strip())
    if os.name != "nt":
        import time

        deadline = time.monotonic() + 2.0
        alive = True
        while time.monotonic() < deadline:
            try:
                os.kill(grand_pid, 0)
                time.sleep(0.05)
            except ProcessLookupError:
                alive = False
                break
        assert not alive, f"Grandchild {grand_pid} survived seed command timeout!"

