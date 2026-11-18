"""Tier 1 concurrent MCP server, silent default-on (`P2.7`/`P2.8`), process tree kill, RSI worktree & wheel smoke tests (`< 15s`)."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import threading
import time
from typing import Any
import pytest

from mindie_harness import Deadline, ProcessSpec, ProfileRef, __version__, run_owned
from mindie_harness.mcp.router import MCPRouter, RequestContext
from mindie_harness.mcp.server import MCPStdioServer, read_mcp_message, write_mcp_message
from mindie_harness.rsi import complete, experiment_ledger, finish, init, next_step


@pytest.mark.tier1
def test_concurrent_mcp_stdio_dual_framing_zero_binding_and_cancellation(tmp_path: Path) -> None:
    profile = ProfileRef.resolve(
        "oc",
        plugin_root=tmp_path / "plugin",
        config_path=tmp_path / "cfg" / "oc.json",
        data_dir=tmp_path / "data",
    )
    tools = [
        {
            "name": "remote_bash",
            "inputSchema": {"type": "object", "properties": {"cmd": {"type": "string"}}, "required": ["cmd"]},
        },
        {
            "name": "remote_read",
            "annotations": {"readOnlyHint": True},
            # Even if a legacy manifest listed `request_nonce` as required, router strips it per P2.7!
            "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path", "request_nonce"]},
        },
        {
            "name": "remote_job_status",
            "inputSchema": {"type": "object", "properties": {"job_id": {"type": "string"}}, "required": ["job_id"]},
        },
        {
            "name": "knowledge_query",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "query": {"type": "string"},
                    "mode": {"type": "string"},
                    "request_nonce": {"type": "string"},
                    "_mindie_bind_id": {"type": "string"},
                    "context_file": {"type": "string"},
                },
                "required": ["query", "request_nonce", "_mindie_bind_id", "context_file"],
                "additionalProperties": False,
            },
        },
        {
            "name": "knowledge_explain",
            "inputSchema": {
                "type": "object",
                "properties": {"ref": {"type": "string"}},
                "required": ["ref"],
                "additionalProperties": False,
            },
        },
        {
            "name": "knowledge_distill",
            "inputSchema": {
                "type": "object",
                "properties": {"summary": {"type": "string"}, "request_nonce": {"type": "string"}},
                "required": ["summary", "request_nonce"],
                "additionalProperties": False,
            },
        },
    ]

    slow_lock = threading.Lock()
    slow_count = 0
    both_mutations_blocked = threading.Event()
    release_slow = threading.Event()

    def _handler(ctx: RequestContext, args: dict[str, Any]) -> dict[str, Any]:
        nonlocal slow_count
        if ctx.tool_name == "remote_bash":
            with slow_lock:
                slow_count += 1
                if slow_count >= 2:
                    both_mutations_blocked.set()
            while not release_slow.is_set():
                if ctx.cancel.is_set():
                    return {"content": [{"type": "text", "text": "cancelled"}], "isError": True}
                time.sleep(0.01)
            return {"content": [{"type": "text", "text": f"bash:{args['cmd']}"}], "isError": False}
        return {"content": [{"type": "text", "text": f"{ctx.tool_name}:ok:{ctx.session_id}"}], "isError": False}

    env_snapshot = dict(os.environ)
    cwd_snapshot = os.getcwd()

    c2s_r, c2s_w = os.pipe()
    s2c_r, s2c_w = os.pipe()
    router = MCPRouter(profile, surface="all", tools=tools, handler=_handler)
    server = MCPStdioServer(router, max_mutation_workers=2)

    srv_in = os.fdopen(c2s_r, "rb")
    srv_out = os.fdopen(s2c_w, "wb")
    cli_out = os.fdopen(c2s_w, "wb")
    cli_in = os.fdopen(s2c_r, "rb")

    responses: dict[str | int, tuple[dict[str, Any], str, float]] = {}
    resp_cv = threading.Condition()

    def _reader_loop() -> None:
        while True:
            msg, fmt = read_mcp_message(cli_in)
            if msg is None:
                break
            with resp_cv:
                responses[msg["id"]] = (msg, fmt, time.monotonic())
                resp_cv.notify_all()

    srv_thread = threading.Thread(target=lambda: server.serve(stdin=srv_in, stdout=srv_out), daemon=True)
    rdr_thread = threading.Thread(target=_reader_loop, daemon=True)
    srv_thread.start()
    rdr_thread.start()

    def _wait_id(req_id: str | int, timeout: float = 5.0) -> tuple[dict[str, Any], str]:
        end = time.monotonic() + timeout
        with resp_cv:
            while req_id not in responses:
                rem = end - time.monotonic()
                if rem <= 0:
                    raise TimeoutError(f"Timed out waiting for RPC {req_id}")
                resp_cv.wait(timeout=rem)
            msg, fmt, _ = responses[req_id]
            return msg, fmt

    try:
        # 1. Content-Length framing initialize + tools/list (all tools visible on cold start, correlation keys stripped!)
        write_mcp_message(cli_out, {"jsonrpc": "2.0", "id": "init-1", "method": "initialize", "params": {}}, "content-length")
        init_resp, init_fmt = _wait_id("init-1")
        assert init_fmt == "content-length"
        assert init_resp["result"]["serverInfo"]["name"] == "mindie-all"

        write_mcp_message(cli_out, {"jsonrpc": "2.0", "id": "list-1", "method": "tools/list", "params": {}}, "jsonl")
        list_resp, list_fmt = _wait_id("list-1")
        assert list_fmt == "jsonl"
        listed_names = [t["name"] for t in list_resp["result"]["tools"]]
        assert "knowledge_query" in listed_names
        assert "knowledge_distill" in listed_names
        read_schema = next(t["inputSchema"] for t in list_resp["result"]["tools"] if t["name"] == "remote_read")
        assert "request_nonce" not in read_schema["required"]
        kq_schema = next(t["inputSchema"] for t in list_resp["result"]["tools"] if t["name"] == "knowledge_query")
        assert kq_schema["required"] == ["query"]
        assert set(kq_schema["properties"]) == {"query", "mode"}

        # 2. Saturate ALL `max_mutation_workers=2` threads with two concurrent `remote_bash` calls!
        for slow_idx in (1, 2):
            write_mcp_message(
                cli_out,
                {
                    "jsonrpc": "2.0",
                    "id": f"bash-slow-{slow_idx}",
                    "method": "tools/call",
                    "params": {"name": "remote_bash", "arguments": {"cmd": f"sleep {slow_idx}"}},
                },
                "jsonl",
            )
        assert both_mutations_blocked.wait(timeout=3.0)

        for i in range(6):
            write_mcp_message(
                cli_out,
                {"jsonrpc": "2.0", "id": f"read-{i}", "method": "tools/call", "params": {"name": "remote_read", "arguments": {"path": f"/f/{i}"}}},
                "content-length" if i % 2 == 0 else "jsonl",
            )
        write_mcp_message(
            cli_out,
            {"jsonrpc": "2.0", "id": "status-1", "method": "tools/call", "params": {"name": "remote_job_status", "arguments": {"job_id": "j1"}}},
            "jsonl",
        )
        write_mcp_message(
            cli_out,
            {"jsonrpc": "2.0", "id": "kq-fastlane", "method": "tools/call", "params": {"name": "knowledge_query", "arguments": {"query": "tiling", "mode": "explore"}}},
            "jsonl",
        )
        write_mcp_message(
            cli_out,
            {"jsonrpc": "2.0", "id": "ke-fastlane", "method": "tools/call", "params": {"name": "knowledge_explain", "arguments": {"ref": "mindie://unit/1"}}},
            "content-length",
        )

        # With BOTH mutation workers blocked, all 6 reads + status + knowledge_query + knowledge_explain MUST finish on the fast lane!
        for i in range(6):
            r_msg, r_fmt = _wait_id(f"read-{i}", timeout=2.0)
            assert r_fmt == ("content-length" if i % 2 == 0 else "jsonl")
            assert r_msg["result"]["isError"] is False
        st_msg, _ = _wait_id("status-1", timeout=2.0)
        assert st_msg["result"]["isError"] is False
        kqf_msg, _ = _wait_id("kq-fastlane", timeout=2.0)
        assert kqf_msg["result"]["isError"] is False
        assert f"knowledge_query:ok:oc-conn-{router.connection_id[:12]}" in kqf_msg["result"]["content"][0]["text"]
        kef_msg, kef_fmt = _wait_id("ke-fastlane", timeout=2.0)
        assert kef_fmt == "content-length"
        assert kef_msg["result"]["isError"] is False
        assert f"knowledge_explain:ok:oc-conn-{router.connection_id[:12]}" in kef_msg["result"]["content"][0]["text"]
        assert "bash-slow-1" not in responses and "bash-slow-2" not in responses

        # 3. Cancel `bash-slow-1` via `notifications/cancelled`, then release `bash-slow-2`
        write_mcp_message(cli_out, {"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": "bash-slow-1"}}, "jsonl")
        bash1_msg, _ = _wait_id("bash-slow-1", timeout=2.0)
        assert bash1_msg["result"]["isError"] is True
        release_slow.set()
        bash2_msg, _ = _wait_id("bash-slow-2", timeout=2.0)
        assert bash2_msg["result"]["isError"] is False

        # 4. Silent default-on (`P2.7` / `P2.8`) cold-start `knowledge_*` with zero `_meta` & zero `admission.sqlite3`
        write_mcp_message(
            cli_out,
            {
                "jsonrpc": "2.0",
                "id": "kd-cold",
                "method": "tools/call",
                "params": {
                    "name": "knowledge_distill",
                    "arguments": {"summary": "x", "request_nonce": "legacy-nonce", "_mindie_bind_id": "legacy-bind"},
                },
            },
            "jsonl",
        )
        kd_msg, _ = _wait_id("kd-cold")
        assert kd_msg["result"]["isError"] is False
        assert f"knowledge_distill:ok:oc-conn-{router.connection_id[:12]}" in kd_msg["result"]["content"][0]["text"]
        assert not profile.admission_db.exists()  # Cold start never requires or creates `admission.sqlite3`!

        # Forged identity arguments in `arguments` remain strictly rejected!
        write_mcp_message(
            cli_out,
            {
                "jsonrpc": "2.0",
                "id": "k-forged",
                "method": "tools/call",
                "params": {"name": "knowledge_query", "arguments": {"query": "tiling", "session_id": "spoofed"}},
            },
            "jsonl",
        )
        kf_msg, _ = _wait_id("k-forged")
        assert kf_msg["result"]["isError"] is True
        assert kf_msg["result"]["structuredContent"]["reason"] == "forged_identity_argument"

        assert dict(os.environ) == env_snapshot
        assert os.getcwd() == cwd_snapshot
    finally:
        release_slow.set()
        cli_out.close()
        srv_thread.join(timeout=3.0)
        srv_in.close()
        srv_out.close()
        cli_in.close()


@pytest.mark.tier1
def test_owned_process_tree_reclaims_grandchild_on_timeout(tmp_path: Path) -> None:
    pid_file = tmp_path / "grandchild.pid"
    script = (
        "import subprocess, sys, time\n"
        f"p = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'])\n"
        f"open({str(pid_file)!r}, 'w').write(str(p.pid))\n"
        "sys.stdout.flush()\n"
        "time.sleep(30)\n"
    )
    with pytest.raises(TimeoutError) as exc_info:
        run_owned(
            ProcessSpec(argv=(sys.executable, "-c", script)),
            deadline=Deadline.from_timeout(0.35, cleanup_grace=0.15),
        )
    outcome = getattr(exc_info.value, "outcome", None)
    assert outcome is not None and outcome.execution == "unknown"

    if pid_file.is_file():
        gc_pid = int(pid_file.read_text().strip())
        from mindie_harness.mcp.receipts import process_boot_signature

        # Wait briefly for kernel process-group / Job teardown
        deadline = time.monotonic() + 1.5
        while time.monotonic() < deadline and process_boot_signature(gc_pid) is not None:
            time.sleep(0.05)
        assert process_boot_signature(gc_pid) is None


@pytest.mark.tier1
def test_rsi_loop_and_ledger_across_linked_git_worktree(tmp_path: Path) -> None:
    base_repo = tmp_path / "base_repo"
    base_repo.mkdir()
    git_env = {
        **os.environ,
        "GIT_AUTHOR_NAME": "Test",
        "GIT_AUTHOR_EMAIL": "t@example.com",
        "GIT_COMMITTER_NAME": "Test",
        "GIT_COMMITTER_EMAIL": "t@example.com",
    }
    subprocess.run(["git", "init", "-q", str(base_repo)], env=git_env, check=True)
    (base_repo / "kernel.py").write_text("def op(x):\n    return x + 1\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(base_repo), "add", "kernel.py"], env=git_env, check=True)
    subprocess.run(["git", "-C", str(base_repo), "commit", "-q", "-m", "init"], env=git_env, check=True)

    # Create a real linked Git worktree where `.git` is a file (`gitdir: ...`)!
    cand_wt = tmp_path / "cand_worktree"
    subprocess.run(["git", "-C", str(base_repo), "worktree", "add", "-q", "-b", "cand", str(cand_wt)], env=git_env, check=True)
    assert (cand_wt / ".git").is_file()
    wt_info = experiment_ledger.resolve_git_worktree_info(cand_wt)
    assert wt_info is not None and wt_info["is_linked_worktree"] is True

    state_file = tmp_path / "campaign" / "rsi-loop.json"
    ledger_file = tmp_path / "campaign" / "experiment-ledger.jsonl"
    progress_file = tmp_path / "campaign" / "PROGRESS.md"
    progress_file.parent.mkdir(parents=True)
    progress_file.write_text("# RSI Progress: matmul\n\nin_flight_runs: run-recover-01\n", encoding="utf-8")

    s0 = init(
        state_file,
        task_id="matmul",
        ledger_path=ledger_file,
        baseline_repo=base_repo,
        direction="maximize",
        repetitions=2,
        target_speedup=1.05,
        progress=progress_file,
    )
    assert s0["step"] == "profile"

    # Mutate candidate linked worktree
    (cand_wt / "kernel.py").write_text("def op(x):\n    return (x + 1)  # tiled\n", encoding="utf-8")
    res_rec, code_rec = complete(
        state_file,
        "record",
        {
            "bottleneck_summary": {"bound": "memory", "aic_pct": 22.0},
            "profile_ref": "prof-001",
            "unit_refs": [],
            "skipped_reason": "cold profile control",
            "exp_id": "exp-01",
            "hypothesis": "L1 tile prefetch",
            "candidate_repo": str(cand_wt),
            "scope_conditions": {"chip": "910B"},
            "factors": ["tiling"],
            "run_ids": ["r1", "r2"],
            "baseline": [{"status": "completed", "metric": 100.0}, {"status": "completed", "metric": 100.0}],
            "candidate": [{"status": "completed", "metric": 115.0}, {"status": "completed", "metric": 116.0}],
            "correctness": "passed",
            "compile_ok": True,
            "card_seconds": 4.5,
            "note": "verified 1.155x on linked worktree",
        },
    )
    assert code_rec == 0
    assert res_rec["baseline"]["exp_id"] == "exp-01"
    assert "run-recover-01" in progress_file.read_text(encoding="utf-8")

    # Proposing the exact same source digest again hits duplicate gate (`BLOCKED == 3`)
    (cand_wt / "kernel.py").write_text("def op(x):\n    return (x + 1)  # v2\n", encoding="utf-8")
    _, _ = complete(
        state_file,
        "record",
        {
            "exp_id": "exp-02",
            "hypothesis": "bad unroll",
            "candidate_repo": str(cand_wt),
            "scope_conditions": {"chip": "910B"},
            "factors": ["unroll"],
            "run_ids": ["r3", "r4"],
            "baseline": [{"status": "completed", "metric": 115.0}, {"status": "completed", "metric": 115.0}],
            "candidate": [{"status": "completed", "metric": 95.0}, {"status": "completed", "metric": 95.0}],
            "correctness": "passed",
            "compile_ok": True,
        },
    )
    dup_out, dup_code = complete(
        state_file,
        "propose",
        {
            "exp_id": "exp-02-dup",
            "hypothesis": "repeat refuted source",
            "candidate_repo": str(cand_wt),
            "scope_conditions": {"chip": "910B"},
        },
    )
    assert dup_code == 3 and dup_out["blocked"] is True

    # CLI module entrypoint smoke (`python -m mindie_harness.rsi.rsi_loop` & `experiment_ledger`)
    cli_next = subprocess.run(
        [sys.executable, "-m", "mindie_harness.rsi.rsi_loop", "next", "--state", str(state_file)],
        capture_output=True,
        text=True,
        check=True,
    )
    assert json.loads(cli_next.stdout)["status"] == "running"
    cli_fp = subprocess.run(
        [sys.executable, "-m", "mindie_harness.rsi.experiment_ledger", "fingerprint", str(cand_wt)],
        capture_output=True,
        text=True,
        check=True,
    )
    assert json.loads(cli_fp.stdout)["source_digest"].startswith("sha256:")
    fin = finish(state_file, "campaign complete")
    assert fin["status"] == "finished"
    assert next_step(state_file)["status"] == "finished"


@pytest.mark.tier1
def test_out_of_tree_wheel_install_and_zero_dependency_smoke(tmp_path: Path) -> None:
    uv = shutil.which("uv")
    if not uv:
        pytest.skip("uv not installed")
    repo_root = Path(__file__).resolve().parents[2]
    wheel_dir = tmp_path / "wheels"
    subprocess.run([uv, "build", "--wheel", "--out-dir", str(wheel_dir), str(repo_root)], check=True, timeout=60)
    wheels = list(wheel_dir.glob("mindie_harness-*.whl"))
    assert len(wheels) == 1

    venv_dir = tmp_path / "isolated_venv"
    subprocess.run([uv, "venv", "--python", sys.executable, str(venv_dir)], check=True, timeout=60)
    py = venv_dir / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    subprocess.run([uv, "pip", "install", "--python", str(py), "--no-deps", str(wheels[0])], check=True, timeout=60)

    blank_cwd = tmp_path / "blank_cwd"
    blank_cwd.mkdir()
    ver = subprocess.run([str(py), "-I", "-m", "mindie_harness.cli", "--version"], cwd=str(blank_cwd), capture_output=True, text=True, check=True)
    assert ver.stdout.strip() == f"mindie-harness {__version__}"

    insp = subprocess.run([str(py), "-I", "-m", "mindie_harness.cli", "inspect", "--host", "codex"], cwd=str(blank_cwd), capture_output=True, text=True, check=True)
    insp_doc = json.loads(insp.stdout)
    assert insp_doc["api_version"] == 1 and insp_doc["host"] == "codex"
