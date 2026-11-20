"""Gate Layer 1 substrate & full-stack contract selftest (`mindie-selftest/1`).

[Role]
Implements `run_selftest(mode="candidate"|"full")`:
- `candidate` (`< 2.5s` typical, daemon-free): runs inside `prepare_candidate_runtime`
  before `runtime.json` (`validated`) is written, verifying Windows PE `Subsystem == 2`,
  dual-framing (`Content-Length` + `jsonl`) MCP stdio handshake, ephemeral in-thread
  `knowledge` loopback query (`0` SQLite side effects), `doctor`/`diagnostics_status`,
  `remote_auth(status)`, and installed component CLIs.
- `full` (`< 25s`, zero-mock live stdio): spawns real resident MCP server processes
  across Topology 1 (`.venv`) and Topology 2 (stdlib bootstrap -> `.venv` child IPC),
  exercising a real local Git `mindie-graded-unit/1` `knowledge_sync -> query ->
  explain(refs=...) -> feedback -> distill` lifecycle (unleased, leased, revoked),
  all 8 sibling components, `debugger` `stdin_text`, RSI `stdin_json`, and Codex
  `remote_write_stdin(session_id=...)`.

[Invariants]
- 100% pure Python stdlib at top-level import (`HAR-ABI`).
- Fail-closed fullstack verification: `--mode full` (and `--mode candidate` when
  `MINDIE_REQUIRE_FULLSTACK=1`) NEVER skips missing sibling packages.
- Strictly isolated inside `tempfile.TemporaryDirectory` (`HOME`, `USERPROFILE`,
  `APPDATA`, `LOCALAPPDATA`, `XDG_*`, `MINDIE_*`, `REMOTE_DEV_*`, `TMPDIR`);
  any `knowledge` service started in `--mode full` is retired in `finally:`.

[Timeouts & Locks]
- Bounded by `Deadline` (`15s` default for `candidate`, `90s` default for `full`).

[Side-Effect Policy]
- Writes exclusively inside a disposable `TemporaryDirectory` cleaned up before return.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any, Callable

from .atomic import atomic_write_json, atomic_write_text
from .mcp.gateway import ManagedMCPAdapter
from .mcp.router import CORRELATION_STRIP_KEYS, MCPRouter
from .mcp.server import MCPStdioServer, read_mcp_message, write_mcp_message
from .paths import HarnessError, ProfileRef, resolve_base_cpython, same_interpreter
from .process.supervisor import Deadline, ProcessSpec, run_owned
from .process.win32 import verify_gui_subsystem
from .runtime.knowledge_binding import ensure_knowledge_binding
from .sharing import configure_sharing

SELFTEST_SCHEMA = "mindie-selftest/1"
_CREATE_NO_WINDOW = 0x08000000 if os.name == "nt" else 0
FULLSTACK_MODULES: tuple[str, ...] = (
    "mindie_harness",
    "mindie_knowledge",
    "remote_dev",
    "mindie_diagnostics",
    "mindie_debugger",
    "mindie_profiler",
    "mindie_sim",
    "npu_top",
    "mindie_coordinator",
)


def _has_mod(name: str) -> bool:
    try:
        return importlib.util.find_spec(name) is not None
    except (ImportError, AttributeError, ValueError):
        return False


def _sandbox_env(root: Path, base_env: dict[str, str] | None = None) -> dict[str, str]:
    src = dict(os.environ if base_env is None else base_env)
    home = root / "home"
    cfg = root / "cfg"
    data = root / "data"
    diag = root / "diag"
    rstate = root / "remote-state"
    rauth = root / "remote-auth"
    tmp = root / "tmp"
    for d in (home, cfg, data, diag, rstate, rauth, tmp):
        d.mkdir(parents=True, exist_ok=True)
    for drop in (
        "MINDIE_AGENT_CONFIG",
        "MINDIE_DIAGNOSTICS_CONFIG",
        "MINDIE_KNOWLEDGE_ROOT",
        "MINDIE_SESSION_ID",
        "REMOTE_DEV_SESSION_ID",
        "CODEX_THREAD_ID",
        "CLAUDE_SESSION_ID",
        "GH_TOKEN",
        "GITHUB_TOKEN",
    ):
        src.pop(drop, None)
    src.update(
        {
            "HOME": str(home),
            "USERPROFILE": str(home),
            "APPDATA": str(root / "appdata"),
            "LOCALAPPDATA": str(root / "localappdata"),
            "XDG_CONFIG_HOME": str(root / "xdg-cfg"),
            "XDG_DATA_HOME": str(root / "xdg-data"),
            "XDG_STATE_HOME": str(root / "xdg-state"),
            "MINDIE_CONFIG_HOME": str(cfg),
            "MINDIE_DATA_HOME": str(data),
            "MINDIE_DIAGNOSTICS_ROOT": str(diag),
            "MINDIE_REMOTE_STATE_DIR": str(rstate),
            "REMOTE_DEV_STATE_DIR": str(rstate),
            "REMOTE_DEV_AUTH_DIR": str(rauth),
            "TMPDIR": str(tmp),
            "TEMP": str(tmp),
            "TMP": str(tmp),
            "PYTHONUTF8": "1",
        }
    )
    return src


class _LiveMCPClient:
    """Zero-mock stdio JSON-RPC client speaking both `Content-Length` and `jsonl`."""

    def __init__(self, argv: list[str], *, env: dict[str, str], cwd: Path) -> None:
        self._proc = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=str(cwd),
            env=env,
            creationflags=_CREATE_NO_WINDOW,
        )
        self._next_id = 1

    def request(self, method: str, params: dict[str, Any] | None = None, *, framing: str = "content-length") -> dict[str, Any]:
        assert self._proc.stdin is not None and self._proc.stdout is not None
        req_id = self._next_id
        self._next_id += 1
        msg: dict[str, Any] = {"jsonrpc": "2.0", "id": req_id, "method": method}
        if params is not None:
            msg["params"] = params
        write_mcp_message(self._proc.stdin, msg, framing)
        reply, reply_framing = read_mcp_message(self._proc.stdout)
        if reply is None:
            err_tail = (self._proc.stderr.read() if self._proc.stderr else b"").decode("utf-8", errors="replace")[-600:]
            raise RuntimeError(f"MCP server closed stdout unexpectedly (rc={self._proc.poll()}): {err_tail}")
        if reply_framing != framing:
            raise AssertionError(f"Framing mismatch: sent {framing}, received {reply_framing}")
        if reply.get("id") != req_id:
            raise AssertionError(f"Mismatched JSON-RPC id: expected {req_id}, got {reply.get('id')}")
        if "error" in reply:
            raise RuntimeError(f"JSON-RPC protocol error: {reply['error']}")
        return dict(reply["result"])

    def call_tool(self, name: str, arguments: dict[str, Any] | None = None, *, framing: str = "content-length", meta: dict[str, Any] | None = None) -> dict[str, Any]:
        params: dict[str, Any] = {"name": name, "arguments": arguments or {}}
        if meta is not None:
            params["_meta"] = meta
        return self.request("tools/call", params, framing=framing)

    def close(self) -> None:
        try:
            if self._proc.stdin:
                self._proc.stdin.close()
            self._proc.wait(timeout=5.0)
        except Exception:
            self._proc.kill()
            self._proc.wait(timeout=2.0)
        finally:
            for stream in (self._proc.stdout, self._proc.stderr):
                if stream:
                    stream.close()


def _record_check(checks: list[dict[str, Any]], name: str, fn: Callable[[], dict[str, Any] | None]) -> None:
    t0 = time.monotonic()
    try:
        detail = fn() or {}
        checks.append({"name": name, "status": "passed", "elapsed_ms": int((time.monotonic() - t0) * 1000), **detail})
    except TimeoutError:
        raise
    except Exception as exc:
        checks.append(
            {
                "name": name,
                "status": "failed",
                "elapsed_ms": int((time.monotonic() - t0) * 1000),
                "error_type": type(exc).__name__,
                "error": str(exc)[:600],
            }
        )


def _create_graded_corpus_git(corpus_dir: Path, env: dict[str, str]) -> str:
    from mindie_knowledge.graded.index import RoutingIndex, read_units

    git_bin = shutil.which("git", path=env.get("PATH"))
    if not git_bin:
        raise RuntimeError("`git` binary is required on PATH for selftest --mode full corpus fixture")
    corpus_dir.mkdir(parents=True, exist_ok=True)
    unit_dir = corpus_dir / "_common"
    unit_dir.mkdir(parents=True, exist_ok=True)
    unit_md = (
        "---\n"
        "category: axiom\n"
        "conditions:\n"
        "  framework:\n"
        "  - vllm-ascend\n"
        "domain_path: _common\n"
        "evidence_strength: software_contract\n"
        "id: unit-vllm-ascend-aclgraph-smoke-001\n"
        "inherits_from: []\n"
        "provenance:\n"
        "  evidence_refs:\n"
        "  - https://github.com/mindie-agent/harness\n"
        f"  source_digest: {'a' * 64}\n"
        f"  source_locator: mindie-agent/harness@{'b' * 40}:mindie_harness/selftest.py\n"
        "  source_type: runtime_architecture_specification\n"
        "  supersedes: []\n"
        "revision: 1\n"
        "schema: mindie-graded-unit/1\n"
        "tier: L1\n"
        "title: ACLGraph stream capture smoke invariant\n"
        "triggers:\n"
        "  error_signatures:\n"
        "  - aclgraph capture stream mismatch\n"
        "  keywords:\n"
        "  - aclgraph\n"
        "  - capture\n"
        "  - stream\n"
        "---\n"
        "# ACLGraph stream capture smoke invariant\n\n"
        "## Condition\n\nWhen capturing ACLGraph execution streams on Ascend NPU.\n\n"
        "## Constraint\n\nKeep stream capture deterministic and buffer addresses stable.\n\n"
        "## Rationale\n\nPrevents replay address drift.\n\n"
        "## Evidence\n\nVerified by Gate Layer 1 fullstack selftest.\n"
    )
    atomic_write_text(unit_dir / "unit-vllm-ascend-aclgraph-smoke-001.md", unit_md)
    atomic_write_json(
        corpus_dir / "publication-contract.json",
        {
            "domain": "vllm-ascend",
            "formats": {
                "feedback": "mindie-graded-feedback/1",
                "routing": "mindie-routing-manifest/1",
                "unit": "mindie-graded-unit/1",
            },
            "review": {"check": "publication-head", "contract": "mindie-content-review/2"},
            "schema": "mindie-publication-contract/2",
            "validator": {"repository": "mindie-agent/knowledge", "revision": "c" * 40},
        },
    )
    manifest = RoutingIndex(read_units(corpus_dir)).manifest()
    atomic_write_json(corpus_dir / "index" / "routing-manifest.json", manifest)

    def _git(*args: str) -> str:
        out = run_owned(
            ProcessSpec(argv=(git_bin, *args), cwd=corpus_dir, env=env, role="foreground"),
            deadline=Deadline.from_timeout(15.0),
        )
        return (out.stdout or "").strip()

    _git("init", "-q")
    _git("checkout", "-q", "-B", "main")
    _git("config", "user.email", "selftest@mindie.local")
    _git("config", "user.name", "MindIE Selftest")
    _git("add", ".")
    _git("commit", "-q", "-m", "selftest graded corpus")
    return _git("rev-parse", "HEAD")


def _run_candidate_in_process(require_fullstack: bool, deadline: Deadline) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="mindie-selftest-cand-", ignore_cleanup_errors=(os.name == "nt")) as tmp_raw:
        root = Path(tmp_raw)
        saved_env = dict(os.environ)
        env = _sandbox_env(root)
        os.environ.clear()
        os.environ.update(env)
        try:
            if require_fullstack:
                missing_mods = [m for m in FULLSTACK_MODULES if not _has_mod(m)]
                if missing_mods:
                    return [
                        {
                            "name": "fullstack_packages_present",
                            "status": "failed",
                            "elapsed_ms": 0,
                            "error_type": "ModuleNotFoundError",
                            "error": f"Missing required fullstack modules: {missing_mods}",
                        }
                    ]
                checks.append(
                    {
                        "name": "fullstack_packages_present",
                        "status": "passed",
                        "elapsed_ms": 0,
                        "modules": list(FULLSTACK_MODULES),
                    }
                )
            if os.name == "nt":
                pyw = Path(sys.executable).with_name("pythonw.exe")
                if pyw.is_file():
                    _record_check(checks, "win32_gui_subsystem", lambda: {"pythonw": str(verify_gui_subsystem(pyw))})

            profile = ProfileRef.resolve("codex", plugin_root=root / "plugin", config_path=root / "cfg" / "codex.json", data_dir=root / "data", env=env)
            atomic_write_json(profile.config_path, {"host": "codex", "python": sys.executable, "source_root": str(profile.plugin_root)})

            ephemeral_service: Any = None
            ephemeral_thread: threading.Thread | None = None
            ephemeral_store: Any = None
            ephemeral_consumer: Any = None
            if _has_mod("mindie_knowledge"):
                kb = ensure_knowledge_binding(profile, python_executable=sys.executable)
                assert kb["status"] == "configured", kb
                from mindie_knowledge.loop.activation import Admission
                from mindie_knowledge.loop.cli import config_at, connection_path
                from mindie_knowledge.loop.engine import Engine
                from mindie_knowledge.loop.lifecycle import acquire_consumer, config_fingerprint
                from mindie_knowledge.loop.store import Store
                from mindie_knowledge.loop.transport import Service

                eng_path = Path(kb["engine_config"])
                eng_doc = config_at(eng_path)
                c_path = connection_path(eng_doc)
                ephemeral_consumer = acquire_consumer(eng_path, eng_doc)
                ephemeral_store = Store(eng_doc["root"], eng_doc["domain"])
                ephemeral_service = Service(
                    Engine(ephemeral_store),
                    connection_path=c_path,
                    admission=Admission(eng_doc["admission_path"]),
                    config_path=eng_path,
                    config_fingerprint=config_fingerprint(eng_path, eng_doc),
                )
                ephemeral_thread = threading.Thread(target=ephemeral_service.serve, daemon=True)
                ephemeral_thread.start()
                wait_ready = time.monotonic() + 5.0
                while time.monotonic() < wait_ready and not c_path.is_file():
                    time.sleep(0.01)

            try:
                def _check_mcp_core() -> dict[str, Any]:
                    adapter = ManagedMCPAdapter("codex", plugin_root=profile.plugin_root, config_path=profile.config_path, data_dir=profile.data_dir)
                    router = MCPRouter(
                        profile,
                        surface="all",
                        tools=adapter.mcp_tools("all", profile),
                        handler=lambda ctx, args: adapter.dispatch_tool(ctx, args, profile),
                        session_extractor=adapter.extract_session_identity,
                        base_env=env,
                    )
                    in_buf, out_buf = io.BytesIO(), io.BytesIO()
                    write_mcp_message(in_buf, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}, "content-length")
                    write_mcp_message(in_buf, {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}, "jsonl")
                    write_mcp_message(in_buf, {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "mindie_status", "arguments": {}}}, "content-length")
                    in_buf.seek(0)
                    MCPStdioServer(router).serve(stdin=in_buf, stdout=out_buf)
                    out_buf.seek(0)
                    r1, f1 = read_mcp_message(out_buf)
                    r2, f2 = read_mcp_message(out_buf)
                    r3, f3 = read_mcp_message(out_buf)
                    assert f1 == "content-length" and f2 == "jsonl" and f3 == "content-length"
                    tools_list = (r2 or {}).get("result", {}).get("tools", [])
                    for t in tools_list:
                        req = (t.get("inputSchema") or {}).get("required") or []
                        assert not CORRELATION_STRIP_KEYS.intersection(req), t["name"]
                    st_res = (r3 or {}).get("result", {})
                    assert st_res.get("isError") is False
                    assert str(st_res["structuredContent"]["session_id"]).startswith("codex-conn-")

                    if _has_mod("mindie_diagnostics"):
                        doc = router.call_tool({"id": "d1", "params": {"name": "mindie_doctor", "arguments": {"probe_remote": False}}})
                        assert doc.get("isError") is False and doc["structuredContent"]["schema"] == "mindie-doctor/1", doc
                        ds = router.call_tool({"id": "d2", "params": {"name": "diagnostics_status", "arguments": {}}})
                        assert ds.get("isError") is False, ds
                    if _has_mod("mindie_knowledge"):
                        kq = router.call_tool({"id": "k1", "params": {"name": "knowledge_query", "arguments": {"query": "aclgraph", "domain": "vllm-ascend"}}})
                        assert kq.get("isError") is False and kq["structuredContent"]["results"] == [], kq
                        assert not profile.admission_db.exists(), "Public query created admission.sqlite3"
                    if _has_mod("remote_dev"):
                        ra = router.call_tool(
                            {
                                "id": "r1",
                                "params": {
                                    "name": "remote_auth",
                                    "arguments": {"action": "status", "host": "127.0.0.1", "port": 22},
                                },
                            }
                        )
                        assert ra.get("isError") is False, ra
                    return {"tool_count": len(tools_list)}

                _record_check(checks, "dual_framing_mcp_and_inproc_tools", _check_mcp_core)

                def _check_clis() -> dict[str, Any]:
                    adapter = ManagedMCPAdapter("codex", plugin_root=profile.plugin_root, config_path=profile.config_path, data_dir=profile.data_dir)
                    router = MCPRouter(
                        profile,
                        surface="tools",
                        tools=adapter.mcp_tools("tools", profile),
                        handler=lambda ctx, args: adapter.dispatch_tool(ctx, args, profile),
                        base_env=env,
                    )
                    cli_matrix = [
                        ("rsi_loop", "mindie_harness", ["--help"]),
                        ("experiment_ledger", "mindie_harness", ["--help"]),
                        ("sim", "mindie_sim", ["extensions", "list"]),
                        ("profiler", "mindie_profiler", ["--version"]),
                        ("debugger", "mindie_debugger", ["decode-code", "507015"]),
                        ("coordinator", "mindie_coordinator", ["task-server", "--describe"]),
                        ("npu_top", "npu_top", ["--version"]),
                    ]
                    active = [
                        (tname, argv)
                        for tname, mod, argv in cli_matrix
                        if (mod == "mindie_harness" or _has_mod(mod))
                    ]

                    def _invoke_one(pair: tuple[str, list[str]]) -> str:
                        tname, argv = pair
                        res = router.call_tool({"id": f"c-{tname}", "params": {"name": tname, "arguments": {"argv": argv}}})
                        if res.get("isError") is True:
                            raise RuntimeError(f"{tname} failed: {res.get('structuredContent')}")
                        return tname

                    with ThreadPoolExecutor(max_workers=min(8, max(1, len(active)))) as pool:
                        ran = list(pool.map(_invoke_one, active))
                    return {"components_verified": sorted(ran)}

                if deadline.remaining() > 1.0:
                    _record_check(checks, "component_fast_clis", _check_clis)
            finally:
                if ephemeral_service is not None:
                    ephemeral_service.close()
                    if ephemeral_thread is not None:
                        ephemeral_thread.join(timeout=5.0)
                if ephemeral_store is not None:
                    ephemeral_store.close()
                if ephemeral_consumer is not None:
                    ephemeral_consumer.release()
        finally:
            os.environ.clear()
            os.environ.update(saved_env)
    return checks


def _run_full_in_process(deadline: Deadline) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    missing = [m for m in FULLSTACK_MODULES if not _has_mod(m)]
    if missing:
        return [
            {
                "name": "fullstack_packages_present",
                "status": "failed",
                "elapsed_ms": 0,
                "error_type": "ModuleNotFoundError",
                "error": f"Missing required fullstack modules: {missing}",
            }
        ]
    checks.append({"name": "fullstack_packages_present", "status": "passed", "elapsed_ms": 0, "modules": list(FULLSTACK_MODULES)})

    with tempfile.TemporaryDirectory(prefix="mindie-selftest-full-", ignore_cleanup_errors=(os.name == "nt")) as tmp_raw:
        root = Path(tmp_raw)
        env = _sandbox_env(root)
        ws = root / "workspace"
        ws.mkdir(parents=True, exist_ok=True)
        profile = ProfileRef.resolve("codex", plugin_root=root / "plugin", config_path=root / "cfg" / "codex.json", data_dir=root / "data", env=env)
        atomic_write_json(profile.config_path, {"host": "codex", "python": sys.executable, "source_root": str(profile.plugin_root)})

        saved_env = dict(os.environ)
        os.environ.clear()
        os.environ.update(env)
        active_eng_path: Path | None = None
        mcp_t1: _LiveMCPClient | None = None
        mcp_t2: _LiveMCPClient | None = None
        try:
            if os.name == "nt":
                pyw = Path(sys.executable).with_name("pythonw.exe")
                _record_check(checks, "win32_gui_subsystem", lambda: {"pythonw": str(verify_gui_subsystem(pyw))})

            # Provision 9-domain knowledge binding + local Git corpus feed
            corpus_dir = root / "corpus-vllm-ascend"
            head_sha = _create_graded_corpus_git(corpus_dir, env)
            kb = ensure_knowledge_binding(profile, python_executable=sys.executable)
            assert kb["status"] == "configured", kb
            eng_doc = json.loads(Path(kb["engine_config"]).read_text(encoding="utf-8"))
            eng_doc["feeds"] = [
                {
                    "domain": "vllm-ascend",
                    "repository": "mindie-agent/knowledge-vllm-ascend",
                    "url": corpus_dir.as_uri(),
                    "ref": "main",
                }
            ]
            feed_text = json.dumps(eng_doc, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
            feed_hash = hashlib.sha256(feed_text.encode("utf-8")).hexdigest()[:20]
            active_eng_path = profile.config_path.parent / "engines" / "codex" / feed_hash / "vllm-ascend.engine.json"
            atomic_write_text(active_eng_path, feed_text)
            from mindie_knowledge.loop.handoff import prepare_schema

            prepare_schema(active_eng_path)
            cfg_doc = json.loads(profile.config_path.read_text(encoding="utf-8"))
            cfg_doc["engine_config"] = str(active_eng_path)
            cfg_doc["domain_configs"]["vllm-ascend"] = str(active_eng_path)
            atomic_write_json(profile.config_path, cfg_doc)
            configure_sharing(profile, choice="local-only", project_roots=[ws])

            # Start Topology 1 resident MCP server
            t1_sites = [Path(sys.executable).parent.parent / "Lib" / "site-packages", *(Path(sys.executable).parent.parent / "lib").glob("python*/site-packages")]
            if any((s / "mindie_harness" / "cli.py").is_file() for s in t1_sites if s.is_dir()):
                t1_cmd = [sys.executable, "-I", "-X", "utf8", "-m", "mindie_harness.cli", "--host", "codex", "--config", str(profile.config_path), "--data-dir", str(profile.data_dir), "mcp", "all"]
            else:
                t1_cmd = [sys.executable, "-I", "-X", "utf8", "-c", "import sys; sys.path.append(sys.argv.pop(1)); from mindie_harness.cli import main; raise SystemExit(main())", str(Path(__file__).resolve().parents[1]), "--host", "codex", "--config", str(profile.config_path), "--data-dir", str(profile.data_dir), "mcp", "all"]
            mcp_t1 = _LiveMCPClient(t1_cmd, env=env, cwd=ws)

            def _t1_core_and_diag() -> dict[str, Any]:
                assert mcp_t1 is not None
                init = mcp_t1.request("initialize", {}, framing="content-length")
                mcp_t1.request("ping", {}, framing="jsonl")
                tlist = mcp_t1.request("tools/list", {}, framing="content-length")["tools"]
                names = {t["name"] for t in tlist}
                for req_tool in ("mindie_status", "mindie_doctor", "knowledge_query", "knowledge_explain", "knowledge_sync", "sim", "profiler", "debugger", "coordinator", "npu_top", "rsi_loop", "experiment_ledger", "remote_auth", "remote_write_stdin"):
                    assert req_tool in names, f"Missing tool {req_tool}"
                st = mcp_t1.call_tool("mindie_status", {}, framing="jsonl")
                assert st["isError"] is False and str(st["structuredContent"]["session_id"]).startswith("codex-conn-")
                intr = mcp_t1.call_tool("mindie_interrupt", {}, framing="content-length")
                assert intr["isError"] is False
                doc = mcp_t1.call_tool("mindie_doctor", {"probe_remote": False})
                assert doc["isError"] is False and doc["structuredContent"]["schema"] == "mindie-doctor/1"
                dstat = mcp_t1.call_tool("diagnostics_status", {})
                assert dstat["isError"] is False, dstat
                dstat_doc = json.loads(dstat["structuredContent"]["stdout"])
                assert dstat_doc["status"] == "configured" and dstat_doc["enabled"] is False, dstat_doc
                diag_logs = root / "diag-logs"
                diag_logs.mkdir(exist_ok=True)
                bundle_out = root / "bundle.json"
                dbun = mcp_t1.call_tool("diagnostics_bundle", {"argv": ["--root", str(diag_logs), "--output", str(bundle_out)]})
                assert dbun["isError"] is False and bundle_out.is_file()
                json.loads(bundle_out.read_text(encoding="utf-8"))
                return {"protocolVersion": init["protocolVersion"], "tool_count": len(tlist)}

            _record_check(checks, "topology1_mcp_framing_doctor_diagnostics", _t1_core_and_diag)

            def _t1_knowledge_lifecycle() -> dict[str, Any]:
                assert mcp_t1 is not None
                sync_res = mcp_t1.call_tool("knowledge_sync", {"domain": "vllm-ascend"})
                assert sync_res["isError"] is False, sync_res
                assert sync_res["structuredContent"]["results"][0]["commit"] == head_sha

                q_res = mcp_t1.call_tool(
                    "knowledge_query",
                    {
                        "query": "aclgraph capture stream",
                        "domain": "vllm-ascend",
                        "conditions": {"framework": "vllm-ascend"},
                        "token_budget": 8000,
                    },
                    framing="jsonl",
                )
                assert q_res["isError"] is False, q_res
                results = q_res["structuredContent"]["results"]
                assert results and results[0]["id"] == "unit-vllm-ascend-aclgraph-smoke-001", q_res
                assert not profile.admission_db.exists(), "Public sync/query created admission.sqlite3"

                unit_ref = f"mindie://vllm-ascend/{results[0]['id']}@{results[0]['revision']}" if not str(results[0].get("ref") or "").startswith("mindie://") else str(results[0]["ref"])
                local_ref = f"{results[0]['id']}@{results[0]['revision']}"
                ex_res = mcp_t1.call_tool("knowledge_explain", {"refs": [local_ref], "token_budget": 8000})
                assert ex_res["isError"] is False, ex_res
                assert "ACLGraph" in json.dumps(ex_res["structuredContent"])

                fb_ref = str(results[0].get("feedback_ref") or f"mindie://vllm-ascend/units/{results[0]['id']}@{results[0]['revision']}")
                fb_res = mcp_t1.call_tool("knowledge_feedback", {"ref": fb_ref, "rating": "up", "reason": "selftest verified"})
                assert fb_res["isError"] is False, fb_res

                # 1. Unleased distill without authorized cwd -> knowledge_authorization_required
                d_unauth = mcp_t1.call_tool("knowledge_distill", {"inputs": [], "task_state": "completed"}, meta={"session_id": "selftest-unauth"})
                assert d_unauth["isError"] is True and d_unauth["structuredContent"]["reason"] == "knowledge_authorization_required", d_unauth

                # 2. Leased distill -> succeeds cleanly
                from mindie_knowledge.loop.activation import Admission

                adm = Admission(profile.admission_db)
                adm.activate("selftest-leased", project_root=str(ws), root_session="selftest-leased", not_before=0.0)
                d_ok = mcp_t1.call_tool("knowledge_distill", {"inputs": [], "task_state": "completed"}, meta={"session_id": "selftest-leased"})
                assert d_ok["isError"] is False, d_ok

                # 3. Revoked session -> NEVER revived even if PreToolUse bind supplies authorized cwd!
                adm.deactivate("selftest-leased")
                d_rev = mcp_t1.call_tool("knowledge_distill", {"inputs": [], "task_state": "completed"}, meta={"session_id": "selftest-leased"})
                assert d_rev["isError"] is True and d_rev["structuredContent"]["reason"] == "knowledge_authorization_required", d_rev
                return {"synced_commit": head_sha, "unit_ref": unit_ref}

            _record_check(checks, "topology1_knowledge_sync_query_explain_feedback_distill", _t1_knowledge_lifecycle)

            def _t1_components_and_remote() -> dict[str, Any]:
                assert mcp_t1 is not None
                sim_res = mcp_t1.call_tool("sim", {"argv": ["compose", "--model", "qwen3-30b-a3b", "--hardware", "a2", "--layers", "1"]})
                assert sim_res["isError"] is False, sim_res

                prof_dir = root / "prof"
                prof_dir.mkdir(exist_ok=True)
                atomic_write_text(
                    prof_dir / "kernel_details.csv",
                    "Name,Type,Accelerator Core,Start Time(us),Duration(us)\nMatMulV2,MatMul,AI_CORE,10.0,50.0\nAdd,Add,AI_VECTOR_CORE,65.0,10.0\n",
                )
                prof_res = mcp_t1.call_tool("profiler", {"argv": ["analyze", "--root", str(prof_dir), "--full-range"]})
                assert prof_res["isError"] is False, prof_res

                dbg_res = mcp_t1.call_tool(
                    "debugger",
                    {
                        "argv": ["triage"],
                        "stdin_text": "[ERROR] RUNTIME(1234,python3):2026-01-01-00:00:00.000.000 [engine.cc:10]1234 ReportExceptProc:Task exception! retCode=0x91, [model stream execute timeout]\n",
                    },
                )
                assert dbg_res["isError"] is False, dbg_res

                coord1 = mcp_t1.call_tool("coordinator", {"argv": ["task-server", "--describe"]})
                coord2 = mcp_t1.call_tool("coordinator", {"argv": ["hosts", "--action", "list"]})
                assert coord1["isError"] is False and coord2["isError"] is False

                nt_ver = mcp_t1.call_tool("npu_top", {"argv": ["--version"]})
                assert nt_ver["isError"] is False, nt_ver
                nt_default = mcp_t1.call_tool("npu_top", {})
                assert nt_default["isError"] is False or (
                    nt_default["structuredContent"].get("returncode") == 2
                    and "127.0.0.1:8788" in str(nt_default["structuredContent"].get("stderr") or "")
                ), nt_default
                machines_json = root / "machines.json"
                atomic_write_json(machines_json, {"machines": []})
                nt_sync = mcp_t1.call_tool("npu_top", {"argv": ["inventory", "sync", "--from-coordinator", "--machines", str(machines_json)]})
                assert nt_sync["isError"] is False, nt_sync

                fp_res = mcp_t1.call_tool("experiment_ledger", {"argv": ["fingerprint", str(corpus_dir)]})
                assert fp_res["isError"] is False, fp_res
                rsi_state = root / "rsi-state.json"
                rsi_ledger = root / "rsi-ledger.jsonl"
                rsi_init = mcp_t1.call_tool(
                    "rsi_loop",
                    {"argv": ["init", "--state", str(rsi_state), "--task-id", "smoke", "--ledger", str(rsi_ledger), "--baseline-repo", str(corpus_dir), "--direction", "maximize", "--repetitions", "1"]},
                )
                assert rsi_init["isError"] is False and rsi_state.is_file(), rsi_init

                ra_res = mcp_t1.call_tool("remote_auth", {"action": "status", "host": "127.0.0.1", "port": 22})
                assert ra_res["isError"] is False, ra_res
                ws_res = mcp_t1.call_tool("remote_write_stdin", {"session_id": 99999, "chars": ""})
                assert ws_res["structuredContent"].get("reason") != "forged_identity_argument", ws_res
                rp_res = mcp_t1.call_tool("remote_probe", {})
                assert rp_res["isError"] is True and isinstance(rp_res["structuredContent"].get("error_details"), dict), rp_res
                return {"probe_error_category": rp_res["structuredContent"]["error_details"].get("category")}

            _record_check(checks, "topology1_components_rsi_and_remote_contracts", _t1_components_and_remote)

            # Topology 2: Bootstrap stdlib Python (pure mindie_harness copy ONLY!) -> .venv child fallback
            def _t2_bootstrap_fallback() -> dict[str, Any]:
                nonlocal mcp_t2
                deadline.require_remaining(2.0)
                base_py = resolve_base_cpython(sys.executable, env)
                boot_pkg_root = root / "bootstrap-stdlib-only"
                shutil.copytree(
                    Path(__file__).resolve().parent,
                    boot_pkg_root / "mindie_harness",
                    dirs_exist_ok=True,
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
                )
                boot_code = (
                    "import importlib.util, sys; "
                    "sys.path = [p for p in sys.path if 'site-packages' not in p and 'dist-packages' not in p]; "
                    "sys.path.insert(0, sys.argv.pop(1)); "
                    "assert importlib.util.find_spec('mindie_knowledge') is None, 'bootstrap leaked mindie_knowledge'; "
                    "assert importlib.util.find_spec('remote_dev') is None, 'bootstrap leaked remote_dev'; "
                    "from mindie_harness.cli import main; raise SystemExit(main())"
                )
                mcp_t2 = _LiveMCPClient(
                    [str(base_py), "-I", "-X", "utf8", "-c", boot_code, str(boot_pkg_root), "--host", "codex", "--config", str(profile.config_path), "--data-dir", str(profile.data_dir), "mcp", "all"],
                    env=env,
                    cwd=ws,
                )
                mcp_t2.request("initialize", {}, framing="jsonl")
                t2_tools = mcp_t2.request("tools/list", {}, framing="jsonl")["tools"]
                assert any(t["name"] == "remote_write_stdin" for t in t2_tools)
                doc2 = mcp_t2.call_tool("mindie_doctor", {"probe_remote": False}, framing="jsonl")
                assert doc2["isError"] is False and doc2["structuredContent"]["schema"] == "mindie-doctor/1", doc2
                kq2 = mcp_t2.call_tool(
                    "knowledge_query",
                    {"query": "aclgraph capture stream", "domain": "vllm-ascend", "include_unknown": True},
                    framing="content-length",
                )
                assert kq2["isError"] is False and kq2["structuredContent"]["results"][0]["id"] == "unit-vllm-ascend-aclgraph-smoke-001", kq2
                ra2 = mcp_t2.call_tool("remote_auth", {"action": "status", "host": "127.0.0.1", "port": 22}, framing="jsonl")
                assert ra2["isError"] is False, ra2
                rp2 = mcp_t2.call_tool("remote_probe", {}, framing="jsonl")
                assert rp2["isError"] is True and isinstance(rp2["structuredContent"].get("error_details"), dict), rp2
                return {"base_python": str(base_py), "tool_count": len(t2_tools)}

            _record_check(checks, "topology2_stdlib_bootstrap_child_fallback", _t2_bootstrap_fallback)
        finally:
            if mcp_t2 is not None:
                mcp_t2.close()
            if mcp_t1 is not None:
                mcp_t1.close()
            if active_eng_path is not None and active_eng_path.is_file():
                try:
                    from mindie_knowledge.loop.lifecycle import retire_service

                    retire_service(active_eng_path, control_timeout=15.0)
                except Exception:
                    pass
            os.environ.clear()
            os.environ.update(saved_env)
    return checks


def run_selftest(
    mode: str = "candidate",
    *,
    profile: ProfileRef | None = None,
    venv_python: str | Path | None = None,
    timeout_sec: float | None = None,
) -> dict[str, Any]:
    """Run Gate Layer 1 `candidate` or `full` contract selftest."""
    clean_mode = str(mode or "candidate").strip().lower()
    if clean_mode not in {"candidate", "full"}:
        raise HarnessError(f"Unsupported selftest mode {mode!r}", stage="selftest", reason="invalid_selftest_mode", reportable=False)

    target_py = Path(venv_python) if venv_python is not None else Path(sys.executable)
    budget = float(timeout_sec) if timeout_sec is not None else (90.0 if clean_mode == "full" else 20.0)
    deadline = Deadline.from_timeout(max(5.0, budget), cleanup_grace=2.0)

    if not same_interpreter(target_py, sys.executable):
        out = run_owned(
            ProcessSpec(
                argv=(
                    str(target_py),
                    "-I",
                    "-X",
                    "utf8",
                    "-m",
                    "mindie_harness.cli",
                    "--host",
                    profile.host if profile is not None else "codex",
                    "selftest",
                    "--mode",
                    clean_mode,
                    "--timeout",
                    str(max(3.0, deadline.inner_remaining())),
                    "--json",
                ),
                role="foreground",
                allowed_returncodes=None,
            ),
            deadline=deadline,
        )
        lines = [ln for ln in (out.stdout or "").splitlines() if ln.strip()]
        if lines:
            try:
                parsed = json.loads(lines[-1])
                if isinstance(parsed, dict) and parsed.get("schema") == SELFTEST_SCHEMA:
                    return parsed
            except ValueError:
                pass
        return {
            "schema": SELFTEST_SCHEMA,
            "mode": clean_mode,
            "status": "failed",
            "python": str(target_py),
            "checks": [{"name": "delegate_venv_python", "status": "failed", "returncode": out.returncode, "stderr": (out.stderr or "")[-500:]}],
        }

    started = time.monotonic()
    require_fs = clean_mode == "full" or os.environ.get("MINDIE_REQUIRE_FULLSTACK") == "1"
    checks = _run_full_in_process(deadline) if clean_mode == "full" else _run_candidate_in_process(require_fs, deadline)
    passed = bool(checks) and all(c.get("status") == "passed" for c in checks)
    return {
        "schema": SELFTEST_SCHEMA,
        "mode": clean_mode,
        "status": "passed" if passed else "failed",
        "python": str(sys.executable),
        "require_fullstack": require_fs,
        "elapsed_ms": int((time.monotonic() - started) * 1000),
        "checks": checks,
    }


__all__ = ["FULLSTACK_MODULES", "SELFTEST_SCHEMA", "run_selftest"]
