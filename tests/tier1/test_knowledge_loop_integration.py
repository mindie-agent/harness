"""Optional integration with the installed Knowledge package and real loopback RPC.

[Role] Detect drift between the shared adapter and released Knowledge APIs.
[Invariants] No provider, feed, OS service manager, or capture authorization needed.
[Timeouts & Locks] Local HTTP uses a five-second caller budget; server is joined.
[Side-Effect Policy] Store, adapter, and configuration live in pytest's sandbox.
"""
from __future__ import annotations

import json
import threading

import pytest

from mindie_harness.mcp.knowledge_rpc import invoke_knowledge_tool
from mindie_harness.paths import ProfileRef
from mindie_harness.process.supervisor import Deadline


def test_query_against_installed_knowledge_loop(tmp_path, monkeypatch):
    cli = pytest.importorskip("mindie_knowledge.loop.cli")
    from mindie_knowledge.loop.activation import Admission
    from mindie_knowledge.loop.engine import Engine
    from mindie_knowledge.loop.store import Store
    from mindie_knowledge.loop.transport import Service

    engine_path = tmp_path / "current.engine.json"
    admission_path = tmp_path / "admission.sqlite3"
    engine_path.write_text(json.dumps({
        "domain": "vllm-ascend", "root": str(tmp_path / "knowledge"),
        "admission_path": str(admission_path),
        "redactor_executable": str(tmp_path / "unused-redactor.exe"),
        "transcript_adapter": str(tmp_path / "unused-transcript.py"),
    }), encoding="utf-8")
    profile = ProfileRef.resolve("codex", config_path=tmp_path / "codex.json")
    profile.config_path.write_text(json.dumps({
        "engine_config": str(engine_path),
        "domain_configs": {"vllm-ascend": str(tmp_path / "retired.engine.json")},
    }), encoding="utf-8")
    store = Store(tmp_path / "knowledge", "vllm-ascend")
    engine = Engine(store)
    service = Service(engine, admission=Admission(admission_path))
    # Exercise real authenticated HTTP and Service identity checks without an
    # OS-managed background process, a feed sync, or any user configuration.
    worker = threading.Thread(target=service.http.serve_forever, kwargs={"poll_interval": 0.01})
    worker.start()
    selected = []

    def connection(path):
        selected.append(path)
        return service.connection

    monkeypatch.setattr(cli, "ensure_service", connection)
    try:
        result = invoke_knowledge_tool(
            "knowledge_query", {"query": "aclgraph", "domain": "vllm-ascend", "token_budget": 8000},
            profile=profile, session_id="integration-host-session",
            deadline=Deadline.from_timeout(5),
        )
        assert result["isError"] is False, result
        assert result["structuredContent"]["domain"] == "vllm-ascend"
        assert result["structuredContent"]["results"] == []
        assert selected == [engine_path.resolve()]
        assert not admission_path.exists(), "a public query must not create capture authority"
    finally:
        service.http.shutdown()
        worker.join(5)
        service.http.server_close()
        store.close()
    assert not worker.is_alive()
