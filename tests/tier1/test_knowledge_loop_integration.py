"""Integration with the installed Knowledge package and real loopback RPC.

[Role] Detect drift between the shared adapter and released Knowledge APIs.
[Invariants] Fail-closed (`pytest.fail`) when `MINDIE_REQUIRE_FULLSTACK=1` is set;
no provider, remote feed, or capture authorization needed for public reads.
[Timeouts & Locks] Local HTTP uses a five-second caller budget; server is joined.
[Side-Effect Policy] Store, adapter, and configuration live in pytest's sandbox.
"""
from __future__ import annotations

import importlib
import json
import os
import threading

import pytest

from mindie_harness.mcp.knowledge_rpc import invoke_knowledge_tool
from mindie_harness.paths import ProfileRef
from mindie_harness.process.supervisor import Deadline
from mindie_harness.runtime.knowledge_binding import ensure_knowledge_binding


def _require_or_skip_knowledge():
    try:
        return importlib.import_module("mindie_knowledge.loop.cli")
    except ModuleNotFoundError as exc:
        if os.environ.get("MINDIE_REQUIRE_FULLSTACK") == "1":
            pytest.fail(
                f"MINDIE_REQUIRE_FULLSTACK=1 set, but required package is missing: {exc}",
                pytrace=False,
            )
        pytest.skip(f"mindie_knowledge not installed in standalone unit env: {exc}")


def test_query_against_installed_knowledge_loop(tmp_path, monkeypatch):
    cli = _require_or_skip_knowledge()
    from mindie_knowledge.loop.activation import Admission
    from mindie_knowledge.loop.engine import Engine
    from mindie_knowledge.loop.store import Store
    from mindie_knowledge.loop.transport import Service

    profile = ProfileRef.resolve(
        "codex",
        plugin_root=tmp_path / "plugin",
        config_path=tmp_path / "cfg" / "codex.json",
        data_dir=tmp_path / "data",
    )
    bound = ensure_knowledge_binding(profile)
    assert bound["status"] == "configured", bound
    assert len(bound["domain_configs"]) == 9

    engine_path = tmp_path / "cfg" / "codex.json"
    cfg_doc = json.loads(engine_path.read_text(encoding="utf-8"))
    default_eng = tmp_path / "cfg" / "engines" / "codex"
    assert default_eng.is_dir()
    selected_eng_path = bound["engine_config"]
    eng_doc = cli.config_at(selected_eng_path)
    admission_path = profile.admission_db

    store = Store(eng_doc["root"], "vllm-ascend")
    engine = Engine(store)
    service = Service(engine, admission=Admission(admission_path))
    worker = threading.Thread(target=service.http.serve_forever, kwargs={"poll_interval": 0.01})
    worker.start()
    selected = []

    def connection(path):
        selected.append(path)
        return service.connection

    monkeypatch.setattr(cli, "ensure_service", connection)
    try:
        result = invoke_knowledge_tool(
            "knowledge_query",
            {"query": "aclgraph", "domain": "vllm-ascend", "token_budget": 8000},
            profile=profile,
            session_id="integration-host-session",
            deadline=Deadline.from_timeout(5),
        )
        assert result["isError"] is False, result
        assert result["structuredContent"]["domain"] == "vllm-ascend"
        assert result["structuredContent"]["results"] == []
        assert len(selected) == 1 and str(selected[0]) == str(cfg_doc["engine_config"])
        assert not admission_path.exists(), "a public query must not create capture authority"
    finally:
        service.http.shutdown()
        worker.join(5)
        service.http.server_close()
        store.close()
    assert not worker.is_alive()
