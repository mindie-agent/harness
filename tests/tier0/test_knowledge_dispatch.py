"""Knowledge loop API dispatch, identity, domains, and post-RPC receipts.

[Role] Exercise the published submodule API without package-root exports.
[Invariants] Reads create no admission lease; uncertain calls are never replayed.
[Timeouts & Locks] In-memory collaborators only; no service or process starts.
[Side-Effect Policy] pytest isolates environment and temporary adapter files.
"""
from __future__ import annotations

import json
from pathlib import Path
import sys
from types import ModuleType, SimpleNamespace
from unittest.mock import Mock

import pytest

from mindie_harness.mcp.knowledge_rpc import invoke_knowledge_tool
from mindie_harness.process.supervisor import Deadline


@pytest.fixture
def loop_api(tmp_path, monkeypatch):
    # The released package root deliberately does not re-export rpc/Admission.
    for name in ("mindie_knowledge", "mindie_knowledge.loop", "mindie_knowledge.graded"):
        package = ModuleType(name)
        package.__path__ = []
        monkeypatch.setitem(sys.modules, name, package)
    default = tmp_path / "current.engine.json"
    default.write_text(json.dumps({"domain": "vllm-ascend", "admission_path": str(tmp_path / "admission.sqlite3")}), encoding="utf-8")
    config = tmp_path / "codex.json"
    config.write_text(json.dumps({"engine_config": str(default), "domain_configs": {"vllm-ascend": str(tmp_path / "retired.engine.json")}}), encoding="utf-8")
    api = SimpleNamespace(
        profile=SimpleNamespace(config_path=config), default=default,
        admission=Mock(), select=Mock(return_value=default),
        ensure=Mock(return_value={"url": "http://127.0.0.1:1", "token": "test-only"}),
        rpc=Mock(return_value={"results": [{"ref": "mindie://vllm-ascend/units/test@abc"}]}),
        view=Mock(side_effect=lambda raw: ({**raw, "operation_status": "completed"}, False)),
    )
    api.admission.return_value.active_lease.return_value = {"token": "test-lease", "entry_enabled": 1}
    modules = {
        "activation": {"Admission": api.admission},
        "cli": {"config_at": lambda path: json.loads(Path(path).read_text(encoding="utf-8")), "ensure_service": api.ensure},
        "domain_routes": {"select_engine_config": api.select},
        "transport": {"rpc": api.rpc},
    }
    for name, exports in modules.items():
        module = ModuleType("mindie_knowledge.loop." + name)
        module.__dict__.update(exports)
        monkeypatch.setitem(sys.modules, module.__name__, module)
    distill = ModuleType("mindie_knowledge.graded.distill")
    distill.result_view = api.view
    monkeypatch.setitem(sys.modules, distill.__name__, distill)
    return api


def call(api, method, arguments, **kwargs):
    return invoke_knowledge_tool("knowledge_" + method, arguments, profile=api.profile, session_id="host-session", **kwargs)


def test_query_uses_loop_api_current_engine_and_host_identity(loop_api):
    api = loop_api
    args = {"query": "aclgraph", "domain": "vllm-ascend", "token_budget": 8000}
    assert call(api, "query", args)["isError"] is False
    api.select.assert_called_once_with(api.default, domain="vllm-ascend", ref=None, domain_configs={"vllm-ascend": str(api.default.resolve())})
    api.ensure.assert_called_once_with(api.default)
    connection, method, payload = api.rpc.call_args.args
    assert connection == api.ensure.return_value and method == "query"
    assert payload == {"query": "aclgraph", "token_budget": 8000, "_session_id": "host-session", "_session_verified": True}
    assert args == {"query": "aclgraph", "domain": "vllm-ascend", "token_budget": 8000}
    api.admission.assert_not_called()


@pytest.mark.parametrize("method,args", [
    ("explain", {"ref": "mindie://operators/units/test@abc"}),
    ("feedback", {"ref": "mindie://operators/units/test@abc", "rating": "up"}),
    ("sync", {"domain": "operators"}),
])
def test_other_methods_route_and_normalize_sync(loop_api, method, args):
    api = loop_api
    target = api.default.with_name("operators.engine.json")
    api.select.return_value = target
    if method == "sync":
        api.rpc.return_value = [{"status": "synced"}]
    result = call(api, method, args)
    assert result["isError"] is False
    api.ensure.assert_called_once_with(target)
    assert api.rpc.call_args.args[1] == method
    payload = api.rpc.call_args.args[2]
    assert "domain" not in payload
    if method != "sync":
        assert payload["_session_verified"] is True
        assert api.select.call_args.kwargs["ref"] == args["ref"]
    else:
        assert result["structuredContent"] == {"results": [{"status": "synced"}]}


def test_domain_selection_failure_does_not_start_service(loop_api):
    loop_api.select.side_effect = ValueError("unknown domain")
    result = call(loop_api, "query", {"query": "x", "domain": "unknown"})
    assert result["structuredContent"]["stage"] == "config"
    assert result["structuredContent"]["submission_state"] == "not_sent"
    loop_api.ensure.assert_not_called()


def test_batch_references_cannot_cross_domains(loop_api):
    loop_api.select.side_effect = [loop_api.default, loop_api.default.with_name("other.json")]
    result = call(loop_api, "explain", {"ref": "first", "refs": ["second"]})
    assert result["isError"] is True
    loop_api.rpc.assert_not_called()


def test_forged_internal_identity_is_rejected(loop_api):
    assert call(loop_api, "query", {"query": "x", "_session_verified": True})["isError"] is True
    loop_api.ensure.assert_not_called()


def test_rpc_type_error_is_not_a_signature_probe_or_replayed(loop_api):
    loop_api.rpc.side_effect = TypeError("error inside executed RPC")
    result = call(loop_api, "feedback", {"ref": "ref", "rating": "up"})
    assert result["isError"] is True
    assert result["structuredContent"]["submission_state"] == "sent"
    loop_api.rpc.assert_called_once()


def test_distill_retains_scoped_token_and_result_view(loop_api):
    loop_api.rpc.return_value = {"status": "noop"}
    result = call(loop_api, "distill", {"inputs": [], "task_state": "completed"})
    assert result["isError"] is False
    assert result["structuredContent"]["operation_status"] == "completed"
    assert loop_api.rpc.call_args.args[2]["_activation"] == "test-lease"
    loop_api.admission.return_value.finish.assert_called_once_with("host-session", "test-lease", True)


def test_distill_does_not_grant_missing_capture_authority(loop_api):
    loop_api.admission.return_value.active_lease.return_value = None
    result = call(loop_api, "distill", {"inputs": [], "task_state": "completed"})
    assert result["structuredContent"]["reason"] == "knowledge_authorization_required"
    loop_api.admission.return_value.activate.assert_not_called()
    loop_api.ensure.assert_not_called()


@pytest.mark.parametrize("failure", [OSError("receipt full"), TimeoutError("receipt budget")])
def test_receipt_failure_preserves_completed_distill(loop_api, failure):
    loop_api.rpc.return_value = {"status": "noop"}
    loop_api.admission.return_value.finish.side_effect = failure
    result = call(loop_api, "distill", {"inputs": [], "task_state": "completed"})
    assert result["isError"] is False and result["receipt_unconfirmed"] is True
    assert "receipt_warning" in result
    loop_api.rpc.assert_called_once()


def test_expired_deadline_starts_no_service(loop_api):
    with pytest.raises(TimeoutError):
        call(loop_api, "query", {"query": "x"}, deadline=Deadline(expires_at=0))
    loop_api.ensure.assert_not_called()


def test_rpc_preserves_deadline_cleanup_grace(loop_api):
    deadline = Deadline.from_timeout(20, cleanup_grace=5)
    assert call(loop_api, "query", {"query": "x"}, deadline=deadline)["isError"] is False
    assert 10 < loop_api.rpc.call_args.kwargs["timeout"] <= 15.000001
