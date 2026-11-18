"""Tier 0 pure in-memory & zero-subprocess algorithmic tests (`< 5s`)."""
from __future__ import annotations

import io
import json
import os
from pathlib import Path
import struct
import sys
import pytest

from mindie_harness import API_VERSION, Deadline, HarnessError, ProcessOutcome
from mindie_harness.bootstrap.seed_main import (
    SEED_LOCK_SCHEMA,
    compute_seed_lock,
    render_plugin_bootstrap_template,
    verify_seed_lock,
)
from mindie_harness.mcp.router import (
    CORRELATION_STRIP_KEYS,
    FORGED_IDENTITY_KEYS,
    MCPRouter,
    RequestContext,
    compute_tool_deadline,
)
from mindie_harness.mcp.server import read_mcp_message, write_mcp_message
from mindie_harness.paths import HOSTS, ProfileRef, assert_wal_safe_path, is_wsl_drvfs, parse_mountinfo
from mindie_harness.process.posix import which_posix_binary
from mindie_harness.process.win32 import (
    IMAGE_SUBSYSTEM_WINDOWS_CUI,
    IMAGE_SUBSYSTEM_WINDOWS_GUI,
    read_pe_subsystem,
    verify_gui_subsystem,
)
from mindie_harness.rsi import (
    assess_stagnation,
    derive_crossover_ablation_receipt,
    rsi_explore,
    suggest_orthogonal_crossovers,
)
from mindie_harness.runtime.registry import select_compatible_release, version_satisfies


def _build_minimal_pe_bytes(*, subsystem: int, pe32_plus: bool = True) -> bytes:
    dos = bytearray(64)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 64)
    pe = bytearray(24)
    pe[0:4] = b"PE\x00\x00"
    struct.pack_into("<H", pe, 20, 112)  # SizeOfOptionalHeader >= 70
    opt = bytearray(112)
    struct.pack_into("<H", opt, 0, 0x20B if pe32_plus else 0x10B)
    struct.pack_into("<H", opt, 68, subsystem)
    return bytes(dos + pe + opt)


@pytest.mark.tier0
def test_wsl2_mountinfo_parser_and_drvfs_wal_guard() -> None:
    mountinfo = "\n".join(
        [
            "36 25 8:16 / / rw,relatime - ext4 /dev/sdb rw,discard",
            "89 36 0:39 / /mnt/c rw,noatime - 9p drvfs rw,dirsync,aname=drvfs;path=C:\\;uid=1000",
            "92 36 0:42 / /windrive/Program\\040Files\\040(x86) rw - drvfs D:\\ rw",
            "95 89 7:0 / /mnt/c/loop_ext4 rw,relatime - ext4 /dev/loop0 rw",
        ]
    )
    entries = parse_mountinfo(mountinfo)
    assert len(entries) == 4
    assert entries[2].mount_point == "/windrive/Program Files (x86)"
    assert is_wsl_drvfs("/mnt/c/Users/alice/state.sqlite3", mountinfo_text=mountinfo) is True
    assert is_wsl_drvfs("/windrive/Program Files (x86)/app/db.sqlite3", mountinfo_text=mountinfo) is True
    assert is_wsl_drvfs("/home/alice/.local/share/mindie-agent", mountinfo_text=mountinfo) is False
    # Deepest mountpoint wins: ext4 loopback mounted under /mnt/c/loop_ext4 is native Linux!
    assert is_wsl_drvfs("/mnt/c/loop_ext4/state.sqlite3", mountinfo_text=mountinfo) is False

    with pytest.raises(HarnessError) as exc_info:
        assert_wal_safe_path("/mnt/c/Users/alice/mindie", mountinfo_text=mountinfo)
    assert exc_info.value.reason == "drvfs_unsafe_state_root"
    assert exc_info.value.reportable is False


@pytest.mark.tier0
@pytest.mark.skipif(os.name == "nt", reason="POSIX executable bit semantics")
def test_which_posix_binary_iterates_all_64_windows_path_entries(tmp_path: Path) -> None:
    win_dirs: list[str] = []
    for idx in range(64):
        d = tmp_path / f"Program Files (x86) {idx}"
        d.mkdir()
        # Plant .exe, .cmd, and an extensionless MZ PE shim named `python3`!
        for ext_file in (d / "python3.exe", d / "python3.cmd"):
            ext_file.write_bytes(b"MZfake")
            ext_file.chmod(0o755)
        mz_shim = d / "python3"
        mz_shim.write_bytes(_build_minimal_pe_bytes(subsystem=3))
        mz_shim.chmod(0o755)
        win_dirs.append(str(d))

    linux_bin = tmp_path / "usr_bin"
    linux_bin.mkdir()
    real_py = linux_bin / "python3"
    real_py.write_bytes(b"#!/bin/sh\necho ok\n")
    real_py.chmod(0o755)

    path_env = os.pathsep.join([*win_dirs, str(linux_bin)])
    resolved = which_posix_binary("python3", path_env=path_env, reject_drvfs=False)
    assert resolved == real_py


@pytest.mark.tier0
def test_pe_header_subsystem_rejects_renamed_cui_and_checks_pyvenv_base(tmp_path: Path) -> None:
    base_home = tmp_path / "uv_cpython"
    base_home.mkdir()
    base_pyw = base_home / "pythonw.exe"
    base_pyw.write_bytes(_build_minimal_pe_bytes(subsystem=IMAGE_SUBSYSTEM_WINDOWS_GUI, pe32_plus=True))

    venv_dir = tmp_path / "gen" / ".venv"
    scripts = venv_dir / "Scripts"
    scripts.mkdir(parents=True)
    (venv_dir / "pyvenv.cfg").write_text(f"home = {base_home}\nversion = 3.13.1\n", encoding="utf-8")

    good_pyw = scripts / "pythonw.exe"
    good_pyw.write_bytes(_build_minimal_pe_bytes(subsystem=IMAGE_SUBSYSTEM_WINDOWS_GUI, pe32_plus=False))
    assert read_pe_subsystem(good_pyw) == IMAGE_SUBSYSTEM_WINDOWS_GUI
    assert verify_gui_subsystem(good_pyw) == good_pyw

    # Renamed CUI python.exe -> pythonw.exe must be rejected!
    renamed_cui = tmp_path / "fake_pythonw.exe"
    renamed_cui.write_bytes(_build_minimal_pe_bytes(subsystem=IMAGE_SUBSYSTEM_WINDOWS_CUI))
    with pytest.raises(HarnessError) as exc_info:
        verify_gui_subsystem(renamed_cui)
    assert exc_info.value.reason == "windowless_interpreter_invalid"

    # Corrupted CUI base pythonw.exe in pyvenv.cfg must ALSO be rejected!
    base_pyw.write_bytes(_build_minimal_pe_bytes(subsystem=IMAGE_SUBSYSTEM_WINDOWS_CUI))
    with pytest.raises(HarnessError) as base_exc:
        verify_gui_subsystem(good_pyw)
    assert base_exc.value.reason == "windowless_interpreter_invalid"


@pytest.mark.tier0
def test_deadline_arithmetic_and_decoupled_mcp_truncation() -> None:
    assert Deadline.compute_outer([600.0], cleanup_grace=60.0) == 660.0
    with pytest.raises(ValueError, match="Principle 10"):
        Deadline.validate_outer(120.0, [600.0], cleanup_grace=60.0)

    big_text = "A" * 2048 + "中" * 512
    outcome = ProcessOutcome(execution="completed", returncode=0, stdout=big_text)
    projected, truncated = outcome.mcp_stdout(cap_bytes=512)
    assert truncated is True
    assert "truncated" in projected
    assert outcome.stdout == big_text  # Process capture untouched


@pytest.mark.tier0
def test_component_tool_deadline_propagates_caller_timeout_ms(monkeypatch: pytest.MonkeyPatch) -> None:
    """`timeout_ms` propagates into component deadlines with a 600s inner cap + 60s grace."""
    captured: list[tuple[float, float]] = []
    real_from_timeout = Deadline.from_timeout

    def _capture(timeout_seconds: float, *, cleanup_grace: float = 0.0, now: float | None = None) -> Deadline:
        captured.append((float(timeout_seconds), float(cleanup_grace)))
        return real_from_timeout(timeout_seconds, cleanup_grace=cleanup_grace, now=now)

    monkeypatch.setattr(Deadline, "from_timeout", staticmethod(_capture))

    def _outer(timeout_ms: object = None, *, explicit: float | None = None) -> tuple[float, float]:
        captured.clear()
        args = {} if timeout_ms is None else {"timeout_ms": timeout_ms}
        compute_tool_deadline("component", "profiler", args, explicit_timeout=explicit)
        assert len(captured) == 1
        return captured[0]

    # Absent caller timeout keeps the historical 120s inner + 10s grace = 130s outer.
    assert _outer() == (130.0, 10.0)
    # 300s caller inner -> 300s + 60s grace = 360s (grace escalates once inner > 120s).
    assert _outer(300_000) == (360.0, 60.0)
    # 600s caller inner (the host-plugin ceiling) -> 600s + 60s grace = 660s (Principle 10).
    assert _outer(600_000) == (660.0, 60.0)
    # Oversized callers clamp to the 600s inner cap, never exceeding 660s outer.
    assert _outer(900_000) == (660.0, 60.0)
    # Non-numeric / boolean / non-finite / non-positive callers fall back to 130s.
    for invalid in (True, "300000", float("nan"), float("inf"), 0, -1):
        assert _outer(invalid) == (130.0, 10.0), invalid
    # An explicit router-level timeout may only extend, never shrink, the outer deadline.
    assert _outer(600_000, explicit=900.0) == (900.0, 60.0)
    assert _outer(300_000, explicit=1.0) == (360.0, 60.0)


@pytest.mark.tier0
def test_stdlib_version_specifier_fallback_and_release_selector(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "packaging", None)
    monkeypatch.setitem(sys.modules, "packaging.specifiers", None)
    monkeypatch.setitem(sys.modules, "packaging.version", None)

    assert version_satisfies("0.118.0", ">=0.114.0,<0.200.0") is True
    assert version_satisfies("0.113.9", ">=0.114.0,<0.200.0") is False
    assert version_satisfies("1.2.5", "~=1.2.0") is True
    assert version_satisfies("1.3.0", "~=1.2.0") is False
    assert version_satisfies("0.2.0rc1", ">=0.2.0") is False

    releases = [
        {"version": "0.1.34", "compatibility": {"harness_api_version": 1, "hosts": {"codex": ">=0.110.0"}}},
        {"version": "0.1.35", "compatibility": {"harness_api_version": 1, "hosts": {"codex": ">=0.114.0,<0.200.0"}}},
        {"version": "0.2.0", "compatibility": {"harness_api_version": 2, "hosts": {"codex": ">=0.114.0"}}},
    ]
    sel = select_compatible_release(releases, host="codex", host_version="0.118.0", installed_version="0.1.34", api_version=API_VERSION)
    assert sel["status"] == "candidate"
    assert sel["candidate"]["version"] == "0.1.35"


@pytest.mark.tier0
def test_dual_mcp_framing_and_rsi_pure_helpers(tmp_path: Path) -> None:
    buf = io.BytesIO()
    msg_cl = {"jsonrpc": "2.0", "id": 1, "result": {"note": "昇腾 NPU 🚀"}}
    msg_jl = {"jsonrpc": "2.0", "id": 2, "result": {"ok": True}}
    write_mcp_message(buf, msg_cl, "content-length")
    write_mcp_message(buf, msg_jl, "jsonl")
    buf.seek(0)

    parsed1, fmt1 = read_mcp_message(buf)
    parsed2, fmt2 = read_mcp_message(buf)
    eof_msg, _ = read_mcp_message(buf)
    assert fmt1 == "content-length" and parsed1 == msg_cl
    assert fmt2 == "jsonl" and parsed2 == msg_jl
    assert eof_msg is None

    norm = rsi_explore.parse_args({"mode": "explore", "native_subcontext": 1})
    assert norm["mode"] == "explore" and norm["native_subcontext"] is True
    with pytest.raises(ValueError, match="mode must be one of"):
        rsi_explore.parse_args({"mode": "invalid"})

    # Stagnation promotion requires 3 distinct refuted hashes
    entries = [
        {"run_id": f"r{i}", "verdict": "refuted", "outcome": "speedup_below_target", "source_digest": f"sha256:{i}"}
        for i in range(3)
    ]
    stag = assess_stagnation(entries)
    assert stag["stalled"] is True and stag["promotion_ready"] is True

    # Orthogonal crossover suggestion + LOO ablation reuse
    live = [
        {"exp_id": "e1", "verdict": "supported", "speedup_ratio": 1.10, "baseline_source_digest": "sha256:b0", "source_digest": "sha256:s1", "factors": ["tiling"], "conditions": {"chip": "A2"}},
        {"exp_id": "e2", "verdict": "supported", "speedup_ratio": 1.08, "baseline_source_digest": "sha256:b0", "source_digest": "sha256:s2", "factors": ["double_buffer"], "conditions": {"chip": "A2"}},
    ]
    cands = suggest_orthogonal_crossovers(live)
    assert len(cands) == 1 and cands[0]["parent_exp_ids"] == ["e1", "e2"]
    loo = derive_crossover_ablation_receipt(
        live,
        parent_exp_ids=["e1", "e2"],
        baseline_source_digest="sha256:b0",
        conditions={"chip": "A2"},
        combined_speedup_ratio=1.20,
    )
    assert loo is not None and loo["ablation_retained"] is True

    # Seed lock & <115L template check
    repo_root = Path(__file__).resolve().parents[2]
    lock_doc = verify_seed_lock(repo_root / "dist" / "mindie-harness-seed.pyz", repo_root / "dist" / "seed-lock.json")
    assert lock_doc["schema"] == SEED_LOCK_SCHEMA
    for host in HOSTS:
        tpl = render_plugin_bootstrap_template(host)
        assert len(tpl.splitlines()) < 115

    tampered = tmp_path / "bad.pyz"
    tampered.write_bytes(b"tampered")
    good_lock = tmp_path / "lock.json"
    good_lock.write_text(json.dumps(compute_seed_lock(repo_root / "dist" / "mindie-harness-seed.pyz")), encoding="utf-8")
    with pytest.raises(ValueError, match="integrity mismatch"):
        verify_seed_lock(tampered, good_lock)


@pytest.mark.tier0
def test_mcp_router_silent_default_on_all_surfaces_and_forged_identity_guard(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile = ProfileRef.resolve(
        "codex",
        plugin_root=tmp_path / "plugin",
        config_path=tmp_path / "cfg" / "codex.json",
        data_dir=tmp_path / "data",
    )
    tools = [
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
        {
            "name": "knowledge_sync",
            "inputSchema": {
                "type": "object",
                "properties": {"domain": {"type": "string"}},
                "additionalProperties": False,
            },
        },
        {
            "name": "knowledge_feedback",
            "inputSchema": {
                "type": "object",
                "properties": {"ref": {"type": "string"}},
                "required": ["ref"],
                "additionalProperties": False,
            },
        },
        {
            "name": "coordinator",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "argv": {"type": "array"},
                    "context_file": {"type": "string"},
                    "_mindie_bind_id": {"type": "string"},
                    "request_nonce": {"type": "string"},
                },
                "required": ["argv", "context_file", "_mindie_bind_id", "request_nonce"],
                "additionalProperties": False,
            },
        },
    ]

    seen_calls: list[tuple[str, str, Path | None, dict[str, object]]] = []
    raise_in_handler = False

    def _handler(ctx: RequestContext, args: dict[str, object]) -> dict[str, object]:
        if raise_in_handler:
            raise TimeoutError("simulated in-flight tool timeout after dispatch")
        seen_calls.append((ctx.tool_name, ctx.session_id, ctx.cwd, dict(args)))
        return {
            "content": [{"type": "text", "text": json.dumps({"tool": ctx.tool_name, "session_id": ctx.session_id})}],
            "isError": False,
        }

    assert CORRELATION_STRIP_KEYS == frozenset({"_mindie_bind_id", "request_nonce", "context_file"})

    # 0. Explicit `tools=[]` stays empty, whereas `tools=None` defaults to `[mindie_status]`.
    assert MCPRouter(profile, surface="tools", tools=[], base_env={}).list_tools() == []
    assert [t["name"] for t in MCPRouter(profile, surface="tools", tools=None, base_env={}).list_tools()] == ["mindie_status"]

    # 1. Single-point normalization in `__init__` strips CORRELATION_STRIP_KEYS from `properties` AND `required`.
    for surface in ("knowledge", "tools", "all"):
        r = MCPRouter(profile, surface=surface, tools=tools, handler=_handler, base_env={})
        listed = r.list_tools()
        assert [t["name"] for t in listed] == [t["name"] for t in tools]
        for item in listed:
            prop_fields = set(item.get("inputSchema", {}).get("properties") or ())
            req_fields = set(item.get("inputSchema", {}).get("required") or ())
            assert prop_fields.isdisjoint(CORRELATION_STRIP_KEYS), (surface, item["name"], prop_fields)
            assert req_fields.isdisjoint(CORRELATION_STRIP_KEYS), (surface, item["name"], req_fields)
    assert not profile.admission_db.exists()

    # 2. Cold-start `call_tool()` on `surface="knowledge"` with zero `_meta` skips `claim_bind` SQLite lock completely.
    router = MCPRouter(profile, surface="knowledge", tools=tools, handler=_handler, base_env={})
    expected_fallback = f"codex-conn-{router.connection_id[:12]}"

    bind_cwd = tmp_path / "victim-proj"
    bind_cwd.mkdir()
    real_claim_bind = router.binds.claim_bind
    router.binds.publish_bind(
        "victim-bind-1",
        session="victim-sess",
        surface="knowledge",
        tool="knowledge_explain",
        args_digest="unused",
        cwd=str(bind_cwd),
    )

    def _forbid_anonymous_claim_bind(**_kwargs: object) -> None:
        pytest.fail("claim_bind must never be called when both _meta bind_id and session are absent")

    monkeypatch.setattr(router.binds, "claim_bind", _forbid_anonymous_claim_bind)

    q_res = router.call_tool(
        {
            "jsonrpc": "2.0",
            "id": "kq-1",
            "method": "tools/call",
            "params": {"name": "knowledge_query", "arguments": {"query": "aclgraph", "mode": "explore"}},
        }
    )
    assert q_res["isError"] is False
    assert seen_calls[-1] == (
        "knowledge_query",
        expected_fallback,
        None,
        rsi_explore.parse_args({"query": "aclgraph", "mode": "explore"}),
    )
    assert not profile.admission_db.exists()
    assert not profile.receipts_db.exists()  # Read-only fast-lane query never creates receipts DB!

    bad_rsi = router.call_tool(
        {
            "jsonrpc": "2.0",
            "id": "kq-bad-rsi",
            "method": "tools/call",
            "params": {"name": "knowledge_query", "arguments": {"query": "aclgraph", "mode": "invalid"}},
        }
    )
    assert bad_rsi["isError"] is True
    assert bad_rsi["structuredContent"]["reason"] == "invalid_rsi_arguments"

    # Model-supplied `_mindie_bind_id` in `arguments` is stripped and NEVER used to claim `victim-bind-1`!
    e_res = router.call_tool(
        {
            "jsonrpc": "2.0",
            "id": "ke-1",
            "method": "tools/call",
            "params": {
                "name": "knowledge_explain",
                "arguments": {
                    "ref": "mindie://unit/1",
                    "request_nonce": "legacy-nonce",
                    "_mindie_bind_id": "victim-bind-1",
                    "context_file": "/tmp/legacy-ctx.json",
                },
            },
        }
    )
    assert e_res["isError"] is False
    assert seen_calls[-1] == (
        "knowledge_explain",
        expected_fallback,
        None,
        rsi_explore.parse_args({"ref": "mindie://unit/1"}),
    )
    assert not profile.receipts_db.exists()

    # Host-supplied `_meta.bind_id` DOES claim the pending bind and enrich `session_id` + `cwd`.
    monkeypatch.setattr(router.binds, "claim_bind", real_claim_bind)
    meta_bind_res = router.call_tool(
        {
            "jsonrpc": "2.0",
            "id": "ke-meta-bind",
            "method": "tools/call",
            "params": {
                "name": "knowledge_explain",
                "arguments": {"ref": "mindie://unit/1"},
                "_meta": {"bind_id": "victim-bind-1"},
            },
        }
    )
    assert meta_bind_res["isError"] is False
    assert seen_calls[-1] == (
        "knowledge_explain",
        "victim-sess",
        bind_cwd,
        rsi_explore.parse_args({"ref": "mindie://unit/1"}),
    )

    # 3. Non-readonly mutating `knowledge_*` tools succeed on cold start & enforce idempotent RemoteReceipts.
    for idx, (tname, targs) in enumerate(
        (
            ("knowledge_distill", {"summary": "verified tile rule", "request_nonce": "strip-me"}),
            ("knowledge_sync", {"domain": "operators"}),
            ("knowledge_feedback", {"ref": "mindie://unit/1"}),
        )
    ):
        m_res = router.call_tool(
            {
                "jsonrpc": "2.0",
                "id": f"mut-{idx}",
                "method": "tools/call",
                "params": {"name": tname, "arguments": targs},
            }
        )
        assert m_res["isError"] is False
        assert seen_calls[-1][1] == expected_fallback
    assert not profile.admission_db.exists()
    assert profile.receipts_db.is_file()

    dup_res = router.call_tool(
        {
            "jsonrpc": "2.0",
            "id": "mut-0",
            "method": "tools/call",
            "params": {"name": "knowledge_distill", "arguments": {"summary": "verified tile rule"}},
        }
    )
    assert dup_res["isError"] is True
    assert dup_res["structuredContent"]["reason"] == "duplicate_request"

    # 4. `FORGED_IDENTITY_KEYS` remain strictly rejected on both `knowledge_*` and deterministic tools.
    for key in FORGED_IDENTITY_KEYS:
        for tname, base_arg in (("knowledge_query", {"query": "x"}), ("coordinator", {"argv": ["hosts"]})):
            forged_res = router.call_tool(
                {
                    "jsonrpc": "2.0",
                    "id": f"forged-{tname}-{key}",
                    "method": "tools/call",
                    "params": {"name": tname, "arguments": {**base_arg, key: "forged-value"}},
                }
            )
            assert forged_res["isError"] is True
            assert forged_res["structuredContent"]["reason"] == "forged_identity_argument"

    # 5. Principle 14 + Iron Rule 2: pre-dispatch `TimeoutError` -> `not_sent`; post-dispatch `TimeoutError` -> `uncertain`.
    def _timeout_claim_bind(**_kwargs: object) -> None:
        raise TimeoutError("simulated bind SQLite deadline exceeded")

    monkeypatch.setattr(router.binds, "claim_bind", _timeout_claim_bind)
    pre_to_res = router.call_tool(
        {
            "jsonrpc": "2.0",
            "id": "kq-pre-timeout",
            "method": "tools/call",
            "params": {
                "name": "knowledge_query",
                "arguments": {"query": "x"},
                "_meta": {"session_id": "s-pre-timeout"},
            },
        }
    )
    assert pre_to_res["isError"] is True
    assert pre_to_res["structuredContent"]["reason"] == "helper_timeout"
    assert pre_to_res["structuredContent"]["submission_state"] == "not_sent"

    monkeypatch.setattr(router.binds, "claim_bind", real_claim_bind)
    raise_in_handler = True
    post_to_res = router.call_tool(
        {
            "jsonrpc": "2.0",
            "id": "kq-post-timeout",
            "method": "tools/call",
            "params": {"name": "knowledge_query", "arguments": {"query": "x"}},
        }
    )
    assert post_to_res["isError"] is True
    assert post_to_res["structuredContent"]["reason"] == "helper_timeout"
    assert post_to_res["structuredContent"]["submission_state"] == "uncertain"
