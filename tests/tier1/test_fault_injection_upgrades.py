"""Tier 1 local boundary & 10-scenario fault-injection runtime upgrade tests (`< 15s`)."""
from __future__ import annotations

from collections import namedtuple
import json
import os
from pathlib import Path
import sys
import pytest

from mindie_harness import (
    HarnessError,
    ProfileRef,
    RuntimeSelection,
    activate_runtime,
    maintain_runtime,
    open_wal_database,
    prepare_runtime,
)
from mindie_harness.atomic import atomic_write_bytes, atomic_write_json, read_json_safe
from mindie_harness.locks import FileLock, acquire_generation_lease
from mindie_harness.mcp.router import MCPRouter
from mindie_harness.paths import venv_python_path
from mindie_harness.process.win32 import IMAGE_SUBSYSTEM_WINDOWS_GUI
from mindie_harness.runtime.activation import reclaim_generations, write_pending_update_check
from mindie_harness.runtime.builder import BUILDING_SENTINEL, MIN_BUILD_FREE_BYTES, prepare_candidate_runtime

_DiskUsage = namedtuple("_DiskUsage", ["total", "used", "free"])


def _fake_pe_gui_bytes() -> bytes:
    import struct

    dos = bytearray(64)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 64)
    pe = bytearray(24)
    pe[0:4] = b"PE\x00\x00"
    struct.pack_into("<H", pe, 20, 112)
    opt = bytearray(112)
    struct.pack_into("<H", opt, 0, 0x20B)
    struct.pack_into("<H", opt, 68, IMAGE_SUBSYSTEM_WINDOWS_GUI)
    return bytes(dos + pe + opt)


def _make_fast_builder(exit_code: int = 0):
    """Create a fast real-interpreter shim inside `venv_dir` without network `uv`."""
    def _builder(gen_dir: Path, venv_dir: Path, env: dict[str, str], deadline) -> None:
        py = venv_python_path(venv_dir)
        py.parent.mkdir(parents=True, exist_ok=True)
        if exit_code != 0:
            raise HarnessError("simulated uv failure", stage="runtime_build", reason="candidate_build_failed_cleanly", retryable=True, reportable=False)
        if os.name == "nt":
            # Copy PEP-405 pyvenv.cfg if running inside a venv so venvlauncher exits 0 instead of 106
            import shutil

            src_cfg = Path(sys.prefix) / "pyvenv.cfg"
            if src_cfg.is_file():
                shutil.copy2(src_cfg, venv_dir / "pyvenv.cfg")
            shutil.copy2(sys.executable, py)
            src_pyw = Path(sys.executable).with_name("pythonw.exe")
            if src_pyw.is_file():
                shutil.copy2(src_pyw, py.with_name("pythonw.exe"))
            else:
                py.with_name("pythonw.exe").write_bytes(_fake_pe_gui_bytes())
        else:
            py.write_text(f"#!/bin/sh\nexec \"{sys.executable}\" \"$@\"\n", encoding="utf-8")
            py.chmod(0o755)

    return _builder


@pytest.mark.tier1
def test_10_fault_injection_upgrade_and_gc_scenarios(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    profile = ProfileRef.resolve(
        "codex",
        plugin_root=tmp_path / "plugin",
        config_path=tmp_path / "cfg" / "codex.json",
        data_dir=tmp_path / "data",
    )
    profile.plugin_root.mkdir(parents=True)
    # Seed user consent to verify upgrades NEVER overwrite or delete it
    consent_payload = {"schema": "mindie-consent/1", "choice": "contribute", "choice_revision": 3}
    atomic_write_json(profile.consent_path, consent_payload)

    # --- Scenario 1: Disk < 2.5 GiB blocks candidate build cleanly while small receipts still succeed ---
    low_disk = lambda _p: _DiskUsage(10 * 1024**3, 9 * 1024**3, MIN_BUILD_FREE_BYTES - 1024)
    with pytest.raises(HarnessError) as disk_exc:
        prepare_candidate_runtime(
            profile,
            selection=RuntimeSelection.from_pins({"mindie-harness": {"version": "0.1.0", "revision": "a" * 40}}),
            builder_fn=_make_fast_builder(),
            usage_fn=low_disk,
        )
    assert disk_exc.value.reason == "insufficient_disk_space"
    assert disk_exc.value.reportable is False
    # Small receipt write still works despite low disk floor!
    marker = write_pending_update_check(profile, reason="low_disk_receipt_ok")
    assert marker.is_file()

    # --- Scenario 2: Clean non-zero builder failure leaves ZERO permanent `unknown` self-brick ---
    sel_v1 = RuntimeSelection.from_pins({"mindie-harness": {"version": "0.1.0", "revision": "1" * 40}}, plugin_version="0.1.34")
    with pytest.raises(HarnessError) as fail_exc:
        prepare_runtime(profile, selection=sel_v1, builder_fn=_make_fast_builder(exit_code=2))
    assert fail_exc.value.reason == "candidate_build_failed_cleanly"
    assert fail_exc.value.retryable is True
    assert not (profile.generations_dir / sel_v1.generation_key / "runtime.json").exists()
    # Immediate retry succeeds cleanly!
    prep_v1 = prepare_runtime(profile, selection=sel_v1, builder_fn=_make_fast_builder())
    assert prep_v1.status == "validated"

    # --- Scenario 3: Interrupted/stale `.building` sentinel directory recovered on rebuild ---
    sel_v2 = RuntimeSelection.from_pins({"mindie-harness": {"version": "0.1.0", "revision": "2" * 40}}, plugin_version="0.1.35")
    stale_dir = profile.generations_dir / sel_v2.generation_key
    stale_dir.mkdir(parents=True)
    (stale_dir / BUILDING_SENTINEL).write_text("999999\n", encoding="utf-8")
    prep_v2 = prepare_runtime(profile, selection=sel_v2, builder_fn=_make_fast_builder())
    assert prep_v2.status == "validated"
    act_v1 = activate_runtime(profile, prep_v1, run_gc=False)
    assert act_v1.status == "active"

    # --- Scenario 4: Pre-commit hook failure (e.g. scheduler migration) aborts BEFORE <host>.json flips ---
    def _boom_pre_commit(_prof, _prep, _cfg) -> None:
        raise RuntimeError("simulated scheduler migration failure")

    with pytest.raises(RuntimeError, match="scheduler migration"):
        activate_runtime(profile, prep_v2, on_before_commit=_boom_pre_commit)
    # Authoritative <host>.json still points to v1!
    assert read_json_safe(profile.config_path)["component_release"] == str(prep_v1.generation_dir)

    # --- Scenario 5: Lock contention (`LockTimeoutError`) returns `deferred` (`reportable=False`) ---
    sel_v3 = RuntimeSelection.from_pins({"mindie-harness": {"version": "0.1.0", "revision": "3" * 40}}, plugin_version="0.1.36")
    with FileLock(profile.generations_dir / f".prepare.{sel_v3.generation_key}.lock", exclusive=True, timeout=1.0):
        deferred_prep = prepare_runtime(profile, selection=sel_v3, lock_timeout=0.02, builder_fn=_make_fast_builder())
    assert deferred_prep.status == "deferred" and deferred_prep.reportable is False

    with FileLock(profile.config_path.with_name(f".{profile.config_path.name}.update.lock"), exclusive=True, timeout=1.0):
        deferred_act = activate_runtime(profile, prep_v2, lock_timeout=0.02)
    assert deferred_act.status == "deferred" and deferred_act.reportable is False

    # --- Scenario 6: Crash during `os.replace` leaves ZERO `.tmp` leak & preserves config + consent ---
    orig_replace = os.replace

    def _failing_replace(src, dst):
        if str(dst).endswith("codex.json"):
            raise OSError("injected disk error on replace")
        return orig_replace(src, dst)

    monkeypatch.setattr(os, "replace", _failing_replace)
    with pytest.raises(OSError, match="injected disk error"):
        atomic_write_bytes(profile.config_path, b'{"corrupt": true}')
    monkeypatch.setattr(os, "replace", orig_replace)
    assert not list(profile.config_path.parent.glob(".codex.json.tmp.*"))
    assert read_json_safe(profile.config_path)["component_release"] == str(prep_v1.generation_dir)
    assert read_json_safe(profile.consent_path) == consent_payload

    # --- Scenarios 7 & 8: `.inuse` lease + Scheduled Task + Cross-Plugin Closure + `Active + Rollback <= 2` ---
    prep_v3 = prepare_runtime(profile, selection=sel_v3, builder_fn=_make_fast_builder())
    sel_v4 = RuntimeSelection.from_pins({"mindie-harness": {"version": "0.1.0", "revision": "4" * 40}}, plugin_version="0.1.37")
    sel_v5 = RuntimeSelection.from_pins({"mindie-harness": {"version": "0.1.0", "revision": "5" * 40}}, plugin_version="0.1.38")
    prep_v4 = prepare_runtime(profile, selection=sel_v4, builder_fn=_make_fast_builder())
    prep_v5 = prepare_runtime(profile, selection=sel_v5, builder_fn=_make_fast_builder())

    # Activate v5 (so Active=v5, newest Rollback=v4).
    # Protect v1 via Scheduled Task `.pyw` file in state_dir, protect v2 via cross-plugin `kimi.json`,
    # and hold a live `.inuse` lease on v3!
    sched_pyw = profile.state_dir / "MindIEKimiUpdate.pyw"
    atomic_write_json(profile.config_path.parent / "kimi.json", {"host": "kimi", "python": str(prep_v2.python_path)})
    sched_pyw.parent.mkdir(parents=True, exist_ok=True)
    sched_pyw.write_text(f"cmd = ['{prep_v1.python_path}', 'check']\n", encoding="utf-8")

    with acquire_generation_lease(prep_v3.generation_dir):
        act_v5 = activate_runtime(profile, prep_v5, run_gc=True)
        assert act_v5.status == "active"
        # v1 (scheduled), v2 (kimi.json), v3 (leased -> deferred_in_use), v4 (rollback), v5 (active) ALL survive!
        for p in (prep_v1, prep_v2, prep_v3, prep_v4, prep_v5):
            assert p.generation_dir.is_dir()
        assert act_v5.gc_summary is not None and act_v5.gc_summary["deferred_dirs"] == 1

    # Now lease on v3 is released -> next GC pass reclaims v3 while keeping v1, v2, v4, v5!
    gc_after = reclaim_generations(profile)
    assert gc_after["reclaimed_dirs"] == 1
    assert not prep_v3.generation_dir.exists()
    for p in (prep_v1, prep_v2, prep_v4, prep_v5):
        assert p.generation_dir.is_dir()

    # --- Scenario 9: Hook `pending-update-check.json` handoff consumed asynchronously by `maintain_runtime` ---
    write_pending_update_check(profile, reason="session_start")
    consumed_events: list[dict] = []
    maint = maintain_runtime(
        profile,
        consume_pending_check=True,
        builder_callback=lambda _prof, ev: consumed_events.append(ev) or {"status": "checked"},
    )
    assert len(consumed_events) == 1 and consumed_events[0]["reason"] == "session_start"
    assert not profile.pending_update_path.exists()
    assert maint["update_outcome"] == {"status": "checked"}

    # --- Scenario 10: Iron Rule 1 read-only DB check + Receipt Honesty (`isError=False` + `receipt_warning`) ---
    missing_db = tmp_path / "never_created.sqlite3"
    assert open_wal_database(missing_db, create=False) is None
    assert not missing_db.exists()

    tools = [
        {
            "name": "remote_write",
            "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]},
        }
    ]
    router = MCPRouter(
        profile,
        surface="remote",
        tools=tools,
        handler=lambda _ctx, args: {"content": [{"type": "text", "text": f"wrote {args['path']}"}], "isError": False},
    )

    def _broken_finish(_cid: str, _outcome: str, **_kw) -> None:
        raise OSError("simulated local SQLite disk full on finish")

    monkeypatch.setattr(router.receipts, "finish", _broken_finish)
    resp = router.call_tool({"jsonrpc": "2.0", "id": "req-10", "method": "tools/call", "params": {"name": "remote_write", "arguments": {"path": "/tmp/a"}}})
    assert resp["isError"] is False
    assert resp["receipt_unconfirmed"] is True
    assert "simulated local SQLite disk full" in resp["receipt_warning"]
    assert read_json_safe(profile.consent_path) == consent_payload
