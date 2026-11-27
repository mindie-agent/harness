# MindIE Harness (`mindie-harness`)

<p>
  <a href="https://github.com/mindie-agent/harness/releases"><img src="https://img.shields.io/badge/Release-v0.1.9-blue" alt="Release v0.1.9"></a>
</p>

简体中文: [README.md](README.md) | English

`mindie-harness` (repository `mindie-agent/harness`, import package `mindie_harness`, version `0.1.9`) is the **zero-heavy-dependency, pure-Python-stdlib shared plugin substrate** (`API_VERSION = 1`) powering the MindIE Agent host plugins `codex`, `cc`, `kimi`, `dsh`, `agy`, `wb`, `oc`, and `omp` (oh-my-pi).

## Core Responsibilities

1. **Cross-Platform Process Supervision & Windows 11 Zero-Popup Kernel Safety (`mindie_harness.process`)**
   - Spawns Windows children via `CreateProcessW(CREATE_SUSPENDED | CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT | CREATE_NEW_PROCESS_GROUP)` (forbidding `CREATE_NEW_CONSOLE` and `DETACHED_PROCESS`) and attaches a non-inheritable nested Job Object (`KILL_ON_JOB_CLOSE`, `512 MiB` control-plane memory limit, optional `JOB_OBJECT_LIMIT_BREAKAWAY_OK` for explicit daemons, `BELOW_NORMAL_PRIORITY_CLASS`, and `CpuRateControl`) **before** `ResumeThread`.
   - Verifies PE `OptionalHeader.Subsystem == 2` (`IMAGE_SUBSYSTEM_WINDOWS_GUI`) on both `.venv\Scripts\pythonw.exe` and base `pyvenv.cfg` `pythonw.exe` interpreters, automatically repairing `uv <= 0.12.3` console-subsystem (`Subsystem == 3`) venv `pythonw.exe` shims from CPython `venvwlauncher.exe`.
   - Uses `start_new_session=True` + `killpg` on POSIX and iterates all `$PATH` entries on WSL2 while skipping `.exe`/`.cmd`/`MZ` binaries and DrvFS mounts.
2. **Atomic Dual-Generation Lifecycle, `.inuse` Lease GC & 9-Domain `knowledge_binding` (`mindie_harness.runtime`)**
   - Enforces a `2.5 GiB` free-space floor on candidate builds, pins same-volume `UV_CACHE_DIR`, installs prebuilt wheelhouses offline with `--override`, runs Gate Layer 1 `candidate` selftests before writing `runtime.json` (`validated`), and commits `<host>.json` last; resident MCP servers and `maintain` consume `pending-update-check.json` in the background via `update_runtime`.
   - Protects live generations via non-`FILE_SHARE_DELETE` `.inuse.<pid>.<uuid>.lease` handles + two-stage `.trash.<uuid>` atomic directory renames, retaining `Active + Rollback (<= 2)`, cross-plugin pointers, and OS-scheduled closures (`MindIEKimiUpdate` and diagnostics reporting services).
   - `knowledge_binding` provisions content-addressed `<config_home>/engines/<host>/<20hex>/<domain>.engine.json` configs across all 9 public corpora via `domain_catalog.prepare`; defaults to `capture_mode="disabled"` (`noop_transcript_adapter.py`) when standalone or `gitleaks` is absent, upgrades automatically to `"public-transcript"` when a host transcript adapter is bound with `retire_changed` / `restore_changed` rollback safety, and enforces `< 100ms` zero-SQLite `run_stop_capture` honoring permanent `inactive` session revocation.
3. **Dual-Framing Concurrent MCP Gateway & Cross-Component Contracts (`mindie_harness.mcp`)**
   - `mindie-harness mcp <surface>` serves `ManagedMCPAdapter` by default over both `Content-Length` and JSONL stdio framing; read-only, status, and cancel calls skip `BindStore.claim_bind` writer locks and run on a lock-free fast lane without blocking behind foreground mutations.
   - Enforces 100% silent default-on & `P2.7` / `P2.8` zero pre-call session binding across `remote`, `tools`, `components`, `knowledge`, and `all`: strips optional correlation keys (`request_nonce`, `_mindie_bind_id`, `context_file`), accepts schema-declared `remote_*` `session_id` job handles while blocking forged identity overrides, falls back to `{host}-conn-{connection_id[:12]}`, isolates multi-session `remote_dev` calls via `session_scope` or framed stdin/stdout child IPC with `safe_auth_error_details` sanitization, and preserves Receipt Honesty (`isError=False` + `receipt_warning` + `receipt_unconfirmed=True`).
   - `knowledge_rpc` prioritizes `<host>.json["python"]` via framed stdin/stdout child IPC (`MINDIE_KRPC_JSON:`), supporting `query(query|continuation)` (`35s`/`45s`), batch `explain(ref|refs)`, `feedback`, on-demand scoped `distill` leases (`450s`/`510s`), and honest `sync` feed-failure reporting. Cross-component dispatch preserves custom wrappers while standardizing `sim` (`mindie_sim.cli`), `npu_top` (default `["--json", "servers"]`), `coordinator` (`MINDIE_COORDINATOR_NATIVE_CALL=1`), `<= 1 MiB` `stdin_text`/`stdin_json` for `debugger` and RSI, `ProfileRef`-aware `mindie_doctor`, and locked `sharing` writes preserving `diagnostics.json["revision"]` plus `fork`/`account` on `mindie-community.json`.
4. **Consolidated Pure-Stdlib RSI Engine (`mindie_harness.rsi`)**
   - Hosts linked-worktree-safe `experiment_ledger`, `rsi_loop` (`mindie-rsi-loop/2`), `rsi_crossover`, and `rsi_explore`.
5. **Reproducible `< 60 KB` Cold-Bootstrap Seed & Gate Layer 1 Selftest (`mindie_harness.bootstrap` / `mindie_harness.selftest`)**
   - Builds deterministic `dist/mindie-harness-seed.pyz` + `dist/seed-lock.json` (`mindie-harness-seed/1`) and renders the `< 115`-line stdlib plugin launcher template.
   - Ships `mindie-harness selftest --mode candidate|full [--json]` (`mindie-selftest/1`) verifying dual-framing stdio MCP, Topology 1 (`.venv`) + Topology 2 (stdlib bootstrap -> `.venv` child IPC), and zero-mock 9-package full-stack integration.

## Quick Start

```bash
# Inspect version, profile state, and read-only diagnostics health
mindie-harness --version
mindie-harness inspect --host codex
mindie-harness doctor --host codex

# Run Gate Layer 1 candidate smoke and 9-package full-stack contract selftests
mindie-harness selftest --host codex --mode candidate --json
mindie-harness selftest --host codex --mode full --json

# Verify deterministic cold-bootstrap Seed lock and run local orthogonal tests
python3 scripts/build_seed.py --check
pytest -q
```
