# MindIE Harness (`mindie-harness`)

<p>
  <a href="https://github.com/mindie-agent/harness/releases"><img src="https://img.shields.io/badge/Release-v0.1.4-blue" alt="Release v0.1.4"></a>
</p>

简体中文: [README.md](README.md) | English

`mindie-harness` (repository `mindie-agent/harness`, import package `mindie_harness`, version `0.1.4`) is the **zero-heavy-dependency, pure-Python-stdlib shared plugin substrate** powering all 7 MindIE Agent host plugins (`codex`, `cc`, `kimi`, `dsh`, `agy`, `wb`, `oc`).

## Core Responsibilities

1. **Cross-Platform Process Supervision & Windows 11 Zero-Popup Kernel Safety (`mindie_harness.process`)**
   - Spawns Windows children via `CreateProcessW(CREATE_SUSPENDED | CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT | CREATE_NEW_PROCESS_GROUP)` (forbidding `CREATE_NEW_CONSOLE` and `DETACHED_PROCESS`) and attaches a non-inheritable nested Job Object (`KILL_ON_JOB_CLOSE`, optional `512 MiB` memory limit, `BELOW_NORMAL_PRIORITY_CLASS`, and best-effort `CpuRateControl`) **before** `ResumeThread`.
   - Verifies PE `OptionalHeader.Subsystem == 2` (`IMAGE_SUBSYSTEM_WINDOWS_GUI`) on both venv and base `pyvenv.cfg` `pythonw.exe` interpreters for GUI/Scheduled-Task workers.
   - Uses `start_new_session=True` + `killpg` on POSIX and iterates all `$PATH` entries on WSL2 while rejecting `.exe`/`.cmd`/`MZ` binaries and DrvFS mounts.
2. **Atomic Dual-Generation Runtime Lifecycle & `.inuse` Lease GC (`mindie_harness.runtime`)**
   - Enforces a `2.5 GiB` free-space floor on candidate runtime builds (never blocking small receipt writes), pins same-volume `UV_CACHE_DIR`, builds a single `.venv` at the final generation path, and commits `<host>.json` last.
   - Protects live generations via non-`FILE_SHARE_DELETE` `.inuse.<pid>.<uuid>.lease` handles + two-stage `.trash.<uuid>` atomic directory renames, retaining `Active + Rollback (<= 2)` plus cross-plugin and OS-scheduled closures.
3. **Dual-Framing Concurrent Resident MCP Gateway & Receipt Honesty (`mindie_harness.mcp`)**
   - Serves both `Content-Length` and JSONL stdio framing concurrently; read-only/status/cancel calls (including `knowledge_query` and `knowledge_explain`) never block behind foreground mutations.
   - Enforces 100% silent default-on & `P2.7` / `P2.8` zero pre-call session binding uniformly across all MCP surfaces (`remote`, `tools`, `components`, `knowledge`, `all`), stripping optional correlation keys (`request_nonce`, `_mindie_bind_id`, `context_file`), falling back to `{host}-conn-{connection_id[:12]}` when host metadata is absent, and preserving `isError=False` + `receipt_warning` + `receipt_unconfirmed=True` on post-success local receipt errors.
4. **Consolidated Pure-Stdlib RSI Engine (`mindie_harness.rsi`)**
   - Hosts linked-worktree-safe `experiment_ledger`, `rsi_loop` (`mindie-rsi-loop/2`), `rsi_crossover`, and `rsi_explore`.
5. **Reproducible `< 60 KB` Cold-Bootstrap Seed (`mindie_harness.bootstrap`)**
   - Builds deterministic `dist/mindie-harness-seed.pyz` + `dist/seed-lock.json` (`mindie-harness-seed/1`) and renders the `< 115`-line stdlib plugin launcher template.

## Quick Start

```bash
mindie-harness --version
mindie-harness inspect --host codex
python3 scripts/build_seed.py --check
pytest -q
```
