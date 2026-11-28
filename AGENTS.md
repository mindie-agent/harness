# MindIE Harness (`mindie-agent/harness`) — Agent Operating Rules

This repository owns the shared pure-stdlib plugin substrate (`mindie_harness`, `API_VERSION = 1`) consumed by the MindIE Agent host plugins (`codex`, `cc`, `kimi`, `dsh`, `agy`, `wb`, `oc`, `omp`).

## 1. Non-Negotiable Architectural Invariants

1. **Root Package Layout & Zero Heavy Dependencies (`HAR-ABI`)**:
   - Keep `mindie_harness/` at repository root (`harness/mindie_harness/`, NEVER `src/mindie_harness/`) so `mindie_diagnostics/triage_card.py` (`layout == "package"`) resolves GitHub source permalinks cleanly.
   - Core `mindie_harness` and `mindie_harness/bootstrap/seed_main.py` MUST remain **100% pure Python standard library** (`dependencies = []`; optional `packaging` permitted only in `[project.optional-dependencies] updates` with a deterministic stdlib fallback). Never import `mindie_knowledge`, `mindie_diagnostics`, `torch`, `torch_npu`, or host plugin modules at top level.
   - Keep every Python module `< 800` lines with a top-30-line `[Role]` / `[Invariants]` / `[Timeouts & Locks]` / `[Side-Effect Policy]` docstring header.

2. **Windows 11 Zero-Popup & Process-Tree Ownership (`HAR-PROC`)**:
   - On Windows, all child processes MUST spawn via `CreateProcessW` with `CREATE_SUSPENDED | CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT | CREATE_NEW_PROCESS_GROUP` (NEVER `CREATE_NEW_CONSOLE` or `DETACHED_PROCESS`), attach a non-inheritable nested Job Object (`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, optional `512 MiB` memory limit, `BELOW_NORMAL_PRIORITY_CLASS` for background maintenance, best-effort `CpuRateControl`) **before** `ResumeThread`, and clean up handles on any pre-resume failure.
   - Scheduled Task / GUI workers MUST verify PE `OptionalHeader.Subsystem == 2` (`IMAGE_SUBSYSTEM_WINDOWS_GUI`) on both `.venv\Scripts\pythonw.exe` and any base `home\pythonw.exe` in `pyvenv.cfg`, and tolerate `sys.stdin/stdout/stderr is None`.
   - On POSIX/WSL2, spawn with `start_new_session=True` + `os.killpg` reclamation; iterate ALL `os.pathsep` `$PATH` entries when resolving native Linux tools, skipping `.exe`/`.cmd`/`.bat`, DrvFS paths, and `b"MZ"` PE shims.
   - Enforce `outer_timeout >= sum(inner_budgets) + cleanup_grace` (`Deadline`) and precede every broad `except OSError:` with `except TimeoutError: raise`.

3. **Atomic Dual-Generation Upgrades, `.inuse` Leases & Hook Decoupling (`HAR-UPGRADE`)**:
   - Enforce the `2.5 GiB` disk free-space floor on candidate runtime builds only (never blocking small receipt/marker JSON writes), pin same-volume `UV_CACHE_DIR`, build a single `.venv` at the final generation path, and commit `<host>.json` atomically **last** (never modifying `mindie-consent.json`).
   - Short-lived hooks (`SessionStart`) write `pending-update-check.json` (`< 5ms`) and NEVER spawn `uv sync` directly inside a host hook Job.
   - Retain at most `Active + Rollback (<= 2)` generations plus live `.inuse.<pid>.<uuid>.lease` (non-`FILE_SHARE_DELETE` on Windows), cross-plugin `<other_host>.json`, and OS Scheduled Task / LaunchAgent closures via two-stage same-volume `.trash.<uuid>` atomic directory renames.
   - Classify lock contention (`LockTimeoutError`) as `deferred` (`reportable=False`) and clean non-zero builder exits as retryable `failed_cleanly`—zero permanent local `unknown` self-bricking.
   - Whenever `mindie_harness/bootstrap/seed_main.py` changes, rebuild `dist/mindie-harness-seed.pyz` and `dist/seed-lock.json` via `python3 scripts/build_seed.py` and verify `python3 scripts/build_seed.py --check`.

4. **State Safety, WSL2 DrvFS Guard, Silent Default-On `P2.7`/`P2.8` MCP & Linked Worktrees (`HAR-STATE`)**:
   - Configure SQLite `WAL` + `busy_timeout=5000` once in `open_wal_database` (`open_database`); read-only checks (`create=False`) NEVER create empty SQLite files, and WSL2 `drvfs`/`9p` (`aname=drvfs`) paths fail fast with `drvfs_unsafe_state_root`.
   - All MCP surfaces (`remote`, `tools`, `components`, `knowledge`, `all`) enforce **100% silent default-on & zero pre-call session binding (`P2.7` / `P2.8`)**, stripping legacy correlation keys (`request_nonce`, `_mindie_bind_id`, `context_file`), falling back to `{host}-conn-{connection_id[:12]}` when host session metadata is absent, and running read-only/status/cancel calls (including `knowledge_query` and `knowledge_explain`) without blocking behind foreground mutations while rejecting forged identity arguments.
   - Preserve Receipt Honesty (`isError=False` + `receipt_warning` + `receipt_unconfirmed=True`) when local receipt writes fail after a primary operation succeeds.
   - Keep `mindie_harness.rsi` linked-worktree safe (`.git` directory and `.git` file `gitdir:` checkouts).

## 2. Sibling Workspace & Verification Protocol

- Standard workspace topology places sibling repos at `../<repo>` and isolated topic branches at `../.worktrees/harness-<topic>`.
- Isolate `HOME`, `USERPROFILE`, `APPDATA`, `LOCALAPPDATA`, `XDG_*`, `MINDIE_CONFIG_HOME`, `MINDIE_DATA_HOME`, `MINDIE_DIAGNOSTICS_ROOT`, `MINDIE_REMOTE_STATE_DIR`, `UV_CACHE_DIR`, and `TMPDIR` in all tests.
- Before committing, run:
  ```bash
  python3 scripts/build_seed.py --check
  python3 .github/scripts/check_lf_eol.py
  pytest -q
  ```
