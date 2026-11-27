# Contributing to `mindie-agent/harness`

简体中文: [CONTRIBUTING.md](CONTRIBUTING.md) | English

Thank you for contributing to `mindie-harness`! Because this repository provides the shared pure-stdlib substrate for the MindIE Agent host plugins, changes here directly govern process safety, atomic auto-updates, and concurrent MCP reliability across macOS, Linux, Windows 11, and WSL2.

## 1. Flat Workspace & Linked Git Worktree Workflow

Use the organization-standard flat sibling layout with linked worktrees under `../.worktrees/`:

```bash
git -C ../harness worktree add -b feat/my-change ../.worktrees/harness-my-change origin/main
cd ../.worktrees/harness-my-change
```

*(When running sandboxed CLI agents from `mindie-agent/`, grant write access to both `../harness` and `../.worktrees/harness-<topic>` so Git can update refs in `commondir`.)*

## 2. Core Engineering Rules

1. **Pure Stdlib & Root Package Layout (`HAR-ABI`)**: Keep `mindie_harness/` at the repository root (never `src/mindie_harness/`), keep core `dependencies = []`, never import `mindie_knowledge`, `mindie_diagnostics`, `torch`, or host plugins at top level, and keep modules `< 800` lines with `[Role]` / `[Invariants]` / `[Timeouts & Locks]` / `[Side-Effect Policy]` headers.
2. **Windows Zero-Popup & Process Ownership (`HAR-PROC`)**: Never pass `CREATE_NEW_CONSOLE` or `DETACHED_PROCESS` on Windows, never call unguarded `os.kill(pid, 0)` on Windows, always attach nested Job Objects before `ResumeThread`, and verify PE `Subsystem == 2` for GUI/scheduled interpreters.
3. **Atomic Upgrades & Seed Reproducibility (`HAR-UPGRADE`)**: Whenever `mindie_harness/bootstrap/seed_main.py` changes, run `python3 scripts/build_seed.py` (`< 60 KB` `.pyz`, `< 115`-line template).
4. **State Honesty & Test Isolation (`HAR-STATE`)**: Isolate `MINDIE_CONFIG_HOME`, `MINDIE_DATA_HOME`, `HOME`/`USERPROFILE`, `XDG_*`, and `UV_CACHE_DIR` in all tests, and enforce Unix `LF` (`\n`) line endings.

## 3. Pre-PR Verification Commands

```bash
python3 scripts/build_seed.py --check
python3 .github/scripts/check_lf_eol.py
pytest -q
python3 .github/scripts/check_pr_checklist.py --profile harness --body-file /path/to/pr_body.md
```
