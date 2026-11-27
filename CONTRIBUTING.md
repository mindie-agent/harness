# 贡献指南 (`mindie-agent/harness`)

[English](CONTRIBUTING.en.md) | 简体中文

感谢为 `mindie-harness` 贡献代码！本仓承载 MindIE Agent 宿主插件共用的纯标准库底座，任何改动都会直接影响 macOS、Linux、Windows 11 与 WSL2 上的宿主启动、热更新与 MCP 并发可靠性。

## 1. 标准平铺目录与 Git Worktree 开发流

推荐使用平铺目录 + `.worktrees/` 链接工作树（若从 `mindie-agent` 主仓路由至此）：

```bash
# 在同级 .worktrees/ 创建隔离特性分支（注意沙箱需同时具备 ../harness 与对应 worktree 写权限）
git -C ../harness worktree add -b feat/my-change ../.worktrees/harness-my-change origin/main
cd ../.worktrees/harness-my-change
```

## 2. 开发红线与编码准则

1. **纯标准库与根包布局 (`HAR-ABI`)**：核心包位于仓库根 `mindie_harness/`（禁止改为 `src/`），`pyproject.toml` 运行时 `dependencies` 保持为空，严禁顶层导入 `mindie_knowledge`、`mindie_diagnostics`、`torch` 或宿主插件。单文件 `< 800` 行并包含 `[Role]` / `[Invariants]` / `[Timeouts & Locks]` / `[Side-Effect Policy]` 头部文档。
2. **Windows 零弹窗与进程树监管 (`HAR-PROC`)**：禁止在 Windows 使用裸 `subprocess.Popen`（无 `CREATE_NO_WINDOW`）、`CREATE_NEW_CONSOLE`、`DETACHED_PROCESS` 或裸调 `os.kill(pid, 0)`；涉及 GUI/计划任务必须通过 `verify_gui_subsystem` 校验 PE `Subsystem == 2`。
3. **双代原子更新与 Seed 一致性 (`HAR-UPGRADE`)**：若修改 `mindie_harness/bootstrap/seed_main.py`，必须运行 `python3 scripts/build_seed.py` 更新 `dist/mindie-harness-seed.pyz` 与 `dist/seed-lock.json`（`< 60 KB`，模板 `< 115` 行）。
4. **状态诚实与零宿主机污染 (`HAR-STATE`)**：测试必须完整隔离 `MINDIE_CONFIG_HOME`、`MINDIE_DATA_HOME`、`HOME`/`USERPROFILE`、`XDG_*` 与 `UV_CACHE_DIR`；所有文本文件使用 Unix `LF` (`\n`) 换行。

## 3. 提交前必跑门禁（Pre-PR Verification）

```bash
# 1. 校验冷启动 Seed 可重现性与哈希锁
python3 scripts/build_seed.py --check

# 2. 校验全仓 Unix LF 换行符
python3 .github/scripts/check_lf_eol.py

# 3. 运行 Tier 0 + Tier 1 正交行为测试与源码外 Wheel 安装冒烟测试
pytest -q

# 4. 校验 PR 描述清单（文档类 PR 可在核查项注明 not-applicable: docs-only）
python3 .github/scripts/check_pr_checklist.py --profile harness --body-file /path/to/pr_body.md
```
