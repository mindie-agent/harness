## 变更摘要 (Summary)

- 

## 底座架构核查清单 (Pre-PR Checklist — `harness`)

> 请逐项核实并勾选 `[x]`；纯文档变更可在证据栏填写 `not-applicable: docs-only`。

- [ ] **HAR-ABI（纯标准库零重依赖与根包契约）**：确认根包路径保持 `mindie_harness/`（兼容 `triage_card.py` `"package"` 规则）、`API_VERSION = 1` 公共契约向后兼容、核心零第三方运行时重依赖，且新增/修改模块 `< 800` 行并具备标准四段式头部文档。
- [ ] **HAR-UPGRADE（双代原子切流、`.inuse` 租约 GC 与冷启动 Seed 一致性）**：确认候选构建遵守 `2.5 GiB` 磁盘下限、权威宿主配置最后一步原子落盘、保留 `Active + Rollback (<= 2)` 及租约/计划任务闭包，且 `python3 scripts/build_seed.py --check` 校验通过。
- [ ] **HAR-PROC（跨平台受管进程树与 Windows 11 零弹窗证据）**：确认无裸调 `Popen` / `CREATE_NEW_CONSOLE` / `DETACHED_PROCESS` / Windows `os.kill(pid, 0)`，满足 `outer_timeout >= sum(inner) + cleanup_grace` 且 `except TimeoutError: raise` 置于 `except OSError:` 之前（涉及 Win32 进程/计划任务改动须附 Win11 零 `conhost.exe` 实测证据）。
- [ ] **HAR-STATE（SQLite WAL / WSL2 DrvFS 防护、`P2.7`/`P2.8` 全表面静默默认开放与 Receipt Honesty）**：确认只读检查不创建空库、WSL2 DrvFS 阻断 WAL、全表面（含 `knowledge_*`）零前置会话绑定直通（`P2.7` / `P2.8`）、主操作成功后本地回执异常保持 `isError=False` 并附 `receipt_warning`，且兼容 linked Git worktree。
- **自查结论与证据**：

## 验证结果 (Verification)

- 
