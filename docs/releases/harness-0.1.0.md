# mindie-harness 0.1.0：7 大原生宿主插件统一纯标准库底座首发

[English](harness-0.1.0.en.md)

`mindie-harness v0.1.0` 正式发布，作为 MindIE Agent 全系 7 个原生宿主插件（`codex`、`cc`、`kimi`、`dsh`、`agy`、`wb`、`oc`）共用的零重依赖纯 Python 标准库共享底座（`mindie_harness`）：

- **跨平台无窗进程与嵌套 Win32 Job 监管（`mindie_harness.process`）**：Windows 统一采用 `CreateProcessW(CREATE_SUSPENDED | CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT | CREATE_NEW_PROCESS_GROUP)` 并在 `ResumeThread` 前挂载非继承嵌套 Job Object（`KILL_ON_JOB_CLOSE` + 控制面 `512 MiB` 内存硬限 + 后台维护降权），彻底禁用 `CREATE_NEW_CONSOLE` / `DETACHED_PROCESS`；计划任务与 GUI Worker 强制校验解释器及 `pyvenv.cfg` 基础二进制的 `IMAGE_SUBSYSTEM_WINDOWS_GUI` PE 头；POSIX / WSL2 采用进程组生命周期与等待管道 EOF 排空机制，并过滤 WSL2 DrvFS / `.exe` / `MZ` 垫片。
- **单活双代（`Active + Rollback`）`.inuse` 租约原子更新（`mindie_harness.runtime`）**：候选环境构建前执行 `>= 2.5 GiB` 可用磁盘空间门禁与同卷 `UV_CACHE_DIR` 固定，单 `.venv` 原地校验后最后一步原子更新 `<host>.json` 权威指针；通过非 `FILE_SHARE_DELETE` `.inuse` 租约句柄与双阶段 `.trash` 原子重命名安全回收旧代，最多保留 `<= 2` 代及跨插件活跃闭包。
- **双帧长驻并发 MCP 网关与诚实回执（`mindie_harness.mcp`）**：同时兼容 `Content-Length` 与 JSONL 标准输入输出帧，只读状态查询与取消通道独立并发；严格落实 `P2.7` 确定性工具零会话绑定直通、`P2.1` `knowledge_*` 显式会话准入分流，以及主操作成功后本地回执异常保持 `isError=False` 并附带 `receipt_warning` + `receipt_unconfirmed=True`。
- **单状态源 `ExperimentLedger` RSI 闭环与确定性冷启动 Seed（`mindie_harness.rsi` & `mindie_harness.bootstrap`）**：统一承载兼容 linked Git worktree 的纯标准库 `experiment_ledger` / `rsi_loop`（`mindie-rsi-loop/2`）引擎，并提供可重现 `< 60 KB` `dist/mindie-harness-seed.pyz` 与 `seed-lock.json`（`mindie-harness-seed/1`）冷启动引导包。
