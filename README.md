# MindIE Harness (`mindie-harness`)

<p>
  <a href="https://github.com/mindie-agent/harness/releases"><img src="https://img.shields.io/badge/Release-v0.1.8-blue" alt="Release v0.1.8"></a>
</p>

[English](README.en.md) | 简体中文

`mindie-harness`（仓库 `mindie-agent/harness`，导入包 `mindie_harness`，当前版本 `0.1.8`）是 MindIE Agent 7 个原生宿主插件（`codex`、`cc`、`kimi`、`dsh`、`agy`、`wb`、`oc`）共用的**零重依赖纯 Python 标准库底座**（`API_VERSION = 1`）。

## 核心职责边界

1. **跨平台受管进程与 Windows 11 零弹窗内核监管 (`mindie_harness.process`)**
   - Windows 统一采用 `CreateProcessW(CREATE_SUSPENDED | CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT | CREATE_NEW_PROCESS_GROUP)`，严禁 `CREATE_NEW_CONSOLE` / `DETACHED_PROCESS`；在 `ResumeThread` 前挂载嵌套非继承 Job Object（`KILL_ON_JOB_CLOSE` + 控制面 `512 MiB` 内存硬限 + 显式守护进程 `JOB_OBJECT_LIMIT_BREAKAWAY_OK` + 后台维护 `BELOW_NORMAL_PRIORITY_CLASS` + `CpuRateControl`）。
   - 系统计划任务 / GUI Worker 强制双层校验 `.venv\Scripts\pythonw.exe` 与 `pyvenv.cfg` 基底 `pythonw.exe` 的 PE 头 `OptionalHeader.Subsystem == 2`（`IMAGE_SUBSYSTEM_WINDOWS_GUI`），并自动使用基底 CPython `venvwlauncher.exe` 修复 `uv <= 0.12.3` 生成的控制台子系统启动器。
   - POSIX / WSL2 采用 `start_new_session=True` + `killpg` 进程组回收；WSL2 二进制解析器完整遍历 `$PATH` 并跳过 `.exe`/`.cmd`/`MZ` 与 DrvFS 挂载盘。
2. **双代原子更新、`.inuse` 租约回收与 9 域知识引擎绑定 (`mindie_harness.runtime`)**
   - 候选环境构建执行 `>= 2.5 GiB` 可用磁盘预检、同卷 `UV_CACHE_DIR` 硬链接、零 Git `--override` Wheelhouse 离线安装与 Gate Layer 1 `candidate` 自检，权威指针 `<host>.json` 最后一步原子落盘；常驻 MCP 与 `maintain` 后台异步消费 `pending-update-check.json` 驱动 `update_runtime`。
   - Windows 非 `FILE_SHARE_DELETE` `.inuse.<pid>.<uuid>.lease` 句柄配合双阶段同卷 `.trash.<uuid>` 原子改名回收，保留 `Active + Rollback (<= 2)` 代、跨插件配置与系统计划任务闭包（含 `MindIEKimiUpdate` 与诊断上报服务）。
   - `knowledge_binding` 基于 `domain_catalog.prepare` 为全部 9 个公开语料库生成内容寻址配置 `<config_home>/engines/<host>/<20hex>/<domain>.engine.json`；独立运行或缺少 `gitleaks` 时默认 `capture_mode="disabled"`（绑定 `noop_transcript_adapter.py`）并在宿主适配器就绪后自动升级为 `"public-transcript"`，切换失败可通过 `retire_changed` / `restore_changed` 回滚；`run_stop_capture` 在未授权或超范围目录实现 `< 100ms` 零 SQLite 跳过，并永久尊重 `inactive` 会话撤销。
3. **双帧长驻并发 MCP 网关与跨组件契约 (`mindie_harness.mcp`)**
   - `mindie-harness mcp <surface>` 默认启用 `ManagedMCPAdapter`，同时兼容 `Content-Length` 与 JSONL 帧；只读/状态查询/取消调用跳过 `BindStore.claim_bind` 写锁并走独立高并发快车道，绝不被前台慢操作阻塞。
   - 全表面（`remote`、`tools`、`components`、`knowledge`、`all`）贯彻静默默认就绪与零前置会话绑定直通（`P2.7` / `P2.8`）：自动剥离可选关联键（`request_nonce`、`_mindie_bind_id`、`context_file`），保留 Schema 声明的 `remote_*` `session_id` 作业句柄并拦截伪造身份覆盖，在缺失宿主元数据时回退至 `{host}-conn-{connection_id[:12]}`；`remote_dev` 通过 `session_scope` 与帧化 stdin/stdout 子进程 IPC 隔离多会话环境并执行 `safe_auth_error_details` 脱敏，主操作成功后本地记账异常统一保持 `isError=False` 并附加 `receipt_warning` + `receipt_unconfirmed=True`。
   - `knowledge_rpc` 优先路由至 `<host>.json["python"]`（`MINDIE_KRPC_JSON:` 帧化 stdin/stdout IPC），支持 `query(query|continuation)`（`35s`/`45s`）、批量 `explain(ref|refs)`、`feedback`、按需范围授权 `distill` 租约（`450s`/`510s`）及 `sync` 源失败诚实上报；跨组件分发保留用户自定义包装器，统一 `sim`（`mindie_sim.cli`）、`npu_top`（默认 `["--json", "servers"]`）、`coordinator`（`MINDIE_COORDINATOR_NATIVE_CALL=1`）、`debugger`/`rsi`（`<= 1 MiB` `stdin_text`/`stdin_json`）、感知 `ProfileRef` 的 `mindie_doctor` 以及加锁保版本的 `sharing` 策略写入。
4. **纯标准库 RSI 实验账本与循环状态机 (`mindie_harness.rsi`)**
   - 统一承载兼容 linked Git worktree `.git` 文件的 `experiment_ledger`、`rsi_loop`（`mindie-rsi-loop/2`）、`rsi_crossover` 与 `rsi_explore`。
5. **`< 60 KB` 确定性冷启动 Seed 与 Gate Layer 1 全栈自检 (`mindie_harness.bootstrap` / `mindie_harness.selftest`)**
   - 确定性构建 `dist/mindie-harness-seed.pyz` 与 `dist/seed-lock.json`（`mindie-harness-seed/1`），向 7 个薄宿主插件输出 `< 115` 行纯标准库冷启动转发入口。
   - 内置 `mindie-harness selftest --mode candidate|full [--json]`（`mindie-selftest/1`），覆盖底座双帧协议、Topology 1（`.venv` 直连）与 Topology 2（纯标准库引导转发 `.venv` 子进程 IPC）及 9 包真实全栈闭环验证。

## 快速使用

```bash
# 查看版本、配置快照与只读健康诊断
mindie-harness --version
mindie-harness inspect --host codex
mindie-harness doctor --host codex

# 运行 Gate Layer 1 候选环境快速自检与 9 包全栈契约自检
mindie-harness selftest --host codex --mode candidate --json
mindie-harness selftest --host codex --mode full --json

# 校验冷启动 Seed 确定性锁并运行本地正交测试
python3 scripts/build_seed.py --check
pytest -q
```
