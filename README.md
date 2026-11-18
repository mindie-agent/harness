# MindIE Harness (`mindie-harness`)

<p>
  <a href="https://github.com/mindie-agent/harness/releases"><img src="https://img.shields.io/badge/Release-v0.1.3-blue" alt="Release v0.1.3"></a>
</p>

[English](README.en.md) | 简体中文

`mindie-harness`（仓库 `mindie-agent/harness`，导入包 `mindie_harness`，当前版本 `0.1.3`）是 MindIE Agent 7 个原生宿主插件（`codex`、`cc`、`kimi`、`dsh`、`agy`、`wb`、`oc`）共用的**零重依赖纯 Python 标准库底座**。

## 核心职责边界

1. **跨平台受管进程与 Windows 11 零弹窗内核监管 (`mindie_harness.process`)**
   - Windows 统一采用 `CreateProcessW(CREATE_SUSPENDED | CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT | CREATE_NEW_PROCESS_GROUP)`，严禁 `CREATE_NEW_CONSOLE` / `DETACHED_PROCESS`；在 `ResumeThread` 前挂载嵌套非继承 Job Object（`KILL_ON_JOB_CLOSE` + 控制面 `512 MiB` 内存硬限 + 后台维护 `BELOW_NORMAL_PRIORITY_CLASS` + `CpuRateControl`）。
   - 系统计划任务 / GUI Worker 强制校验可执行文件与 `pyvenv.cfg` 基础解释器 PE 头 `OptionalHeader.Subsystem == 2`（`IMAGE_SUBSYSTEM_WINDOWS_GUI`）。
   - POSIX / WSL2 采用 `start_new_session=True` + `killpg` 进程组回收；WSL2 二进制解析器完整遍历 `$PATH` 并跳过 `.exe`/`.cmd`/`MZ` 与 DrvFS 挂载盘。
2. **单活双代原子更新与 `.inuse` 租约回收 (`mindie_harness.runtime`)**
   - 候选环境构建强制 `>= 2.5 GiB` 可用磁盘预检（绝不阻塞轻量回执落盘）、同卷 `UV_CACHE_DIR` 零拷贝硬链接、最终路径单 `.venv` 构建，权威指针 `<host>.json` 最后一步原子提交。
   - Windows 非 `FILE_SHARE_DELETE` `.inuse.<pid>.<uuid>.lease` 句柄 + 双阶段同卷 `.trash.<uuid>` 原子改名探测，保留 `Active + Rollback (<= 2)` 代及跨插件/计划任务闭包。
3. **双帧长驻并发 MCP 网关与诚实回执 (`mindie_harness.mcp`)**
   - 同时兼容 `Content-Length` 与 JSONL 帧；只读/状态查询/取消请求（含 `knowledge_query` 与 `knowledge_explain`）走独立高并发线程池，绝不被慢速前台命令阻塞。
   - 统一贯彻全表面（`remote`、`tools`、`components`、`knowledge`、`all`）静默默认就绪与零前置会话绑定直通（`P2.7` / `P2.8`），自动剥离可选关联键（`request_nonce`、`_mindie_bind_id`、`context_file`）并在缺失宿主元数据时回退至连接标识 `{host}-conn-{connection_id[:12]}`；落实 Receipt Honesty（主操作成功后本地回执异常保持 `isError=False` 并附加 `receipt_warning` + `receipt_unconfirmed=True`）。
4. **纯标准库 RSI 实验账本与循环状态机 (`mindie_harness.rsi`)**
   - 统一承载 `experiment_ledger`（原生支持 linked Git worktree `.git` 文件）、`rsi_loop`（`mindie-rsi-loop/2`）、`rsi_crossover` 与 `rsi_explore`。
5. **`< 60 KB` 可重现冷启动 Seed (`mindie_harness.bootstrap`)**
   - 确定性构建 `dist/mindie-harness-seed.pyz` 与 `seed-lock.json`（`mindie-harness-seed/1`），向 7 个薄插件输出 `< 115` 行纯标准库转发入口。

## 快速使用

```bash
# 查看版本与只读环境诊断
mindie-harness --version
mindie-harness inspect --host codex

# 验证可重现冷启动 Seed 构建
python3 scripts/build_seed.py --check

# 运行全量本地正交测试
pytest -q
```
