# mindie-harness 0.1.2：全表面 MCP 静默默认就绪、零前置会话绑定（`P2.7` / `P2.8`）与冷启动 `Stop` 授权门控

[English](harness-0.1.2.en.md)

`mindie-harness v0.1.2` 正式发布，作为 MindIE Agent 全系 7 个原生宿主插件（`codex`、`cc`、`kimi`、`dsh`、`agy`、`wb`、`oc`）共用纯标准库底座（`mindie_harness`）的补丁版本，统一收敛全表面 MCP 的静默默认就绪体验与冷启动 Hook 边界：

- **全表面静默默认开放与零 SQLite 匿名快路径（`mindie_harness.mcp.router.MCPRouter`）**：退役 `knowledge_*` 上历史遗留的手动会话准入门禁与 `admission.sqlite3` 前置校验，`remote`、`tools`、`components`、`knowledge`、`all` 全表面工具（保留显式 `tools=[]` 空集语义）在冷启动下均直接通过 `tools/list` 暴露并可通过标准 `tools/call` 零配置执行；仅从宿主受控 `_meta` 提取可选绑定 ID，匿名零元数据调用跳过 `BindStore.claim_bind` SQLite 写锁并统一回退至 `{host}-conn-{connection_id[:12]}`。
- **单点 Schema 归一化、伪造身份拦截与前置超时诚实分类（Iron Rule 2 & Principle 14）**：在 `MCPRouter.__init__` 初始化阶段一次性从 `inputSchema.properties` 与 `inputSchema.required` 剥离 `CORRELATION_STRIP_KEYS`（`request_nonce`、`_mindie_bind_id`、`context_file`）并在入参校验中向后兼容剔除，严格保留 `FORGED_IDENTITY_KEYS` 拦截、`rsi_explore.parse_args` 校验及 `except TimeoutError: raise`；区分工具执行前超时（`submission_state="not_sent"`）与执行中超时（`submission_state="uncertain"`）。
- **只读快车道与幂等写入回执**：`knowledge_query` 与 `knowledge_explain` 纳入只读快车道（在写工作池饱和时仍可无阻塞并发完成），非只读变更型工具（含 `knowledge_distill`、`knowledge_sync`、`knowledge_feedback` 与远端/组件写操作）统一接入 `RemoteReceipts` 幂等防重放与 Receipt Honesty（`isError=False` + `receipt_warning` + `receipt_unconfirmed=True`）。
- **冷启动 `Stop`/`SessionEnd` 授权范围门控与 Seed 同步（`mindie_harness.bootstrap`）**：移除冷启动 `pre-invocation`/`user-prompt-submit` 的 32 MiB 提示词扫描器，将 `stop`/`session-end` 冷门控切换为校验持久化共享授权（`mindie-community.json` / `mindie-consent.json` 中 `enabled is True` 且事件工作区位于 `project_roots` 内）；`pyproject.toml`、包元数据、双语文档与 `dist/mindie-harness-seed.pyz` / `dist/seed-lock.json`（`mindie-harness-seed/1`）统一升至 `0.1.2`（`API_VERSION = 1`）。
