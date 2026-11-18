# mindie-harness 0.1.2：全表面 MCP 静默默认就绪与零前置会话绑定（`P2.7` / `P2.8`）

[English](harness-0.1.2.en.md)

`mindie-harness v0.1.2` 正式发布，作为 MindIE Agent 全系 7 个原生宿主插件（`codex`、`cc`、`kimi`、`dsh`、`agy`、`wb`、`oc`）共用纯标准库底座（`mindie_harness`）的补丁版本，统一收敛全表面 MCP 的静默默认就绪体验：

- **全表面静默默认开放与零前置会话绑定（`mindie_harness.mcp.router.MCPRouter`）**：退役 `knowledge_*` 上历史遗留的手动会话准入门禁与 `admission.sqlite3` 前置校验，`remote`、`tools`、`components`、`knowledge`、`all` 全表面工具在冷启动下均直接通过 `tools/list` 暴露并可通过标准 `tools/call` 零配置执行；缺失宿主会话元数据时统一回退至连接标识 `{host}-conn-{connection_id[:12]}`，同时保留可选 `PreToolUse` `BindStore` 上下文富化能力。
- **关联键统一剥离与伪造身份拦截**：在全部工具的 `inputSchema["required"]` 与入参校验中统一剥离 `CORRELATION_STRIP_KEYS`（`request_nonce`、`_mindie_bind_id`、`context_file`），同时严格保留 `FORGED_IDENTITY_KEYS` 模型入参伪造拦截、`rsi_explore.parse_args` 探索模式参数校验以及 `except TimeoutError: raise` 超时优先传递（Principle 14）。
- **只读快车道与幂等写入回执**：`knowledge_query` 与 `knowledge_explain` 纳入只读快车道（零并发锁争用、不写入 `remote-receipts.sqlite3`），非只读变更型工具（含 `knowledge_distill`、`knowledge_sync`、`knowledge_feedback` 与远端/组件写操作）统一接入 `RemoteReceipts` 幂等防重放与 Receipt Honesty（`isError=False` + `receipt_warning` + `receipt_unconfirmed=True`）。
- **版本与冷启动 Seed 同步**：`pyproject.toml`、包元数据、双语文档与 `dist/mindie-harness-seed.pyz` / `dist/seed-lock.json`（`mindie-harness-seed/1`）统一升至 `0.1.2`；`API_VERSION` 保持 `1`，公共 ABI 完全向后兼容。
