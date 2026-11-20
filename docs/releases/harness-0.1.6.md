# mindie-harness 0.1.6：授权会话 `Stop` 采集路由自动晋升与 `Admission` 租约前置激活

[English](harness-0.1.6.en.md)

`mindie-harness v0.1.6` 正式发布。在保持 `API_VERSION = 1` 与纯标准库零重依赖（`dependencies = []`）的前提下，修复了从初始只读配置切换为 `contribute` / `local-only` 授权采集时的 `Stop` 钩子路由晋升与租约激活顺序：

- **授权 `Stop` 自动从 `capture_mode="disabled"` 晋升为 `"public-transcript"`（`runtime/knowledge_binding.py`）**：当用户已显式开启 `contribute` 或 `local-only` 隐私等级且工作区命中授权 `project_roots` 时，`run_stop_capture` 在检测到当前默认引擎仍处于初始冷启动 `capture_mode == "disabled"` 且宿主真实 `transcript_adapter` 已就位时，自动调用 `_ensure_in_process(..., force_public_transcript=True, retire_previous=True)` 原子晋升 9 域引擎配置并退役旧只读路由。
- **`Admission` 租约签发与撤销校验前置**：在授权 `Stop` 路径中优先完成 `Admission` 状态核验与首次会话租约激活（同时对 `status == "inactive"` 显式撤销永久保持 `stage="inert", reason="revoked"` 闭锁，且未授权/关闭同意书路径仍由纯标准库 `< 5ms` 短路零 SQLite 创建），并同步重建确定性 `dist/mindie-harness-seed.pyz`。
