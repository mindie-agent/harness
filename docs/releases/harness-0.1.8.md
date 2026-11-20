# mindie-harness 0.1.8：本地预构建包引导的 PyPI 三方依赖按需索引对齐

[English](harness-0.1.8.en.md)

`mindie-harness v0.1.8` 正式发布。在保持 `API_VERSION = 1` 与纯标准库零重依赖（`dependencies = []`）的前提下，对齐 `mindie-harness-seed.pyz` 与 `wheelhouse.py` 的本地预构建包安装语义：

- **按 `UV_OFFLINE` 条件附加 `--offline --no-index`（`mindie_harness/bootstrap/seed_main.py`）**：`mindie-wheels-bundle.tar.gz` 承载全量自研组件与 `reme-ai` 预构建 `.whl`（彻底消除 `git` 源码克隆），三方纯公共依赖在非离线环境按标准索引与缓存解析，仅在 `UV_OFFLINE=1` 时启用完全离线无索引模式，与 `mindie_harness/runtime/wheelhouse.py` 严格一致。
- **对齐 `sharing` 提供方模式的 `diagnostics.json` 路径归属（`mindie_harness/sharing.py`）**：`_configure_with_providers` 与 `_configure_stdlib` 统一传入 `diagnostics_policy_path(profile=profile)`，确保显式 `ProfileRef` 在全栈已安装 `mindie_knowledge`/`mindie_diagnostics` 时零越界落盘。
