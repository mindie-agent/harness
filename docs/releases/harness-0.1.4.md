# mindie-harness 0.1.4：产品通道 `release-channel.json` 对齐与零 Git `--override` Wheelhouse 安装加固

[English](harness-0.1.4.en.md)

`mindie-harness v0.1.4` 正式发布，在不改变 `API_VERSION = 1` 的前提下，对齐产品级 `channels/0.1.json` / `mindie-wheels-bundle.tar.gz` 契约并彻底消除内置 wheel `Requires-Dist` Git URL 对运行时安装的隐式 Git 依赖：

- **`channels/0.1.json` 通道元数据归一化（`wheelhouse.py`）**：`discover_channel` 优先读取 `current_patch_version`；`_normalize_components` 按 `role == "shared_component"` 与 `package` 字段归一至 9 个共享运行时包（自动排除 `harness_plugin` 与评测包 `mindie-bench`），并兼容 `commit` / `revision` 字段。
- **零 Git `--override` Wheelhouse 安装与 Bundle 成员对齐（`wheelhouse.py` / `wheelhouse_assets.py`）**：安全解包白名单同步接纳 `requirements.txt` 与 `bundle-manifest.json`，并在 `uv pip install` 时传入 `--override <req> -r <req>`，覆盖发布 wheel `METADATA` 中的 `git+https://...` 直接依赖为本地预编译版本。
- **版本与确定性 Seed 同步**：`pyproject.toml`、`mindie_harness.__version__`、双语 README、发布工作流及 `dist/mindie-harness-seed.pyz` / `dist/seed-lock.json` 统一升至 `0.1.4`（`API_VERSION = 1`）。
