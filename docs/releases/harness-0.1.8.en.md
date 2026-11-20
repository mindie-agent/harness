# mindie-harness 0.1.8: Conditional Offline Index Flags for Local Prebuilt Bundle Bootstrap

[中文](harness-0.1.8.md)

`mindie-harness v0.1.8` is now available. While keeping `API_VERSION = 1` and a 100% pure-stdlib runtime (`dependencies = []`), this patch aligns `mindie-harness-seed.pyz` with `mindie_harness/runtime/wheelhouse.py` when provisioning from a local `MINDIE_CHANNEL_BASE_URL` bundle:

- **Conditional `--offline --no-index` Gating on `UV_OFFLINE=1` (`mindie_harness/bootstrap/seed_main.py`)**: Resolves all first-party components and `reme-ai` from `mindie-wheels-bundle.tar.gz` via `--find-links` + `--override` (zero `git` dependency) while allowing standard PyPI wheel resolution unless `UV_OFFLINE=1` is set, matching `wheelhouse.py`.
- **`ProfileRef`-Scoped `diagnostics.json` Parity in Provider Mode (`mindie_harness/sharing.py`)**: Passes `profile=profile` to `diagnostics_policy_path(profile=profile)` in `_configure_with_providers` (matching `_configure_stdlib`), preventing out-of-profile writes when `mindie_knowledge` and `mindie_diagnostics` are installed in-process.
