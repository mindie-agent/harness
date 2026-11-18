# mindie-harness 0.1.4: Product `release-channel.json` Alignment & Zero-Git `--override` Wheelhouse Hardening

[中文](harness-0.1.4.md)

`mindie-harness v0.1.4` is a patch release keeping `API_VERSION = 1` stable while aligning `wheelhouse` discovery and bundle extraction with the product `channels/0.1.json` / `mindie-wheels-bundle.tar.gz` contract:

- **Product `channels/0.1.json` Normalization (`wheelhouse.py`)**: `discover_channel` reads `current_patch_version` first, and `_normalize_components` filters `role == "shared_component"` entries keyed by `package` across the 9 shared runtime wheels (excluding `harness_plugin` and `mindie-bench`), accepting both `revision` and `commit`.
- **Zero-Git `--override` Wheelhouse Install & Bundle Member Alignment (`wheelhouse.py` / `wheelhouse_assets.py`)**: `extract_wheel_bundle_safely` accepts `requirements.txt` and `bundle-manifest.json`, and `_wheelhouse_builder` invokes `uv pip install --override <req> -r <req>` so embedded `git+https://...` `Requires-Dist` pins resolve purely from local prebuilt wheels without Git.
- **Version & Deterministic Seed Synchronization**: `pyproject.toml`, `mindie_harness.__version__`, bilingual READMEs, the release workflow, and `dist/mindie-harness-seed.pyz` / `dist/seed-lock.json` advance to `0.1.4` (`API_VERSION = 1`).
