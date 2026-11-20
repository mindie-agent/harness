# mindie-harness 0.1.7: Windows Concurrent Cold-Seed `LK_NBLCK` Lock Retry & Local Prebuilt Bundle Bootstrap

[中文](harness-0.1.7.md)

`mindie-harness v0.1.7` is now available. While keeping `API_VERSION = 1` and a 100% pure-stdlib runtime (`dependencies = []`), this patch resolves a Windows multi-surface concurrent cold-launch lock failure in `mindie-harness-seed.pyz`:

- **Bounded `300s` `msvcrt.LK_NBLCK` Polling on Windows (`mindie_harness/bootstrap/seed_main.py`)**: Replaces `msvcrt.locking(..., LK_LOCK, 1)` (which aborts after ~10 CRT retries with `OSError: [Errno 36] Resource deadlock avoided` while the first MCP surface is still building the runtime) with a bounded `300s` `LK_NBLCK` retry loop and deterministic `LK_UNLCK` release in `finally`, allowing sibling MCP surfaces to cleanly reuse the validated generation receipt.
- **Direct Local `MINDIE_CHANNEL_BASE_URL` Bundle Provisioning**: When `MINDIE_CHANNEL_BASE_URL` points to a local directory or `file://` stage containing `mindie-wheels-bundle.tar.gz`, `mindie-harness-seed.pyz` installs directly from the prebuilt wheelhouse without falling back to Git source clones.
