"""Global sandbox isolation fixture preventing host filesystem or env pollution.

[Role]
Isolates `HOME`, `USERPROFILE`, `APPDATA`, `LOCALAPPDATA`, `XDG_*`, `MINDIE_*`,
`REMOTE_DEV_*`, `UV_CACHE_DIR`, and `TMPDIR`/`TEMP`/`TMP` in every pytest test.
"""
from __future__ import annotations

from pathlib import Path
import pytest


@pytest.fixture(autouse=True)
def _isolated_mindie_host_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    sandbox = tmp_path / "_sandbox_env"
    home = sandbox / "home"
    cfg = sandbox / "mindie_cfg"
    data = sandbox / "mindie_data"
    diag = sandbox / "mindie_diag"
    rdev = sandbox / "remote_dev"
    uv_cache = sandbox / "uv_cache"
    tmp_dir = sandbox / "tmp"
    for d in (home, cfg, data, diag, rdev, uv_cache, tmp_dir):
        d.mkdir(parents=True, exist_ok=True)

    env_overrides = {
        "HOME": str(home),
        "USERPROFILE": str(home),
        "APPDATA": str(home / "AppData" / "Roaming"),
        "LOCALAPPDATA": str(home / "AppData" / "Local"),
        "XDG_CONFIG_HOME": str(sandbox / "xdg_config"),
        "XDG_DATA_HOME": str(sandbox / "xdg_data"),
        "XDG_CACHE_HOME": str(sandbox / "xdg_cache"),
        "XDG_STATE_HOME": str(sandbox / "xdg_state"),
        "MINDIE_CONFIG_HOME": str(cfg),
        "MINDIE_DATA_HOME": str(data),
        "MINDIE_DIAGNOSTICS_ROOT": str(diag),
        "MINDIE_REMOTE_STATE_DIR": str(rdev),
        "REMOTE_DEV_AUTH_DIR": str(sandbox / "rdev_auth"),
        "UV_CACHE_DIR": str(uv_cache),
        "TMPDIR": str(tmp_dir),
        "TEMP": str(tmp_dir),
        "TMP": str(tmp_dir),
    }
    for key, val in env_overrides.items():
        monkeypatch.setenv(key, val)
    for clear_key in (
        "MINDIE_AGENT_CONFIG",
        "MINDIE_SESSION_ID",
        "REMOTE_DEV_SESSION_ID",
        "CODEX_THREAD_ID",
        "KIMI_SESSION_ID",
        "OPENCODE_SESSION_ID",
        "CLAUDE_SESSION_ID",
    ):
        monkeypatch.delenv(clear_key, raising=False)
    return sandbox
