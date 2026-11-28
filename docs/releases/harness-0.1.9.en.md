# mindie-harness 0.1.9: Native oh-my-pi support

[简体中文](harness-0.1.9.md)

`mindie-harness v0.1.9` adds the `omp` (oh-my-pi) host and retains `API_VERSION = 1` and the pure-Python standard-library runtime.

- The CLI and cold-start template support `--host omp`. The installer detects oh-my-pi via its `omp` executable, configuration paths, or `PI_SESSION_ID`. Python callers can also pass `oh-my-pi` to `run_install`.
- The shared host path rules give OMP its own `omp.json`, `state/omp`, and `runtimes/omp`. MCP serves the `canonical` remote tool catalog, recognizes standard session metadata and `PI_SESSION_ID`, and uses an OMP connection ID when no session identity is available.
