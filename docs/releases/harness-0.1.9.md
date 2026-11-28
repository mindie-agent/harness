# mindie-harness 0.1.9：原生 oh-my-pi 宿主支持

[English](harness-0.1.9.en.md)

`mindie-harness v0.1.9` 新增 `omp`（oh-my-pi）宿主，继续使用 `API_VERSION = 1` 和纯 Python 标准库运行时。

- CLI 与冷启动模板支持 `--host omp`。安装器通过 `omp` 可执行文件、配置路径或 `PI_SESSION_ID` 检测宿主。Python `run_install` 也接受别名 `oh-my-pi`。
- 现有宿主路径规则为 OMP 解析独立的 `omp.json`、`state/omp` 和 `runtimes/omp`。MCP 使用通用 `canonical` 远端工具目录，优先读取标准会话元数据，也接受 `PI_SESSION_ID`。缺少会话身份时回退到 OMP 的连接级 ID。
