# mindie-harness 0.1.7：Windows 并发冷启动种子锁死锁规避（`LK_NBLCK`）与本地预构建包快速引导

[English](harness-0.1.7.en.md)

`mindie-harness v0.1.7` 正式发布。在保持 `API_VERSION = 1` 与纯标准库零重依赖（`dependencies = []`）的前提下，修复了 Windows 多表面 MCP 并发冷启动时的 CRT 文件锁早退异常：

- **Windows 并发冷启动非阻塞轮询锁（`mindie_harness/bootstrap/seed_main.py`）**：Windows CRT 的 `msvcrt.locking(..., LK_LOCK, 1)` 仅固定重试约 10 秒即抛出 `OSError: [Errno 36] Resource deadlock avoided`，导致多路 MCP 表面并发冷启动时第 2 路进程在首路构建完成前异常退出；现改为有界 `300s` `LK_NBLCK` 非阻塞轮询并在 `finally` 确定性释放锁，多路并发进程复用首路验证回执零报错启动。
- **本地 `MINDIE_CHANNEL_BASE_URL` 预构建包优先解包安装**：当 `MINDIE_CHANNEL_BASE_URL` 指向含 `mindie-wheels-bundle.tar.gz` 的本地目录或 `file://` 通道时，直接离线安装预构建 wheelhouse 而无需回退拉取远端 Git 源码。
