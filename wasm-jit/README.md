# iTerminal `wasm-jit` v2.4 升级套件（Alpine `.tar` RootFS 引导 + 动态库 `mmap` + SwiftUI 终端控制器）

本升级套件面向 [liaojinxuan666-eng/iTerminal](https://github.com/liaojinxuan666-eng/iTerminal) 的 `wasm-jit` 架构，零外部依赖（纯 UMD JS + Swift），可在 Node.js 18+ 与 iOS `WKWebView` 中直接运行。

## 文件清单

| 文件 | 核心职责 |
| :--- | :--- |
| `src/wasm-encoder-v2.js` | 支持 `Table`、`call_indirect`、控制流、`CLZ`/`CTZ`/`POPCNT`/`ROTL` 与完整 `i32`/`i64` 操作码的 WASM 编码器 |
| `src/dbt-runtime.js` | 端侧 AArch64→WASM 动态二进制翻译器 + WASM 内部调度循环（4096 项 Direct-Mapped I-Cache + `call_indirect`），支持 `ET_DYN`（PIE）重定位、`PT_INTERP`、故障指令转储、`musl` 核心指令与 128 位 SIMD `Q` 寄存器 `LDP`/`STP` |
| `src/vfs-memfs.js` | 零依赖 POSIX 内存文件系统，支持文件、目录、BusyBox 软链接解析、重命名、AArch64 `struct stat`/`linux_dirent64` 与快照持久化 |
| `src/rootfs-tar.js` | 零依赖 POSIX USTAR/GNU `.tar` 解包与构建器，可直接将 Alpine Linux `minirootfs.tar` 解压进 `MemFS` 并引导 |
| `src/vmm-syscalls.js` | 紧凑 32 位 `brk`/`mmap`（含文件映射与 `MAP_FIXED` 动态库加载）/`munmap`、动态链接器与完整 `auxv`、可挂起异步 syscall（`-2`）、BSD TCP Socket、`pread64`/`pwrite64`/`readv`、TTY `ioctl`、`SIGINT` 信号与 `clone`/`pipe2`/`dup3`/`execve`/`wait4` |
| `ios-bridge/guest-v2.js` | `WKWebView` 运行时入口，桥接异步 Swift PTY、TCP 网络、`.tar` RootFS 挂载与 MemFS 快照导入导出 |
| `ios-bridge/WasmGuestBridgeV2.swift` | Swift `WKWebView` 宿主，集成 `Network.framework`（`NWConnection`）真机 TCP 桥接、`Documents` 沙箱持久化、软链接挂载、终端尺寸同步与 Ctrl-C 中断 |
| `ios-bridge/ITerminalSession.swift` | 开箱即用的 SwiftUI `ObservableObject` 终端会话控制器，内置 PTY 输入队列、Ctrl-C、自动持久化与 Jetsam 终止恢复提示 |
| `tests/test_suite.js` | 自包含 AArch64 汇编器 + ELF64/PIE/TAR 构造器 + 17 项端到端验证与性能基准 |

## 本地运行与提交

```bash
tar -xzf iTerminal-wasm-jit-v2.4.tar.gz -C .
node wasm-jit-v2/tests/test_suite.js
```

全部 17 项端到端验证均通过（包含 USTAR `.tar` RootFS 解包引导、文件映射 `mmap` + `MAP_FIXED` 动态库 `BLR` 懒翻译执行以及 `pread64`/`readv` 分散聚集 I/O）。
