# iTerminal `wasm-jit` v2.3 升级套件（动态 ELF + BSD Socket + 沙箱持久化版）

本升级套件面向 [liaojinxuan666-eng/iTerminal](https://github.com/liaojinxuan666-eng/iTerminal) 的 `wasm-jit` 架构，零外部依赖（纯 UMD JS + Swift），可在 Node.js 18+ 与 iOS `WKWebView` 中直接运行。

## 文件清单

| 文件 | 核心职责 |
| :--- | :--- |
| `src/wasm-encoder-v2.js` | 支持 `Table`、`call_indirect`、控制流、`CLZ`/`CTZ`/`POPCNT`/`ROTL` 与完整 `i32`/`i64` 操作码的 WASM 编码器 |
| `src/dbt-runtime.js` | 端侧 AArch64→WASM 动态二进制翻译器 + WASM 内部调度循环（4096 项 Direct-Mapped I-Cache + `call_indirect`），支持 `ET_DYN`（PIE）自动重定位、`PT_INTERP` 解析、故障指令/寄存器转储（`formatFaultDiagnostic`）、`musl` 核心指令与 128 位 SIMD `Q` 寄存器 `LDP`/`STP` |
| `src/vfs-memfs.js` | 零依赖 POSIX 内存文件系统，支持文件、目录、BusyBox 软链接解析、重命名、AArch64 `struct stat`/`linux_dirent64` 及 `serialize()`/`deserialize()` 快照持久化 |
| `src/vmm-syscalls.js` | 紧凑 32 位 `brk`/`mmap`/`munmap`、动态链接器加载与完整 `auxv`（`AT_PHDR`/`AT_PHENT`/`AT_PHNUM`/`AT_BASE`/`AT_ENTRY`）、可挂起异步 syscall 状态机（`-2`）、BSD TCP Socket（`socket`/`connect`/`sendto`/`recvfrom`/`setsockopt`）、TTY `ioctl`、`SIGINT` 信号中断与 `clone`/`pipe2`/`dup3`/`execve`/`wait4` |
| `ios-bridge/guest-v2.js` | `WKWebView` 运行时入口，桥接异步 Swift PTY、TCP 网络与 MemFS 快照导入导出 |
| `ios-bridge/WasmGuestBridgeV2.swift` | 升级版 Swift `WKWebView` 宿主，集成 `Network.framework`（`NWConnection`）真机 TCP 桥接、`Documents` 沙箱持久化（`saveRootFS`/`loadRootFS`）、软链接挂载、终端尺寸同步与 Ctrl-C 中断 |
| `tests/test_suite.js` | 自包含 AArch64 汇编器 + ELF64/PIE 构造器 + 14 项端到端验证与性能基准 |

## 本地运行与提交

```bash
tar -xzf iTerminal-wasm-jit-v2.3.tar.gz -C .
node wasm-jit-v2/tests/test_suite.js
```

14 项端到端测试覆盖：WASM 内部调度循环（~9–10x 加速）、间接跳转懒翻译、紧凑 32 位 `brk`/`mmap`/`munmap`、可挂起异步 PTY `read`、`fork`+`pipe2`+`wait4`、`musl` 核心与 SIMD 指令、VFS + Linux `argv` ABI、跨 ELF `fork`+`pipe2`+`dup3`+`execve` 管道、BusyBox 软链接 + `/proc/self/exe` + TTY `TIOCGWINSZ`、`Ctrl-C`（`SIGINT`）中断、PIE `ET_DYN` + `PT_INTERP` 动态链接器启动、异步 BSD TCP Socket 收发与关闭、以及 MemFS 持久化快照往返恢复。
