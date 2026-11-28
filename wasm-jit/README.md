# iTerminal `wasm-jit` v2.2 升级套件（BusyBox / 交互式 Shell 就绪版）

本升级套件面向 [liaojinxuan666-eng/iTerminal](https://github.com/liaojinxuan666-eng/iTerminal) 的 `wasm-jit` 架构，零外部依赖（纯 UMD JS + Swift），可在 Node.js 18+ 与 iOS `WKWebView` 中直接运行。

## 文件清单

| 文件 | 核心职责 |
| :--- | :--- |
| `src/wasm-encoder-v2.js` | 支持 `Table`、`call_indirect`、控制流、`CLZ`/`CTZ`/`POPCNT`/`ROTL` 与完整 `i32`/`i64` 操作码的 WASM 编码器 |
| `src/dbt-runtime.js` | 端侧 AArch64→WASM 动态二进制翻译器 + WASM 内部调度循环（4096 项 Direct-Mapped I-Cache + `call_indirect`），新增 `UMULH`（`printf`/常量除法）、`CLZ`/`REV`、`CCMP`/`CCMN`、`EXTR`、`LDR (literal)` 及 128-bit SIMD `Q0..Q31` `LDR`/`STR`/`LDP`/`STP`（`musl` `memcpy`/`memset` 快速路径） |
| `src/vfs-memfs.js` | 零依赖 POSIX 内存文件系统，支持文件、目录、软链接解析（`/bin/sh -> /bin/busybox`）、重命名及 AArch64 Linux ABI `struct stat`（128 字节）与 `linux_dirent64` |
| `src/vmm-syscalls.js` | 紧凑 32 位 `brk`/`mmap`/`munmap`、Linux `argc`/`argv`/`envp`/`auxv` 启动栈、可挂起异步 syscall 状态机（`-2`）、TTY `ioctl`（`TIOCGWINSZ`/`TCGETS`/`TIOCGPGRP`）、`/proc/self/exe` + `readlinkat`、`rt_sigaction`/`kill` 与 `SIGINT`/`SIGWINCH` 信号投递，以及 `clone`/`pipe2`/`dup3`/`execve`/`wait4` |
| `ios-bridge/guest-v2.js` | `WKWebView` 侧运行时胶水，支持预挂载文件/软链接、终端尺寸同步、Ctrl-C 信号发送与异步 Swift PTY 桥接 |
| `ios-bridge/WasmGuestBridgeV2.swift` | 升级版 Swift `WKWebView` 宿主，提供 `mountFile`、`mountSymlink`、`resizeTerminal(rows:cols:)`、`sendInterrupt(signal:)`、`iterminal-host://` COOP/COEP 协议处理与 Jetsam 终止恢复 |
| `tests/test_suite.js` | 自包含 AArch64 汇编器 + ELF64 构造器 + 11 项端到端验证与性能基准 |

## 本地运行与提交

```bash
tar -xzf iTerminal-wasm-jit-v2.2.tar.gz -C .
node wasm-jit-v2/tests/test_suite.js
```

11 项端到端验证覆盖：WASM 内部调度循环（较 JS 逐块调度加速 ~10x）、间接跳转懒翻译、紧凑 32 位 `brk`/`mmap`/`munmap`、可挂起异步 PTY `read`、`fork`+`pipe2`+`wait4`、`musl` 核心指令（`UDIV`/`SDIV`/`CSEL`/`UBFM`/`SBFM`/`TPIDR_EL0`/`LDXR`+`STXR`/`UMULH`/`CLZ`/`REV`/`CCMP`/128-bit SIMD `LDP`/`STP Q`）、VFS + Linux `argv` ABI、跨 ELF `fork`+`pipe2`+`dup3`+`execve` 管道、BusyBox 软链接 + `/proc/self/exe` + TTY `TIOCGWINSZ`、以及 `Ctrl-C`（`SIGINT`）信号中断。
