# iTerminal `wasm-jit` v2.1 升级套件

本升级套件面向 [liaojinxuan666-eng/iTerminal](https://github.com/liaojinxuan666-eng/iTerminal) 的 `wasm-jit` 架构，在 v2 的 WASM 内部调度循环与端侧动态翻译基础上，进一步补齐了面向 `musl` 静态 Linux CLI（如 BusyBox）的关键指令集、POSIX 内存 VFS、Linux AArch64 `argc`/`argv`/`envp`/`auxv` 启动栈与 `execve` 跨进程执行管线。全部代码零外部依赖（纯 UMD JS + Swift），可直接在 Node.js 18+ 与 iOS `WKWebView` 运行。

## 文件清单

| 文件 | 核心职责 |
| :--- | :--- |
| `src/wasm-encoder-v2.js` | 支持 `Table`、`call_indirect`、控制流与完整 `i32`/`i64` 操作码的 WASM 编码器 |
| `src/dbt-runtime.js` | 端侧 AArch64→WASM 动态二进制翻译器 + WASM 内部调度循环（4096 项 Direct-Mapped I-Cache + `call_indirect`），覆盖 `CSEL`/`UDIV`/`SDIV`/`SBFM`/`UBFM`/`BFM`/逻辑立即数/`ADD`/`SUB` 扩展寄存器/`LDUR`/`STUR`/前后变址/`MRS`/`MSR TPIDR_EL0`/`LDXR`/`STXR` 及 `resetForExec()` |
| `src/vfs-memfs.js` | 零依赖 POSIX 内存文件系统，支持目录树、ELF 二进制挂载及 AArch64 Linux ABI `struct stat`（128 字节）与 `linux_dirent64` |
| `src/vmm-syscalls.js` | 紧凑 32 位 `brk`/`mmap`/`munmap`、Linux AArch64 初始栈构造（`argc`/`argv`/`envp`/`auxv`）、可挂起异步 syscall 状态机（`-2`）以及 `clone`/`pipe2`/`dup3`/`execve`/`wait4`/`openat`/`fstat`/`newfstatat`/`getdents64`/`writev`/`uname` |
| `ios-bridge/guest-v2.js` | `WKWebView` 运行时入口，支持 `mountBase64File` 预装 `/bin` 工具与异步 Swift PTY 桥接 |
| `ios-bridge/WasmGuestBridgeV2.swift` | 升级版 Swift `WKWebView` 宿主（支持 `mountFile`、`argv`/`envp` 传参、异步 `reqId` 回调、`iterminal-host://` COOP/COEP 协议处理与 Jetsam 终止恢复） |
| `tests/test_suite.js` | 自包含 AArch64 汇编器 + ELF64 构造器 + 8 项端到端测试与性能基准 |

## 本地运行与验证

```bash
tar -xzf iTerminal-wasm-jit-v2.1.tar.gz -C .
node wasm-jit-v2/tests/test_suite.js
```

8 项端到端验证：
1. **Tight Loop 基准**：20 万次循环下 WASM 内部调度循环较 JS 逐块调度加速约 **10x**。
2. **间接跳转懒翻译**：`ADR` + `BLR` + `RET` 运行时按需翻译并写入 I-Cache。
3. **紧凑 32 位 VMM**：`brk`/`mmap`/`munmap` 跨页读写与回收。
4. **可挂起异步 Syscall**：模拟异步 Swift PTY `read(0, ...)` 挂起与无损恢复。
5. **多进程管道**：`fork` + `pipe2` + `wait4` 在小时间片交错调度下通信与回收。
6. **Musl 关键指令**：验证 `UDIV`/`SDIV`/`CSEL`/`UBFM`/`SBFM`/`TPIDR_EL0`/`LDXR`+`STXR`/`LDUR`+`STUR`。
7. **VFS 与 Linux `argv` ABI**：从初始栈读取 `argc`/`argv[1]`，通过 `openat`/`read`/`write` 输出 `/etc/hostname`。
8. **完整 Shell 管道**：`/bin/sh` 执行 `fork` + `pipe2` + `dup3(wfd, 1)` + `execve("/bin/echo", ...)` + `wait4`，跨两个独立 ELF64 二进制完成管道捕获与子进程回收。
