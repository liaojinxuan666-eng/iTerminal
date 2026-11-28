# iTerminal `wasm-jit` v2 核心升级包

本升级包面向 [liaojinxuan666-eng/iTerminal](https://github.com/liaojinxuan666-eng/iTerminal) 的 `wasm-jit` 架构，实现了从「离线静态翻译 PoC」迈向「端侧 Linux CLI 生态」的四项核心底层能力，全部代码零外部依赖（纯 UMD JS + Swift），可在 Node.js 与 iOS `WKWebView` 中直接运行。

## 文件清单与合入位置

| 文件 | 对应原仓库路径 / 说明 |
| :--- | :--- |
| `src/wasm-encoder-v2.js` | 升级自 `wasm-jit/src/wasm-encoder.js`，新增 `Table`、`call_indirect`、`loop`/`if`/`else`/`br` 与完整 `i32`/`i64` 编码 |
| `src/dbt-runtime.js` | 端侧按需动态二进制翻译器（WASM-DBT）+ **WASM 内部调度循环**（Direct-Mapped I-Cache + `call_indirect`）+ `fork()` 内存/寄存器快照 |
| `src/vmm-syscalls.js` | 紧凑 32 位虚拟内存管理器（`brk`/`mmap`/`munmap`）、可挂起异步 syscall 状态机（`STATUS.SYSCALL_PENDING = -2`）与多进程协作调度器（`clone`/`pipe2`/`wait4`） |
| `ios-bridge/guest-v2.js` | `WKWebView` 侧运行时胶水，通过 `reqId` Promise 映射桥接异步 Swift 宿主 I/O（PTY `stdin` / `stdout` / `stderr`） |
| `ios-bridge/WasmGuestBridgeV2.swift` | 升级自 `WasmGuestBridge.swift`，支持异步 `GuestHostDelegate`、`iterminal-host://` 自定义 `WKURLSchemeHandler`（注入 COOP/COEP 头，为后续 Web Worker + `SharedArrayBuffer` 预留）与 Jetsam 进程终止回调 |
| `tests/test_suite.js` | 自包含 AArch64 汇编器 + ELF64 构造器 + 5 项端到端测试与性能基准（无需交叉编译器即可验证） |

## 线性内存布局

```text
0x0000_0000 - 0x0000_0FFF  CPU 状态页 (x0..x30, SP, PC, N/Z/C/V, TPIDR_EL0)
0x0000_1000 - 0x0000_8FFF  Direct-Mapped I-Cache (4096 项 x 8B: { tag_pc, tbl_idx })
0x0001_0000 - 0x001F_EFFF  ELF PT_LOAD 代码/数据段 + brk 堆区
0x001F_F000 (向下增长)       Guest 栈空间
0x0020_0000 - 0x7FFF_FFFF  Compact 32-bit mmap 匿名映射区（按需自动 grow WASM 内存）
```

## 本地验证

在 Node.js 18+ 环境下直接运行：

```bash
node tests/test_suite.js
```

预期验证项：
1. **Tight Loop 性能对比**：20 万次循环下，WASM 内部调度循环（`stepWasmLoop`）对比原版 JS 逐块调度（`stepJSPerBlock`）实测加速 **~10x**。
2. **间接跳转与端侧懒翻译**：运行时通过 `ADR` + `BLR` + `RET` 跳转至未预翻译函数，验证按需编译并写入 `WebAssembly.Table` + I-Cache。
3. **紧凑 32 位 VMM**：验证 `brk` 扩堆、`mmap` 匿名页分配、跨页读写与 `munmap` 回收。
4. **可挂起异步 Syscall**：模拟异步 Swift PTY `read(0, ...)` 返回 `-2` 挂起、Promise 就绪后写入 `x0` 并从 `nextPC` 无缝恢复。
5. **多进程 `fork` + `pipe2` + `wait4`**：在极小时间片（`sliceBudget = 8`）交错调度下，子进程写管道后以退出码 `42` 退出，父进程阻塞读取并成功回收。

## 下一步接入现有仓库建议

1. 将原仓库 `src/syscalls.js` 中的 `openat`/`fstat`/`getdents64`/`memfs.js` 适配器接入 `GuestKernel._handleSyscall`，即可同时具备完整文件系统与多进程/异步 I/O 能力。
2. 针对 `musl` 静态编译版 BusyBox 补齐剩余 AArch64 指令（`SBFM`/`UBFM`/`CSEL`/`UDIV`/`SDIV`/`LDXR`/`STXR`）和 `execve`（重载 ELF + 刷新 I-Cache）。
