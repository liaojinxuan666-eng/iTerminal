# iTerminal (TypeScript v3.0)

在无 JIT entitlement 的 iOS 设备上，通过 **TypeScript 编写的 AArch64→WASM 端侧动态二进制翻译器 + `WKWebView` JavaScriptCore JIT** 兼容原生 Linux CLI 生态。

## 仓库目录结构

```text
iTerminal/
├── .github/workflows/build-ios.yml   # GitHub Actions：tsc 严格类型检查 + 19 项测试 + esbuild 单文件打包 + Alpine RootFS + 无签名 .ipa
├── wasm-jit/                         # 严格 TypeScript 动态翻译器与 Linux 内核层
│   ├── package.json                  # npm run typecheck / build:ios / test
│   ├── tsconfig.json                 # strict: true, noImplicitAny: true
│   ├── src/
│   │   ├── wasm-encoder-v2.ts        # WASM 字节码编码器
│   │   ├── dbt-runtime.ts            # AArch64→WASM DBT + WASM 内部调度循环 + PIE/PT_INTERP + SIMD DUP/LDP/STP Q
│   │   ├── vfs-memfs.ts              # POSIX 内存文件系统（软链接、struct stat、快照持久化）
│   │   ├── rootfs-tar.ts             # USTAR .tar RootFS 解包/构建器
│   │   └── vmm-syscalls.ts           # 32 位 VMM、动态链接 auxv、异步 syscall、BSD Socket、fork/execve
│   ├── runtime/
│   │   └── guest-v2.ts               # WKWebView 入口（由 esbuild 编译为单个 iterminal-runtime.js）
│   └── tests/
│       └── test_suite.ts             # 19 项端到端测试与性能基准（含真机 ld-musl CSET 与 DUP memset 回归测试）
└── ios-app/                          # 独立 iOS SwiftUI 交互层
    ├── project.yml                   # XcodeGen 项目定义
    ├── Info.plist                    # iOS App 配置（开启 Documents 文件共享）
    └── Sources/
        ├── ITerminalApp.swift
        ├── TerminalView.swift
        ├── ITerminalSession.swift    # 加载单个 iterminal-runtime.js + 自动挂载 Alpine RootFS 并启动 /bin/sh
        └── WasmGuestBridgeV2.swift   # WKWebView 宿主桥接 + NWConnection TCP 转发 + Jetsam 恢复
```

## 本地开发与 CI

```bash
cd wasm-jit
npm install
npm run typecheck
npm test
npm run build:ios
```
