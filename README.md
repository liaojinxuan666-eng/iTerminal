# iTerminal

在无 JIT entitlement 的 iOS 设备上，通过「AArch64 ELF → WebAssembly 端侧动态翻译 + `WKWebView` JavaScriptCore JIT」兼容原生 Linux CLI 生态。

## 仓库目录结构（引擎层与交互层完全解耦）

```text
iTerminal/
├── .github/workflows/build-ios.yml   # GitHub Actions：Node.js 测试 + XcodeGen 生成工程 + 编译无签名 .ipa
├── wasm-jit/                         # 纯 JS 动态二进制翻译与 Linux 运行时（零 Swift/Xcode 依赖）
│   ├── src/
│   │   ├── wasm-encoder-v2.js        # WASM 字节码编码器
│   │   ├── dbt-runtime.js            # 端侧 AArch64->WASM DBT + WASM 内部调度循环 + PIE/PT_INTERP 加载
│   │   ├── vfs-memfs.js              # POSIX 内存文件系统（软链接、struct stat、快照持久化）
│   │   ├── rootfs-tar.js             # USTAR .tar RootFS 解包/构建器（支持 Alpine minirootfs）
│   │   └── vmm-syscalls.js           # 32 位 VMM、动态链接 auxv、异步 syscall、BSD Socket、fork/execve
│   ├── runtime/
│   │   └── guest-v2.js               # WKWebView 侧 JS 运行时入口
│   └── tests/
│       └── test_suite.js             # 17 项端到端测试与性能基准
└── ios-app/                          # 独立 iOS SwiftUI 交互层
    ├── project.yml                   # XcodeGen 项目定义（CI 自动生成 .xcodeproj）
    ├── Info.plist                    # iOS App 配置（开启 Documents 文件共享）
    └── Sources/
        ├── ITerminalApp.swift        # SwiftUI @main 入口
        ├── TerminalView.swift        # 深色交互终端界面（输出区、输入框、Ctrl-C、状态栏）
        ├── ITerminalSession.swift    # PTY 输入队列、Bundle 资源加载与沙箱自动持久化
        └── WasmGuestBridgeV2.swift   # WKWebView 宿主桥接 + NWConnection TCP 转发 + Jetsam 恢复
```

## 本地验证与 GitHub Actions 编译

1. 本地运行全部 17 项核心测试：
   ```bash
   node wasm-jit/tests/test_suite.js
   ```
2. 推送到 `main` 分支后，GitHub Actions（`.github/workflows/build-ios.yml`）会自动执行：
   - 在 `ubuntu-latest` 上跑通 `wasm-jit` 全部 17 项测试；
   - 在 `macos-15` 上自动将 `wasm-jit/src/*.js` 与 `wasm-jit/runtime/guest-v2.js` 打包进 `ios-app/Resources/runtime/`；
   - 通过 `xcodegen generate` 生成 Xcode 工程并编译输出无签名 `iTerminal-unsigned.ipa`（可在 Actions Artifacts 下载，通过 TrollStore / AltStore / SideStore 安装到真机）。
