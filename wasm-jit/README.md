# wasm-jit — 借 WebKit 的 JIT 在 iOS 上跑 Linux 二进制

> 核心思路：iOS App 拿不到 JIT entitlement，但 WKWebView 里的 JavaScriptCore 有系统签名的 JIT 能力。
> 把 AArch64 Linux 二进制**翻译成 WebAssembly**，交给 WebKit JIT 执行——App 自己一行机器码都不生成。

这是一个**可验证的原型**：翻译器和 syscall 桥接全部从零实现，未修改的 aarch64 Linux ELF 已在 Node（同为 WASM JIT 宿主）上真实跑通。

---

## 1. 为什么走这条路

上一版 `linux-abi` 是纯解释执行——能跑，但没有 JIT，性能注定上不去。iOS 上直接 JIT 的障碍：

| 障碍 | 说明 |
|---|---|
| `W^X` / `dynamic-codesigning` | 普通 App 无法 `mmap` 可执行内存，拿不到 JIT entitlement |
| 苹果审核 | 动态生成机器码是 3.3.2 红线 |
| proot/ptrace | iOS 的 ptrace 不支持完整 syscall trace，走不通 |

**借壳方案**：把 guest 代码编译成 WASM，让 WebKit 的 JSC 做 JIT。App 只是加载字节码 + 收发消息，不碰机器码。

> 事实依据：iOS 14.5 起 WKWebView 在第三方 App 内可启用 JIT（BBQ 基线编译器 + OMG 优化编译器）；WASM 通过 JSC 编译执行。见 [WebKit/Safari WASM 安全分析](https://www.systemshardening.com/articles/wasm/wasm-webkit-mobile-security)。

---

## 2. 架构

```
┌─────────────────────────────────────────────────────────┐
│  Swift App (宿主，无 JIT entitlement)                    │
│    WasmGuestBridge ──WKScriptMessageHandler──┐           │
└──────────────────────────────────────────────┼───────────┘
                                              │ syscall 消息
┌──────────────────────────────────────────────▼───────────┐
│  WKWebView WebContent 进程 (系统签名，持有 JIT)           │
│    guest.js ──WASM import──> JIT 编译后的 guest 代码      │
│                              (bb0..bbN 基本块函数)        │
└─────────────────────────────────────────────────────────┘

离线（构建时）：
  AArch64 ELF ──translator.js──> .wasm 模块 ──> 打进 App Bundle
```

**关键设计**：
- **翻译离线化**：ELF→WASM 在构建时完成，iOS 端只加载 `.wasm`。避免把 Buffer/fs 依赖搬进浏览器。
- **基本块 = WASM 函数**：每个块返回下一个块号，JS 只做调度。JIT 编译的是真正的 guest 指令翻译结果。
- **寄存器 = mutable global**：x0..x30、SP、NZCV 标志、返回地址都是 i64/i32 global。
- **地址重映射**：guest 64 位地址静态减去 `bias`（最小 PT_LOAD vaddr），映射到 WASM 32 位线性内存偏移。这是绕不开的折衷（见边界）。
- **syscall = WASM import**：JS 侧实现 write/exit/uname 等；复杂 syscall（文件/socket）通过 `WKScriptMessageHandler` 桥到 Swift。

---

## 3. 已验证结果

用标准 `aarch64-linux-gnu-gcc` 交叉编译的**未修改静态 ELF**，经翻译后在 WASM JIT 中真实执行：

```
$ node run.js /workspace/linux-abi/tests/minimal
Hello from pure AArch64 Linux binary!
[wasm-jit] guest 退出码=55        ← 1+2+...+10 正确

$ node run.js /workspace/linux-abi/tests/verify
test: mul/div/call/uname/write...
PASS: all AArch64 ops verified!
[wasm-jit] guest 退出码=12        ← 5! = 120 正确

$ node run.js /workspace/linux-abi/tests/real_c
K
[wasm-jit] guest 退出码=71        ← 真实 gcc 编译的 C，15+42+14=71 正确

$ node -e "run('tests/echo',{input:Buffer.from('HelloTerm!')})"
输出 "HelloTerm!"，退出码 10   ← read syscall 输入链路正确
```

`verify` 覆盖：**MADD、UDIV、SUBS/CMP、B.cond、BL/RET 函数调用、uname/write/exit syscall、退出码传递**。

**关键跨越 — `real_c.c`**：这是由标准 `aarch64-linux-gnu-gcc -O1 -mgeneral-regs-only` 编译的**真实 C 代码**（不是手写汇编），包含数组、结构体、指针算术、多层嵌套函数调用、局部变量栈帧。它跑通意味着翻译器已经能处理编译器生成的真实栈操作和对访存，而不只是精心构造的汇编片段。

**浏览器宿主**（`ios-bridge/guest.js`）也在 Node 模拟环境跑通同样结果，证明 Swift 桥接层吃的接口是好的。

**指令级回归测试**：`tests/regression.js` 用 17 个手写汇编 ELF（退出码携带运算结果）+ 4 个端到端用例，覆盖上述全部新增指令与修复的 bug：
```bash
$ node tests/regression.js
结果: 25 passed, 0 failed
```

### 指令集扩展（2026-11 引擎升级）
最初翻译器只覆盖手写汇编 + 简单 C 的指令子集。用真实 `gcc -O0/-O2 -mgeneral-regs-only` 编译的复杂 C 程序做覆盖探针，补齐了编译器高频生成的指令：

| 指令族 | 覆盖 |
|---|---|
| 逻辑寄存器 | AND/BIC/ORR/ORN/EOR/EON/ANDS/BICS + LSL/LSR/ASR/ROR 移位 |
| 逻辑立即数 | ANDI/ORRI/EORI/ANDSI + 完整 `DecodeBitMasks` 位掩码解码 |
| 位域 | SBFM/UBFM/BFM 及别名 sxtw/sbfx/ubfx/ubfiz/asr/lsl/lsr/bfi |
| 变量移位 | LSLV/LSRV/ASRV/RORV |
| 符号加载 | LDRSB/LDRSH/LDRSW |
| 寄存器变址访存 | `ldr/str [Rn, Rm{, extend {amount}}]`（`-O0` 下 `arr[i]` 的典型形式）|
| MOVE 宽立即数 | MOVZ/MOVK/MOVN 完整区分 + 32 位零扩展 |
| 其它 | NOP（对齐填充）、ANDS/条件标志 |

现在真实 gcc 编译的复杂 C 探针（数组/结构体/位运算/除法/switch/符号加载）**全部指令 0 未实现**。

### 调试中修掉的真实 bug（都是硬细节）
- **MOVK 识别掩码错误**：原掩码 `0x1f800000` 把区分 MOVZ/MOVK 的 opc 位（bit30:29）清掉，导致所有 MOVK 被当成 MOVZ，`movk` 拼大常量失效 → 改用 `0x7f800000` 按 opc 区分（MOVZ=MOVW opc=2 / MOVK opc=3 / MOVN opc=0）
- **CMP 破坏 SP**：ADD/SUB 立即数里 Rd=31 正常是 SP，但 CMP/CMN（setflags=1）时 Rd=31 是 ZR。原实现把 CMP 结果写进 SP，导致栈指针被污染、访存越界 → setflags 且 rd=31 时改为 `drop`
- **i64→Number 精度丢失**：syscall 桥接把 WASM i64(BigInt) 转 Number（>2^53 丢精度），exit code 低位被污染，恒为 0 → exit 走 BigInt 域 `& 0xff`（run.js / guest.js 均已修）
- **位域 opc 编码写反**：SBFM=opc0 / UBFM=opc2 / BFM=opc3，原代码把 SBFM 当 opc1，导致 sxtw/asr 走错分支 → 修正并改正符号扩展（逻辑右移+掩码再符号扩展）
- JS 位运算返回有符号 32 位：`0xd4000001 & 0xff000000` 是负数，导致 svc 指令永远匹配不上 → 统一 `>>> 0`
- WASM `if` 缺 block type 字节 `0x40`
- import memory 的 limits flags 顺序
- 条件标志未归一化：`FLAGS & 4 = 4`，`C && !Z` 变成 `4 & 1 = 0` → 用 `(FLAGS >> n) & 1`
- 函数索引：import 函数返回的索引算错，syscall 调到了 setflags
- WASM i64 参数是 BigInt，`Buffer.from(buf, bigint)` 拿不到数据 → JS 侧转 Number
- 块发现用了未算绝对地址的 classify，把目标 `0x4000f0` 算成 `0x0`
- exit syscall 后的字符串被当指令解码 → 常量追踪 x8 识别 exit 并停扫
- **影子调用栈**：原来用单个 `RETADDR` global 存返回地址，嵌套调用会覆盖 → 改用 WASM 线性内存中的影子栈（CALLSP 指针），支持任意深度函数调用
- **ADRP 漏加 PC 页基址**：`guestAddr` 直接用 imm，少算了 `pc & ~0xfffff` → 修正为 `(pc & ~0xfff) + (imm<<12)`
- **ADD 移位寄存器 LSL 缺失**：shiftType=0（LSL）分支没实现，`add x1,x2,x0,lsl#3` 退化成不加倍 → 补全 LSL/LSR/ASR
- **LDR/STR 寻址模式判断错误**：用 bits[23:22]（load/store 位）区分 pre/post，实际应看 bits[11:10] → 修正，`ldur` 负偏移才正确
- **访存地址缺 `i32_wrap_i64`**：WASM 内存地址必须是 i32，原来直接喂 i64（手写汇编测试无访存所以没暴露）→ 补 LDP/STP 与地址转换
- 补 `OP.i32_add`/`i32_sub`（ret 弹栈需要）
- 补 **CSEL/CSINC** 条件选择、**CBZ/CBNZ** 条件分支指令

---

## 4. 文件结构

```
wasm-jit/
├── src/
│   ├── wasm-encoder.js      # 手写 WASM 二进制编码器（无第三方依赖）
│   ├── translator.js        # ELF 解析 + 基本块发现 + AArch64→WASM 翻译
│   └── syscalls.js          # 可复用 syscall 表（Node/iOS 共用逻辑）
├── run.js                   # Node 宿主：块调度 + CLI
├── Scripts/translate.sh     # 离线翻译脚本
├── ios-bridge/
│   ├── guest.js             # WKWebView 内宿主（syscall→Swift 桥）
│   ├── WasmGuestBridge.swift# Swift 侧 WKWebView 桥接骨架
│   └── assets/*.wasm        # 预翻译的测试模块
├── tests/
│   ├── regression.js        # 指令级 + 端到端回归测试（25 断言）
│   ├── minimal/verify/real_c/echo  # 端到端测试 ELF
│   └── asm/                 # 17 个指令级汇编测试（源码 + ELF + 期望值）
└── README.md

测试源码在相邻的 /workspace/linux-abi/tests/：
  minimal.S / verify.S      # 手写汇编（早期验证）
  crt.S + real_c.c          # 真实 gcc 编译的 C（数组/结构体/调用栈）
  crt.S + echo.c            # read syscall 输入链路
```

## 5. 用法

**Node 验证**：
```bash
node run.js <aarch64-elf> [--trace] [--verbose] [--dump out.wasm]
node tests/regression.js          # 全量回归（25 断言）
```

**离线翻译**（产物打进 iOS App）：
```bash
bash Scripts/translate.sh <aarch64-elf> ios-bridge/assets/foo.wasm
```

**iOS 集成**：
1. 把 `guest.js` 和 `assets/*.wasm` 加入 App Bundle
2. `WasmGuestBridge` 调用 `setup(guestJS:wasm:)`，再 `await run()`
3. 实现 `GuestSyscallHandler` 处理文件/socket 等复杂 syscall

---

## 6. 边界与风险（诚实说明）

### 技术边界
| 限制 | 说明 |
|---|---|
| **32 位线性内存** | WASM 地址空间上限 4GB，iOS Safari 实测常低于 1.5GB，低端 WebContent 进程仅 150–300MB。64 位 guest 地址被静态压缩，无法支持真实 Linux 的完整地址布局 |
| **静态 ELF only** | 尚未实现动态链接（ld.so、GOT/PLT 重定位） |
| **指令子集** | 覆盖测试所需的整数/分支/访存/SVC；SIMD/NEON/FP、原子、异常未实现 |
| **signal/线程/futex** | 未实现，guest 目前是单线程顺序执行 |
| **syscall 覆盖** | Node 宿主实现了 write/exit/uname/getpid 等；Swift 侧需按应用需求补齐 |
| **offline 翻译** | 翻译在构建时做，运行时不能加载任意新 ELF（除非把 translator 搬进 JS，需 polyfill Buffer/fs） |

### iOS 特定风险
- **JIT 可用性**：WKWebView 的 JIT 由系统进程持有，但**不同 iOS 版本/配置行为有差异**（BBQ-only vs OMG）。低端设备或特定配置可能降级为 BBQ-only（慢但不禁用）。需在目标真机上验证。
- **Lockdown Mode**：启用后会禁用 WASM。必须有 JS 解释器降级路径（性能下降 3–5 倍）。
- **内存压力**：WASM 线性内存 + JS 堆 + 编译后代码共享 WebContent 进程配额，超限会被 jetsam 杀掉。
- **App Store 审核**：WASM 本身是网页标准，不算"动态执行未签名代码"；但**运行时从网络下载 wasm 并执行**可能触发 3.3.2。建议 wasm 随 App 内置、只做本地翻译产物。
- **后台执行**：WKWebView 在后台会暂停，长时任务需 `beginBackgroundTask` 或移到底层（但那样又失去 WKWebView 的 JIT）。

---

## 7. 与相邻项目的关系

- `/workspace/linux-abi/`：从零实现的解释器版（无 JIT），验证 ABI 兼容本身
- `/workspace/ios-linux-terminal/`：终端 UI + ish-arm64 集成的产品骨架
- **本项目**：exploration——验证"借 WebKit JIT"这条路是否真的可行

三者是递进关系：ABI 引擎 → JIT 加速引擎 → 产品壳。本项目证明了 JIT 借壳在技术上跑得通，剩下的是工程量（补指令、补 syscall、补动态链接、真机验证）。

---

## 8. 下一步

1. **真机验证**：在 iOS 设备跑 `guest.js`，确认 JSC 实际启用 OMG tier（而非 BBQ-only）
2. **补齐 translator 搬进 JS**：加 Buffer/Uint8Array polyfill，让运行时可翻译新 ELF
3. **扩展指令集**：NEON/FP（glibc 静态二进制大量使用）、原子操作
4. **动态链接**：实现 ld.so 最小加载 + GOT/PLT 重定位
5. **musl 优先**：静态 musl 二进制比 glibc 简单得多，更适合作为首个完整支持目标
