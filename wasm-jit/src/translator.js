/*
 * translator.js — AArch64 Linux ELF → WebAssembly 翻译器
 *
 * 核心思想：
 *   1. 解析 ELF64，取得入口与 PT_LOAD 段；
 *   2. 从入口做可达性分析，按控制流切分基本块；
 *   3. 每个基本块 → 一个 WASM 函数，返回下一个块号（-1 表示 guest 退出）；
 *   4. guest 寄存器 → mutable i64 global，guest 内存 → linear memory；
 *   5. syscall → import 函数，由宿主（Node/WebKit JS）实现。
 *
 * 地址映射：guest 64 位地址静态减去 bias（=最小 PT_LOAD vaddr），
 *          映射到 WASM 32 位线性内存的偏移。这是"借壳 JIT"的关键折衷。
 */

'use strict';
// 惰性加载 fs：浏览器/WebKit 里没有 fs，只在传路径字符串时才用
let _fs = null;
function getFs() { if (!_fs) _fs = require('fs'); return _fs; }
const { ModuleBuilder, OP, VT, uleb, sleb } = require('./wasm-encoder');

/* ==================== ELF64 解析 ==================== */

function parseELF(buf) {
    if (buf.toString('ascii', 0, 4) !== '\x7fELF') throw new Error('不是 ELF 文件');
    if (buf[4] !== 2) throw new Error('只支持 ELF64');
    if (buf.readUInt16LE(18) !== 0xb7) throw new Error('只支持 AArch64 (EM_AARCH64=183)');

    const entry = Number(buf.readBigUInt64LE(0x18));
    const phoff = Number(buf.readBigUInt64LE(0x20));
    const phentsize = buf.readUInt16LE(0x36);
    const phnum = buf.readUInt16LE(0x38);

    const loads = [];
    for (let i = 0; i < phnum; i++) {
        const off = phoff + i * phentsize;
        const type = buf.readUInt32LE(off);
        if (type !== 1) continue; // PT_LOAD
        const p_offset = Number(buf.readBigUInt64LE(off + 8));
        const p_vaddr = Number(buf.readBigUInt64LE(off + 16));
        const p_filesz = Number(buf.readBigUInt64LE(off + 32));
        const p_memsz = Number(buf.readBigUInt64LE(off + 40));
        loads.push({ p_offset, p_vaddr, p_filesz, p_memsz });
    }
    if (!loads.length) throw new Error('ELF 没有 PT_LOAD 段');

    const bias = Math.min(...loads.map(l => l.p_vaddr));
    const maxAddr = Math.max(...loads.map(l => l.p_vaddr + l.p_memsz));
    return { buf, entry, loads, bias, memSize: maxAddr - bias };
}

/* ==================== AArch64 位工具 ==================== */
const B = (x, hi, lo) => Number((BigInt(x) >> BigInt(lo)) & ((1n << BigInt(hi - lo + 1)) - 1n));
const SEXT = (v, bits) => {
    const b = BigInt(v) & ((1n << BigInt(bits)) - 1n);
    return Number(b >= (1n << BigInt(bits - 1)) ? b - (1n << BigInt(bits)) : b);
};

/* ==================== 基本块发现 ==================== */

function findBlocks(elf) {
    const { buf, entry, bias } = elf;
    const codeAt = addr => {
        // 代码字节在 ELF 文件中的位置 = vaddr - bias + 段文件偏移换算
        for (const l of elf.loads) {
            if (addr >= l.p_vaddr && addr + 4 <= l.p_vaddr + l.p_filesz) {
                return buf.readUInt32LE(l.p_offset + (addr - l.p_vaddr));
            }
        }
        return null;
    };

    const leaders = new Set([entry]);
    const seen = new Set();
    const queue = [entry];
    const insns = new Map(); // addr -> word

    while (queue.length) {
        let pc = queue.shift();
        let x8Const = null; // 追踪 movz x8,#imm，用于识别 exit syscall
        if (seen.has(pc)) continue;
        seen.add(pc);
        while (true) {
            const w = codeAt(pc);
            if (w === null) break;
            insns.set(pc, w);

            // 追踪 syscall 号常量（movz x8,#imm）
            if (((w & 0x1f800000) >>> 0) === 0x12800000 && B(w, 4, 0) === 8) {
                x8Const = B(w, 20, 5) | (B(w, 22, 21) << 16);
            }

            // 解析指令类型判断是否结束块（必须用 classifyAt 算绝对目标）
            const info = classifyAt(w, pc);
            if (info.kind === 'bcond' || info.kind === 'b' || info.kind === 'cbz') {
                leaders.add(info.target);
                leaders.add(pc + 4);
                queue.push(info.target, pc + 4);
                break;
            }
            if (info.kind === 'bl') {
                leaders.add(info.target);
                leaders.add(pc + 4);
                queue.push(info.target, pc + 4);
                break;
            }
            if (info.kind === 'ret') break;
            if (info.kind === 'svc') {
                // exit/exit_group 之后是指令流的终点，继续扫描会踩到数据区
                if (x8Const === 93 || x8Const === 94) break;
                x8Const = null; // 非 exit syscall，返回后继续
            }
            pc += 4;
        }
    }

    const sorted = [...leaders].sort((a, b) => a - b);
    const addrToBlock = new Map(sorted.map((a, i) => [a, i]));
    return { leaders: sorted, addrToBlock, insns, codeAt };
}

function elfReg() { return 0; } // 保留位，svc 的 nr 在运行时由 x8 决定

/** 粗分类：返回控制流信息 */
function classify(w) {
    if (((w & 0xfc000000) >>> 0) === 0x14000000) {
        const imm = SEXT(w & 0x03ffffff, 26) << 2;
        return { kind: 'b', target: 0, imm }; // target 在 decode 时结合 pc
    }
    if (((w & 0xfc000000) >>> 0) === 0x94000000) {
        const imm = SEXT(w & 0x03ffffff, 26) << 2;
        return { kind: 'bl', target: 0, imm };
    }
    if (((w & 0xff000010) >>> 0) === 0x54000000) {
        const imm = SEXT(B(w, 23, 5), 19) << 2;
        return { kind: 'bcond', target: 0, imm };
    }
    // CBZ / CBNZ (32/64-bit): sf 0x34/0x35 (w), 0xb4/0xb5 (x)
    {
        const top = (w & 0x7f000000) >>> 0;
        if (top === 0x34000000 || top === 0x35000000 ||
            top === 0xb4000000 || top === 0xb5000000) {
            const imm = SEXT(B(w, 23, 5), 19) << 2;
            const nonzero = (top === 0x35000000 || top === 0xb5000000);
            return { kind: 'cbz', target: 0, imm, nonzero };
        }
    }
    if (w === 0xd65f03c0) return { kind: 'ret' };
    if (((w & 0xff000000) >>> 0) === 0xd4000000) return { kind: 'svc' };
    return { kind: 'other' };
}

/** 带 pc 的精确分类（把相对偏移算成绝对地址） */
function classifyAt(w, pc) {
    const c = classify(w);
    if (c.kind === 'b' || c.kind === 'bl' || c.kind === 'bcond' || c.kind === 'cbz') c.target = pc + c.imm;
    return c;
}

/* ==================== WASM global 分配 ==================== */
const G = {
    X0: 0,            // x0..x30 -> 0..30
    SP: 31,           // r31 作为 SP 时的 global
    FLAGS: 32,        // NZCV: bit0=N bit1=Z bit2=C bit3=V
    RETADDR: 33,      // bl 返回的块号（i32）
    SCRATCH: 34,      // 地址计算临时寄存器 base（i64）
    RETURN: 35,       // bl 返回地址 guest 值（i64，供 ret 读取 lr）
    SCRATCH2: 36,     // pair 访存槽0 地址（i64）
    CALLSP: 37,       // 影子调用栈指针（i32，指向 WASM 内存）
    COUNT: 38,
};
const gIdx = r => r; // x0..x30

/* 寄存器读取指令序列：r==31 时按 useSP 决定读 SP 还是常量 0 */
function getReg(r, useSP) {
    if (r === 31) return useSP ? [OP.global_get, ...uleb(G.SP)] : [OP.i64_const, ...sleb(0)];
    return [OP.global_get, ...uleb(gIdx(r))];
}
function setReg(r, useSP) {
    if (r === 31) return useSP ? [OP.global_set, ...uleb(G.SP)] : [OP.drop];
    return [OP.global_set, ...uleb(gIdx(r))];
}

/* 条件判断：产生 i32 (0/1)，读 FLAGS global。
   关键：每个标志位必须归一化成 0/1，否则 FLAGS&4=4 参与 i32.and 会出错。 */
function emitCond(cond) {
    // 取一个标志位并归一化为 0/1：(FLAGS >> shift) & 1
    const bit = shift => [
        OP.global_get, ...uleb(G.FLAGS),
        OP.i32_const, ...sleb(shift), OP.i32_shr_u,
        OP.i32_const, ...sleb(1), OP.i32_and,
    ];
    const N = bit(0), Z = bit(1), C = bit(2), V = bit(3);
    const NZ = [...Z, OP.i32_eqz];
    const NC = [...C, OP.i32_eqz];
    const NN = [...N, OP.i32_eqz];
    const NV = [...V, OP.i32_eqz];
    const eqNV = () => [...N, ...V, OP.i32_eq];   // N == V
    const neNV = () => [...N, ...V, OP.i32_ne];   // N != V
    switch (cond & 0xf) {
        case 0: return Z;                                              // EQ
        case 1: return NZ;                                             // NE
        case 2: return C;                                              // CS/HS
        case 3: return NC;                                             // CC/LO
        case 4: return N;                                              // MI
        case 5: return NN;                                             // PL
        case 6: return V;                                              // VS
        case 7: return NV;                                             // VC
        case 8: return [...C, ...NZ, OP.i32_and];                      // HI
        case 9: return [...NC, ...Z, OP.i32_or];                       // LS
        case 10: return eqNV();                                        // GE
        case 11: return neNV();                                        // LT
        case 12: return [...NZ, ...eqNV(), OP.i32_and];                // GT
        case 13: return [...Z, ...neNV(), OP.i32_or];                  // LE
        case 14: return [OP.i32_const, ...sleb(1)];                    // AL
        default: return [OP.i32_const, ...sleb(0)];                    // NV
    }
}

/* ==================== 指令翻译 ==================== */

function translateBlock(blocks, blockIdx, ctx) {
    const { addrToBlock, insns, codeAt, leaders } = blocks;
    const start = leaders[blockIdx];
    const out = [];
    const emit = a => out.push(...a);

    // 下一个块的默认地址
    const nextAddrOf = pc => {
        // 找 pc+4 所在块
        const t = pc + 4;
        return addrToBlock.has(t) ? addrToBlock.get(t) : -1;
    };

    let pc = start;
    while (true) {
        const w = insns.get(pc);
        if (w === undefined) { emit([OP.i32_const, ...sleb(-1), OP.return]); break; }
        const ci = classifyAt(w, pc);

        if (ci.kind === 'ret') {
            // 从影子调用栈弹出返回块号：CALLSP -= 4; blk = i32.load(CALLSP)
            emit([
                OP.global_get, ...uleb(G.CALLSP), OP.i32_const, ...sleb(4), OP.i32_sub,
                OP.global_set, ...uleb(G.CALLSP),
                OP.global_get, ...uleb(G.CALLSP), OP.i32_load, 2, 0,
                OP.return,
            ]);
            break;
        }
        if (ci.kind === 'b' || ci.kind === 'bcond' || ci.kind === 'cbz') {
            const tgtBlk = addrToBlock.get(ci.target);
            const fallBlk = nextAddrOf(pc);
            if (ci.kind === 'b') {
                emit([OP.i32_const, ...sleb(tgtBlk === undefined ? -1 : tgtBlk), OP.return]);
            } else if (ci.kind === 'cbz') {
                // cbz: 寄存器为 0 跳转；cbnz: 非 0 跳转。32 位时取低 32 位。
                const rt = B(w, 4, 0);
                const sf = (w >>> 31) & 1;
                emit(getReg(rt, false));
                let isZero;
                if (!sf) { emit([OP.i32_wrap_i64]); isZero = OP.i32_eqz; } // w 寄存器看低 32 位
                else isZero = OP.i64_eqz;
                if (!ci.nonzero) emit([isZero]);        // cbz: val==0
                else emit([isZero, OP.i32_eqz]);        // cbnz: !(val==0)
                emit([OP.if, VT.i32]);
                emit([OP.i32_const, ...sleb(tgtBlk === undefined ? -1 : tgtBlk)]);
                emit([OP.else]);
                emit([OP.i32_const, ...sleb(fallBlk)]);
                emit([OP.end, OP.return]);
            } else {
                const cond = B(w, 3, 0);
                // (cond ? tgt : fall)
                emit(emitCond(cond));
                emit([OP.if, VT.i32]);
                emit([OP.i32_const, ...sleb(tgtBlk === undefined ? -1 : tgtBlk)]);
                emit([OP.else]);
                emit([OP.i32_const, ...sleb(fallBlk)]);
                emit([OP.end, OP.return]);
            }
            break;
        }
        if (ci.kind === 'bl') {
            const tgtBlk = addrToBlock.get(ci.target);
            const retBlk = nextAddrOf(pc);
            emit([
                // 压栈：i32.store(CALLSP, retBlk); CALLSP += 4
                OP.global_get, ...uleb(G.CALLSP),
                OP.i32_const, ...sleb(retBlk), OP.i32_store, 2, 0,
                OP.global_get, ...uleb(G.CALLSP), OP.i32_const, ...sleb(4), OP.i32_add,
                OP.global_set, ...uleb(G.CALLSP),
                // LR = guest 地址（写入 x30）
                OP.i64_const, ...sleb(pc + 4 - ctx.bias), ...setReg(30, false),
                OP.i32_const, ...sleb(tgtBlk === undefined ? -1 : tgtBlk), OP.return,
            ]);
            break;
        }
        if (ci.kind === 'svc') {
            // syscall(nr=x8, a0..a5=x0..x5) -> i64
            const args = [OP.global_get, ...uleb(G.X0 + 8)];
            for (let i = 0; i < 6; i++) args.push(OP.global_get, ...uleb(G.X0 + i));
            emit(args);
            emit([OP.call, ...uleb(ctx.syscallIdx)]);
            emit([...setReg(0, false)]); // 返回值写入 x0
            // exit (nr==93) → 停止调度：宿主已记录退出码，这里返回 -1
            emit([
                OP.global_get, ...uleb(G.X0 + 8), OP.i64_const, ...sleb(93), OP.i64_eq,
                OP.if, 0x40, OP.i32_const, ...sleb(-1), OP.return, OP.end,
            ]);
            pc += 4;
            continue;
        }

        // 普通指令
        const insnBytes = translateInsn(w, pc, ctx);
        emit(insnBytes);
        pc += 4;

        // 如果下一条不是块 leader，继续；否则结束本块并跳到下一块
        if (addrToBlock.has(pc) && insns.has(pc)) {
            emit([OP.i32_const, ...sleb(addrToBlock.get(pc)), OP.return]);
            break;
        }
    }
    return out;
}

function translateInsn(w, pc, ctx) {
    const o = [];
    const rd = B(w, 4, 0), rn = B(w, 9, 5), rm = B(w, 20, 16);

    // ---- MOVZ / MOVK / MOVN ----
    if (((w & 0x1f800000) >>> 0) === 0x12800000 || ((w & 0x1f800000) >>> 0) === 0x13800000 || ((w & 0x1f800000) >>> 0) === 0x10800000) {
        const hw = B(w, 22, 21) * 16;
        const imm16 = B(w, 20, 5);
        const isMovn = ((w & 0x1f800000) >>> 0) === 0x10800000;
        const isMovk = ((w & 0x1f800000) >>> 0) === 0x13800000;
        if (isMovk) {
            // 保留高位，替换 16 位
            o.push(...getReg(rd, false), OP.i64_const, ...sleb(~0xffffn << BigInt(hw) & 0xffffffffffffffffn), OP.i64_and);
            o.push(OP.i64_const, ...sleb(BigInt(imm16) << BigInt(hw)), OP.i64_or);
        } else {
            let v = BigInt(imm16) << BigInt(hw);
            if (isMovn) v = ~v;
            o.push(OP.i64_const, ...sleb(v));
        }
        o.push(...setReg(rd, false));
        return o;
    }

    // ---- ADR / ADRP ----
    if (((w & 0x1f000000) >>> 0) === 0x10000000) {
        const isAdrp = ((w & 0x80000000) >>> 0) !== 0;
        const immlo = B(w, 30, 29), immhi = B(w, 23, 5);
        let imm = SEXT((immhi << 2) | immlo, 21);
        // ADRP: 目标页基址 = (pc & ~0xfff) + (imm << 12)；ADR: pc + imm
        const guestAddr = isAdrp ? ((pc & ~0xfff) + (imm << 12)) : (pc + imm);
        o.push(OP.i64_const, ...sleb(guestAddr - ctx.bias), ...setReg(rd, false));
        return o;
    }

    // ---- ADD/SUB 立即数 ----
    if (((w & 0x7f000000) >>> 0) === 0x11000000 || ((w & 0x7f000000) >>> 0) === 0x51000000 ||
        ((w & 0x7f000000) >>> 0) === 0x31000000 || ((w & 0x7f000000) >>> 0) === 0x71000000) {
        const isSub = ((w >> 30) & 1) === 1;
        const setFlags = ((w >> 29) & 1) === 1;
        const imm12 = B(w, 21, 10), shift = B(w, 23, 22);
        const imm = imm12 * (shift ? 4096 : 1);
        const useSP = rn === 31;
        o.push(...getReg(rn, useSP), OP.i64_const, ...sleb(imm));
        if (setFlags) {
            o.push(OP.call, ...uleb(ctx.setflagsIdx)); // 消费 a,b 返回 r 并设 flags
        } else {
            o.push(isSub ? OP.i64_sub : OP.i64_add);
        }
        o.push(...setReg(rd, rd === 31));
        return o;
    }

    // ---- ADD/SUB 移位寄存器 ----
    if (((w & 0x7f000000) >>> 0) === 0x0b000000 || ((w & 0x7f000000) >>> 0) === 0x4b000000 ||
        ((w & 0x7f000000) >>> 0) === 0x2b000000 || ((w & 0x7f000000) >>> 0) === 0x6b000000) {
        const isSub = ((w >> 30) & 1) === 1;
        const setFlags = ((w >> 29) & 1) === 1;
        const shiftType = B(w, 23, 22), imm6 = B(w, 15, 10);
        o.push(...getReg(rn, rn === 31));
        o.push(...getReg(rm, false));
        // shiftType: 0=LSL, 1=LSR, 2=ASR
        if (imm6) {
            if (shiftType === 0) o.push(OP.i64_const, ...sleb(imm6), OP.i64_shl);
            else if (shiftType === 1) o.push(OP.i64_const, ...sleb(imm6), OP.i64_shr_u);
            else if (shiftType === 2) o.push(OP.i64_const, ...sleb(imm6), OP.i64_shr_s);
        }
        if (setFlags) o.push(OP.call, ...uleb(ctx.setflagsIdx));
        else o.push(isSub ? OP.i64_sub : OP.i64_add);
        o.push(...setReg(rd, rd === 31));
        return o;
    }

    // ---- 逻辑寄存器 ORR（mov 别名）----
    if (((w & 0x7f000000) >>> 0) === 0x0a000000 || ((w & 0x7f000000) >>> 0) === 0x2a000000) {
        o.push(...getReg(rn, false), ...getReg(rm, false));
        o.push(((w & 0x7f000000) >>> 0) === 0x2a000000 ? OP.i64_or : OP.i64_and);
        o.push(...setReg(rd, false));
        return o;
    }

    // ---- MADD / MSUB / MUL ----
    if (((w & 0x7f000000) >>> 0) === 0x1b000000) {
        const ra = B(w, 14, 10);
        const isSub = ((w >> 30) & 1) === 1;
        o.push(...getReg(rn, false), ...getReg(rm, false), OP.i64_mul);
        if (ra !== 31) {
            o.push(...getReg(ra, false), isSub ? OP.i64_sub : OP.i64_add);
        }
        o.push(...setReg(rd, false));
        return o;
    }

    // ---- CSEL / CSINC（条件选择）----
    // CSEL: Rd = cond ? Rn : Rm ; 编码 0x1a800000
    // CSINC: Rd = cond ? Rn : Rm+1 ; 编码 0x1a800400（常用于 CSET）
    if (((w & 0x7fe00c00) >>> 0) === 0x1a800000 || ((w & 0x7fe00c00) >>> 0) === 0x1a800400) {
        const isInc = ((w & 0x7fe00c00) >>> 0) === 0x1a800400;
        const sf = (w >>> 31) & 1;
        const cond = B(w, 15, 12);
        const rn = B(w, 9, 5), rm = B(w, 20, 16);
        const get = r => getReg(r, false);
        const set = r => setReg(r, false);
        // 压入两个候选值（cond 真选第一个）
        o.push(...get(rn));
        if (isInc) {
            o.push(...get(rm), OP.i64_const, ...sleb(1), OP.i64_add);
        } else {
            o.push(...get(rm));
        }
        // 条件（i32 0/1）
        o.push(...emitCond(cond));
        // 32 位结果需截断到低 32 位并零扩展
        o.push(OP.select);
        if (!sf) {
            o.push(OP.i32_wrap_i64, OP.i64_extend_i32_u);
        }
        o.push(...set(rd));
        return o;
    }

    // ---- UDIV / SDIV ----
    if (((w & 0x7fe0fc00) >>> 0) === 0x1ac00800 || ((w & 0x7fe0fc00) >>> 0) === 0x1ac00c00) {
        const isSigned = ((w >> 10) & 1) === 1;
        o.push(...getReg(rn, false), ...getReg(rm, false));
        o.push(isSigned ? OP.i64_div_s : OP.i64_div_u);
        o.push(...setReg(rd, false));
        return o;
    }

    // ---- LDR/STR 立即数（unsigned offset / unscaled / pre-index / post-index）----
    // 用 SCRATCH 保存 base，避免 WASM 栈无法复制的问题。
    // 策略：base→SCRATCH；若写回则单独重算 Rn=base+imm；再用 SCRATCH 重算 EA 做访存。
    if (((w & 0x3b000000) >>> 0) === 0x39000000 || ((w & 0x3b000000) >>> 0) === 0x38000000) {
        const size = B(w, 31, 30);          // 0=byte 1=half 2=word 3=dword
        const isLoad = ((w >> 22) & 1) === 1;
        const isUnscaled = ((w & 0x3b000000) >>> 0) === 0x38000000;
        const addrMode = B(w, 11, 10);      // 00=unscaled offset, 01=post-index, 11=pre-index
        let imm = isUnscaled ? SEXT(B(w, 20, 12), 9) : B(w, 21, 10) * (1 << size);
        const isPost = isUnscaled && addrMode === 1;   // post-index: EA=base, Rn=base+imm
        const isPre = isUnscaled && addrMode === 3;    // pre-index: EA=base+imm, Rn=base+imm
        const writeback = isPost || isPre;

        // base → SCRATCH
        o.push(...getReg(rn, true), OP.global_set, ...uleb(G.SCRATCH));
        // 写回 Rn = base + imm
        if (writeback) {
            o.push(OP.global_get, ...uleb(G.SCRATCH), OP.i64_const, ...sleb(imm), OP.i64_add, ...setReg(rn, true));
        }
        // EA（i32）：post 用 base，其余用 base+imm
        o.push(OP.global_get, ...uleb(G.SCRATCH));
        if (!isPost) o.push(OP.i64_const, ...sleb(imm), OP.i64_add);
        o.push(OP.i32_wrap_i64);

        if (isLoad) {
            const op = size === 3 ? OP.i64_load : size === 2 ? OP.i64_load32_u
                     : size === 1 ? OP.i64_load16_u : OP.i64_load8_u;
            o.push(op, size, 0, ...setReg(rd, false));
        } else {
            o.push(...getReg(rd, false));
            const op = size === 3 ? OP.i64_store : size === 2 ? OP.i64_store32
                     : size === 1 ? OP.i64_store16 : OP.i64_store8;
            o.push(op, size, 0);
        }
        return o;
    }

    // ---- LDP / STP（load/store pair）----
    if (((w & 0x3a000000) >>> 0) === 0x28000000) {
        const isLoad = ((w >> 22) & 1) === 1;
        const opc = B(w, 31, 30);
        const is64 = (opc & 2) !== 0;      // opc=10/01→64位, opc=00→32位
        const slot = is64 ? 8 : 4;
        const imm7 = SEXT(B(w, 21, 15), 7) * slot;
        const mode = B(w, 24, 23);         // 01=post-index, 10=signed offset, 11=pre-index
        const rt = B(w, 4, 0), rt2 = B(w, 14, 10);
        const isPost = mode === 1, isPre = mode === 3;
        const writeback = isPost || isPre;

        // base → SCRATCH
        o.push(...getReg(rn, true), OP.global_set, ...uleb(G.SCRATCH));
        // 写回 Rn = base + imm7
        if (writeback) {
            o.push(OP.global_get, ...uleb(G.SCRATCH), OP.i64_const, ...sleb(imm7), OP.i64_add, ...setReg(rn, true));
        }
        // 槽0 EA：post 用 base，其余 base+imm7；存入 SCRATCH2
        o.push(OP.global_get, ...uleb(G.SCRATCH));
        if (!isPost) o.push(OP.i64_const, ...sleb(imm7), OP.i64_add);
        o.push(OP.global_set, ...uleb(G.SCRATCH2));

        const loadOp = is64 ? OP.i64_load : OP.i64_load32_u;
        const storeOp = is64 ? OP.i64_store : OP.i64_store32;
        const align = is64 ? 3 : 2;

        if (isLoad) {
            o.push(OP.global_get, ...uleb(G.SCRATCH2), OP.i32_wrap_i64, loadOp, align, 0, ...setReg(rt, false));
            o.push(OP.global_get, ...uleb(G.SCRATCH2), OP.i64_const, ...sleb(slot), OP.i64_add,
                   OP.i32_wrap_i64, loadOp, align, 0, ...setReg(rt2, false));
        } else {
            o.push(OP.global_get, ...uleb(G.SCRATCH2), OP.i32_wrap_i64, ...getReg(rt, false), storeOp, align, 0);
            o.push(OP.global_get, ...uleb(G.SCRATCH2), OP.i64_const, ...sleb(slot), OP.i64_add,
                   OP.i32_wrap_i64, ...getReg(rt2, false), storeOp, align, 0);
        }
        return o;
    }

    // ---- 未实现：返回 trap 标记（宿主可观测）----
    o.push(OP.unreachable);
    return o;
}

/* ==================== 组装模块 ==================== */

function translateELF(pathOrBuffer, opts = {}) {
    // Node 传路径字符串，浏览器/WebKit 直接传 ArrayBuffer/Uint8Array
    let buf;
    if (typeof pathOrBuffer === 'string') buf = getFs().readFileSync(pathOrBuffer);
    else if (pathOrBuffer instanceof Uint8Array) buf = Buffer.from(pathOrBuffer.buffer || pathOrBuffer,
        pathOrBuffer.byteOffset || 0, pathOrBuffer.byteLength);
    else buf = Buffer.from(pathOrBuffer);
    const elf = parseELF(buf);
    const blocks = findBlocks(elf);
    const memPages = opts.memPages || 16; // 16*64KiB = 1MiB

    const m = new ModuleBuilder();
    // import syscall(nr,a0..a5) -> i64
    const syscallIdx = m.importFunc('env', 'syscall',
        [VT.i64, VT.i64, VT.i64, VT.i64, VT.i64, VT.i64, VT.i64], [VT.i64]);
    // import memory
    m.importMemory('env', 'memory', memPages);

    // globals
    const gInit = i => [OP.i32_const, ...sleb(i)];
    for (let i = 0; i < 31; i++) m.defineGlobal(VT.i64, true, [OP.i64_const, ...sleb(0)]); // x0..x30
    m.defineGlobal(VT.i64, true, [OP.i64_const, ...sleb(memPages * 65536 - 4096)]); // SP (31)
    m.defineGlobal(VT.i32, true, gInit(0)); // FLAGS (32)
    m.defineGlobal(VT.i32, true, gInit(0)); // RETADDR (33)
    m.defineGlobal(VT.i64, true, [OP.i64_const, ...sleb(0)]); // SCRATCH (34)
    m.defineGlobal(VT.i64, true, [OP.i64_const, ...sleb(0)]); // RETURN (35)
    m.defineGlobal(VT.i64, true, [OP.i64_const, ...sleb(0)]); // SCRATCH2 (36)
    m.defineGlobal(VT.i32, true, [OP.i32_const, ...sleb(memPages * 65536 - 8192)]); // CALLSP (37)

    // helper: setflags_sub(a,b) -> r (同时写 FLAGS)
    const setflagsIdx = m.defineFunc([VT.i64, VT.i64], [VT.i64]);
    const sfBody = [];
    sfBody.push(OP.local_get, ...uleb(0), OP.local_get, ...uleb(1), OP.i64_sub, OP.local_set, ...uleb(2));
    sfBody.push(OP.i32_const, ...sleb(0), OP.global_set, ...uleb(G.FLAGS)); // 先清零
    // Z
    sfBody.push(OP.local_get, ...uleb(2), OP.i64_eqz, OP.if, 0x40);
    sfBody.push(OP.i32_const, ...sleb(2), OP.global_get, ...uleb(G.FLAGS), OP.i32_or, OP.global_set, ...uleb(G.FLAGS), OP.end);
    // N
    sfBody.push(OP.local_get, ...uleb(2), OP.i64_const, ...sleb(63), OP.i64_shr_u, OP.i32_wrap_i64, OP.i32_const, ...sleb(1), OP.i32_and, OP.if, 0x40);
    sfBody.push(OP.i32_const, ...sleb(1), OP.global_get, ...uleb(G.FLAGS), OP.i32_or, OP.global_set, ...uleb(G.FLAGS), OP.end);
    // C = a >=_u b
    sfBody.push(OP.local_get, ...uleb(0), OP.local_get, ...uleb(1), OP.i64_ge_u, OP.if, 0x40);
    sfBody.push(OP.i32_const, ...sleb(4), OP.global_get, ...uleb(G.FLAGS), OP.i32_or, OP.global_set, ...uleb(G.FLAGS), OP.end);
    // V = ((a^b) & (a^r)) < 0
    sfBody.push(OP.local_get, ...uleb(0), OP.local_get, ...uleb(1), OP.i64_xor,
                OP.local_get, ...uleb(0), OP.local_get, ...uleb(2), OP.i64_xor, OP.i64_and,
                OP.i64_const, ...sleb(63), OP.i64_shr_u, OP.i32_wrap_i64, OP.i32_const, ...sleb(1), OP.i32_and, OP.if, 0x40);
    sfBody.push(OP.i32_const, ...sleb(8), OP.global_get, ...uleb(G.FLAGS), OP.i32_or, OP.global_set, ...uleb(G.FLAGS), OP.end);
    sfBody.push(OP.local_get, ...uleb(2));
    m.code(sfBody, [{ count: 1, type: VT.i64 }]);

    // 每个块一个函数 () -> i32
    const ctx = { syscallIdx, setflagsIdx, bias: elf.bias };
    const blockFuncIdx = [];
    const blockBodies = [];
    for (let i = 0; i < blocks.leaders.length; i++) {
        const idx = m.defineFunc([], [VT.i32]);
        blockFuncIdx.push(idx);
        const body = translateBlock(blocks, i, ctx);
        blockBodies.push(body);
        m.code(body);
        m.exportFunc('bb' + i, idx);
    }

    // data section: 把 PT_LOAD 段内容写入 WASM memory
    for (const l of elf.loads) {
        const off = l.p_vaddr - elf.bias;
        const bytes = elf.buf.subarray(l.p_offset, l.p_offset + l.p_filesz);
        if (bytes.length) m.data([OP.i32_const, ...uleb(off)], bytes);
    }


    const bin = m.build();
    const entryBlock = blocks.addrToBlock.get(elf.entry);
    return {
        binary: bin,
        entryBlock,
        blockCount: blocks.leaders.length,
        elf,
        blocks,
        blockBodies,
        validate: () => WebAssembly.validate(bin),
    };
}

module.exports = { translateELF, parseELF, classifyAt, emitCond, G };
