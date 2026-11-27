/*
 * wasm-encoder.js — 最小 WebAssembly 二进制编码器
 *
 * 完全手写，不依赖 wabt/assemblyscript 等第三方库。
 * 只实现本项目需要的指令子集和 section。
 * 目标：让翻译器能直接产出可被 WebKit JSC / Node 执行的 WASM 模块。
 */

'use strict';

/* ============ LEB128 ============ */

/** 无符号 LEB128，接受 number 或 bigint */
function uleb(v) {
    let n = BigInt(v);
    if (n < 0n) throw new Error('uleb: negative value');
    // 归一化到无符号 64 位：避免调用方传入 >2^64 的掩码时编码出非法长 varint
    n &= 0xffffffffffffffffn;
    const out = [];
    do {
        let byte = Number(n & 0x7fn);
        n >>= 7n;
        if (n !== 0n) byte |= 0x80;
        out.push(byte);
    } while (n !== 0n);
    return out;
}

/** 有符号 LEB128，接受 number 或 bigint */
function sleb(v) {
    let n = BigInt(v);
    // 归一化到有符号 64 位：WASM i64.const 必须是 64 位有符号 LEB128。
    // 调用方常产生 0xffffffffffff.... 这类无符号位掩码，不归一化会编出 10 字节非法 varint。
    n &= 0xffffffffffffffffn;
    if (n >= (1n << 63n)) n -= (1n << 64n);
    const out = [];
    for (;;) {
        let byte = Number(n & 0x7fn);
        n >>= 7n;
        const signBit = (byte & 0x40) !== 0;
        if ((n === 0n && !signBit) || (n === -1n && signBit)) {
            out.push(byte);
            break;
        }
        out.push(byte | 0x80);
    }
    return out;
}

/** name 以 UTF-8 写入，前面带长度 */
function name(s) {
    const bytes = Buffer.from(s, 'utf8');
    return [...uleb(bytes.length), ...bytes];
}

/* ============ Opcode 常量 ============ */
const OP = {
    unreachable: 0x00, nop: 0x01,
    block: 0x02, loop: 0x03, if: 0x04, else: 0x05, end: 0x0b,
    br: 0x0c, br_if: 0x0d, br_table: 0x0e,
    return: 0x0f, call: 0x10, call_indirect: 0x11,
    drop: 0x1a, select: 0x1b,
    local_get: 0x20, local_set: 0x21, local_tee: 0x22,
    global_get: 0x23, global_set: 0x24,

    i32_load: 0x28, i64_load: 0x29,
    i32_load8_u: 0x2d, i32_load8_s: 0x2c,
    i32_load16_u: 0x2f, i32_load16_s: 0x2e,
    i64_load8_u: 0x31, i64_load8_s: 0x30,
    i64_load16_u: 0x33, i64_load16_s: 0x32,
    i64_load32_u: 0x35, i64_load32_s: 0x34,
    i32_store: 0x36, i64_store: 0x37,
    i32_store8: 0x3a, i32_store16: 0x3b,
    i64_store8: 0x3c, i64_store16: 0x3d, i64_store32: 0x3e,
    memory_size: 0x3f, memory_grow: 0x40,

    i32_const: 0x41, i64_const: 0x42,

    i32_eqz: 0x45, i32_eq: 0x46, i32_ne: 0x47,
    i32_and: 0x71, i32_or: 0x72, i32_xor: 0x73,
    i32_lt_s: 0x48, i32_lt_u: 0x49, i32_gt_s: 0x4a, i32_gt_u: 0x4b,
    i32_le_s: 0x4c, i32_le_u: 0x4d, i32_ge_s: 0x4e, i32_ge_u: 0x4f,

    i64_eqz: 0x50, i64_eq: 0x51, i64_ne: 0x52,
    i64_lt_s: 0x53, i64_lt_u: 0x54, i64_gt_s: 0x55, i64_gt_u: 0x56,
    i64_le_s: 0x57, i64_le_u: 0x58, i64_ge_s: 0x59, i64_ge_u: 0x5a,

    i32_add: 0x6a, i32_sub: 0x6b, i32_mul: 0x6c,
    i32_shl: 0x74, i32_shr_s: 0x75, i32_shr_u: 0x76,
    i64_clz: 0x79, i64_ctz: 0x7a, i64_popcnt: 0x7b,
    i64_add: 0x7c, i64_sub: 0x7d, i64_mul: 0x7e,
    i64_div_s: 0x7f, i64_div_u: 0x80, i64_rem_s: 0x81, i64_rem_u: 0x82,
    i64_and: 0x83, i64_or: 0x84, i64_xor: 0x85,
    i64_shl: 0x86, i64_shr_s: 0x87, i64_shr_u: 0x88,
    i64_rotl: 0x89, i64_rotr: 0x8a,

    i64_extend_i32_u: 0xad, i64_extend_i32_s: 0xac,
    i32_wrap_i64: 0xa7,
};

const VT = { i32: 0x7f, i64: 0x7e, f32: 0x7d, f64: 0x7c };
const SECTION = { type: 1, import: 2, function: 3, table: 4, memory: 5,
                  global: 6, export: 7, start: 8, element: 9, code: 10, data: 11 };

/* ============ ModuleBuilder ============ */

class ModuleBuilder {
    constructor() {
        this.types = [];       // 每个元素: {params:[vt...], results:[vt...]}
        this.imports = [];     // {module, field, kind, desc}
        this.funcTypes = [];   // 每个本地函数对应的 type index
        this.memories = [];    // limits
        this.globals = [];     // {type, mutable, initOp}
        this.exports = [];     // {name, kind, index}
        this.codes = [];       // Uint8Array body（不含 size）
        this.datas = [];       // {mem, offsetExpr, bytes}
        this.typeMap = new Map();
    }

    /** 注册/复用一个函数签名，返回 type index */
    type(params, results) {
        const key = params.join(',') + '->' + results.join(',');
        if (this.typeMap.has(key)) return this.typeMap.get(key);
        const idx = this.types.length;
        this.types.push({ params, results });
        this.typeMap.set(key, idx);
        return idx;
    }

    importFunc(mod, field, params, results) {
        const t = this.type(params, results);
        // 返回该函数在 function index 空间中的位置（push 之前的数量即为索引）
        const idx = this.funcCountSoFar();
        this.imports.push({ module: mod, field, kind: 0x00, typeIdx: t });
        return idx;
    }

    importMemory(mod, field, minPages, maxPages) {
        this.imports.push({ module: mod, field, kind: 0x02,
                            limits: maxPages == null ? [minPages] : [minPages, maxPages] });
        return 0; // 单 memory
    }

    /** 返回当前 function index 数量（import func + 本地 func） */
    funcCountSoFar() {
        return this.imports.filter(i => i.kind === 0x00).length + this.funcTypes.length;
    }

    defineFunc(params, results) {
        const t = this.type(params, results);
        this.funcTypes.push(t);
        // 返回 function index（import 函数在前）
        return this.imports.filter(i => i.kind === 0x00).length + this.funcTypes.length - 1;
    }

    defineGlobal(type, mutable, initExpr) {
        const idx = this.globals.length;
        this.globals.push({ type, mutable, initExpr });
        return idx;
    }

    exportFunc(n, idx) { this.exports.push({ name: n, kind: 0x00, index: idx }); }
    exportMemory(n, idx) { this.exports.push({ name: n, kind: 0x02, index: idx }); }
    exportGlobal(n, idx) { this.exports.push({ name: n, kind: 0x03, index: idx }); }

    /** body: 已经编码好的指令字节数组（不含末尾 end 和 size） */
    code(body, locals) {
        const groups = locals || [];
        // 函数体 = local 声明组数 + 各组(count,type) + 指令 + end
        const payload = [...uleb(groups.length)];
        for (const g of groups) payload.push(...uleb(g.count), g.type);
        payload.push(...body, OP.end);
        this.codes.push(Uint8Array.from(payload));
    }

    data(offsetExpr, bytes) {
        this.datas.push({ mem: 0, offsetExpr, bytes: Uint8Array.from(bytes) });
    }

    /** 组装最终二进制 */
    build() {
        const out = [];
        out.push(0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00); // magic + version

        const section = (id, payload) => {
            out.push(id, ...uleb(payload.length), ...payload);
        };

        // 1. type
        if (this.types.length) {
            const p = [...uleb(this.types.length)];
            for (const t of this.types) {
                p.push(0x60, ...uleb(t.params.length), ...t.params,
                       ...uleb(t.results.length), ...t.results);
            }
            section(SECTION.type, p);
        }

        // 2. import
        if (this.imports.length) {
            const p = [...uleb(this.imports.length)];
            for (const im of this.imports) {
                p.push(...name(im.module), ...name(im.field), im.kind);
                if (im.kind === 0x00) p.push(...uleb(im.typeIdx));
                else if (im.kind === 0x02) {
                    // limits = flags(1) + min + [max]，flags 必须在最前
                    if (im.limits.length > 1) p.push(1, ...uleb(im.limits[0]), ...uleb(im.limits[1]));
                    else p.push(0, ...uleb(im.limits[0]));
                }
            }
            section(SECTION.import, p);
        }

        // 3. function
        if (this.funcTypes.length) {
            const p = [...uleb(this.funcTypes.length), ...this.funcTypes.flatMap(t => uleb(t))];
            section(SECTION.function, p);
        }

        // 5. memory（如果没用 import memory）
        if (this.memories.length) {
            const p = [...uleb(this.memories.length)];
            for (const lim of this.memories) {
                if (lim.length > 1) p.push(1, ...uleb(lim[0]), ...uleb(lim[1]));
                else p.push(0, ...uleb(lim[0]));
            }
            section(SECTION.memory, p);
        }

        // 6. global
        if (this.globals.length) {
            const p = [...uleb(this.globals.length)];
            for (const g of this.globals) {
                p.push(g.type, g.mutable ? 1 : 0, ...g.initExpr, OP.end);
            }
            section(SECTION.global, p);
        }

        // 7. export
        if (this.exports.length) {
            const p = [...uleb(this.exports.length)];
            for (const e of this.exports) {
                p.push(...name(e.name), e.kind, ...uleb(e.index));
            }
            section(SECTION.export, p);
        }

        // 10. code
        if (this.codes.length) {
            const p = [...uleb(this.codes.length)];
            for (const body of this.codes) {
                p.push(...uleb(body.length), ...body);
            }
            section(SECTION.code, p);
        }

        // 11. data
        if (this.datas.length) {
            const p = [...uleb(this.datas.length)];
            for (const d of this.datas) {
                p.push(0x00, ...d.offsetExpr, OP.end, ...uleb(d.bytes.length), ...d.bytes);
            }
            section(SECTION.data, p);
        }

        return Uint8Array.from(out);
    }
}

module.exports = { ModuleBuilder, OP, VT, SECTION, uleb, sleb, name };
