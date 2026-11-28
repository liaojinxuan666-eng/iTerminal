import { VALTYPE, OP, uleb128, sleb128, ModuleBuilder } from './wasm-encoder-v2';

const STATE_BASE = 0x0000;
export const OFF_X = (n: number): number => STATE_BASE + n * 8;
export const OFF_SP = STATE_BASE + 31 * 8;
export const OFF_PC = STATE_BASE + 32 * 8;
export const OFF_N = STATE_BASE + 0x108;
export const OFF_Z = STATE_BASE + 0x10c;
export const OFF_C = STATE_BASE + 0x110;
export const OFF_V = STATE_BASE + 0x114;
export const OFF_TPIDR = STATE_BASE + 0x118;
export const OFF_Q = (n: number): number => STATE_BASE + 0x120 + n * 16; // Q0..Q31 (128-bit SIMD)

export const ICACHE_BASE = 0x1000;
const ICACHE_ENTRIES = 4096;
const ICACHE_MASK = ICACHE_ENTRIES - 1;

export const STATUS = {
  CONTINUE: 0,
  YIELD: 1,
  CACHE_MISS: 2,
  EXIT: -1,
  SYSCALL_PENDING: -2,
  FAULT: -3,
};

function signExtend(val: number, bits: number): number {
  const shift = 32 - bits;
  return (val << shift) >> shift;
}

// ARMv8 DecodeBitMasks(immN, imms, immr, is64) -> BigInt mask
export function decodeBitMasks(immN: number, imms: number, immr: number, is64: boolean): bigint {
  const lenVal = (immN << 6) | (~imms & 0x3f);
  let len = 6;
  while (len > 0 && ((lenVal >>> len) & 1) === 0) len--;
  if (len < 1) return 0n;
  const esize = 1 << len;
  const levels = esize - 1;
  const S = imms & levels;
  const R = immr & levels;
  const welem = (1n << BigInt(S + 1)) - 1n;
  const esizeB = BigInt(esize);
  const rB = BigInt(R);
  // Rotate right within esize bits
  const rotated =
    rB === 0n
      ? welem
      : ((welem >> rB) | ((welem << (esizeB - rB)) & ((1n << esizeB) - 1n)));
  // Replicate across 32 or 64 bits
  const totalBits = is64 ? 64 : 32;
  let out = 0n;
  for (let pos = 0; pos < totalBits; pos += esize) {
    out |= rotated << BigInt(pos);
  }
  return out;
}

class CodeBuf {
  b: number[] = [];
  op(...ops: number[]): void {
    for (const o of ops) this.b.push(o);
  }
  i32Const(v: number): void {
    this.b.push(OP.I32_CONST, ...sleb128(v | 0));
  }
  i64Const(v: number | bigint): void {
    this.b.push(OP.I64_CONST, ...sleb128(BigInt.asIntN(64, typeof v === 'bigint' ? v : BigInt(v))));
  }
  localGet(idx: number): void {
    this.b.push(OP.LOCAL_GET, ...uleb128(idx));
  }
  localSet(idx: number): void {
    this.b.push(OP.LOCAL_SET, ...uleb128(idx));
  }
  localTee(idx: number): void {
    this.b.push(OP.LOCAL_TEE, ...uleb128(idx));
  }
  loadI32(offset = 0, align = 2): void {
    this.b.push(OP.I32_LOAD, ...uleb128(align), ...uleb128(offset));
  }
  loadI64(offset = 0, align = 3): void {
    this.b.push(OP.I64_LOAD, ...uleb128(align), ...uleb128(offset));
  }
  storeI32(offset = 0, align = 2): void {
    this.b.push(OP.I32_STORE, ...uleb128(align), ...uleb128(offset));
  }
  storeI64(offset = 0, align = 3): void {
    this.b.push(OP.I64_STORE, ...uleb128(align), ...uleb128(offset));
  }
  getReg(r: number, useSp = false, is32 = false): void {
    if (r === 31 && !useSp) {
      this.i64Const(0n);
      return;
    }
    this.i32Const(r === 31 ? OFF_SP : OFF_X(r));
    this.loadI64(0, 3);
    if (is32) {
      this.i64Const(0xffffffffn);
      this.op(OP.I64_AND);
    }
  }
  beginSetReg(r: number, useSp = false): boolean {
    if (r === 31 && !useSp) return false;
    this.i32Const(r === 31 ? OFF_SP : OFF_X(r));
    return true;
  }
  endSetReg(r: number, useSp = false, is32 = false): void {
    if (r === 31 && !useSp) {
      this.op(OP.DROP);
      return;
    }
    if (is32) {
      this.i64Const(0xffffffffn);
      this.op(OP.I64_AND);
    }
    this.storeI64(0, 3);
  }
  setPC(pcVal: number): void {
    this.i32Const(OFF_PC);
    this.i64Const(BigInt(pcVal >>> 0));
    this.storeI64(0, 3);
  }
  emitCond(cond: number): void {
    const base = cond & 0xe;
    const loadFlag = (off: number): void => {
      this.i32Const(off);
      this.loadI32(0, 2);
    };
    switch (base) {
      case 0x0: loadFlag(OFF_Z); break;
      case 0x2: loadFlag(OFF_C); break;
      case 0x4: loadFlag(OFF_N); break;
      case 0x6: loadFlag(OFF_V); break;
      case 0x8:
        loadFlag(OFF_C);
        loadFlag(OFF_Z);
        this.op(OP.I32_EQZ, OP.I32_AND);
        break;
      case 0xa:
        loadFlag(OFF_N);
        loadFlag(OFF_V);
        this.op(OP.I32_EQ);
        break;
      case 0xc:
        loadFlag(OFF_Z);
        this.op(OP.I32_EQZ);
        loadFlag(OFF_N);
        loadFlag(OFF_V);
        this.op(OP.I32_EQ, OP.I32_AND);
        break;
      case 0xe:
        this.i32Const(1);
        break;
    }
    if ((cond & 1) === 1 && base !== 0xe) {
      this.op(OP.I32_EQZ);
    }
  }
}

function buildDispatcherModule(memMinPages = 16, tableMin = 1024): WebAssembly.Module {
  const mb = new ModuleBuilder();
  const tBlock = mb.addType([], [VALTYPE.I32]);
  const tRun = mb.addType([VALTYPE.I32], [VALTYPE.I32]);
  mb.importMemory('env', 'mem', memMinPages);
  mb.importTable('env', 'tbl', tableMin);

  const c = new CodeBuf();
  c.op(OP.LOOP, VALTYPE.VOID);
  c.localGet(0);
  c.i32Const(0);
  c.op(OP.I32_LE_S, OP.IF, VALTYPE.VOID);
  c.i32Const(STATUS.YIELD);
  c.op(OP.RETURN, OP.END);

  c.i32Const(OFF_PC);
  c.loadI32(0, 2);
  c.localTee(1);

  c.i32Const(2);
  c.op(OP.I32_SHR_U);
  c.i32Const(ICACHE_MASK);
  c.op(OP.I32_AND);
  c.i32Const(3);
  c.op(OP.I32_SHL);
  c.i32Const(ICACHE_BASE);
  c.op(OP.I32_ADD);
  c.localTee(2);

  c.loadI32(0, 2);
  c.localGet(1);
  c.op(OP.I32_NE, OP.IF, VALTYPE.VOID);
  c.i32Const(STATUS.CACHE_MISS);
  c.op(OP.RETURN, OP.END);

  c.localGet(2);
  c.loadI32(4, 2);
  c.op(OP.CALL_INDIRECT, ...uleb128(tBlock), 0x00);
  c.localTee(3);
  c.op(OP.IF, VALTYPE.VOID);
  c.localGet(3);
  c.op(OP.RETURN, OP.END);

  c.localGet(0);
  c.i32Const(1);
  c.op(OP.I32_SUB);
  c.localSet(0);
  c.op(OP.BR, 0);
  c.op(OP.END);

  c.i32Const(STATUS.YIELD);
  mb.addFunction(tRun, [[3, VALTYPE.I32]], c.b, 'run_slice');
  return new WebAssembly.Module(mb.toUint8Array() as BufferSource);
}

export function translateBasicBlock(memView: DataView, startPC: number, maxInsns = 128): WebAssembly.Module {
  const mb = new ModuleBuilder();
  const tSyscall = mb.addType([], [VALTYPE.I32]);
  const tBlock = mb.addType([], [VALTYPE.I32]);
  mb.importMemory('env', 'mem', 1);
  const fnSyscall = mb.importFunc('env', 'syscall', tSyscall);

  // Locals: 0=tmpA(i64), 1=tmpB(i64), 2=tmpR(i64), 3=tmpAddr(i32)
  const c = new CodeBuf();
  let pc = startPC >>> 0;
  let terminated = false;

  for (let count = 0; count < maxInsns && !terminated; count++) {
    if (pc + 4 > memView.byteLength) {
      c.setPC(pc);
      c.i32Const(STATUS.FAULT);
      c.op(OP.RETURN);
      terminated = true;
      break;
    }
    const insn = memView.getUint32(pc, true);
    const nextPC = (pc + 4) >>> 0;

    // 1. NOP / DMB / DSB / ISB / CLREX / HINT
    if (
      insn === 0xd503201f ||
      ((insn & 0xfffff01f) >>> 0) === 0xd503301f ||
      ((insn & 0xfffff0ff) >>> 0) === 0xd503305f ||
      ((insn & 0xfffff01f) >>> 0) === 0xd503201f
    ) {
      pc = nextPC;
      continue;
    }

    // 2. MRS Xt, TPIDR_EL0 (0xD53BD040) & MSR TPIDR_EL0, Xt (0xD51BD040)
    if (((insn & 0xffffffe0) >>> 0) === 0xd53bd040) {
      const rt = insn & 0x1f;
      if (c.beginSetReg(rt, false)) {
        c.i32Const(OFF_TPIDR);
        c.loadI64(0, 3);
        c.endSetReg(rt, false, false);
      }
      pc = nextPC;
      continue;
    }
    if (((insn & 0xffffffe0) >>> 0) === 0xd51bd040) {
      const rt = insn & 0x1f;
      c.i32Const(OFF_TPIDR);
      c.getReg(rt, false, false);
      c.storeI64(0, 3);
      pc = nextPC;
      continue;
    }

    // 3. SVC #imm16
    if (((insn & 0xffe0001f) >>> 0) === 0xd4000001) {
      c.setPC(nextPC);
      c.op(OP.CALL, ...uleb128(fnSyscall));
      c.op(OP.RETURN);
      terminated = true;
      break;
    }

    // 4. B / BL
    if (((insn & 0x7c000000) >>> 0) === 0x14000000) {
      const isBL = (insn >>> 31) === 1;
      const imm26 = signExtend(insn & 0x03ffffff, 26);
      const target = (pc + (imm26 << 2)) >>> 0;
      if (isBL) {
        c.beginSetReg(30, false);
        c.i64Const(BigInt(nextPC));
        c.endSetReg(30, false, false);
      }
      c.setPC(target);
      c.i32Const(STATUS.CONTINUE);
      c.op(OP.RETURN);
      terminated = true;
      break;
    }

    // 5. B.cond
    if (((insn & 0xff000010) >>> 0) === 0x54000000) {
      const cond = insn & 0xf;
      const imm19 = signExtend((insn >>> 5) & 0x7ffff, 19);
      const target = (pc + (imm19 << 2)) >>> 0;
      c.emitCond(cond);
      c.op(OP.IF, VALTYPE.VOID);
      c.setPC(target);
      c.op(OP.ELSE);
      c.setPC(nextPC);
      c.op(OP.END);
      c.i32Const(STATUS.CONTINUE);
      c.op(OP.RETURN);
      terminated = true;
      break;
    }

    // 6. CBZ / CBNZ
    if (((insn & 0x7e000000) >>> 0) === 0x34000000) {
      const is64 = (insn >>> 31) === 1;
      const isNZ = ((insn >>> 24) & 1) === 1;
      const rt = insn & 0x1f;
      const imm19 = signExtend((insn >>> 5) & 0x7ffff, 19);
      const target = (pc + (imm19 << 2)) >>> 0;
      c.getReg(rt, false, !is64);
      c.op(OP.I64_EQZ);
      if (isNZ) c.op(OP.I32_EQZ);
      c.op(OP.IF, VALTYPE.VOID);
      c.setPC(target);
      c.op(OP.ELSE);
      c.setPC(nextPC);
      c.op(OP.END);
      c.i32Const(STATUS.CONTINUE);
      c.op(OP.RETURN);
      terminated = true;
      break;
    }

    // 7. TBZ / TBNZ
    if (((insn & 0x7e000000) >>> 0) === 0x36000000) {
      const b5 = (insn >>> 31) & 1;
      const isNZ = ((insn >>> 24) & 1) === 1;
      const b40 = (insn >>> 19) & 0x1f;
      const bit = (b5 << 5) | b40;
      const rt = insn & 0x1f;
      const imm14 = signExtend((insn >>> 5) & 0x3fff, 14);
      const target = (pc + (imm14 << 2)) >>> 0;
      c.getReg(rt, false, false);
      c.i64Const(1n << BigInt(bit));
      c.op(OP.I64_AND, OP.I64_EQZ);
      if (isNZ) c.op(OP.I32_EQZ);
      c.op(OP.IF, VALTYPE.VOID);
      c.setPC(target);
      c.op(OP.ELSE);
      c.setPC(nextPC);
      c.op(OP.END);
      c.i32Const(STATUS.CONTINUE);
      c.op(OP.RETURN);
      terminated = true;
      break;
    }

    // 8. BR / BLR / RET
    if (((insn & 0xff9ffc1f) >>> 0) === 0xd61f0000) {
      const opc = (insn >>> 21) & 0x3;
      const rn = (insn >>> 5) & 0x1f;
      c.getReg(rn, false, false);
      c.localSet(0);
      if (opc === 1) {
        c.beginSetReg(30, false);
        c.i64Const(BigInt(nextPC));
        c.endSetReg(30, false, false);
      }
      c.i32Const(OFF_PC);
      c.localGet(0);
      c.storeI64(0, 3);
      c.i32Const(STATUS.CONTINUE);
      c.op(OP.RETURN);
      terminated = true;
      break;
    }

    // 9. MOVZ / MOVK / MOVN
    if (((insn & 0x1f800000) >>> 0) === 0x12800000) {
      const is64 = (insn >>> 31) === 1;
      const opc = (insn >>> 29) & 0x3;
      const hw = (insn >>> 21) & 0x3;
      const imm16 = BigInt((insn >>> 5) & 0xffff);
      const rd = insn & 0x1f;
      const shift = BigInt(hw * 16);
      if (c.beginSetReg(rd, false)) {
        if (opc === 2) {
          c.i64Const(imm16 << shift);
        } else if (opc === 0) {
          const mask = is64 ? 0xffffffffffffffffn : 0xffffffffn;
          c.i64Const((~(imm16 << shift)) & mask);
        } else if (opc === 3) {
          const clearMask = ~(0xffffn << shift);
          c.getReg(rd, false, !is64);
          c.i64Const(clearMask);
          c.op(OP.I64_AND);
          c.i64Const(imm16 << shift);
          c.op(OP.I64_OR);
        }
        c.endSetReg(rd, false, !is64);
      }
      pc = nextPC;
      continue;
    }

    // 10. ADR / ADRP
    if (((insn & 0x1f000000) >>> 0) === 0x10000000) {
      const isADRP = (insn >>> 31) === 1;
      const immlo = (insn >>> 29) & 0x3;
      const immhi = (insn >>> 5) & 0x7ffff;
      const imm = signExtend((immhi << 2) | immlo, 21);
      const rd = insn & 0x1f;
      const base = isADRP ? (pc & ~0xfff) >>> 0 : pc;
      const addr = (base + (isADRP ? imm * 4096 : imm)) >>> 0;
      if (c.beginSetReg(rd, false)) {
        c.i64Const(BigInt(addr));
        c.endSetReg(rd, false, false);
      }
      pc = nextPC;
      continue;
    }

    // 11. Logical immediate: AND, ORR, EOR, ANDS (imm)
    if (((insn & 0x1f800000) >>> 0) === 0x12000000) {
      const is64 = (insn >>> 31) === 1;
      const opc = (insn >>> 29) & 0x3;
      const immN = (insn >>> 22) & 1;
      const immr = (insn >>> 16) & 0x3f;
      const imms = (insn >>> 10) & 0x3f;
      const rn = (insn >>> 5) & 0x1f;
      const rd = insn & 0x1f;
      const imm = decodeBitMasks(immN, imms, immr, is64);
      const rdIsSp = opc !== 3;
      c.getReg(rn, false, !is64);
      c.i64Const(imm);
      if (opc === 0 || opc === 3) c.op(OP.I64_AND);
      else if (opc === 1) c.op(OP.I64_OR);
      else if (opc === 2) c.op(OP.I64_XOR);
      if (!is64) {
        c.i64Const(0xffffffffn);
        c.op(OP.I64_AND);
      }
      c.localSet(2);
      if (c.beginSetReg(rd, rdIsSp)) {
        c.localGet(2);
        c.endSetReg(rd, rdIsSp, !is64);
      }
      if (opc === 3) emitLogicalFlags(c, is64);
      pc = nextPC;
      continue;
    }

    // 12. Bitfield: SBFM (opc=0), BFM (opc=1), UBFM (opc=2)
    // Covers LSL/LSR/ASR imm, SXTB/SXTH/SXTW, UXTB/UXTH, UBFX/SBFX/BFI!
    if (((insn & 0x1f800000) >>> 0) === 0x13000000) {
      const is64 = (insn >>> 31) === 1;
      const opc = (insn >>> 29) & 0x3;
      const immr = (insn >>> 16) & 0x3f;
      const imms = (insn >>> 10) & 0x3f;
      const rn = (insn >>> 5) & 0x1f;
      const rd = insn & 0x1f;
      const bits = is64 ? 64 : 32;

      if (c.beginSetReg(rd, false)) {
        if (opc === 2) {
          // UBFM
          c.getReg(rn, false, !is64);
          if (imms >= immr) {
            // UBFX: (src >> immr) & ((1 << (imms - immr + 1)) - 1)
            const width = imms - immr + 1;
            if (immr > 0) {
              c.i64Const(BigInt(immr));
              c.op(OP.I64_SHR_U);
            }
            if (width < 64) {
              c.i64Const((1n << BigInt(width)) - 1n);
              c.op(OP.I64_AND);
            }
          } else {
            // UBFIZ / LSL imm: (src & ((1 << (imms + 1)) - 1)) << (bits - immr)
            const width = imms + 1;
            const lshift = bits - immr;
            if (width < 64) {
              c.i64Const((1n << BigInt(width)) - 1n);
              c.op(OP.I64_AND);
            }
            c.i64Const(BigInt(lshift));
            c.op(OP.I64_SHL);
          }
        } else if (opc === 0) {
          // SBFM: sign-extend from bit `imms` (or SBFX / ASR / SXTB/H/W)
          c.getReg(rn, false, !is64);
          if (imms >= immr) {
            // SBFX: shift left by (63 - imms), then arithmetic shift right by (63 - imms + immr)
            const shl = 63 - imms;
            const shr = shl + immr;
            if (shl > 0) {
              c.i64Const(BigInt(shl));
              c.op(OP.I64_SHL);
            }
            if (shr > 0) {
              c.i64Const(BigInt(shr));
              c.op(OP.I64_SHR_S);
            }
          } else {
            // SBFIZ
            const shl = 63 - imms;
            const shr = shl - (bits - immr);
            if (shl > 0) {
              c.i64Const(BigInt(shl));
              c.op(OP.I64_SHL);
            }
            if (shr > 0) {
              c.i64Const(BigInt(shr));
              c.op(OP.I64_SHR_S);
            }
          }
        } else {
          // BFM (opc === 1): insert bitfield into dst
          const dstWidth = imms >= immr ? imms - immr + 1 : imms + 1;
          const fieldMask = dstWidth >= 64 ? -1n : (1n << BigInt(dstWidth)) - 1n;
          const dstPos = imms >= immr ? 0 : bits - immr;
          const clearMask = ~(fieldMask << BigInt(dstPos));
          c.getReg(rd, false, !is64);
          c.i64Const(clearMask);
          c.op(OP.I64_AND);
          c.getReg(rn, false, !is64);
          if (imms >= immr && immr > 0) {
            c.i64Const(BigInt(immr));
            c.op(OP.I64_SHR_U);
          }
          c.i64Const(fieldMask);
          c.op(OP.I64_AND);
          if (dstPos > 0) {
            c.i64Const(BigInt(dstPos));
            c.op(OP.I64_SHL);
          }
          c.op(OP.I64_OR);
        }
        c.endSetReg(rd, false, !is64);
      }
      pc = nextPC;
      continue;
    }

    // 13. ADD / ADDS / SUB / SUBS (immediate)
    if (((insn & 0x1f800000) >>> 0) === 0x11000000) {
      const is64 = (insn >>> 31) === 1;
      const isSub = ((insn >>> 30) & 1) === 1;
      const setFlags = ((insn >>> 29) & 1) === 1;
      const sh = ((insn >>> 22) & 1) === 1;
      const imm12 = (insn >>> 10) & 0xfff;
      const imm = BigInt(sh ? imm12 << 12 : imm12);
      const rn = (insn >>> 5) & 0x1f;
      const rd = insn & 0x1f;
      const rdIsSp = !setFlags;
      c.getReg(rn, true, !is64);
      c.localSet(0);
      c.i64Const(imm);
      c.localSet(1);
      emitAddSub(c, is64, isSub, setFlags, rd, rdIsSp);
      pc = nextPC;
      continue;
    }

    // 14. ADD / ADDS / SUB / SUBS (shifted register)
    if (((insn & 0x1f200000) >>> 0) === 0x0b000000) {
      const is64 = (insn >>> 31) === 1;
      const isSub = ((insn >>> 30) & 1) === 1;
      const setFlags = ((insn >>> 29) & 1) === 1;
      const shiftType = (insn >>> 22) & 0x3;
      const rm = (insn >>> 16) & 0x1f;
      const imm6 = (insn >>> 10) & 0x3f;
      const rn = (insn >>> 5) & 0x1f;
      const rd = insn & 0x1f;
      c.getReg(rn, false, !is64);
      c.localSet(0);
      c.getReg(rm, false, !is64);
      emitShift(c, shiftType, imm6, is64);
      c.localSet(1);
      emitAddSub(c, is64, isSub, setFlags, rd, false);
      pc = nextPC;
      continue;
    }

    // 15. ADD / ADDS / SUB / SUBS (extended register)
    if (((insn & 0x1f200000) >>> 0) === 0x0b200000) {
      const is64 = (insn >>> 31) === 1;
      const isSub = ((insn >>> 30) & 1) === 1;
      const setFlags = ((insn >>> 29) & 1) === 1;
      const rm = (insn >>> 16) & 0x1f;
      const option = (insn >>> 13) & 0x7;
      const imm3 = (insn >>> 10) & 0x7;
      const rn = (insn >>> 5) & 0x1f;
      const rd = insn & 0x1f;
      const rdIsSp = !setFlags;
      c.getReg(rn, true, !is64);
      c.localSet(0);
      c.getReg(rm, false, false);
      emitExtend(c, option);
      if (imm3 > 0) {
        c.i64Const(BigInt(imm3));
        c.op(OP.I64_SHL);
      }
      if (!is64) {
        c.i64Const(0xffffffffn);
        c.op(OP.I64_AND);
      }
      c.localSet(1);
      emitAddSub(c, is64, isSub, setFlags, rd, rdIsSp);
      pc = nextPC;
      continue;
    }

    // 16. Logical (shifted register)
    if (((insn & 0x1f000000) >>> 0) === 0x0a000000) {
      const is64 = (insn >>> 31) === 1;
      const opc = (insn >>> 29) & 0x3;
      const shiftType = (insn >>> 22) & 0x3;
      const invert = ((insn >>> 21) & 1) === 1;
      const rm = (insn >>> 16) & 0x1f;
      const imm6 = (insn >>> 10) & 0x3f;
      const rn = (insn >>> 5) & 0x1f;
      const rd = insn & 0x1f;
      c.getReg(rn, false, !is64);
      c.getReg(rm, false, !is64);
      emitShift(c, shiftType, imm6, is64);
      if (invert) {
        c.i64Const(-1n);
        c.op(OP.I64_XOR);
      }
      if (opc === 0 || opc === 3) c.op(OP.I64_AND);
      else if (opc === 1) c.op(OP.I64_OR);
      else if (opc === 2) c.op(OP.I64_XOR);
      if (!is64) {
        c.i64Const(0xffffffffn);
        c.op(OP.I64_AND);
      }
      c.localTee(2);
      if (rd !== 31) {
        c.i32Const(OFF_X(rd));
        c.localGet(2);
        c.storeI64(0, 3);
      }
      c.op(OP.DROP);
      if (opc === 3) emitLogicalFlags(c, is64);
      pc = nextPC;
      continue;
    }

    // 17. Conditional Select: CSEL, CSINC, CSINV, CSNEG
    if (((insn & 0x1fe00800) >>> 0) === 0x1a800000) {
      const is64 = (insn >>> 31) === 1;
      const isInv = ((insn >>> 30) & 1) === 1;
      const rm = (insn >>> 16) & 0x1f;
      const cond = (insn >>> 12) & 0xf;
      const isInc = ((insn >>> 10) & 1) === 1;
      const rn = (insn >>> 5) & 0x1f;
      const rd = insn & 0x1f;
      if (c.beginSetReg(rd, false)) {
        c.emitCond(cond);
        c.op(OP.IF, VALTYPE.I64);
        c.getReg(rn, false, !is64);
        c.op(OP.ELSE);
        c.getReg(rm, false, !is64);
        if (isInv) {
          c.i64Const(-1n);
          c.op(OP.I64_XOR);
        }
        if (isInc) {
          c.i64Const(1n);
          c.op(OP.I64_ADD);
        }
        c.op(OP.END);
        c.endSetReg(rd, false, !is64);
      }
      pc = nextPC;
      continue;
    }

    // 18. Data-processing (2-source): UDIV, SDIV, LSLV, LSRV, ASRV, RORV
    if (((insn & 0x5fe00000) >>> 0) === 0x1ac00000) {
      const is64 = (insn >>> 31) === 1;
      const rm = (insn >>> 16) & 0x1f;
      const opcode = (insn >>> 10) & 0x3f;
      const rn = (insn >>> 5) & 0x1f;
      const rd = insn & 0x1f;
      if (c.beginSetReg(rd, false)) {
        if (opcode === 0x02 || opcode === 0x03) {
          // UDIV (2) / SDIV (3) — ARMv8 returns 0 on divide-by-zero
          c.getReg(rm, false, !is64);
          c.localTee(1);
          c.op(OP.I64_EQZ, OP.IF, VALTYPE.I64);
          c.i64Const(0n);
          c.op(OP.ELSE);
          c.getReg(rn, false, !is64);
          if (opcode === 0x03 && !is64) {
            c.op(OP.I32_WRAP_I64, OP.I64_EXTEND_I32_S);
            c.localGet(1);
            c.op(OP.I32_WRAP_I64, OP.I64_EXTEND_I32_S);
          } else {
            c.localGet(1);
          }
          c.op(opcode === 0x02 ? OP.I64_DIV_U : OP.I64_DIV_S);
          c.op(OP.END);
        } else {
          // Shifts: 0x08=LSLV, 0x09=LSRV, 0x0a=ASRV, 0x0b=RORV
          c.getReg(rn, false, !is64);
          if (opcode === 0x0a && !is64) {
            c.op(OP.I32_WRAP_I64, OP.I64_EXTEND_I32_S);
          }
          c.getReg(rm, false, false);
          c.i64Const(is64 ? 63n : 31n);
          c.op(OP.I64_AND);
          if (opcode === 0x08) c.op(OP.I64_SHL);
          else if (opcode === 0x09) c.op(OP.I64_SHR_U);
          else if (opcode === 0x0a) c.op(OP.I64_SHR_S);
          else if (opcode === 0x0b) c.op(OP.I64_ROTR);
        }
        c.endSetReg(rd, false, !is64);
      }
      pc = nextPC;
      continue;
    }

    // 19. MADD / MSUB (MUL)
    if (((insn & 0x7fe00000) >>> 0) === 0x1b000000) {
      const is64 = (insn >>> 31) === 1;
      const isSub = ((insn >>> 15) & 1) === 1;
      const rm = (insn >>> 16) & 0x1f;
      const ra = (insn >>> 10) & 0x1f;
      const rn = (insn >>> 5) & 0x1f;
      const rd = insn & 0x1f;
      if (c.beginSetReg(rd, false)) {
        c.getReg(ra, false, !is64);
        c.getReg(rn, false, !is64);
        c.getReg(rm, false, !is64);
        c.op(OP.I64_MUL);
        c.op(isSub ? OP.I64_SUB : OP.I64_ADD);
        c.endSetReg(rd, false, !is64);
      }
      pc = nextPC;
      continue;
    }

    // 39. System registers (DCZID_EL0, CTR_EL0, CNTFRQ_EL0, CNTVCT_EL0, FPCR/FPSR), PRFM prefetch, & cache ops
    if (((insn & 0xffffffe0) >>> 0) === 0xd53b00e0) {
      // MRS Xt, DCZID_EL0 -> return 0x10 (DZP=1: disable DC ZVA, use STP Q loop in musl memset!)
      const rt = insn & 0x1f;
      if (c.beginSetReg(rt, false)) { c.i64Const(0x10n); c.endSetReg(rt, false, false); }
      pc = nextPC;
      continue;
    }
    if (((insn & 0xffffffe0) >>> 0) === 0xd53b0020) {
      // MRS Xt, CTR_EL0 (64-byte cache lines)
      const rt = insn & 0x1f;
      if (c.beginSetReg(rt, false)) { c.i64Const(0x84448004n); c.endSetReg(rt, false, false); }
      pc = nextPC;
      continue;
    }
    if (((insn & 0xffffffe0) >>> 0) === 0xd53be000) {
      // MRS Xt, CNTFRQ_EL0 (24 MHz)
      const rt = insn & 0x1f;
      if (c.beginSetReg(rt, false)) { c.i64Const(24000000n); c.endSetReg(rt, false, false); }
      pc = nextPC;
      continue;
    }
    if (
      ((insn & 0xffffffe0) >>> 0) === 0xd53be040 || // CNTVCT_EL0
      ((insn & 0xffffffe0) >>> 0) === 0xd53b4400 || // FPCR
      ((insn & 0xffffffe0) >>> 0) === 0xd53b4420    // FPSR
    ) {
      const rt = insn & 0x1f;
      if (c.beginSetReg(rt, false)) { c.i64Const(0n); c.endSetReg(rt, false, false); }
      pc = nextPC;
      continue;
    }
    if (
      ((insn & 0xffffffe0) >>> 0) === 0xd51b4400 || // MSR FPCR
      ((insn & 0xffffffe0) >>> 0) === 0xd51b4420 || // MSR FPSR
      ((insn & 0xffff8000) >>> 0) === 0xd50b0000 || // DC/IC cache maintenance (NOP)
      ((insn & 0xffc00000) >>> 0) === 0xf9800000 || // PRFM unsigned imm
      ((insn & 0xff000000) >>> 0) === 0xd8000000 || // PRFM literal
      ((insn & 0xffe00c00) >>> 0) === 0xf8800000 || // PRFM unscaled
      ((insn & 0xffe00c00) >>> 0) === 0xf8a00800    // PRFM reg
    ) {
      pc = nextPC;
      continue;
    }

    // 40. Load-Acquire (LDAR/LDARB/LDARH) & Store-Release (STLR/STLRB/STLRH) — used by musl mallocng
    if (((insn & 0x3ffffc00) >>> 0) === 0x08dffc00 || ((insn & 0x3ffffc00) >>> 0) === 0x089ffc00) {
      const size = (insn >>> 30) & 0x3;
      const isLoad = ((insn >>> 22) & 1) === 1;
      const rn = (insn >>> 5) & 0x1f;
      const rt = insn & 0x1f;
      c.getReg(rn, true, false);
      c.op(OP.I32_WRAP_I64);
      c.localSet(3);
      emitLoadStoreAtLocal3(c, size, isLoad ? 1 : 0, rt);
      pc = nextPC;
      continue;
    }


    // 20. Load/Store Exclusive (LDXR/LDAXR/STXR/STLXR) for musl atomics
    if (((insn & 0x3f200000) >>> 0) === 0x08000000) {
      const size = (insn >>> 30) & 0x3;
      const isLoad = ((insn >>> 22) & 1) === 1;
      const rs = (insn >>> 16) & 0x1f;
      const rn = (insn >>> 5) & 0x1f;
      const rt = insn & 0x1f;
      c.getReg(rn, true, false);
      c.op(OP.I32_WRAP_I64);
      c.localSet(3);
      if (isLoad) {
        emitLoadStoreAtLocal3(c, size, 1, rt);
      } else {
        emitLoadStoreAtLocal3(c, size, 0, rt);
        // Cooperative single-thread: exclusive store always succeeds (Ws = 0)
        if (c.beginSetReg(rs, false)) {
          c.i64Const(0n);
          c.endSetReg(rs, false, true);
        }
      }
      pc = nextPC;
      continue;
    }

    // 21. Load/Store unsigned immediate
    if (((insn & 0x3f000000) >>> 0) === 0x39000000) {
      const size = (insn >>> 30) & 0x3;
      const opc = (insn >>> 22) & 0x3;
      const imm12 = (insn >>> 10) & 0xfff;
      const rn = (insn >>> 5) & 0x1f;
      const rt = insn & 0x1f;
      emitLoadStore(c, size, opc, rn, rt, imm12 << size);
      pc = nextPC;
      continue;
    }

    // 22. Load/Store unscaled (LDUR/STUR), post-index, and pre-index
    if (
      ((insn & 0x3f200c00) >>> 0) === 0x38000000 ||
      ((insn & 0x3f200c00) >>> 0) === 0x38000400 ||
      ((insn & 0x3f200c00) >>> 0) === 0x38000c00
    ) {
      const size = (insn >>> 30) & 0x3;
      const opc = (insn >>> 22) & 0x3;
      const mode = (insn >>> 10) & 0x3; // 0=unscaled, 1=post-index, 3=pre-index
      const imm9 = signExtend((insn >>> 12) & 0x1ff, 9);
      const rn = (insn >>> 5) & 0x1f;
      const rt = insn & 0x1f;

      c.getReg(rn, true, false);
      if (mode === 0 || mode === 3) {
        c.i64Const(BigInt(imm9));
        c.op(OP.I64_ADD);
      }
      c.op(OP.I32_WRAP_I64);
      c.localSet(3);
      emitLoadStoreAtLocal3(c, size, opc, rt);

      if (mode === 1 || mode === 3) {
        if (c.beginSetReg(rn, true)) {
          c.getReg(rn, true, false);
          c.i64Const(BigInt(imm9));
          c.op(OP.I64_ADD);
          c.endSetReg(rn, true, false);
        }
      }
      pc = nextPC;
      continue;
    }

    // 23. Load/Store register offset
    if (((insn & 0x3f200c00) >>> 0) === 0x38200800) {
      const size = (insn >>> 30) & 0x3;
      const opc = (insn >>> 22) & 0x3;
      const rm = (insn >>> 16) & 0x1f;
      const option = (insn >>> 13) & 0x7;
      const sBit = ((insn >>> 12) & 1) === 1;
      const rn = (insn >>> 5) & 0x1f;
      const rt = insn & 0x1f;
      c.getReg(rn, true, false);
      c.getReg(rm, false, false);
      emitExtend(c, option);
      if (sBit && size > 0) {
        c.i64Const(BigInt(size));
        c.op(OP.I64_SHL);
      }
      c.op(OP.I64_ADD, OP.I32_WRAP_I64);
      c.localSet(3);
      emitLoadStoreAtLocal3(c, size, opc, rt);
      pc = nextPC;
      continue;
    }

    // 24. LDP / STP
    if (
      ((insn & 0x7e400000) >>> 0) === 0x28000000 ||
      ((insn & 0x7e400000) >>> 0) === 0x28400000
    ) {
      const is64 = (insn >>> 31) === 1;
      const mode = (insn >>> 23) & 0x3;
      const isLoad = ((insn >>> 22) & 1) === 1;
      const imm7 = signExtend((insn >>> 15) & 0x7f, 7);
      const rt2 = (insn >>> 10) & 0x1f;
      const rn = (insn >>> 5) & 0x1f;
      const rt = insn & 0x1f;
      const scale = is64 ? 8 : 4;
      const offset = imm7 * scale;

      c.getReg(rn, true, false);
      if (mode === 0 || mode === 2 || mode === 3) {
        c.i64Const(BigInt(offset));
        c.op(OP.I64_ADD);
      }
      c.op(OP.I32_WRAP_I64);
      c.localSet(3);

      if (isLoad) {
        if (c.beginSetReg(rt, false)) {
          c.localGet(3);
          if (is64) c.loadI64(0, 3);
          else { c.loadI32(0, 2); c.op(OP.I64_EXTEND_I32_U); }
          c.endSetReg(rt, false, !is64);
        }
        if (c.beginSetReg(rt2, false)) {
          c.localGet(3);
          if (is64) c.loadI64(scale, 3);
          else { c.loadI32(scale, 2); c.op(OP.I64_EXTEND_I32_U); }
          c.endSetReg(rt2, false, !is64);
        }
      } else {
        c.localGet(3);
        c.getReg(rt, false, !is64);
        if (is64) c.storeI64(0, 3);
        else { c.op(OP.I32_WRAP_I64); c.storeI32(0, 2); }
        c.localGet(3);
        c.getReg(rt2, false, !is64);
        if (is64) c.storeI64(scale, 3);
        else { c.op(OP.I32_WRAP_I64); c.storeI32(scale, 2); }
      }

      if (mode === 1 || mode === 3) {
        if (c.beginSetReg(rn, true)) {
          c.getReg(rn, true, false);
          c.i64Const(BigInt(offset));
          c.op(OP.I64_ADD);
          c.endSetReg(rn, true, false);
        }
      }
      pc = nextPC;
      continue;
    }


    // 25. LDR (literal) 32-bit / 64-bit / LDRSW (PC-relative constant pool)
    if (((insn & 0x3f000000) >>> 0) === 0x18000000) {
      const opc = (insn >>> 30) & 0x3; // 0=32u, 1=64, 2=32s
      const imm19 = signExtend((insn >>> 5) & 0x7ffff, 19);
      const rt = insn & 0x1f;
      const addr = (pc + (imm19 << 2)) >>> 0;
      if (c.beginSetReg(rt, false)) {
        c.i32Const(addr);
        if (opc === 0) c.op(OP.I64_LOAD32_U, 2, 0);
        else if (opc === 1) c.loadI64(0, 3);
        else c.op(OP.I64_LOAD32_S, 2, 0);
        c.endSetReg(rt, false, opc === 0);
      }
      pc = nextPC;
      continue;
    }

    // 26. UMULH (0x9BC07C00) — GCC uses this for constant division (printf/itoa)
    if (((insn & 0xffe0fc00) >>> 0) === 0x9bc07c00) {
      const rm = (insn >>> 16) & 0x1f;
      const rn = (insn >>> 5) & 0x1f;
      const rd = insn & 0x1f;
      if (c.beginSetReg(rd, false)) {
        // local 0 = a, local 1 = b, local 2 = p01, local 4 = p10, local 5 = mid
        c.getReg(rn, false, false); c.localSet(0);
        c.getReg(rm, false, false); c.localSet(1);

        // p01 = (a & 0xffffffff) * (b >>> 32)
        c.localGet(0); c.i64Const(0xffffffffn); c.op(OP.I64_AND);
        c.localGet(1); c.i64Const(32n); c.op(OP.I64_SHR_U);
        c.op(OP.I64_MUL); c.localSet(2);

        // p10 = (a >>> 32) * (b & 0xffffffff)
        c.localGet(0); c.i64Const(32n); c.op(OP.I64_SHR_U);
        c.localGet(1); c.i64Const(0xffffffffn); c.op(OP.I64_AND);
        c.op(OP.I64_MUL); c.localSet(4);

        // mid = (((a & 0xffffffff) * (b & 0xffffffff)) >>> 32) + (p01 & 0xffffffff) + (p10 & 0xffffffff)
        c.localGet(0); c.i64Const(0xffffffffn); c.op(OP.I64_AND);
        c.localGet(1); c.i64Const(0xffffffffn); c.op(OP.I64_AND);
        c.op(OP.I64_MUL); c.i64Const(32n); c.op(OP.I64_SHR_U);
        c.localGet(2); c.i64Const(0xffffffffn); c.op(OP.I64_AND); c.op(OP.I64_ADD);
        c.localGet(4); c.i64Const(0xffffffffn); c.op(OP.I64_AND); c.op(OP.I64_ADD);
        c.localSet(5);

        // hi = (a >>> 32)*(b >>> 32) + (p01 >>> 32) + (p10 >>> 32) + (mid >>> 32)
        c.localGet(0); c.i64Const(32n); c.op(OP.I64_SHR_U);
        c.localGet(1); c.i64Const(32n); c.op(OP.I64_SHR_U);
        c.op(OP.I64_MUL);
        c.localGet(2); c.i64Const(32n); c.op(OP.I64_SHR_U); c.op(OP.I64_ADD);
        c.localGet(4); c.i64Const(32n); c.op(OP.I64_SHR_U); c.op(OP.I64_ADD);
        c.localGet(5); c.i64Const(32n); c.op(OP.I64_SHR_U); c.op(OP.I64_ADD);
        c.endSetReg(rd, false, false);
      }
      pc = nextPC;
      continue;
    }

    // 27. Data-processing (1-source): RBIT (0), REV16 (1), REV32 (2), REV64 (3), CLZ (4), CLS (5)
    if (((insn & 0x5fe00000) >>> 0) === 0x5ac00000) {
      const is64 = (insn >>> 31) === 1;
      const opcode = (insn >>> 10) & 0x3f;
      const rn = (insn >>> 5) & 0x1f;
      const rd = insn & 0x1f;
      if (c.beginSetReg(rd, false)) {
        if (opcode === 0) {
          // RBIT (exact 32-bit / 64-bit bit reversal — used by musl a_ctz_32 / a_ctz_64!)
          c.getReg(rn, false, !is64);
          c.localSet(0);
          const steps: [bigint, bigint][] = is64
            ? [
                [0x5555555555555555n, 1n],
                [0x3333333333333333n, 2n],
                [0x0f0f0f0f0f0f0f0fn, 4n],
                [0x00ff00ff00ff00ffn, 8n],
                [0x0000ffff0000ffffn, 16n],
                [0x00000000ffffffffn, 32n],
              ]
            : [
                [0x55555555n, 1n],
                [0x33333333n, 2n],
                [0x0f0f0f0fn, 4n],
                [0x00ff00ffn, 8n],
                [0x0000ffffn, 16n],
              ];
          for (const [mask, sh] of steps) {
            // x = ((x >>> sh) & mask) | ((x & mask) << sh)
            c.localGet(0); c.i64Const(sh); c.op(OP.I64_SHR_U); c.i64Const(mask); c.op(OP.I64_AND);
            c.localGet(0); c.i64Const(mask); c.op(OP.I64_AND); c.i64Const(sh); c.op(OP.I64_SHL);
            c.op(OP.I64_OR);
            c.localSet(0);
          }
          c.localGet(0);
        } else if (opcode === 1) {
          // REV16: swap bytes inside each 16-bit halfword
          c.getReg(rn, false, !is64);
          c.localSet(0);
          const m = is64 ? 0x00ff00ff00ff00ffn : 0x00ff00ffn;
          c.localGet(0); c.i64Const(8n); c.op(OP.I64_SHR_U); c.i64Const(m); c.op(OP.I64_AND);
          c.localGet(0); c.i64Const(m); c.op(OP.I64_AND); c.i64Const(8n); c.op(OP.I64_SHL);
          c.op(OP.I64_OR);
        } else if (opcode === 4) {
          // CLZ
          c.getReg(rn, false, !is64);
          if (is64) {
            c.op(OP.I64_CLZ);
          } else {
            c.op(OP.I32_WRAP_I64, OP.I32_CLZ, OP.I64_EXTEND_I32_U);
          }
        } else if (opcode === 5) {
          // CLS: count leading sign bits (excluding sign bit itself)
          c.getReg(rn, false, !is64);
          c.localSet(0);
          if (is64) {
            c.localGet(0);
            c.localGet(0); c.i64Const(63n); c.op(OP.I64_SHR_S);
            c.op(OP.I64_XOR, OP.I64_CLZ);
            c.i64Const(1n); c.op(OP.I64_SUB);
          } else {
            c.localGet(0); c.op(OP.I32_WRAP_I64);
            c.localGet(0); c.op(OP.I32_WRAP_I64); c.i32Const(31); c.op(OP.I32_SHR_S);
            c.op(OP.I32_XOR, OP.I32_CLZ);
            c.i32Const(1); c.op(OP.I32_SUB, OP.I64_EXTEND_I32_U);
          }
        } else if (opcode === 3 || (opcode === 2 && !is64)) {
          // REV64 / 32-bit REV
          c.getReg(rn, false, !is64);
          c.localSet(0);
          const nBytes = is64 ? 8 : 4;
          c.i64Const(0n);
          for (let b = 0; b < nBytes; b++) {
            c.localGet(0);
            if (b > 0) { c.i64Const(BigInt(b * 8)); c.op(OP.I64_SHR_U); }
            c.i64Const(0xffn); c.op(OP.I64_AND);
            const dstShift = (nBytes - 1 - b) * 8;
            if (dstShift > 0) { c.i64Const(BigInt(dstShift)); c.op(OP.I64_SHL); }
            c.op(OP.I64_OR);
          }
        } else if (opcode === 2 && is64) {
          // REV32 on 64-bit register: reverse bytes within each 32-bit word
          c.getReg(rn, false, false);
          c.localSet(0);
          c.i64Const(0n);
          for (let w = 0; w < 2; w++) {
            for (let b = 0; b < 4; b++) {
              const srcBit = w * 32 + b * 8;
              const dstBit = w * 32 + (3 - b) * 8;
              c.localGet(0);
              if (srcBit > 0) { c.i64Const(BigInt(srcBit)); c.op(OP.I64_SHR_U); }
              c.i64Const(0xffn); c.op(OP.I64_AND);
              if (dstBit > 0) { c.i64Const(BigInt(dstBit)); c.op(OP.I64_SHL); }
              c.op(OP.I64_OR);
            }
          }
        } else {
          c.getReg(rn, false, !is64);
        }
        c.endSetReg(rd, false, !is64);
      }
      pc = nextPC;
      continue;
    }

    // 28. CCMP / CCMN (register & immediate)
    if (((insn & 0x1fe00410) >>> 0) === 0x1a400000) {
      const is64 = (insn >>> 31) === 1;
      const isSub = ((insn >>> 30) & 1) === 1; // 1=CCMP (SUB), 0=CCMN (ADD)
      const isImm = ((insn >>> 11) & 1) === 1;
      const rmOrImm5 = (insn >>> 16) & 0x1f;
      const cond = (insn >>> 12) & 0xf;
      const rn = (insn >>> 5) & 0x1f;
      const nzcv = insn & 0xf;

      c.emitCond(cond);
      c.op(OP.IF, VALTYPE.VOID);
      c.getReg(rn, false, !is64); c.localSet(0);
      if (isImm) c.i64Const(BigInt(rmOrImm5));
      else c.getReg(rmOrImm5, false, !is64);
      c.localSet(1);
      emitAddSub(c, is64, isSub, true, 31, false);
      c.op(OP.ELSE);
      c.i32Const(OFF_N); c.i32Const((nzcv >>> 3) & 1); c.storeI32(0, 2);
      c.i32Const(OFF_Z); c.i32Const((nzcv >>> 2) & 1); c.storeI32(0, 2);
      c.i32Const(OFF_C); c.i32Const((nzcv >>> 1) & 1); c.storeI32(0, 2);
      c.i32Const(OFF_V); c.i32Const(nzcv & 1); c.storeI32(0, 2);
      c.op(OP.END);
      pc = nextPC;
      continue;
    }

    // 29. EXTR (extract register / ROR immediate)
    if (((insn & 0x1f800000) >>> 0) === 0x13800000) {
      const is64 = (insn >>> 31) === 1;
      const rm = (insn >>> 16) & 0x1f;
      const imms = (insn >>> 10) & 0x3f;
      const rn = (insn >>> 5) & 0x1f;
      const rd = insn & 0x1f;
      const bits = is64 ? 64 : 32;
      if (c.beginSetReg(rd, false)) {
        if (imms === 0) {
          c.getReg(rm, false, !is64);
        } else {
          c.getReg(rm, false, !is64);
          c.i64Const(BigInt(imms));
          c.op(OP.I64_SHR_U);
          c.getReg(rn, false, !is64);
          c.i64Const(BigInt(bits - imms));
          c.op(OP.I64_SHL);
          c.op(OP.I64_OR);
        }
        c.endSetReg(rd, false, !is64);
      }
      pc = nextPC;
      continue;
    }

    // 30. 128-bit SIMD LDP/STP Q-registers (used by musl memcpy/memset!)
    // opc=2 (10), V=1 (bit 26): (insn & 0xFE400000) === 0xAC000000 (STP Q) / 0xAC400000 (LDP Q)
    if (
      ((insn & 0xfe400000) >>> 0) === 0xac000000 ||
      ((insn & 0xfe400000) >>> 0) === 0xac400000 ||
      ((insn & 0xfe400000) >>> 0) === 0xad000000 ||
      ((insn & 0xfe400000) >>> 0) === 0xad400000 ||
      ((insn & 0xfe400000) >>> 0) === 0xad800000 ||
      ((insn & 0xfe400000) >>> 0) === 0xadc00000
    ) {
      const mode = (insn >>> 23) & 0x3; // 1=post, 2=signed-off, 3=pre
      const isLoad = ((insn >>> 22) & 1) === 1;
      const imm7 = signExtend((insn >>> 15) & 0x7f, 7);
      const qt2 = (insn >>> 10) & 0x1f;
      const rn = (insn >>> 5) & 0x1f;
      const qt = insn & 0x1f;
      const offset = imm7 * 16;

      c.getReg(rn, true, false);
      if (mode === 0 || mode === 2 || mode === 3) {
        c.i64Const(BigInt(offset));
        c.op(OP.I64_ADD);
      }
      c.op(OP.I32_WRAP_I64);
      c.localSet(3);

      if (isLoad) {
        // Load qt (lo, hi) and qt2 (lo, hi)
        c.i32Const(OFF_Q(qt)); c.localGet(3); c.loadI64(0, 3); c.storeI64(0, 3);
        c.i32Const(OFF_Q(qt) + 8); c.localGet(3); c.loadI64(8, 3); c.storeI64(0, 3);
        c.i32Const(OFF_Q(qt2)); c.localGet(3); c.loadI64(16, 3); c.storeI64(0, 3);
        c.i32Const(OFF_Q(qt2) + 8); c.localGet(3); c.loadI64(24, 3); c.storeI64(0, 3);
      } else {
        c.localGet(3); c.i32Const(OFF_Q(qt)); c.loadI64(0, 3); c.storeI64(0, 3);
        c.localGet(3); c.i32Const(OFF_Q(qt) + 8); c.loadI64(0, 3); c.storeI64(8, 3);
        c.localGet(3); c.i32Const(OFF_Q(qt2)); c.loadI64(0, 3); c.storeI64(16, 3);
        c.localGet(3); c.i32Const(OFF_Q(qt2) + 8); c.loadI64(0, 3); c.storeI64(24, 3);
      }

      if (mode === 1 || mode === 3) {
        if (c.beginSetReg(rn, true)) {
          c.getReg(rn, true, false);
          c.i64Const(BigInt(offset));
          c.op(OP.I64_ADD);
          c.endSetReg(rn, true, false);
        }
      }
      pc = nextPC;
      continue;
    }

    // 31. 128-bit SIMD LDR/STR Qt, [Xn, #uimm12*16] (unsigned offset)
    if (((insn & 0xff800000) >>> 0) === 0x3d800000 || ((insn & 0xff800000) >>> 0) === 0x3dc00000) {
      const isLoad = ((insn >>> 22) & 1) === 1;
      const imm12 = (insn >>> 10) & 0xfff;
      const rn = (insn >>> 5) & 0x1f;
      const qt = insn & 0x1f;
      c.getReg(rn, true, false);
      if (imm12 > 0) { c.i64Const(BigInt(imm12 * 16)); c.op(OP.I64_ADD); }
      c.op(OP.I32_WRAP_I64);
      c.localSet(3);
      if (isLoad) {
        c.i32Const(OFF_Q(qt)); c.localGet(3); c.loadI64(0, 3); c.storeI64(0, 3);
        c.i32Const(OFF_Q(qt) + 8); c.localGet(3); c.loadI64(8, 3); c.storeI64(0, 3);
      } else {
        c.localGet(3); c.i32Const(OFF_Q(qt)); c.loadI64(0, 3); c.storeI64(0, 3);
        c.localGet(3); c.i32Const(OFF_Q(qt) + 8); c.loadI64(0, 3); c.storeI64(8, 3);
      }
      pc = nextPC;
      continue;
    }


    // 32. SIMD MOVI (all lanes: 8B/16B, 4H/8H, 2S/4S, 2D — covers 0x4F00E400 & 0x4F00E440!)
    if (((insn & 0x9ff80c00) >>> 0) === 0x0f000400) {
      const isQ = (insn >>> 30) === 1;
      const opBit = (insn >>> 29) & 1;
      const abc = (insn >>> 16) & 0x7;
      const cmode = (insn >>> 12) & 0xf;
      const defgh = (insn >>> 5) & 0x1f;
      const imm8 = (abc << 5) | defgh;
      const vd = insn & 0x1f;

      let lane64 = 0n;
      if (cmode === 14 && opBit === 0) {
        // MOVI Vd.8B/16B, #imm8
        lane64 = BigInt(imm8) * 0x0101010101010101n;
      } else if (cmode === 14 && opBit === 1) {
        // MOVI Dd / Vd.2D, #imm64 (each bit expands to 0xFF or 0x00)
        for (let bit = 0; bit < 8; bit++) {
          if (((imm8 >>> bit) & 1) === 1) lane64 |= 0xffn << BigInt(bit * 8);
        }
      } else if ((cmode & 0x9) === 0 && opBit === 0) {
        // MOVI Vd.2S/4S, #imm8, LSL #(cmode * 4)
        const w32 = (BigInt(imm8) << BigInt((cmode >>> 1) * 8)) & 0xffffffffn;
        lane64 = w32 | (w32 << 32n);
      } else if ((cmode & 0xd) === 8 && opBit === 0) {
        // MOVI Vd.4H/8H, #imm8, LSL #((cmode - 8) * 4)
        const h16 = (BigInt(imm8) << BigInt(((cmode - 8) >>> 1) * 8)) & 0xffffn;
        lane64 = h16 * 0x0001000100010001n;
      }

      c.i32Const(OFF_Q(vd)); c.i64Const(lane64); c.storeI64(0, 3);
      c.i32Const(OFF_Q(vd) + 8); c.i64Const(isQ ? lane64 : 0n); c.storeI64(0, 3);
      pc = nextPC;
      continue;
    }

    // 32b. SIMD Bitwise AND (0x0E201C00), BIC (0x0E601C00), EOR (0x2E201C00) on 8B/16B
    if (
      ((insn & 0xbfe0fc00) >>> 0) === 0x0e201c00 ||
      ((insn & 0xbfe0fc00) >>> 0) === 0x0e601c00 ||
      ((insn & 0xbfe0fc00) >>> 0) === 0x2e201c00
    ) {
      const isQ = (insn >>> 30) === 1;
      const isEor = ((insn >>> 29) & 1) === 1;
      const isBic = !isEor && ((insn >>> 22) & 1) === 1;
      const rm = (insn >>> 16) & 0x1f;
      const rn = (insn >>> 5) & 0x1f;
      const vd = insn & 0x1f;

      const emitLane = (off: number): void => {
        c.i32Const(OFF_Q(vd) + off);
        c.i32Const(OFF_Q(rn) + off); c.loadI64(0, 3);
        c.i32Const(OFF_Q(rm) + off); c.loadI64(0, 3);
        if (isBic) { c.i64Const(-1n); c.op(OP.I64_XOR); c.op(OP.I64_AND); }
        else if (isEor) c.op(OP.I64_XOR);
        else c.op(OP.I64_AND);
        c.storeI64(0, 3);
      };
      emitLane(0);
      if (isQ) emitLane(8);
      else { c.i32Const(OFF_Q(vd) + 8); c.i64Const(0n); c.storeI64(0, 3); }
      pc = nextPC;
      continue;
    }

    // 32c. 64-bit FP/SIMD D-reg LDUR/STUR & pre/post-index (0xFC000000 / 0xFC400000)
    if (
      ((insn & 0xffa00c00) >>> 0) === 0xfc000000 ||
      ((insn & 0xffa00c00) >>> 0) === 0xfc000400 ||
      ((insn & 0xffa00c00) >>> 0) === 0xfc000c00
    ) {
      const isLoad = ((insn >>> 22) & 1) === 1;
      const mode = (insn >>> 10) & 0x3;
      const imm9 = signExtend((insn >>> 12) & 0x1ff, 9);
      const rn = (insn >>> 5) & 0x1f;
      const dt = insn & 0x1f;
      c.getReg(rn, true, false);
      if (mode === 0 || mode === 3) { c.i64Const(BigInt(imm9)); c.op(OP.I64_ADD); }
      c.op(OP.I32_WRAP_I64);
      c.localSet(3);
      if (isLoad) {
        c.i32Const(OFF_Q(dt)); c.localGet(3); c.loadI64(0, 3); c.storeI64(0, 3);
        c.i32Const(OFF_Q(dt) + 8); c.i64Const(0n); c.storeI64(0, 3);
      } else {
        c.localGet(3); c.i32Const(OFF_Q(dt)); c.loadI64(0, 3); c.storeI64(0, 3);
      }
      if (mode === 1 || mode === 3) {
        if (c.beginSetReg(rn, true)) {
          c.getReg(rn, true, false); c.i64Const(BigInt(imm9)); c.op(OP.I64_ADD); c.endSetReg(rn, true, false);
        }
      }
      pc = nextPC;
      continue;
    }

    // 33. 128-bit SIMD LDUR/STUR & pre/post-index LDR/STR Qt, [Xn, #simm9]
    if (
      ((insn & 0xffa00c00) >>> 0) === 0x3c800000 ||
      ((insn & 0xffa00c00) >>> 0) === 0x3c800400 ||
      ((insn & 0xffa00c00) >>> 0) === 0x3c800c00
    ) {
      const isLoad = ((insn >>> 22) & 1) === 1;
      const mode = (insn >>> 10) & 0x3; // 0=unscaled, 1=post, 3=pre
      const imm9 = signExtend((insn >>> 12) & 0x1ff, 9);
      const rn = (insn >>> 5) & 0x1f;
      const qt = insn & 0x1f;

      c.getReg(rn, true, false);
      if (mode === 0 || mode === 3) {
        c.i64Const(BigInt(imm9));
        c.op(OP.I64_ADD);
      }
      c.op(OP.I32_WRAP_I64);
      c.localSet(3);

      if (isLoad) {
        c.i32Const(OFF_Q(qt)); c.localGet(3); c.loadI64(0, 3); c.storeI64(0, 3);
        c.i32Const(OFF_Q(qt) + 8); c.localGet(3); c.loadI64(8, 3); c.storeI64(0, 3);
      } else {
        c.localGet(3); c.i32Const(OFF_Q(qt)); c.loadI64(0, 3); c.storeI64(0, 3);
        c.localGet(3); c.i32Const(OFF_Q(qt) + 8); c.loadI64(0, 3); c.storeI64(8, 3);
      }

      if (mode === 1 || mode === 3) {
        if (c.beginSetReg(rn, true)) {
          c.getReg(rn, true, false);
          c.i64Const(BigInt(imm9));
          c.op(OP.I64_ADD);
          c.endSetReg(rn, true, false);
        }
      }
      pc = nextPC;
      continue;
    }


    // 34. ADC / ADCS / SBC / SBCS
    if (((insn & 0x1fe0fc00) >>> 0) === 0x1a000000) {
      const is64 = (insn >>> 31) === 1;
      const isSub = ((insn >>> 30) & 1) === 1;
      const setFlags = ((insn >>> 29) & 1) === 1;
      const rm = (insn >>> 16) & 0x1f;
      const rn = (insn >>> 5) & 0x1f;
      const rd = insn & 0x1f;
      c.getReg(rn, false, !is64);
      c.localSet(0);
      // operand2 = rm + carry (for ADC) or rm + (1 - carry) (for SBC)
      c.getReg(rm, false, !is64);
      c.i32Const(OFF_C);
      c.loadI32(0, 2);
      if (isSub) { c.i32Const(1); c.op(OP.I32_XOR); }
      c.op(OP.I64_EXTEND_I32_U, OP.I64_ADD);
      c.localSet(1);
      emitAddSub(c, is64, isSub, setFlags, rd, false);
      pc = nextPC;
      continue;
    }

    // 35. SMADDL / SMSUBL / UMADDL / UMSUBL (32x32->64 multiply-add/sub)
    if (((insn & 0xff200000) >>> 0) === 0x9b200000) {
      const isUnsigned = ((insn >>> 23) & 1) === 1;
      const isSub = ((insn >>> 15) & 1) === 1;
      const rm = (insn >>> 16) & 0x1f;
      const ra = (insn >>> 10) & 0x1f;
      const rn = (insn >>> 5) & 0x1f;
      const rd = insn & 0x1f;
      if (c.beginSetReg(rd, false)) {
        c.getReg(ra, false, false);
        c.getReg(rn, false, true);
        if (!isUnsigned) c.op(OP.I32_WRAP_I64, OP.I64_EXTEND_I32_S);
        c.getReg(rm, false, true);
        if (!isUnsigned) c.op(OP.I32_WRAP_I64, OP.I64_EXTEND_I32_S);
        c.op(OP.I64_MUL);
        c.op(isSub ? OP.I64_SUB : OP.I64_ADD);
        c.endSetReg(rd, false, false);
      }
      pc = nextPC;
      continue;
    }

    // 36. 64-bit FP/SIMD D-reg LDR/STR unsigned offset (0xFD000000 / 0xFD400000)
    if (((insn & 0xff800000) >>> 0) === 0xfd000000 || ((insn & 0xff800000) >>> 0) === 0xfd400000) {
      const isLoad = ((insn >>> 22) & 1) === 1;
      const imm12 = (insn >>> 10) & 0xfff;
      const rn = (insn >>> 5) & 0x1f;
      const dt = insn & 0x1f;
      c.getReg(rn, true, false);
      if (imm12 > 0) { c.i64Const(BigInt(imm12 * 8)); c.op(OP.I64_ADD); }
      c.op(OP.I32_WRAP_I64);
      c.localSet(3);
      if (isLoad) {
        c.i32Const(OFF_Q(dt)); c.localGet(3); c.loadI64(0, 3); c.storeI64(0, 3);
      } else {
        c.localGet(3); c.i32Const(OFF_Q(dt)); c.loadI64(0, 3); c.storeI64(0, 3);
      }
      pc = nextPC;
      continue;
    }

    // 37. 64-bit FP/SIMD D-reg LDP/STP (opc=01, V=1: 0x6C000000..0x6DC00000)
    if (
      ((insn & 0xfe400000) >>> 0) === 0x6c000000 ||
      ((insn & 0xfe400000) >>> 0) === 0x6c400000 ||
      ((insn & 0xfe400000) >>> 0) === 0x6d000000 ||
      ((insn & 0xfe400000) >>> 0) === 0x6d400000 ||
      ((insn & 0xfe400000) >>> 0) === 0x6d800000 ||
      ((insn & 0xfe400000) >>> 0) === 0x6dc00000
    ) {
      const mode = (insn >>> 23) & 0x3;
      const isLoad = ((insn >>> 22) & 1) === 1;
      const imm7 = signExtend((insn >>> 15) & 0x7f, 7);
      const dt2 = (insn >>> 10) & 0x1f;
      const rn = (insn >>> 5) & 0x1f;
      const dt = insn & 0x1f;
      const offset = imm7 * 8;
      c.getReg(rn, true, false);
      if (mode === 0 || mode === 2 || mode === 3) { c.i64Const(BigInt(offset)); c.op(OP.I64_ADD); }
      c.op(OP.I32_WRAP_I64);
      c.localSet(3);
      if (isLoad) {
        c.i32Const(OFF_Q(dt)); c.localGet(3); c.loadI64(0, 3); c.storeI64(0, 3);
        c.i32Const(OFF_Q(dt2)); c.localGet(3); c.loadI64(8, 3); c.storeI64(0, 3);
      } else {
        c.localGet(3); c.i32Const(OFF_Q(dt)); c.loadI64(0, 3); c.storeI64(0, 3);
        c.localGet(3); c.i32Const(OFF_Q(dt2)); c.loadI64(0, 3); c.storeI64(8, 3);
      }
      if (mode === 1 || mode === 3) {
        if (c.beginSetReg(rn, true)) {
          c.getReg(rn, true, false); c.i64Const(BigInt(offset)); c.op(OP.I64_ADD); c.endSetReg(rn, true, false);
        }
      }
      pc = nextPC;
      continue;
    }


    // 38. SIMD DUP Vd.<T>, Rn (general) — e.g. 0x4E010C20 = DUP V0.16B, W1 (musl memset!)
    if (((insn & 0xbfe0fc00) >>> 0) === 0x0e000c00) {
      const isQ = (insn >>> 30) === 1;
      const imm5 = (insn >>> 16) & 0x1f;
      const rn = (insn >>> 5) & 0x1f;
      const vd = insn & 0x1f;
      // Replicate element across 64-bit lane in local 0
      c.getReg(rn, false, false);
      if ((imm5 & 1) === 1) {
        // 8-bit byte: (val & 0xFF) * 0x0101010101010101
        c.i64Const(0xffn); c.op(OP.I64_AND);
        c.i64Const(0x0101010101010101n); c.op(OP.I64_MUL);
      } else if ((imm5 & 2) === 2) {
        // 16-bit halfword
        c.i64Const(0xffffn); c.op(OP.I64_AND);
        c.i64Const(0x0001000100010001n); c.op(OP.I64_MUL);
      } else if ((imm5 & 4) === 4) {
        // 32-bit word
        c.i64Const(0xffffffffn); c.op(OP.I64_AND);
        c.i64Const(0x0000000100000001n); c.op(OP.I64_MUL);
      }
      c.localSet(0);
      c.i32Const(OFF_Q(vd)); c.localGet(0); c.storeI64(0, 3);
      c.i32Const(OFF_Q(vd) + 8);
      if (isQ) c.localGet(0);
      else c.i64Const(0n);
      c.storeI64(0, 3);
      pc = nextPC;
      continue;
    }


    // 41. SIMD UMOV Wd/Xd, Vn.<B/H/S/D>[idx] — e.g. 0x4E083C01 = UMOV X1, V0.D[0] (musl memset!)
    if (((insn & 0xbfe0fc00) >>> 0) === 0x0e003c00) {
      const is64 = (insn >>> 30) === 1;
      const imm5 = (insn >>> 16) & 0x1f;
      const rn = (insn >>> 5) & 0x1f;
      const rd = insn & 0x1f;
      if (c.beginSetReg(rd, false)) {
        let byteOff = 0;
        let width = 8;
        if ((imm5 & 1) === 1) { width = 1; byteOff = imm5 >>> 1; }
        else if ((imm5 & 3) === 2) { width = 2; byteOff = (imm5 >>> 2) * 2; }
        else if ((imm5 & 7) === 4) { width = 4; byteOff = (imm5 >>> 3) * 4; }
        else if ((imm5 & 15) === 8) { width = 8; byteOff = (imm5 >>> 4) * 8; }
        c.i32Const(OFF_Q(rn) + byteOff);
        if (width === 1) c.op(OP.I64_LOAD8_U, 0, 0);
        else if (width === 2) c.op(OP.I64_LOAD16_U, 1, 0);
        else if (width === 4) c.op(OP.I64_LOAD32_U, 2, 0);
        else c.loadI64(0, 3);
        c.endSetReg(rd, false, !is64);
      }
      pc = nextPC;
      continue;
    }

    // 42. SIMD INS Vd.<B/H/S/D>[idx], Rn
    if (((insn & 0xbfe0fc00) >>> 0) === 0x4e001c00) {
      const imm5 = (insn >>> 16) & 0x1f;
      const rn = (insn >>> 5) & 0x1f;
      const vd = insn & 0x1f;
      let byteOff = 0;
      let width = 8;
      if ((imm5 & 1) === 1) { width = 1; byteOff = imm5 >>> 1; }
      else if ((imm5 & 3) === 2) { width = 2; byteOff = (imm5 >>> 2) * 2; }
      else if ((imm5 & 7) === 4) { width = 4; byteOff = (imm5 >>> 3) * 4; }
      else if ((imm5 & 15) === 8) { width = 8; byteOff = (imm5 >>> 4) * 8; }
      c.i32Const(OFF_Q(vd) + byteOff);
      c.getReg(rn, false, width <= 4);
      if (width === 1) c.op(OP.I64_STORE8, 0, 0);
      else if (width === 2) c.op(OP.I64_STORE16, 1, 0);
      else if (width === 4) c.op(OP.I64_STORE32, 2, 0);
      else c.storeI64(0, 3);
      pc = nextPC;
      continue;
    }

    // 43. FMOV GP <-> FP/SIMD (32-bit S & 64-bit D)
    if (((insn & 0x7f3ffc00) >>> 0) === 0x1e260000) {
      // FMOV Wd, Sn (0x1e260000) / FMOV Xd, Dn (0x9e660000)
      const is64 = (insn >>> 31) === 1;
      const rn = (insn >>> 5) & 0x1f;
      const rd = insn & 0x1f;
      if (c.beginSetReg(rd, false)) {
        c.i32Const(OFF_Q(rn));
        if (is64) c.loadI64(0, 3);
        else c.op(OP.I64_LOAD32_U, 2, 0);
        c.endSetReg(rd, false, !is64);
      }
      pc = nextPC;
      continue;
    }
    if (((insn & 0x7f3ffc00) >>> 0) === 0x1e270000) {
      // FMOV Sd, Wn (0x1e270000) / FMOV Dd, Xn (0x9e670000)
      const is64 = (insn >>> 31) === 1;
      const rn = (insn >>> 5) & 0x1f;
      const rd = insn & 0x1f;
      c.i32Const(OFF_Q(rd));
      c.getReg(rn, false, !is64);
      c.storeI64(0, 3);
      c.i32Const(OFF_Q(rd) + 8);
      c.i64Const(0n);
      c.storeI64(0, 3);
      pc = nextPC;
      continue;
    }

    // 44. SIMD ORR Vd.16B/8B, Vn, Vm (includes MOV Vd.16B, Vn.16B)
    if (((insn & 0xbfe0fc00) >>> 0) === 0x0ea01c00) {
      const isQ = (insn >>> 30) === 1;
      const rm = (insn >>> 16) & 0x1f;
      const rn = (insn >>> 5) & 0x1f;
      const vd = insn & 0x1f;
      c.i32Const(OFF_Q(vd));
      c.i32Const(OFF_Q(rn)); c.loadI64(0, 3);
      c.i32Const(OFF_Q(rm)); c.loadI64(0, 3);
      c.op(OP.I64_OR);
      c.storeI64(0, 3);
      c.i32Const(OFF_Q(vd) + 8);
      if (isQ) {
        c.i32Const(OFF_Q(rn) + 8); c.loadI64(0, 3);
        c.i32Const(OFF_Q(rm) + 8); c.loadI64(0, 3);
        c.op(OP.I64_OR);
      } else {
        c.i64Const(0n);
      }
      c.storeI64(0, 3);
      pc = nextPC;
      continue;
    }

    // 45. FP/SIMD 32-bit S-reg LDR/STR unsigned offset (0xBD000000 / 0xBD400000)
    if (((insn & 0xff800000) >>> 0) === 0xbd000000 || ((insn & 0xff800000) >>> 0) === 0xbd400000) {
      const isLoad = ((insn >>> 22) & 1) === 1;
      const imm12 = (insn >>> 10) & 0xfff;
      const rn = (insn >>> 5) & 0x1f;
      const st = insn & 0x1f;
      c.getReg(rn, true, false);
      if (imm12 > 0) { c.i64Const(BigInt(imm12 * 4)); c.op(OP.I64_ADD); }
      c.op(OP.I32_WRAP_I64);
      c.localSet(3);
      if (isLoad) {
        c.i32Const(OFF_Q(st)); c.localGet(3); c.op(OP.I64_LOAD32_U, 2, 0); c.storeI64(0, 3);
        c.i32Const(OFF_Q(st) + 8); c.i64Const(0n); c.storeI64(0, 3);
      } else {
        c.localGet(3); c.i32Const(OFF_Q(st)); c.loadI32(0, 2); c.storeI32(0, 2);
      }
      pc = nextPC;
      continue;
    }
    // Unrecognized instruction -> fault
    c.setPC(pc);
    c.i32Const(STATUS.FAULT);
    c.op(OP.RETURN);
    terminated = true;
    break;
  }

  if (!terminated) {
    c.setPC(pc);
    c.i32Const(STATUS.CONTINUE);
    c.op(OP.RETURN);
  }

  mb.addFunction(tBlock, [[3, VALTYPE.I64], [1, VALTYPE.I32], [2, VALTYPE.I64]], c.b, 'bb');
  return new WebAssembly.Module(mb.toUint8Array() as BufferSource);
}

function emitExtend(c: CodeBuf, option: number): void {
  // 0=UXTB, 1=UXTH, 2=UXTW, 3=UXTX, 4=SXTB, 5=SXTH, 6=SXTW, 7=SXTX
  switch (option) {
    case 0: c.i64Const(0xffn); c.op(OP.I64_AND); break;
    case 1: c.i64Const(0xffffn); c.op(OP.I64_AND); break;
    case 2: c.i64Const(0xffffffffn); c.op(OP.I64_AND); break;
    case 4: c.i64Const(56n); c.op(OP.I64_SHL); c.i64Const(56n); c.op(OP.I64_SHR_S); break;
    case 5: c.i64Const(48n); c.op(OP.I64_SHL); c.i64Const(48n); c.op(OP.I64_SHR_S); break;
    case 6: c.op(OP.I32_WRAP_I64, OP.I64_EXTEND_I32_S); break;
    default: break;
  }
}

function emitShift(c: CodeBuf, shiftType: number, amount: number, is64: boolean): void {
  if (amount === 0) return;
  c.i64Const(BigInt(amount));
  if (shiftType === 0) c.op(OP.I64_SHL);
  else if (shiftType === 1) c.op(OP.I64_SHR_U);
  else if (shiftType === 2) {
    if (!is64) {
      c.op(OP.DROP);
      c.op(OP.I32_WRAP_I64, OP.I64_EXTEND_I32_S);
      c.i64Const(BigInt(amount));
    }
    c.op(OP.I64_SHR_S);
  } else if (shiftType === 3) {
    c.op(OP.I64_ROTR);
  }
  if (!is64) {
    c.i64Const(0xffffffffn);
    c.op(OP.I64_AND);
  }
}

function emitAddSub(c: CodeBuf, is64: boolean, isSub: boolean, setFlags: boolean, rd: number, rdIsSp: boolean): void {
  c.localGet(0);
  c.localGet(1);
  c.op(isSub ? OP.I64_SUB : OP.I64_ADD);
  if (!is64) {
    c.i64Const(0xffffffffn);
    c.op(OP.I64_AND);
  }
  c.localSet(2);

  if (c.beginSetReg(rd, rdIsSp)) {
    c.localGet(2);
    c.endSetReg(rd, rdIsSp, !is64);
  }

  if (setFlags) {
    const signShift = is64 ? 63n : 31n;
    c.i32Const(OFF_N);
    c.localGet(2);
    c.i64Const(signShift);
    c.op(OP.I64_SHR_U, OP.I32_WRAP_I64);
    c.i32Const(1);
    c.op(OP.I32_AND);
    c.storeI32(0, 2);

    c.i32Const(OFF_Z);
    c.localGet(2);
    c.op(OP.I64_EQZ);
    c.storeI32(0, 2);

    c.i32Const(OFF_C);
    if (isSub) {
      c.localGet(0);
      c.localGet(1);
      c.op(OP.I64_GE_U);
    } else {
      c.localGet(2);
      c.localGet(0);
      c.op(OP.I64_LT_U);
    }
    c.storeI32(0, 2);

    c.i32Const(OFF_V);
    c.localGet(0);
    c.localGet(1);
    c.op(OP.I64_XOR);
    if (!isSub) {
      c.i64Const(-1n);
      c.op(OP.I64_XOR);
    }
    c.localGet(0);
    c.localGet(2);
    c.op(OP.I64_XOR, OP.I64_AND);
    c.i64Const(signShift);
    c.op(OP.I64_SHR_U, OP.I32_WRAP_I64);
    c.i32Const(1);
    c.op(OP.I32_AND);
    c.storeI32(0, 2);
  }
}

function emitLogicalFlags(c: CodeBuf, is64: boolean): void {
  c.i32Const(OFF_N);
  c.localGet(2);
  c.i64Const(is64 ? 63n : 31n);
  c.op(OP.I64_SHR_U, OP.I32_WRAP_I64);
  c.i32Const(1);
  c.op(OP.I32_AND);
  c.storeI32(0, 2);

  c.i32Const(OFF_Z);
  c.localGet(2);
  c.op(OP.I64_EQZ);
  c.storeI32(0, 2);

  c.i32Const(OFF_C);
  c.i32Const(0);
  c.storeI32(0, 2);

  c.i32Const(OFF_V);
  c.i32Const(0);
  c.storeI32(0, 2);
}

function emitLoadStore(c: CodeBuf, size: number, opc: number, rn: number, rt: number, byteOff: number): void {
  c.getReg(rn, true, false);
  if (byteOff !== 0) {
    c.i64Const(BigInt(byteOff));
    c.op(OP.I64_ADD);
  }
  c.op(OP.I32_WRAP_I64);
  c.localSet(3);
  emitLoadStoreAtLocal3(c, size, opc, rt);
}

function emitLoadStoreAtLocal3(c: CodeBuf, size: number, opc: number, rt: number): void {
  if (opc === 0) {
    c.localGet(3);
    c.getReg(rt, false, false);
    if (size === 0) c.op(OP.I64_STORE8, 0, 0);
    else if (size === 1) c.op(OP.I64_STORE16, 1, 0);
    else if (size === 2) c.op(OP.I64_STORE32, 2, 0);
    else c.storeI64(0, 3);
  } else {
    const isSigned = opc === 2 || opc === 3;
    const is32Target = opc === 3 || (opc === 1 && size <= 2);
    if (c.beginSetReg(rt, false)) {
      c.localGet(3);
      if (size === 0) c.op(isSigned ? OP.I64_LOAD8_S : OP.I64_LOAD8_U, 0, 0);
      else if (size === 1) c.op(isSigned ? OP.I64_LOAD16_S : OP.I64_LOAD16_U, 1, 0);
      else if (size === 2) c.op(isSigned ? OP.I64_LOAD32_S : OP.I64_LOAD32_U, 2, 0);
      else c.loadI64(0, 3);
      c.endSetReg(rt, false, is32Target);
    }
  }
}

export class DBTEngine {
  dispatcherModule: WebAssembly.Module;
  moduleCache: Map<string, WebAssembly.Module>;

  constructor() {
    this.dispatcherModule = buildDispatcherModule(16, 1024);
    this.moduleCache = new Map();
  }

  getOrCompileBlock(memView: DataView, pc: number): WebAssembly.Module {
    // Hash first 2 instructions to avoid stale cache hits across execve() at same PC
    const w0 = memView.getUint32(pc, true);
    const w1 = pc + 4 < memView.byteLength ? memView.getUint32(pc + 4, true) : 0;
    const key = `${pc}:${w0}:${w1}`;
    let mod = this.moduleCache.get(key);
    if (!mod) {
      mod = translateBasicBlock(memView, pc);
      this.moduleCache.set(key, mod);
    }
    return mod;
  }
}

export type SyscallBridge = (cpu: GuestCPU) => number;

export class GuestCPU {
  engine: DBTEngine;
  syscallBridge: SyscallBridge;
  memory: WebAssembly.Memory;
  table: WebAssembly.Table;
  nextTableIdx: number;
  pcToTableIdx: Map<number, number>;
  compiledBlocks: number;
  dispatcherInstance: WebAssembly.Instance;
  runSliceWasm: (budget: number) => number;

  constructor(engine: DBTEngine, syscallBridge: SyscallBridge, initialPages = 64, maxPages = 4096) {
    this.engine = engine;
    this.syscallBridge = syscallBridge;
    this.memory = new WebAssembly.Memory({ initial: initialPages, maximum: maxPages });
    this.table = new WebAssembly.Table({ initial: 1024, maximum: 16384, element: 'anyfunc' });
    this.nextTableIdx = 1;
    this.pcToTableIdx = new Map();
    this.compiledBlocks = 0;

    this.dispatcherInstance = new WebAssembly.Instance(engine.dispatcherModule, {
      env: { mem: this.memory, tbl: this.table },
    });
    this.runSliceWasm = this.dispatcherInstance.exports.run_slice as (budget: number) => number;
  }

  private _cachedBuf: ArrayBuffer | null = null;
  private _cachedView: DataView | null = null;
  private _cachedU8: Uint8Array | null = null;

  private _refreshViews(): void {
    const buf = this.memory.buffer;
    if (this._cachedBuf !== buf) {
      this._cachedBuf = buf;
      this._cachedView = new DataView(buf);
      this._cachedU8 = new Uint8Array(buf);
    }
  }

  get view(): DataView {
    this._refreshViews();
    return this._cachedView!;
  }

  get u8(): Uint8Array {
    this._refreshViews();
    return this._cachedU8!;
  }

  getReg(r: number): bigint {
    const off = r === 31 ? OFF_SP : OFF_X(r);
    return this.view.getBigUint64(off, true);
  }

  setReg(r: number, val: number | bigint): void {
    const off = r === 31 ? OFF_SP : OFF_X(r);
    this.view.setBigUint64(off, BigInt.asUintN(64, BigInt(val)), true);
  }

  getPC(): number {
    return Number(this.view.getBigUint64(OFF_PC, true));
  }

  setPC(pc: number): void {
    this.view.setBigUint64(OFF_PC, BigInt(pc >>> 0), true);
  }

  ensureMemory(byteSize: number): boolean {
    const cur = this.memory.buffer.byteLength;
    if (byteSize <= cur) return true;
    const neededPages = Math.ceil((byteSize - cur) / 65536);
    this.memory.grow(neededPages);
    return true;
  }

  // Flush CPU state, I-Cache, and block table when execve() replaces the process image
  resetForExec(): void {
    this.u8.fill(0, 0, ICACHE_BASE + ICACHE_ENTRIES * 8);
    this.pcToTableIdx.clear();
    this.nextTableIdx = 1;
  }

  ensureBlock(pc: number): number {
    pc = pc >>> 0;
    let idx = this.pcToTableIdx.get(pc);
    if (idx === undefined) {
      const mod = this.engine.getOrCompileBlock(this.view, pc);
      const inst = new WebAssembly.Instance(mod, {
        env: {
          mem: this.memory,
          syscall: () => this.syscallBridge(this),
        },
      });
      if (this.nextTableIdx >= this.table.length) {
        this.table.grow(1024);
      }
      idx = this.nextTableIdx++;
      this.table.set(idx, inst.exports.bb as () => number);
      this.pcToTableIdx.set(pc, idx);
      this.compiledBlocks++;
    }
    const slotAddr = ICACHE_BASE + (((pc >>> 2) & ICACHE_MASK) << 3);
    const dv = this.view;
    dv.setUint32(slotAddr, pc, true);
    dv.setUint32(slotAddr + 4, idx, true);
    return idx;
  }

  stepWasmLoop(budget = 4096): number {
    let remaining = budget;
    while (remaining > 0) {
      const status = this.runSliceWasm(remaining);
      if (status === STATUS.CACHE_MISS) {
        this.ensureBlock(this.getPC());
        remaining--;
        continue;
      }
      return status;
    }
    return STATUS.YIELD;
  }

  stepJSPerBlock(budget = 4096): number {
    for (let i = 0; i < budget; i++) {
      const pc = this.getPC();
      const idx = this.ensureBlock(pc);
      const fn = this.table.get(idx) as () => number;
      const status = fn();
      if (status !== STATUS.CONTINUE) return status;
    }
    return STATUS.YIELD;
  }

  cloneForFork(newSyscallBridge: SyscallBridge): GuestCPU {
    const pages = this.memory.buffer.byteLength / 65536;
    const child = new GuestCPU(this.engine, newSyscallBridge, pages, 4096);
    child.u8.set(this.u8);
    child.u8.fill(0, ICACHE_BASE, ICACHE_BASE + ICACHE_ENTRIES * 8);
    return child;
  }
}

export interface LoadELFOptions {
  loadBias?: number;
  noSetPC?: boolean;
}

export interface ELFInfo {
  entry: number;
  brkStart: number;
  loadBias: number;
  eType: number;
  interpPath: string | null;
  phdrVaddr: number;
  phentsize: number;
  phnum: number;
}

export function loadELF64(cpu: GuestCPU, elfBytes: Uint8Array, opts: LoadELFOptions = {}): ELFInfo {
  const dv = new DataView(elfBytes.buffer, elfBytes.byteOffset, elfBytes.byteLength);
  if (
    dv.getUint8(0) !== 0x7f ||
    dv.getUint8(1) !== 0x45 ||
    dv.getUint8(2) !== 0x4c ||
    dv.getUint8(3) !== 0x46
  ) {
    throw new Error('Not an ELF binary');
  }
  const eType = dv.getUint16(16, true); // 2=ET_EXEC, 3=ET_DYN (PIE/shared)
  const eMachine = dv.getUint16(18, true);
  if (eMachine !== 183) throw new Error(`Unsupported ELF machine ${eMachine}, expected AArch64 (183)`);
  const rawEntry = Number(dv.getBigUint64(24, true));
  const phoff = Number(dv.getBigUint64(32, true));
  const phentsize = dv.getUint16(54, true);
  const phnum = dv.getUint16(56, true);

  // Rebase ET_DYN (PIE / ld-musl) to a safe non-zero compact 32-bit base
  const loadBias = eType === 3 ? (opts.loadBias ?? 0x00040000) : 0;

  let minVaddr = Infinity;
  let maxEnd = 0x10000;
  let interpPath: string | null = null;
  let phdrVaddr = 0;

  for (let i = 0; i < phnum; i++) {
    const off = phoff + i * phentsize;
    const pType = dv.getUint32(off, true);
    const pOffset = Number(dv.getBigUint64(off + 8, true));
    const pVaddr = Number(dv.getBigUint64(off + 16, true));
    const pFilesz = Number(dv.getBigUint64(off + 32, true));
    const pMemsz = Number(dv.getBigUint64(off + 40, true));

    if (pType === 3) {
      // PT_INTERP
      const slice = elfBytes.subarray(pOffset, pOffset + pFilesz);
      let len = slice.length;
      while (len > 0 && slice[len - 1] === 0) len--;
      interpPath = new TextDecoder().decode(slice.subarray(0, len));
      continue;
    }
    if (pType === 6) {
      // PT_PHDR
      phdrVaddr = loadBias + pVaddr;
      continue;
    }
    if (pType !== 1) continue; // PT_LOAD

    const dst = loadBias + pVaddr;
    if (dst < minVaddr) minVaddr = dst;
    cpu.ensureMemory(dst + pMemsz + 0x10000);
    cpu.u8.set(elfBytes.subarray(pOffset, pOffset + pFilesz), dst);
    if (pMemsz > pFilesz) {
      cpu.u8.fill(0, dst + pFilesz, dst + pMemsz);
    }
    if (dst + pMemsz > maxEnd) maxEnd = dst + pMemsz;
  }

  if (!phdrVaddr && minVaddr !== Infinity) {
    phdrVaddr = minVaddr + phoff;
  }
  const entry = loadBias + rawEntry;
  const brkStart = (maxEnd + 0xfff) & ~0xfff;
  if (!opts.noSetPC) cpu.setPC(entry);
  return {
    entry,
    brkStart,
    loadBias,
    eType,
    interpPath,
    phdrVaddr,
    phentsize,
    phnum,
  };
}

export function formatFaultDiagnostic(cpu: GuestCPU): string {
  const pc = cpu.getPC();
  const raw = pc + 4 <= cpu.view.byteLength ? cpu.view.getUint32(pc, true) : 0;
  const regs: string[] = [];
  for (let i = 0; i < 8; i++) regs.push(`x${i}=0x${cpu.getReg(i).toString(16)}`);
  return `PC=0x${pc.toString(16)} insn=0x${raw.toString(16).padStart(8, '0')} sp=0x${cpu
    .getReg(31)
    .toString(16)} lr=0x${cpu.getReg(30).toString(16)} [${regs.join(' ')}]`;
}

