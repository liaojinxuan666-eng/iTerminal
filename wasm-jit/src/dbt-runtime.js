(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory(require('./wasm-encoder-v2'));
  } else {
    root.WasmDBT = factory(root.WasmEncoderV2);
  }
})(typeof globalThis !== 'undefined' ? globalThis : this, function (WasmEnc) {
  'use strict';

  const { VALTYPE, OP, uleb128, sleb128, ModuleBuilder } = WasmEnc;

  // ---------------------------------------------------------------------------
  // Linear Memory Layout (shared across dispatcher + all dynamically compiled blocks)
  // 0x0000_0000 .. 0x0000_0FFF : CPU State Page (4 KB)
  //   0x000 .. 0x0F7 : x0..x30 (31 x 8 bytes)
  //   0x0F8          : SP      (8 bytes)
  //   0x100          : PC      (8 bytes)
  //   0x108          : Flag N  (i32)
  //   0x10C          : Flag Z  (i32)
  //   0x110          : Flag C  (i32)
  //   0x114          : Flag V  (i32)
  //   0x118          : TPIDR_EL0 (8 bytes)
  // 0x0000_1000 .. 0x0000_8FFF : Direct-Mapped I-Cache (4096 entries x 8 bytes)
  //   entry[slot] = { tag_pc: u32, tbl_idx: u32 }
  // 0x0001_0000+               : Guest 32-bit compact virtual address space
  // ---------------------------------------------------------------------------
  const STATE_BASE = 0x0000;
  const OFF_X = (n) => STATE_BASE + n * 8;
  const OFF_SP = STATE_BASE + 31 * 8;      // 0x0F8
  const OFF_PC = STATE_BASE + 32 * 8;      // 0x100
  const OFF_N = STATE_BASE + 0x108;
  const OFF_Z = STATE_BASE + 0x10c;
  const OFF_C = STATE_BASE + 0x110;
  const OFF_V = STATE_BASE + 0x114;
  const OFF_TPIDR = STATE_BASE + 0x118;

  const ICACHE_BASE = 0x1000;
  const ICACHE_ENTRIES = 4096;
  const ICACHE_MASK = ICACHE_ENTRIES - 1;

  // Execution status codes returned by basic blocks and dispatcher
  const STATUS = {
    CONTINUE: 0,
    YIELD: 1,            // Step budget exhausted (time slice end)
    CACHE_MISS: 2,       // Target PC not in I-Cache -> invoke on-device DBT
    EXIT: -1,            // Guest exited via exit/exit_group
    SYSCALL_PENDING: -2, // Blocking syscall awaiting async host Promise
    FAULT: -3,           // Illegal instruction or unmapped PC
  };

  function signExtend(val, bits) {
    const shift = 32 - bits;
    return (val << shift) >> shift;
  }

  // Emit helpers
  class CodeBuf {
    constructor() {
      this.b = [];
    }
    op(...ops) {
      for (const o of ops) this.b.push(o);
    }
    i32Const(v) {
      this.b.push(OP.I32_CONST, ...sleb128(v | 0));
    }
    i64Const(v) {
      this.b.push(OP.I64_CONST, ...sleb128(typeof v === 'bigint' ? v : BigInt(v)));
    }
    localGet(idx) {
      this.b.push(OP.LOCAL_GET, ...uleb128(idx));
    }
    localSet(idx) {
      this.b.push(OP.LOCAL_SET, ...uleb128(idx));
    }
    localTee(idx) {
      this.b.push(OP.LOCAL_TEE, ...uleb128(idx));
    }
    loadI32(offset = 0, align = 2) {
      this.b.push(OP.I32_LOAD, ...uleb128(align), ...uleb128(offset));
    }
    loadI64(offset = 0, align = 3) {
      this.b.push(OP.I64_LOAD, ...uleb128(align), ...uleb128(offset));
    }
    storeI32(offset = 0, align = 2) {
      this.b.push(OP.I32_STORE, ...uleb128(align), ...uleb128(offset));
    }
    storeI64(offset = 0, align = 3) {
      this.b.push(OP.I64_STORE, ...uleb128(align), ...uleb128(offset));
    }
    // Load AArch64 register (r=31 is XZR unless useSp=true)
    getReg(r, useSp = false, is32 = false) {
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
    // Emit address for storing AArch64 register; call before pushing value, then call endSetReg
    beginSetReg(r, useSp = false) {
      if (r === 31 && !useSp) return false;
      this.i32Const(r === 31 ? OFF_SP : OFF_X(r));
      return true;
    }
    endSetReg(r, useSp = false, is32 = false) {
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
    setPC(pcVal) {
      this.i32Const(OFF_PC);
      this.i64Const(BigInt(pcVal >>> 0));
      this.storeI64(0, 3);
    }
    // Emit condition check (leaves i32 0/1 on stack) from NZCV flags
    emitCond(cond) {
      const base = cond & 0xe;
      const loadFlag = (off) => {
        this.i32Const(off);
        this.loadI32(0, 2);
      };
      switch (base) {
        case 0x0: // EQ: Z == 1
          loadFlag(OFF_Z);
          break;
        case 0x2: // CS/HS: C == 1
          loadFlag(OFF_C);
          break;
        case 0x4: // MI: N == 1
          loadFlag(OFF_N);
          break;
        case 0x6: // VS: V == 1
          loadFlag(OFF_V);
          break;
        case 0x8: // HI: C == 1 && Z == 0
          loadFlag(OFF_C);
          loadFlag(OFF_Z);
          this.op(OP.I32_EQZ, OP.I32_AND);
          break;
        case 0xa: // GE: N == V
          loadFlag(OFF_N);
          loadFlag(OFF_V);
          this.op(OP.I32_EQ);
          break;
        case 0xc: // GT: Z == 0 && N == V
          loadFlag(OFF_Z);
          this.op(OP.I32_EQZ);
          loadFlag(OFF_N);
          loadFlag(OFF_V);
          this.op(OP.I32_EQ, OP.I32_AND);
          break;
        case 0xe: // AL
          this.i32Const(1);
          break;
      }
      if ((cond & 1) === 1 && base !== 0xe) {
        this.op(OP.I32_EQZ);
      }
    }
  }

  // ---------------------------------------------------------------------------
  // Build the WASM-Internal Dispatch Loop Module (compiled ONCE per engine)
  // Exports: run_slice(budget: i32) -> i32 (STATUS)
  // Imports: env.mem (memory), env.tbl (table funcref)
  // ---------------------------------------------------------------------------
  function buildDispatcherModule(memMinPages = 16, tableMin = 1024) {
    const mb = new ModuleBuilder();
    const tBlock = mb.addType([], [VALTYPE.I32]);        // () -> i32
    const tRun = mb.addType([VALTYPE.I32], [VALTYPE.I32]); // (budget: i32) -> i32
    mb.importMemory('env', 'mem', memMinPages);
    mb.importTable('env', 'tbl', tableMin);

    // locals: 0=budget(param), 1=pc, 2=slotAddr, 3=status
    const c = new CodeBuf();
    c.op(OP.LOOP, VALTYPE.VOID);
    // if budget <= 0 return STATUS.YIELD
    c.localGet(0);
    c.i32Const(0);
    c.op(OP.I32_LE_S, OP.IF, VALTYPE.VOID);
    c.i32Const(STATUS.YIELD);
    c.op(OP.RETURN, OP.END);

    // pc = i32.load(OFF_PC)
    c.i32Const(OFF_PC);
    c.loadI32(0, 2);
    c.localTee(1);

    // slotAddr = ICACHE_BASE + (((pc >>> 2) & ICACHE_MASK) << 3)
    c.i32Const(2);
    c.op(OP.I32_SHR_U);
    c.i32Const(ICACHE_MASK);
    c.op(OP.I32_AND);
    c.i32Const(3);
    c.op(OP.I32_SHL);
    c.i32Const(ICACHE_BASE);
    c.op(OP.I32_ADD);
    c.localTee(2);

    // if i32.load(slotAddr) != pc -> return STATUS.CACHE_MISS
    c.loadI32(0, 2);
    c.localGet(1);
    c.op(OP.I32_NE, OP.IF, VALTYPE.VOID);
    c.i32Const(STATUS.CACHE_MISS);
    c.op(OP.RETURN, OP.END);

    // tblIdx = i32.load(slotAddr + 4)
    c.localGet(2);
    c.loadI32(4, 2);
    // status = call_indirect (type 0)
    c.op(OP.CALL_INDIRECT, ...uleb128(tBlock), 0x00);
    c.localTee(3);
    // if status != 0 return status
    c.op(OP.IF, VALTYPE.VOID);
    c.localGet(3);
    c.op(OP.RETURN, OP.END);

    // budget = budget - 1; continue loop
    c.localGet(0);
    c.i32Const(1);
    c.op(OP.I32_SUB);
    c.localSet(0);
    c.op(OP.BR, 0);
    c.op(OP.END); // end loop

    c.i32Const(STATUS.YIELD);

    mb.addFunction(tRun, [[3, VALTYPE.I32]], c.b, 'run_slice');
    return new WebAssembly.Module(mb.toUint8Array());
  }

  // ---------------------------------------------------------------------------
  // On-Device AArch64 Basic-Block Translator (reads straight from guest memory)
  // Compiles 1 basic block starting at `startPC` into a standalone WebAssembly.Module
  // ---------------------------------------------------------------------------
  function translateBasicBlock(memView, startPC, maxInsns = 64) {
    const mb = new ModuleBuilder();
    const tSyscall = mb.addType([], [VALTYPE.I32]); // () -> i32 (STATUS)
    const tBlock = mb.addType([], [VALTYPE.I32]);   // () -> i32 (STATUS)
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

      // 1. NOP (0xD503201F)
      if (insn === 0xd503201f) {
        pc = nextPC;
        continue;
      }

      // 2. SVC #imm16 (0xD4000001 with imm16 in bits [20:5])
      if (((insn & 0xffe0001f) >>> 0) === 0xd4000001) {
        // Advance PC to next instruction before calling syscall handler;
        // if syscall returns SYSCALL_PENDING, host resumes right at nextPC after filling x0.
        c.setPC(nextPC);
        c.op(OP.CALL, ...uleb128(fnSyscall));
        c.op(OP.RETURN);
        terminated = true;
        break;
      }

      // 3. B / BL (unconditional immediate branch)
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

      // 4. B.cond (0x54000000, bit 4 = 0)
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

      // 5. CBZ / CBNZ
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

      // 6. TBZ / TBNZ
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

      // 7. BR / BLR / RET (Indirect Branches!)
      if (((insn & 0xff9ffc1f) >>> 0) === 0xd61f0000) {
        const opc = (insn >>> 21) & 0x3; // 0=BR, 1=BLR, 2=RET
        const rn = (insn >>> 5) & 0x1f;
        // Read target register BEFORE clobbering x30 (in case of BLR x30)
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

      // 8. MOVZ / MOVK / MOVN (Move wide immediate)
      if (((insn & 0x1f800000) >>> 0) === 0x12800000) {
        const is64 = (insn >>> 31) === 1;
        const opc = (insn >>> 29) & 0x3; // 0=MOVN, 2=MOVZ, 3=MOVK
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

      // 9. ADR / ADRP
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

      // 10. ADD / ADDS / SUB / SUBS (immediate)
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

      // 11. ADD / ADDS / SUB / SUBS (shifted register)
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

      // 12. Logical (shifted register): AND, ORR, EOR, ANDS (also MOV Xd, Xm = ORR Xd, XZR, Xm)
      if (((insn & 0x1f000000) >>> 0) === 0x0a000000) {
        const is64 = (insn >>> 31) === 1;
        const opc = (insn >>> 29) & 0x3; // 0=AND, 1=ORR, 2=EOR, 3=ANDS
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
        if (opc === 3) {
          emitLogicalFlags(c, is64);
        }
        pc = nextPC;
        continue;
      }

      // 13. MADD / MSUB (3-source: MUL is MADD Xd, Xn, Xm, XZR)
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

      // 14. Load/Store unsigned immediate: LDR/STR (8/16/32/64-bit)
      if (((insn & 0x3b000000) >>> 0) === 0x39000000) {
        const size = (insn >>> 30) & 0x3; // 0=1B, 1=2B, 2=4B, 3=8B
        const opc = (insn >>> 22) & 0x3;  // 0=STR, 1=LDR(u), 2=LDRSW/64s, 3=LDR32s
        const imm12 = (insn >>> 10) & 0xfff;
        const rn = (insn >>> 5) & 0x1f;
        const rt = insn & 0x1f;
        const byteOff = imm12 << size;
        emitLoadStore(c, size, opc, rn, rt, byteOff, 0);
        pc = nextPC;
        continue;
      }

      // 15. Load/Store register offset: LDR/STR Xt, [Xn, Xm]
      if (((insn & 0x3b200c00) >>> 0) === 0x38200800) {
        const size = (insn >>> 30) & 0x3;
        const opc = (insn >>> 22) & 0x3;
        const rm = (insn >>> 16) & 0x1f;
        const sBit = ((insn >>> 12) & 1) === 1;
        const rn = (insn >>> 5) & 0x1f;
        const rt = insn & 0x1f;
        c.getReg(rn, true, false);
        c.getReg(rm, false, false);
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

      // 16. LDP / STP (64-bit signed offset, pre-index, post-index)
      if (((insn & 0x7e400000) >>> 0) === 0x28000000 || ((insn & 0x7e400000) >>> 0) === 0x28400000) {
        const is64 = (insn >>> 31) === 1;
        const mode = (insn >>> 23) & 0x3; // 1=post, 2=signed-off, 3=pre
        const isLoad = ((insn >>> 22) & 1) === 1;
        const imm7 = signExtend((insn >>> 15) & 0x7f, 7);
        const rt2 = (insn >>> 10) & 0x1f;
        const rn = (insn >>> 5) & 0x1f;
        const rt = insn & 0x1f;
        const scale = is64 ? 8 : 4;
        const offset = imm7 * scale;

        // Compute base address in local 3
        c.getReg(rn, true, false);
        if (mode === 2 || mode === 3) {
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

        // Writeback for pre-index (3) or post-index (1)
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

    mb.addFunction(tBlock, [[3, VALTYPE.I64], [1, VALTYPE.I32]], c.b, 'bb');
    return new WebAssembly.Module(mb.toUint8Array());
  }

  function emitShift(c, shiftType, amount, is64) {
    if (amount === 0) return;
    c.i64Const(BigInt(amount));
    if (shiftType === 0) c.op(OP.I64_SHL);
    else if (shiftType === 1) c.op(OP.I64_SHR_U);
    else if (shiftType === 2) {
      if (!is64) {
        // sign extend 32-bit before arithmetic right shift
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

  function emitAddSub(c, is64, isSub, setFlags, rd, rdIsSp) {
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
      // N = (res >> signShift) & 1
      c.i32Const(OFF_N);
      c.localGet(2);
      c.i64Const(signShift);
      c.op(OP.I64_SHR_U, OP.I32_WRAP_I64);
      c.i32Const(1);
      c.op(OP.I32_AND);
      c.storeI32(0, 2);

      // Z = (res == 0)
      c.i32Const(OFF_Z);
      c.localGet(2);
      c.op(OP.I64_EQZ);
      c.storeI32(0, 2);

      // C: for SUB -> a >=u b; for ADD -> res <u a
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

      // V: signed overflow
      // ADD: ((~(a ^ b)) & (a ^ r)) >> signShift & 1
      // SUB: ((a ^ b) & (a ^ r)) >> signShift & 1
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

  function emitLogicalFlags(c, is64) {
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

  function emitLoadStore(c, size, opc, rn, rt, byteOff) {
    c.getReg(rn, true, false);
    if (byteOff !== 0) {
      c.i64Const(BigInt(byteOff));
      c.op(OP.I64_ADD);
    }
    c.op(OP.I32_WRAP_I64);
    c.localSet(3);
    emitLoadStoreAtLocal3(c, size, opc, rt);
  }

  function emitLoadStoreAtLocal3(c, size, opc, rt) {
    if (opc === 0) {
      // STR
      c.localGet(3);
      c.getReg(rt, false, false);
      if (size === 0) c.op(OP.I64_STORE8, 0, 0);
      else if (size === 1) c.op(OP.I64_STORE16, 1, 0);
      else if (size === 2) c.op(OP.I64_STORE32, 2, 0);
      else c.storeI64(0, 3);
    } else {
      // LDR
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

  // ---------------------------------------------------------------------------
  // Shared Compiled-Block Module Cache (reusable across fork()ed processes!)
  // ---------------------------------------------------------------------------
  class DBTEngine {
    constructor() {
      this.dispatcherModule = buildDispatcherModule(16, 1024);
      this.moduleCache = new Map(); // key: `${pc}:${firstInsn}` -> WebAssembly.Module
    }

    getOrCompileBlock(memView, pc) {
      const firstInsn = memView.getUint32(pc, true);
      const key = `${pc}:${firstInsn}`;
      let mod = this.moduleCache.get(key);
      if (!mod) {
        mod = translateBasicBlock(memView, pc);
        this.moduleCache.set(key, mod);
      }
      return mod;
    }
  }

  // ---------------------------------------------------------------------------
  // GuestCPU: owns linear memory, WebAssembly.Table, I-Cache, and dispatcher
  // ---------------------------------------------------------------------------
  class GuestCPU {
    constructor(engine, syscallBridge, initialPages = 64, maxPages = 4096) {
      this.engine = engine;
      this.syscallBridge = syscallBridge;
      this.memory = new WebAssembly.Memory({ initial: initialPages, maximum: maxPages });
      this.table = new WebAssembly.Table({ initial: 1024, maximum: 16384, element: 'anyfunc' });
      this.nextTableIdx = 1; // reserve 0
      this.pcToTableIdx = new Map();
      this.compiledBlocks = 0;

      this.dispatcherInstance = new WebAssembly.Instance(engine.dispatcherModule, {
        env: { mem: this.memory, tbl: this.table },
      });
      this.runSliceWasm = this.dispatcherInstance.exports.run_slice;
    }

    get view() {
      return new DataView(this.memory.buffer);
    }

    get u8() {
      return new Uint8Array(this.memory.buffer);
    }

    getReg(r) {
      const off = r === 31 ? OFF_SP : OFF_X(r);
      return this.view.getBigUint64(off, true);
    }

    setReg(r, val) {
      const off = r === 31 ? OFF_SP : OFF_X(r);
      this.view.setBigUint64(off, BigInt.asUintN(64, BigInt(val)), true);
    }

    getPC() {
      return Number(this.view.getBigUint64(OFF_PC, true));
    }

    setPC(pc) {
      this.view.setBigUint64(OFF_PC, BigInt(pc >>> 0), true);
    }

    // Ensure guest memory covers [0 .. byteSize)
    ensureMemory(byteSize) {
      const cur = this.memory.buffer.byteLength;
      if (byteSize <= cur) return true;
      const neededPages = Math.ceil((byteSize - cur) / 65536);
      this.memory.grow(neededPages);
      return true;
    }

    // Install or look up a compiled block at `pc` in this process's Table + I-Cache
    ensureBlock(pc) {
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
        this.table.set(idx, inst.exports.bb);
        this.pcToTableIdx.set(pc, idx);
        this.compiledBlocks++;
      }
      // Write direct-mapped I-Cache entry
      const slotAddr = ICACHE_BASE + (((pc >>> 2) & ICACHE_MASK) << 3);
      const dv = this.view;
      dv.setUint32(slotAddr, pc, true);
      dv.setUint32(slotAddr + 4, idx, true);
      return idx;
    }

    // Execute up to `budget` basic blocks using WASM-internal dispatch loop
    stepWasmLoop(budget = 4096) {
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

    // Baseline comparison mode: JS-side per-basic-block dispatch (like v1 guest.js)
    stepJSPerBlock(budget = 4096) {
      for (let i = 0; i < budget; i++) {
        const pc = this.getPC();
        const idx = this.ensureBlock(pc);
        const fn = this.table.get(idx);
        const status = fn();
        if (status !== STATUS.CONTINUE) return status;
      }
      return STATUS.YIELD;
    }

    // Clone CPU + linear memory for fork()
    cloneForFork(newSyscallBridge) {
      const pages = this.memory.buffer.byteLength / 65536;
      const child = new GuestCPU(this.engine, newSyscallBridge, pages, 4096);
      // Single memcpy snapshots registers + stack + heap + code!
      child.u8.set(this.u8);
      // Clear child's I-Cache so it lazily binds blocks to child's own memory instance
      child.u8.fill(0, ICACHE_BASE, ICACHE_BASE + ICACHE_ENTRIES * 8);
      return child;
    }
  }

  // ---------------------------------------------------------------------------
  // Minimal ELF64 AArch64 Loader (PT_LOAD segments -> compact 32-bit memory)
  // ---------------------------------------------------------------------------
  function loadELF64(cpu, elfBytes) {
    const dv = new DataView(elfBytes.buffer, elfBytes.byteOffset, elfBytes.byteLength);
    if (
      dv.getUint8(0) !== 0x7f ||
      dv.getUint8(1) !== 0x45 ||
      dv.getUint8(2) !== 0x4c ||
      dv.getUint8(3) !== 0x46
    ) {
      throw new Error('Not an ELF binary');
    }
    const eMachine = dv.getUint16(18, true);
    if (eMachine !== 183) throw new Error(`Unsupported ELF machine ${eMachine}, expected AArch64 (183)`);
    const entry = Number(dv.getBigUint64(24, true));
    const phoff = Number(dv.getBigUint64(32, true));
    const phentsize = dv.getUint16(54, true);
    const phnum = dv.getUint16(56, true);

    let maxEnd = 0x10000;
    for (let i = 0; i < phnum; i++) {
      const off = phoff + i * phentsize;
      const pType = dv.getUint32(off, true);
      if (pType !== 1) continue; // PT_LOAD
      const pOffset = Number(dv.getBigUint64(off + 8, true));
      const pVaddr = Number(dv.getBigUint64(off + 16, true));
      const pFilesz = Number(dv.getBigUint64(off + 32, true));
      const pMemsz = Number(dv.getBigUint64(off + 40, true));

      cpu.ensureMemory(pVaddr + pMemsz + 0x10000);
      cpu.u8.set(elfBytes.subarray(pOffset, pOffset + pFilesz), pVaddr);
      if (pMemsz > pFilesz) {
        cpu.u8.fill(0, pVaddr + pFilesz, pVaddr + pMemsz);
      }
      if (pVaddr + pMemsz > maxEnd) maxEnd = pVaddr + pMemsz;
    }

    const brkStart = (maxEnd + 0xfff) & ~0xfff;
    cpu.setPC(entry);
    return { entry, brkStart };
  }

  return {
    STATUS,
    OFF_X,
    OFF_SP,
    OFF_PC,
    OFF_N,
    OFF_Z,
    OFF_C,
    OFF_V,
    OFF_TPIDR,
    ICACHE_BASE,
    DBTEngine,
    GuestCPU,
    loadELF64,
    translateBasicBlock,
  };
});
