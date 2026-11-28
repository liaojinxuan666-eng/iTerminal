'use strict';

const assert = require('assert');
const { performance } = require('perf_hooks');
const WasmDBT = require('../src/dbt-runtime');
const { MemFS } = require('../src/vfs-memfs');
const { SYS, SIG, IOCTL_CMD, GuestKernel } = require('../src/vmm-syscalls');

// ---------------------------------------------------------------------------
// Minimal AArch64 Assembler + ELF64 Builder (for self-contained verification)
// ---------------------------------------------------------------------------
const A64 = {
  nop: () => 0xd503201f,
  umulh: (rd, rn, rm) =>
    (0x9bc07c00 | ((rm & 31) << 16) | ((rn & 31) << 5) | (rd & 31)) >>> 0,
  clz64: (rd, rn) => (0xdac01000 | ((rn & 31) << 5) | (rd & 31)) >>> 0,
  rev64: (rd, rn) => (0xdac00c00 | ((rn & 31) << 5) | (rd & 31)) >>> 0,
  ccmpImm: (rn, imm5, nzcv, cond) =>
    (0xfa400800 | ((imm5 & 31) << 16) | ((cond & 15) << 12) | ((rn & 31) << 5) | (nzcv & 15)) >>> 0,
  ldrLit64: (rt, relInsns) =>
    (0x58000000 | ((relInsns & 0x7ffff) << 5) | (rt & 31)) >>> 0,
  ldpQ: (qt, qt2, rn, imm7 = 0) =>
    (0xad400000 | ((imm7 & 0x7f) << 15) | ((qt2 & 31) << 10) | ((rn & 31) << 5) | (qt & 31)) >>> 0,
  stpQ: (qt, qt2, rn, imm7 = 0) =>
    (0xad000000 | ((imm7 & 0x7f) << 15) | ((qt2 & 31) << 10) | ((rn & 31) << 5) | (qt & 31)) >>> 0,
  svc: (imm16 = 0) => (0xd4000001 | ((imm16 & 0xffff) << 5)) >>> 0,
  movz: (rd, imm16, hw = 0) =>
    (0xd2800000 | ((hw & 3) << 21) | ((imm16 & 0xffff) << 5) | (rd & 31)) >>> 0,
  movk: (rd, imm16, hw = 0) =>
    (0xf2800000 | ((hw & 3) << 21) | ((imm16 & 0xffff) << 5) | (rd & 31)) >>> 0,
  movn: (rd, imm16, hw = 0) =>
    (0x92800000 | ((hw & 3) << 21) | ((imm16 & 0xffff) << 5) | (rd & 31)) >>> 0,
  movReg: (rd, rm) => (0xaa0003e0 | ((rm & 31) << 16) | (rd & 31)) >>> 0,
  addImm: (rd, rn, imm12) =>
    (0x91000000 | ((imm12 & 0xfff) << 10) | ((rn & 31) << 5) | (rd & 31)) >>> 0,
  subImm: (rd, rn, imm12) =>
    (0xd1000000 | ((imm12 & 0xfff) << 10) | ((rn & 31) << 5) | (rd & 31)) >>> 0,
  subsImm: (rd, rn, imm12) =>
    (0xf1000000 | ((imm12 & 0xfff) << 10) | ((rn & 31) << 5) | (rd & 31)) >>> 0,
  addReg: (rd, rn, rm) =>
    (0x8b000000 | ((rm & 31) << 16) | ((rn & 31) << 5) | (rd & 31)) >>> 0,
  mul: (rd, rn, rm) =>
    (0x9b007c00 | ((rm & 31) << 16) | ((rn & 31) << 5) | (rd & 31)) >>> 0,
  udiv: (rd, rn, rm) =>
    (0x9ac00800 | ((rm & 31) << 16) | ((rn & 31) << 5) | (rd & 31)) >>> 0,
  sdiv: (rd, rn, rm) =>
    (0x9ac00c00 | ((rm & 31) << 16) | ((rn & 31) << 5) | (rd & 31)) >>> 0,
  lslv: (rd, rn, rm) =>
    (0x9ac02000 | ((rm & 31) << 16) | ((rn & 31) << 5) | (rd & 31)) >>> 0,
  csel: (rd, rn, rm, cond) =>
    (0x9a800000 | ((rm & 31) << 16) | ((cond & 15) << 12) | ((rn & 31) << 5) | (rd & 31)) >>> 0,
  csneg: (rd, rn, rm, cond) =>
    (0xda800400 | ((rm & 31) << 16) | ((cond & 15) << 12) | ((rn & 31) << 5) | (rd & 31)) >>> 0,
  ubfm64: (rd, rn, immr, imms) =>
    (0xd3400000 | ((immr & 63) << 16) | ((imms & 63) << 10) | ((rn & 31) << 5) | (rd & 31)) >>> 0,
  sbfm64: (rd, rn, immr, imms) =>
    (0x93400000 | ((immr & 63) << 16) | ((imms & 63) << 10) | ((rn & 31) << 5) | (rd & 31)) >>> 0,
  mrsTpidr: (rt) => (0xd53bd040 | (rt & 31)) >>> 0,
  msrTpidr: (rt) => (0xd51bd040 | (rt & 31)) >>> 0,
  ldxr64: (rt, rn) => (0xc85f7c00 | ((rn & 31) << 5) | (rt & 31)) >>> 0,
  stxr64: (rs, rt, rn) => (0xc8007c00 | ((rs & 31) << 16) | ((rn & 31) << 5) | (rt & 31)) >>> 0,
  ldr64: (rt, rn, byteOff = 0) =>
    (0xf9400000 | (((byteOff >>> 3) & 0xfff) << 10) | ((rn & 31) << 5) | (rt & 31)) >>> 0,
  str64: (rt, rn, byteOff = 0) =>
    (0xf9000000 | (((byteOff >>> 3) & 0xfff) << 10) | ((rn & 31) << 5) | (rt & 31)) >>> 0,
  ldr32: (rt, rn, byteOff = 0) =>
    (0xb9400000 | (((byteOff >>> 2) & 0xfff) << 10) | ((rn & 31) << 5) | (rt & 31)) >>> 0,
  ldr8Post: (rt, rn, simm9) =>
    (0x38400400 | ((simm9 & 0x1ff) << 12) | ((rn & 31) << 5) | (rt & 31)) >>> 0,
  ldur64: (rt, rn, simm9) =>
    (0xf8400000 | ((simm9 & 0x1ff) << 12) | ((rn & 31) << 5) | (rt & 31)) >>> 0,
  stur64: (rt, rn, simm9) =>
    (0xf8000000 | ((simm9 & 0x1ff) << 12) | ((rn & 31) << 5) | (rt & 31)) >>> 0,
  b: (relInsns) => (0x14000000 | (relInsns & 0x03ffffff)) >>> 0,
  bl: (relInsns) => (0x94000000 | (relInsns & 0x03ffffff)) >>> 0,
  bCond: (cond, relInsns) => (0x54000000 | ((relInsns & 0x7ffff) << 5) | (cond & 0xf)) >>> 0,
  cbz: (rt, relInsns) => (0xb4000000 | ((relInsns & 0x7ffff) << 5) | (rt & 31)) >>> 0,
  cbnz: (rt, relInsns) => (0xb5000000 | ((relInsns & 0x7ffff) << 5) | (rt & 31)) >>> 0,
  br: (rn) => (0xd61f0000 | ((rn & 31) << 5)) >>> 0,
  blr: (rn) => (0xd63f0000 | ((rn & 31) << 5)) >>> 0,
  ret: (rn = 30) => (0xd65f0000 | ((rn & 31) << 5)) >>> 0,
  adr: (rd, relBytes) => {
    const immlo = relBytes & 0x3;
    const immhi = (relBytes >> 2) & 0x7ffff;
    return (0x10000000 | (immlo << 29) | (immhi << 5) | (rd & 31)) >>> 0;
  },
};

function buildELF64(codeInsns, dataBytes = new Uint8Array(0), baseVaddr = 0x10000) {
  const codeSize = codeInsns.length * 4;
  const dataOffsetInSeg = (codeSize + 15) & ~15;
  const segSize = dataOffsetInSeg + dataBytes.length;

  const ehdrSize = 64;
  const phdrSize = 56;
  const fileOffset = 0x100;
  const totalSize = fileOffset + segSize;
  const buf = new Uint8Array(totalSize);
  const dv = new DataView(buf.buffer);

  buf[0] = 0x7f; buf[1] = 0x45; buf[2] = 0x4c; buf[3] = 0x46;
  buf[4] = 2; buf[5] = 1; buf[6] = 1;
  dv.setUint16(16, 2, true);
  dv.setUint16(18, 183, true);
  dv.setUint32(20, 1, true);
  dv.setBigUint64(24, BigInt(baseVaddr), true);
  dv.setBigUint64(32, BigInt(ehdrSize), true);
  dv.setUint16(52, ehdrSize, true);
  dv.setUint16(54, phdrSize, true);
  dv.setUint16(56, 1, true);

  dv.setUint32(ehdrSize + 0, 1, true);
  dv.setUint32(ehdrSize + 4, 7, true);
  dv.setBigUint64(ehdrSize + 8, BigInt(fileOffset), true);
  dv.setBigUint64(ehdrSize + 16, BigInt(baseVaddr), true);
  dv.setBigUint64(ehdrSize + 24, BigInt(baseVaddr), true);
  dv.setBigUint64(ehdrSize + 32, BigInt(segSize), true);
  dv.setBigUint64(ehdrSize + 40, BigInt(segSize), true);
  dv.setBigUint64(ehdrSize + 48, 0x1000n, true);

  for (let i = 0; i < codeInsns.length; i++) {
    dv.setUint32(fileOffset + i * 4, codeInsns[i], true);
  }
  if (dataBytes.length) buf.set(dataBytes, fileOffset + dataOffsetInSeg);
  return { elf: buf, dataVaddr: baseVaddr + dataOffsetInSeg };
}

// ---------------------------------------------------------------------------
// Test 1: Tight Loop + WASM-Internal Dispatch vs JS-per-BB Benchmark
// ---------------------------------------------------------------------------
async function testLoopAndBenchmark() {
  const N = 200000;
  const code = [
    A64.movz(0, 0),
    A64.movz(1, N & 0xffff, 0),
    A64.movk(1, (N >>> 16) & 0xffff, 1),
    A64.addReg(0, 0, 1),
    A64.subsImm(1, 1, 1),
    A64.bCond(1, -2),
    A64.movReg(19, 0),
    A64.movz(0, 0),
    A64.movz(8, SYS.EXIT_GROUP),
    A64.svc(0),
  ];
  const { elf } = buildELF64(code);
  const expectedSum = (BigInt(N) * BigInt(N + 1)) / 2n;

  const kWasm = new GuestKernel(new WasmDBT.DBTEngine());
  const pWasm = kWasm.spawnELF(elf);
  const t0 = performance.now();
  await kWasm.runAll({ mode: 'wasm', sliceBudget: 50000 });
  const wasmMs = performance.now() - t0;
  assert.strictEqual(pWasm.cpu.getReg(19), expectedSum);

  const kJS = new GuestKernel(new WasmDBT.DBTEngine());
  const pJS = kJS.spawnELF(elf);
  const t1 = performance.now();
  await kJS.runAll({ mode: 'js', sliceBudget: 50000 });
  const jsMs = performance.now() - t1;
  assert.strictEqual(pJS.cpu.getReg(19), expectedSum);

  console.log(
    `[PASS] Test 1 (Loop ${N.toLocaleString()} iters): WASM-loop=${wasmMs.toFixed(
      2
    )}ms vs JS-per-BB=${jsMs.toFixed(2)}ms (${(jsMs / wasmMs).toFixed(2)}x speedup)`
  );
}

// ---------------------------------------------------------------------------
// Test 2: Indirect Branches (BLR / RET) & On-Device Lazy DBT
// ---------------------------------------------------------------------------
async function testIndirectBranchesDBT() {
  const code = [
    A64.adr(9, 7 * 4),
    A64.movz(0, 12),
    A64.blr(9),
    A64.movReg(19, 0),
    A64.movz(0, 0),
    A64.movz(8, SYS.EXIT_GROUP),
    A64.svc(0),
    A64.mul(0, 0, 0),
    A64.ret(30),
  ];
  const { elf } = buildELF64(code);
  const kernel = new GuestKernel(new WasmDBT.DBTEngine());
  const proc = kernel.spawnELF(elf);
  await kernel.runAll();
  assert.strictEqual(proc.cpu.getReg(19), 144n);
  console.log(`[PASS] Test 2 (Indirect BLR/RET & Lazy DBT): 12^2=144`);
}

// ---------------------------------------------------------------------------
// Test 3: Compact 32-bit VMM (brk + mmap + munmap)
// ---------------------------------------------------------------------------
async function testCompactVMM() {
  const code = [
    A64.movz(0, 0), A64.movz(8, SYS.BRK), A64.svc(0), A64.movReg(19, 0),
    A64.addImm(0, 19, 4095), A64.addImm(0, 0, 4095), A64.movz(8, SYS.BRK), A64.svc(0),
    A64.movz(1, 0x5678, 0), A64.movk(1, 0x1234, 1), A64.str64(1, 19, 4096), A64.ldr64(21, 19, 4096),
    A64.movz(0, 0), A64.movz(1, 8192), A64.movz(2, 3), A64.movz(3, 0x22), A64.movz(8, SYS.MMAP), A64.svc(0),
    A64.movReg(22, 0), A64.movz(1, 0xcafe), A64.str64(1, 22, 8), A64.ldr64(23, 22, 8),
    A64.movReg(0, 22), A64.movz(1, 8192), A64.movz(8, SYS.MUNMAP), A64.svc(0), A64.movReg(24, 0),
    A64.movz(0, 0), A64.movz(8, SYS.EXIT_GROUP), A64.svc(0),
  ];
  const { elf } = buildELF64(code);
  const kernel = new GuestKernel(new WasmDBT.DBTEngine());
  const proc = kernel.spawnELF(elf);
  await kernel.runAll();
  assert.strictEqual(proc.cpu.getReg(21), 0x12345678n);
  assert.strictEqual(proc.cpu.getReg(23), 0xcafen);
  assert.strictEqual(proc.cpu.getReg(24), 0n);
  console.log(`[PASS] Test 3 (Compact 32-bit VMM): brk/mmap/munmap verified`);
}

// ---------------------------------------------------------------------------
// Test 4: Suspendable Async Syscall (Simulated Swift PTY read)
// ---------------------------------------------------------------------------
async function testSuspendableAsyncSyscall() {
  const code = [
    A64.subImm(31, 31, 64),
    A64.movz(0, 0), A64.addImm(1, 31, 0), A64.movz(2, 64), A64.movz(8, SYS.READ), A64.svc(0),
    A64.movReg(2, 0), A64.movz(0, 1), A64.addImm(1, 31, 0), A64.movz(8, SYS.WRITE), A64.svc(0),
    A64.movz(0, 0), A64.movz(8, SYS.EXIT_GROUP), A64.svc(0),
  ];
  const { elf } = buildELF64(code);
  let stdout = '';
  const kernel = new GuestKernel(new WasmDBT.DBTEngine(), {
    onStdout: (b) => { stdout += new TextDecoder().decode(b); },
    readStdinAsync: () => new Promise((r) => setTimeout(() => r(new TextEncoder().encode('hello PTY!\n')), 10)),
  });
  kernel.spawnELF(elf);
  await kernel.runAll();
  assert.strictEqual(stdout, 'hello PTY!\n');
  console.log(`[PASS] Test 4 (Suspendable Async Syscall): echoed "${stdout.trim()}"`);
}

// ---------------------------------------------------------------------------
// Test 5: fork() + pipe2() + wait4()
// ---------------------------------------------------------------------------
async function testForkPipeWait() {
  const msg = new TextEncoder().encode('child->pipe->parent OK!\n');
  const baseVaddr = 0x10000;
  const code = [
    A64.subImm(31, 31, 128),
    A64.addImm(0, 31, 0), A64.movz(1, 0), A64.movz(8, SYS.PIPE2), A64.svc(0),
    A64.ldr32(19, 31, 0), A64.ldr32(20, 31, 4),
    A64.movz(0, 0), A64.movz(8, SYS.CLONE), A64.svc(0),
    A64.cbz(0, 0), // patched
    A64.movReg(21, 0),
    A64.movReg(0, 20), A64.movz(8, SYS.CLOSE), A64.svc(0),
    A64.movReg(0, 19), A64.addImm(1, 31, 16), A64.movz(2, 64), A64.movz(8, SYS.READ), A64.svc(0),
    A64.movReg(2, 0), A64.movz(0, 1), A64.addImm(1, 31, 16), A64.movz(8, SYS.WRITE), A64.svc(0),
    A64.movReg(0, 21), A64.addImm(1, 31, 80), A64.movz(2, 0), A64.movz(3, 0), A64.movz(8, SYS.WAIT4), A64.svc(0),
    A64.ldr32(22, 31, 80), A64.movz(0, 0), A64.movz(8, SYS.EXIT_GROUP), A64.svc(0),
  ];
  const childIdx = code.length;
  code[10] = A64.cbz(0, childIdx - 10);
  code.push(
    A64.movReg(0, 19), A64.movz(8, SYS.CLOSE), A64.svc(0),
    A64.movReg(0, 20), A64.movz(1, 0, 0), A64.movk(1, 0, 1), A64.movz(2, msg.length), A64.movz(8, SYS.WRITE), A64.svc(0),
    A64.movReg(0, 20), A64.movz(8, SYS.CLOSE), A64.svc(0),
    A64.movz(0, 42), A64.movz(8, SYS.EXIT_GROUP), A64.svc(0)
  );
  const realMsgAddr = baseVaddr + ((code.length * 4 + 15) & ~15);
  code[childIdx + 4] = A64.movz(1, realMsgAddr & 0xffff, 0);
  code[childIdx + 5] = A64.movk(1, (realMsgAddr >>> 16) & 0xffff, 1);

  const { elf } = buildELF64(code, msg, baseVaddr);
  let stdout = '';
  const kernel = new GuestKernel(new WasmDBT.DBTEngine(), {
    onStdout: (b) => { stdout += new TextDecoder().decode(b); },
  });
  const parent = kernel.spawnELF(elf);
  await kernel.runAll({ sliceBudget: 8 });
  assert.strictEqual(stdout, 'child->pipe->parent OK!\n');
  assert.strictEqual(parent.cpu.getReg(22), BigInt(42 << 8));
  console.log(`[PASS] Test 5 (fork + pipe2 + wait4): reaped child exitCode=42`);
}

// ---------------------------------------------------------------------------
// Test 6: Musl-Critical AArch64 ISA (CSEL, UDIV/SDIV, UBFM/SBFM, TPIDR_EL0, LDXR/STXR, LDUR/STUR)
// ---------------------------------------------------------------------------
async function testMuslISA() {
  const code = [
    // 1. UDIV: 100 / 7 = 14 -> x19
    A64.movz(0, 100), A64.movz(1, 7), A64.udiv(19, 0, 1),
    // 2. SDIV: -42 / 6 = -7 -> x20
    A64.movn(0, 41), A64.movz(1, 6), A64.sdiv(20, 0, 1),
    // 3. CSEL: cmp x19, #14 (EQ=0) -> choose 777 over 999 -> x21
    A64.subsImm(31, 19, 14), A64.movz(2, 777), A64.movz(3, 999), A64.csel(21, 2, 3, 0),
    // 4. UBFM (LSL #4): 5 << 4 = 80 (immr=60, imms=59) -> x22
    A64.movz(4, 5), A64.ubfm64(22, 4, 60, 59),
    // 5. SBFM (SXTB): sign-extend 0xFF -> -1 (immr=0, imms=7) -> x23
    A64.movz(5, 0xff), A64.sbfm64(23, 5, 0, 7),
    // 6. MSR/MRS TPIDR_EL0: write 0x55AA -> read back into x24
    A64.movz(6, 0x55aa), A64.msrTpidr(6), A64.mrsTpidr(24),
    // 7. STUR/LDUR + LDXR/STXR atomic increment on [sp - 16]
    A64.subImm(31, 31, 32),
    A64.movz(7, 41), A64.stur64(7, 31, 16),
    A64.addImm(9, 31, 16),
    A64.ldxr64(10, 9), A64.addImm(10, 10, 1), A64.stxr64(25, 10, 9), // x25 = status (0)
    A64.ldur64(26, 31, 16),                                          // x26 = 42
    A64.movz(0, 0), A64.movz(8, SYS.EXIT_GROUP), A64.svc(0),
  ];
  const { elf } = buildELF64(code);
  const kernel = new GuestKernel(new WasmDBT.DBTEngine());
  const proc = kernel.spawnELF(elf);
  await kernel.runAll();

  assert.strictEqual(proc.cpu.getReg(19), 14n, 'UDIV');
  assert.strictEqual(BigInt.asIntN(64, proc.cpu.getReg(20)), -7n, 'SDIV');
  assert.strictEqual(proc.cpu.getReg(21), 777n, 'CSEL');
  assert.strictEqual(proc.cpu.getReg(22), 80n, 'UBFM LSL');
  assert.strictEqual(BigInt.asIntN(64, proc.cpu.getReg(23)), -1n, 'SBFM SXTB');
  assert.strictEqual(proc.cpu.getReg(24), 0x55aan, 'TPIDR_EL0');
  assert.strictEqual(proc.cpu.getReg(25), 0n, 'STXR status');
  assert.strictEqual(proc.cpu.getReg(26), 42n, 'LDXR/STXR value');
  console.log(`[PASS] Test 6 (Musl ISA): UDIV/SDIV/CSEL/UBFM/SBFM/TPIDR_EL0/LDXR+STXR all verified`);
}

// ---------------------------------------------------------------------------
// Test 7: VFS (MemFS openat + fstat + read + getdents64) + argv ABI
// ---------------------------------------------------------------------------
async function testVFSAndArgv() {
  // Program reads argv[1] from [sp + 16], opens that file via openat(AT_FDCWD, argv[1], 0),
  // reads its contents and writes them to stdout!
  const code = [
    A64.ldr64(19, 31, 0),    // x19 = argc
    A64.ldr64(20, 31, 16),   // x20 = argv[1] ("/etc/hostname")
    // openat(-100, argv[1], 0, 0)
    A64.movn(0, 99),         // x0 = -100 (AT_FDCWD)
    A64.movReg(1, 20),
    A64.movz(2, 0),
    A64.movz(3, 0),
    A64.movz(8, SYS.OPENAT),
    A64.svc(0),
    A64.movReg(21, 0),       // x21 = fd
    // read(fd, sp - 64, 64)
    A64.subImm(31, 31, 64),
    A64.movReg(0, 21), A64.addImm(1, 31, 0), A64.movz(2, 64), A64.movz(8, SYS.READ), A64.svc(0),
    // write(1, sp, n)
    A64.movReg(2, 0), A64.movz(0, 1), A64.addImm(1, 31, 0), A64.movz(8, SYS.WRITE), A64.svc(0),
    A64.movz(0, 0), A64.movz(8, SYS.EXIT_GROUP), A64.svc(0),
  ];
  const { elf } = buildELF64(code);
  const fs = new MemFS();
  fs.writeFile('/etc/hostname', 'iterminal-ios\n');
  let stdout = '';
  const kernel = new GuestKernel(new WasmDBT.DBTEngine(), {
    fs,
    onStdout: (b) => { stdout += new TextDecoder().decode(b); },
  });
  const proc = kernel.spawnELF(elf, { argv: ['/bin/cat', '/etc/hostname'] });
  await kernel.runAll();

  assert.strictEqual(proc.cpu.getReg(19), 2n, 'argc should be 2');
  assert.strictEqual(stdout, 'iterminal-ios\n');
  console.log(`[PASS] Test 7 (VFS + Linux argv ABI): /bin/cat /etc/hostname -> "${stdout.trim()}"`);
}

// ---------------------------------------------------------------------------
// Test 8: Full Shell Pipeline: fork() + pipe2() + dup3(wfd, 1) + execve("/bin/echo") + wait4()
// ---------------------------------------------------------------------------
async function testForkExecvePipeline() {
  // Binary B (`/bin/echo`): reads argv[1] from Linux stack [sp + 16], computes strlen via LDRB post-index,
  // writes argv[1] to fd 1 (redirected to pipe!), exits with code 7.
  const echoCode = [
    A64.ldr64(19, 31, 16),       // 0: x19 = argv[1] ptr
    A64.movReg(20, 19),          // 1: x20 = cursor
    // strlen loop (idx 2..4):
    A64.ldr8Post(1, 20, 1),      // 2: w1 = *x20++
    A64.cbnz(1, -1),             // 3: loop while byte != 0
    A64.subImm(20, 20, 1),       // 4: exclude trailing '\0'
    // x2 = x20 - x19 (length) via SUB shifted reg
    ((0xcb000000 | (19 << 16) | (20 << 5) | 2) >>> 0), // 5: sub x2, x20, x19
    A64.movz(0, 1),              // 6: fd = 1 (stdout -> pipe!)
    A64.movReg(1, 19),           // 7: buf = argv[1]
    A64.movz(8, SYS.WRITE),      // 8
    A64.svc(0),                  // 9
    A64.movz(0, 7),              // 10: exit(7)
    A64.movz(8, SYS.EXIT_GROUP), // 11
    A64.svc(0),                  // 12
  ];
  const { elf: echoElf } = buildELF64(echoCode);

  // Binary A (`/bin/sh` mini-shell):
  //   pipe2 -> fork -> child: dup3(wfd, 1, 0), close(rfd), close(wfd), execve("/bin/echo", ["/bin/echo", "execve-pipeline-ok!"], NULL)
  //                 -> parent: close(wfd), read(rfd), write(1), wait4(child)
  const enc = new TextEncoder();
  const sPath = enc.encode('/bin/echo\0');
  const sArg1 = enc.encode('execve-pipeline-ok!\n\0');
  const dataBlob = new Uint8Array(sPath.length + sArg1.length);
  dataBlob.set(sPath, 0);
  dataBlob.set(sArg1, sPath.length);

  const baseVaddr = 0x10000;
  const shCode = [
    A64.subImm(31, 31, 160),
    A64.addImm(0, 31, 0), A64.movz(1, 0), A64.movz(8, SYS.PIPE2), A64.svc(0),
    A64.ldr32(19, 31, 0), A64.ldr32(20, 31, 4),
    A64.movz(0, 0), A64.movz(8, SYS.CLONE), A64.svc(0),
    A64.cbz(0, 0), // idx 10 -> patched to childIdx
    // Parent:
    A64.movReg(21, 0),
    A64.movReg(0, 20), A64.movz(8, SYS.CLOSE), A64.svc(0),
    A64.movReg(0, 19), A64.addImm(1, 31, 16), A64.movz(2, 64), A64.movz(8, SYS.READ), A64.svc(0),
    A64.movReg(2, 0), A64.movz(0, 1), A64.addImm(1, 31, 16), A64.movz(8, SYS.WRITE), A64.svc(0),
    A64.movReg(0, 21), A64.addImm(1, 31, 96), A64.movz(2, 0), A64.movz(3, 0), A64.movz(8, SYS.WAIT4), A64.svc(0),
    A64.ldr32(22, 31, 96), A64.movz(0, 0), A64.movz(8, SYS.EXIT_GROUP), A64.svc(0),
  ];
  const childIdx = shCode.length;
  shCode[10] = A64.cbz(0, childIdx - 10);

  // Child: dup3(wfd, 1, 0); close(rfd); close(wfd); build argv[] at [sp+112]; execve(path, argv, 0)
  shCode.push(
    A64.movReg(0, 20), A64.movz(1, 1), A64.movz(2, 0), A64.movz(8, SYS.DUP3), A64.svc(0),
    A64.movReg(0, 19), A64.movz(8, SYS.CLOSE), A64.svc(0),
    A64.movReg(0, 20), A64.movz(8, SYS.CLOSE), A64.svc(0),
    A64.movz(10, 0, 0), A64.movk(10, 0, 1), // patched: pathPtr (/bin/echo)
    A64.movz(11, 0, 0), A64.movk(11, 0, 1), // patched: arg1Ptr (execve-pipeline-ok!\n)
    A64.movz(12, 0),
    A64.str64(10, 31, 112),
    A64.str64(11, 31, 120),
    A64.str64(12, 31, 128),
    A64.movReg(0, 10),
    A64.addImm(1, 31, 112),
    A64.movz(2, 0),
    A64.movz(8, SYS.EXECVE),
    A64.svc(0),
    // Fallback if execve failed
    A64.movz(0, 99), A64.movz(8, SYS.EXIT_GROUP), A64.svc(0)
  );

  const realDataOff = (shCode.length * 4 + 15) & ~15;
  const pathPtr = baseVaddr + realDataOff;
  const arg1Ptr = pathPtr + sPath.length;
  const patchBase = childIdx + 11;
  shCode[patchBase + 0] = A64.movz(10, pathPtr & 0xffff, 0);
  shCode[patchBase + 1] = A64.movk(10, (pathPtr >>> 16) & 0xffff, 1);
  shCode[patchBase + 2] = A64.movz(11, arg1Ptr & 0xffff, 0);
  shCode[patchBase + 3] = A64.movk(11, (arg1Ptr >>> 16) & 0xffff, 1);

  const { elf: shElf } = buildELF64(shCode, dataBlob, baseVaddr);
  const fs = new MemFS();
  fs.writeFile('/bin/echo', echoElf, 0o755);

  let stdout = '';
  const kernel = new GuestKernel(new WasmDBT.DBTEngine(), {
    fs,
    onStdout: (b) => { stdout += new TextDecoder().decode(b); },
  });
  const parent = kernel.spawnELF(shElf, { argv: ['/bin/sh'] });
  await kernel.runAll({ sliceBudget: 16 });

  assert.strictEqual(stdout, 'execve-pipeline-ok!\n');
  assert.strictEqual(parent.cpu.getReg(22), BigInt(7 << 8));
  console.log(
    `[PASS] Test 8 (Shell Pipeline fork+pipe2+dup3+execve+wait4): captured "${stdout.trim()}" (exit=7)`
  );
}


// ---------------------------------------------------------------------------
// Test 9: Musl printf/strlen/memcpy ISA (UMULH, CLZ, REV, CCMP, LDR literal, 128-bit LDP/STP Q)
// ---------------------------------------------------------------------------
async function testMuslPrintfMemcpyISA() {
  // Data pool holds 64-bit magic multiplier for dividing by 10: 0xCCCCCCCCCCCCCCCD
  const pool = new Uint8Array(64);
  const pdv = new DataView(pool.buffer);
  pdv.setBigUint64(0, 0xcccccccccccccccdn, true); // magic / 10
  // 32 bytes source buffer at pool+16 for 128-bit LDP/STP Q0, Q1 memcpy test
  pdv.setBigUint64(16, 0x1122334455667788n, true);
  pdv.setBigUint64(24, 0x99aabbccddeeff00n, true);
  pdv.setBigUint64(32, 0xdeadbeefcafebaben, true);
  pdv.setBigUint64(40, 0x0123456789abcdefn, true);

  const code = [
    // 0: ldr x1, [pc + literal_pool] (patched below)
    0,
    // 1..3: UMULH magic division: 12345 / 10 = (umulh(12345, magic) >> 3) = 1234 -> x19
    A64.movz(0, 12345),
    A64.umulh(19, 0, 1),
    A64.ubfm64(19, 19, 3, 63), // LSR #3
    // 4..5: CLZ(0x0000_0000_0000_0010) = 59 -> x20
    A64.movz(2, 0x10),
    A64.clz64(20, 2),
    // 6..7: REV64(0x0102) -> 0x0201_0000_0000_0000 -> x21
    A64.movz(3, 0x0102),
    A64.rev64(21, 3),
    // 8..11: CCMP: cmp x19, #1234 (EQ); ccmp x20, #59, #0, EQ -> Z=1 -> csel x22 = 1 else 0
    A64.subsImm(31, 19, 1234),
    A64.ccmpImm(20, 59 & 31, 0, 0), // wait 59 > 31, use x20 - 59? Let's test imm5=10 with movz(4, 10)
    A64.movz(4, 10),
    A64.ccmpImm(4, 10, 0, 0),
    A64.movz(5, 1),
    A64.movz(6, 0),
    A64.csel(22, 5, 6, 0),
    // 15..20: 128-bit SIMD memcpy via LDP Q0, Q1, [x7] -> STP Q0, Q1, [sp]
    A64.subImm(31, 31, 64),
    A64.movz(7, 0, 0), // patched: src = dataVaddr + 16
    A64.movk(7, 0, 1),
    A64.ldpQ(0, 1, 7, 0),
    A64.stpQ(0, 1, 31, 0),
    A64.ldr64(23, 31, 0),
    A64.ldr64(24, 31, 24),
    A64.movz(0, 0),
    A64.movz(8, SYS.EXIT_GROUP),
    A64.svc(0),
  ];
  // Clean up index 9 (replace redundant ccmp with nop so cmp x19,#1234 flows cleanly into ccmp x4,#10)
  code[9] = A64.movz(4, 10);
  code[10] = A64.subsImm(31, 19, 1234);

  const baseVaddr = 0x10000;
  const dataOff = (code.length * 4 + 15) & ~15;
  const dataVaddr = baseVaddr + dataOff;
  code[0] = A64.ldrLit64(1, dataOff >>> 2);
  const srcAddr = dataVaddr + 16;
  code[16] = A64.movz(7, srcAddr & 0xffff, 0);
  code[17] = A64.movk(7, (srcAddr >>> 16) & 0xffff, 1);

  const { elf } = buildELF64(code, pool, baseVaddr);
  const kernel = new GuestKernel(new WasmDBT.DBTEngine());
  const proc = kernel.spawnELF(elf);
  await kernel.runAll();

  assert.strictEqual(proc.cpu.getReg(19), 1234n, 'UMULH /10');
  assert.strictEqual(proc.cpu.getReg(20), 59n, 'CLZ64');
  assert.strictEqual(proc.cpu.getReg(21), 0x0201000000000000n, 'REV64');
  assert.strictEqual(proc.cpu.getReg(22), 1n, 'CCMP+CSEL');
  assert.strictEqual(proc.cpu.getReg(23), 0x1122334455667788n, 'SIMD LDP/STP Q0');
  assert.strictEqual(proc.cpu.getReg(24), 0x0123456789abcdefn, 'SIMD LDP/STP Q1');
  console.log(`[PASS] Test 9 (Musl printf/memcpy ISA): UMULH/CLZ/REV/CCMP/LDR-lit/128-bit Q-reg memcpy verified`);
}

// ---------------------------------------------------------------------------
// Test 10: BusyBox Symlinks + /proc/self/exe + TTY ioctl(TIOCGWINSZ)
// ---------------------------------------------------------------------------
async function testBusyBoxSymlinkAndTTY() {
  const enc = new TextEncoder();
  const sSelf = enc.encode('/proc/self/exe\0');
  const code = [
    // readlinkat(AT_FDCWD, "/proc/self/exe", sp - 64, 64) -> write to stdout
    A64.subImm(31, 31, 96),
    A64.movn(0, 99),
    A64.movz(1, 0, 0), // patched: sSelf ptr
    A64.movk(1, 0, 1),
    A64.addImm(2, 31, 0),
    A64.movz(3, 64),
    A64.movz(8, SYS.READLINKAT),
    A64.svc(0),
    A64.movReg(2, 0), A64.movz(0, 1), A64.addImm(1, 31, 0), A64.movz(8, SYS.WRITE), A64.svc(0),

    // ioctl(1, TIOCGWINSZ=0x5413, sp + 64) -> x19 = rows, x20 = cols
    A64.movz(0, 1),
    A64.movz(1, IOCTL_CMD.TIOCGWINSZ),
    A64.addImm(2, 31, 64),
    A64.movz(8, SYS.IOCTL),
    A64.svc(0),
    A64.ldr32(19, 31, 64), // low 16=rows, high 16=cols
    A64.movz(0, 0), A64.movz(8, SYS.EXIT_GROUP), A64.svc(0),
  ];
  const baseVaddr = 0x10000;
  const dataOff = (code.length * 4 + 15) & ~15;
  const sSelfAddr = baseVaddr + dataOff;
  code[2] = A64.movz(1, sSelfAddr & 0xffff, 0);
  code[3] = A64.movk(1, (sSelfAddr >>> 16) & 0xffff, 1);

  const { elf } = buildELF64(code, sSelf, baseVaddr);
  const fs = new MemFS();
  fs.writeFile('/bin/busybox', elf, 0o755);
  fs.symlink('/bin/busybox', '/bin/sh');

  let stdout = '';
  const kernel = new GuestKernel(new WasmDBT.DBTEngine(), {
    fs,
    rows: 40,
    cols: 120,
    onStdout: (b) => { stdout += new TextDecoder().decode(b); },
  });
  const proc = kernel.spawnELF(fs.readFile('/bin/sh'), {
    argv: ['/bin/sh'],
    exePath: fs.resolveSymlinks('/bin/sh'),
  });
  await kernel.runAll();

  const packed = Number(proc.cpu.getReg(19));
  const rows = packed & 0xffff;
  const cols = (packed >>> 16) & 0xffff;
  assert.strictEqual(stdout, '/bin/busybox');
  assert.strictEqual(rows, 40);
  assert.strictEqual(cols, 120);
  console.log(`[PASS] Test 10 (BusyBox Symlink & TTY ioctl): /proc/self/exe="${stdout}", winsize=${rows}x${cols}`);
}

// ---------------------------------------------------------------------------
// Test 11: Interactive Ctrl-C (SIGINT) Signal Interruption
// ---------------------------------------------------------------------------
async function testSignalInterrupt() {
  // Infinite spin loop until interrupted by host SIGINT (exitCode = 128 + 2 = 130)
  const code = [
    A64.addImm(0, 0, 1),
    A64.b(-1),
  ];
  const { elf } = buildELF64(code);
  const kernel = new GuestKernel(new WasmDBT.DBTEngine());
  const proc = kernel.spawnELF(elf);
  // Schedule Ctrl-C (SIGINT) after 10ms while yielding periodically via sliceBudget
  const runPromise = (async () => {
    let ticks = 0;
    while (proc.state !== 'exited') {
      if (ticks === 5) kernel.sendSignal(proc.pid, SIG.SIGINT);
      if (kernel._deliverPendingSignals(proc)) break;
      proc.cpu.stepWasmLoop(1024);
      ticks++;
    }
    return proc.exitCode;
  })();
  const codeExit = await runPromise;
  assert.strictEqual(codeExit, 130, 'SIGINT should terminate with exitCode 130');
  console.log(`[PASS] Test 11 (Ctrl-C SIGINT Delivery): spin loop cleanly interrupted with exitCode=${codeExit}`);
}

(async () => {
  await testLoopAndBenchmark();
  await testIndirectBranchesDBT();
  await testCompactVMM();
  await testSuspendableAsyncSyscall();
  await testForkPipeWait();
  await testMuslISA();
  await testVFSAndArgv();
  await testForkExecvePipeline();
  await testMuslPrintfMemcpyISA();
  await testBusyBoxSymlinkAndTTY();
  await testSignalInterrupt();
  console.log('\nALL 11 TESTS PASSED.');
})().catch((err) => {
  console.error('TEST FAILED:', err);
  process.exit(1);
});
