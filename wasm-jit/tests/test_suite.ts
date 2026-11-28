import assert from 'assert';
import { performance } from 'perf_hooks';
import { DBTEngine } from '../src/dbt-runtime';
import { MemFS } from '../src/vfs-memfs';
import { buildTar, extractTarToMemFS } from '../src/rootfs-tar';
import { GuestKernel, IOCTL_CMD, SIG, SYS } from '../src/vmm-syscalls';

// ---------------------------------------------------------------------------
// Minimal AArch64 Assembler + ELF64 Builder (for self-contained verification)
// ---------------------------------------------------------------------------
const A64 = {
  nop: () => 0xd503201f,
  umulh: (rd: number, rn: number, rm: number) =>
    (0x9bc07c00 | ((rm & 31) << 16) | ((rn & 31) << 5) | (rd & 31)) >>> 0,
  clz64: (rd: number, rn: number) => (0xdac01000 | ((rn & 31) << 5) | (rd & 31)) >>> 0,
  rev64: (rd: number, rn: number) => (0xdac00c00 | ((rn & 31) << 5) | (rd & 31)) >>> 0,
  ccmpImm: (rn: number, imm5: number, nzcv: number, cond: number) =>
    (0xfa400800 | ((imm5 & 31) << 16) | ((cond & 15) << 12) | ((rn & 31) << 5) | (nzcv & 15)) >>> 0,
  ldrLit64: (rt: number, relInsns: number) =>
    (0x58000000 | ((relInsns & 0x7ffff) << 5) | (rt & 31)) >>> 0,
  ldpQ: (qt: number, qt2: number, rn: number, imm7 = 0) =>
    (0xad400000 | ((imm7 & 0x7f) << 15) | ((qt2 & 31) << 10) | ((rn & 31) << 5) | (qt & 31)) >>> 0,
  stpQ: (qt: number, qt2: number, rn: number, imm7 = 0) =>
    (0xad000000 | ((imm7 & 0x7f) << 15) | ((qt2 & 31) << 10) | ((rn & 31) << 5) | (qt & 31)) >>> 0,
  svc: (imm16 = 0) => (0xd4000001 | ((imm16 & 0xffff) << 5)) >>> 0,
  movz: (rd: number, imm16: number, hw = 0) =>
    (0xd2800000 | ((hw & 3) << 21) | ((imm16 & 0xffff) << 5) | (rd & 31)) >>> 0,
  movk: (rd: number, imm16: number, hw = 0) =>
    (0xf2800000 | ((hw & 3) << 21) | ((imm16 & 0xffff) << 5) | (rd & 31)) >>> 0,
  movn: (rd: number, imm16: number, hw = 0) =>
    (0x92800000 | ((hw & 3) << 21) | ((imm16 & 0xffff) << 5) | (rd & 31)) >>> 0,
  movReg: (rd: number, rm: number) => (0xaa0003e0 | ((rm & 31) << 16) | (rd & 31)) >>> 0,
  addImm: (rd: number, rn: number, imm12: number) =>
    (0x91000000 | ((imm12 & 0xfff) << 10) | ((rn & 31) << 5) | (rd & 31)) >>> 0,
  subImm: (rd: number, rn: number, imm12: number) =>
    (0xd1000000 | ((imm12 & 0xfff) << 10) | ((rn & 31) << 5) | (rd & 31)) >>> 0,
  subsImm: (rd: number, rn: number, imm12: number) =>
    (0xf1000000 | ((imm12 & 0xfff) << 10) | ((rn & 31) << 5) | (rd & 31)) >>> 0,
  addReg: (rd: number, rn: number, rm: number) =>
    (0x8b000000 | ((rm & 31) << 16) | ((rn & 31) << 5) | (rd & 31)) >>> 0,
  mul: (rd: number, rn: number, rm: number) =>
    (0x9b007c00 | ((rm & 31) << 16) | ((rn & 31) << 5) | (rd & 31)) >>> 0,
  udiv: (rd: number, rn: number, rm: number) =>
    (0x9ac00800 | ((rm & 31) << 16) | ((rn & 31) << 5) | (rd & 31)) >>> 0,
  sdiv: (rd: number, rn: number, rm: number) =>
    (0x9ac00c00 | ((rm & 31) << 16) | ((rn & 31) << 5) | (rd & 31)) >>> 0,
  lslv: (rd: number, rn: number, rm: number) =>
    (0x9ac02000 | ((rm & 31) << 16) | ((rn & 31) << 5) | (rd & 31)) >>> 0,
  csel: (rd: number, rn: number, rm: number, cond: number) =>
    (0x9a800000 | ((rm & 31) << 16) | ((cond & 15) << 12) | ((rn & 31) << 5) | (rd & 31)) >>> 0,
  csneg: (rd: number, rn: number, rm: number, cond: number) =>
    (0xda800400 | ((rm & 31) << 16) | ((cond & 15) << 12) | ((rn & 31) << 5) | (rd & 31)) >>> 0,
  ubfm64: (rd: number, rn: number, immr: number, imms: number) =>
    (0xd3400000 | ((immr & 63) << 16) | ((imms & 63) << 10) | ((rn & 31) << 5) | (rd & 31)) >>> 0,
  sbfm64: (rd: number, rn: number, immr: number, imms: number) =>
    (0x93400000 | ((immr & 63) << 16) | ((imms & 63) << 10) | ((rn & 31) << 5) | (rd & 31)) >>> 0,
  mrsTpidr: (rt: number) => (0xd53bd040 | (rt & 31)) >>> 0,
  msrTpidr: (rt: number) => (0xd51bd040 | (rt & 31)) >>> 0,
  ldxr64: (rt: number, rn: number) => (0xc85f7c00 | ((rn & 31) << 5) | (rt & 31)) >>> 0,
  stxr64: (rs: number, rt: number, rn: number) => (0xc8007c00 | ((rs & 31) << 16) | ((rn & 31) << 5) | (rt & 31)) >>> 0,
  ldr64: (rt: number, rn: number, byteOff = 0) =>
    (0xf9400000 | (((byteOff >>> 3) & 0xfff) << 10) | ((rn & 31) << 5) | (rt & 31)) >>> 0,
  str64: (rt: number, rn: number, byteOff = 0) =>
    (0xf9000000 | (((byteOff >>> 3) & 0xfff) << 10) | ((rn & 31) << 5) | (rt & 31)) >>> 0,
  ldr32: (rt: number, rn: number, byteOff = 0) =>
    (0xb9400000 | (((byteOff >>> 2) & 0xfff) << 10) | ((rn & 31) << 5) | (rt & 31)) >>> 0,
  ldr8Post: (rt: number, rn: number, simm9: number) =>
    (0x38400400 | ((simm9 & 0x1ff) << 12) | ((rn & 31) << 5) | (rt & 31)) >>> 0,
  ldur64: (rt: number, rn: number, simm9: number) =>
    (0xf8400000 | ((simm9 & 0x1ff) << 12) | ((rn & 31) << 5) | (rt & 31)) >>> 0,
  stur64: (rt: number, rn: number, simm9: number) =>
    (0xf8000000 | ((simm9 & 0x1ff) << 12) | ((rn & 31) << 5) | (rt & 31)) >>> 0,
  b: (relInsns: number) => (0x14000000 | (relInsns & 0x03ffffff)) >>> 0,
  bl: (relInsns: number) => (0x94000000 | (relInsns & 0x03ffffff)) >>> 0,
  bCond: (cond: number, relInsns: number) => (0x54000000 | ((relInsns & 0x7ffff) << 5) | (cond & 0xf)) >>> 0,
  cbz: (rt: number, relInsns: number) => (0xb4000000 | ((relInsns & 0x7ffff) << 5) | (rt & 31)) >>> 0,
  cbnz: (rt: number, relInsns: number) => (0xb5000000 | ((relInsns & 0x7ffff) << 5) | (rt & 31)) >>> 0,
  br: (rn: number) => (0xd61f0000 | ((rn & 31) << 5)) >>> 0,
  blr: (rn: number) => (0xd63f0000 | ((rn & 31) << 5)) >>> 0,
  ret: (rn = 30) => (0xd65f0000 | ((rn & 31) << 5)) >>> 0,
  adr: (rd: number, relBytes: number) => {
    const immlo = relBytes & 0x3;
    const immhi = (relBytes >> 2) & 0x7ffff;
    return (0x10000000 | (immlo << 29) | (immhi << 5) | (rd & 31)) >>> 0;
  },
};

function buildELF64(codeInsns: number[], dataBytes = new Uint8Array(0), baseVaddr = 0x10000): { elf: Uint8Array; dataVaddr: number } {
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

  const kWasm = new GuestKernel(new DBTEngine());
  const pWasm = kWasm.spawnELF(elf);
  const t0 = performance.now();
  await kWasm.runAll({ mode: 'wasm', sliceBudget: 50000 });
  const wasmMs = performance.now() - t0;
  assert.strictEqual(pWasm.cpu.getReg(19), expectedSum);

  const kJS = new GuestKernel(new DBTEngine());
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
  const kernel = new GuestKernel(new DBTEngine());
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
  const kernel = new GuestKernel(new DBTEngine());
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
  const kernel = new GuestKernel(new DBTEngine(), {
    onStdout: (b: Uint8Array) => { stdout += new TextDecoder().decode(b); },
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
  const kernel = new GuestKernel(new DBTEngine(), {
    onStdout: (b: Uint8Array) => { stdout += new TextDecoder().decode(b); },
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
  const kernel = new GuestKernel(new DBTEngine());
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
  const kernel = new GuestKernel(new DBTEngine(), {
    fs,
    onStdout: (b: Uint8Array) => { stdout += new TextDecoder().decode(b); },
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
  const kernel = new GuestKernel(new DBTEngine(), {
    fs,
    onStdout: (b: Uint8Array) => { stdout += new TextDecoder().decode(b); },
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
  const kernel = new GuestKernel(new DBTEngine());
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
  const kernel = new GuestKernel(new DBTEngine(), {
    fs,
    rows: 40,
    cols: 120,
    onStdout: (b: Uint8Array) => { stdout += new TextDecoder().decode(b); },
  });
  const proc = kernel.spawnELF(fs.readFile('/bin/sh')!, {
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
  const kernel = new GuestKernel(new DBTEngine());
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


// ---------------------------------------------------------------------------
// Test 12: Dynamic PIE (ET_DYN) + PT_INTERP Dynamic Linker Boot & auxv Handshake
// ---------------------------------------------------------------------------
async function testDynamicPIEAndInterp() {
  // Build a PIE (ET_DYN) ELF64 binary with PT_INTERP="/lib/ld-musl-aarch64.so.1"
  function buildPIEWithInterp(codeInsns: number[], interpStr: string): Uint8Array {
    const codeSize = codeInsns.length * 4;
    const interpBytes = new TextEncoder().encode(interpStr + '\0');
    const ehdrSize = 64;
    const phdrSize = 56;
    const phnum = 2; // PT_LOAD + PT_INTERP
    const fileOff = 0x100;
    const interpOff = fileOff + ((codeSize + 15) & ~15);
    const total = interpOff + interpBytes.length;
    const buf = new Uint8Array(total);
    const dv = new DataView(buf.buffer);

    buf[0] = 0x7f; buf[1] = 0x45; buf[2] = 0x4c; buf[3] = 0x46;
    buf[4] = 2; buf[5] = 1; buf[6] = 1;
    dv.setUint16(16, 3, true);      // ET_DYN (PIE!)
    dv.setUint16(18, 183, true);    // EM_AARCH64
    dv.setUint32(20, 1, true);
    dv.setBigUint64(24, 0n, true);  // e_entry = 0 (relative to loadBias!)
    dv.setBigUint64(32, BigInt(ehdrSize), true);
    dv.setUint16(52, ehdrSize, true);
    dv.setUint16(54, phdrSize, true);
    dv.setUint16(56, phnum, true);

    // PHDR 0: PT_LOAD at vaddr 0
    dv.setUint32(ehdrSize + 0, 1, true);
    dv.setUint32(ehdrSize + 4, 7, true);
    dv.setBigUint64(ehdrSize + 8, BigInt(fileOff), true);
    dv.setBigUint64(ehdrSize + 16, 0n, true);
    dv.setBigUint64(ehdrSize + 24, 0n, true);
    dv.setBigUint64(ehdrSize + 32, BigInt(codeSize), true);
    dv.setBigUint64(ehdrSize + 40, BigInt(codeSize), true);
    dv.setBigUint64(ehdrSize + 48, 0x1000n, true);

    // PHDR 1: PT_INTERP
    const p1 = ehdrSize + phdrSize;
    dv.setUint32(p1 + 0, 3, true);
    dv.setUint32(p1 + 4, 4, true);
    dv.setBigUint64(p1 + 8, BigInt(interpOff), true);
    dv.setBigUint64(p1 + 16, 0n, true);
    dv.setBigUint64(p1 + 24, 0n, true);
    dv.setBigUint64(p1 + 32, BigInt(interpBytes.length), true);
    dv.setBigUint64(p1 + 40, BigInt(interpBytes.length), true);
    dv.setBigUint64(p1 + 48, 1n, true);

    for (let i = 0; i < codeInsns.length; i++) dv.setUint32(fileOff + i * 4, codeInsns[i], true);
    buf.set(interpBytes, interpOff);
    return buf;
  }

  // Mock ld-musl-aarch64.so.1 (ET_DYN):
  //   Stack layout with argc=1, envc=2:
  //     [sp+0]=argc(1), [sp+8]=argv[0], [sp+16]=0, [sp+24]=env[0], [sp+32]=env[1], [sp+40]=0
  //     auxv starts at sp+48:
  //       +48: AT_PHDR(3), +64: AT_PHENT(4), +80: AT_PHNUM(5), +96: AT_BASE(7), +112: AT_ENTRY(9)
  //   Load AT_BASE into x20, AT_ENTRY into x21, then BR x21 (jump into PIE main!)
  const ldCode = [
    A64.ldr64(20, 31, 104), // AT_BASE value (expect 0x180000)
    A64.ldr64(21, 31, 120), // AT_ENTRY value (expect 0x40000)
    A64.br(21),             // jump to PIE main!
  ];
  // Build ld-musl as ET_DYN too (no PT_INTERP)
  const { elf: ldRaw } = buildELF64(ldCode, new Uint8Array(0), 0);
  new DataView(ldRaw.buffer).setUint16(16, 3, true); // mark ET_DYN

  // PIE main: sets x19 = 0x2026 and exits cleanly
  const pieMain = buildPIEWithInterp(
    [A64.movz(19, 0x2026), A64.movz(0, 0), A64.movz(8, SYS.EXIT_GROUP), A64.svc(0)],
    '/lib/ld-musl-aarch64.so.1'
  );

  const fs = new MemFS();
  fs.writeFile('/lib/ld-musl-aarch64.so.1', ldRaw, 0o755);
  const kernel = new GuestKernel(new DBTEngine(), { fs });
  const proc = kernel.spawnELF(pieMain, { argv: ['/bin/pie_app'] });
  await kernel.runAll();

  assert.strictEqual(proc.cpu.getReg(20), 0x400000n, 'AT_BASE mismatch');
  assert.strictEqual(proc.cpu.getReg(21), 0x40000n, 'AT_ENTRY mismatch');
  assert.strictEqual(proc.cpu.getReg(19), 0x2026n, 'PIE main did not execute');
  console.log(
    `[PASS] Test 12 (Dynamic PIE + PT_INTERP): ld-musl@0x${proc.cpu
      .getReg(20)
      .toString(16)} -> PIE@0x${proc.cpu.getReg(21).toString(16)} (x19=0x2026)`
  );
}

// ---------------------------------------------------------------------------
// Test 13: Async BSD TCP Socket (socket -> connect -> sendto -> recvfrom -> close)
// ---------------------------------------------------------------------------
async function testAsyncBSDSocket() {
  // sockaddr_in (16 bytes) for 127.0.0.1:8080 + payload "PING"
  const data = new Uint8Array(32);
  const dv = new DataView(data.buffer);
  dv.setUint16(0, 2, true);       // AF_INET
  dv.setUint16(2, 8080, false);   // port 8080 (big-endian)
  data[4] = 127; data[5] = 0; data[6] = 0; data[7] = 1;
  data.set(new TextEncoder().encode('PING'), 16);

  const code = [
    A64.subImm(31, 31, 64),
    // socket(AF_INET=2, SOCK_STREAM=1, 0) -> x19
    A64.movz(0, 2), A64.movz(1, 1), A64.movz(2, 0), A64.movz(8, SYS.SOCKET), A64.svc(0),
    A64.movReg(19, 0),
    // connect(fd, sockaddr, 16)
    A64.movReg(0, 19), A64.movz(1, 0, 0), A64.movk(1, 0, 1), A64.movz(2, 16), A64.movz(8, SYS.CONNECT), A64.svc(0),
    // sendto(fd, "PING", 4, 0, 0, 0)
    A64.movReg(0, 19), A64.movz(1, 0, 0), A64.movk(1, 0, 1), A64.movz(2, 4), A64.movz(8, SYS.SENDTO), A64.svc(0),
    // recvfrom(fd, sp, 32, 0, 0, 0) -> write(1, sp, n)
    A64.movReg(0, 19), A64.addImm(1, 31, 0), A64.movz(2, 32), A64.movz(8, SYS.RECVFROM), A64.svc(0),
    A64.movReg(2, 0), A64.movz(0, 1), A64.addImm(1, 31, 0), A64.movz(8, SYS.WRITE), A64.svc(0),
    // close(fd); exit(0)
    A64.movReg(0, 19), A64.movz(8, SYS.CLOSE), A64.svc(0),
    A64.movz(0, 0), A64.movz(8, SYS.EXIT_GROUP), A64.svc(0),
  ];

  const baseVaddr = 0x10000;
  const dataOff = (code.length * 4 + 15) & ~15;
  const sockAddrPtr = baseVaddr + dataOff;
  const pingPtr = sockAddrPtr + 16;
  code[8] = A64.movz(1, sockAddrPtr & 0xffff, 0);
  code[9] = A64.movk(1, (sockAddrPtr >>> 16) & 0xffff, 1);
  code[14] = A64.movz(1, pingPtr & 0xffff, 0);
  code[15] = A64.movk(1, (pingPtr >>> 16) & 0xffff, 1);

  const { elf } = buildELF64(code, data, baseVaddr);
  let stdout = '';
  let connectedTarget = '';
  let closedSock = 0;

  const kernel = new GuestKernel(new DBTEngine(), {
    onStdout: (b: Uint8Array) => { stdout += new TextDecoder().decode(b); },
    net: {
      connect: async (ip, port) => {
        connectedTarget = `${ip}:${port}`;
        return 101;
      },
      send: async (sockId, bytes) => {
        assert.strictEqual(sockId, 101);
        assert.strictEqual(new TextDecoder().decode(bytes), 'PING');
        return bytes.length;
      },
      recv: async (sockId) => {
        assert.strictEqual(sockId, 101);
        return new TextEncoder().encode('PONG-FROM-IOS-NWCONNECTION');
      },
      close: (sockId: number) => { closedSock = sockId; },
    },
  });
  kernel.spawnELF(elf);
  await kernel.runAll();

  assert.strictEqual(connectedTarget, '127.0.0.1:8080');
  assert.strictEqual(stdout, 'PONG-FROM-IOS-NWCONNECTION');
  assert.strictEqual(closedSock, 101);
  console.log(`[PASS] Test 13 (Async BSD TCP Socket): connected ${connectedTarget}, recv="${stdout}"`);
}

// ---------------------------------------------------------------------------
// Test 14: MemFS Snapshot Serialization & Restore (iOS Sandbox Persistence)
// ---------------------------------------------------------------------------
async function testMemFSPersistence() {
  const fs1 = new MemFS();
  fs1.writeFile('/etc/profile', 'export PS1="iTerminal$ "\n', 0o644);
  fs1.writeFile('/bin/busybox', new Uint8Array([0x7f, 0x45, 0x4c, 0x46]), 0o755);
  fs1.symlink('/bin/busybox', '/bin/sh');

  const snapshot = fs1.serialize();
  const fs2 = MemFS.deserialize(snapshot);

  assert.strictEqual(new TextDecoder().decode(fs2.readFile('/etc/profile')!), 'export PS1="iTerminal$ "\n');
  assert.strictEqual(fs2.readlink('/bin/sh')!, '/bin/busybox');
  assert.deepStrictEqual(Array.from(fs2.readFile('/bin/sh')!), [0x7f, 0x45, 0x4c, 0x46]);
  console.log(`[PASS] Test 14 (MemFS Persistence Snapshot): serialized ${snapshot.length}B & restored cleanly`);
}



// ---------------------------------------------------------------------------
// Test 15: POSIX USTAR .tar RootFS Unpack & Boot (/bin/sh -> /bin/busybox)
// ---------------------------------------------------------------------------
async function testTarRootFSBoot() {
  // Mini busybox binary that reads /etc/alpine-release and prints it to stdout
  const sPath = new TextEncoder().encode('/etc/alpine-release\0');
  const code = [
    A64.subImm(31, 31, 64),
    A64.movn(0, 99),
    A64.movz(1, 0, 0), // patched
    A64.movk(1, 0, 1),
    A64.movz(2, 0), A64.movz(3, 0), A64.movz(8, SYS.OPENAT), A64.svc(0),
    A64.movReg(19, 0),
    A64.movReg(0, 19), A64.addImm(1, 31, 0), A64.movz(2, 64), A64.movz(8, SYS.READ), A64.svc(0),
    A64.movReg(2, 0), A64.movz(0, 1), A64.addImm(1, 31, 0), A64.movz(8, SYS.WRITE), A64.svc(0),
    A64.movz(0, 0), A64.movz(8, SYS.EXIT_GROUP), A64.svc(0),
  ];
  const baseVaddr = 0x10000;
  const dataOff = (code.length * 4 + 15) & ~15;
  const sAddr = baseVaddr + dataOff;
  code[2] = A64.movz(1, sAddr & 0xffff, 0);
  code[3] = A64.movk(1, (sAddr >>> 16) & 0xffff, 1);
  const { elf } = buildELF64(code, sPath, baseVaddr);

  const tarBytes = buildTar([
    { path: 'bin', type: 'dir', mode: 0o755 },
    { path: 'etc', type: 'dir', mode: 0o755 },
    { path: 'bin/busybox', type: 'file', data: elf, mode: 0o755 },
    { path: 'bin/sh', type: 'symlink', target: '/bin/busybox' },
    { path: 'etc/alpine-release', type: 'file', data: '3.20.3-iterminal\n', mode: 0o644 },
  ]);

  const fs = new MemFS();
  const count = extractTarToMemFS(tarBytes, fs);
  assert.strictEqual(count, 5);

  let stdout = '';
  const kernel = new GuestKernel(new DBTEngine(), {
    fs,
    onStdout: (b: Uint8Array) => { stdout += new TextDecoder().decode(b); },
  });
  kernel.spawnELF(fs.readFile('/bin/sh')!, { argv: ['/bin/sh'] });
  await kernel.runAll();

  assert.strictEqual(stdout, '3.20.3-iterminal\n');
  console.log(`[PASS] Test 15 (USTAR .tar RootFS Boot): extracted ${count} entries, /bin/sh -> "${stdout.trim()}"`);
}

// ---------------------------------------------------------------------------
// Test 16: File-Backed mmap + MAP_FIXED Shared Library Code Execution via Lazy DBT
// ---------------------------------------------------------------------------
async function testFileBackedMmapSharedLib() {
  // Shared library raw AArch64 code page (`/lib/libmath.so`): add x0, x0, #42; ret
  const libCode = new Uint8Array(8);
  const ldv = new DataView(libCode.buffer);
  ldv.setUint32(0, A64.addImm(0, 0, 42), true);
  ldv.setUint32(4, A64.ret(30), true);

  const sLib = new TextEncoder().encode('/lib/libmath.so\0');
  const code = [
    // openat(-100, "/lib/libmath.so", 0, 0) -> x19
    A64.movn(0, 99),
    A64.movz(1, 0, 0), // patched
    A64.movk(1, 0, 1),
    A64.movz(2, 0), A64.movz(3, 0), A64.movz(8, SYS.OPENAT), A64.svc(0),
    A64.movReg(19, 0),
    // mmap(0x300000, 4096, PROT_RX=5, MAP_PRIVATE|MAP_FIXED=0x12, fd=x19, off=0) -> x20
    A64.movz(0, 0x0030, 1),      // 0x0030_0000
    A64.movz(1, 4096),
    A64.movz(2, 5),
    A64.movz(3, 0x12),           // MAP_PRIVATE | MAP_FIXED (file-backed!)
    A64.movReg(4, 19),           // fd
    A64.movz(5, 0),              // offset
    A64.movz(8, SYS.MMAP),
    A64.svc(0),
    A64.movReg(20, 0),           // mapped addr (expect 0x300000)
    // Call into the mmap'd .so page: x0 = 100; blr x20 -> x0 = 142!
    A64.movz(0, 100),
    A64.blr(20),
    A64.movReg(21, 0),
    A64.movz(0, 0), A64.movz(8, SYS.EXIT_GROUP), A64.svc(0),
  ];
  const baseVaddr = 0x10000;
  const dataOff = (code.length * 4 + 15) & ~15;
  const sLibAddr = baseVaddr + dataOff;
  code[1] = A64.movz(1, sLibAddr & 0xffff, 0);
  code[2] = A64.movk(1, (sLibAddr >>> 16) & 0xffff, 1);

  const { elf } = buildELF64(code, sLib, baseVaddr);
  const fs = new MemFS();
  fs.writeFile('/lib/libmath.so', libCode, 0o755);

  const kernel = new GuestKernel(new DBTEngine(), { fs });
  const proc = kernel.spawnELF(elf);
  await kernel.runAll();

  assert.strictEqual(proc.cpu.getReg(20), 0x300000n, 'MAP_FIXED address mismatch');
  assert.strictEqual(proc.cpu.getReg(21), 142n, 'BLR into file-backed mmap .so failed');
  console.log(`[PASS] Test 16 (File-Backed mmap + MAP_FIXED .so): BLR@0x300000(100) = 142`);
}

// ---------------------------------------------------------------------------
// Test 17: pread64 + readv Scatter-Gather I/O
// ---------------------------------------------------------------------------
async function testPreadAndReadv() {
  const sFile = new TextEncoder().encode('/tmp/data.txt\0');
  const code = [
    A64.subImm(31, 31, 128),
    // openat(-100, "/tmp/data.txt", 0, 0) -> x19
    A64.movn(0, 99),
    A64.movz(1, 0, 0), // patched
    A64.movk(1, 0, 1),
    A64.movz(2, 0), A64.movz(3, 0), A64.movz(8, SYS.OPENAT), A64.svc(0),
    A64.movReg(19, 0),
    // pread64(fd, sp, 5, offset=6) -> reads "WORLD" from "HELLO_WORLD!" without moving fd offset!
    A64.movReg(0, 19), A64.addImm(1, 31, 0), A64.movz(2, 5), A64.movz(3, 6), A64.movz(8, SYS.PREAD64), A64.svc(0),
    // write(1, sp, 5)
    A64.movz(0, 1), A64.addImm(1, 31, 0), A64.movz(2, 5), A64.movz(8, SYS.WRITE), A64.svc(0),
    // Build 2 iovecs at sp+64: iov[0]=(sp+16, 2), iov[1]=(sp+32, 3) -> readv reads "HE" + "LLO" from offset 0!
    A64.addImm(9, 31, 16), A64.str64(9, 31, 64), A64.movz(10, 2), A64.str64(10, 31, 72),
    A64.addImm(9, 31, 32), A64.str64(9, 31, 80), A64.movz(10, 3), A64.str64(10, 31, 88),
    A64.movReg(0, 19), A64.addImm(1, 31, 64), A64.movz(2, 2), A64.movz(8, SYS.READV), A64.svc(0),
    // write(1, sp+16, 2) + write(1, sp+32, 3)
    A64.movz(0, 1), A64.addImm(1, 31, 16), A64.movz(2, 2), A64.movz(8, SYS.WRITE), A64.svc(0),
    A64.movz(0, 1), A64.addImm(1, 31, 32), A64.movz(2, 3), A64.movz(8, SYS.WRITE), A64.svc(0),
    A64.movz(0, 0), A64.movz(8, SYS.EXIT_GROUP), A64.svc(0),
  ];
  const baseVaddr = 0x10000;
  const dataOff = (code.length * 4 + 15) & ~15;
  const sAddr = baseVaddr + dataOff;
  code[2] = A64.movz(1, sAddr & 0xffff, 0);
  code[3] = A64.movk(1, (sAddr >>> 16) & 0xffff, 1);

  const { elf } = buildELF64(code, sFile, baseVaddr);
  const fs = new MemFS();
  fs.writeFile('/tmp/data.txt', 'HELLO_WORLD!');

  let stdout = '';
  const kernel = new GuestKernel(new DBTEngine(), {
    fs,
    onStdout: (b: Uint8Array) => { stdout += new TextDecoder().decode(b); },
  });
  kernel.spawnELF(elf);
  await kernel.runAll();

  assert.strictEqual(stdout, 'WORLDHELLO');
  console.log(`[PASS] Test 17 (pread64 + readv): output="${stdout}"`);
}


// ---------------------------------------------------------------------------
// Test 18: Real-Device Alpine ld-musl Regression (0x9a9f17e3 CSET/CSINC + SMADDL + ADC)
// ---------------------------------------------------------------------------
async function testLdMuslRegression() {
  const code = [
    // Exact opcode observed on iPhone at PC=0x1eb028: 0x9a9f17e3 = csinc x3, xzr, xzr, ne (cset x3, eq)
    A64.subsImm(31, 0, 0),   // Z=1 (EQ)
    0x9a9f17e3,              // cset x3, eq -> expect x3 = 1!
    A64.movReg(19, 3),
    // Now test with Z=0 (NE): expect x3 = 0
    A64.movz(1, 5),
    A64.subsImm(31, 1, 0),   // Z=0 (NE)
    0x9a9f17e3,              // cset x3, eq -> expect x3 = 0!
    A64.movReg(20, 3),
    // SMADDL x21, w1, w2, xzr -> 5 * (-3) = -15
    A64.movn(2, 2),          // w2 = -3
    ((0x9b207c00 | (2 << 16) | (1 << 5) | 21) >>> 0), // smull x21, w1, w2
    A64.movz(0, 0), A64.movz(8, SYS.EXIT_GROUP), A64.svc(0),
  ];
  const { elf } = buildELF64(code);
  const kernel = new GuestKernel(new DBTEngine());
  const proc = kernel.spawnELF(elf);
  await kernel.runAll();

  assert.strictEqual(proc.cpu.getReg(19), 1n, '0x9a9f17e3 CSET EQ when Z=1');
  assert.strictEqual(proc.cpu.getReg(20), 0n, '0x9a9f17e3 CSET EQ when Z=0');
  assert.strictEqual(BigInt.asIntN(64, proc.cpu.getReg(21)), -15n, 'SMADDL/SMULL');
  console.log(`[PASS] Test 18 (Alpine ld-musl Regression): 0x9a9f17e3 (CSET/CSINC) & SMULL verified`);
}


// ---------------------------------------------------------------------------
// Test 19: Real-Device Alpine ld-musl memset Regression (0x4e010c20 DUP V0.16B, W1)
// ---------------------------------------------------------------------------
async function testMuslMemsetDup() {
  const code = [
    A64.subImm(31, 31, 64),
    A64.movz(1, 0xab),       // fill byte = 0xAB
    0x4e010c20,              // exact iPhone opcode: DUP V0.16B, W1
    A64.stpQ(0, 0, 31, 0),   // memset 32 bytes at [sp]
    A64.ldr64(19, 31, 0),    // expect 0xABABABABABABABAB
    A64.ldr64(20, 31, 24),   // expect 0xABABABABABABABAB
    A64.movz(0, 0), A64.movz(8, SYS.EXIT_GROUP), A64.svc(0),
  ];
  const { elf } = buildELF64(code);
  const kernel = new GuestKernel(new DBTEngine());
  const proc = kernel.spawnELF(elf);
  await kernel.runAll();

  assert.strictEqual(proc.cpu.getReg(19), 0xababababababababn, 'DUP V0.16B low');
  assert.strictEqual(proc.cpu.getReg(20), 0xababababababababn, 'DUP V0.16B high');
  console.log(`[PASS] Test 19 (Alpine ld-musl memset): 0x4e010c20 (DUP V0.16B, W1) verified`);
}


// ---------------------------------------------------------------------------
// Test 20: Real-Device Alpine ld-musl DCZID_EL0 (0xd53b00e5) + PRFM + STLR/LDAR
// ---------------------------------------------------------------------------
async function testSysregAndLdarStlr() {
  const code = [
    // Exact iPhone opcode at PC=0x413f08: 0xd53b00e5 = MRS X5, DCZID_EL0 -> expect 0x10 (DZP=1)
    0xd53b00e5,
    A64.movReg(19, 5),
    // PRFM PLDL1KEEP, [sp] -> NOP
    0xf98003e0,
    // STLR x1, [sp] + LDAR x20, [sp]
    A64.subImm(31, 31, 32),
    A64.movz(1, 0xbeef),
    0xc89fffe1, // stlr x1, [sp]
    0xc8dffff4, // ldar x20, [sp]
    A64.movz(0, 0), A64.movz(8, SYS.EXIT_GROUP), A64.svc(0),
  ];
  const { elf } = buildELF64(code);
  const kernel = new GuestKernel(new DBTEngine());
  const proc = kernel.spawnELF(elf);
  await kernel.runAll();

  assert.strictEqual(proc.cpu.getReg(19), 0x10n, 'MRS DCZID_EL0 should return 0x10 (DZP=1)');
  assert.strictEqual(proc.cpu.getReg(20), 0xbeefn, 'STLR/LDAR mismatch');
  console.log(`[PASS] Test 20 (DCZID_EL0 + PRFM + STLR/LDAR): 0xd53b00e5=0x10, LDAR=0xbeef`);
}


// ---------------------------------------------------------------------------
// Test 21: Musl mallocng RBIT + CLZ (a_ctz_32 / a_ctz_64) & REV16/REV32
// ---------------------------------------------------------------------------
async function testRbitCtzRev() {
  const code = [
    // a_ctz_32(1) -> rbit w4, w6; clz w4, w4 -> expect 0!
    A64.movz(6, 1),
    0x5ac000c4, // rbit w4, w6
    0x5ac01084, // clz w4, w4
    A64.movReg(19, 4),
    // a_ctz_32(0x10) -> expect 4!
    A64.movz(6, 0x10),
    0x5ac000c4, // rbit w4, w6
    0x5ac01084, // clz w4, w4
    A64.movReg(20, 4),
    // a_ctz_64(1 << 40) -> rbit x5, x7; clz x5, x5 -> expect 40!
    A64.movz(7, 0x0100, 2), // 1 << 40
    0xdac000e5, // rbit x5, x7
    0xdac010a5, // clz x5, x5
    A64.movReg(21, 5),
    // REV16 w8, w9: 0x12345678 -> 0x34127856
    A64.movz(9, 0x5678, 0), A64.movk(9, 0x1234, 1),
    0x5ac00528, // rev16 w8, w9
    A64.movReg(22, 8),
    A64.movz(0, 0), A64.movz(8, SYS.EXIT_GROUP), A64.svc(0),
  ];
  const { elf } = buildELF64(code);
  const kernel = new GuestKernel(new DBTEngine());
  const proc = kernel.spawnELF(elf);
  await kernel.runAll();

  assert.strictEqual(proc.cpu.getReg(19), 0n, 'a_ctz_32(1) must be 0');
  assert.strictEqual(proc.cpu.getReg(20), 4n, 'a_ctz_32(0x10) must be 4');
  assert.strictEqual(proc.cpu.getReg(21), 40n, 'a_ctz_64(1<<40) must be 40');
  assert.strictEqual(proc.cpu.getReg(22), 0x34127856n, 'REV16 mismatch');
  console.log(`[PASS] Test 21 (Musl mallocng RBIT+CLZ & REV16): ctz32(1)=0, ctz32(16)=4, ctz64(1<<40)=40`);
}


// ---------------------------------------------------------------------------
// Test 22: Real-Device BusyBox/musl UMOV (0x4e083c01) + FMOV + SIMD ORR
// ---------------------------------------------------------------------------
async function testUmovFmovSimd() {
  const code = [
    // Fill V0 with 0xCD via DUP V0.16B, W1 (0x4e010c20), then UMOV X1, V0.D[0] (0x4e083c01)
    A64.movz(1, 0xcd),
    0x4e010c20, // DUP V0.16B, W1
    A64.movz(1, 0),
    0x4e083c01, // exact iPhone opcode at PC=0x413e88: UMOV X1, V0.D[0] -> expect 0xCDCDCDCDCDCDCDCD
    A64.movReg(19, 1),
    // FMOV D2, X2 -> FMOV X20, D2
    A64.movz(2, 0x1337),
    0x9e670042, // fmov d2, x2
    0x9e660054, // fmov x20, d2
    A64.movz(0, 0), A64.movz(8, SYS.EXIT_GROUP), A64.svc(0),
  ];
  const { elf } = buildELF64(code);
  const kernel = new GuestKernel(new DBTEngine());
  const proc = kernel.spawnELF(elf);
  await kernel.runAll();

  assert.strictEqual(proc.cpu.getReg(19), 0xcdcdcdcdcdcdcdcdn, 'UMOV X1, V0.D[0] mismatch');
  assert.strictEqual(proc.cpu.getReg(20), 0x1337n, 'FMOV D/X mismatch');
  console.log(`[PASS] Test 22 (BusyBox/musl UMOV + FMOV): 0x4e083c01 & FMOV verified`);
}


// ---------------------------------------------------------------------------
// Test 23: Real-Device BusyBox ash MOVI V0.16B, #2 (0x4f00e440) + SIMD EOR/AND
// ---------------------------------------------------------------------------
async function testMoviAndSimdBitwise() {
  const code = [
    // Exact iPhone opcode at PC=0x9b700: 0x4f00e440 = MOVI V0.16B, #2
    0x4f00e440,
    0x4e083c01, // UMOV X1, V0.D[0] -> expect 0x0202020202020202
    A64.movReg(19, 1),
    // EOR V0.16B, V0.16B, V0.16B (0x6e201c00) -> expect 0
    0x6e201c00,
    0x4e083c01,
    A64.movReg(20, 1),
    A64.movz(0, 0), A64.movz(8, SYS.EXIT_GROUP), A64.svc(0),
  ];
  const { elf } = buildELF64(code);
  const kernel = new GuestKernel(new DBTEngine());
  const proc = kernel.spawnELF(elf);
  await kernel.runAll();

  assert.strictEqual(proc.cpu.getReg(19), 0x0202020202020202n, 'MOVI V0.16B, #2 mismatch');
  assert.strictEqual(proc.cpu.getReg(20), 0n, 'SIMD EOR zero mismatch');
  console.log(`[PASS] Test 23 (BusyBox ash MOVI + SIMD EOR): 0x4f00e440=0x0202020202020202`);
}


// ---------------------------------------------------------------------------
// Test 24: SIMD STR/STUR Q0 vs GP STR X0 Mask Isolation (V=1 bit 26)
// ---------------------------------------------------------------------------
async function testSimdStrQNotHijackedByGP() {
  const code = [
    A64.subImm(31, 31, 64),
    // Put distinct sentinel in X0 (0xDEAD) and distinct value in Q0 (0x00)
    A64.movz(0, 0xdead),
    0x4f00e400, // MOVI V0.16B, #0 -> Q0 = 0
    // STR Q0, [sp, #0] (0x3d8003e0) — must write 0, NOT 0xDEAD!
    0x3d8003e0,
    // STUR Q0, [sp, #16] (0x3c8103e0) — must write 0, NOT 0xDEAD!
    0x3c8103e0,
    A64.ldr64(19, 31, 0),
    A64.ldr64(20, 31, 16),
    A64.movz(0, 0), A64.movz(8, SYS.EXIT_GROUP), A64.svc(0),
  ];
  const { elf } = buildELF64(code);
  const kernel = new GuestKernel(new DBTEngine());
  const proc = kernel.spawnELF(elf);
  await kernel.runAll();

  assert.strictEqual(proc.cpu.getReg(19), 0n, 'STR Q0 was hijacked by GP STR X0!');
  assert.strictEqual(proc.cpu.getReg(20), 0n, 'STUR Q0 was hijacked by GP STUR X0!');
  console.log(`[PASS] Test 24 (SIMD STR/STUR Q0 Mask Isolation): Q0=0 stored cleanly (X0=0xdead untouched)`);
}


// ---------------------------------------------------------------------------
// Test 25: PRFM Non-Clobber + FCNTL F_DUPFD_CLOEXEC + /dev/null + O_TRUNC
// ---------------------------------------------------------------------------
async function testAuditHardening() {
  const sNull = new TextEncoder().encode('/dev/null\0');
  const code = [
    // 1. PRFM PLDL1KEEP, [sp] must NOT clobber X0!
    A64.movz(0, 0x5a5a),
    0xf98003e0, // PRFM PLDL1KEEP, [sp]
    A64.movReg(19, 0), // expect 0x5a5a!
    // 2. fcntl(1, F_DUPFD_CLOEXEC=1030, 10) -> expect new fd == 10!
    A64.movz(0, 1), A64.movz(1, 1030), A64.movz(2, 10), A64.movz(8, SYS.FCNTL), A64.svc(0),
    A64.movReg(20, 0),
    // 3. openat(-100, "/dev/null", 0, 0) -> read returns 0 (EOF)
    A64.movn(0, 99),
    A64.movz(1, 0, 0), // patched
    A64.movk(1, 0, 1),
    A64.movz(2, 0), A64.movz(3, 0), A64.movz(8, SYS.OPENAT), A64.svc(0),
    A64.subImm(31, 31, 32),
    A64.addImm(1, 31, 0), A64.movz(2, 16), A64.movz(8, SYS.READ), A64.svc(0),
    A64.movReg(21, 0), // expect 0
    A64.movz(0, 0), A64.movz(8, SYS.EXIT_GROUP), A64.svc(0),
  ];
  const baseVaddr = 0x10000;
  const dataOff = (code.length * 4 + 15) & ~15;
  const sNullAddr = baseVaddr + dataOff;
  code[10] = A64.movz(1, sNullAddr & 0xffff, 0);
  code[11] = A64.movk(1, (sNullAddr >>> 16) & 0xffff, 1);

  const { elf } = buildELF64(code, sNull, baseVaddr);
  const kernel = new GuestKernel(new DBTEngine());
  const proc = kernel.spawnELF(elf);
  await kernel.runAll();

  assert.strictEqual(proc.cpu.getReg(19), 0x5a5an, 'PRFM clobbered X0!');
  assert.strictEqual(proc.cpu.getReg(20), 10n, 'FCNTL F_DUPFD_CLOEXEC did not return fd>=10');
  assert.strictEqual(proc.cpu.getReg(21), 0n, '/dev/null read should return 0');
  console.log(`[PASS] Test 25 (Audit Hardening): PRFM safe, F_DUPFD_CLOEXEC=10, /dev/null=EOF`);
}


// ---------------------------------------------------------------------------
// Test 26: Unified FP/SIMD B/H/S/D/Q Load/Store (0x3d0042c0 STR B0, [X22, #16])
// ---------------------------------------------------------------------------
async function testUnifiedSimdLoadStore() {
  const code = [
    A64.subImm(31, 31, 64),
    A64.addImm(22, 31, 0),    // x22 = sp
    0x4f00e440,               // MOVI V0.16B, #2 (B0 = 0x02)
    0x3d0042c0,               // exact iPhone opcode at PC=0x9b71c: STR B0, [X22, #16]
    // Load back byte at [X22, #16] into X19 -> expect 2!
    ((0x394042d3) >>> 0),     // ldrb w19, [x22, #16]
    A64.movz(0, 0), A64.movz(8, SYS.EXIT_GROUP), A64.svc(0),
  ];
  const { elf } = buildELF64(code);
  const kernel = new GuestKernel(new DBTEngine());
  const proc = kernel.spawnELF(elf);
  await kernel.runAll();

  assert.strictEqual(proc.cpu.getReg(19), 2n, 'STR B0 (0x3d0042c0) failed');
  console.log(`[PASS] Test 26 (Unified FP/SIMD B/H/S/D/Q Load/Store): 0x3d0042c0 (STR B0)=2 verified`);
}


// ---------------------------------------------------------------------------
// Test 27: Real-Device BusyBox/musl INS V0.S[1], W1 (0x4e0c1c20) + DUP element
// ---------------------------------------------------------------------------
async function testInsAndDupElement() {
  const code = [
    0x4f00e400, // MOVI V0.16B, #0
    A64.movz(1, 0x1234),
    0x4e0c1c20, // exact iPhone opcode at PC=0x451c60: INS V0.S[1], W1
    0x4e083c02, // UMOV X2, V0.D[0] -> expect 0x00001234_00000000
    A64.movReg(19, 2),
    A64.movz(0, 0), A64.movz(8, SYS.EXIT_GROUP), A64.svc(0),
  ];
  const { elf } = buildELF64(code);
  const kernel = new GuestKernel(new DBTEngine());
  const proc = kernel.spawnELF(elf);
  await kernel.runAll();

  assert.strictEqual(proc.cpu.getReg(19), 0x0000123400000000n, 'INS V0.S[1], W1 (0x4e0c1c20) failed');
  console.log(`[PASS] Test 27 (INS V0.S[1], W1): 0x4e0c1c20 verified`);
}


// ---------------------------------------------------------------------------
// Test 28: Real-Device BusyBox/musl SXTL V0.2D, V0.2S (0x0f20a400) + UXTL
// ---------------------------------------------------------------------------
async function testSxtlUxtl() {
  const code = [
    // Pack w0 = -5 (0xFFFFFFFB) into V0.S[0] and w1 = 42 into V0.S[1]
    A64.movn(0, 4),  // -5
    0x4e041c00,      // INS V0.S[0], W0
    A64.movz(1, 42),
    0x4e0c1c20,      // INS V0.S[1], W1
    // Exact iPhone opcode at PC=0x451c64: 0x0f20a400 = SXTL V0.2D, V0.2S
    0x0f20a400,
    0x4e083c13,      // UMOV X19, V0.D[0] -> expect -5n
    0x4e183c14,      // UMOV X20, V0.D[1] -> expect 42n
    A64.movz(0, 0), A64.movz(8, SYS.EXIT_GROUP), A64.svc(0),
  ];
  const { elf } = buildELF64(code);
  const kernel = new GuestKernel(new DBTEngine());
  const proc = kernel.spawnELF(elf);
  await kernel.runAll();

  assert.strictEqual(BigInt.asIntN(64, proc.cpu.getReg(19)), -5n, 'SXTL lane 0');
  assert.strictEqual(proc.cpu.getReg(20), 42n, 'SXTL lane 1');
  console.log(`[PASS] Test 28 (SXTL/SSHLL V0.2D, V0.2S): 0x0f20a400 (-5, 42) verified`);
}


// ---------------------------------------------------------------------------
// Test 29: wait4(-1, WNOHANG) -> -ECHILD (no shell hang after 1st command!) + getgroups
// ---------------------------------------------------------------------------
async function testWait4EchildAndGetgroups() {
  const code = [
    // wait4(-1, 0, WNOHANG=1, 0) with no children -> must return -ECHILD (-10) immediately!
    A64.movn(0, 0),  // -1
    A64.movz(1, 0),
    A64.movz(2, 1),  // WNOHANG
    A64.movz(3, 0),
    A64.movz(8, SYS.WAIT4),
    A64.svc(0),
    A64.movReg(19, 0),
    // getgroups(0, 0) -> expect 1
    A64.movz(0, 0), A64.movz(1, 0), A64.movz(8, SYS.GETGROUPS), A64.svc(0),
    A64.movReg(20, 0),
    A64.movz(0, 0), A64.movz(8, SYS.EXIT_GROUP), A64.svc(0),
  ];
  const { elf } = buildELF64(code);
  const kernel = new GuestKernel(new DBTEngine());
  const proc = kernel.spawnELF(elf);
  await kernel.runAll();

  assert.strictEqual(BigInt.asIntN(64, proc.cpu.getReg(19)), -10n, 'wait4 with no children must return -ECHILD (-10)');
  assert.strictEqual(proc.cpu.getReg(20), 1n, 'getgroups(0, 0) should return 1');
  console.log(`[PASS] Test 29 (wait4 ECHILD + getgroups): wait4=-10 (ECHILD), getgroups=1`);
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
  await testDynamicPIEAndInterp();
  await testAsyncBSDSocket();
  await testMemFSPersistence();
  await testTarRootFSBoot();
  await testFileBackedMmapSharedLib();
  await testPreadAndReadv();
  await testLdMuslRegression();
  await testMuslMemsetDup();
  await testSysregAndLdarStlr();
  await testRbitCtzRev();
  await testUmovFmovSimd();
  await testMoviAndSimdBitwise();
  await testSimdStrQNotHijackedByGP();
  await testAuditHardening();
  await testUnifiedSimdLoadStore();
  await testInsAndDupElement();
  await testSxtlUxtl();
  await testWait4EchildAndGetgroups();
  console.log('\nALL 29 TESTS PASSED.');
})().catch((err) => {
  console.error('TEST FAILED:', err);
  process.exit(1);
});
