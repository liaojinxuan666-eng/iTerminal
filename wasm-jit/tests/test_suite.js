'use strict';

const assert = require('assert');
const { performance } = require('perf_hooks');
const WasmDBT = require('../src/dbt-runtime');
const { SYS, GuestKernel } = require('../src/vmm-syscalls');

// ---------------------------------------------------------------------------
// Minimal AArch64 Assembler + ELF64 Builder (for self-contained verification)
// ---------------------------------------------------------------------------
const A64 = {
  nop: () => 0xd503201f,
  svc: (imm16 = 0) => (0xd4000001 | ((imm16 & 0xffff) << 5)) >>> 0,
  movz: (rd, imm16, hw = 0) =>
    (0xd2800000 | ((hw & 3) << 21) | ((imm16 & 0xffff) << 5) | (rd & 31)) >>> 0,
  movk: (rd, imm16, hw = 0) =>
    (0xf2800000 | ((hw & 3) << 21) | ((imm16 & 0xffff) << 5) | (rd & 31)) >>> 0,
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
  // Unsigned offset LDR/STR 64-bit (byteOff must be multiple of 8)
  ldr64: (rt, rn, byteOff = 0) =>
    (0xf9400000 | (((byteOff >>> 3) & 0xfff) << 10) | ((rn & 31) << 5) | (rt & 31)) >>> 0,
  str64: (rt, rn, byteOff = 0) =>
    (0xf9000000 | (((byteOff >>> 3) & 0xfff) << 10) | ((rn & 31) << 5) | (rt & 31)) >>> 0,
  ldr32: (rt, rn, byteOff = 0) =>
    (0xb9400000 | (((byteOff >>> 2) & 0xfff) << 10) | ((rn & 31) << 5) | (rt & 31)) >>> 0,
  str8: (rt, rn, byteOff = 0) =>
    (0x39000000 | ((byteOff & 0xfff) << 10) | ((rn & 31) << 5) | (rt & 31)) >>> 0,
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

  // ELF Header
  buf[0] = 0x7f; buf[1] = 0x45; buf[2] = 0x4c; buf[3] = 0x46;
  buf[4] = 2; // ELF64
  buf[5] = 1; // Little-endian
  buf[6] = 1; // Version
  dv.setUint16(16, 2, true);      // ET_EXEC
  dv.setUint16(18, 183, true);    // EM_AARCH64
  dv.setUint32(20, 1, true);
  dv.setBigUint64(24, BigInt(baseVaddr), true); // e_entry
  dv.setBigUint64(32, BigInt(ehdrSize), true);  // e_phoff
  dv.setUint16(52, ehdrSize, true);
  dv.setUint16(54, phdrSize, true);
  dv.setUint16(56, 1, true);      // e_phnum = 1

  // PT_LOAD Program Header
  dv.setUint32(ehdrSize + 0, 1, true); // PT_LOAD
  dv.setUint32(ehdrSize + 4, 7, true); // RWX
  dv.setBigUint64(ehdrSize + 8, BigInt(fileOffset), true);
  dv.setBigUint64(ehdrSize + 16, BigInt(baseVaddr), true);
  dv.setBigUint64(ehdrSize + 24, BigInt(baseVaddr), true);
  dv.setBigUint64(ehdrSize + 32, BigInt(segSize), true);
  dv.setBigUint64(ehdrSize + 40, BigInt(segSize), true);
  dv.setBigUint64(ehdrSize + 48, 0x1000n, true);

  for (let i = 0; i < codeInsns.length; i++) {
    dv.setUint32(fileOffset + i * 4, codeInsns[i], true);
  }
  if (dataBytes.length) {
    buf.set(dataBytes, fileOffset + dataOffsetInSeg);
  }
  return { elf: buf, dataVaddr: baseVaddr + dataOffsetInSeg };
}

// ---------------------------------------------------------------------------
// Test 1: Tight Loop + WASM-Internal Dispatch vs JS-per-BB Benchmark
// ---------------------------------------------------------------------------
async function testLoopAndBenchmark() {
  const N = 200000;
  // x0 = 0 (sum), x1 = N (counter)
  // loop: x0 += x1; x1 -= 1; cbnz x1, loop
  // exit(x0 & 0xff)
  const code = [
    A64.movz(0, 0),
    A64.movz(1, N & 0xffff, 0),
    A64.movk(1, (N >>> 16) & 0xffff, 1),
    // loop (idx 3):
    A64.addReg(0, 0, 1),
    A64.subsImm(1, 1, 1),
    A64.bCond(1, -2), // B.NE back to idx 3
    // store 64-bit result in x19 so we can inspect it, then exit(0)
    A64.movReg(19, 0),
    A64.movz(0, 0),
    A64.movz(8, SYS.EXIT_GROUP),
    A64.svc(0),
  ];
  const { elf } = buildELF64(code);
  const expectedSum = (BigInt(N) * BigInt(N + 1)) / 2n;

  // Run with WASM-internal dispatch loop
  const engineWasm = new WasmDBT.DBTEngine();
  const kWasm = new GuestKernel(engineWasm);
  const pWasm = kWasm.spawnELF(elf);
  const t0 = performance.now();
  await kWasm.runAll({ mode: 'wasm', sliceBudget: 50000 });
  const wasmMs = performance.now() - t0;
  assert.strictEqual(pWasm.cpu.getReg(19), expectedSum, 'WASM loop sum mismatch');

  // Run with JS-per-block dispatch (v1 baseline)
  const engineJS = new WasmDBT.DBTEngine();
  const kJS = new GuestKernel(engineJS);
  const pJS = kJS.spawnELF(elf);
  const t1 = performance.now();
  await kJS.runAll({ mode: 'js', sliceBudget: 50000 });
  const jsMs = performance.now() - t1;
  assert.strictEqual(pJS.cpu.getReg(19), expectedSum, 'JS loop sum mismatch');

  const speedup = jsMs / wasmMs;
  console.log(
    `[PASS] Test 1 (Loop ${N.toLocaleString()} iters): sum=${expectedSum} | WASM-loop=${wasmMs.toFixed(
      2
    )}ms vs JS-per-BB=${jsMs.toFixed(2)}ms (${speedup.toFixed(2)}x speedup)`
  );
}

// ---------------------------------------------------------------------------
// Test 2: Indirect Branches (BLR / RET / BR) & On-Device Lazy DBT
// ---------------------------------------------------------------------------
async function testIndirectBranchesDBT() {
  // main:
  //   adr x9, fn_square     (runtime function pointer)
  //   mov x0, #12
  //   blr x9                (indirect call -> lazy DBT compiles fn_square!)
  //   mov x19, x0           (expect 144)
  //   mov x0, #0; mov x8, #94; svc #0
  // fn_square:
  //   mul x0, x0, x0
  //   ret
  const code = [
    A64.adr(9, 6 * 4),      // idx 0: x9 = PC + 24 -> idx 6 (fn_square)
    A64.movz(0, 12),        // idx 1
    A64.blr(9),             // idx 2: indirect call!
    A64.movReg(19, 0),      // idx 3: save result
    A64.movz(0, 0),         // idx 4
    A64.movz(8, SYS.EXIT_GROUP), // idx 5 -- wait: let's put svc at idx 6 and fn_square at idx 7
  ];
  // Rebuild with exact offsets:
  const code2 = [
    A64.adr(9, 7 * 4),           // 0: x9 -> idx 7 (fn_square)
    A64.movz(0, 12),             // 1
    A64.blr(9),                  // 2: indirect call -> lazy DBT
    A64.movReg(19, 0),           // 3
    A64.movz(0, 0),              // 4
    A64.movz(8, SYS.EXIT_GROUP), // 5
    A64.svc(0),                  // 6
    // idx 7: fn_square(x0) -> x0 * x0
    A64.mul(0, 0, 0),            // 7
    A64.ret(30),                 // 8: indirect return!
  ];
  const { elf } = buildELF64(code2);
  const engine = new WasmDBT.DBTEngine();
  const kernel = new GuestKernel(engine);
  const proc = kernel.spawnELF(elf);
  await kernel.runAll();

  assert.strictEqual(proc.cpu.getReg(19), 144n, 'BLR/RET indirect branch result mismatch');
  assert(proc.cpu.compiledBlocks >= 3, 'Expected lazy compilation of at least 3 blocks');
  console.log(
    `[PASS] Test 2 (Indirect BLR/RET & Lazy DBT): 12^2=${proc.cpu.getReg(
      19
    )}, lazily compiled ${proc.cpu.compiledBlocks} blocks`
  );
}

// ---------------------------------------------------------------------------
// Test 3: Compact 32-bit VMM (brk + mmap + munmap)
// ---------------------------------------------------------------------------
async function testCompactVMM() {
  // 1. x19 = brk(0)
  // 2. x20 = brk(x19 + 8192)
  // 3. write 0x12345678 at [x19 + 4096], read back into x21
  // 4. x22 = mmap(0, 8192, PROT_RW, MAP_ANON)
  // 5. write 0xCAFE at [x22 + 8], read back into x23
  // 6. munmap(x22, 8192) -> x24 = 0
  // 7. exit(0)
  const code = [
    A64.movz(0, 0),
    A64.movz(8, SYS.BRK),
    A64.svc(0),
    A64.movReg(19, 0),           // x19 = old brk

    A64.addImm(0, 19, 4095),
    A64.addImm(0, 0, 4095),      // x0 = old brk + 8190
    A64.movz(8, SYS.BRK),
    A64.svc(0),
    A64.movReg(20, 0),           // x20 = new brk

    A64.movz(1, 0x5678, 0),
    A64.movk(1, 0x1234, 1),
    A64.str64(1, 19, 4096),
    A64.ldr64(21, 19, 4096),     // x21 = 0x12345678

    // mmap(0, 8192, 3, 0x22)
    A64.movz(0, 0),
    A64.movz(1, 8192),
    A64.movz(2, 3),
    A64.movz(3, 0x22),
    A64.movz(8, SYS.MMAP),
    A64.svc(0),
    A64.movReg(22, 0),           // x22 = mmap addr

    A64.movz(1, 0xcafe),
    A64.str64(1, 22, 8),
    A64.ldr64(23, 22, 8),        // x23 = 0xcafe

    // munmap(x22, 8192)
    A64.movReg(0, 22),
    A64.movz(1, 8192),
    A64.movz(8, SYS.MUNMAP),
    A64.svc(0),
    A64.movReg(24, 0),           // x24 = 0

    A64.movz(0, 0),
    A64.movz(8, SYS.EXIT_GROUP),
    A64.svc(0),
  ];
  const { elf } = buildELF64(code);
  const kernel = new GuestKernel(new WasmDBT.DBTEngine());
  const proc = kernel.spawnELF(elf);
  await kernel.runAll();

  assert.strictEqual(proc.cpu.getReg(21), 0x12345678n);
  assert.strictEqual(proc.cpu.getReg(23), 0xcafen);
  assert.strictEqual(proc.cpu.getReg(24), 0n);
  assert(proc.cpu.getReg(22) >= 0x200000n && proc.cpu.getReg(22) < 0x7fff0000n);
  console.log(
    `[PASS] Test 3 (Compact 32-bit VMM): brk=0x${proc.cpu
      .getReg(19)
      .toString(16)}->0x${proc.cpu.getReg(20).toString(16)}, mmap=0x${proc.cpu
      .getReg(22)
      .toString(16)}, munmap=0`
  );
}

// ---------------------------------------------------------------------------
// Test 4: Suspendable Async Syscall (Simulated Async Swift PTY stdin read)
// ---------------------------------------------------------------------------
async function testSuspendableAsyncSyscall() {
  // Allocate buffer on stack (sp - 64), read(0, buf, 64) [async!], write(1, buf, n), exit(0)
  const code = [
    A64.subImm(31, 31, 64),      // sp -= 64
    A64.movz(0, 0),              // fd = 0 (stdin)
    A64.addImm(1, 31, 0),        // buf = sp
    A64.movz(2, 64),             // len = 64
    A64.movz(8, SYS.READ),
    A64.svc(0),                  // SUSPENDS until Swift/host Promise resolves!

    A64.movReg(2, 0),            // len = bytes read
    A64.movz(0, 1),              // fd = 1 (stdout)
    A64.addImm(1, 31, 0),        // buf = sp
    A64.movz(8, SYS.WRITE),
    A64.svc(0),

    A64.movz(0, 0),
    A64.movz(8, SYS.EXIT_GROUP),
    A64.svc(0),
  ];
  const { elf } = buildELF64(code);
  let stdout = '';
  const dec = new TextDecoder();
  const enc = new TextEncoder();

  const kernel = new GuestKernel(new WasmDBT.DBTEngine(), {
    onStdout: (b) => {
      stdout += dec.decode(b);
    },
    readStdinAsync: () =>
      new Promise((resolve) => {
        setTimeout(() => resolve(enc.encode('hello from async iOS PTY!\n')), 20);
      }),
  });
  kernel.spawnELF(elf);
  await kernel.runAll();

  assert.strictEqual(stdout, 'hello from async iOS PTY!\n');
  console.log(`[PASS] Test 4 (Suspendable Async Syscall): echoed "${stdout.trim()}"`);
}

// ---------------------------------------------------------------------------
// Test 5: Multi-Process fork() + pipe2() + wait4() Pipeline
// ---------------------------------------------------------------------------
async function testForkPipeWait() {
  const msg = new TextEncoder().encode('child->pipe->parent OK!\n');
  // Stack layout:
  //   [sp + 0] = rfd (i32), [sp + 4] = wfd (i32)
  //   [sp + 16..80] = read buffer
  //   [sp + 80] = wait4 status
  const baseVaddr = 0x10000;
  // Build placeholder first to know dataVaddr
  const dummyLen = 37;
  const dataOffsetInSeg = (dummyLen * 4 + 15) & ~15;
  const msgAddr = baseVaddr + dataOffsetInSeg;

  const code = [
    // 0: sp -= 128
    A64.subImm(31, 31, 128),
    // 1..4: pipe2(sp, 0)
    A64.addImm(0, 31, 0),
    A64.movz(1, 0),
    A64.movz(8, SYS.PIPE2),
    A64.svc(0),
    // 5..6: load rfd -> x19, wfd -> x20
    A64.ldr32(19, 31, 0),
    A64.ldr32(20, 31, 4),
    // 7..9: clone() (fork)
    A64.movz(0, 0),
    A64.movz(8, SYS.CLONE),
    A64.svc(0),
    // 10: if x0 == 0 jump to child (idx 27)
    A64.cbz(0, 17),

    // --- PARENT (idx 11..26) ---
    // 11: save childPid in x21
    A64.movReg(21, 0),
    // 12..14: close(wfd)
    A64.movReg(0, 20),
    A64.movz(8, SYS.CLOSE),
    A64.svc(0),
    // 15..19: read(rfd, sp+16, 64) [blocks until child writes!]
    A64.movReg(0, 19),
    A64.addImm(1, 31, 16),
    A64.movz(2, 64),
    A64.movz(8, SYS.READ),
    A64.svc(0),
    // 20..24: write(1, sp+16, n)
    A64.movReg(2, 0),
    A64.movz(0, 1),
    A64.addImm(1, 31, 16),
    A64.movz(8, SYS.WRITE),
    A64.svc(0),
    // 25..30: wait4(childPid, sp+80, 0, 0), then exit(0)
    A64.movReg(0, 21),
    A64.addImm(1, 31, 80),
    A64.movz(2, 0),
    A64.movz(3, 0),
    A64.movz(8, SYS.WAIT4),
    A64.svc(0),
    A64.ldr32(22, 31, 80), // x22 = wait status (expect 42 << 8)
    A64.movz(0, 0),
    A64.movz(8, SYS.EXIT_GROUP),
    A64.svc(0),

    // --- CHILD (idx 35..45) --- wait, let's adjust cbz offset cleanly!
  ];

  // Cleanly compute child index
  const childIdx = code.length; // 35
  code[10] = A64.cbz(0, childIdx - 10);

  // Child closes rfd, writes msg to wfd, closes wfd, exits with code 42
  code.push(
    A64.movReg(0, 19),
    A64.movz(8, SYS.CLOSE),
    A64.svc(0),

    A64.movReg(0, 20),
    A64.movz(1, 0, 0), // patched below with real dataVaddr
    A64.movk(1, 0, 1), // patched below
    A64.movz(2, msg.length),
    A64.movz(8, SYS.WRITE),
    A64.svc(0),

    A64.movReg(0, 20),
    A64.movz(8, SYS.CLOSE),
    A64.svc(0),

    A64.movz(0, 42),
    A64.movz(8, SYS.EXIT_GROUP),
    A64.svc(0)
  );

  // Patch msgAddr now that code.length is final
  const realDataOff = (code.length * 4 + 15) & ~15;
  const realMsgAddr = baseVaddr + realDataOff;
  code[childIdx + 4] = A64.movz(1, realMsgAddr & 0xffff, 0);
  code[childIdx + 5] = A64.movk(1, (realMsgAddr >>> 16) & 0xffff, 1);

  const { elf, dataVaddr } = buildELF64(code, msg, baseVaddr);
  assert.strictEqual(dataVaddr, realMsgAddr);

  let stdout = '';
  const dec = new TextDecoder();
  const kernel = new GuestKernel(new WasmDBT.DBTEngine(), {
    onStdout: (b) => {
      stdout += dec.decode(b);
    },
  });
  const parent = kernel.spawnELF(elf);
  await kernel.runAll({ sliceBudget: 8 }); // small sliceBudget forces interleaving!

  assert.strictEqual(stdout, 'child->pipe->parent OK!\n');
  assert.strictEqual(parent.cpu.getReg(22), BigInt(42 << 8), 'wait4 exit status mismatch');
  console.log(
    `[PASS] Test 5 (fork + pipe2 + wait4): received "${stdout.trim()}", reaped child exitCode=${
      Number(parent.cpu.getReg(22)) >> 8
    }`
  );
}

(async () => {
  await testLoopAndBenchmark();
  await testIndirectBranchesDBT();
  await testCompactVMM();
  await testSuspendableAsyncSyscall();
  await testForkPipeWait();
  console.log('\nALL 5 TESTS PASSED.');
})().catch((err) => {
  console.error('TEST FAILED:', err);
  process.exit(1);
});
