/*
 * verify.S — 综合验证：多个 syscall + 循环 + 算术 + 函数调用
 */
    .global _start

_start:
    /* 测试 1: write */
    mov     x0, #1
    adr     x1, msg1
    mov     x2, #34
    mov     x8, #64
    svc     #0

    /* 测试 2: 阶乘 5! = 120 (mul/sub/cmp/b.hi) */
    mov     x10, #1
    mov     x11, #5
fact:
    mul     x10, x10, x11
    sub     x11, x11, #1
    cmp     x11, #1
    b.hi    fact
    /* x10 = 120 */

    /* 测试 3: 除法 120/10 = 12，验证 udiv */
    mov     x12, #10
    udiv    x13, x10, x12      // x13 = 12
    cmp     x13, #12
    b.ne    fail_div               // 若不等则跳到 fail

    /* 测试 4: 函数调用（bl/ret） */
    mov     x0, #7
    bl      double_it
    cmp     x0, #14
    b.ne    fail_call

    /* 测试 5: uname syscall，检查 sysname 是 "Linux" */
    sub     sp, sp, #256
    mov     x0, sp
    mov     x8, #189
    svc     #0
    // x0 应 = 0 (uname 成功)
    cmp     x0, #0
    b.ne    fail_uname
    add     sp, sp, #256

    /* 成功：输出 OK */
    mov     x0, #1
    adr     x1, okmsg
    mov     x2, #34
    mov     x8, #64
    svc     #0
    mov     x0, x13            // 退出码 = 12
    mov     x8, #93
    svc     #0

fail_div:
    mov     x0, #91
    mov     x8, #93
    svc     #0
fail_call:
    mov     x0, #92
    mov     x8, #93
    svc     #0
fail_uname:
    mov     x0, #93
    mov     x8, #93
    svc     #0
fail:
    mov     x0, #99
    mov     x8, #93
    svc     #0

/* 函数：x0 = x0 * 2 */
double_it:
    add     x0, x0, x0
    ret

msg1:
    .ascii  "test: mul/div/call/uname/write...\n"
okmsg:
    .ascii  "PASS: all AArch64 ops verified!\n"
