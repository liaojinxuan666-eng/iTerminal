/*
 * minimal.S — 纯 AArch64 汇编，只用 syscall，不链接 libc。
 * 这是验证兼容层核心的黄金标准：指令集完全可控，输出可预期。
 */
    .global _start

    /* 写 "Hello from pure AArch64 Linux binary!\n" 到 stdout */
    mov     x0, #1                      // fd = stdout
    adr     x1, msg                     // buf
    mov     x2, #38                     // len
    mov     x8, #64                     // __NR_write (AArch64)
    svc     #0

    /* 做一个循环计算 1+2+...+10，存到 x10 */
    mov     x10, #0
    mov     x11, #1
loop:
    add     x10, x10, x11
    add     x11, x11, #1
    cmp     x11, #11
    b.lo    loop

    /* 退出，返回码 = 计算结果 & 0xff (=55) */
    mov     x0, x10
    mov     x8, #93                     // __NR_exit
    svc     #0

msg:
    .ascii  "Hello from pure AArch64 Linux binary!\n"
