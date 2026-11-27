/*
 * crt.S — 极简 C runtime 启动桩（musl 风格）
 * 设置 sp，清零，调用 main，用 main 返回值做 exit syscall。
 * 不含任何 FP/SIMD 指令，让翻译器能聚焦验证整数 + 访存路径。
 */
.section .text
.global _start
_start:
    mov     x29, #0          // 清帧指针
    mov     x30, #0          // 清 LR
    bl      main             // 调用真实 C main
    mov     x8, #93          // exit
    svc     #0
1:  b       1b
