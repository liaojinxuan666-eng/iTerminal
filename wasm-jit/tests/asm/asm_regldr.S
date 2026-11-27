.section .data
arr: .quad 0x123456789abcdef0
     .quad 0x1111111111111111
     .quad 0x2222222222222222
     .quad 0x3333333333333333
.section .text
.global _start
_start:
    adrp x0, arr
    add  x0, x0, :lo12:arr
    mov  x1, #3          // index
    ldr  x2, [x0, x1, lsl #3]   // arr[3] = 0x3333...33
    mov  x0, x2
    mov  x8, #93
    svc  #0
