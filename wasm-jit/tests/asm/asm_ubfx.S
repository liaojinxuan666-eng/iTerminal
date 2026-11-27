.section .text
.global _start
_start:
movz x0,#0xdef0
movk x0,#0x9abc,lsl#16
movk x0,#0x5678,lsl#32
movk x0,#0x1234,lsl#48
ubfx x1,x0,#11,#6
mov x0,x1
mov x8,#93
svc #0
