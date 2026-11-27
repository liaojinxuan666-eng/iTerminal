.section .text
.global _start
_start:
movz x0,#0xdef0
movk x0,#0x9abc,lsl#16
movk x0,#0x5678,lsl#32
movk x0,#0x1234,lsl#48
and w1,w0,#0xff
mov x0,x1
mov x8,#93
svc #0
