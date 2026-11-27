.section .text
.global _start
_start:
movz x0,#0xdef0
movk x0,#0x9abc,lsl#16
movk x0,#0x5678,lsl#32
movk x0,#0x1234,lsl#48
and x1,x0,#0xff00ff00ff00ff00
mov x0,x1
mov x8,#93
svc #0
