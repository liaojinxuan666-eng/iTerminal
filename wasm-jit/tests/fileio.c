/*
 * fileio.c — 验证文件系统 syscall 链路（openat/read/write/fstat/lseek/close）
 * 不依赖 libc，全部用内联 svc。编译方式与 echo.c 相同。
 */
typedef long i64;

/* 6 参数 syscall；nr 走 x8，参数走 x0..x5 */
static i64 sys6(i64 nr, i64 a0, i64 a1, i64 a2, i64 a3, i64 a4, i64 a5) {
    register long x8 asm("x8") = nr;
    register long x0 asm("x0") = a0;
    register long x1 asm("x1") = a1;
    register long x2 asm("x2") = a2;
    register long x3 asm("x3") = a3;
    register long x4 asm("x4") = a4;
    register long x5 asm("x5") = a5;
    asm volatile("svc #0" : "+r"(x0)
                 : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5)
                 : "memory");
    return x0;
}
#define S3(nr,a,b,c) sys6(nr,a,b,c,0,0,0)
#define S2(nr,a,b)   sys6(nr,a,b,0,0,0,0)
#define S1(nr,a)     sys6(nr,a,0,0,0,0,0)

static void putc(char c) { S3(64, 1, (i64)&c, 1); }

int main(void) {
    char buf[128];
    char st[256];

    /* openat(AT_FDCWD=-100, "/etc/version", O_RDONLY=0, 0) */
    i64 fd = S3(56, -100, (i64)"/etc/version", 0);
    if (fd < 0) { putc('O'); return 10; }

    /* read(fd, buf, 64) */
    i64 n = S3(63, fd, (i64)buf, 64);
    if (n <= 0) { putc('R'); return 11; }

    /* write(1, buf, n) —— 输出文件内容 */
    S3(64, 1, (i64)buf, n);

    /* fstat(fd, st)：st_size 在内核 ABI 偏移 48 */
    i64 fr = S2(80, fd, (i64)st);
    if (fr < 0) { putc('F'); return 12; }
    i64 size = *(i64*)(st + 48);
    putc((char)('0' + size));   /* 期望文件 8 字节 -> '8' */

    /* lseek(fd, 0, SEEK_SET=0) 应返回 0 */
    i64 off = S3(62, fd, 0, 0);
    putc((char)('0' + off));    /* 期望 '0' */

    /* 再次 read 前 3 字节，输出 */
    n = S3(63, fd, (i64)buf, 3);
    S3(64, 1, (i64)buf, n);

    /* close(fd) */
    S1(57, fd);

    /* getcwd(buf, 128)：返回 buf 指针，内容为 "/"，输出首字节 */
    i64 cwd = S2(96, (i64)buf, 128);
    if (cwd < 0) { putc('C'); return 13; }
    putc(buf[0]);               /* 期望 '/' */

    return 7;
}
