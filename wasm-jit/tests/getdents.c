/*
 * getdents.c — 验证 getdents64（目录列举）+ openat(O_DIRECTORY)
 * 打开 rootfs 根目录，列举条目，输出每个 dirent 的 d_type 和名字首字符。
 */
typedef long i64;

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
    char buf[512];
    /* openat(AT_FDCWD, "/etc", O_RDONLY|O_DIRECTORY=0x10000) */
    i64 fd = S3(56, -100, (i64)"/etc", 0x10000);
    if (fd < 0) { putc('O'); return 10; }

    /* getdents64(fd, buf, 512) */
    i64 n = S3(217, fd, (i64)buf, 512);
    if (n <= 0) { putc('D'); return 11; }

    /* 遍历 dirent：d_reclen 在 +16(u16)，d_type 在 +18，d_name 在 +19 */
    long off = 0;
    int count = 0;
    while (off < n) {
        unsigned short reclen = *(unsigned short*)(buf + off + 16);
        char type = buf[off + 18];
        char first = buf[off + 19];
        putc(type);          /* 4=DIR, 8=REG */
        putc(first);         /* 名字首字符 */
        if (reclen == 0) break;
        off += reclen;
        count++;
        if (count > 16) break;
    }
    S1(57, fd);
    return count;
}
