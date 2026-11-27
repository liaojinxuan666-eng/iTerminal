/*
 * echo.c — 验证 read syscall（终端输入链路）
 * 从 stdin 读若干字节，原样写到 stdout，退出码为读到的字节数。
 */
typedef long i64;

static void write_buf(const char *p, i64 n) {
    register long x0 asm("x0") = 1;
    register const char *x1 asm("x1") = p;
    register long x2 asm("x2") = n;
    register long x8 asm("x8") = 64;
    asm volatile("svc #0" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x8) : "memory");
}

static i64 read_buf(char *p, i64 n) {
    register long x0 asm("x0") = 0;
    register char *x1 asm("x1") = p;
    register long x2 asm("x2") = n;
    register long x8 asm("x8") = 63;
    asm volatile("svc #0" : "=r"(x0) : "r"(x0), "r"(x1), "r"(x2), "r"(x8) : "memory");
    return x0;
}

int main(void) {
    char buf[64];
    i64 n = read_buf(buf, 16);
    write_buf(buf, n);
    return (int)n;
}
