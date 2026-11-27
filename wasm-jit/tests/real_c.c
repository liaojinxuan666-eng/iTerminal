/*
 * real_c.c — 由真实 gcc 编译的 C 代码，验证翻译器的访存/栈/调用栈能力。
 * 覆盖：数组读写、结构体、指针、多层函数调用、局部变量栈帧、循环。
 */
typedef long i64;

/* 多层函数调用（验证影子调用栈） */
static i64 add3(i64 a, i64 b, i64 c) { return a + b + c; }
static i64 twice(i64 x) { return add3(x, x, 0); }

/* 数组求和（验证 LDR/STR 变址寻址） */
static i64 sum_arr(const i64 *p, int n) {
    i64 s = 0;
    for (int i = 0; i < n; i++) s += p[i];
    return s;
}

/* 结构体（验证 LDP/STP 以及字段偏移） */
struct Pair { i64 a; i64 b; };
static i64 pair_sum(struct Pair p) { return p.a + p.b; }

/* 直接 syscall write，输出一个字符标记 */
static void putc(char c) {
    register long x0 asm("x0") = 1;
    register const char *x1 asm("x1") = &c;
    register long x2 asm("x2") = 1;
    register long x8 asm("x8") = 64;
    asm volatile("svc #0" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x8) : "memory");
}

int main(void) {
    i64 arr[5] = {1, 2, 3, 4, 5};
    i64 s = sum_arr(arr, 5);          // 15

    struct Pair p = { .a = 20, .b = 22 };
    i64 ps = pair_sum(p);             // 42

    i64 t = twice(7);                 // 14

    i64 total = s + ps + t;           // 15 + 42 + 14 = 71

    // 输出 'K' 作为通过标记
    putc('K');

    // 期望 total == 71；相等则 exit(71)，否则 exit(99)
    return (total == 71) ? 71 : 99;
}
