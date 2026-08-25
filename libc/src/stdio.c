/*
 * stdio.c —— Cat-OS 最小用户态 C 库：标准 I/O 实现（code9 · 并行任务）
 * ─────────────────────────────────────────────────────────────────────────────
 * write() 封装 VFS 兼容 ABI nr=1（fd1=stdout=/dev/console）；
 * printf 为无缓冲直写实现：每个转换片段一次 emit（精简取舍，见 README）。
 * 输出统一汇聚到弱符号 catos_stdout_emit —— 宿主机单元测试以强同名符号
 * 覆盖捕获输出做精确断言；目标机上无人覆盖，走真实 write syscall。
 */

#include "stdio.h"
#include "catos_syscall.h"

int write(int fd, const void *buf, unsigned int len)
{
    /* 指针经截断传入 EBX 是本 ABI 的既定形态（i386 指针即 32 位；
     * 截断转换仅为宿主机 64 位编译时消除告警，目标机无宽度损失）。 */
    return catos_syscall3(CATOS_SYS_WRITE_NR, (unsigned)fd,
                          (unsigned)(unsigned long)buf, len);
}

/* 弱输出汇聚点：返回值语义与 write 相同（≥0 字节数 / <0 -errno） */
__attribute__((weak)) int catos_stdout_emit(const char *buf, unsigned len)
{
    return write(1, buf, len);
}

int putchar(int c)
{
    unsigned char ch = (unsigned char)c;
    int r = catos_stdout_emit((const char *)&ch, 1u);

    return (r < 0) ? r : (int)ch;
}

int puts(const char *s)
{
    unsigned n;

    if (s == NULL)
        return -1;
    n = 0u;
    while (s[n] != '\0')
        n++;
    if (catos_stdout_emit(s, n) < 0)
        return -1;
    if (catos_stdout_emit("\n", 1u) < 0)
        return -1;
    return (int)n + 1;
}

/* 无符号整数 → 十六进制/十进制 ASCII（小写），返回输出字节数或负 errno。
 * buf 逆序生成后倒序输出；32 位上限：十进制 10 位、十六进制 8 位。 */
static int emit_unsigned(unsigned v, unsigned base)
{
    char rev[10];
    char out[10];
    int i = 0;
    int j;

    do {
        unsigned d = v % base;
        rev[i++] = (char)((d < 10u) ? ('0' + (char)d) : ('a' + (char)d - 10));
        v /= base;
    } while (v != 0u);

    for (j = 0; j < i; j++)
        out[j] = rev[i - 1 - j];
    return catos_stdout_emit(out, (unsigned)i);
}

int printf(const char *fmt, ...)
{
    va_list ap;
    const char *p;
    int total = 0;
    int k;

    if (fmt == NULL)
        return -1;

    va_start(ap, fmt);
    for (p = fmt; *p != '\0'; p++) {
        char spec;

        if (*p != '%') {
            if (putchar(*p) < 0)
                goto fail;
            total++;
            continue;
        }

        p++; /* 越过 '%' */
        spec = *p;
        if (spec == '\0') {
            /* 尾随孤立 '%'：按字面补齐后结束 */
            if (putchar('%') < 0)
                goto fail;
            total++;
            break;
        }

        switch (spec) {
        case '%':
            if (putchar('%') < 0)
                goto fail;
            total++;
            break;
        case 'c': {
            int ch = va_arg(ap, int);
            if (putchar(ch) < 0)
                goto fail;
            total++;
            break;
        }
        case 's': {
            const char *s = va_arg(ap, const char *);
            if (s == NULL)
                s = "(null)";
            while (*s != '\0') {
                if (putchar(*s++) < 0)
                    goto fail;
                total++;
            }
            break;
        }
        case 'd': {
            /* INT_MIN 安全：先转 unsigned 再取负，避免对 INT_MIN 取负溢出 */
            int v = va_arg(ap, int);
            unsigned m = (unsigned)v;
            if (v < 0) {
                if (putchar('-') < 0)
                    goto fail;
                total++;
                m = 0u - m;
            }
            k = emit_unsigned(m, 10u);
            if (k < 0)
                goto fail;
            total += k;
            break;
        }
        case 'u': {
            k = emit_unsigned(va_arg(ap, unsigned), 10u);
            if (k < 0)
                goto fail;
            total += k;
            break;
        }
        case 'x': {
            k = emit_unsigned(va_arg(ap, unsigned), 16u);
            if (k < 0)
                goto fail;
            total += k;
            break;
        }
        default:
            /* 未支持转换符：字面输出 '%' + 字符 */
            if (putchar('%') < 0 || putchar(spec) < 0)
                goto fail;
            total += 2;
            break;
        }
    }
    va_end(ap);
    return total;

fail:
    va_end(ap);
    return -1;
}
