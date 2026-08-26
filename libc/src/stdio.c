/*
 * stdio.c —— Cat-OS 最小用户态 C 库：标准 I/O 实现（code9 · 并行任务）
 * ─────────────────────────────────────────────────────────────────────────────
 * write()/read() 封装 VFS 兼容 ABI nr=1（fd1=stdout=/dev/console）与 nr=0
 * （stdin）；printf 为无缓冲直写实现：每个转换片段一次 emit（精简取舍）。
 *
 * 输出统一汇聚到弱符号 catos_stdout_emit —— 宿主机单元测试以强同名符号
 * 覆盖捕获输出做精确断言；目标机上无人覆盖，走真实 write syscall。
 * 输入同理经弱符号 catos_stdin_read 汇聚，供宿主机注入脚本化数据。
 */

#include "stdio.h"
#include "string.h"
#include "catos_syscall.h"

int read(int fd, void *buf, unsigned int len)
{
    /* 指针经截断传入 EBX 是本 ABI 的既定形态（i386 指针即 32 位；
     * 截断转换仅为宿主机 64 位编译时消除告警，目标机无宽度损失）。 */
    return catos_syscall3(CATOS_SYS_READ_NR, (unsigned)fd,
                          (unsigned)(unsigned long)buf, len);
}

int write(int fd, const void *buf, unsigned int len)
{
    return catos_syscall3(CATOS_SYS_WRITE_NR, (unsigned)fd,
                          (unsigned)(unsigned long)buf, len);
}

/* 弱输出汇聚点：返回值语义与 write 相同（≥0 字节数 / <0 -errno） */
__attribute__((weak)) int catos_stdout_emit(const char *buf, unsigned len)
{
    return write(1, buf, len);
}

/* 弱输入汇聚点：返回值语义与 read 相同（≥0 字节数 / <0 -errno） */
__attribute__((weak)) int catos_stdin_read(int fd, char *buf, unsigned len)
{
    return read(fd, buf, len);
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

int getchar(void)
{
    unsigned char ch;

    if (catos_stdin_read(0, (char *)&ch, 1u) != 1)
        return -1; /* EOF 或错误统一收敛为 -1 */
    return (int)ch;
}

char *fgets(char *s, int size, int fd)
{
    int i = 0;

    if (s == NULL || size <= 1)
        return NULL;

    /* 逐字节读取：无流缓冲层时唯一能保证 '\n' 后不多消费的形态
     * （精简实现取舍；控制台行输入场景无性能压力）。 */
    while (i < size - 1) {
        char ch;

        if (catos_stdin_read(fd, &ch, 1u) != 1)
            break; /* EOF(0) / 错误(<0)：停止收集 */
        s[i++] = ch;
        if (ch == '\n')
            break;
    }
    if (i == 0)
        return NULL; /* 未读到任何数据 */
    s[i] = '\0';
    return s;
}

/* 无符号整数 → 十六进制/十进制 ASCII（小写），填入 out 返回长度。
 * 32 位上限：十进制 10 位、十六进制 8 位。 */
static unsigned catos_u32_to_str(unsigned v, unsigned base, char *out)
{
    char rev[10];
    int i = 0;
    int j;

    do {
        unsigned d = v % base;
        rev[i++] = (char)((d < 10u) ? ('0' + (char)d) : ('a' + (char)d - 10));
        v /= base;
    } while (v != 0u);

    for (j = 0; j < i; j++)
        out[j] = rev[i - 1 - j];
    return (unsigned)i;
}

/* 空格填充 width-len 个；先填（右对齐）或后填（左对齐）由调用方排序 */
static int catos_emit_pad(unsigned n)
{
    for (; n != 0u; n--)
        if (putchar(' ') < 0)
            return -1;
    return 0;
}

/* 输出正文并按 width/left/fill 补齐，返回输出总字节数或 -1。
 * lead = 正文前导字节数（负号/"0x"），零填充时保持在填充符之前；
 * zeropad（'0' 标志）仅在右对齐且 pad>0 时生效。 */
static int catos_emit_field(const char *body, unsigned len, unsigned lead,
                            int width, int left, int zeropad)
{
    unsigned pad =
        (width > 0 && (unsigned)width > len) ? (unsigned)width - len : 0u;

    if (!left && pad != 0u) {
        if (!zeropad) { /* 右对齐空格填充 */
            if (catos_emit_pad(pad) < 0)
                return -1;
        } else { /* '0' 标志：前导符号先出，其后补零 */
            for (unsigned i = 0u; i < lead; i++)
                if (putchar(body[i]) < 0)
                    return -1;
            for (unsigned i = 0u; i < pad; i++)
                if (putchar('0') < 0)
                    return -1;
            for (unsigned i = lead; i < len; i++)
                if (putchar(body[i]) < 0)
                    return -1;
            return (int)(len + pad);
        }
    }
    for (unsigned i = 0u; i < len; i++)
        if (putchar(body[i]) < 0)
            return -1;
    if (left && pad != 0u) /* 左对齐：尾部空格填充 */
        if (catos_emit_pad(pad) < 0)
            return -1;
    return (int)(len + pad);
}

int printf(const char *fmt, ...)
{
    va_list ap;
    const char *p;
    int total = 0;

    if (fmt == NULL)
        return -1;

    va_start(ap, fmt);
    for (p = fmt; *p != '\0'; p++) {
        const char *spec_start; /* '%' 之后第一个字符位置（回放锚点） */
        char spec;
        int left;
        int zeropad;
        int width;
        int k;

        if (*p != '%') {
            if (putchar(*p) < 0)
                goto fail;
            total++;
            continue;
        }

        p++;
        spec_start = p;
        /* 标志位：'-'（左对齐）与 '0'（零填充，仅数值类；'-' 同现时优先） */
        left = 0;
        {
            int zflag = 0;

            while (*p == '-' || *p == '0') {
                if (*p == '-')
                    left = 1;
                else
                    zflag = 1;
                p++;
            }
            /* 最小字段宽：十进制数字序列 */
            width = 0;
            while (*p >= '0' && *p <= '9') {
                width = width * 10 + (*p - '0');
                p++;
            }
            spec = *p;
            /* 零填充仅数值转换有意义；%s/%c/%% 一律退化为空格语义 */
            zeropad = (zflag && !left &&
                       (spec == 'd' || spec == 'u' || spec == 'x' ||
                        spec == 'p'));
        }

        if (spec == '\0') {
            /* 尾随不完整转换（如 "tail:%"、"%5"）：字面回放已扫原文 */
            if (putchar('%') < 0)
                goto fail;
            total++;
            for (const char *q = spec_start; q < p; q++) {
                if (putchar(*q) < 0)
                    goto fail;
                total++;
            }
            break;
        }

        switch (spec) {
        case '%': /* 标志/宽度对 %% 无意义，忽略 */
            if (putchar('%') < 0)
                goto fail;
            total++;
            break;
        case 'c': {
            char ch = (char)va_arg(ap, int);

            k = catos_emit_field(&ch, 1u, 0u, width, left, 0);
            if (k < 0)
                goto fail;
            total += k;
            break;
        }
        case 's': {
            const char *s = va_arg(ap, const char *);

            if (s == NULL)
                s = "(null)";
            k = catos_emit_field(s, strlen(s), 0u, width, left, 0);
            if (k < 0)
                goto fail;
            total += k;
            break;
        }
        case 'd': {
            char buf[11]; /* '-' + 十进制 10 位 */
            int v = va_arg(ap, int);
            unsigned m = (unsigned)v;
            unsigned len = 0u;

            if (v < 0) {
                buf[len++] = '-';
                m = 0u - m; /* INT_MIN 安全：先转 unsigned 再取负 */
            }
            len += catos_u32_to_str(m, 10u, buf + len);
            k = catos_emit_field(buf, len, (v < 0) ? 1u : 0u, width, left,
                                 zeropad);
            if (k < 0)
                goto fail;
            total += k;
            break;
        }
        case 'u':
        case 'x': {
            char buf[10];
            unsigned len = catos_u32_to_str(va_arg(ap, unsigned),
                                            (spec == 'u') ? 10u : 16u, buf);

            k = catos_emit_field(buf, len, 0u, width, left, zeropad);
            if (k < 0)
                goto fail;
            total += k;
            break;
        }
        case 'p': {
            const void *pv = va_arg(ap, const void *);

            if (pv == NULL) { /* 空指针：防解引用，打印 "(nil)" */
                k = catos_emit_field("(nil)", 5u, 0u, width, left, 0);
                if (k < 0)
                    goto fail;
                total += k;
            } else {
                char buf[10]; /* "0x" + 小写十六进制 ≤8 位（i386 指针） */
                unsigned len;
                unsigned long v = (unsigned long)pv;

                buf[0] = '0';
                buf[1] = 'x';
                len = 2u + catos_u32_to_str((unsigned)v, 16u, buf + 2);
                k = catos_emit_field(buf, len, 2u, width, left, zeropad);
                if (k < 0)
                    goto fail;
                total += k;
            }
            break;
        }
        default:
            /* 未支持转换符：字面回放 '%' 起、至该字符止的原文（含标志/宽度） */
            if (putchar('%') < 0)
                goto fail;
            total++;
            for (const char *q = spec_start; q <= p; q++) {
                if (putchar(*q) < 0)
                    goto fail;
                total++;
            }
            break;
        }
    }
    va_end(ap);
    return total;

fail:
    va_end(ap);
    return -1;
}
