/*
 * host_test.c —— libc 宿主机逻辑单元测试（code9 · 并行任务）
 * ─────────────────────────────────────────────────────────────────────────────
 * 目的：ring3 运行时受文件锁阻塞（exec 链路需 kernel.c/shell_bin.h/vfs.c
 * 配合，均在锁内），先在宿主机上以强符号 catos_stdout_emit 覆盖 stdio.c 的
 * 弱输出汇聚点，捕获输出做【逐字节精确断言】，验证：
 *   string 全家族（含 memcmp/strncpy/strncat/strchr/strrchr/strstr/
 *   strcasecmp 族/strtok_r）、printf 全转换符（含 %p、宽度、左对齐）、
 *   ctype 整套、environ 家族、strtol/strtoul（含溢出饱和与 ERANGE）、
 *   fgets/getchar（经 catos_stdin_read 强符号注入脚本化输入）、
 *   malloc/free 分配器行为（对齐、碎片复用、合并、防御性 free、
 *   耗尽-回收循环）。
 * int 0x80 真实通路不在本文件覆盖范围（见 README 测试证据节）。
 *
 * 编译：gcc -O2 -Wall -Wextra -Ilibc/include -o /tmp/host_test \
 *          libc/src/string.c libc/src/stdio.c libc/src/stdlib.c \
 *          libc/src/environ.c libc/src/ctype.c libc/src/errno.c \
 *          libc/tests/host_test.c && /tmp/host_test
 */

#include "ctype.h"
#include "errno.h"
#include "stdio.h"
#include "stdlib.h"
#include "string.h"

/* ── 输出捕获：覆盖 stdio.c 的弱符号 ──────────────────────────────── */
static char cap_buf[8192];
static unsigned cap_len;
static int cap_fail;

int catos_stdout_emit(const char *buf, unsigned len)
{
    if (cap_len + len >= sizeof(cap_buf)) {
        cap_fail = 1;
        return -1;
    }
    for (unsigned i = 0; i < len; i++)
        cap_buf[cap_len++] = buf[i];
    cap_buf[cap_len] = '\0';
    return (int)len;
}

static void cap_reset(void)
{
    cap_len = 0u;
    cap_buf[0] = '\0';
    cap_fail = 0;
}

/* ── 输入注入：覆盖 stdio.c 的弱符号 catos_stdin_read ─────────────── */
static const char *in_buf;
static unsigned in_len;
static unsigned in_pos;
static int in_fail;

int catos_stdin_read(int fd, char *buf, unsigned len)
{
    (void)fd; /* 注入通道不区分 fd */
    if (in_fail)
        return -5; /* 模拟读错误（任意负 errno） */
    if (in_pos >= in_len)
        return 0; /* EOF */
    {
        unsigned n = (len < in_len - in_pos) ? len : (in_len - in_pos);

        for (unsigned i = 0u; i < n; i++)
            buf[i] = in_buf[in_pos++];
        return (int)n;
    }
}

static void in_reset(const char *data)
{
    in_buf = data;
    in_len = strlen(data);
    in_pos = 0u;
    in_fail = 0;
}

/* ── 断言框架 ─────────────────────────────────────────────────────── */
static int g_fails;

/* 失败报告直写通道（Linux i386 ABI nr=4 fd=2）：绕开输出捕获缓冲，
 * 保证后续用例的 cap_reset 不会吞掉先前的失败现场。 */
static void raw_out(const char *s)
{
    unsigned n = 0u;

    while (s[n] != '\0')
        n++;
    __asm__ volatile("int $0x80"
                     :: "a"(4u), "b"(2u), "c"(s), "d"(n)
                     : "memory");
}

static void raw_out_dec(int v)
{
    char rev[12];
    char buf[12];
    int m = 0;
    int n = 0;

    if (v == 0) {
        raw_out("0");
        return;
    }
    while (v > 0) {
        rev[m++] = (char)('0' + v % 10);
        v /= 10;
    }
    while (m > 0)
        buf[n++] = rev[--m];
    buf[n] = '\0';
    raw_out(buf);
}

#define EXPECT(cond, name)                                                   \
    do {                                                                     \
        if (!(cond)) {                                                       \
            raw_out("FAIL: " name " (line ");                                 \
            raw_out_dec(__LINE__);                                            \
            raw_out(")\n");                                                   \
            g_fails++;                                                        \
        }                                                                     \
    } while (0)

static void raw_out_trunc(const char *s, unsigned cap)
{
    unsigned n = 0u;

    while (s[n] != '\0' && n < cap)
        n++;
    __asm__ volatile("int $0x80"
                     :: "a"(4u), "b"(2u), "c"(s), "d"(n)
                     : "memory");
}

static void expect_out(const char *want, const char *name)
{
    if (!cap_fail && strcmp(cap_buf, want) == 0)
        return;
    raw_out("FAIL: ");
    raw_out(name);
    raw_out("\n  want=[");
    raw_out(want);
    raw_out("]\n  got =[" );
    raw_out_trunc(cap_buf, 96u);
    raw_out("]\n");
    g_fails++;
}

/* ══ 1. string 家族 ═══════════════════════════════════════════════════ */
static void test_string(void)
{
    char buf[64];

    memset(buf, 'A', 8u);
    memset(buf + 8, 'B', 8u);
    EXPECT(buf[0] == 'A' && buf[7] == 'A' && buf[8] == 'B' && buf[15] == 'B',
           "memset spans");

    memcpy(buf, "hello", 6u);
    EXPECT(strcmp(buf, "hello") == 0, "memcpy incl NUL");
    EXPECT(strlen("hello") == 5u && strlen("") == 0u, "strlen");

    EXPECT(strcmp("", "") == 0, "strcmp empty-empty");
    EXPECT(strcmp("abc", "abd") < 0 && strcmp("abd", "abc") > 0,
           "strcmp order");
    /* unsigned char 语义：0x80 以上不应变负 */
    {
        char hi[2] = { (char)0x80, '\0' };
        char lo[2] = { (char)0x7f, '\0' };
        EXPECT(strcmp(hi, lo) > 0, "strcmp unsigned-char semantics");
    }

    EXPECT(strncmp("abcdef", "abcxyz", 3u) == 0, "strncmp prefix eq");
    EXPECT(strncmp("abc", "abd", 3u) < 0, "strncmp lt");
    EXPECT(strncmp("ab", "ab", 8u) == 0, "strncmp NUL stop");
    EXPECT(strncmp("ab", "cd", 0u) == 0, "strncmp n=0");

    strcpy(buf, "foo");
    strcat(buf, "bar");
    EXPECT(strcmp(buf, "foobar") == 0 && strlen(buf) == 6u,
           "strcpy+strcat");
    strcpy(buf, "");
    strcat(buf, "x");
    EXPECT(strcmp(buf, "x") == 0, "strcat onto empty");

    memcpy(buf, "1234567890", 11u);
    memmove(buf + 2, buf, 5u); /* 前向重叠：fo→"12"+"12345" */
    EXPECT(strcmp(buf, "1212345890") == 0, "memmove fwd overlap");
    memcpy(buf, "12345", 6u);
    memmove(buf + 1, buf, 4u); /* 后向重叠路径 */
    EXPECT(strcmp(buf, "11234") == 0, "memmove back overlap");
    memcpy(buf, "same", 5u);
    memmove(buf, buf, 5u); /* 自拷贝 */
    EXPECT(strcmp(buf, "same") == 0, "memmove self");
}

/* ══ 2. printf 精确输出 ═══════════════════════════════════════════════ */
static void test_printf(void)
{
    int r;

    cap_reset();
    r = printf("i=%d u=%u x=%x c=%c pct=%% s=%s\n", -42, 42u, 0xbeefu, 'Z',
               "ok");
    expect_out("i=-42 u=42 x=beef c=Z pct=% s=ok\n", "printf basic mix");
    EXPECT(r == 33, "printf return value counts chars");

    cap_reset();
    r = printf("[%d]", -2147483647 - 1); /* INT_MIN，不写裸字面量防告警 */
    expect_out("[-2147483648]", "printf INT_MIN");
    EXPECT(r == 13, "INT_MIN length 11+2");

    cap_reset();
    printf("%d %u %x", 0, 0u, 0u);
    expect_out("0 0 0", "printf zeros");

    cap_reset();
    printf("%u %x", 4294967295u, 4294967295u);
    expect_out("4294967295 ffffffff", "printf UINT_MAX");

    cap_reset();
    printf("<%s><%s>", "", (char *)0);
    expect_out("<><(null)>", "printf empty & NULL str");

    cap_reset();
    printf("tail:%");
    expect_out("tail:%", "printf trailing lone percent");

    cap_reset();
    printf("unk:%y end");
    expect_out("unk:%y end", "printf unknown spec literal");

    cap_reset();
    printf("%s%d%s", "a", 1, "b");
    expect_out("a1b", "printf consecutive specs");

    /* putchar / puts 返回值 */
    cap_reset();
    EXPECT(putchar('k') == 'k', "putchar returns char");
    EXPECT(puts("ln") == 3, "puts returns n+1");
    expect_out("kln\n", "putchar+puts stream");
    EXPECT(puts((char *)0) < 0, "puts NULL rejected");
}

/* ══ 3. malloc/free 分配器 ════════════════════════════════════════════ */
#define ALIGNED16(p) ((((unsigned long)(p)) & 15UL) == 0UL)

static void fill(unsigned char *p, unsigned n, unsigned char seed)
{
    for (unsigned i = 0; i < n; i++)
        p[i] = (unsigned char)(seed + i);
}

static int check(const unsigned char *p, unsigned n, unsigned char seed)
{
    for (unsigned i = 0; i < n; i++)
        if (p[i] != (unsigned char)(seed + i))
            return 0;
    return 1;
}

static void test_malloc_basic(void)
{
    unsigned char *p;

    p = malloc(1);
    EXPECT(p != (void *)0, "malloc(1)");
    EXPECT(ALIGNED16(p), "malloc result 16-aligned");
    fill(p, 1, 0x10);
    EXPECT(check(p, 1, 0x10), "tiny payload intact");
    free(p);

    p = malloc(0);
    EXPECT(p != (void *)0, "malloc(0) non-null");
    free(p);

    EXPECT(malloc((size_t)-1) == (void *)0, "huge malloc guarded");

    /* 中等块写入全量校验（探测头/尾越界）*/
    p = malloc(333);
    EXPECT(p != (void *)0 && ALIGNED16(p), "malloc(333) ok aligned");
    fill(p, 333, 0x77);
    EXPECT(check(p, 333, 0x77), "odd-size payload intact");
    free(p);

    /* 防御性 free */
    {
        int stack_var = 1;
        free((void *)0);
        free(&stack_var);
        free((char *)&stack_var + 3); /* 非 16 对齐 */
        p = malloc(32);
        EXPECT(p != (void *)0, "heap alive after bogus frees");
        free(p);
        free(p); /* 双重释放 → 应被魔数拦截 */
        p = malloc(32);
        EXPECT(p != (void *)0, "heap alive after double free");
        free(p);    /* 不泄漏：后续耗尽用例依赖全池精确复位 */
    }
}

static void test_fragmentation(void)
{
    unsigned char *a = malloc(100);
    unsigned char *b = malloc(100);
    unsigned char *c = malloc(100);
    unsigned char *hole;
    unsigned char *big2;

    EXPECT(a && b && c, "frag setup trio");
    fill(a, 100, 1);
    fill(b, 100, 2);
    fill(c, 100, 3);

    free(b);
    hole = malloc(96); /* 恰好 ≤ 空洞载荷 → 应命中原 b 位置 */
    EXPECT(hole != (void *)0 && (void *)hole == (void *)b,
           "first-fit reuses exact hole");
    free(hole);

    big2 = malloc(200); /* 大于空洞 → 不应落在 b 位置 */
    EXPECT(big2 != (void *)0 && (void *)big2 != (void *)b,
           "oversize skips hole");
    fill(big2, 200, 9);
    EXPECT(check(a, 100, 1) && check(c, 100, 3),
           "neighbors untouched by split/reuse");
    free(a);
    free(c);
    free(big2);
}

static void test_exhaust_and_recover(void)
{
    enum { MAXP = 256 };
    static unsigned char *ptrs[MAXP];
    static unsigned sizes[MAXP];
    int n = 0;
    void *big;

    /* 阶段一：4000B 大块分配到耗尽（步进 4016，512KiB 池约容 130 块）；
     * MAXP 仅作循环保险。 */
    while (n < MAXP) {
        unsigned char *p = malloc(4000);
        if (p == (void *)0)
            break;
        fill(p, 4000, (unsigned char)n);
        ptrs[n] = p;
        sizes[n] = 4000u;
        n++;
    }
    EXPECT(n >= 120 && n < MAXP, "exhaustion point reached sanely");

    /* 阶段二：小块吸干尾部零料（含无分裂整块交付路径），直至真枯竭 */
    while (n < MAXP) {
        unsigned char *p = malloc(64);
        if (p == (void *)0)
            break;
        fill(p, 64, (unsigned char)n);
        ptrs[n] = p;
        sizes[n] = 64u;
        n++;
    }
    EXPECT(malloc(64) == (void *)0, "pool has no 64-byte block left");

    for (int i = 0; i < n; i++)
        EXPECT(check(ptrs[i], sizes[i], (unsigned char)i),
               "payload intact under pressure");
    for (int i = 0; i < n; i++)
        free(ptrs[i]);

    big = malloc(60000); /* 全部释放后应能整池级分配 → 合并正确 */
    EXPECT(big != (void *)0, "coalesce restores full-pool block");
    free(big);
}

/* ══ 4. string 扩展家族 ══════════════════════════════════════════════ */
static void test_string_ext(void)
{
    char buf[64];

    /* memcmp：二进制语义（含内嵌 NUL 不得提前收敛） */
    EXPECT(memcmp("abc", "abd", 3u) < 0, "memcmp lt");
    EXPECT(memcmp("abd", "abc", 3u) > 0, "memcmp gt");
    EXPECT(memcmp("abc", "abd", 2u) == 0, "memcmp n stops before diff");
    EXPECT(memcmp("x", "y", 0u) == 0, "memcmp n=0");
    {
        char p1[3] = { 'a', '\0', 'c' };
        char p2[3] = { 'a', '\0', 'd' };

        EXPECT(memcmp(p1, p2, 3u) < 0, "memcmp binary past NUL");
        EXPECT(memcmp(p1, p1, 3u) == 0, "memcmp self");
    }

    /* strncpy：截断不补 / 截断后补满 / 精确适配 */
    memset(buf, 'X', sizeof(buf));
    strncpy(buf, "abcdefg", 3u);
    EXPECT(buf[0] == 'a' && buf[2] == 'c' && buf[3] == 'X',
           "strncpy truncate no NUL");
    strncpy(buf, "ab", 6u);
    EXPECT(buf[0] == 'a' && buf[1] == 'b' && buf[2] == '\0' &&
               buf[5] == '\0' && buf[6] == 'X',
           "strncpy pads to n");
    strncpy(buf, "abcd", 4u);
    EXPECT(strlen(buf) == 4u && strcmp(buf, "abcd") == 0,
           "strncpy exact fit incl NUL");
    buf[0] = 'Z';
    strncpy(buf, "never", 0u);
    EXPECT(buf[0] == 'Z', "strncpy n=0 untouched");

    /* strncat：部分追加恒单 NUL / 超长 src 全量追加 */
    strcpy(buf, "foo");
    strncat(buf, "barbaz", 3u);
    EXPECT(strcmp(buf, "foobar") == 0 && strlen(buf) == 6u,
           "strncat partial append");
    strncat(buf, "q", 10u);
    EXPECT(strcmp(buf, "foobarq") == 0, "strncat short src full copy");
    strcpy(buf, "x");
    strncat(buf, "ignored", 0u);
    EXPECT(strcmp(buf, "x") == 0, "strncat n=0 no-op");

    /* strchr：首匹配 / 未命中 / c=='\0' 指向串尾 */
    {
        const char *h = "hello";

        EXPECT(strchr(h, 'l') == h + 2, "strchr first match");
        EXPECT(strchr(h, 'z') == (char *)0, "strchr miss");
        EXPECT(*strchr(h, '\0') == '\0', "strchr NUL finds terminator");
        EXPECT(strchr("", 'a') == (char *)0, "strchr empty miss");
        EXPECT(strchr("", '\0') != (char *)0, "strchr empty terminator");
    }

    /* strrchr：末匹配 */
    {
        const char *b = "banana";

        EXPECT(strrchr(b, 'a') == b + 5, "strrchr last match");
        EXPECT(strrchr(b, 'b') == b, "strrchr single");
        EXPECT(strrchr(b, 'z') == (char *)0, "strrchr miss");
        EXPECT(*strrchr(b, '\0') == '\0', "strrchr NUL terminator");
    }

    /* strstr：常规 / 空针 / 无命中 / 首位重叠匹配 */
    EXPECT(strstr("hello world", "wor") ==
               (const char *)"hello world" + 6,
           "strstr mid match");
    EXPECT(strstr("abc", "") == (const char *)"abc", "strstr empty needle");
    EXPECT(strstr("", "") == (const char *)"", "strstr both empty");
    EXPECT(strstr("", "a") == (char *)0, "strstr empty haystack miss");
    EXPECT(strstr("abc", "abcd") == (char *)0, "strstr needle longer");
    EXPECT(strstr("aaa", "aa") == (const char *)"aaa",
           "strstr overlapping first");
    EXPECT(strstr("abab", "ba") == (const char *)"abab" + 1,
           "strstr second pos");

    /* strcasecmp / strncasecmp */
    EXPECT(strcasecmp("HeLLo", "hello") == 0, "strcasecmp fold eq");
    EXPECT(strcasecmp("", "") == 0, "strcasecmp empty-empty");
    EXPECT(strcasecmp("a", "b") < 0 && strcasecmp("B", "A") > 0,
           "strcasecmp order");
    EXPECT(strcasecmp("hello!", "hello?") < 0,
           "strcasecmp non-letter raw diff"); /* '!'(33) < '?'(63) */
    {
        char hi[2] = { (char)0x80, '\0' };
        char lo[2] = { (char)0x90, '\0' };

        EXPECT(strcasecmp(hi, lo) < 0, "strcasecmp unsigned semantics");
    }
    EXPECT(strncasecmp("ABCDEF", "abcdefg", 6u) == 0,
           "strncasecmp prefix eq");
    EXPECT(strncasecmp("ABCDEF", "abcxyz", 3u) == 0 &&
               strncasecmp("ABCDEF", "abcxyz", 4u) < 0,
           "strncasecmp n boundary");
    EXPECT(strncasecmp("ab", "ab", 8u) == 0, "strncasecmp NUL stop");
    EXPECT(strncasecmp("ab", "cd", 0u) == 0, "strncasecmp n=0");

    /* strtok_r：连续分隔符折叠 / 全分隔符 / 多分隔符集 / 双流交错 */
    {
        char t[32];
        char *sp;
        char *tk;

        strcpy(t, "a,bb,,ccc");
        tk = strtok_r(t, ",", &sp);
        EXPECT(tk != (char *)0 && strcmp(tk, "a") == 0, "strtok_r tok1");
        tk = strtok_r((char *)0, ",", &sp);
        EXPECT(tk != (char *)0 && strcmp(tk, "bb") == 0,
               "strtok_r skips empty field");
        tk = strtok_r((char *)0, ",", &sp);
        EXPECT(tk != (char *)0 && strcmp(tk, "ccc") == 0, "strtok_r tok3");
        tk = strtok_r((char *)0, ",", &sp);
        EXPECT(tk == (char *)0, "strtok_r exhausted");

        strcpy(t, ",,,");
        sp = (char *)0;
        EXPECT(strtok_r(t, ",", &sp) == (char *)0,
               "strtok_r all-delimiters");

        strcpy(t, "x::y; z");
        tk = strtok_r(t, ":; ", &sp);
        EXPECT(tk != (char *)0 && strcmp(tk, "x") == 0,
               "strtok_r multi-delim set 1");
        tk = strtok_r((char *)0, ":; ", &sp);
        EXPECT(tk != (char *)0 && strcmp(tk, "y") == 0,
               "strtok_r multi-delim set 2");
        tk = strtok_r((char *)0, ":; ", &sp);
        EXPECT(tk != (char *)0 && strcmp(tk, "z") == 0,
               "strtok_r multi-delim set 3");
        tk = strtok_r((char *)0, ":; ", &sp);
        EXPECT(tk == (char *)0, "strtok_r multi-delim end");

        {
            char u1[16], u2[16];
            char *sp1, *sp2;

            strcpy(u1, "1-2");
            strcpy(u2, "3-4");
            tk = strtok_r(u1, "-", &sp1);
            EXPECT(tk != (char *)0 && strcmp(tk, "1") == 0,
                   "strtok_r stream A first");
            tk = strtok_r(u2, "-", &sp2);
            EXPECT(tk != (char *)0 && strcmp(tk, "3") == 0,
                   "strtok_r stream B interleaved");
            tk = strtok_r((char *)0, "-", &sp1);
            EXPECT(tk != (char *)0 && strcmp(tk, "2") == 0,
                   "strtok_r stream A resumed");
            tk = strtok_r((char *)0, "-", &sp2);
            EXPECT(tk != (char *)0 && strcmp(tk, "4") == 0,
                   "strtok_r stream B resumed");
            EXPECT(strtok_r((char *)0, "-", &sp1) == (char *)0 &&
                       strtok_r((char *)0, "-", &sp2) == (char *)0,
                   "strtok_r both streams drained");
        }
    }
}

/* ══ 5. ctype 整套 ════════════════════════════════════════════════════ */
static void test_ctype(void)
{
    EXPECT(isalpha('Q') && isalpha('q'), "isalpha letters");
    EXPECT(!isalpha('1') && !isalpha(' '), "isalpha non-letters");
    EXPECT(isdigit('7') && !isdigit('a') && !isdigit('/'), "isdigit bounds");
    EXPECT(isspace(' ') && isspace('\t') && isspace('\n') &&
               isspace('\v') && isspace('\f') && isspace('\r'),
           "isspace all six");
    EXPECT(!isspace('a') && !isspace('\0'), "isspace non-space");
    EXPECT(isalnum('5') && isalnum('Z') && !isalnum('#'), "isalnum mix");
    EXPECT(isupper('A') && isupper('Z') && !isupper('a'), "isupper");
    EXPECT(islower('a') && islower('z') && !islower('A'), "islower");
    EXPECT(isblank(' ') && isblank('\t') && !isblank('\n'),
           "isblank space-tab only");
    EXPECT(iscntrl(0x01) && iscntrl(0x1F) && iscntrl(0x7F),
           "iscntrl range+DEL");
    EXPECT(!iscntrl(' ') && !iscntrl('~'), "iscntrl printable excluded");
    EXPECT(isprint(' ') && isprint('~') && !isprint('\t') &&
               !isprint(0x7F),
           "isprint [0x20,0x7E]");
    EXPECT(isgraph('!') && isgraph('~') && !isgraph(' '),
           "isgraph excludes space");
    EXPECT(ispunct('!') && ispunct('/') && !ispunct('e') && !ispunct(' '),
           "ispunct graph-non-alnum");
    EXPECT(isxdigit('9') && isxdigit('F') && isxdigit('f') &&
               !isxdigit('g') && !isxdigit('/'),
           "isxdigit");
    EXPECT(tolower('G') == 'g' && tolower('g') == 'g' &&
               tolower('5') == '5',
           "tolower idempotent non-upper");
    EXPECT(toupper('g') == 'G' && toupper('G') == 'G' &&
               toupper('%') == '%',
           "toupper idempotent non-lower");
    /* EOF(-1)/越界防御：分类恒 0、转换原样返回 */
    EXPECT(!isalpha(-1) && !isdigit(-1) && !isspace(-1) && !isxdigit(-1),
           "ctype EOF classifies false");
    EXPECT(!isalpha(256) && !iscntrl(256), "ctype out-of-range safe");
    EXPECT(tolower(-1) == -1 && toupper(300) == 300,
           "ctype convert passthrough");
}

/* ══ 6. environ 家族 ══════════════════════════════════════════════════ */
static void test_environ(void)
{
    static char putv_slot[] = "PUTV=direct"; /* putenv 所有权归环境 */

    /* 初始空表与非法入参 */
    EXPECT(getenv("NOPE") == (char *)0, "getenv initial empty");
    EXPECT(getenv((char *)0) == (char *)0, "getenv NULL name");
    EXPECT(getenv("") == (char *)0, "getenv empty name");
    EXPECT(getenv("A=B") == (char *)0, "getenv name with '=' rejected");

    /* setenv 新增 / overwrite==0 保护 / overwrite==1 替换 */
    EXPECT(setenv("FOO", "bar", 1) == 0, "setenv new");
    EXPECT(getenv("FOO") != (char *)0 &&
               strcmp(getenv("FOO"), "bar") == 0,
           "getenv roundtrip");
    EXPECT(setenv("FOO", "baz", 0) == 0, "setenv overwrite=0 succeeds");
    EXPECT(strcmp(getenv("FOO"), "bar") == 0, "overwrite=0 keeps value");
    EXPECT(setenv("FOO", "qux", 1) == 0, "setenv overwrite=1");
    EXPECT(strcmp(getenv("FOO"), "qux") == 0, "overwrite=1 replaces");

    /* 空值合法 */
    EXPECT(setenv("EMPTY", "", 1) == 0 && getenv("EMPTY")[0] == '\0',
           "setenv empty value");

    /* 非法 name */
    EXPECT(setenv((char *)0, "v", 1) == -1, "setenv NULL name");
    EXPECT(setenv("", "v", 1) == -1, "setenv empty name");
    EXPECT(setenv("B=C", "v", 1) == -1, "setenv name contains '='");

    /* putenv：纳入调用方串 → getenv 可见；随后被 setenv 顶替 */
    EXPECT(putenv(putv_slot) == 0, "putenv accepts NAME=value");
    EXPECT(getenv("PUTV") != (char *)0 &&
               strcmp(getenv("PUTV"), "direct") == 0,
           "putenv visible via getenv");
    EXPECT(setenv("PUTV", "replaced", 1) == 0, "setenv over putenv entry");
    EXPECT(strcmp(getenv("PUTV"), "replaced") == 0,
           "putenv entry replaced by value");
    EXPECT(putenv((char *)0) == -1, "putenv NULL rejected");
    EXPECT(putenv("NOEQUALS") == -1, "putenv missing '=' rejected");

    /* unsetenv：移除 / 不存在 / 非法名；移除后可重设（追加路径复用） */
    EXPECT(unsetenv("FOO") == 0, "unsetenv existing");
    EXPECT(getenv("FOO") == (char *)0, "unsetenv really gone");
    EXPECT(unsetenv("NOPE") == -1, "unsetenv missing");
    EXPECT(unsetenv("B=C") == -1, "unsetenv invalid name");
    EXPECT(unsetenv("") == -1, "unsetenv empty name");
    EXPECT(setenv("FOO", "again", 1) == 0, "re-set after unset");

    /* environ 直读：NULL 结尾且内容精确（EMPTY 先于 PUTV/FOO 追加） */
    {
        int saw_empty = 0, saw_putv = 0, saw_foo = 0;
        int count = 0;

        for (char **e = environ; *e != (char *)0; e++) {
            count++;
            if (strcmp(*e, "EMPTY=") == 0)
                saw_empty = 1;
            if (strcmp(*e, "PUTV=replaced") == 0)
                saw_putv = 1;
            if (strcmp(*e, "FOO=again") == 0)
                saw_foo = 1;
        }
        EXPECT(count == 3, "environ exact entry count");
        EXPECT(saw_empty && saw_putv && saw_foo,
               "environ contents via direct walk");
    }

    /* 清场：后续分配器测试依赖堆余量（owned 串全部回收） */
    EXPECT(unsetenv("EMPTY") == 0 && unsetenv("PUTV") == 0 &&
               unsetenv("FOO") == 0,
           "environ teardown");
}

/* ══ 7. strtol/strtoul ════════════════════════════════════════════════ */
static void test_strto(void)
{
    char *e;

    errno = 0;
    EXPECT(strtol("42", (char **)0, 10) == 42L, "strtol plain");
    errno = 0;
    EXPECT(strtol("   -42xyz", &e, 10) == -42L && *e == 'x',
           "strtol ws+sign+endptr");
    errno = 0;
    EXPECT(strtol("+7", &e, 10) == 7L && *e == '\0', "strtol plus sign");
    errno = 0;
    EXPECT(strtol("0x1F", &e, 0) == 31L && *e == '\0',
           "strtol base=0 hex auto");
    errno = 0;
    EXPECT(strtol("0X1f", &e, 16) == 31L && *e == '\0',
           "strtol base16 upper prefix");
    errno = 0;
    EXPECT(strtol("012", &e, 0) == 10L, "strtol base=0 octal auto");
    errno = 0;
    EXPECT(strtol("012", &e, 10) == 12L, "strtol leading zero base10");
    errno = 0;
    EXPECT(strtol("789", &e, 8) == 7L && *e == '8',
           "strtol stops at invalid digit");
    errno = 0;
    e = (char *)0;
    EXPECT(strtol("zzz", &e, 10) == 0L && e != (char *)0 &&
               strcmp(e, "zzz") == 0,
           "strtol no digits endptr=nptr");
    errno = 0;
    EXPECT(strtol("", &e, 10) == 0L && strcmp(e, "") == 0,
           "strtol empty string");
    errno = 0;
    EXPECT(strtol("10", &e, 1) == 0L && errno == EINVAL,
           "strtol invalid base EINVAL");

    /* 边界值（LP32：LONG_MAX=2147483647）*/
    errno = 0;
    EXPECT(strtol("2147483647", &e, 10) == 2147483647L && errno == 0,
           "strtol LONG_MAX exact");
    errno = 0;
    EXPECT(strtol("-2147483648", &e, 10) == (-2147483647L - 1L) &&
               errno == 0,
           "strtol LONG_MIN exact");
    errno = 0;
    EXPECT(strtol("2147483648", &e, 10) == 2147483647L &&
               errno == ERANGE,
           "strtol overflow saturates LONG_MAX");
    errno = 0;
    EXPECT(strtol("-2147483649", &e, 10) == (-2147483647L - 1L) &&
               errno == ERANGE,
           "strtol underflow saturates LONG_MIN");
    errno = 0;
    EXPECT(strtol("99999999999", &e, 10) == 2147483647L &&
               errno == ERANGE,
           "strtol big overflow saturate");
    errno = 0;
    EXPECT(strtol("FFFFFFFFF", &e, 16) == 2147483647L && errno == ERANGE,
           "strtol hex overflow saturate");

    /* strtoul */
    errno = 0;
    EXPECT(strtoul("4000000000", &e, 10) == 4000000000UL && errno == 0,
           "strtoul big in-range");
    errno = 0;
    EXPECT(strtoul("0xffffffff", &e, 0) == 4294967295UL,
           "strtoul hex max");
    errno = 0;
    EXPECT(strtoul("+42", (char **)0, 10) == 42UL, "strtoul plus sign");
    errno = 0;
    EXPECT(strtoul("-1", &e, 10) == 4294967295UL && errno == ERANGE,
           "strtoul negative wraps + ERANGE flag");
    errno = 0;
    EXPECT(strtoul("99999999999", &e, 10) == 4294967295UL &&
               errno == ERANGE,
           "strtoul overflow saturates ULONG_MAX");
    errno = 0;
    EXPECT(strtoul("789", &e, 8) == 7UL && *e == '8',
           "strtoul stop digit shared core");
}

/* ══ 8. printf 扩展：%p / 宽度 / 左对齐 ══════════════════════════════ */
static void test_printf_ext(void)
{
    int r;

    cap_reset();
    r = printf("[%p]", (const void *)&cap_buf); /* 任意非空指针 */
    EXPECT(r >= 4, "printf %p return sane");
    EXPECT(cap_buf[0] == '[' && cap_buf[1] == '0' && cap_buf[2] == 'x',
           "printf %p 0x-prefixed");

    cap_reset();
    printf("<%p>", (const void *)0);
    expect_out("<(nil)>", "printf %p NULL");

    cap_reset();
    r = printf("%5d|%-5d|", 42, 42);
    expect_out("   42|42   |", "printf width right/left d");
    EXPECT(r == 12, "width padding counted in return");

    cap_reset();
    printf("%6s|%-6s|", "ab", "ab");
    expect_out("    ab|ab    |", "printf width right/left s");

    cap_reset();
    printf("%3x|%4u|", 0x1fu, 7u);
    expect_out(" 1f|   7|", "printf width x/u");

    cap_reset();
    printf("%4c|%-4c|", 'q', 'q');
    expect_out("   q|q   |", "printf width c");

    cap_reset();
    printf("%8s|", (char *)0);
    expect_out("  (null)|", "printf width applies to (null)");

    cap_reset();
    r = printf("%13d", -2147483647 - 1); /* INT_MIN + 宽度 */
    expect_out("  -2147483648", "printf INT_MIN right-aligned width");
    EXPECT(r == 13, "INT_MIN padded length 13");

    cap_reset();
    printf("%-13d|", 0);
    expect_out("0            |", "printf zero left-aligned");

    cap_reset();
    printf("tail:%5");
    expect_out("tail:%5", "printf trailing incomplete spec replayed");

    cap_reset();
    printf("%-3y end"); /* 未支持转换符连同标志宽度字面回放 */
    expect_out("%-3y end", "printf unknown spec with flags literal");

    /* '0' 零填充标志（仅数值类；负号/0x 前缀在零之前） */
    cap_reset();
    r = printf("[%05d]", 42);
    expect_out("[00042]", "printf zero-pad d");
    EXPECT(r == 7, "zero-pad return counts width");
    cap_reset();
    printf("%05d|%08x|%010p", -42, 0xbeefu, (const void *)0x1234);
    expect_out("-0042|0000beef|0x00001234", "printf zero-pad sign/hex/prefix");
    cap_reset();
    printf("%-05d|%010p|", 42, (const void *)0);
    expect_out("42   |     (nil)|", "printf '-' beats zero-pad; NULL space pad");
}

/* ══ 9. fgets/getchar（经 catos_stdin_read 注入）═════════════════════ */
static void test_fgets_getchar(void)
{
    char buf[32];

    /* 常规两行读取，EOF 后返回 NULL */
    in_reset("hi\nrest");
    EXPECT(fgets(buf, sizeof(buf), 0) == buf && strcmp(buf, "hi\n") == 0,
           "fgets line with newline kept");
    EXPECT(fgets(buf, sizeof(buf), 0) == buf && strcmp(buf, "rest") == 0,
           "fgets tail without newline at EOF");
    EXPECT(fgets(buf, sizeof(buf), 0) == (char *)0, "fgets EOF returns NULL");

    /* 截断保护：size-1 上限，剩余数据留给后续读取 */
    in_reset("abcdefghij");
    EXPECT(fgets(buf, 5, 0) == buf && strcmp(buf, "abcd") == 0,
           "fgets truncates to size-1");
    EXPECT(fgets(buf, 5, 0) == buf && strcmp(buf, "efgh") == 0,
           "fgets resumes after truncation");
    EXPECT(fgets(buf, 5, 0) == buf && strcmp(buf, "ij") == 0,
           "fgets final fragment");

    /* 恰好整行填满缓冲（含 '\n' 与 NUL 正好 size 字节） */
    in_reset("12345\n");
    EXPECT(fgets(buf, 7, 0) == buf && strcmp(buf, "12345\n") == 0,
           "fgets exact-fit line");
    EXPECT(fgets(buf, 7, 0) == (char *)0, "fgets exhausted after exact fit");

    /* 参数防御 */
    in_reset("data\n");
    EXPECT(fgets(buf, 1, 0) == (char *)0, "fgets size=1 rejected");
    EXPECT(fgets(buf, 0, 0) == (char *)0, "fgets size=0 rejected");
    EXPECT(fgets((char *)0, 8, 0) == (char *)0, "fgets NULL buffer rejected");
    EXPECT(in_pos == 0u, "rejected fgets consumes no input");

    /* 读错误路径：立即错误 → NULL */
    in_reset("");
    in_fail = 1;
    EXPECT(fgets(buf, sizeof(buf), 0) == (char *)0, "fgets error -> NULL");
    in_fail = 0;

    /* getchar：逐字节 + EOF 收敛为 -1 */
    in_reset("AB");
    EXPECT(getchar() == 'A', "getchar first");
    EXPECT(getchar() == 'B', "getchar second");
    EXPECT(getchar() == -1, "getchar EOF -> -1");

    in_fail = 1;
    in_reset("");
    EXPECT(getchar() == -1, "getchar error -> -1");
    in_fail = 0;

    /* read 弱汇聚点未被覆盖时的默认通路无法在宿主机验证（真实 syscall），
     * 此处仅验证注入通道与库内 fgets 的协作已全覆盖。 */
    in_reset("");
}

int main(void);

/* Linux i386 ABI：nr=4 write / nr=1 exit，退出码 = main 返回值（freestanding 无 crt）。
 * 捕获缓冲吞掉了全部断言输出，故在此收尾外放：成功打 PASS 行，失败倾倒现场。 */
__attribute__((noreturn)) void _start(void)
{
    static const char ok[] = "host-test PASS (all assertions)\n";
    int rc = main();

    if (rc == 0)
        __asm__ volatile("int $0x80"
                         :: "a"(4u), "b"(1u), "c"(ok), "d"(sizeof(ok) - 1u)
                         : "memory");
    else
        __asm__ volatile("int $0x80"
                         :: "a"(4u), "b"(2u), "c"(cap_buf), "d"(cap_len)
                         : "memory");
    __asm__ volatile("int $0x80" :: "a"(1u), "b"((unsigned int)rc) : "memory");
    for (;;)
        ;
}

int main(void)
{
    test_string();
    test_printf();
    test_malloc_basic();
    test_fragmentation();
    test_exhaust_and_recover();
    test_string_ext();
    test_ctype();
    test_environ();
    test_strto();
    test_printf_ext();
    test_fgets_getchar();

    if (g_fails == 0) {
        printf("host-test PASS (all assertions)\n");
        return 0;
    }
    printf("host-test FAIL count=%d\n", g_fails);
    return 1;
}
