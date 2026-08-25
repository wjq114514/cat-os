/*
 * host_test.c —— libc 宿主机逻辑单元测试（code9 · 并行任务）
 * ─────────────────────────────────────────────────────────────────────────────
 * 目的：ring3 运行时受文件锁阻塞（exec 链路需 kernel.c/shell_bin.h/vfs.c
 * 配合，均在锁内），先在宿主机上以强符号 catos_stdout_emit 覆盖 stdio.c 的
 * 弱输出汇聚点，捕获输出做【逐字节精确断言】，验证：
 *   string 全家族、printf 全转换符（含边界值）、malloc/free 分配器行为
 *   （对齐、碎片复用、合并、防御性 free、耗尽-回收循环）。
 * int 0x80 真实通路不在本文件覆盖范围（见 README 测试证据节）。
 *
 * 编译：gcc -O2 -Wall -Wextra -Ilibc/include -o /tmp/host_test \
 *          libc/src/string.c libc/src/stdio.c libc/src/stdlib.c \
 *          libc/tests/host_test.c && /tmp/host_test
 */

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

/* ── 断言框架 ─────────────────────────────────────────────────────── */
static int g_fails;

#define EXPECT(cond, name)                                                   \
    do {                                                                     \
        if (!(cond)) {                                                       \
            printf("FAIL: %s (line %d)\n", (name), __LINE__);                \
            g_fails++;                                                       \
        }                                                                    \
    } while (0)

static void expect_out(const char *want, const char *name)
{
    if (cap_fail || strcmp(cap_buf, want) != 0) {
        printf("FAIL: %s\n  want=[%s]\n  got =[%s]\n", name, want, cap_buf);
        g_fails++;
    }
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
    EXPECT(r == 30, "printf return value counts chars");

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
        EXPECT(malloc(32) != (void *)0, "heap alive after double free");
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
    enum { MAXP = 64 };
    static unsigned char *ptrs[MAXP];
    static unsigned sizes[MAXP];
    int n = 0;
    void *big;

    /* 阶段一：4000B 大块分配到耗尽（步进 4016，64KiB 池约容 16 块）；
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
    EXPECT(n >= 14 && n <= 18, "exhaustion point reached sanely");

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
    EXPECT(malloc(8) == (void *)0, "pool fully exhausted");

    for (int i = 0; i < n; i++)
        EXPECT(check(ptrs[i], sizes[i], (unsigned char)i),
               "payload intact under pressure");
    for (int i = 0; i < n; i++)
        free(ptrs[i]);

    big = malloc(60000); /* 全部释放后应能整池级分配 → 合并正确 */
    EXPECT(big != (void *)0, "coalesce restores full-pool block");
    free(big);
}

int main(void)
{
    test_string();
    test_printf();
    test_malloc_basic();
    test_fragmentation();
    test_exhaust_and_recover();

    if (g_fails == 0) {
        printf("host-test PASS (all assertions)\n");
        return 0;
    }
    printf("host-test FAIL count=%d\n", g_fails);
    return 1;
}
