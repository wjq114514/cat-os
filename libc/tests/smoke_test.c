/*
 * smoke_test.c —— libc ring3 冒烟测试（code9 · 并行任务）
 * ─────────────────────────────────────────────────────────────────────────────
 * 形态：ELF32 i386 ET_EXEC，入口 _start，由内核 exec syscall 经 elf_load()
 * 装载后以 ring3 运行（链接布局约束同 shell_user：-Ttext=0x400000，
 * 栈由内核置于 ELF_USER_STACK_SP=0x701000，elf.h）。
 *
 * 覆盖面：
 *   1) string 家族全量（memset/memcpy/memmove 含重叠双向/strlen/strcmp/
 *      strncmp/strcpy/strcat）；
 *   2) printf 全转换符（%s %d %u %x %c %%、负数、INT_MIN、0、UINT_MAX、
 *      NULL 串、尾随孤立 '%'）；
 *   3) malloc/free 分配-释放循环 ×3 轮：空洞复用 + 载荷完整性校验；
 *   4) 全池释放后一次性 ~58.6KB 大块分配 → 验证物理相邻合并正确。
 *
 * 通过标志：串口输出末行 "libc-smoke PASS"；随后 exit(0)（nr=12）。
 * ⚠️ 已知观测限制：内核 PCB 无退出码字段（process.h 定稿），exit 状态码
 *   当前无处上报 —— 串口原文是唯一判据（见 README「测试证据」节）。
 */

#include "stdio.h"
#include "stdlib.h"
#include "string.h"

static int g_fails;

/* 简化断言辅助：两串逐字节相等（含 NUL） */
static int memcmp_eq(const char *a, const char *b)
{
    while (*a != '\0') {
        if (*a != *b)
            return 0;
        a++;
        b++;
    }
    return *b == '\0';
}

#define CHECK(cond, msg)                                                     \
    do {                                                                     \
        if (cond) {                                                          \
            printf("[ok] ");                                                 \
        } else {                                                             \
            printf("[FAIL] ");                                               \
            g_fails++;                                                       \
        }                                                                    \
        printf("%s\n", (msg));                                               \
    } while (0)

static void test_string(void)
{
    char buf[64];

    memset(buf, 'A', 8u);
    CHECK(buf[0] == 'A' && buf[7] == 'A', "memset writes all n bytes");

    memcpy(buf, "hello", 6u);
    CHECK(strcmp(buf, "hello") == 0, "memcpy copies incl NUL");
    CHECK(strlen("hello") == 5u, "strlen counts before NUL");

    CHECK(strncmp("abcdef", "abcxyz", 3u) == 0, "strncmp equal prefix");
    CHECK(strncmp("abc", "abd", 3u) < 0, "strncmp less");
    CHECK(strncmp("ab", "ab", 8u) == 0, "strncmp stops at NUL");

    strcpy(buf, "foo");
    strcat(buf, "bar");
    CHECK(strcmp(buf, "foobar") == 0, "strcpy+strcat chain");

    strcpy(buf, "foobar");
    memmove(buf + 2, buf, 5u); /* 前向重叠 */
    CHECK(memcmp_eq(buf, "fofooba"), "memmove forward overlap");
    CHECK(buf[7] == '\0', "memmove keeps tail NUL");

    strcpy(buf, "12345");
    memmove(buf + 1, buf, 4u); /* 后向重叠路径 */
    CHECK(strcmp(buf, "11234") == 0, "memmove backward overlap");
}

static void test_printf(void)
{
    /* 目标机无输出捕获通道，此处为确定性打印供串口人工/脚本比对；
     * 精确断言在宿主机单测 host_test.c 完成。 */
    printf("p1:[%d %u %x %c %%]\n", -42, 42u, 0xbeefu, 'Z');
    printf("p2:[%d]\n", -2147483647 - 1); /* INT_MIN */
    printf("p3:[%u %x]\n", 4294967295u, 0u);
    printf("p4:[%s][%s]\n", "cat", (char *)0);
    printf("p5:%\n"); /* 尾随孤立 '%' */
}

static void test_malloc(void)
{
    for (int round = 0; round < 3; round++) {
        unsigned char *a = malloc(100);
        unsigned char *b = malloc(200);
        unsigned char *c = malloc(300);
        unsigned char *d;
        int ok;
        int i;

        CHECK(a != 0 && b != 0 && c != 0, "malloc trio non-null");

        memset(a, '0' + round, 100u);
        memset(b, 0x5A, 200u);
        memset(c, 0x33, 300u);

        free(b); /* 中间挖洞 */
        d = malloc(150);
        CHECK(d != 0, "malloc reuses freed hole");

        ok = (a != 0 && c != 0 && d != 0);
        for (i = 0; ok && i < 100; i++)
            ok = (a[i] == (unsigned char)('0' + round));
        for (i = 0; ok && i < 200; i++)
            ok = (b[i] == 0x5A); /* b 虽已释放但内容应未被踩 */
        for (i = 0; ok && i < 300; i++)
            ok = (c[i] == 0x33);
        CHECK(ok, "payload integrity across alloc/free cycle");

        free(a);
        free(c);
        free(d);
    }

    /* 三轮全部释放完毕 → 池应合并回单一整块，可容纳 ~58.6KB */
    {
        void *big = malloc(60000u);

        CHECK(big != 0, "coalesced near-full-pool allocation");
        free(big);
    }

    /* 防御性用例：非法释放不应破坏堆 */
    {
        int local = 123;
        free(&local);  /* 池外指针 → 忽略 */
        free((void *)0);
        CHECK(malloc(16) != 0, "heap survives bogus frees");
    }
}

void _start(void)
{
    printf("libc-smoke begin\n");
    test_string();
    test_printf();
    test_malloc();

    if (g_fails == 0)
        printf("libc-smoke PASS\n");
    else
        printf("libc-smoke FAIL count=%d\n", g_fails);

    exit(g_fails == 0 ? 0 : 1);
}
