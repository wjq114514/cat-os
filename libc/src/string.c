/*
 * string.c —— Cat-OS 最小用户态 C 库：字符串/内存块实现（code9 · 并行任务）
 * ─────────────────────────────────────────────────────────────────────────────
 * 纯实现，无 syscall、无 libgcc 依赖；逐字节版本优先保证正确性与可审计性
 * （ring3 无 MMIO 性能压力，-O2 下 GCC 可自动向量化/内联）。
 */

#include "string.h"

typedef __UINTPTR_TYPE__ catos_uintptr_t;

void *memset(void *s, int c, size_t n)
{
    unsigned char *p = (unsigned char *)s;
    unsigned char v = (unsigned char)c;

    while (n-- != 0u)
        *p++ = v;
    return s;
}

void *memcpy(void *dst, const void *src, size_t n)
{
    unsigned char *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;

    while (n-- != 0u)
        *d++ = *s++;
    return dst;
}

/* 重叠安全：dst > src 且区间重叠时从尾部向前拷贝（POSIX memmove 语义） */
void *memmove(void *dst, const void *src, size_t n)
{
    unsigned char *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;

    if (d == s || n == 0u)
        return dst;

    if ((catos_uintptr_t)d < (catos_uintptr_t)s ||
        (catos_uintptr_t)d >= (catos_uintptr_t)s + n) {
        /* 不重叠或向前安全：正序 */
        while (n-- != 0u)
            *d++ = *s++;
    } else {
        /* 重叠且 d 在 s 之后：倒序拷贝 */
        d += n;
        s += n;
        while (n-- != 0u)
            *--d = *--s;
    }
    return dst;
}

int memcmp(const void *a, const void *b, size_t n)
{
    const unsigned char *x = (const unsigned char *)a;
    const unsigned char *y = (const unsigned char *)b;

    /* 二进制比较：不因 NUL 提前收敛（与 strcmp 的本质区别） */
    for (size_t i = 0u; i < n; i++) {
        if (x[i] != y[i])
            return (int)x[i] - (int)y[i]; /* unsigned char 语义 */
    }
    return 0;
}

size_t strlen(const char *s)
{
    size_t n = 0u;

    while (s[n] != '\0')
        n++;
    return n;
}

int strcmp(const char *a, const char *b)
{
    while (*a != '\0' && *a == *b) {
        a++;
        b++;
    }
    return (int)(unsigned char)*a - (int)(unsigned char)*b;
}

int strncmp(const char *a, const char *b, size_t n)
{
    for (size_t i = 0u; i < n; i++) {
        unsigned char ca = (unsigned char)a[i];
        unsigned char cb = (unsigned char)b[i];

        if (ca != cb)
            return (int)ca - (int)cb;
        if (ca == (unsigned char)'\0')
            return 0; /* 同长同前缀，提前收敛 */
    }
    return 0;
}

char *strcpy(char *dst, const char *src)
{
    char *d = dst;

    while ((*d++ = *src++) != '\0')
        ;
    return dst;
}

char *strncpy(char *dst, const char *src, size_t n)
{
    char *d = dst;
    size_t i = 0u;

    if (n == 0u)
        return dst;
    /* 拷贝至 NUL 或 n 上限 */
    for (; i < n && src[i] != '\0'; i++)
        d[i] = src[i];
    /* 不足 n 时以 NUL 填满（标准要求，含截断后不补的歧义澄清：必须补） */
    for (; i < n; i++)
        d[i] = '\0';
    return dst;
}

char *strcat(char *dst, const char *src)
{
    char *d = dst;

    while (*d != '\0')
        d++;
    while ((*d++ = *src++) != '\0')
        ;
    return dst;
}

char *strncat(char *dst, const char *src, size_t n)
{
    char *d = dst;
    size_t i = 0u;

    while (*d != '\0')
        d++;
    if (n == 0u) {
        *d = '\0'; /* 保持 dst 终结态（防御 src 为空串外的意外路径） */
        return dst;
    }
    while (i < n && src[i] != '\0') {
        d[i] = src[i];
        i++;
    }
    d[i] = '\0'; /* 恒补单个 NUL（与 strncpy 的补满语义不同） */
    return dst;
}

char *strchr(const char *s, int c)
{
    unsigned char target = (unsigned char)c;

    for (;; s++) {
        if ((unsigned char)*s == target)
            return (char *)s;
        if (*s == '\0')
            return (char *)0; /* c=='\0' 已在上一行命中串尾 NUL */
    }
}

char *strrchr(const char *s, int c)
{
    unsigned char target = (unsigned char)c;
    const char *last = (const char *)0;

    for (;; s++) {
        if ((unsigned char)*s == target)
            last = s;
        if (*s == '\0')
            return (char *)last;
    }
}

char *strstr(const char *h, const char *n)
{
    if (*n == '\0')
        return (char *)h; /* 空针匹配任意串首（含空 haystack） */

    for (; *h != '\0'; h++) {
        const char *a = h;
        const char *b = n;

        while (*a != '\0' && *b != '\0' && *a == *b) {
            a++;
            b++;
        }
        if (*b == '\0')
            return (char *)h;
    }
    return (char *)0;
}

/* ASCII 大小写折叠（其余字节原样参与比较，unsigned char 语义） */
static int catos_case_fold(unsigned char c)
{
    return (c >= 'A' && c <= 'Z') ? c + ('a' - 'A') : c;
}

int strcasecmp(const char *a, const char *b)
{
    while (*a != '\0' &&
           catos_case_fold((unsigned char)*a) ==
               catos_case_fold((unsigned char)*b)) {
        a++;
        b++;
    }
    return catos_case_fold((unsigned char)*a) -
           catos_case_fold((unsigned char)*b);
}

int strncasecmp(const char *a, const char *b, size_t n)
{
    for (size_t i = 0u; i < n; i++) {
        int ca = catos_case_fold((unsigned char)a[i]);
        int cb = catos_case_fold((unsigned char)b[i]);

        if (ca != cb)
            return ca - cb;
        if (a[i] == '\0')
            return 0;
    }
    return 0;
}

char *strtok_r(char *s, const char *delim, char **sp)
{
    char *tok;
    char *cur;

    if (s == (char *)0)
        s = *sp; /* 续扫：从上次保存点恢复 */
    if (s == (char *)0) {
        *sp = (char *)0;
        return (char *)0;
    }

    /* 跳过前导分隔符（连续分隔符不产生空 token） */
    cur = s;
    while (*cur != '\0' && strchr(delim, (unsigned char)*cur) != (char *)0)
        cur++;
    if (*cur == '\0') {
        *sp = cur; /* 全是分隔符：游标停在终结符处 */
        return (char *)0;
    }

    tok = cur;
    /* 推进至下一分隔符或串尾 */
    while (*cur != '\0' && strchr(delim, (unsigned char)*cur) == (char *)0)
        cur++;
    if (*cur != '\0') {
        *cur++ = '\0'; /* 原地截断 token */
    }
    *sp = cur; /* 无论是否截断，均保存续扫起点 */
    return tok;
}
