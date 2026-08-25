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

char *strcat(char *dst, const char *src)
{
    char *d = dst;

    while (*d != '\0')
        d++;
    while ((*d++ = *src++) != '\0')
        ;
    return dst;
}
