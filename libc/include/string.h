/*
 * string.h —— Cat-OS 最小用户态 C 库：字符串/内存块函数声明（code9 · 并行任务）
 * ─────────────────────────────────────────────────────────────────────────────
 * freestanding 头文件自洽：不 include 任何系统头；size_t/NULL 用 GCC 内建
 * 类型宏定义，并以守卫宏防止与同库其他头文件重复 typedef 冲突。
 *
 * int 0x80 调用约定（据 interrupts.c interrupt_dispatch vector==128 分支核实，
 * 四源一致：interrupts.c 寄存器打包 / syscall.c 注释 / shell_user.c 内联汇编 /
 * usermode.c 机器码生成器）：
 *   EAX = nr；EBX,ECX,EDX,ESI,EDI → a[0..4]；返回值 sign-extend 写回 EAX。
 * 本头文件的函数为纯实现，不发任何 syscall。
 */

#ifndef CATOS_LIBC_STRING_H
#define CATOS_LIBC_STRING_H

#ifndef CATOS_LIBC_SIZE_T_DEFINED
#define CATOS_LIBC_SIZE_T_DEFINED
typedef __SIZE_TYPE__ size_t;
#endif

#ifndef CATOS_LIBC_NULL_DEFINED
#define CATOS_LIBC_NULL_DEFINED
#define NULL ((void *)0)
#endif

/* 内存块：纯实现，无边界检查（与标准语义一致，调用方负责长度） */
void *memset(void *s, int c, size_t n);
void *memcpy(void *dst, const void *src, size_t n);      /* 不处理重叠 */
void *memmove(void *dst, const void *src, size_t n);     /* 处理重叠   */

/* 字符串 */
size_t strlen(const char *s);
int strcmp(const char *a, const char *b);                /* <0/0/>0，unsigned char 语义 */
int strncmp(const char *a, const char *b, size_t n);
char *strcpy(char *dst, const char *src);                /* 含 NUL，返回 dst */
char *strcat(char *dst, const char *src);                /* 追加含 NUL，返回 dst */

#endif /* CATOS_LIBC_STRING_H */
