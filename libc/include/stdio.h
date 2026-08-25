/*
 * stdio.h —— Cat-OS 最小用户态 C 库：标准 I/O 声明（code9 · 并行任务）
 * ─────────────────────────────────────────────────────────────────────────────
 * freestanding 头文件自洽：va_list 直接取 GCC 内建 __builtin_va_*，
 * 不依赖系统 <stdarg.h>。
 *
 * 所用 syscall（号表对照 syscall.h / vfs.h VFS 兼容 ABI，已核实）：
 *   nr=1 write(fd,buf,len) —— fd1 = stdout（/dev/console，vfs_init 安装）。
 *
 * ⚠️ 已知内核 ABI 陷阱（syscall.c L8 审计块）：nr==3 在本内核被别名到 close，
 *   绝不可当 read 使用；本库只使用 nr=1，不触碰该雷区。
 */

#ifndef CATOS_LIBC_STDIO_H
#define CATOS_LIBC_STDIO_H

#ifndef CATOS_LIBC_SIZE_T_DEFINED
#define CATOS_LIBC_SIZE_T_DEFINED
typedef __SIZE_TYPE__ size_t;
#endif

#ifndef CATOS_LIBC_NULL_DEFINED
#define CATOS_LIBC_NULL_DEFINED
#define NULL ((void *)0)
#endif

/* 变参支持：GCC freestanding 内建，无需宿主头 */
typedef __builtin_va_list va_list;
#define va_start(v, l) __builtin_va_start(v, l)
#define va_arg(v, T)   __builtin_va_arg(v, T)
#define va_end(v)      __builtin_va_end(v)
#define va_copy(d, s)  __builtin_va_copy(d, s)

/* ── write 封装（VFS 兼容 ABI nr=1）───────────────────────────────────
 * 返回：成功 = 实际写入字节数；失败 = 负 errno（-EFAULT/-EBADF/…，
 * 内核经 sign-extend 写回 EAX）。不设全局 errno 变量。 */
int write(int fd, const void *buf, unsigned int len);

/* stdout 输出（fd=1）。putchar 返回写入的字符或负 errno；
 * puts 返回输出的字节数（含追加的 '\n'）或负 errno。 */
int putchar(int c);
int puts(const char *s);

/* 精简 printf：支持 %s %d %u %x %c %%。
 * - %x 为小写十六进制、无填充无前缀；%d 处理 INT_MIN；
 * - %s 对 NULL 打印 "(null)"（防 ring3 空指针解引用）；
 * - 未支持的转换符按字面输出 '%' + 该字符；
 * - 无缓冲：每个片段直接一次 write syscall（精简实现取舍，见 README）。
 * 返回：成功 = 输出字符总数；输出失败 = 负值。 */
int printf(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

#endif /* CATOS_LIBC_STDIO_H */
