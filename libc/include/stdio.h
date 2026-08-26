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

/* ── write/read 封装（VFS 兼容 ABI nr=1 / nr=0）──────────────────────
 * 返回：成功 = 实际传输字节数；失败 = 负 errno（-EFAULT/-EBADF/…，
 * 内核经 sign-extend 写回 EAX）。不设全局 errno 变量。
 * ⚠️ nr==3 在本内核被别名到 close（雷区），read 走 nr=0，与此无关。 */
int read(int fd, void *buf, unsigned int len);
int write(int fd, const void *buf, unsigned int len);

/* stdout 输出（fd=1）。putchar 返回写入的字符或负 errno；
 * puts 返回输出的字节数（含追加的 '\n'）或负 errno。 */
int putchar(int c);
int puts(const char *s);

/* stdin（fd=0）逐字节读取。getchar 返回 (unsigned char) 字符，
 * EOF/错误返回 -1。 */
int getchar(void);

/* 行读取（Cat-OS 精简 ABI 取舍：第三参为文件描述符而非 FILE*）。
 * 从 fd 读至多 size-1 字节，遇 '\n' 停止并保留之，恒补 '\0'。
 * 成功返回 s；size<=1、立即 EOF 或读错误返回 NULL（部分已读数据仍留在 s）。 */
char *fgets(char *s, int size, int fd);

/* printf 家族：支持 %s %d %u %x %c %p %% 及标志/宽度。
 * - %x 为小写十六进制、无前缀；%d 处理 INT_MIN；
 * - %p 打印 "0x"+小写十六进制；空指针打印 "(nil)"；
 * - 宽度：'%' 后十进制数字指定最小字段宽（默认空格右填充）；
 *   '-' 标志改为左对齐（右填充），如 "%-5d"；
 *   '0' 标志数值类（%d/%u/%x/%p）改用零填充，负号/"0x" 前缀保持在
 *   零之前（"%05d",-42 → "-0042"）；'-' 同现时 '-' 优先；
 * - 不支持：精度、长度修饰符、动态宽度 '*'（按字面回放）；
 * - %s 对 NULL 打印 "(null)"（防 ring3 空指针解引用）；
 * - 未支持的转换符按字面输出 '%' 起、至该字符止的原文；
 * - 无缓冲：每个片段直接一次 write syscall（精简实现取舍，见 README）。
 * 返回：成功 = 输出字符总数；输出失败 = 负值。 */
int printf(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

#endif /* CATOS_LIBC_STDIO_H */
