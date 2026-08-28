/*
 * errno.h —— Cat-OS 最小用户态 C 库：错误码（strtol 家族等使用）
 * ─────────────────────────────────────────────────────────────────────────────
 * freestanding 头文件自洽；errno 为普通进程级全局 int
 * （Cat-OS ring3 单线程，无 TLS 需求）。数值对齐 Linux/通用 ABI 习惯。
 */

#ifndef CATOS_LIBC_ERRNO_H
#define CATOS_LIBC_ERRNO_H

#define ENOENT  2  /* No such file or directory */
#define EFAULT 14  /* Bad address */
#define EINVAL 22 /* 无效参数 */
#define ERANGE 34 /* 数值结果超范围 */

extern int errno;
int *__errno_location(void);

#endif /* CATOS_LIBC_ERRNO_H */
