#ifndef CATOS_KERNEL_H
#define CATOS_KERNEL_H

#include <stdint.h>

/* 内核 errno 常量（与 linux-ref/include/uapi/asm-generic/errno-base.h 对齐） */
#ifndef EPERM
#define EPERM    1
#endif
#ifndef ENOENT
#define ENOENT   2
#endif
#ifndef ENOEXEC
#define ENOEXEC  8
#endif
#ifndef EBADF
#define EBADF    9
#endif
#ifndef ENOMEM
#define ENOMEM  12
#endif
#ifndef EACCES
#define EACCES  13
#endif
#ifndef EFAULT
#define EFAULT  14
#endif
#ifndef EINVAL
#define EINVAL  22
#endif
#ifndef EAGAIN
#define EAGAIN  11
#endif
#ifndef ENOTSOCK
#define ENOTSOCK 88
#endif
#ifndef EMSGSIZE
#define EMSGSIZE 90
#endif

void kputs(const char *s);
void kput_hex32(uint32_t value);
void kput_dec(uint32_t value);
void kput_sdec(int32_t value);
void panic(const char *message) __attribute__((noreturn));

/* stage4: IRQ0 tick 钩子 —— 延迟自动拉起内嵌 sock_abi 测试进程（kernel.c 实现） */
void stage4_autorun_tick(void);

#endif
