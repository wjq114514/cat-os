#ifndef CATOS_SYSCALL_H
#define CATOS_SYSCALL_H
#include <stdint.h>
#define CATOS_ENOSYS 38
#define CATOS_EFAULT 14
#define CATOS_EBADF 9
#define CATOS_ENOTSOCK 88
#define CATOS_EINVAL 22
#define CATOS_EAGAIN 11
#define CATOS_EADDRINUSE 98
#define CATOS_EMFILE 24
#define CATOS_ENOTCONN 107
/* ── errno 补充（fork/waitpid/kill 组；数值依据 linux-ref include/uapi/
 *    asm-generic/errno-base.h：EPERM=:7 ESRCH=:3 ENOENT=:2 ECHILD=:11 行）── */
#define CATOS_EPERM 1
#define CATOS_ESRCH 3
#define CATOS_ENOENT 2
#define CATOS_E2BIG 7
#define CATOS_ECHILD 10
#define CATOS_ENOSPC 28
#define CATOS_ESPIPE 29
#define CATOS_ENOTTY 25
#define CATOS_ENOTSUP 95
#define CATOS_ENOMEM 12
#define CATOS_AF_INET 2
#define CATOS_SOCK_DGRAM 2
#define CATOS_SOCK_STREAM 1
#define CATOS_SYS_SOCKET 20
#define CATOS_SYS_BIND 21
#define CATOS_SYS_LISTEN 22
#define CATOS_SYS_ACCEPT 23
#define CATOS_SYS_SENDTO 24
#define CATOS_SYS_RECVFROM 25
#define CATOS_SYS_SEND 26
#define CATOS_SYS_RECV 27
#define CATOS_SYS_CLOSE 28
#define CATOS_SYS_PING 29
#define CATOS_SYS_PING_STATS 30
#define CATOS_SYS_RESOLVE 31
#define CATOS_SYS_NET_STATS 32
/* ── 进程控制组编号锁定（2026-08-26，nginx M1 任务）：nr=33/34/35 归
 *    fork/waitpid/kill 专属；poll 及后续扩展自 nr=36 起预留，不得占用。
 *    EXEC/EXIT/WAIT(13) 为历史号段自 syscall.c 迁入统一管理（值不变）。 ── */
#define CATOS_SYS_EXEC 11
#define CATOS_SYS_EXIT 12
#define CATOS_SYS_WAIT 13   /* 遗留 stub（恒 -ECHILD），真实语义在 nr=34 */
#define CATOS_SYS_FORK 33
#define CATOS_SYS_WAITPID 34
#define CATOS_SYS_KILL 35
#define CATOS_ETIMEDOUT 110
/* ── Wave 1 新增（nginx M2 事件 + 时间 + POSIX 补全）───────────────── */
#define CATOS_SYS_GETTIMEOFDAY  196
#define CATOS_SYS_CLOCK_GETTIME 263
#define CATOS_SYS_POLL          168
#define CATOS_SYS_LSEEK         19
#define CATOS_SYS_FSTAT         197
#define CATOS_SYS_DUP2          63
#define CATOS_SYS_FCNTL         55
#define CATOS_SYS_IOCTL         54
#define CATOS_SYS_WRITEV        146
#define CATOS_SYS_MMAP2         192
#define CATOS_SYS_MUNMAP        91
#define CATOS_SYS_BRK           45
/* struct catos_pollfd (for poll nr=168) */
#define CATOS_POLLIN   0x001
#define CATOS_POLLOUT  0x004
#define CATOS_POLLERR  0x008
struct catos_pollfd { int fd; short events; short revents; };
void syscall_init(void);
int32_t syscall_dispatch(uint32_t,uint32_t,const uint32_t *);
int user_range_ok(uint32_t,uint32_t);
#endif
