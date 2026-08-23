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
#define CATOS_ETIMEDOUT 110
void syscall_init(void);
int32_t syscall_dispatch(uint32_t,uint32_t,const uint32_t *);
int user_range_ok(uint32_t,uint32_t);
#endif
