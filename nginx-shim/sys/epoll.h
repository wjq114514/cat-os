
#ifndef _SHIM_SYS_EPOLL_H
#define _SHIM_SYS_EPOLL_H
#include <sys/types.h>
typedef union epoll_data { void *ptr; int fd; unsigned u32; unsigned long u64; } epoll_data_t;
struct epoll_event { uint32_t events; epoll_data_t data; };
#define EPOLLIN  0x001
#define EPOLLOUT 0x004
#define EPOLLERR 0x008
#define EPOLLHUP 0x010
#define EPOLLRDHUP 0x2000
#define EPOLLET  0x80000000
#define EPOLLONESHOT 0x40000000
#define EPOLLEXCLUSIVE (1u<<28)
#define EPOLL_CTL_ADD 1
#define EPOLL_CTL_DEL 2
#define EPOLL_CTL_MOD 3
static inline int epoll_create(int s){(void)s;return -1;}
static inline int epoll_create1(int f){(void)f;return -1;}
static inline int epoll_ctl(int o,int f,int e,struct epoll_event *ev){
    (void)o;(void)f;(void)e;(void)ev;return -1;}
static inline int epoll_wait(int o,struct epoll_event *e,int m,int t){
    (void)o;(void)e;(void)m;(void)t;return -1;}
#endif
