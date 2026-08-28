
#ifndef _SHIM_SYS_EVENTFD_H
#define _SHIM_SYS_EVENTFD_H
#include <stdint.h>
typedef uint64_t eventfd_t;
#define EFD_SEMAPHORE 0x1
#define EFD_CLOEXEC   0x80000
#define EFD_NONBLOCK  0x800
static inline int eventfd(unsigned int initval, int flags){(void)initval;(void)flags;return -1;}
static inline int eventfd_read(int fd, eventfd_t *value){(void)fd;(void)value;return -1;}
static inline int eventfd_write(int fd, eventfd_t value){(void)fd;(void)value;return -1;}
#endif
