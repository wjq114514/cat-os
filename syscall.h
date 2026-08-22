#ifndef CATOS_SYSCALL_H
#define CATOS_SYSCALL_H
#include <stdint.h>
#define CATOS_ENOSYS 38
#define CATOS_EFAULT 14
void syscall_init(void);
int32_t syscall_dispatch(uint32_t,uint32_t,const uint32_t *);
int user_range_ok(uint32_t,uint32_t);
#endif
