
#ifndef _SHIM_SYS_SYSCALL_H
#define _SHIM_SYS_SYSCALL_H
#define __NR_read     0
#define __NR_write    1
#define __NR_open     2
#define __NR_close    3
#define __NR_stat     4
#define __NR_fstat    5
#define __NR_lstat    6
#define __NR_lseek    7
#define __NR_mmap     9
#define __NR_mprotect 10
#define __NR_munmap   11
#define __NR_brk      45
#define __NR_ioctl    54
#define __NR_fcntl    55
#define __NR_dup2     63
#define __NR_mmap2    192
#define __NR_gettimeofday 196
#define __NR_fstat64  197
#define SYS_capget 125
#define SYS_capset 158
#include <stdarg.h>
long syscall(long number, ...);
#endif
