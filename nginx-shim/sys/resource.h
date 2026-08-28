
#ifndef _SHIM_SYS_RESOURCE_H
#define _SHIM_SYS_RESOURCE_H
#include <sys/types.h>
#define RLIMIT_NOFILE 7
#define RLIMIT_STACK 3
#define RLIMIT_AS 9
#define RLIMIT_CORE 4
#define RLIMIT_NPROC 6
#define RLIM_INFINITY ((unsigned long)-1)
struct rlimit { rlim_t rlim_cur; rlim_t rlim_max; };
int getrlimit(int, struct rlimit *);
int setrlimit(int, const struct rlimit *);
#endif
