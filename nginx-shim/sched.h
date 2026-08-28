
#ifndef _SHIM_SCHED_H
#define _SHIM_SCHED_H
#include <sys/types.h>
struct sched_param { int sched_priority; };
int sched_yield(void);
int sched_setaffinity(pid_t, size_t, const unsigned long *);
int sched_getaffinity(pid_t, size_t, unsigned long *);
#define SCHED_OTHER 0
#define SCHED_FIFO  1
#define SCHED_RR    2
#define PRIO_PROCESS 0
#define PRIO_PGRP   1
#define PRIO_USER   2
int setpriority(int, id_t, int);
int getpriority(int, id_t);
int initgroups(const char *, gid_t);
#define __CPU_SETSIZE 1024
#define __NCPUBITS (8 * sizeof(unsigned long))
typedef struct { unsigned long __bits[__CPU_SETSIZE/__NCPUBITS]; } cpu_set_t;
#define CPU_ZERO(cpuset) do { unsigned long *__p = (cpuset)->__bits; unsigned long __i; for (__i = 0; __i < __CPU_SETSIZE/__NCPUBITS; __i++) __p[__i] = 0; } while(0)
#define CPU_SET(cpu, cpuset) ((cpuset)->__bits[(cpu)/__NCPUBITS] |= (1UL << ((cpu) % __NCPUBITS)))
#define CPU_CLR(cpu, cpuset) ((cpuset)->__bits[(cpu)/__NCPUBITS] &= ~(1UL << ((cpu) % __NCPUBITS)))
#define CPU_ISSET(cpu, cpuset) ((cpuset)->__bits[(cpu)/__NCPUBITS] & (1UL << ((cpu) % __NCPUBITS)))
#define CPU_SETSIZE __CPU_SETSIZE
#endif
