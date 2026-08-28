
#ifndef _SHIM_SYS_PRCTL_H
#define _SHIM_SYS_PRCTL_H
#define PR_SET_DUMPABLE 4
#define PR_SET_KEEPCAPS 8
static inline int prctl(int o,...){(void)o;return -1;}
#endif
