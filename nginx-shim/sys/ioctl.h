
#ifndef _SHIM_SYS_IOCTL_H
#define _SHIM_SYS_IOCTL_H
#include <sys/types.h>
#define FIONBIO  0x5421
#define FIONREAD 0x541B
#define FIOASYNC 0x5452
int ioctl(int, unsigned long, ...);
#endif
