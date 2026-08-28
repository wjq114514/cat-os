
#ifndef _SHIM_SYS_WAIT_H
#define _SHIM_SYS_WAIT_H
#include <sys/types.h>
#define WNOHANG 1
#define WUNTRACED 2
#define WEXITED 4
#define WCONTINUED 8
#define WTERMSIG(s) ((s)&0x7f)
#define WIFEXITED(s) (((s)&0x7f)==0)
#define WEXITSTATUS(s) (((s)>>8)&0xff)
#define WIFSIGNALED(s) (((unsigned)((s)&0x7f)-1u)<0x7eu)
#define WIFSTOPPED(s) (((s)&0xff)==0x7f)
#define WSTOPSIG(s) (((s)>>8)&0xff)
pid_t wait(int *); pid_t waitpid(pid_t, int *, int);
#endif
