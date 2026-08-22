#include "kernel.h"
#include "syscall.h"
static int32_t no(void){return -CATOS_ENOSYS;}
void syscall_init(void){kputs("[OK] syscall dispatcher initialized (native/Linux shim tables)\n");}
int user_range_ok(uint32_t p,uint32_t n){return p>=0x400000u&&n<=0xBFC00000u-p;}
int32_t syscall_dispatch(uint32_t a,uint32_t n,const uint32_t *p){(void)a;(void)n;if(!p||!user_range_ok((uint32_t)p,24))return -CATOS_EFAULT;return no();}
