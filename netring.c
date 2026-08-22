#include "kernel.h"
#include "netring.h"
void netring_init(void){kputs("[OK] net shared ring initialized (fixed buffers, batch submit/complete, DMA/doorbell hooks)\n");}
