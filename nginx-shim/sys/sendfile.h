
#ifndef _SHIM_SYS_SENDFILE_H
#define _SHIM_SYS_SENDFILE_H
#include <sys/types.h>
ssize_t sendfile(int, int, off_t *, size_t);
#endif
