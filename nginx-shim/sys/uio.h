
#ifndef _SHIM_SYS_UIO_H
#define _SHIM_SYS_UIO_H
#include <sys/types.h>
struct iovec { void *iov_base; size_t iov_len; };
ssize_t readv(int, const struct iovec *, int);
ssize_t writev(int, const struct iovec *, int);
ssize_t preadv(int, const struct iovec *, int, off_t);
ssize_t pwritev(int, const struct iovec *, int, off_t);
#endif
