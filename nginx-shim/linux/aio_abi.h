
#ifndef _SHIM_LINUX_AIO_ABI_H
#define _SHIM_LINUX_AIO_ABI_H
#include <stdint.h>
typedef unsigned long aio_context_t;
struct iocb {
    uint64_t aio_data; uint32_t aio_key; uint16_t aio_lio_opcode;
    uint16_t aio_reqprio; uint32_t aio_buf; uint32_t aio_nbytes;
    uint64_t aio_offset; uint64_t aio_reserved2; uint32_t aio_flags;
    uint32_t aio_resfd;
};
#endif
