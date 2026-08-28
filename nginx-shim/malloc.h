
#ifndef _SHIM_MALLOC_H
#define _SHIM_MALLOC_H
#include <stddef.h>
#include <sys/types.h>
void *malloc(size_t);
void *calloc(size_t, size_t);
void *realloc(void *, size_t);
void free(void *);
void *memalign(size_t, size_t);
void *valloc(size_t);
void *pvalloc(size_t);
int posix_memalign(void **, size_t, size_t);
#endif
