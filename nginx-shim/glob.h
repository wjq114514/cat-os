
#ifndef _SHIM_GLOB_H
#define _SHIM_GLOB_H
#include <sys/types.h>
#define GLOB_ERR      (1<<0)
#define GLOB_MARK     (1<<1)
#define GLOB_NOSPACE  (1<<2)
#define GLOB_ABORTED  (1<<3)
#define GLOB_NOMATCH  (1<<4)
#define GLOB_NOCHECK  (1<<5)
#define GLOB_APPEND   (1<<6)
#define GLOB_NOESCAPE (1<<7)
typedef struct {
    size_t gl_pathc; char **gl_pathv; size_t gl_offs;
    size_t gl_pathc_alloc;
} glob_t;
int glob(const char *, int, int (*)(const char *, int), glob_t *);
void globfree(glob_t *);
#endif
