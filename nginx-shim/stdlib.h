
#ifndef _SHIM_STDLIB_H
#define _SHIM_STDLIB_H
#include <stddef.h>
#include <sys/types.h>
void *malloc(size_t); void *calloc(size_t, size_t);
void *realloc(void *, size_t); void free(void *);
void exit(int); void _exit(int); void abort(void);
int atexit(void (*)(void)); int on_exit(void (*)(int, void *), void *);
int system(const char *);
int atoi(const char *); long atol(const char *); long long atoll(const char *);
long strtol(const char *, char **, int);
unsigned long strtoul(const char *, char **, int);
long long strtoll(const char *, char **, int);
void srand(unsigned int); int rand(void);
long random(void); void srandom(unsigned int);
void qsort(void *, size_t, size_t, int (*)(const void *, const void *));
void *bsearch(const void *, const void *, size_t, size_t, int (*)(const void *, const void *));
int abs(int); long labs(long);
char *getenv(const char *); int putenv(char *);
int posix_memalign(void **, size_t, size_t);
char *realpath(const char *, char *);
#define RAND_MAX 2147483647
#endif
