
#ifndef _SHIM_DLFCN_H
#define _SHIM_DLFCN_H
#define RTLD_LAZY    1
#define RTLD_NOW     2
#define RTLD_GLOBAL  256
void *dlopen(const char *, int);
void *dlsym(void *, const char *);
int   dlclose(void *);
char *dlerror(void);
#endif
