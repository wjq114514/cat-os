
#ifndef _SHIM_SEMAPHORE_H
#define _SHIM_SEMAPHORE_H
#include <sys/types.h>
typedef struct { int dummy; } sem_t;
#define SEM_FAILED ((sem_t *)0)
int sem_init(sem_t *, int, unsigned);
int sem_destroy(sem_t *);
int sem_wait(sem_t *);
int sem_trywait(sem_t *);
int sem_post(sem_t *);
sem_t *sem_open(const char *, int, ...);
int sem_close(sem_t *);
int sem_unlink(const char *);
#endif
