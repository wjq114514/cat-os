
#ifndef _SHIM_SYS_TIME_H
#define _SHIM_SYS_TIME_H
#include <stddef.h>
#include <sys/types.h>
struct timeval { time_t tv_sec; long tv_usec; };
struct timezone { int tz_minuteswest; int tz_dsttime; };
struct itimerval {
    struct timeval it_interval;
    struct timeval it_value;
};
#define ITIMER_REAL    0
#define ITIMER_VIRTUAL 1
#define ITIMER_PROF    2
int gettimeofday(struct timeval *, struct timezone *);
int settimeofday(const struct timeval *, const struct timezone *);
int utimes(const char *, const struct timeval[2]);
int setitimer(int, const struct itimerval *, struct itimerval *);
int getitimer(int, struct itimerval *);
#endif
