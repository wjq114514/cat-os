
#ifndef _SHIM_TIME_H
#define _SHIM_TIME_H
#include <stddef.h>
#include <sys/types.h>
#include <sys/time.h>
struct tm {
    int tm_sec; int tm_min; int tm_hour;
    int tm_mday; int tm_mon; int tm_year;
    int tm_wday; int tm_yday; int tm_isdst;
    long tm_gmtoff; const char *tm_zone;
};
#define CLOCKS_PER_SEC 1000000L
#define CLOCK_REALTIME  0
#define CLOCK_MONOTONIC 1
#define CLOCK_MONOTONIC_RAW 4
#define CLOCK_BOOTTIME  5
#define TIMER_ABSTIME   1
struct timespec { time_t tv_sec; long tv_nsec; };
clock_t clock(void);
time_t time(time_t *);
int clock_gettime(int, struct timespec *);
int clock_settime(int, const struct timespec *);
int nanosleep(const struct timespec *, struct timespec *);
struct tm *gmtime(const time_t *);
struct tm *localtime(const time_t *);
struct tm *localtime_r(const time_t *, struct tm *);
struct tm *gmtime_r(const time_t *, struct tm *);
time_t mktime(struct tm *);
size_t strftime(char *, size_t, const char *, const struct tm *);
void tzset(void);
#endif
