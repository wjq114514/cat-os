
#ifndef _SHIM_GRP_H
#define _SHIM_GRP_H
#include <sys/types.h>
struct group { char *gr_name; gid_t gr_gid; char **gr_mem; };
struct group *getgrnam(const char *);
struct group *getgrgid(gid_t);
#endif
