
#ifndef _SHIM_PWD_H
#define _SHIM_PWD_H
#include <sys/types.h>
struct passwd {
    char *pw_name; uid_t pw_uid; gid_t pw_gid;
    char *pw_dir; char *pw_shell; char *pw_passwd;
};
struct passwd *getpwnam(const char *);
struct passwd *getpwuid(uid_t);
#endif
