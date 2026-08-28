
#ifndef _SHIM_SYS_VFS_H
#define _SHIM_SYS_VFS_H
#include <sys/types.h>
struct statfs {
    unsigned long f_type; unsigned long f_bsize; unsigned long f_blocks;
    unsigned long f_bfree; unsigned long f_bavail; unsigned long f_files;
    unsigned long f_ffree; unsigned long f_fsid[2]; unsigned long f_namelen;
    unsigned long f_frsize; unsigned long f_flags; unsigned long f_spare[4];
};
int statfs(const char *, struct statfs *);
#endif
