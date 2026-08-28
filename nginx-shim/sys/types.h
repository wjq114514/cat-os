
#ifndef _SHIM_SYS_TYPES_H
#define _SHIM_SYS_TYPES_H
#include <stddef.h>
#include <stdint.h>
/* POSIX basic types */
typedef long ssize_t; typedef long off_t; typedef long off64_t;
typedef unsigned long ino_t; typedef int pid_t; typedef unsigned int uid_t;
typedef unsigned int gid_t; typedef long dev_t; typedef unsigned long mode_t;
typedef long nlink_t; typedef unsigned long blksize_t; typedef unsigned long blkcnt_t;
typedef long clock_t; typedef unsigned long time_t; typedef unsigned long useconds_t;
typedef int socklen_t; typedef uint16_t in_port_t; typedef uint32_t in_addr_t;
typedef unsigned long rlim_t; typedef unsigned long fpos_t; typedef unsigned int id_t;
typedef char *caddr_t;
/* BSD extension types used by nginx */
typedef unsigned char  u_char;
typedef unsigned short u_short;
typedef unsigned int   u_int;
typedef unsigned long  u_long;
#endif
