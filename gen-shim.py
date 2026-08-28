#!/usr/bin/env python3
"""Generate all POSIX shim headers for nginx cross-compilation on Cat-OS."""
import os
from pathlib import Path

SHIM = str(Path(__file__).resolve().parent / "nginx-shim")
os.makedirs(f"{SHIM}/sys", exist_ok=True)
os.makedirs(f"{SHIM}/netinet", exist_ok=True)
os.makedirs(f"{SHIM}/arpa", exist_ok=True)

def w(path, content):
    full = os.path.join(SHIM, path)
    os.makedirs(os.path.dirname(full), exist_ok=True)
    with open(full, "w") as f:
        f.write(content)
    print(f"  + {path}")

# ── sys/types.h ──
w("sys/types.h", r"""
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
""")

# ── sys/time.h ──
w("sys/time.h", r"""
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
""")

# ── sys/stat.h ──
w("sys/stat.h", r"""
#ifndef _SHIM_SYS_STAT_H
#define _SHIM_SYS_STAT_H
#include <sys/types.h>
#define S_IFMT   0170000
#define S_IFSOCK 0140000
#define S_IFLNK  0120000
#define S_IFREG  0100000
#define S_IFBLK  0060000
#define S_IFDIR  0040000
#define S_IFCHR  0020000
#define S_IFIFO  0010000
#define S_ISBLK(m) (((m)&S_IFMT)==S_IFBLK)
#define S_ISCHR(m) (((m)&S_IFMT)==S_IFCHR)
#define S_ISDIR(m) (((m)&S_IFMT)==S_IFDIR)
#define S_ISFIFO(m) (((m)&S_IFMT)==S_IFIFO)
#define S_ISREG(m) (((m)&S_IFMT)==S_IFREG)
#define S_ISLNK(m) (((m)&S_IFMT)==S_IFLNK)
#define S_ISSOCK(m) (((m)&S_IFMT)==S_IFSOCK)
#define S_IRWXU 00700
#define S_IRUSR 00400
#define S_IWUSR 00200
#define S_IXUSR 00100
#define S_IRWXG 00070
#define S_IRGRP 00040
#define S_IWGRP 00020
#define S_IXGRP 00010
#define S_IRWXO 00007
#define S_IROTH 00004
#define S_IWOTH 00002
#define S_IXOTH 00001
#define S_ISUID 04000
#define S_ISGID 02000
#define S_ISVTX 01000
struct stat {
    dev_t st_dev; ino_t st_ino; mode_t st_mode; nlink_t st_nlink;
    uid_t st_uid; gid_t st_gid; dev_t st_rdev; off_t st_size;
    blksize_t st_blksize; blkcnt_t st_blocks;
    struct timeval st_atim; struct timeval st_mtim; struct timeval st_ctim;
};
#define st_atime st_atim.tv_sec
#define st_mtime st_mtim.tv_sec
#define st_ctime st_ctim.tv_sec
int stat(const char *, struct stat *); int fstat(int, struct stat *);
int lstat(const char *, struct stat *); int chmod(const char *, mode_t);
int fchmod(int, mode_t); int mkdir(const char *, mode_t);
int unlink(const char *); int rmdir(const char *);
int rename(const char *, const char *);
#endif
""")

# ── sys/wait.h ──
w("sys/wait.h", r"""
#ifndef _SHIM_SYS_WAIT_H
#define _SHIM_SYS_WAIT_H
#include <sys/types.h>
#define WNOHANG 1
#define WUNTRACED 2
#define WEXITED 4
#define WCONTINUED 8
#define WTERMSIG(s) ((s)&0x7f)
#define WIFEXITED(s) (((s)&0x7f)==0)
#define WEXITSTATUS(s) (((s)>>8)&0xff)
#define WIFSIGNALED(s) (((unsigned)((s)&0x7f)-1u)<0x7eu)
#define WIFSTOPPED(s) (((s)&0xff)==0x7f)
#define WSTOPSIG(s) (((s)>>8)&0xff)
pid_t wait(int *); pid_t waitpid(pid_t, int *, int);
#endif
""")

# ── sys/mman.h ──
w("sys/mman.h", r"""
#ifndef _SHIM_SYS_MMAN_H
#define _SHIM_SYS_MMAN_H
#include <sys/types.h>
#define MAP_SHARED    0x01
#define MAP_PRIVATE   0x02
#define MAP_FIXED     0x10
#define MAP_ANONYMOUS 0x20
#define MAP_ANON      MAP_ANONYMOUS
#define MAP_FILE      0
#define PROT_READ     1
#define PROT_WRITE    2
#define PROT_EXEC     4
#define PROT_NONE     0
#define MAP_FAILED    ((void *)-1)
#define MADV_NORMAL 0
#define MADV_RANDOM 1
#define MADV_SEQUENTIAL 2
#define MADV_WILLNEED 3
#define MADV_DONTNEED 4
#define MS_SYNC 4
#define MS_ASYNC 1
void *mmap(void *, size_t, int, int, int, off_t);
int munmap(void *, size_t);
int mprotect(void *, size_t, int);
int madvise(void *, size_t, int);
int msync(void *, size_t, int);
#endif
""")

# ── fcntl.h ──
w("fcntl.h", r"""
#ifndef _SHIM_FCNTL_H
#define _SHIM_FCNTL_H
#include <sys/types.h>
#define O_RDONLY    0
#define O_WRONLY    1
#define O_RDWR      2
#define O_CREAT     0100
#define O_EXCL      0200
#define O_TRUNC     01000
#define O_APPEND    02000
#define O_NONBLOCK  04000
#define O_NDELAY    O_NONBLOCK
#define O_SYNC      04010000
#define O_FSYNC     O_SYNC
#define O_DIRECT    0200000
#define O_LARGEFILE 0
#define O_NOFOLLOW  0400000
#define O_CLOEXEC   02000000
#define O_PATH      010000000
#define O_DIRECTORY 0200000
#define AT_FDCWD         -100
#define AT_SYMLINK_NOFOLLOW 0400
#define AT_REMOVEDIR    0x200
#define AT_NO_AUTOMOUNT 0x1000
#define F_DUPFD  0
#define F_GETFD  1
#define F_SETFD  2
#define F_GETFL  3
#define F_SETFL  4
#define F_GETLK  5
#define F_SETLK  6
#define F_SETLKW 7
#define F_GETOWN 9
#define F_SETOWN 10
#define F_DUPFD_CLOEXEC 1030
#define FD_CLOEXEC 1
#define F_RDLCK 0
#define F_WRLCK 1
#define F_UNLCK 2
#define POSIX_FADV_NORMAL     0
#define POSIX_FADV_RANDOM     1
#define POSIX_FADV_SEQUENTIAL 2
#define POSIX_FADV_WILLNEED   3
#define POSIX_FADV_DONTNEED   4
#define POSIX_FADV_NOREUSE    5
struct flock { short l_type; short l_whence; off_t l_start; off_t l_len; pid_t l_pid; };
int open(const char *, int, ...);
int openat(int, const char *, int, ...);
int fcntl(int, int, ...);
int creat(const char *, mode_t);
int posix_fadvise(int, off_t, off_t, int);
#endif
""")

# ── sys/resource.h ──
w("sys/resource.h", r"""
#ifndef _SHIM_SYS_RESOURCE_H
#define _SHIM_SYS_RESOURCE_H
#include <sys/types.h>
#define RLIMIT_NOFILE 7
#define RLIMIT_STACK 3
#define RLIMIT_AS 9
#define RLIMIT_CORE 4
#define RLIMIT_NPROC 6
#define RLIM_INFINITY ((unsigned long)-1)
struct rlimit { rlim_t rlim_cur; rlim_t rlim_max; };
int getrlimit(int, struct rlimit *);
int setrlimit(int, const struct rlimit *);
#endif
""")

# ── sys/uio.h ──
w("sys/uio.h", r"""
#ifndef _SHIM_SYS_UIO_H
#define _SHIM_SYS_UIO_H
#include <sys/types.h>
struct iovec { void *iov_base; size_t iov_len; };
ssize_t readv(int, const struct iovec *, int);
ssize_t writev(int, const struct iovec *, int);
ssize_t preadv(int, const struct iovec *, int, off_t);
ssize_t pwritev(int, const struct iovec *, int, off_t);
#endif
""")

# ── sys/socket.h ──
w("sys/socket.h", r"""
#ifndef _SHIM_SYS_SOCKET_H
#define _SHIM_SYS_SOCKET_H
#include <sys/types.h>
#include <netinet/in.h>
struct sockaddr { sa_family_t sa_family; char sa_data[14]; };
struct sockaddr_storage { sa_family_t ss_family; char __ss_padding[128-sizeof(sa_family_t)]; };
struct msghdr {
    void *msg_name; socklen_t msg_namelen;
    struct iovec *msg_iov; int msg_iovlen;
    void *msg_control; socklen_t msg_controllen; int msg_flags;
};
struct cmsghdr {
    socklen_t cmsg_len; int cmsg_level; int cmsg_type;
};
#define AF_UNIX  1
#define AF_INET  2
#define AF_INET6 10
#define AF_PACKET 17
#define PF_UNIX  AF_UNIX
#define PF_INET  AF_INET
#define PF_INET6 AF_INET6
#define SOCK_STREAM 1
#define SOCK_DGRAM  2
#define SOCK_RAW    3
#define SOCK_NONBLOCK 0x800
#define SOCK_CLOEXEC 0x80000
#define SOL_SOCKET  1
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define SO_REUSEADDR 2
#define SO_REUSEPORT 15
#define SO_KEEPALIVE 9
#define SO_LINGER   13
#define SO_SNDBUF  7
#define SO_RCVBUF  8
#define SO_ERROR   4
#define SO_TYPE    3
#define SO_ACCEPTFILTER 0x1000
#define SO_NOSIGPIPE 0x1022
#define SO_COOKIE 0x39
#define SO_SNDLOWAT 19
#define SO_RCVLOWAT 18
#define SO_BUSY_POLL 46
#define IP_OPTIONS 1
#define IP_HDRINCL 3
#define IP_TOS 1
#define IP_TTL 2
#define IP_PKTINFO 8
#define IP_RECVDSTADDR 25
#define IP_TRANSPARENT 19
#define IP_BIND_ADDRESS_NO_PORT 24
#define IPV6_V6ONLY 26
#define IPV6_RECVPKTINFO 49
#define TCP_NODELAY   1
#define TCP_MAXSEG    2
#define TCP_CORK      3
#define TCP_KEEPIDLE  4
#define TCP_KEEPINTVL 5
#define TCP_KEEPCNT   6
#define TCP_DEFER_ACCEPT 9
#define TCP_FASTOPEN  23
#define TCP_INFO      11
#define TCP_QUICKACK  12
struct linger { int l_onoff; int l_linger; };
int socket(int, int, int);
int bind(int, const struct sockaddr *, socklen_t);
int listen(int, int);
int accept(int, struct sockaddr *, socklen_t *);
int accept4(int, struct sockaddr *, socklen_t *, int);
int connect(int, const struct sockaddr *, socklen_t);
ssize_t send(int, const void *, size_t, int);
ssize_t recv(int, void *, size_t, int);
ssize_t sendto(int, const void *, size_t, int, const struct sockaddr *, socklen_t);
ssize_t recvfrom(int, void *, size_t, int, struct sockaddr *, socklen_t *);
ssize_t sendmsg(int, const struct msghdr *, int);
ssize_t recvmsg(int, struct msghdr *, int);
int shutdown(int, int);
int setsockopt(int, int, int, const void *, socklen_t);
int getsockopt(int, int, int, void *, socklen_t *);
int socketpair(int, int, int, int[2]);
#define SHUT_RD 0
#define SHUT_WR 1
#define SHUT_RDWR 2
#define MSG_PEEK     0x02
#define MSG_DONTROUTE 0x04
#define MSG_DONTWAIT  0x40
#define MSG_WAITALL   0x100
#define MSG_NOSIGNAL  0x4000
#define MSG_CTRUNC    0x08
#define MSG_TRUNC     0x01
#define SCM_RIGHTS    0x01
int getsockname(int, struct sockaddr *, socklen_t *);
int getpeername(int, struct sockaddr *, socklen_t *);
struct accept_filter_arg { char af_name[16]; char af_arg[256-16]; };
#define SO_ACCEPTFILTER 0x1000
/* CMSG macros */
#define CMSG_ALIGN(len) (((len) + sizeof(long) - 1) & ~(sizeof(long) - 1))
#define CMSG_SPACE(len) (CMSG_ALIGN(sizeof(struct cmsghdr)) + CMSG_ALIGN(len))
#define CMSG_LEN(len)  (CMSG_ALIGN(sizeof(struct cmsghdr)) + (len))
#define CMSG_FIRSTHDR(mhdr) \
    ((mhdr)->msg_controllen >= sizeof(struct cmsghdr) ? \
     (struct cmsghdr *)(mhdr)->msg_control : (struct cmsghdr *)0)
#define CMSG_NXTHDR(mhdr, cmsg) \
    (((char *)(cmsg) + CMSG_ALIGN((cmsg)->cmsg_len) >= \
      (char *)(mhdr)->msg_control + (mhdr)->msg_controllen) ? \
     (struct cmsghdr *)0 : \
     (struct cmsghdr *)((char *)(cmsg) + CMSG_ALIGN((cmsg)->cmsg_len)))
#define CMSG_DATA(cmsg) ((unsigned char *)((struct cmsghdr *)(cmsg) + 1))
#endif
""")

# ── sys/ioctl.h ──
w("sys/ioctl.h", r"""
#ifndef _SHIM_SYS_IOCTL_H
#define _SHIM_SYS_IOCTL_H
#include <sys/types.h>
#define FIONBIO  0x5421
#define FIONREAD 0x541B
#define FIOASYNC 0x5452
int ioctl(int, unsigned long, ...);
#endif
""")

# ── sys/utsname.h ──
w("sys/utsname.h", r"""
#ifndef _SHIM_SYS_UTSNAME_H
#define _SHIM_SYS_UTSNAME_H
struct utsname {
    char sysname[65]; char nodename[65];
    char release[65];  char version[65]; char machine[65];
};
int uname(struct utsname *);
#endif
""")

# ── sys/vfs.h ──
w("sys/vfs.h", r"""
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
""")

# ── sys/sendfile.h ──
w("sys/sendfile.h", r"""
#ifndef _SHIM_SYS_SENDFILE_H
#define _SHIM_SYS_SENDFILE_H
#include <sys/types.h>
ssize_t sendfile(int, int, off_t *, size_t);
#endif
""")

# ── sys/param.h ──
w("sys/param.h", r"""
#ifndef _SHIM_SYS_PARAM_H
#define _SHIM_SYS_PARAM_H
#include <sys/types.h>
#define MAXPATHLEN 4096
#define NOFILE 256
#endif
""")

# ── sys/mount.h ──
w("sys/mount.h", r"""
#ifndef _SHIM_SYS_MOUNT_H
#define _SHIM_SYS_MOUNT_H
#endif
""")

# ── sys/statvfs.h ──
w("sys/statvfs.h", r"""
#ifndef _SHIM_SYS_STATVFS_H
#define _SHIM_SYS_STATVFS_H
#include <sys/types.h>
struct statvfs {
    unsigned long f_bsize; unsigned long f_frsize;
    fsblkcnt_t f_blocks; fsblkcnt_t f_bfree; fsblkcnt_t f_bavail;
    fsfilcnt_t f_files; fsfilcnt_t f_ffree; unsigned long f_fsid;
    unsigned long f_flag; unsigned long f_namemax;
    unsigned long __f_spare[6];
};
typedef unsigned long fsblkcnt_t;
typedef unsigned long fsfilcnt_t;
#define ST_RDONLY 1
#define ST_NOSUID 2
int statvfs(const char *, struct statvfs *);
int fstatvfs(int, struct statvfs *);
#endif
""")

# ── sys/epoll.h (stubs) ──
w("sys/epoll.h", r"""
#ifndef _SHIM_SYS_EPOLL_H
#define _SHIM_SYS_EPOLL_H
#include <sys/types.h>
typedef union epoll_data { void *ptr; int fd; unsigned u32; unsigned long u64; } epoll_data_t;
struct epoll_event { uint32_t events; epoll_data_t data; };
#define EPOLLIN  0x001
#define EPOLLOUT 0x004
#define EPOLLERR 0x008
#define EPOLLHUP 0x010
#define EPOLLRDHUP 0x2000
#define EPOLLET  0x80000000
#define EPOLLONESHOT 0x40000000
#define EPOLLEXCLUSIVE (1u<<28)
#define EPOLL_CTL_ADD 1
#define EPOLL_CTL_DEL 2
#define EPOLL_CTL_MOD 3
static inline int epoll_create(int s){(void)s;return -1;}
static inline int epoll_create1(int f){(void)f;return -1;}
static inline int epoll_ctl(int o,int f,int e,struct epoll_event *ev){
    (void)o;(void)f;(void)e;(void)ev;return -1;}
static inline int epoll_wait(int o,struct epoll_event *e,int m,int t){
    (void)o;(void)e;(void)m;(void)t;return -1;}
#endif
""")

# ── sys/eventfd.h (stubs) ──
w("sys/eventfd.h", r"""
#ifndef _SHIM_SYS_EVENTFD_H
#define _SHIM_SYS_EVENTFD_H
#include <stdint.h>
typedef uint64_t eventfd_t;
#define EFD_SEMAPHORE 0x1
#define EFD_CLOEXEC   0x80000
#define EFD_NONBLOCK  0x800
static inline int eventfd(unsigned int initval, int flags){(void)initval;(void)flags;return -1;}
static inline int eventfd_read(int fd, eventfd_t *value){(void)fd;(void)value;return -1;}
static inline int eventfd_write(int fd, eventfd_t value){(void)fd;(void)value;return -1;}
#endif
""")

# ── sys/prctl.h (stubs) ──
w("sys/prctl.h", r"""
#ifndef _SHIM_SYS_PRCTL_H
#define _SHIM_SYS_PRCTL_H
#define PR_SET_DUMPABLE 4
#define PR_SET_KEEPCAPS 8
static inline int prctl(int o,...){(void)o;return -1;}
#endif
""")

# ── sys/syscall.h ──
w("sys/syscall.h", r"""
#ifndef _SHIM_SYS_SYSCALL_H
#define _SHIM_SYS_SYSCALL_H
#define __NR_read     0
#define __NR_write    1
#define __NR_open     2
#define __NR_close    3
#define __NR_stat     4
#define __NR_fstat    5
#define __NR_lstat    6
#define __NR_lseek    7
#define __NR_mmap     9
#define __NR_mprotect 10
#define __NR_munmap   11
#define __NR_brk      45
#define __NR_ioctl    54
#define __NR_fcntl    55
#define __NR_dup2     63
#define __NR_mmap2    192
#define __NR_gettimeofday 196
#define __NR_fstat64  197
#endif
""")

# ── netinet/in.h ──
w("netinet/in.h", r"""
#ifndef _SHIM_NETINET_IN_H
#define _SHIM_NETINET_IN_H
#include <stdint.h>
#include <sys/types.h>
typedef uint16_t sa_family_t;
struct in_addr { in_addr_t s_addr; };
struct sockaddr_in {
    sa_family_t sin_family;
    in_port_t sin_port;
    struct in_addr sin_addr;
    char sin_zero[8];
};
struct in6_addr { uint8_t s6_addr[16]; };
struct sockaddr_in6 {
    sa_family_t sin6_family;
    in_port_t sin6_port;
    uint32_t sin6_flowinfo;
    struct in6_addr sin6_addr;
    uint32_t sin6_scope_id;
};
#define INADDR_ANY       ((in_addr_t)0)
#define INADDR_BROADCAST ((in_addr_t)0xffffffff)
#define INADDR_NONE      ((in_addr_t)0xffffffff)
#define INADDR_LOOPBACK  ((in_addr_t)0x7f000001)
#define INET6_ADDRSTRLEN 46
#define INET_ADDRSTRLEN  16
struct in_pktinfo { int ipi_ifindex; struct in_addr ipi_spec_dst; struct in_addr ipi_addr; };
struct in6_pktinfo { struct in6_addr ipi6_addr; int ipi6_ifindex; };
#define IPPROTO_IP    0
#define IPPROTO_ICMP  1
#define IPPROTO_TCP   6
#define IPPROTO_UDP  17
#define IPPROTO_RAW 255
#define htons(x) __builtin_bswap16(x)
#define ntohs(x) __builtin_bswap16(x)
#define htonl(x) __builtin_bswap32(x)
#define ntohl(x) __builtin_bswap32(x)
#endif
""")

# ── netinet/tcp.h ──
w("netinet/tcp.h", r"""
#ifndef _SHIM_NETINET_TCP_H
#define _SHIM_NETINET_TCP_H
#define TCP_NODELAY   1
#define TCP_MAXSEG    2
#define TCP_CORK      3
#define TCP_KEEPIDLE  4
#define TCP_KEEPINTVL 5
#define TCP_KEEPCNT   6
#define TCP_DEFER_ACCEPT 9
#define TCP_QUICKACK  12
#define TCP_FASTOPEN  23
#define TCP_INFO      11
struct tcp_info {
    uint8_t tcpi_state; uint8_t tcpi_ca_state; uint8_t tcpi_retransmits;
    uint8_t tcpi_probes; uint8_t tcpi_backoff; uint8_t tcpi_options;
    uint16_t tcpi_snd_wscale; uint16_t tcpi_rcv_wscale;
    uint32_t tcpi_rto; uint32_t tcpi_ato; uint32_t tcpi_snd_mss;
    uint32_t tcpi_rcv_mss; uint32_t tcpi_unacked; uint32_t tcpi_sacked;
    uint32_t tcpi_lost; uint32_t tcpi_retrans; uint32_t tcpi_fackets;
    uint32_t tcpi_last_data_sent; uint32_t tcpi_last_ack_sent;
    uint32_t tcpi_last_data_recv; uint32_t tcpi_last_ack_recv;
    uint32_t tcpi_pmtu; uint32_t tcpi_rcv_ssthresh; uint32_t tcpi_rtt;
    uint32_t tcpi_rttvar; uint32_t tcpi_snd_ssthresh; uint32_t tcpi_snd_cwnd;
    uint32_t tcpi_advmss; uint32_t tcpi_reordering;
};
#endif
""")

# ── arpa/inet.h ──
w("arpa/inet.h", r"""
#ifndef _SHIM_ARPA_INET_H
#define _SHIM_ARPA_INET_H
#include <stdint.h>
#include <netinet/in.h>
const char *inet_ntop(int, const void *, char *, socklen_t);
int inet_pton(int, const char *, void *);
in_addr_t inet_addr(const char *);
char *inet_ntoa(struct in_addr);
#endif
""")

# ── netdb.h ──
w("netdb.h", r"""
#ifndef _SHIM_NETDB_H
#define _SHIM_NETDB_H
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
struct addrinfo {
    int ai_flags; int ai_family; int ai_socktype; int ai_protocol;
    socklen_t ai_addrlen; struct sockaddr *ai_addr;
    char *ai_canonname; struct addrinfo *ai_next;
};
#define AI_PASSIVE     0x01
#define AI_CANONNAME   0x02
#define AI_NUMERICHOST 0x04
#define EAI_NONAME   -2
#define EAI_SERVICE  -8
#define EAI_ADDRFAMILY -9
#define EAI_MEMORY   -10
#define EAI_SYSTEM   -11
#define EAI_BADFLAGS -3
#define EAI_FAMILY   -5
#define NI_NUMERICHOST 1
#define NI_NUMERICSERV 2
#define NI_MAXHOST  1025
#define NI_MAXSERV  32
#define HOST_NOT_FOUND 1
#define NO_DATA 4
int getaddrinfo(const char *, const char *, const struct addrinfo *, struct addrinfo **);
void freeaddrinfo(struct addrinfo *);
int getnameinfo(const struct sockaddr *, socklen_t, char *, socklen_t, char *, socklen_t, int);
struct hostent *gethostbyname(const char *);
struct servent *getservbyname(const char *, const char *);
struct hostent {
    char *h_name; char **h_aliases; int h_addrtype; int h_length; char **h_addr_list;
};
struct servent { char *s_name; char **s_aliases; int s_port; char *s_proto; };
#endif
""")

# ── poll.h ──
w("poll.h", r"""
#ifndef _SHIM_POLL_H
#define _SHIM_POLL_H
#include <sys/types.h>
struct pollfd {
    int fd; short events; short revents;
};
typedef unsigned long nfds_t;
#define POLLIN   0x001
#define POLLPRI  0x002
#define POLLOUT  0x004
#define POLLERR  0x008
#define POLLHUP  0x010
#define POLLNVAL 0x020
#define POLLRDNORM 0x040
#define POLLRDBAND 0x080
#define POLLWRNORM 0x100
#define POLLWRBAND 0x200
#define POLLRDHUP 0x2000
int poll(struct pollfd *, nfds_t, int);
#endif
""")

# ── unistd.h ──
w("unistd.h", r"""
#ifndef _SHIM_UNISTD_H
#define _SHIM_UNISTD_H
#include <stddef.h>
#include <sys/types.h>
#include <sys/uio.h>
#define SEEK_SET 0
#define SEEK_CUR 1
#define SEEK_END 2
#define STDIN_FILENO  0
#define STDOUT_FILENO 1
#define STDERR_FILENO 2
#define R_OK 4
#define W_OK 2
#define X_OK 1
#define F_OK 0
#define _SC_NPROCESSORS_ONLN 83
#define _SC_LEVEL1_DCACHE_LINESIZE 190
#define _SC_CLK_TCK 1
#define _SC_PAGESIZE 28
#ifndef IOV_MAX
#define IOV_MAX 1024
#endif
int pipe(int[2]); int chdir(const char *); int fchdir(int);
char *getcwd(char *, size_t);
pid_t getpid(void); pid_t getppid(void);
uid_t getuid(void); uid_t geteuid(void);
gid_t getgid(void); gid_t getegid(void);
int setuid(uid_t); int setgid(gid_t);
long sysconf(int); int getpagesize(void);
int read(int, void *, size_t); int write(int, const void *, size_t);
ssize_t readv(int, const struct iovec *, int);
ssize_t writev(int, const struct iovec *, int);
ssize_t pread(int, void *, size_t, off_t);
ssize_t pwrite(int, const void *, size_t, off_t);
off_t lseek(int, off_t, int); int close(int);
int dup(int); int dup2(int, int);
int access(const char *, int); int isatty(int);
int setsid(void); pid_t fork(void);
int execve(const char *, char *const[], char *const[]);
int execv(const char *, char *const[]);
int execl(const char *, const char *, ...);
int execlp(const char *, const char *, ...);
int chown(const char *, uid_t, gid_t);
int fchown(int, uid_t, gid_t);
mode_t umask(mode_t);
unsigned int sleep(unsigned int);
int usleep(useconds_t);
int pause(void);
int gethostname(char *, size_t);
#endif
""")

# ── signal.h ──
w("signal.h", r"""
#ifndef _SHIM_SIGNAL_H
#define _SHIM_SIGNAL_H
#include <stddef.h>
#include <sys/types.h>
typedef volatile int sig_atomic_t;
#define _NSIG 65
typedef struct { unsigned long sig[_NSIG / (8 * sizeof(unsigned long))]; } sigset_t;
typedef void (*sighandler_t)(int);
#define SIG_DFL ((sighandler_t)0)
#define SIG_IGN ((sighandler_t)1)
#define SIGHUP 1
#define SIGINT 2
#define SIGQUIT 3
#define SIGILL 4
#define SIGTRAP 5
#define SIGABRT 6
#define SIGBUS 7
#define SIGFPE 8
#define SIGKILL 9
#define SIGUSR1 10
#define SIGSEGV 11
#define SIGUSR2 12
#define SIGPIPE 13
#define SIGALRM 14
#define SIGTERM 15
#define SIGSTKFLT 16
#define SIGCHLD 17
#define SIGCONT 18
#define SIGSTOP 19
#define SIGTSTP 20
#define SIGTTIN 21
#define SIGTTOU 22
#define SIGURG  23
#define SIGXCPU 24
#define SIGXFSZ 25
#define SIGVTALRM 26
#define SIGPROF 27
#define SIGWINCH 28
#define SIGIO 29
#define SIGPWR 30
#define SIGSYS 31
#define SA_NOCLDSTOP 0x00000001
#define SA_RESTART   0x10000000
#define SA_SIGINFO   0x00000004
typedef struct {
    int si_signo; int si_errno; int si_code;
    int si_pid; int si_uid; int si_status;
    void *si_addr; long si_band; int si_fd;
    unsigned long si_timer_id; unsigned long si_overrun;
    void *si_ptr;
} siginfo_t;
struct sigaction {
    union { void (*sa_handler)(int); void (*sa_sigaction)(int, siginfo_t *, void *); };
    sigset_t sa_mask; int sa_flags; void (*sa_restorer)(void);
};
sighandler_t signal(int, sighandler_t);
int sigaction(int, const struct sigaction *, struct sigaction *);
int kill(pid_t, int); int raise(int);
int sigemptyset(sigset_t *); int sigfillset(sigset_t *);
int sigaddset(sigset_t *, int); int sigdelset(sigset_t *, int);
int sigprocmask(int, const sigset_t *, sigset_t *);
int sigsuspend(const sigset_t *);
int sigwaitinfo(const sigset_t *, void *);
#define SIG_BLOCK   0
#define SIG_UNBLOCK 1
#define SIG_SETMASK 2
#endif
""")

# ── pwd.h ──
w("pwd.h", r"""
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
""")

# ── grp.h ──
w("grp.h", r"""
#ifndef _SHIM_GRP_H
#define _SHIM_GRP_H
#include <sys/types.h>
struct group { char *gr_name; gid_t gr_gid; char **gr_mem; };
struct group *getgrnam(const char *);
struct group *getgrgid(gid_t);
#endif
""")

# ── dirent.h ──
w("dirent.h", r"""
#ifndef _SHIM_DIRENT_H
#define _SHIM_DIRENT_H
#include <sys/types.h>
#define DT_UNKNOWN 0
#define DT_REG     8
#define DT_DIR     4
#define DT_LNK    10
struct dirent { ino_t d_ino; off_t d_off; unsigned short d_reclen; unsigned char d_type; char d_name[256]; };
typedef struct DIR DIR;
DIR *opendir(const char *);
DIR *fdopendir(int);
struct dirent *readdir(DIR *);
int closedir(DIR *);
#endif
""")

# ── glob.h ──
w("glob.h", r"""
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
""")

# ── semaphore.h ──
w("semaphore.h", r"""
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
""")

# ── dlfcn.h ──
w("dlfcn.h", r"""
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
""")

# ── crypt.h ──
w("crypt.h", r"""
#ifndef _SHIM_CRYPT_H
#define _SHIM_CRYPT_H
char *crypt(const char *, const char *);
char *crypt_r(const char *, const char *, void *);
#endif
""")

# ── sched.h ──
w("sched.h", r"""
#ifndef _SHIM_SCHED_H
#define _SHIM_SCHED_H
#include <sys/types.h>
struct sched_param { int sched_priority; };
int sched_yield(void);
int sched_setaffinity(pid_t, size_t, const unsigned long *);
int sched_getaffinity(pid_t, size_t, unsigned long *);
#define SCHED_OTHER 0
#define SCHED_FIFO  1
#define SCHED_RR    2
#define PRIO_PROCESS 0
#define PRIO_PGRP   1
#define PRIO_USER   2
int setpriority(int, id_t, int);
int getpriority(int, id_t);
int initgroups(const char *, gid_t);
#define __CPU_SETSIZE 1024
#define __NCPUBITS (8 * sizeof(unsigned long))
typedef struct { unsigned long __bits[__CPU_SETSIZE/__NCPUBITS]; } cpu_set_t;
#define CPU_ZERO(cpuset) do { unsigned long *__p = (cpuset)->__bits; unsigned long __i; for (__i = 0; __i < __CPU_SETSIZE/__NCPUBITS; __i++) __p[__i] = 0; } while(0)
#define CPU_SET(cpu, cpuset) ((cpuset)->__bits[(cpu)/__NCPUBITS] |= (1UL << ((cpu) % __NCPUBITS)))
#define CPU_CLR(cpu, cpuset) ((cpuset)->__bits[(cpu)/__NCPUBITS] &= ~(1UL << ((cpu) % __NCPUBITS)))
#define CPU_ISSET(cpu, cpuset) ((cpuset)->__bits[(cpu)/__NCPUBITS] & (1UL << ((cpu) % __NCPUBITS)))
#define CPU_SETSIZE __CPU_SETSIZE
#endif
""")

# ── malloc.h ──
w("malloc.h", r"""
#ifndef _SHIM_MALLOC_H
#define _SHIM_MALLOC_H
#include <stddef.h>
#include <sys/types.h>
void *malloc(size_t);
void *calloc(size_t, size_t);
void *realloc(void *, size_t);
void free(void *);
void *memalign(size_t, size_t);
void *valloc(size_t);
void *pvalloc(size_t);
int posix_memalign(void **, size_t, size_t);
#endif
""")

# ── limits.h ──
w("limits.h", r"""
#ifndef _SHIM_LIMITS_H
#define _SHIM_LIMITS_H
#define CHAR_BIT  8
#define SCHAR_MAX 127
#define SCHAR_MIN (-128)
#define UCHAR_MAX 255
#define CHAR_MAX  127
#define CHAR_MIN  (-128)
#define SHRT_MAX  32767
#define SHRT_MIN  (-32768)
#define USHRT_MAX 65535
#define INT_MAX   2147483647
#define INT_MIN   (-2147483647-1)
#define UINT_MAX  4294967295U
#define LONG_MAX  2147483647L
#define LONG_MIN  (-2147483647L-1)
#define ULONG_MAX 4294967295UL
#define LLONG_MAX  9223372036854775807LL
#define LLONG_MIN  (-9223372036854775807LL-1)
#define ULLONG_MAX 18446744073709551615ULL
#define PATH_MAX   4096
#define PIPE_BUF   4096
#ifndef IOV_MAX
#define IOV_MAX    1024
#endif
#endif
""")

# ── ctype.h ──
w("ctype.h", r"""
#ifndef _SHIM_CTYPE_H
#define _SHIM_CTYPE_H
int isalnum(int); int isalpha(int); int isascii(int);
int isblank(int); int iscntrl(int); int isdigit(int);
int isgraph(int); int islower(int); int isprint(int);
int ispunct(int); int isspace(int); int isupper(int);
int isxdigit(int); int tolower(int); int toupper(int);
#endif
""")

# ── stdio.h ──
w("stdio.h", r"""
#ifndef _SHIM_STDIO_H
#define _SHIM_STDIO_H
#include <sys/types.h>
typedef struct FILE FILE;
extern FILE *stdin;
extern FILE *stdout;
extern FILE *stderr;
FILE *fopen(const char *, const char *);
int fclose(FILE *);
size_t fread(void *, size_t, size_t, FILE *);
size_t fwrite(const void *, size_t, size_t, FILE *);
int fprintf(FILE *, const char *, ...);
int printf(const char *, ...);
int sprintf(char *, const char *, ...);
int snprintf(char *, size_t, const char *, ...);
int sscanf(const char *, const char *, ...);
int vfprintf(FILE *, const char *, __builtin_va_list);
int vsprintf(char *, const char *, __builtin_va_list);
int vsnprintf(char *, size_t, const char *, __builtin_va_list);
int fgetc(FILE *);
char *fgets(char *, int, FILE *);
int fputc(int, FILE *);
int fputs(const char *, FILE *);
int puts(const char *);
int putchar(int);
int fseek(FILE *, long, int);
long ftell(FILE *);
void rewind(FILE *);
int feof(FILE *);
int ferror(FILE *);
void perror(const char *);
int fflush(FILE *);
int ftruncate(int, off_t);
#endif
""")

# ── stdlib.h ──
w("stdlib.h", r"""
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
void bsearch(const void *, const void *, size_t, size_t, int (*)(const void *, const void *));
int abs(int); long labs(long);
char *getenv(const char *); int putenv(char *);
#define RAND_MAX 2147483647
#endif
""")

# ── time.h ──
w("time.h", r"""
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
""")

# ── string.h ──
w("string.h", r"""
#ifndef _SHIM_STRING_H
#define _SHIM_STRING_H
#include <sys/types.h>
void *memcpy(void *, const void *, size_t);
void *memmove(void *, const void *, size_t);
void *memset(void *, int, size_t);
int memcmp(const void *, const void *, size_t);
void *memchr(const void *, int, size_t);
size_t strlen(const char *);
size_t strnlen(const char *, size_t);
char *strcpy(char *, const char *);
char *strncpy(char *, const char *, size_t);
char *strcat(char *, const char *);
char *strncat(char *, const char *, size_t);
int strcmp(const char *, const char *);
int strncmp(const char *, const char *, size_t);
int strcasecmp(const char *, const char *);
int strncasecmp(const char *, const char *, size_t);
char *strchr(const char *, int);
char *strrchr(const char *, int);
char *strstr(const char *, const char *);
char *strcasestr(const char *, const char *);
char *strtok(char *, const char *);
char *strdup(const char *);
char *strndup(const char *, size_t);
char *strerror(int);
size_t strspn(const char *, const char *);
size_t strcspn(const char *, const char *);
char *strpbrk(const char *, const char *);
#endif
""")

# ── errno.h ──
w("errno.h", r"""
#ifndef _SHIM_ERRNO_H
#define _SHIM_ERRNO_H
extern int *__errno_location(void);
#define errno (*__errno_location())
#define EPERM    1
#define ENOENT   2
#define ESRCH    3
#define EINTR    4
#define EIO      5
#define ENXIO    6
#define E2BIG    7
#define ENOEXEC  8
#define EBADF    9
#define ECHILD  10
#define EAGAIN  11
#define ENOMEM  12
#define EACCES  13
#define EFAULT  14
#define ENOTBLK 15
#define EBUSY   16
#define EEXIST  17
#define EXDEV   18
#define ENODEV  19
#define ENOTDIR 20
#define EISDIR  21
#define EINVAL  22
#define ENFILE  23
#define EMFILE  24
#define ENOTTY  25
#define ETXTBSY 26
#define EFBIG   27
#define ENOSPC  28
#define ESPIPE  29
#define EROFS   30
#define EMLINK  31
#define EPIPE   32
#define EDOM    33
#define ERANGE  34
#define EDEADLK 35
#define ENAMETOOLONG 36
#define ENOLCK  37
#define ENOSYS  38
#define ENOTEMPTY 39
#define ELOOP   40
#define ENOMSG  42
#define EIDRM   43
#define ECHRNG  44
#define EL2NSYNC 45
#define EL3HLT  46
#define EL3RST  47
#define ELNRNG  48
#define EUNATCH 49
#define ENOCSI  50
#define EL2HLT  51
#define EBADE   52
#define EBADR   53
#define EXFULL  54
#define ENOANO  55
#define EBADRQC 56
#define EBADSLT 57
#define EBFONT  59
#define ENOSTR  60
#define ENODATA 61
#define ETIME   62
#define ENOSR   63
#define ENONET  64
#define ENOPKG  65
#define EREMOTE 66
#define ENOLINK 67
#define EADV    68
#define ESRMNT  69
#define ECOMM   70
#define EPROTO  71
#define EMULTIHOP 72
#define EDOTDOT 73
#define EBADMSG 74
#define EOVERFLOW 75
#define ENOTUNIQ 76
#define EBADFD  77
#define EREMCHG 78
#define ELIBACC 79
#define ELIBBAD 80
#define ELIBSCN 81
#define ELIBMAX 82
#define ELIBEXEC 83
#define EILSEQ  84
#define ERESTART 85
#define ESTRPIPE 86
#define EUSERS  87
#define ENOTSOCK 88
#define EDESTADDRREQ 89
#define EMSGSIZE 90
#define EPROTOTYPE 91
#define ENOPROTOOPT 92
#define EPROTONOSUPPORT 93
#define ESOCKTNOSUPPORT 94
#define EOPNOTSUPP 95
#define ENOTSUP  95
#define EPFNOSUPPORT 96
#define EAFNOSUPPORT 97
#define EADDRINUSE 98
#define EADDRNOTAVAIL 99
#define ENETDOWN 100
#define ENETUNREACH 101
#define ENETRESET 102
#define ECONNABORTED 103
#define ECONNRESET 104
#define ENOBUFS  105
#define EISCONN  106
#define ENOTCONN 107
#define ESHUTDOWN 108
#define ETOOMANYREFS 109
#define ETIMEDOUT 110
#define ECONNREFUSED 111
#define EHOSTDOWN 112
#define EHOSTUNREACH 113
#define EALREADY 114
#define EINPROGRESS 115
#define ESTALE  116
#endif
""")

# ── stddef.h ──
w("stddef.h", r"""
#ifndef _SHIM_STDDEF_H
#define _SHIM_STDDEF_H
#include_next <stddef.h>
#endif
""")

# ── stdarg.h ──
w("stdarg.h", r"""
#ifndef _SHIM_STDARG_H
#define _SHIM_STDARG_H
#include_next <stdarg.h>
#endif
""")

# ── stdint.h (passthrough to compiler) ──
w("stdint.h", r"""
#ifndef _SHIM_STDINT_H
#define _SHIM_STDINT_H
#include_next <stdint.h>
#endif
""")

# ── inttypes.h ──
w("inttypes.h", r"""
#ifndef _SHIM_INTTYPES_H
#define _SHIM_INTTYPES_H
#include <stdint.h>
#endif
""")

# ── sys/crypt.h (empty) ──
w("crypt.h", r"""
#ifndef _SHIM_CRYPT_H
#define _SHIM_CRYPT_H
char *crypt(const char *, const char *);
struct crypt_data { int initialized; char internal[128]; };
char *crypt_r(const char *, const char *, struct crypt_data *);
#endif
""")

# ── net/if.h (skip, not needed) ──

# ── linux/aio_abi.h (empty stubs) ──
w("linux/aio_abi.h", r"""
#ifndef _SHIM_LINUX_AIO_ABI_H
#define _SHIM_LINUX_AIO_ABI_H
#include <stdint.h>
typedef unsigned long aio_context_t;
struct iocb {
    uint64_t aio_data; uint32_t aio_key; uint16_t aio_lio_opcode;
    uint16_t aio_reqprio; uint32_t aio_buf; uint32_t aio_nbytes;
    uint64_t aio_offset; uint64_t aio_reserved2; uint32_t aio_flags;
    uint32_t aio_resfd;
};
#endif
""")

# ── linux/capability.h (empty stubs) ──
w("linux/capability.h", r"""
#ifndef _SHIM_LINUX_CAPABILITY_H
#define _SHIM_LINUX_CAPABILITY_H
typedef struct __user_cap_header_struct { uint32_t version; int pid; } *cap_user_header_t;
typedef struct __user_cap_data_struct { uint32_t effective; uint32_t permitted; uint32_t inheritable; } *cap_user_data_t;
#define _LINUX_CAPABILITY_VERSION_3 0x20080522
static inline int capget(cap_user_header_t h, cap_user_data_t d){(void)h;(void)d;return -1;}
static inline int capset(cap_user_header_t h, cap_user_data_t d){(void)h;(void)d;return -1;}
#endif
""")

# ── netinet/udp.h (minimal) ──
w("netinet/udp.h", r"""
#ifndef _SHIM_NETINET_UDP_H
#define _SHIM_NETINET_UDP_H
struct udphdr { uint16_t source; uint16_t dest; uint16_t len; uint16_t check; };
#endif
""")

# ── sys/un.h ──
w("sys/un.h", r"""
#ifndef _SHIM_SYS_UN_H
#define _SHIM_SYS_UN_H
#include <sys/socket.h>
struct sockaddr_un { sa_family_t sun_family; char sun_path[108]; };
#endif
""")

# ── linux/bpf.h (empty) ──
w("linux/bpf.h", r"""
#ifndef _SHIM_LINUX_BPF_H
#define _SHIM_LINUX_BPF_H
#endif
""")

# ── linux/string.h (empty) ──
w("linux/string.h", r"""
#ifndef _SHIM_LINUX_STRING_H
#define _SHIM_LINUX_STRING_H
#endif
""")

# ── linux/udp.h (already covered by netinet/udp.h) ──
w("linux/udp.h", r"""
#ifndef _SHIM_LINUX_UDP_H
#define _SHIM_LINUX_UDP_H
#include <netinet/udp.h>
#endif
""")

print("\n=== All shim headers created ===")
