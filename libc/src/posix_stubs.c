/*
 * posix_stubs.c — Cat-OS libc stubs for POSIX functions nginx references
 * but which either don't exist as syscalls or need simple wrappers.
 */

#include "errno.h"

#ifndef CATOS_LIBC_SIZE_T_DEFINED
#define CATOS_LIBC_SIZE_T_DEFINED
typedef unsigned int size_t;
typedef int ssize_t;
typedef int pid_t;
typedef unsigned int uid_t;
typedef unsigned int gid_t;
typedef int mode_t;
typedef int off_t;
typedef unsigned int useconds_t;
typedef unsigned int uintptr_t;
#endif

void *malloc(size_t size);

#define NULL ((void *)0)

/* errno 声明：POSIX 期望设置 errno 的 stub 必须可见。
 * 实际 errno 在 errno.c 中定义为 int，由本桩的 __errno_location 返回地址。 */
extern int errno;

/* 前置声明：stat 族组合实现先于定义处使用 open/close */
struct stat;   /* 标签前置——否则原型各自引入独立作用域的匿名结构体 */
struct iovec;
int open(const char *path, int flags, ...);
int close(int fd);
int fstat(int fd, struct stat *buf);
int stat(const char *path, struct stat *buf);
int read(int fd, void *buf, unsigned int len);
int write(int fd, const void *buf, unsigned int len);
off_t lseek(int fd, off_t offset, int whence);

static inline int catos_syscall3(unsigned nr, unsigned a0, unsigned a1,
                                 unsigned a2)
{
    int ret;
    __asm__ volatile("int $0x80"
                     : "=a"(ret)
                     : "a"(nr), "b"(a0), "c"(a1), "d"(a2)
                     : "memory");
    return ret;
}

/* ── uid/gid stubs ──
 * 资料 N14：无用户体系。必须报非 0 —— nginx 以 geteuid()==0 判定
 * "以 root 运行"并走 initgroups/setgid/setuid 分支，任何一步失败即 [emerg]。
 * 报 1000（普通用户）让 nginx 直接跳过提权路径。 */
uid_t getuid(void) { return 1000; }
uid_t geteuid(void) { return 1000; }
gid_t getgid(void) { return 0; }
gid_t getegid(void) { return 0; }
int setuid(uid_t uid) { (void)uid; return 0; }
int setgid(gid_t gid) { (void)gid; return 0; }

/* ── rename ── */
int rename(const char *old, const char *newpath)
{
    (void)old; (void)newpath;
    return -1;
}

/* ── uname ── */
struct utsname {
    char sysname[65];
    char nodename[65];
    char release[65];
    char version[65];
    char machine[65];
};
static void _strcopy(char *dst, const char *src) { while ((*dst++ = *src++)); }
int uname(struct utsname *buf)
{
    if (buf) {
        _strcopy(buf->sysname, "Cat-OS");
        _strcopy(buf->nodename, "catos");
        _strcopy(buf->release, "0.1.0");
        _strcopy(buf->version, "#1");
        _strcopy(buf->machine, "i686");
    }
    return 0;
}

/* ── timer stubs ── */
struct itimerval {
    struct { long tv_sec; long tv_usec; } it_interval;
    struct { long tv_sec; long tv_usec; } it_value;
};
int setitimer(int which, const struct itimerval *value, struct itimerval *ovalue)
{
    (void)which; (void)value; (void)ovalue;
    return -1;
}

/* ── signal stubs ── */
typedef unsigned int sigset_t;
struct sigaction { void (*sa_handler)(int); sigset_t sa_mask; int sa_flags; };
int sigemptyset(sigset_t *set)
{
    if (set) *set = 0;
    return 0;
}
int sigfillset(sigset_t *set)
{
    if (set) *set = 0x7FFFFFFF;
    return 0;
}
int sigaddset(sigset_t *set, int signo)
{
    if (set && signo > 0 && signo < 32)
        *set |= (1u << (signo - 1));
    return 0;
}
int sigismember(const sigset_t *set, int signo)
{
    if (!set || signo <= 0 || signo >= 32) return 0;
    return (*set >> (signo - 1)) & 1;
}
int sigaction(int sig, const struct sigaction *act, struct sigaction *oldact)
{
    (void)sig; (void)act; (void)oldact;
    return 0;
}
int sigprocmask(int how, const sigset_t *set, sigset_t *oldset)
{
    (void)how; (void)set; (void)oldset;
    return 0;
}
int sigsuspend(const sigset_t *mask)
{
    (void)mask;
    return -1;
}
int kill(pid_t pid, int sig)
{
    (void)pid; (void)sig;
    return -1;
}

/* ── usleep ── */
int usleep(useconds_t usec)
{
    (void)usec;
    return 0;
}

/* ── pipe ── */
int pipe(int pipefd[2])
{
    (void)pipefd;
    return -1;
}

/* ── chdir ── */
int chdir(const char *path)
{
    (void)path;
    return -1;
}

/* ── chmod ── */
int chmod(const char *path, mode_t mode)
{
    (void)path; (void)mode;
    return -1;
}

/* ── chown ── */
int chown(const char *path, uid_t owner, gid_t group)
{
    (void)path; (void)owner; (void)group;
    return -1;
}

/* ── mmap/munmap stubs ── */
void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset)
{
    (void)addr; (void)length; (void)prot; (void)flags; (void)fd; (void)offset;
    return (void *)-1;
}

int munmap(void *addr, size_t length)
{
    (void)addr; (void)length;
    return -1;
}

/* ── getdents ── */
int getdents(int fd, void *dirp, unsigned int count)
{
    (void)fd; (void)dirp; (void)count;
    return -1;
}

/* ── dup/dup2 ── */
int dup(int oldfd)
{
    (void)oldfd;
    return -1;
}

int dup2(int oldfd, int newfd)
{
    return (int)catos_syscall3(63, (unsigned)oldfd, (unsigned)newfd, 0u);
}

/* ── readlink ── */
ssize_t readlink(const char *path, char *buf, size_t bufsiz)
{
    (void)path; (void)buf; (void)bufsiz;
    return -1;
}

/* ── stat 族 ──
 * 内核 nr=197 fstat 出参 catos_stat（vfs.c:199，uint32×11 连续 44B），
 * 字段顺序与用户侧 struct stat 前 10 槽同序。本文件自带的局部 struct stat
 * 即按「前 40B=内核布局 + 3×struct timeval」声明，保持与
 * nginx-shim/sys/stat.h 的 i386 布局一致。无墙钟来源 → 时间恒 0。 */
struct catos_timeval {
    unsigned long tv_sec;
    long tv_usec;
};

struct stat {
    unsigned int st_dev;
    unsigned int st_ino;
    unsigned int st_mode;
    unsigned int st_nlink;
    unsigned int st_uid;
    unsigned int st_gid;
    unsigned int st_rdev;
    unsigned long st_size;
    unsigned long st_blksize;
    unsigned long st_blocks;
    struct catos_timeval st_atim;
    struct catos_timeval st_mtim;
    struct catos_timeval st_ctim;
};

int fstat(int fd, struct stat *buf)
{
    if (!buf) {
        errno = EFAULT;
        return -1;
    }
    unsigned int ks[10];
    long r = catos_syscall3(197, (unsigned)fd, (unsigned)ks, 0);
    if (r < 0) {
        errno = -r;
        return -1;
    }
    buf->st_dev = ks[0];      buf->st_ino = ks[1];
    buf->st_mode = ks[2];     buf->st_nlink = ks[3];
    buf->st_uid = ks[4];      buf->st_gid = ks[5];
    buf->st_rdev = ks[6];     buf->st_size = ks[7];
    buf->st_blksize = ks[8];  buf->st_blocks = ks[9];
    buf->st_atim.tv_sec = 0;  buf->st_atim.tv_usec = 0;
    buf->st_mtim.tv_sec = 0;  buf->st_mtim.tv_usec = 0;
    buf->st_ctim.tv_sec = 0;  buf->st_ctim.tv_usec = 0;
    return 0;
}

int stat(const char *path, struct stat *buf)
{
    if (!path || !buf) {
        errno = EFAULT;
        return -1;
    }
    /* 无内核 stat-by-name：open→fstat→close 组合实现 */
    long fd = open(path, 0 /*O_RDONLY*/);
    if (fd < 0) return -1; /* open() has set errno */
    int r = fstat((int)fd, buf);
    close((int)fd);
    return r;
}

int lstat(const char *path, struct stat *buf)
{
    return stat(path, buf);   /* 无符号链接概念 */
}

/* ── lseek：nr=19 vfs_lseek(fd,offset,whence) 原生 ── */
off_t lseek(int fd, off_t offset, int whence)
{
    return catos_syscall3(19, (unsigned)fd, (unsigned)offset, (unsigned)whence);
}

/* ── getcwd ── */
char *getcwd(char *buf, size_t size)
{
    (void)size;
    if (buf) {
        buf[0] = '/';
        buf[1] = '\0';
    }
    return buf;
}

/* ── sysconf ── */
long sysconf(int name)
{
    (void)name;
    return -1;
}

/* ── getrlimit/setrlimit ── */
struct rlimit { unsigned long rlim_cur; unsigned long rlim_max; };
int getrlimit(int resource, struct rlimit *rlim)
{
    (void)resource;
    if (rlim) {
        rlim->rlim_cur = 65536;
        rlim->rlim_max = 65536;
    }
    return 0;
}

int setrlimit(int resource, const struct rlimit *rlim)
{
    (void)resource; (void)rlim;
    return -1;
}

/* ── setsockopt / getsockopt (thin wrappers around syscall) ── */
int setsockopt(int fd, int level, int optname, const void *optval, unsigned int optlen)
{
    /* 资料 N2/N10：内核无 setsockopt 编号；SO_REUSEADDR 等一律 no-op 返 0
     * （栈本身即时发送：TCP_NODELAY 天然满足） */
    (void)fd; (void)level; (void)optname; (void)optval; (void)optlen;
    return 0;
}

int getsockopt(int fd, int level, int optname, void *optval, unsigned int *optlen)
{
    /* ⚠️ 严禁映射 nr=28(close)：会把 socket 关掉 */
    (void)fd; (void)level; (void)optname;
    if (optval && optlen && *optlen >= 4) {
        unsigned int *v = (unsigned int *)optval;
        v[0] = 0;
        *optlen = 4;
    }
    return 0;
}

/* ── shutdown：内核无编号，stub 返 0 ── */
int shutdown(int fd, int how)
{
    (void)fd; (void)how;
    return 0;
}

/* ── recv (syscall 22) ── */
ssize_t recv(int fd, void *buf, size_t len, int flags)
{
    /* nr=27 = recv（TCP）；⚠️ 严禁 22：那是 listen */
    (void)flags;
    return catos_syscall3(27, (unsigned)fd, (unsigned)buf, (unsigned)len);
}

/* ── sendfile ── */
ssize_t sendfile(int out_fd, int in_fd, off_t *offset, size_t count)
{
    (void)out_fd; (void)in_fd; (void)offset; (void)count;
    return -1;
}

/* ── process stubs ── */
int fork(void)
{
    return catos_syscall3(33, 0, 0, 0);
}

pid_t getpid(void)
{
    /* No dedicated getpid syscall; return 1 as placeholder */
    return 1;
}

int setsid(void)
{
    return 0;
}

int umask(int mask)
{
    (void)mask;
    return 0;
}

int open(const char *path, int flags, ...)
{
    (void)flags;
    /* syscall 5 = open */
    int r = catos_syscall3(5, (unsigned)path, 0, 0);
    if (r < 0) {
        /* Current VFS open has a legacy -1 miss sentinel. Preserve the
         * POSIX return convention for nginx and expose the useful errno. */
        errno = (r == -1) ? ENOENT : -r;
        return -1;
    }
    return r;
}

int close(int fd)
{
    /* syscall 6 = vfs_close (no socket awareness) or 28 = CATOS_SYS_CLOSE */
    return catos_syscall3(28, (unsigned)fd, 0, 0);
}

int getpagesize(void)
{
    return 4096;
}

int initgroups(const char *user, gid_t group)
{
    (void)user; (void)group;
    return 0;
}

int setpriority(int which, int who, int prio)
{
    (void)which; (void)who; (void)prio;
    return 0;
}

void abort(void)
{
    /* Just exit */
    catos_syscall3(12, 1, 0, 0);
    for(;;);
}

int raise(int sig)
{
    (void)sig;
    return -1;
}

/* ── more process stubs ── */
pid_t getppid(void)
{
    return 1;
}

int execve(const char *path, char *const argv[], char *const envp[])
{
    (void)path; (void)argv; (void)envp;
    return -1;
}

int socketpair(int domain, int type, int protocol, int fds[2])
{
    (void)domain; (void)type; (void)protocol;
    fds[0] = -1; fds[1] = -1;
    return -1;
}

/* ioctl：资料 N12 —— Cat-OS socket 原生非阻塞。
 * FIONBIO(0x5421) 置 1 本就成立 → 返 0；FIONREAD(0x541B) 读可用量，
 * 返 0 合理（事件引擎空转无害）。其余请求同样宽容返 0（nginx 仅在
 * 失败路径 abort，成功值大多被忽略）。 */
int ioctl(int fd, unsigned long request, ...)
{
    (void)fd; (void)request;
    return 0;
}

/* fcntl：同上。O_NONBLOCK 获取/设置均原生成立；命令走 nr=55 会把
 * socket fd 当普通文件拒绝 → -EBADF 反成致命。统一返 cmd 本身的
 * 「无操作成功」语义：F_GETFL 返 O_RDWR|O_NONBLOCK 位形最稳。 */
#define CATOS_FCNTL_GETFL 3
#define CATOS_FCNTL_SETFL 4
int fcntl(int fd, int cmd, ...)
{
    /* ⚠️ 原映射 nr=55 对 FILE_SOCKET 一律 -EBADF（socket 非文件槽）；
     * nginx 只用 F_GETFL/F_SETFL(非阻塞位)与 F_GETFD —— 全部虚拟化。 */
    (void)fd;
    switch (cmd) {
    case CATOS_FCNTL_GETFL:
        return 0x802;              /* O_RDWR(2) | O_NONBLOCK(0x800) */
    case CATOS_FCNTL_SETFL:
        return 0;
    default:
        return 0;
    }
}

ssize_t sendmsg(int fd, const void *msg, int flags)
{
    (void)fd; (void)msg; (void)flags;
    return -1;
}

ssize_t recvmsg(int fd, void *msg, int flags)
{
    (void)fd; (void)msg; (void)flags;
    return -1;
}

pid_t waitpid(pid_t pid, int *status, int options)
{
    /* syscall 34 = waitpid */
    return catos_syscall3(34, (unsigned)pid, (unsigned)status, (unsigned)options);
}

ssize_t send(int fd, const void *buf, size_t len, int flags)
{
    (void)flags;
    return catos_syscall3(26, (unsigned)fd, (unsigned)buf, (unsigned)len);
}

ssize_t sendto(int fd, const void *buf, size_t len, int flags,
               const void *dest_addr, unsigned int addrlen)
{
    (void)flags; (void)dest_addr; (void)addrlen;
    return catos_syscall3(26, (unsigned)fd, (unsigned)buf, (unsigned)len);
}

ssize_t writev(int fd, const void *iov, int iovcnt)
{
    /* syscall 146 = writev */
    return catos_syscall3(146, (unsigned)fd, (unsigned)iov, (unsigned)iovcnt);
}

int wait(int *status)
{
    return waitpid(-1, status, 0);
}

int statfs(const char *path, void *buf)
{
    (void)path; (void)buf;
    return -1;
}

ssize_t readv(int fd, const void *iov, int iovcnt)
{
    (void)fd; (void)iov; (void)iovcnt;
    return -1;
}

void *readdir(void *dirp)
{
    (void)dirp;
    return (void *)0;
}

int glob(const char *pattern, int flags, void *errfunc, void *pglob)
{
    (void)pattern; (void)flags; (void)errfunc; (void)pglob;
    return -1;
}

void globfree(void *pglob)
{
    (void)pglob;
}

int utimes(const char *filename, const void *times)
{
    (void)filename; (void)times;
    return -1;
}

int ftruncate(int fd, off_t length)
{
    (void)fd; (void)length;
    return -1;
}

void *opendir(const char *name)
{
    (void)name;
    return (void *)0;
}

/* ── pread / pwrite ──
 * 内核无 positioned-read 编号；以 lseek(19)+read(0)/write(1) 组合模拟。
 * nginx 顺序读配置：offset 自增推进，故读完不回卷（pos 停在 off+got），
 * 与其后一次 read(offset=cur) 的调用序天然衔接。
 * 特例：chr 设备（/dev/null 等）lseek → -ESPIPE(-29)，此时退化为裸
 * read/write —— 正好就是 POSIX 字符设备上 pread 的真实语义。 */
ssize_t pread(int fd, void *buf, size_t count, off_t offset)
{
    long r = lseek(fd, offset, 0 /*SEEK_SET*/);
    if (r < 0 && r != -29) return -1;      /* 非 ESPIPE 定位失败才拦截 */
    return (ssize_t)read(fd, buf, count);
}

ssize_t pwrite(int fd, const void *buf, size_t count, off_t offset)
{
    long r = lseek(fd, offset, 0 /*SEEK_SET*/);
    if (r < 0 && r != -29) return -1;
    return (ssize_t)write(fd, buf, count);
}

int unlink(const char *pathname)
{
    (void)pathname;
    return -1;
}

int posix_memalign(void **memptr, size_t alignment, size_t size)
{
    (void)alignment;
    *memptr = malloc(size);
    return *memptr ? 0 : -1;
}

/* ── time functions ── */
typedef int time_t;
struct tm {
    int tm_sec;
    int tm_min;
    int tm_hour;
    int tm_mday;
    int tm_mon;
    int tm_year;
    int tm_wday;
    int tm_yday;
    int tm_isdst;
};

time_t time(time_t *t)
{
    /* syscall 196 = gettimeofday */
    /* Just return a simple value */
    if (t) *t = 1000000;
    return 1000000;
}

struct tm *gmtime_r(const time_t *timep, struct tm *result)
{
    (void)timep;
    result->tm_sec = 0; result->tm_min = 0; result->tm_hour = 0;
    result->tm_mday = 1; result->tm_mon = 0; result->tm_year = 70;
    result->tm_wday = 0; result->tm_yday = 0; result->tm_isdst = 0;
    return result;
}

struct tm *localtime_r(const time_t *timep, struct tm *result)
{
    return gmtime_r(timep, result);
}

struct tm *localtime(const time_t *timep)
{
    static struct tm static_tm;
    return localtime_r(timep, &static_tm);
}

char *strerror(int errnum)
{
    (void)errnum;
    static char _errstr[] = "error";
    return _errstr;
}

size_t strftime(char *s, size_t max, const char *format, const struct tm *tm)
{
    (void)format; (void)tm;
    if (max > 0) s[0] = '\0';
    return 0;
}

/* ── socket API wrappers ── */
/* ── socket 族：house ABI（资料 NGINX_PORT_PLAN §2.1 / SOCKET_API.md）──
 * nr=20 socket(type)：内核 a[0]=type（无 domain 形参）；此处做翻译：
 * nginx 调 socket(AF_INET, SOCK_STREAM/SOCK_DGRAM, 0) → 取 SOCK_* 型别传入。
 * nr=21 bind(fd, port)：内核直传主机序端口号，无 sockaddr 结构。
 * libc 侧负责从 struct sockaddr_in 提取 ntohs(sin_port)。 */
struct catos_sockaddr_in { unsigned short family; unsigned short sin_port; unsigned int addr; };

int socket(int domain, int type, int protocol)
{
    (void)domain; (void)protocol;
    int t = type & 0xff;                 /* 剥离 SOCK_NONBLOCK/CLOEXEC 位 */
    if (t == 1 /*SOCK_STREAM*/) return catos_syscall3(20, 1u, 0, 0);
    if (t == 2 /*SOCK_DGRAM*/)  return catos_syscall3(20, 2u, 0, 0);
    return -22;                          /* 其余型别（RAW 等）EINVAL */
}

int bind(int fd, const void *addr, unsigned int addrlen)
{
    (void)addrlen;
    if (!addr) return -22; /* EINVAL */
    {
        const struct catos_sockaddr_in *a = (const struct catos_sockaddr_in *)addr;
        unsigned short port = (unsigned short)((a->sin_port >> 8) | (a->sin_port << 8)); /* ntohs */
        return catos_syscall3(21, (unsigned)fd, (unsigned)port, 0);
    }
}

int listen(int fd, int backlog)
{
    return catos_syscall3(22, (unsigned)fd, (unsigned)backlog, 0);
}

int accept(int fd, void *addr, unsigned int *addrlen)
{
    /* nginx 路径：传 addr/addrlen 到内核，让内核填充 sockaddr_in 并写回 addrlen。
     * cat-OS accept 路径已扩展为 5 参（fd/addr/addrlen/0/0）。 */
    int r = catos_syscall3(23, (unsigned)fd, (unsigned)(uintptr_t)addr, (unsigned)(uintptr_t)addrlen);
    if (r < 0) { errno = -r; return -1; }
    return r;
}

int accept4(int fd, void *addr, unsigned int *addrlen, int flags)
{
    (void)flags;
    int r = catos_syscall3(23, (unsigned)fd, (unsigned)(uintptr_t)addr, (unsigned)(uintptr_t)addrlen);
    if (r < 0) { errno = -r; return -1; }
    return r;
}

int connect(int fd, const void *addr, unsigned int addrlen)
{
    /* ⚠️ 严禁映射 nr=24(sendto)：会把缓冲区当 UDP 包发出去。
     * 内核无主动开放 connect；静态服务场景不该走到这里。 */
    (void)fd; (void)addr; (void)addrlen;
    return -107; /* ENOTCONN */
}

/* ── poll stub ── */
struct pollfd {
    int fd;
    short events;
    short revents;
};
int poll(struct pollfd *fds, unsigned long nfds, int timeout)
{
    return catos_syscall3(168, (unsigned)fds, (unsigned)nfds, (unsigned)timeout);
}

int sched_yield(void)
{
    return 0;
}

char *strpbrk(const char *s, const char *accept2)
{
    const char *a;
    for (; *s; s++) {
        for (a = accept2; *a; a++) {
            if (*s == *a) return (char *)s;
        }
    }
    return (void *)0;
}

int getsockname(int fd, void *addr, unsigned int *addrlen)
{
    /* 内核无 getsockname 编号；nginx 在打开监听套接字时强校验，失败致命。
     * 返回 AF_INET+INADDR_ANY 占位（真实 lport 由内核 bind/listen 路径自管）。 */
    (void)fd;
    if (addr && addrlen && *addrlen >= sizeof(struct catos_sockaddr_in)) {
        struct catos_sockaddr_in *a = (struct catos_sockaddr_in *)addr;
        a->family = 2;   /* AF_INET */
        a->sin_port = 0;
        a->addr = 0;     /* INADDR_ANY */
        *addrlen = sizeof(struct catos_sockaddr_in);
    }
    return 0;
}

int getpeername(int fd, void *addr, unsigned int *addrlen)
{
    /* 同上：占位不可达对端（0.0.0.0），避免日志/访问控制路径致命 */
    (void)fd;
    if (addr && addrlen && *addrlen >= sizeof(struct catos_sockaddr_in)) {
        struct catos_sockaddr_in *a = (struct catos_sockaddr_in *)addr;
        a->family = 2;
        a->sin_port = 0;
        a->addr = 0;
        *addrlen = sizeof(struct catos_sockaddr_in);
    }
    return 0;
}

int gethostname(char *name, unsigned int len)
{
    if (len > 0) {
        name[0] = 'c'; name[1] = 'a'; name[2] = 't'; name[3] = 'o';
        name[4] = 's'; name[5] = '\0';
    }
    return 0;
}

struct timeval {
    long tv_sec;
    long tv_usec;
};

int gettimeofday(struct timeval *tv, void *tz)
{
    (void)tz;
    if (tv) {
        catos_syscall3(196, (unsigned)tv, 0, 0);
    }
    return 0;
}

time_t mktime(struct tm *tm)
{
    (void)tm;
    return 1000000;
}

/* mkdir：FAT16 只读、devfs 无目录概念。返回 -EEXIST(-17) —— nginx
 * ngx_create_paths 对 EEXIST 静默跳过（ngx_cycle.c「err==EEXIST 容忍」分支），
 * client_body_temp 等路径初始化即可无伤通过。 */
int mkdir(const char *path, mode_t mode)
{
    (void)path; (void)mode;
    return -17;
}

int closedir(void *dirp)
{
    (void)dirp;
    return -1;
}

struct timespec {
    long tv_sec;
    long tv_nsec;
};

int clock_gettime(int clk_id, struct timespec *tp)
{
    (void)clk_id;
    if (tp) {
        tp->tv_sec = 1000000;
        tp->tv_nsec = 0;
    }
    return 0;
}

struct hostent {
    char *h_name;
    char **h_aliases;
    int h_addrtype;
    int h_length;
    char **h_addr_list;
};

struct hostent *gethostbyname(const char *name)
{
    (void)name;
    return (void *)0;
}

struct passwd {
    char *pw_name;
    char *pw_passwd;
    unsigned int pw_uid;
    unsigned int pw_gid;
    char *pw_gecos;
    char *pw_dir;
    char *pw_shell;
};

/* nginx 在 ngx_init_cycle 中无条件解析默认用户 "nobody"（资料 N14：无用户
 * 数据库 → 返回静态假条目；uid/gid 与 geteuid 的 1000 一致，保证后续
 * 任何 setgid/setuid 分支即使被触发也无权限落差）。 */
static struct passwd catos_pw = {
    (char *)"nobody", (char *)"x", 1000u, 1000u,
    (char *)"catos", (char *)"/mnt/fat", (char *)"/bin/shell"
};

struct passwd *getpwnam(const char *name)
{
    if (name && name[0] == 'n' && name[1] == 'o') return &catos_pw;
    return &catos_pw;   /* 单用户系统：任何名字都映射同一假条目 */
}

struct group {
    char *gr_name;
    char *gr_passwd;
    unsigned int gr_gid;
    char **gr_mem;
};

static struct group catos_gr = { (char*)"nogroup", (char*)"x", 1000u, (char **)0 };

struct group *getgrnam(const char *name)
{
    (void)name;
    return &catos_gr;
}

ssize_t pwritev(int fd, const struct iovec *iov, int iovcnt, off_t offset)
{
    (void)fd; (void)iov; (void)iovcnt; (void)offset;
    return -1;
}

int posix_fadvise(int fd, off_t offset, off_t len, int advice)
{
    (void)fd; (void)offset; (void)len; (void)advice;
    return 0;
}

int sched_setaffinity(unsigned long pid, unsigned long cpusetsize, const unsigned long *cpuset)
{
    (void)pid; (void)cpusetsize; (void)cpuset;
    return 0;
}

char *dlerror(void)
{
    return "dlerror: not supported";
}

long syscall(long number, ...)
{
    (void)number;
    return -38; /* ENOSYS */
}

int ngx_use_epoll_rdhup = 0;

int openat(int dirfd, const char *pathname, int flags, ...)
{
    (void)dirfd; (void)flags;
    return open(pathname, flags);
}

int fstatat(int dirfd, const char *pathname, struct stat *buf, int flags)
{
    (void)dirfd; (void)flags;
    return stat(pathname, buf);
}

struct addrinfo_stub { int ai_flags; int ai_family; int ai_socktype; int ai_protocol; void *ai_addr; char *ai_canonname; void *ai_next; };
void freeaddrinfo(struct addrinfo_stub *res)
{
    (void)res;
}

int sem_init(unsigned int *sem, int pshared, unsigned int value)
{
    (void)sem; (void)pshared; (void)value;
    return 0;
}

int sem_wait(unsigned int *sem)
{
    (void)sem;
    return 0;
}

int sem_post(unsigned int *sem)
{
    (void)sem;
    return 0;
}

int sem_destroy(unsigned int *sem)
{
    (void)sem;
    return 0;
}

const char *strerrordesc_np(int errnum)
{
    (void)errnum;
    return "unknown error";
}

/* Stub for dlopen/dlsym/dlclose/dlerror (no dynamic loading on Cat-OS) */
void *dlopen(const char *filename, int flags)
{
    (void)filename; (void)flags;
    return (void *)0;
}

void *dlsym(void *handle, const char *symbol)
{
    (void)handle; (void)symbol;
    return (void *)0;
}

int dlclose(void *handle)
{
    (void)handle;
    return 0;
}

/* getaddrinfo stub */
struct addrinfo_stub2 {
    int ai_flags; int ai_family; int ai_socktype; int ai_protocol;
    void *ai_addr; char *ai_canonname; void *ai_next;
};
int getaddrinfo(const char *node, const char *service,
                const struct addrinfo_stub2 *hints,
                struct addrinfo_stub2 **res)
{
    (void)node; (void)service; (void)hints; (void)res;
    return -1; /* EAI_FAIL */
}
