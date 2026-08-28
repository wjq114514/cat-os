
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
