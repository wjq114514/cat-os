
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
