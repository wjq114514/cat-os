
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
#define AF_UNSPEC 0
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
/* Linux capability stubs for nginx master process */
#ifndef _LINUX_CAPABILITY_VERSION_1
#define _LINUX_CAPABILITY_VERSION_1 0x19980330
#endif
#ifndef CAP_NET_RAW
#define CAP_NET_RAW 13
#endif
#define SYS_capset 158
#define SYS_capget 125
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
