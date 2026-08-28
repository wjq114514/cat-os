
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
static inline int __in6_is_addr_unspecified(const struct in6_addr *a) {
    return (a->s6_addr[0] | a->s6_addr[1] | a->s6_addr[2] | a->s6_addr[3] |
            a->s6_addr[4] | a->s6_addr[5] | a->s6_addr[6] | a->s6_addr[7] |
            a->s6_addr[8] | a->s6_addr[9] | a->s6_addr[10] | a->s6_addr[11] |
            a->s6_addr[12] | a->s6_addr[13] | a->s6_addr[14] | a->s6_addr[15]) == 0;
}
#define IN6_IS_ADDR_UNSPECIFIED(a) __in6_is_addr_unspecified(a)
static inline int __in6_is_addr_v4mapped(const struct in6_addr *a) {
    return (a->s6_addr[0] | a->s6_addr[1] | a->s6_addr[2] | a->s6_addr[3] |
            a->s6_addr[4] | a->s6_addr[5] | a->s6_addr[6] | a->s6_addr[7] |
            a->s6_addr[8] | a->s6_addr[9] | a->s6_addr[10] | a->s6_addr[11]) == 0 &&
            a->s6_addr[12] == 0xff && a->s6_addr[13] == 0xff;
}
#define IN6_IS_ADDR_V4MAPPED(a) __in6_is_addr_v4mapped(a)
struct in_pktinfo { int ipi_ifindex; struct in_addr ipi_spec_dst; struct in_addr ipi_addr; };
struct in6_pktinfo { struct in6_addr ipi6_addr; int ipi6_ifindex; };
#define IPPROTO_IP    0
#define IPPROTO_ICMP  1
#define IPPROTO_TCP   6
#define IPPROTO_UDP  17
#define IPPROTO_IPV6 41
#define IPPROTO_RAW 255
#define IP_MTU_DISCOVER 2
#define IPV6_MTU_DISCOVER 24
#define IP_PMTUDISC_DONT  0
#define IP_PMTUDISC_WANT  1
#define IP_PMTUDISC_DO    2
#define IPV6_PMTUDISC_DONT  0
#define IPV6_PMTUDISC_WANT  1
#define IPV6_PMTUDISC_DO    2
#define IPV6_V6ONLY 26
#define IPV6_RECVPKTINFO 49
#define IPV6_PKTINFO 50
#define IP_PKTINFO 8
#define htons(x) __builtin_bswap16(x)
#define ntohs(x) __builtin_bswap16(x)
#define htonl(x) __builtin_bswap32(x)
#define ntohl(x) __builtin_bswap32(x)
#endif
