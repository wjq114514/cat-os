
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
