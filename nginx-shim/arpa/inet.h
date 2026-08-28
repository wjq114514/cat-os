
#ifndef _SHIM_ARPA_INET_H
#define _SHIM_ARPA_INET_H
#include <stdint.h>
#include <netinet/in.h>
const char *inet_ntop(int, const void *, char *, socklen_t);
int inet_pton(int, const char *, void *);
in_addr_t inet_addr(const char *);
char *inet_ntoa(struct in_addr);
#endif
