
#ifndef _SHIM_NETINET_UDP_H
#define _SHIM_NETINET_UDP_H
struct udphdr { uint16_t source; uint16_t dest; uint16_t len; uint16_t check; };
#endif
