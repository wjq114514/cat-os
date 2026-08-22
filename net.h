#ifndef CATOS_NET_H
#define CATOS_NET_H
#include <stdint.h>
#include <stdbool.h>
#include "netring.h"

/* ─── Ethernet ─── */
#define ETH_ALEN        6
#define ETH_HLEN        14
#define ETH_TYPE_ARP    0x0806
#define ETH_TYPE_IP     0x0800
typedef struct { uint8_t dst[6],src[6]; uint16_t type; } __attribute__((packed)) eth_hdr_t;

/* ─── ARP ─── */
#define ARP_HTYPE_ETH   1
#define ARP_PTYPE_IP    0x0800
#define ARP_HLEN        6
#define ARP_PLEN        4
#define ARP_OP_REQUEST  1
#define ARP_OP_REPLY    2
typedef struct { uint16_t htype,ptype; uint8_t hlen,plen; uint16_t op; uint8_t sha[6],spa[4],tha[6],tpa[4]; } __attribute__((packed)) arp_pkt_t;

/* ─── IPv4 ─── */
#define IPV4_MIN_HEADER_LEN 20
#define IP_PROTO_ICMP   1
#define IP_PROTO_TCP    6
#define IP_PROTO_UDP    17
typedef struct {
    uint8_t  ver_ihl, dscp_ecn;
    uint16_t tot_len, id, flags_frag;
    uint8_t  ttl, proto;
    uint16_t hdr_csum;
    uint32_t src, dst;
} __attribute__((packed)) ip_hdr_t;

/* ─── ICMP ─── */
#define ICMP_TYPE_ECHO_REPLY   0
#define ICMP_TYPE_ECHO_REQUEST 8
typedef struct { uint8_t type,code; uint16_t csum,id,seq; } __attribute__((packed)) icmp_hdr_t;

/* ─── UDP ─── */
typedef struct { uint16_t src_port,dst_port,len,csum; } __attribute__((packed)) udp_hdr_t;

/* ─── TCP ─── */
typedef struct {
    uint16_t src_port,dst_port;
    uint32_t seq,ack_seq;
    uint8_t  off_res,flags;
    uint16_t window,csum,urgent;
} __attribute__((packed)) tcp_hdr_t;

#define TCP_FLAG_FIN    0x01
#define TCP_FLAG_SYN    0x02
#define TCP_FLAG_RST    0x04
#define TCP_FLAG_PSH    0x08
#define TCP_FLAG_ACK    0x10
#define TCP_FLAG_SYNACK 0x12
#define TCP_FLAG_FINACK 0x11

/* ─── TCP state machine ─── */
enum tcp_state {
    TCP_CLOSED, TCP_LISTEN, TCP_SYN_SENT, TCP_SYN_RECEIVED,
    TCP_ESTABLISHED, TCP_FIN_WAIT_1, TCP_FIN_WAIT_2, TCP_CLOSE_WAIT,
    TCP_CLOSING, TCP_LAST_ACK, TCP_TIME_WAIT
};

#define TCP_MAX_CONNS   16
#define TCP_RX_WINDOW   65535
#define TCP_MSS         1460
#define TCP_BUF_SIZE    4096

typedef struct tcp_conn tcp_conn_t;

/* ─── Socket API ─── */
typedef enum { SOCK_CLOSED, SOCK_UDP, SOCK_TCP_LISTEN, SOCK_TCP_ESTAB } sock_type_t;

typedef struct {
    sock_type_t type;
    union {
        struct { uint16_t lport; } udp;
        struct { tcp_conn_t *conn; } tcp;
    };
} socket_t;

/* ─── Public API ─── */
void net_init(void);
void net_poll(void);
void net_handle_packet(const uint8_t *buf, uint32_t len);

/* IP helpers */
uint16_t ip_checksum(const void *buf, uint32_t len);
uint16_t ip_checksum_pseudo(uint32_t src, uint32_t dst, uint8_t proto, uint16_t tcp_len, const void *buf, uint32_t len);
bool ip_send(uint32_t dst, uint8_t proto, const uint8_t *data, uint32_t len);

/* ARP */
bool arp_resolve(uint32_t ip, uint8_t mac[6]);

/* UDP */
socket_t *udp_open(uint16_t lport);
int udp_sendto(socket_t *s, uint32_t dst_ip, uint16_t dst_port, const uint8_t *data, uint32_t len);
int udp_recvfrom(socket_t *s, uint32_t *src_ip, uint16_t *src_port, uint8_t *buf, uint32_t max_len);

/* TCP */
socket_t *tcp_listen(uint16_t port);
int tcp_accept(socket_t *s, uint32_t *remote_ip, uint16_t *remote_port);
int tcp_send(socket_t *s, const uint8_t *data, uint32_t len);
int tcp_recv(socket_t *s, uint8_t *buf, uint32_t max_len);
void tcp_close(socket_t *s);

/* Convenience */
void net_set_ip(uint32_t ip);
uint32_t net_get_ip(void);
void net_set_gateway(uint32_t gw);
void net_set_subnet(uint32_t mask);

/* NAPI integration */
void net_napi_poll(void);

#endif