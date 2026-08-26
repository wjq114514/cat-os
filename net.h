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
#define TCP_TX_SEG_MAX  8

typedef struct tcp_conn tcp_conn_t;

/* ─── 网络统计（阶段5 观测基建）───
 * 唯一实例 static 于 net.c。字段布局即 ABI：net_stats_snapshot() 按字段序
 * 线性导出（13×uint32 连续无填充），ring3 nr=32 依赖此序，勿重排/删字段；
 * 新增计数只准尾部追加并同步 shell_user.c NS_* 索引与
 * docs/RING3_SYSCALL_ABI.md nr=32 条目（arp_entry_expired 即尾追加范例）。
 * 写上下文仅 PIT IRQ0(net_poll) / 主循环 / syscall(cli)，单核对齐 u32
 * 自增天然原子，免锁；ISR 路径零分配零格式化。 */
#define NET_STATS_COUNT 13u
struct net_stats {
    uint32_t arp_req_out;        /* arp_request: ARP 请求帧成功提交 TX */
    uint32_t arp_reply_in;       /* arp_handle: 收到指向本机的 ARP reply */
    uint32_t arp_resolve_miss;   /* arp_resolve: 缓存未命中(触发请求) */
    uint32_t ip_csum_err;        /* ip_handle: IPv4 头校验和失败丢弃 */
    uint32_t ethertype_unknown;  /* net_handle_packet: 未识别 ethertype */
    uint32_t udp_no_listener;    /* udp_handle: 无 socket 绑定该端口 */
    uint32_t rx_drop_full;       /* udp_handle: RX 队列满整包丢弃 */
    uint32_t tcp_rst_sent;       /* tcp_send_rst_ack 各调用点发出的 RST/RST-ACK */
    uint32_t tcp_rto_rexmit;     /* tcp_tick: RTO 到期重传(SYN-ACK/FIN/数据) */
    uint32_t tcp_sack_rexmit;    /* tcp_tx_retransmit_lost: SACK 选择性重传 */
    uint32_t tcp_persist_probe;  /* tcp_tick: 零窗口 persist 探测(1B) */
    uint32_t icmp_echo_out;      /* icmp_handle: echo reply 成功发出 */
    uint32_t arp_entry_expired;  /* arp_tick: stale 表项探测超时回收(阶段5 第三棒) */
};
int net_stats_snapshot(struct net_stats *out, uint32_t cap);

/* ─── Socket API ─── */
typedef enum { SOCK_CLOSED, SOCK_UDP, SOCK_TCP_LISTEN, SOCK_TCP_ESTAB, SOCK_UDP_UNBOUND, SOCK_TCP_UNBOUND } sock_type_t;

typedef struct {
    sock_type_t type;
    union {
        struct { uint16_t lport; uint8_t slot,owned; } udp;
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
bool net_parse_ipv4(const char *text,uint32_t *out);
int net_ping(uint32_t dst,uint16_t id,uint16_t seq,char *out,uint32_t out_len);
int net_ping_stats(char *out,uint32_t out_len);

/* UDP */
socket_t *udp_open(uint16_t lport);
int udp_sendto(socket_t *s, uint32_t dst_ip, uint16_t dst_port, const uint8_t *data, uint32_t len);
int udp_recvfrom(socket_t *s, uint32_t *src_ip, uint16_t *src_port, uint8_t *buf, uint32_t max_len);

/* DNS（阶段5 最小解析器，仅 syscall 上下文调用——内部 sti 轮询 300 ticks）
 * net_dns_resolve(name,out_ip)：向 g_dns(DHCP option6/回落10.0.2.3) 发 A/IN 查询，
 * 取 answer 首条 A 记录；CNAME 链≤4 跳；只认字面量标签名(05hello03com)，
 * 响应遇 0xC0 压缩指针直接失败（防越界）。out_ip 仅成功时写。
 * 错误码（负 errno，对照 linux errno-base）： */
#define NETDNS_EARGS       (-22)   /* EINVAL：参数空/域名非法/响应畸形 */
#define NETDNS_ENORESOLVER (-101)  /* ENETUNREACH：未配置 DNS/UDP 槽耗尽 */
#define NETDNS_ETIMEOUT    (-110)  /* ETIMEDOUT：总超时无匹配响应 */
#define NETDNS_EREFUSED    (-111)  /* ECONNREFUSED：响应 rcode!=0 */
int net_dns_resolve(const char *name, uint32_t *out_ip);

/* TCP */
socket_t *tcp_listen(uint16_t port);
int tcp_accept(socket_t *s, uint32_t *remote_ip, uint16_t *remote_port);
int tcp_send(socket_t *s, const uint8_t *data, uint32_t len);
int tcp_recv(socket_t *s, uint8_t *buf, uint32_t max_len);
void tcp_close(socket_t *s);
socket_t *net_socket_open(uint32_t type);
int net_socket_bind(socket_t *s,uint16_t port);
socket_t *tcp_accept_socket(socket_t *s);
int tcp_set_backlog(socket_t *s, uint32_t backlog);
void tcp_abort_socket(socket_t *s);
int net_socket_close(socket_t *s);

/* Convenience */
void net_set_ip(uint32_t ip);
uint32_t net_get_ip(void);
void net_set_gateway(uint32_t gw);
void net_set_subnet(uint32_t mask);

/* NAPI integration */
void net_napi_poll(void);

#endif
