#ifndef CATOS_NET_INTERNAL_H
#define CATOS_NET_INTERNAL_H
/* net_internal.h —— 网络栈模块间内部契约（由 net.c 单体机械拆分产生）。
 * 仅限内核协议栈各 net_*.c / net.c 使用；公开 ABI 一律走 net.h，勿在此暴露用户态接口。
 *
 * 所有权约定（多代理并行领地）：
 *   net.c        : 全局配置(g_mac/g_ip/g_gw/g_mask/g_dns/ip_id)、IP 层、统计、socket 胶水
 *   net_arp.c    : ARP 表/请求/响应/老化（arp_scan_deadline 归其所有）
 *   net_dhcp.c   : DHCP 客户端状态机（dhcp_* 全部归其所有）
 *   net_dns.c    : DNS 解析器（只读使用 seq_gen 与 UDP 表原语）
 *   net_icmp.c   : ICMP echo/ping（ping_* 静态私有）
 *   net_udp.c    : UDP 收发与槽表（udp_socks/udp_handles 归其所有）
 *   net_tcp.c    : TCP 全部（seq_gen/tcp_conns/tcp_handles 归其所有）
 *   跨领地读者仅限：net.c 的 socket 胶水(net_socket_open/bind/close)、net_dns.c 的临时端口分配。 */
#include "net.h"

/* ─── 字节序/内存助手（原 net.c:17-24 原文搬移）─── */
static inline uint16_t ntoh16(uint16_t v){return (uint16_t)((v>>8)|(v<<8));}
static inline uint32_t ntoh32(uint32_t v){return ((v&0xff)<<24)|((v&0xff00)<<8)|((v>>8)&0xff00)|((v>>24)&0xff);}
static inline uint16_t hton16(uint16_t v){return ntoh16(v);}
static inline uint32_t hton32(uint32_t v){return ntoh32(v);}
static inline void memcpy_u(void *d,const void *s,uint32_t n){uint8_t *dd=d;const uint8_t *ss=s;for(uint32_t i=0;i<n;i++)dd[i]=ss[i];}
static inline void memcpy6(uint8_t *d,const uint8_t *s){for(int i=0;i<6;i++)d[i]=s[i];}
static inline void memset6(uint8_t *d){for(int i=0;i<6;i++)d[i]=0;}

/* ─── 全局配置（定义于 net.c；网络序存储）─── */
extern uint8_t  g_mac[6];
extern uint32_t g_ip,g_gw,g_mask;
extern uint32_t g_dns;               /* resolver IPv4：DHCP option 6 学得，无 DHCP 回落 10.0.2.3 */
extern uint16_t ip_id;
extern uint32_t seq_gen;             /* 本地 TCP ISN 生成器（定义于 net_tcp.c；net_dns.c 派生 txid 只读复用） */

/* ─── 网络统计（阶段5 观测基建；唯一实例定义于 net.c）───
 * 字段布局/写上下文约束见 net.h struct net_stats 注释。 */
extern struct net_stats g_net_stats;
#define NETSTAT_INC(f) (++g_net_stats.f)

/* ─── net.c 核心：打印/IP 层组帧 ─── */
void net_ip_print(uint32_t ip);
uint8_t *begin_ip(uint32_t dst,uint8_t proto,const uint8_t dmac[6]);
bool end_ip(uint8_t *seg,uint32_t seglen,uint8_t proto);

/* ─── 分发入口（ip_handle/net_poll 按 proto/timer 调用）─── */
void arp_handle(const uint8_t *p,uint32_t len);
void arp_poll(void);                 /* ARP 老化扫描周期闸（原 net_poll 内联语句整体搬移） */
void icmp_handle(const uint8_t *seg,uint32_t seglen,uint32_t src_ip);
void udp_handle(const uint8_t *seg,uint32_t seglen,uint32_t src_ip);
void tcp_handle(const uint8_t *seg,uint32_t seglen,uint32_t src_ip);
void tcp_tick(void);
void dhcp_handle(const uint8_t *d,uint32_t n);
void dhcp_tick(void);                /* DHCP 租约生命周期（原 net_poll 内联块整体搬移） */
void dhcp_start(void);               /* 启动 DISCOVER 探测（原 net_init 内联语句整体搬移） */
bool udp_send(uint32_t dst_ip,uint16_t dst_port,uint16_t src_port,const uint8_t *data,uint32_t len);

/* ─── UDP 槽表内部（所有者 net_udp.c；读者 net_dns.c/net.c socket 胶水）─── */
#define UDP_SLOTS 8
#define UDP_RXBUF 2048
typedef struct {
    bool used,bound,owned;
    uint16_t lport;
    uint8_t rxb[UDP_RXBUF];      /* 线性包队列: [pkt_len(4)][src_ip(4)][sport(2)]payload... */
    uint32_t head,n;
} udp_sock_t;
extern udp_sock_t udp_socks[UDP_SLOTS];
extern socket_t udp_handles[UDP_SLOTS];
udp_sock_t *udp_sock_by_port(uint16_t port);
udp_sock_t *udp_sock_find_free(void);

/* ─── TCP 连接表内部（所有者 net_tcp.c；读者 net.c socket 胶水）─── */
struct tcp_conn {
    bool used,accepted;
    uint8_t state;
    uint8_t backlog;             /* bounded pending accept queue */
    uint32_t rcv_isn,rcv_nxt;    /* 对方 ISN / 期望下一序号 */
    uint32_t snd_isn,snd_nxt,snd_una;  /* 本地 ISN / 下一发送 / 最早未确认 */
    uint32_t peer_ip;
    uint16_t peer_port,lport,peer_win; /* peer_win=对端通告窗口 */
    uint16_t adv_win;            /* 最近一次实际通告到线上的接收窗口（SWS 后值，
                                    供 recv() 判断「窗口显著打开→立即 ACK」，对照
                                    linux tcp.c __tcp_cleanup_rbuf 的 rcv_window_now） */
    uint16_t peer_mss;           /* 对端 SYN 中宣告的 MSS（0=未知，按 TCP_MSS 兜底） */
    uint8_t rxb[TCP_BUF_SIZE];   /* 接收缓冲 */
    uint32_t rxn;
    struct { uint32_t seq; uint16_t len; bool used; uint8_t data[TCP_MSS]; } ooo[TCP_OOO_SLOTS];
    uint32_t ooo_bytes;
    bool sack_ok;
    uint32_t sack_left[2],sack_right[2];
    uint8_t sack_n;
    uint8_t sndb[TCP_BUF_SIZE];  /* 发送缓冲：snd_una..snd_nxt 区间数据 */
    uint32_t snd_used;           /* 缓冲中未确认字节数 */
    struct {
        uint32_t seq;
        uint16_t len;
        bool used, sacked, lost, retransmitted;
    } tx[TCP_TX_SEG_MAX];         /* bounded SACK scoreboard */
    uint8_t tx_n;
    uint32_t rto_deadline;       /* 重传截止时刻(ticks) */
    uint8_t  rto_backoff;        /* 退避指数 0/1/2/... */
    uint8_t  rto_attempts;       /* M1: 同段连续重传计数(R1/R2 度量)，RFC 9293 §3.8.3(a) */
    uint32_t rto_ticks;          /* 动态 RTO，100Hz ticks */
    uint32_t rtt_stamp;          /* 首个未重传数据段发送时刻 */
    uint32_t rtt_seq;            /* 该采样段的结束序号 */
    uint32_t srtt_ticks, rttvar_ticks;
    bool rtt_pending, rtt_retransmitted;
    uint32_t cwnd, ssthresh;     /* Reno byte windows */
    uint32_t dupacks;
    bool fast_recovery;
    uint32_t recover_seq;
    uint32_t tw_until;           /* TIME_WAIT 释放时刻(ticks) */
    uint32_t persist_deadline;   /* zero-window probe deadline */
    uint8_t persist_backoff;
    bool test_sent,test_closed;  /* TCP :81 acceptance path */
    bool dead;                   /* 阶段3 E2：合法 RST 复位死亡标记。stale fd 的
                                    send/recv 据此上报 -ECONNRESET 而非假 EAGAIN；
                                    复用点 tcp_listen()/SYN 接收路径显式清零，
                                    net_socket_open() 整体清零，不泄漏到新连接 */
    /* ── Wave 2: 性能优化字段 ─────────────────────────────────────── */
    bool nodelay;                /* TCP_NODELAY=1: 禁用 Nagle，立即发送 */
    uint8_t rcv_wscale;          /* 接收窗口缩放因子（RFC 7323） */
    uint8_t snd_wscale;          /* 发送窗口缩放因子 */
};
extern tcp_conn_t tcp_conns[TCP_MAX_CONNS];
extern socket_t tcp_handles[TCP_MAX_CONNS];
tcp_conn_t *tcp_conn_find_listen(uint16_t port);
void tcp_drop_pending(uint16_t port);
void tcp_cc_init(tcp_conn_t *c);
void tcp_tx_reset(tcp_conn_t *c);

#endif
