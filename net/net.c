/*
 * net.c - cat-OS 网络协议栈核心（阶段 D 主干）
 * 链路: Ethernet 帧收发(经 e1000)  ─►  ARP  ─►  IPv4  ─►  ICMP / UDP / TCP
 * 设计取舍（性能向）:
 *   - RX/TX 均零拷贝：帧直接在 e1000 固定 DMA buffer 上解析、原地组帧
 *   - 无动态分配：ARP 表 / UDP 槽 / TCP 连接槽全部静态预分配（池化）
 *   - 校验采用标准 16-bit one's complement，IPv4 头校验 + TCP 伪头校验都做
 *   字节序约定: 头结构体内字段按网络序内存存放，读写用 ntoh/hton 助手。
 * 模块布局（自 net.c 单体机械拆分，跨模块符号见 net_internal.h）:
 *   net_arp.c / net_dhcp.c / net_dns.c / net_icmp.c / net_udp.c / net_tcp.c
 *   本文件保留: 全局配置、以太网+IPv4 分发、校验和、socket 胶水、统计快照、init/poll。
 */
#include "net.h"
#include "net_internal.h"
#include "e1000.h"
#include "kernel.h"
#include "interrupts.h"
#include <stddef.h>
#include <stdint.h>

/* ═══════════ 全局配置 ═══════════ */
uint8_t  g_mac[6];
uint32_t g_ip,g_gw,g_mask;   /* 均以网络序存储 */
uint32_t g_dns;              /* resolver IPv4（网络序）：DHCP option 6 学得，
                                       无 DHCP 时 net_poll 回落 slirp 惯例 10.0.2.3 */
uint16_t ip_id;
/* ═══════════ 网络统计（阶段5 观测基建）═══════════
 * 字段布局/写上下文约束见 net.h struct net_stats 注释。 */
struct net_stats g_net_stats;

/* 打印助手（跨模块共用，原型见 net_internal.h） */
void net_ip_print(uint32_t ip){uint8_t *b=(uint8_t*)&ip;for(int i=0;i<4;i++){kput_dec(b[i]);if(i<3)kputs(".");}}

/* ═══════════ 公共设施 ═══════════ */
bool net_parse_ipv4(const char *text,uint32_t *out){
    uint32_t value=0;uint32_t octet=0;uint32_t dots=0;bool digit=false;
    if(!text||!out)return false;
    for(uint32_t i=0;i<16;i++){
        char c=text[i];
        if(c>='0'&&c<='9'){digit=true;octet=octet*10u+(uint32_t)(c-'0');if(octet>255u)return false;continue;}
        if(c=='.'&&digit&&dots<3){value=(value<<8)|octet;octet=0;digit=false;dots++;continue;}
        if(c=='\0'&&digit&&dots==3){*out=hton32((value<<8)|octet);return true;}
        return false;
    }
    return false;
}
/* ═══════════ 校验和 ═══════════ */
uint16_t ip_checksum(const void *buf,uint32_t len){
    const uint8_t *b=buf;uint32_t sum=0;
    while(len>1){sum+=((uint16_t)b[0]<<8)|b[1];b+=2;len-=2;}
    if(len)sum+=(uint16_t)b[0]<<8;
    while(sum>>16)sum=(sum>>16)+(sum&0xffff);
    return (uint16_t)~sum;
}

uint16_t ip_checksum_pseudo(uint32_t src,uint32_t dst,uint8_t proto,uint16_t tcp_len,const void *buf,uint32_t len){
    const uint8_t *s=(const uint8_t*)&src,*d=(const uint8_t*)&dst;
    uint32_t sum=0;
    sum+=((uint16_t)s[0]<<8)|s[1];sum+=((uint16_t)s[2]<<8)|s[3];
    sum+=((uint16_t)d[0]<<8)|d[1];sum+=((uint16_t)d[2]<<8)|d[3];
    sum+=(uint16_t)proto;               /* 0x00 0x06 字节 → 大端 word 0x0006 */
    sum+=tcp_len;
    const uint8_t *b=buf;uint32_t l=len;
    while(l>1){sum+=((uint16_t)b[0]<<8)|b[1];b+=2;l-=2;}
    if(l)sum+=(uint16_t)b[0]<<8;
    while(sum>>16)sum=(sum>>16)+(sum&0xffff);
    return (uint16_t)~sum;
}

/* ═══════════ IP 层 ═══════════ */
uint8_t *begin_ip(uint32_t dst,uint8_t proto,const uint8_t dmac[6]){
    uint8_t *f=e1000_tx_alloc();if(!f)return NULL;
    memcpy6(f,dmac);memcpy6(f+6,g_mac);f[12]=0x08;f[13]=0x00;
    ip_hdr_t *h=(ip_hdr_t*)(f+14);
    h->ver_ihl=0x45;h->dscp_ecn=0;h->tot_len=0;h->id=hton16(ip_id++);
    h->flags_frag=0;h->ttl=64;h->proto=proto;h->hdr_csum=0;
    h->src=g_ip;h->dst=dst;
    return (uint8_t*)(h+1);
}
bool end_ip(uint8_t *seg,uint32_t seglen,uint8_t proto){
    (void)proto;
    ip_hdr_t *h=(ip_hdr_t*)(seg-20);
    h->tot_len=hton16((uint16_t)(20+seglen));
    h->hdr_csum=hton16(ip_checksum(h,20));
    return e1000_tx_submit(14+20+seglen)==0;
}
bool ip_send(uint32_t dst,uint8_t proto,const uint8_t *data,uint32_t len){
    uint8_t dmac[6];if(!arp_resolve(dst,dmac))return false;
    uint8_t *seg=begin_ip(dst,proto,dmac);if(!seg)return false;
    memcpy_u(seg,data,len);
    return end_ip(seg,len,proto);
}

static void ip_handle(const uint8_t *p,uint32_t len){
    if(len<20)return;
    if(ip_checksum(p,20)!=0){NETSTAT_INC(ip_csum_err);return;}
    const ip_hdr_t *h=(const ip_hdr_t*)p;
    uint32_t dst=h->dst;
    if(dst!=g_ip&&dst!=0xFFFFFFFF)return;
    uint32_t plen=ntoh16(h->tot_len);if(plen>len)plen=len;
    const uint8_t *seg=p+20;
    uint32_t seglen=plen-20;
    switch(h->proto){
        case IP_PROTO_ICMP: icmp_handle(seg,seglen,h->src);break;
        case IP_PROTO_UDP:  udp_handle(seg,seglen,h->src);break;
        case IP_PROTO_TCP:  tcp_handle(seg,seglen,h->src);break;
        default: break;
    }
}

/* ═══════════ socket 胶水（跨 UDP/TCP 两表，留在核心） ═══════════ */
int net_socket_bind(socket_t *s,uint16_t port){
    if(!s||port==0)return -22;
    if(s->type==SOCK_UDP_UNBOUND){
        udp_sock_t *u=&udp_socks[s->udp.slot];
        if(!u->used||!u->owned||udp_sock_by_port(port))return -98;
        u->bound=true;u->lport=port;u->head=u->n=0;s->type=SOCK_UDP;s->udp.lport=port;return 0;
    }
    if(s->type==SOCK_TCP_UNBOUND){
        /* H2/EADDRINUSE：端口已被其他 LISTEN 占用时必须拒绝绑定(-98)。
           旧实现把自身 conn 标记 unused 后静默附着到既有 LISTEN conn，
           产生"两个 socket → 同一 TCB"的悬垂共享：任一方 close 都会作废
           另一方的 conn 指针（use-after-free 形态）。
           参照同函数 SOCK_UDP_UNBOUND 分支的 udp_sock_by_port() 占用检查；
           语义依据：RFC 9293 §3.10.7.2 LISTEN 态假定每本地端口一个被动
           打开的 TCB；错误码遵循 POSIX bind(2) EADDRINUSE。 */
        if(tcp_conn_find_listen(port))return -98;
        tcp_conn_t *c=s->tcp.conn;
        c->state=TCP_LISTEN;c->backlog=1;c->lport=port;c->peer_ip=0;c->peer_port=0;
        c->accepted=false;c->rxn=0;c->snd_used=0;c->snd_una=c->snd_nxt=c->snd_isn=0;
        c->rto_deadline=0;c->rto_backoff=0;c->rto_attempts=0;c->tw_until=0;c->persist_deadline=0;c->persist_backoff=0;
        tcp_tx_reset(c);
        tcp_cc_init(c);
        s->type=SOCK_TCP_LISTEN;s->tcp.conn=c;return 0;
    }
    return -22;
}
int net_socket_close(socket_t *s){
    if(!s||s->type==SOCK_CLOSED)return -9;
    if(s->type==SOCK_UDP||s->type==SOCK_UDP_UNBOUND){if(s->udp.owned){udp_socks[s->udp.slot].used=false;udp_socks[s->udp.slot].bound=false;}s->type=SOCK_CLOSED;return 0;}
    if(s->type==SOCK_TCP_ESTAB){tcp_close(s);return 0;}
    if(s->type==SOCK_TCP_UNBOUND){if(s->tcp.conn)s->tcp.conn->used=false;s->type=SOCK_CLOSED;return 0;}
    if(s->type==SOCK_TCP_LISTEN){
        if(s->tcp.conn){tcp_drop_pending(s->tcp.conn->lport);s->tcp.conn->used=false;}
        s->type=SOCK_CLOSED;return 0;
    }
    return -22;
}

short net_socket_poll(socket_t *s, short events)
{
    if (!s)
        return NET_POLLNVAL;
    if (s->type == SOCK_TCP_LISTEN || s->type == SOCK_TCP_ESTAB)
        return tcp_socket_poll(s, events);
    if (s->type == SOCK_UDP || s->type == SOCK_UDP_UNBOUND)
        return udp_socket_poll(s, events);
    return NET_POLLNVAL;
}

/* accept 路径 helper：返回对端 ip/port（host-order）。
 * 仅对 SOCK_TCP_ESTAB 有意义；其他类型返回 0。 */
void net_socket_peer(socket_t *s, uint32_t *ip, uint16_t *port)
{
    if (ip) *ip = 0;
    if (port) *port = 0;
    if (s && s->type == SOCK_TCP_ESTAB && s->tcp.conn) {
        if (ip) *ip = s->tcp.conn->peer_ip;
        if (port) *port = s->tcp.conn->peer_port;
    }
}
socket_t *net_socket_open(uint32_t type){
    if(type==2){for(int i=0;i<UDP_SLOTS;i++)if(!udp_socks[i].used){udp_socks[i]=(udp_sock_t){0};udp_socks[i].used=true;udp_socks[i].owned=true;udp_handles[i]=(socket_t){SOCK_UDP_UNBOUND,{.udp={(uint16_t)0,(uint8_t)i,1}}};return &udp_handles[i];}return NULL;}
    if(type==1){for(int i=0;i<TCP_MAX_CONNS;i++)if(!tcp_conns[i].used){tcp_conns[i]=(tcp_conn_t){0};tcp_conns[i].used=true;tcp_conns[i].state=TCP_CLOSED;tcp_handles[i]=(socket_t){SOCK_TCP_UNBOUND,{.tcp={&tcp_conns[i]}}};return &tcp_handles[i];}return NULL;}
    return NULL;
}
/* ═══════════ 入口 ═══════════ */
void net_handle_packet(const uint8_t *p,uint32_t len){
    if(len<14)return;
    uint16_t type=(uint16_t)((p[12]<<8)|p[13]);
    if(type==ETH_TYPE_ARP)arp_handle(p,len);
    else if(type==ETH_TYPE_IP)ip_handle(p+14,len-14);
    else kputs("[NET] unknown ethertype\n");
}

void net_set_ip(uint32_t ip){g_ip=ip;}
uint32_t net_get_ip(void){return g_ip;}
void net_set_gateway(uint32_t gw){g_gw=gw;}
void net_set_subnet(uint32_t mask){g_mask=mask;}

void net_napi_poll(void){e1000_poll();}

void net_poll(void){
    e1000_poll();tcp_tick();
    arp_poll();
    dhcp_tick();
}

/* 统计快照：按 struct net_stats 字段序线性导出到 out，至多 cap 个条目(u32)。
 * 返回写入条目数(min(cap,NET_STATS_COUNT))；out==NULL → -1；
 * cap==0 合法：不写任何字节、返回 0。 */
int net_stats_snapshot(struct net_stats *out,uint32_t cap){
    if(!out)return -1;
    uint32_t n=cap<NET_STATS_COUNT?cap:NET_STATS_COUNT;
    memcpy_u(out,&g_net_stats,n*sizeof(uint32_t));
    return (int)n;
}

void net_init(void){
    e1000_get_mac(g_mac);
    net_set_ip(0);net_set_gateway(0);net_set_subnet(0);g_dns=0;
    kputs("[NET] up ip=");net_ip_print(g_ip);kputs(" gw=");net_ip_print(g_gw);kputs(" mask=");net_ip_print(g_mask);kputs("\n");
    dhcp_start();
    /* 演示服务: UDP :7 echo; TCP :81 is acceptance-only.
       TCP :80 由 ring3 ext_socktest 绑定服务（blackbox 契约）：
       H2/EADDRINUSE 加固后内核演示监听会令 ring3 bind(:80) 恒返 -98，
       旧「静默附着」路径已删除，故内核不再占用 :80。 */
    /* tcp_listen(80); */
    tcp_listen(81);
    udp_open(7);
}
