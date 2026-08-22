/*
 * net.c - cat-OS 网络协议栈（阶段 D 主干）
 * 链路: Ethernet 帧收发(经 e1000)  ─►  ARP  ─►  IPv4  ─►  ICMP / UDP / TCP
 * 设计取舍（性能向）:
 *   - RX/TX 均零拷贝：帧直接在 e1000 固定 DMA buffer 上解析、原地组帧
 *   - 无动态分配：ARP 表 / UDP 槽 / TCP 连接槽全部静态预分配（池化）
 *   - 校验采用标准 16-bit one's complement，IPv4 头校验 + TCP 伪头校验都做
 *   字节序约定: 头结构体内字段按网络序内存存放，读写用 ntoh/hton 助手。
 */
#include "net.h"
#include "e1000.h"
#include "kernel.h"
#include "interrupts.h"
#include <stddef.h>
#include <stdint.h>

/* ═══════════ 字节序助手 ═══════════ */
static inline uint16_t ntoh16(uint16_t v){return (uint16_t)((v>>8)|(v<<8));}
static inline uint32_t ntoh32(uint32_t v){return ((v&0xff)<<24)|((v&0xff00)<<8)|((v>>8)&0xff00)|((v>>24)&0xff);}
static inline uint16_t hton16(uint16_t v){return ntoh16(v);}
static inline uint32_t hton32(uint32_t v){return ntoh32(v);}
static void memcpy_u(void *d,const void *s,uint32_t n){uint8_t *dd=d;const uint8_t *ss=s;for(uint32_t i=0;i<n;i++)dd[i]=ss[i];}
static void memcpy6(uint8_t *d,const uint8_t *s){for(int i=0;i<6;i++)d[i]=s[i];}
static void memset6(uint8_t *d){for(int i=0;i<6;i++)d[i]=0;}

/* ═══════════ 全局配置 ═══════════ */
static uint8_t  g_mac[6];
static uint32_t g_ip,g_gw,g_mask;   /* 均以网络序存储 */
static uint16_t ip_id;
static uint32_t seq_gen=0x12340000; /* 本地 TCP ISN 生成器 */
static uint32_t dhcp_xid, dhcp_offer, dhcp_server, dhcp_mask, dhcp_gw;
static uint32_t dhcp_last, dhcp_wait;
static uint8_t dhcp_state, dhcp_retries;
#define DHCP_DISCOVER 1
#define DHCP_WAIT_OFFER 2
#define DHCP_WAIT_ACK 3
#define DHCP_DONE 4
void icmp_handle(const uint8_t *,uint32_t,uint32_t);
void udp_handle(const uint8_t *,uint32_t,uint32_t);
void tcp_handle(const uint8_t *,uint32_t,uint32_t);

/* ═══════════ ARP ═══════════ */
#define ARP_CACHE_MAX 8
typedef struct {uint32_t ip;uint8_t mac[6];} arp_entry_t;
static arp_entry_t arp_cache[ARP_CACHE_MAX];
static uint8_t arp_cache_n;

static void net_ip_print(uint32_t ip){uint8_t *b=(uint8_t*)&ip;for(int i=0;i<4;i++){kput_dec(b[i]);if(i<3)kputs(".");}}

static void arp_cache_add(uint32_t ip,const uint8_t mac[6]){
    for(int i=0;i<arp_cache_n;i++)if(arp_cache[i].ip==ip){memcpy6(arp_cache[i].mac,mac);return;}
    if(arp_cache_n<ARP_CACHE_MAX){arp_cache[arp_cache_n].ip=ip;memcpy6(arp_cache[arp_cache_n].mac,mac);arp_cache_n++;return;}
    arp_cache[0].ip=ip;memcpy6(arp_cache[0].mac,mac);   /* 极简 LRU: 满了踢第一个 */
}

/* 组装并发送一帧 ARP 请求 */
static void arp_request(uint32_t ip){
    uint8_t *p=e1000_tx_alloc();if(!p)return;
    for(int i=0;i<6;i++){p[i]=0xFF;p[6+i]=g_mac[i];}
    uint16_t *w=(uint16_t*)p;w[6]=hton16(ETH_TYPE_ARP);
    arp_pkt_t *a=(arp_pkt_t*)(p+14);
    a->htype=hton16(1);a->ptype=hton16(0x0800);a->hlen=6;a->plen=4;a->op=hton16(ARP_OP_REQUEST);
    memcpy6(a->sha,g_mac);*(uint32_t*)a->spa=g_ip;memset6(a->tha);*(uint32_t*)a->tpa=ip;
    if(e1000_tx_submit(42)==0){kputs("[NET] ARP who-has ");net_ip_print(ip);kputs("?\n");}
}

bool arp_resolve(uint32_t ip,uint8_t mac[6]){
    if(ip==0xFFFFFFFFu){memset6(mac);for(int i=0;i<6;i++)mac[i]=0xFF;return true;}
    for(int i=0;i<arp_cache_n;i++)if(arp_cache[i].ip==ip){memcpy6(mac,arp_cache[i].mac);return true;}
    arp_request(ip);
    return false;
}

static void arp_handle(const uint8_t *p,uint32_t len){
    if(len<42)return;
    arp_pkt_t *a=(arp_pkt_t*)(p+14);
    if(ntoh16(a->htype)!=1||ntoh16(a->ptype)!=0x0800||a->hlen!=6||a->plen!=4)return;
    uint32_t spa;memcpy_u(&spa,a->spa,4);      /* 网络序 */
    uint32_t tpa;memcpy_u(&tpa,a->tpa,4);
    uint16_t op=ntoh16(a->op);
    /* 任何 ARP 包都先把发送方塞进缓存 */
    arp_cache_add(spa,a->sha);
    if(op==ARP_OP_REQUEST && tpa==g_ip){
        uint8_t *b=e1000_tx_alloc();if(!b)return;
        /* 以太头: 目标=请求方 MAC，源=本机 */
        memcpy6(b,a->sha);memcpy6(b+6,g_mac);((uint16_t*)b)[6]=hton16(ETH_TYPE_ARP);
        arp_pkt_t *r=(arp_pkt_t*)(b+14);
        r->htype=hton16(1);r->ptype=hton16(0x0800);r->hlen=6;r->plen=4;r->op=hton16(ARP_OP_REPLY);
        memcpy6(r->sha,g_mac);*(uint32_t*)r->spa=g_ip;memcpy6(r->tha,a->sha);*(uint32_t*)r->tpa=spa;
        if(e1000_tx_submit(42)==0){kputs("[NET] ARP reply -> ");net_ip_print(spa);kputs("\n");}
    }else if(op==ARP_OP_REPLY && tpa==g_ip){
        kputs("[NET] ARP reply from ");net_ip_print(spa);kputs("\n");
    }
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
static uint8_t *begin_ip(uint32_t dst,uint8_t proto,const uint8_t dmac[6]){
    uint8_t *f=e1000_tx_alloc();if(!f)return NULL;
    memcpy6(f,dmac);memcpy6(f+6,g_mac);f[12]=0x08;f[13]=0x00;
    ip_hdr_t *h=(ip_hdr_t*)(f+14);
    h->ver_ihl=0x45;h->dscp_ecn=0;h->tot_len=0;h->id=hton16(ip_id++);
    h->flags_frag=0;h->ttl=64;h->proto=proto;h->hdr_csum=0;
    h->src=g_ip;h->dst=dst;
    return (uint8_t*)(h+1);
}
static bool end_ip(uint8_t *seg,uint32_t seglen,uint8_t proto){
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

/* ═══════════ ICMP ═══════════ */
void icmp_handle(const uint8_t *seg,uint32_t seglen,uint32_t src_ip){
    if(seglen<8)return;
    const icmp_hdr_t *ih=(const icmp_hdr_t*)seg;
    if(ih->type!=ICMP_TYPE_ECHO_REQUEST)return;
    uint8_t dmac[6];if(!arp_resolve(src_ip,dmac))return;
    uint8_t *out=begin_ip(src_ip,IP_PROTO_ICMP,dmac);if(!out)return;
    memcpy_u(out,seg,seglen);
    icmp_hdr_t *r=(icmp_hdr_t*)out;
    r->type=ICMP_TYPE_ECHO_REPLY;r->code=0;r->csum=0;
    r->csum=hton16(ip_checksum(out,seglen));
    if(end_ip(out,seglen,IP_PROTO_ICMP)){kputs("[NET] ICMP echo reply -> ");net_ip_print(src_ip);kputs(" (");kput_dec(seglen-8);kputs("B)\n");}
}

/* ═══════════ UDP ═══════════ */
#define UDP_SLOTS 8
#define UDP_RXBUF 2048
typedef struct {
    bool used,bound;
    uint16_t lport;
    uint8_t rxb[UDP_RXBUF];      /* 线性包队列: [pkt_len(4)][src_ip(4)][sport(2)]payload... */
    uint32_t head,n;
} udp_sock_t;
static udp_sock_t udp_socks[UDP_SLOTS];
static udp_sock_t *udp_sock_by_port(uint16_t port){for(int i=0;i<UDP_SLOTS;i++)if(udp_socks[i].used&&udp_socks[i].bound&&udp_socks[i].lport==port)return &udp_socks[i];return NULL;}
static udp_sock_t *udp_sock_find_free(void){for(int i=0;i<UDP_SLOTS;i++)if(!udp_socks[i].used)return &udp_socks[i];return NULL;}

static bool udp_send(uint32_t dst_ip,uint16_t dst_port,uint16_t src_port,const uint8_t *data,uint32_t len){
    uint8_t dmac[6];if(!arp_resolve(dst_ip,dmac))return false;
    uint8_t *seg=begin_ip(dst_ip,IP_PROTO_UDP,dmac);if(!seg)return false;
    udp_hdr_t *u=(udp_hdr_t*)seg;
    u->src_port=hton16(src_port);u->dst_port=hton16(dst_port);u->len=hton16((uint16_t)(8+len));u->csum=0;
    memcpy_u(seg+8,data,len);
    return end_ip(seg,8+len,IP_PROTO_UDP);
}

static void dhcp_send(uint8_t type){
    uint8_t b[548],*o;                           /* 对齐 Linux bootp_pkt: 236 固定 + exten[312]，RFC2131 最小 300B */
    for(uint32_t i=0;i<548;i++)b[i]=0;
    b[0]=1;b[1]=1;b[2]=6;b[3]=0;*(uint32_t*)(b+4)=hton32(dhcp_xid);
    *(uint16_t*)(b+8)=0;*(uint16_t*)(b+10)=hton16(0x8000);memcpy_u(b+28,g_mac,6);
    o=b+236;o[0]=99;o[1]=130;o[2]=83;o[3]=99;o+=4;o[0]=53;o[1]=1;o[2]=type;o+=3;
    if(type==3){o[0]=54;o[1]=4;memcpy_u(o+2,&dhcp_server,4);o+=6;o[0]=50;o[1]=4;memcpy_u(o+2,&dhcp_offer,4);o+=6;}
    o[0]=55;o[1]=3;o[2]=1;o[3]=3;o[4]=6;o+=5;o[0]=255;
    udp_send(0xFFFFFFFFu,67,68,b,548);          /* 发完整 548B，剩余 pad 0 */
    kputs("[NET] DHCP ");kputs(type==1?"DISCOVER\n":"REQUEST\n");
}

static void dhcp_handle(const uint8_t *d,uint32_t n){
    if(n<240||d[0]!=2||d[1]!=1||d[2]!=6||ntoh32(*(const uint32_t*)(d+4))!=dhcp_xid)return;
    if(d[28]!=g_mac[0]||d[29]!=g_mac[1]||d[30]!=g_mac[2]||d[31]!=g_mac[3]||d[32]!=g_mac[4]||d[33]!=g_mac[5])return;
    if(d[236]!=99||d[237]!=130||d[238]!=83||d[239]!=99)return;
    uint8_t mt=0;uint32_t i=240;while(i<n&&d[i]!=255){if(d[i]==0){i++;continue;}if(i+1>=n||i+2+d[i+1]>n)break;uint8_t l=d[i+1];if(d[i]==53&&l)mt=d[i+2];else if(d[i]==54&&l==4)memcpy_u(&dhcp_server,d+i+2,4);else if(d[i]==1&&l==4)memcpy_u(&dhcp_mask,d+i+2,4);else if(d[i]==3&&l>=4)memcpy_u(&dhcp_gw,d+i+2,4);i+=2+l;}
    if(mt==2&&dhcp_state==DHCP_WAIT_OFFER){dhcp_offer=*(const uint32_t*)(d+16);dhcp_state=DHCP_WAIT_ACK;dhcp_send(3);dhcp_last=ticks;dhcp_wait=2;return;}
    if(mt==5&&dhcp_state==DHCP_WAIT_ACK){dhcp_offer=*(const uint32_t*)(d+16);net_set_ip(dhcp_offer);net_set_gateway(dhcp_gw);net_set_subnet(dhcp_mask);dhcp_state=DHCP_DONE;kputs("[NET] DHCP ACK ip=");net_ip_print(g_ip);kputs(" gw=");net_ip_print(g_gw);kputs(" mask=");net_ip_print(g_mask);kputs("\n");}
}

void udp_handle(const uint8_t *seg,uint32_t seglen,uint32_t src_ip){
    if(seglen<8)return;
    const udp_hdr_t *u=(const udp_hdr_t*)seg;
    uint16_t dport=ntoh16(u->dst_port),sport=ntoh16(u->src_port);
    uint32_t plen=ntoh16(u->len);if(plen>seglen)plen=seglen;
    const uint8_t *data=seg+8;uint32_t dlen=plen-8;
    if(dport==68&&sport==67){dhcp_handle(data,dlen);return;}
    udp_sock_t *s=udp_sock_by_port(dport);
    if(!s){
        kputs("[NET] UDP :");kput_dec(dport);kputs(" no listener\n");
        return;
    }
    /* echo 端口 7：服务端回显惯例，测试友好 */
    if(dport==7)udp_send(src_ip,sport,7,data,dlen);
    /* 入队（满则丢弃整包） */
    if(s->n+4+4+2+dlen<=UDP_RXBUF){
        uint8_t *w=&s->rxb[s->head];
        w[0]=(uint8_t)(dlen>>24);w[1]=(uint8_t)(dlen>>16);w[2]=(uint8_t)(dlen>>8);w[3]=(uint8_t)dlen;
        memcpy_u(w+4,&src_ip,4);
        w[8]=(uint8_t)(sport>>8);w[9]=(uint8_t)sport;
        memcpy_u(w+10,data,dlen);
        s->head+=4+4+2+dlen;s->n+=4+4+2+dlen;
    }
    kputs("[NET] UDP :");kput_dec(dport);kputs(" <- ");net_ip_print(src_ip);kputs(":");kput_dec(sport);kputs(" ");kput_dec(dlen);kputs("B\n");
}

socket_t *udp_open(uint16_t lport){
    udp_sock_t *s=udp_sock_find_free();if(!s)return NULL;
    s->used=true;s->bound=true;s->lport=lport;s->head=s->n=0;
    static socket_t sock;                      /* 单例：演示用，避免指针浮动 */
    sock.type=SOCK_UDP;sock.udp.lport=lport;
    kputs("[NET] UDP socket open :");kput_dec(lport);kputs("\n");
    return &sock;
}

int udp_sendto(socket_t *s,uint32_t dst_ip,uint16_t dst_port,const uint8_t *data,uint32_t len){
    if(!s||s->type!=SOCK_UDP)return -1;
    if(len>1472)return -1;
    return udp_send(dst_ip,dst_port,s->udp.lport,data,len)?0:-1;
}

int udp_recvfrom(socket_t *s,uint32_t *src_ip,uint16_t *src_port,uint8_t *buf,uint32_t max_len){
    if(!s||s->type!=SOCK_UDP)return -1;
    udp_sock_t *u=udp_sock_by_port(s->udp.lport);if(!u||u->n==0)return -1;
    uint8_t *r=&u->rxb[0];
    uint32_t dlen=((uint32_t)r[0]<<24)|((uint32_t)r[1]<<16)|((uint32_t)r[2]<<8)|r[3];
    uint32_t total=4+4+2+dlen;
    if(src_ip)memcpy_u(src_ip,r+4,4);
    if(src_port)*src_port=(uint16_t)((r[8]<<8)|r[9]);
    if(dlen>max_len)dlen=max_len;
    memcpy_u(buf,r+10,dlen);
    u->n-=total;if(u->n>0)memcpy_u(u->rxb,u->rxb+total,u->n);
    u->head=u->n;
    return (int)dlen;
}

/* ═══════════ TCP ═══════════ */
typedef struct tcp_conn {
    bool used,accepted;
    uint8_t state;
    uint32_t rcv_isn,rcv_nxt;    /* 对方 ISN / 期望下一序号 */
    uint32_t snd_isn,snd_nxt,snd_una;  /* 本地 ISN / 下一发送 / 最早未确认 */
    uint32_t peer_ip;
    uint16_t peer_port,lport,peer_win; /* peer_win=对端通告窗口 */
    uint8_t rxb[TCP_BUF_SIZE];   /* 接收缓冲 */
    uint32_t rxn;
    uint8_t sndb[TCP_BUF_SIZE];  /* 发送缓冲：snd_una..snd_nxt 区间数据 */
    uint32_t snd_used;           /* 缓冲中未确认字节数 */
    uint32_t rto_deadline;       /* 重传截止时刻(ticks) */
    uint8_t  rto_backoff;        /* 退避指数 0/1/2/... */
    uint32_t tw_until;           /* TIME_WAIT 释放时刻(ticks) */
    bool test_sent,test_closed;  /* TCP :81 acceptance path */
} tcp_conn_t;
static tcp_conn_t tcp_conns[TCP_MAX_CONNS];
static socket_t  tcp_socks[TCP_MAX_CONNS];

#define TCP_RTO_INIT   30u   /* 300ms @100Hz */
#define TCP_RTO_MAX    240u  /* 2.4s */
static uint32_t rto_now(tcp_conn_t *c){uint32_t r=TCP_RTO_INIT<<c->rto_backoff;if(r>TCP_RTO_MAX)r=TCP_RTO_MAX;return r;}
static void tcp_rto_arm(tcp_conn_t *c){c->rto_deadline=ticks+rto_now(c);c->rto_backoff=0;}
static void tcp_rto_retry(tcp_conn_t *c){
    if(c->rto_backoff<6)c->rto_backoff++;
    c->rto_deadline=ticks+rto_now(c);
}

static tcp_conn_t *tcp_conn_find_free(void){for(int i=0;i<TCP_MAX_CONNS;i++)if(!tcp_conns[i].used)return &tcp_conns[i];return NULL;}
static tcp_conn_t *tcp_conn_find_peer(uint32_t ip,uint16_t sport){for(int i=0;i<TCP_MAX_CONNS;i++)if(tcp_conns[i].used&&tcp_conns[i].peer_ip==ip&&tcp_conns[i].peer_port==sport)return &tcp_conns[i];return NULL;}
static tcp_conn_t *tcp_conn_find_listen(uint16_t port){for(int i=0;i<TCP_MAX_CONNS;i++)if(tcp_conns[i].used&&tcp_conns[i].state==TCP_LISTEN&&tcp_conns[i].lport==port)return &tcp_conns[i];return NULL;}
static void tcp_put_pkt(tcp_conn_t *c,uint8_t flags,uint32_t seq,uint32_t ack,const uint8_t *data,uint32_t dlen){
    uint8_t dmac[6];if(!arp_resolve(c->peer_ip,dmac))return;
    uint8_t *seg=begin_ip(c->peer_ip,IP_PROTO_TCP,dmac);if(!seg)return;
    tcp_hdr_t *t=(tcp_hdr_t*)seg;
    t->src_port=hton16(c->lport);t->dst_port=hton16(c->peer_port);
    t->seq=hton32(seq);t->ack_seq=hton32(ack);
    t->off_res=0x50;t->flags=flags;
    uint16_t win=(uint16_t)(TCP_BUF_SIZE-c->rxn);              /* 动态通告接收窗口 */
    t->window=hton16(win);t->csum=0;t->urgent=0;
    memcpy_u(seg+20,data,dlen);
    t->csum=hton16(ip_checksum_pseudo(g_ip,c->peer_ip,IP_PROTO_TCP,(uint16_t)(20+dlen),seg,20+dlen));
    end_ip(seg,20+dlen,IP_PROTO_TCP);
}

/* Send buffered data that fits in the current peer window. */
static void tcp_xmit_pending(tcp_conn_t *c){
    uint32_t in_flight=c->snd_nxt-c->snd_una;
    if(in_flight>=c->peer_win||c->snd_used<=in_flight)return;
    uint32_t n=c->snd_used-in_flight;
    uint32_t room=c->peer_win-in_flight;
    if(n>room)n=room;
    if(n>TCP_MSS)n=TCP_MSS;
    tcp_put_pkt(c,TCP_FLAG_ACK|TCP_FLAG_PSH,c->snd_nxt,c->rcv_nxt,
                c->sndb+in_flight,n);
    c->snd_nxt+=n;
    tcp_rto_arm(c);
}
int tcp_send(socket_t *s,const uint8_t *data,uint32_t len);
void tcp_close(socket_t *s);

socket_t *tcp_listen(uint16_t port){
    tcp_conn_t *c=tcp_conn_find_free();if(!c)return NULL;
    c->used=true;c->state=TCP_LISTEN;c->lport=port;c->peer_ip=0;c->peer_port=0;c->accepted=false;
    c->rxn=0;c->snd_used=0;c->snd_una=c->snd_nxt=c->snd_isn=0;c->rto_deadline=0;c->rto_backoff=0;c->tw_until=0;
    c->test_sent=false;c->test_closed=false;
    for(int i=0;i<TCP_MAX_CONNS;i++)if(!tcp_socks[i].type){tcp_socks[i].type=SOCK_TCP_LISTEN;tcp_socks[i].tcp.conn=c;break;}
    kputs("[NET] TCP listen :");kput_dec(port);kputs("\n");
    return &tcp_socks[0];
}

void tcp_handle(const uint8_t *seg,uint32_t seglen,uint32_t src_ip){
    if(seglen<20)return;
    const tcp_hdr_t *h=(const tcp_hdr_t*)seg;
    uint16_t sport=ntoh16(h->src_port),dport=ntoh16(h->dst_port);
    uint8_t flags=h->flags;
    uint32_t seq=ntoh32(h->seq),ack=ntoh32(h->ack_seq);
    uint32_t hlen=((h->off_res>>4)&0xf)*4;
    if(hlen<20||hlen>seglen)return;
    const uint8_t *data=seg+hlen;uint32_t dlen=seglen-hlen;

    /* 0. 找既有连接；没有则看 listen */
    tcp_conn_t *c=tcp_conn_find_peer(src_ip,sport);
    if(!c){
        tcp_conn_t *l=tcp_conn_find_listen(dport);
        if((flags&TCP_FLAG_SYN)&&l){
            c=tcp_conn_find_free();
            if(!c){kputs("[NET] TCP conn table full, RST\n");return;}
            c->used=true;c->state=TCP_SYN_RECEIVED;c->accepted=false;c->rxn=0;c->snd_used=0;
            c->test_sent=false;c->test_closed=false;
            c->lport=dport;c->peer_ip=src_ip;c->peer_port=sport;c->peer_win=ntoh16(h->window);
            c->rcv_isn=seq;c->rcv_nxt=seq+1;
            c->snd_isn=seq_gen++;c->snd_nxt=c->snd_isn+1;c->snd_una=c->snd_nxt;
            kputs("[NET] TCP SYN :");kput_dec(dport);kputs(" <- ");net_ip_print(src_ip);kputs(":");kput_dec(sport);kputs(" -> SYN-ACK\n");
            tcp_put_pkt(c,TCP_FLAG_SYNACK,c->snd_isn,c->rcv_nxt,NULL,0);
            tcp_rto_arm(c);                    /* SYN-ACK 需要重传保护 */
            return;
        }
        kputs("[NET] TCP :");kput_dec(dport);kputs(" no listener, RST\n");
        uint8_t dmac[6];if(arp_resolve(src_ip,dmac)){
            uint8_t *seg2=begin_ip(src_ip,IP_PROTO_TCP,dmac);if(seg2){
                tcp_hdr_t *t=(tcp_hdr_t*)seg2;
                t->src_port=hton16(dport);t->dst_port=hton16(sport);
                t->seq=hton32(seq+dlen);t->ack_seq=0;
                t->off_res=0x50;t->flags=TCP_FLAG_RST;t->window=0;t->csum=0;t->urgent=0;
                t->csum=hton16(ip_checksum_pseudo(g_ip,src_ip,IP_PROTO_TCP,20,seg2,20));
                end_ip(seg2,20,IP_PROTO_TCP);
            }
        }
        return;
    }

    /* 1. 记录对端窗口 */
    c->peer_win=ntoh16(h->window);

    /* 2. 通用 ACK 处理：推进 snd_una，回收发送缓冲（Linux tcp_ack） */
    if(flags&TCP_FLAG_ACK){
        if(ack>c->snd_una&&ack<=c->snd_nxt){
            uint32_t acked=ack-c->snd_una;
            if(acked>c->snd_used)acked=c->snd_used;
            c->snd_una=ack;
            if(acked){memcpy_u(c->sndb,c->sndb+acked,c->snd_used-acked);c->snd_used-=acked;}
            c->rto_backoff=0;                   /* 收到新 ACK，重置退避 */
            kputs("[NET] TCP ack=");kput_dec(ack);kputs(" una=");kput_dec(c->snd_una);kputs(" sndb=");kput_dec(c->snd_used);kputs("\n");
            tcp_xmit_pending(c);
            if(c->snd_nxt==c->snd_una)c->rto_deadline=0;
            else if(!c->rto_deadline)tcp_rto_arm(c);
        }
    }

    /* 3. RST 处理 */
    if(flags&TCP_FLAG_RST){kputs("[NET] TCP RST -> CLOSED\n");c->used=false;c->state=TCP_CLOSED;return;}

    /* 4. 按状态机推进 */
    switch(c->state){
    case TCP_SYN_RECEIVED:
        if((flags&TCP_FLAG_ACK)&&ack==c->snd_nxt){
            c->state=TCP_ESTABLISHED;
            c->rto_deadline=0;
            kputs("[NET] TCP ESTABLISHED ");net_ip_print(src_ip);kputs(":");kput_dec(sport);kputs("\n");
        }
        if(dlen){if(seq==c->rcv_nxt){if(c->rxn+dlen<=TCP_BUF_SIZE){memcpy_u(&c->rxb[c->rxn],data,dlen);c->rxn+=dlen;}c->rcv_nxt+=dlen;}tcp_put_pkt(c,TCP_FLAG_ACK,c->snd_nxt,c->rcv_nxt,NULL,0);}
        return;
    case TCP_ESTABLISHED:
    case TCP_FIN_WAIT_1:
    case TCP_FIN_WAIT_2:
    case TCP_CLOSE_WAIT:
    case TCP_CLOSING:
        if(dlen){
            if(seq==c->rcv_nxt){
                if(c->rxn+dlen<=TCP_BUF_SIZE){memcpy_u(&c->rxb[c->rxn],data,dlen);c->rxn+=dlen;}
                c->rcv_nxt+=dlen;
                kputs("[NET] TCP data ");kput_dec(dlen);kputs("B <- ");net_ip_print(src_ip);kputs("\n");
            }else{
                kputs("[NET] TCP out-of-order seq, re-ACK\n");
            }
            tcp_put_pkt(c,TCP_FLAG_ACK,c->snd_nxt,c->rcv_nxt,NULL,0);
        }
        if((flags&TCP_FLAG_FIN)&&seq+dlen==c->rcv_nxt){
            kputs("[NET] TCP FIN <- ");net_ip_print(src_ip);kputs("\n");
            c->rcv_nxt+=1;
            tcp_put_pkt(c,TCP_FLAG_ACK,c->snd_nxt,c->rcv_nxt,NULL,0);
            if(c->state==TCP_FIN_WAIT_1){ /* simultaneous close if our FIN is unacked */
                if(c->snd_una>=c->snd_nxt){
                    c->state=TCP_TIME_WAIT;c->tw_until=ticks+200;kputs("[NET] TCP TIME_WAIT entered\n");
                }else c->state=TCP_CLOSING;
            }else if(c->state==TCP_FIN_WAIT_2||c->state==TCP_CLOSING){
                c->state=TCP_TIME_WAIT;c->tw_until=ticks+200;kputs("[NET] TCP TIME_WAIT entered\n"); /* 2s */
            }else if(c->state==TCP_CLOSE_WAIT){ /* 已关过，忽略重复 FIN */
            }else{ /* ESTABLISHED：进 CLOSE_WAIT，应用 close 时发 FIN；无人接管则自动回关 */
                c->state=TCP_CLOSE_WAIT;
                tcp_put_pkt(c,TCP_FLAG_FINACK,c->snd_nxt,c->rcv_nxt,NULL,0);
                c->snd_nxt+=1;
                c->state=TCP_LAST_ACK;tcp_rto_arm(c);
                kputs("[NET] TCP FIN-ACK sent\n");
            }
            return;
        }
        if(flags&TCP_FLAG_FIN)tcp_put_pkt(c,TCP_FLAG_ACK,c->snd_nxt,c->rcv_nxt,NULL,0);
        /* 主动关闭方状态推进 */
        if(c->state==TCP_FIN_WAIT_1&&(flags&TCP_FLAG_ACK)&&c->snd_una>=c->snd_nxt){c->state=TCP_FIN_WAIT_2;c->rto_deadline=0;kputs("[NET] TCP FIN_WAIT_2\n");}
        if(c->state==TCP_CLOSING&&(flags&TCP_FLAG_ACK)&&c->snd_una>=c->snd_nxt){c->state=TCP_TIME_WAIT;c->tw_until=ticks+200;kputs("[NET] TCP TIME_WAIT entered\n");}
        return;
    case TCP_LAST_ACK:
        if((flags&TCP_FLAG_ACK)&&ack>=c->snd_nxt){
            kputs("[NET] TCP LAST_ACK done -> CLOSED\n");
            c->used=false;c->state=TCP_CLOSED;c->rto_deadline=0;
        }
        return;
    case TCP_TIME_WAIT:
        return;
    default:
        return;
    }
}

/* 每 tick 处理：RTO 重传 + TIME_WAIT 到期释放（Linux tcp_retransmit_timer 简化版） */
static void tcp_tick(void){
    for(int i=0;i<TCP_MAX_CONNS;i++){
        tcp_conn_t *c=&tcp_conns[i];if(!c->used)continue;
        if(c->state==TCP_TIME_WAIT){if(c->tw_until&&(int32_t)(ticks-c->tw_until)>=0){c->used=false;c->state=TCP_CLOSED;kputs("[NET] TCP TIME_WAIT expired\n");}continue;}
        if(c->state==TCP_ESTABLISHED&&c->lport==81){
            socket_t ts={SOCK_TCP_ESTAB,{.tcp={c}}};
            static const uint8_t test_data[]="TCP-RTO-REAL";
            if(!c->test_sent){
                int n=tcp_send(&ts,test_data,sizeof(test_data)-1);
                if(n==(int)(sizeof(test_data)-1)){c->test_sent=true;kputs("[NET] TCP test send 12B\n");}
            }else if(!c->test_closed&&c->snd_used==0&&c->snd_nxt==c->snd_una){
                tcp_close(&ts);c->test_closed=true;kputs("[NET] TCP test close requested\n");
            }
        }
        if(c->rto_deadline&&(int32_t)(ticks-c->rto_deadline)>=0){
            if(c->state==TCP_SYN_RECEIVED){
                kputs("[NET] TCP RTO: re-SYN-ACK\n");
                tcp_put_pkt(c,TCP_FLAG_SYNACK,c->snd_isn,c->rcv_nxt,NULL,0);
                tcp_rto_retry(c);
            }else if(c->state==TCP_LAST_ACK){
                kputs("[NET] TCP RTO: re-FIN\n");
                tcp_put_pkt(c,TCP_FLAG_FINACK,c->snd_nxt-1,c->rcv_nxt,NULL,0);
                tcp_rto_retry(c);
            }else if((c->state==TCP_FIN_WAIT_1||c->state==TCP_CLOSING)&&!c->snd_used){
                kputs("[NET] TCP RTO: re-FIN\n");
                tcp_put_pkt(c,TCP_FLAG_FINACK,c->snd_nxt-1,c->rcv_nxt,NULL,0);
                tcp_rto_retry(c);
            }else if(c->snd_used){
                uint32_t in_flight=c->snd_nxt-c->snd_una;
                if(in_flight>c->snd_used)in_flight=c->snd_used;
                kputs("[NET] TCP RTO: re-xmit ");kput_dec(in_flight);kputs("B\n");
                tcp_put_pkt(c,TCP_FLAG_ACK|TCP_FLAG_PSH,c->snd_una,c->rcv_nxt,c->sndb,in_flight);
                tcp_rto_retry(c);
            }else{
                c->rto_deadline=0;
            }
        }
    }
}

int tcp_accept(socket_t *s,uint32_t *remote_ip,uint16_t *remote_port){
    if(!s||s->type!=SOCK_TCP_LISTEN)return -1;
    uint16_t port=s->tcp.conn->lport;
    for(int i=0;i<TCP_MAX_CONNS;i++){
        tcp_conn_t *c=&tcp_conns[i];
        if(c->used&&c->state==TCP_ESTABLISHED&&c->lport==port&&!c->accepted){
            c->accepted=true;
            if(remote_ip)memcpy_u(remote_ip,&c->peer_ip,4);
            if(remote_port)*remote_port=c->peer_port;
            kputs("[NET] TCP accept ");net_ip_print(c->peer_ip);kputs(":");kput_dec(c->peer_port);kputs("\n");
            return 0;
        }
    }
    return -1;
}

int tcp_send(socket_t *s,const uint8_t *data,uint32_t len){
    if(!s||s->type!=SOCK_TCP_ESTAB)return -1;
    tcp_conn_t *c=s->tcp.conn;if(!c||c->state!=TCP_ESTABLISHED)return -1;
    if(len>1460)len=1460;
    if(len>TCP_BUF_SIZE-c->snd_used)len=TCP_BUF_SIZE-c->snd_used;
    if(len==0)return 0;
    memcpy_u(&c->sndb[c->snd_used],data,len);
    c->snd_used+=len;
    tcp_xmit_pending(c);
    return (int)len;
}

int tcp_recv(socket_t *s,uint8_t *buf,uint32_t max_len){
    if(!s||s->type!=SOCK_TCP_ESTAB)return -1;
    tcp_conn_t *c=s->tcp.conn;if(!c)return -1;
    if(c->rxn==0)return -1;
    uint32_t n=c->rxn;if(n>max_len)n=max_len;
    memcpy_u(buf,c->rxb,n);
    if(c->rxn>n)memcpy_u(c->rxb,c->rxb+n,c->rxn-n);
    c->rxn-=n;
    return (int)n;
}

void tcp_close(socket_t *s){
    if(!s)return;
    if(s->type==SOCK_TCP_ESTAB&&s->tcp.conn){
        tcp_conn_t *c=s->tcp.conn;
        if(c->state==TCP_ESTABLISHED){
            kputs("[NET] TCP close: FIN_WAIT_1\n");
            tcp_put_pkt(c,TCP_FLAG_FINACK,c->snd_nxt,c->rcv_nxt,NULL,0);
            c->snd_nxt+=1;
            c->state=TCP_FIN_WAIT_1;tcp_rto_arm(c);
        }else if(c->state==TCP_CLOSE_WAIT){
            kputs("[NET] TCP close: LAST_ACK\n");
            tcp_put_pkt(c,TCP_FLAG_FINACK,c->snd_nxt,c->rcv_nxt,NULL,0);
            c->snd_nxt+=1;
            c->state=TCP_LAST_ACK;tcp_rto_arm(c);
        }
    }
    s->type=SOCK_CLOSED;
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

void net_poll(void){e1000_poll();tcp_tick();if(dhcp_state!=DHCP_DONE&&dhcp_wait&&ticks-dhcp_last>=dhcp_wait*100u){dhcp_wait=0;if(dhcp_retries++>=6){net_set_ip(hton32(0x0A00020F));net_set_gateway(hton32(0x0A000202));net_set_subnet(hton32(0xFFFFFF00));dhcp_state=DHCP_DONE;kputs("[NET] DHCP failed, fallback static\n");}else{dhcp_xid^=(uint32_t)ip_id+0x9e3779b9u;dhcp_send(1);dhcp_state=DHCP_WAIT_OFFER;dhcp_wait=2;dhcp_last=ticks;}}}

void net_init(void){
    e1000_get_mac(g_mac);
    net_set_ip(0);net_set_gateway(0);net_set_subnet(0);
    kputs("[NET] up ip=");net_ip_print(g_ip);kputs(" gw=");net_ip_print(g_gw);kputs(" mask=");net_ip_print(g_mask);kputs("\n");
    /* 探测网关 MAC（无回应也不阻塞，收包路径会自行补缓存） */
    dhcp_xid=0x12340000u^ip_id;dhcp_retries=0;dhcp_wait=2;dhcp_state=DHCP_DISCOVER;dhcp_send(1);dhcp_last=ticks;dhcp_state=DHCP_WAIT_OFFER;
    /* 演示服务: TCP :80 监听 + UDP :7 echo; TCP :81 is acceptance-only. */
    tcp_listen(80);
    tcp_listen(81);
    udp_open(7);
}
