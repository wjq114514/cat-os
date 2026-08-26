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
static uint32_t g_dns;              /* resolver IPv4（网络序）：DHCP option 6 学得，
                                       无 DHCP 时 net_poll 回落 slirp 惯例 10.0.2.3 */
static uint16_t ip_id;
static uint32_t seq_gen=0x12340000; /* 本地 TCP ISN 生成器 */
static uint32_t dhcp_xid, dhcp_offer, dhcp_server, dhcp_mask, dhcp_gw;
static uint32_t dhcp_last, dhcp_wait;
static uint32_t dhcp_ciaddr;         /* 网络序：当前租约地址，RENEW/REBIND REQUEST 的 ciaddr */
static uint8_t dhcp_state, dhcp_retries;
/* 租约截止（绝对 ticks，比较一律 (int32_t)(ticks-due)>=0 回绕安全）；
 * dhcp_timed=false 表示无租期信息（option 51 缺失）——三截止不生效，
 * 维持旧 DHCP_DONE 死态语义。 */
static uint32_t dhcp_t1_due,dhcp_t2_due,dhcp_expire_due;
static bool dhcp_timed;
static bool ping_wait,ping_received;
static uint32_t ping_dst,ping_source,ping_rx_tick;
static uint16_t ping_id,ping_seq,ping_sent_count,ping_received_count;
/* 租约状态机（阶段5 第四棒，RFC 2131 §4.4.5 图 5 取下限）：
 *   DISCOVER→WAIT_OFFER→WAIT_ACK→BOUND --T1--> RENEWING(单播)
 *     --T2--> REBINDING(广播) --expire--> 清地址回 WAIT_OFFER；
 *   任一态收 NAK → 立即清地址回 WAIT_OFFER。
 *   DHCP_DONE 保留为「无租期信息/静态兜底」死态（旧语义，永不续期）。 */
#define DHCP_DISCOVER 1
#define DHCP_WAIT_OFFER 2
#define DHCP_WAIT_ACK 3
#define DHCP_DONE 4
#define DHCP_BOUND 5
#define DHCP_RENEWING 6
#define DHCP_REBINDING 7
/* dhcp_send 报文形态（RFC 2131 §4.4.5 表 4：REQUEST 按状态裁剪字段） */
#define DHCP_MODE_BOOT   0   /* DISCOVER / 首取 REQUEST：广播、ciaddr=0、REQUEST 带 54+50 */
#define DHCP_MODE_RENEW  1   /* RENEWING REQUEST：单播 server、带 ciaddr、无 54/50 */
#define DHCP_MODE_REBIND 2   /* REBINDING REQUEST：广播、带 ciaddr、无 54/50 */
#define DHCP_TICKS_PER_SEC   100u
#define DHCP_RETRY_BASE_SECS 2u    /* 重试初始等待（linux CONF_BASE_TIMEOUT=2s） */
#define DHCP_RETRY_CAP_SECS  30u   /* 退避封顶（linux CONF_TIMEOUT_MAX），×7/4 步进 */
/* ─── CATOS_DHCP_LEASE_SCALE（仅测试构建启用）───
 * slirp 默认租约 86400s，真实时间轴等 T1 不现实。测试构建加
 * -DCATOS_DHCP_LEASE_SCALE=<N>（N≥1）把「秒→ticks」换算除以 N，
 * 例 SCALE=1728000：86400s 租约 → 86400*100/1728000 = 5 ticks(50ms)，
 * T1≈22ms 即可在数秒内观察 BOUND→RENEWING→REBINDING→expire 全程。
 * 默认 1：换算恒为 secs*100 ticks，生产行为逐位不变。 */
#ifndef CATOS_DHCP_LEASE_SCALE
#define CATOS_DHCP_LEASE_SCALE 1
#endif
#if CATOS_DHCP_LEASE_SCALE < 1
#error "CATOS_DHCP_LEASE_SCALE must be >= 1"
#endif
void icmp_handle(const uint8_t *,uint32_t,uint32_t);
void udp_handle(const uint8_t *,uint32_t,uint32_t);
void tcp_handle(const uint8_t *,uint32_t,uint32_t);

/* ═══════════ 网络统计（阶段5 观测基建）═══════════
 * 字段布局/写上下文约束见 net.h struct net_stats 注释。 */
static struct net_stats g_net_stats;
#define NETSTAT_INC(f) (++g_net_stats.f)

/* ═══════════ ARP（阶段5 第三棒：老化/重试/失败回收）═══════════
 * 表项状态机（对照 linux-ref/net/ipv4/arp.c，取下限简化）：
 *   fresh   : now-seen_tick < REACH_TIMEOUT(30s)，命中直接用旧 MAC；
 *   stale   : seen 超 30s 未确认 —— arp_resolve 命中仍先用旧 MAC 保通路
 *             （返回值语义不变），异步补发一次确认 request（1s 节流）；
 *   probing : 补发计数 probes 1..PROBE_MAX(3)，间隔 ≥RETRANS(1s)；
 *   dropped : probes≥3 且末次探测 PROBE_TIMEOUT(3s) 无回应 → 回收+日志+计数。
 * 该 IP 任何 ARP 包到达（arp_handle 无条件 cache_add）即视为可达确认，
 * seen_tick 刷新、probes 清零回 fresh。stale 判定按 seen_tick 即时计算，
 * 不落存储；arp_tick 只做判死回收，O(8) 扫描，IRQ0(net_poll) 上下文安全。
 * 注：长期无人使用的 stale 项不主动回收（探测由 resolve 驱动），靠满表
 * 替换策略兜底 —— 与规划一致。 */
#define ARP_CACHE_MAX     8
#define ARP_REACH_TIMEOUT 3000u  /* 30s@100Hz 可达确认窗(BASE_REACHABLE_TIME/GC_STALETIME 下限) */
#define ARP_RETRANS_TICKS 100u   /* 1s@100Hz 同目标请求节流(RETRANS_TIME=1*HZ) */
#define ARP_PROBE_MAX     3      /* stale 确认探测上限 */
#define ARP_PROBE_TIMEOUT 300u   /* 末次探测后 3s 无回应判死 */
#define ARP_TICK_INTERVAL 100u   /* arp_tick 挂入 net_poll 的扫描周期 */
typedef struct {uint32_t ip;uint8_t mac[6];uint32_t seen_tick,req_tick;uint8_t probes;} arp_entry_t;
static arp_entry_t arp_cache[ARP_CACHE_MAX];
static uint8_t arp_cache_n;
static uint32_t arp_req_gate;        /* miss 路径(无表项)的请求节流闸 */
static uint32_t arp_scan_deadline;   /* arp_tick 周期调度 deadline(回绕安全) */

static void net_ip_print(uint32_t ip){uint8_t *b=(uint8_t*)&ip;for(int i=0;i<4;i++){kput_dec(b[i]);if(i<3)kputs(".");}}

static void arp_cache_fill(arp_entry_t *e,uint32_t ip,const uint8_t mac[6]){
    e->ip=ip;memcpy6(e->mac,mac);e->seen_tick=ticks;e->req_tick=ticks;e->probes=0;
}

static arp_entry_t *arp_lookup(uint32_t ip){
    for(int i=0;i<arp_cache_n;i++)if(arp_cache[i].ip==ip)return &arp_cache[i];
    return NULL;
}

static void arp_cache_del(int idx){
    for(int i=idx;i<(int)arp_cache_n-1;i++)arp_cache[i]=arp_cache[i+1];
    arp_cache_n--;
}

static void arp_cache_add(uint32_t ip,const uint8_t mac[6]){
    arp_entry_t *e=arp_lookup(ip);
    if(e){memcpy6(e->mac,mac);e->seen_tick=ticks;e->probes=0;return;}   /* 可达确认 → 回 fresh */
    if(arp_cache_n<ARP_CACHE_MAX)e=&arp_cache[arp_cache_n++];
    else{
        /* 满表替换：先扫过期(stale)项回收，无过期仍踢最旧(seen 最老，回绕安全比较) */
        e=NULL;
        for(int i=0;i<ARP_CACHE_MAX;i++)if((uint32_t)(ticks-arp_cache[i].seen_tick)>=ARP_REACH_TIMEOUT){e=&arp_cache[i];break;}
        if(!e){e=&arp_cache[0];for(int i=1;i<ARP_CACHE_MAX;i++)if((int32_t)(arp_cache[i].seen_tick-e->seen_tick)<0)e=&arp_cache[i];}
    }
    arp_cache_fill(e,ip,mac);
}

/* 组装并发送一帧 ARP 请求；返回 true=帧已提交 TX（供 stale 补发记账）。
 * 节流：同目标 1s 内至多一帧 —— 有表项记 req_tick（探测超时基准），
 * miss 走全局闸；仅提交成功才占用窗口。 */
static bool arp_request(uint32_t ip){
    arp_entry_t *e=arp_lookup(ip);
    uint32_t last=e?e->req_tick:arp_req_gate;
    if((uint32_t)(ticks-last)<ARP_RETRANS_TICKS)return false;
    uint8_t *p=e1000_tx_alloc();if(!p)return false;
    for(int i=0;i<6;i++){p[i]=0xFF;p[6+i]=g_mac[i];}
    uint16_t *w=(uint16_t*)p;w[6]=hton16(ETH_TYPE_ARP);
    arp_pkt_t *a=(arp_pkt_t*)(p+14);
    a->htype=hton16(1);a->ptype=hton16(0x0800);a->hlen=6;a->plen=4;a->op=hton16(ARP_OP_REQUEST);
    memcpy6(a->sha,g_mac);*(uint32_t*)a->spa=g_ip;memset6(a->tha);*(uint32_t*)a->tpa=ip;
    if(e1000_tx_submit(42)!=0)return false;
    if(e)e->req_tick=ticks;else arp_req_gate=ticks;
    NETSTAT_INC(arp_req_out);kputs("[NET] ARP who-has ");net_ip_print(ip);kputs("?\n");
    return true;
}

bool arp_resolve(uint32_t ip,uint8_t mac[6]){
    if(ip==0xFFFFFFFFu){memset6(mac);for(int i=0;i<6;i++)mac[i]=0xFF;return true;}
    arp_entry_t *e=arp_lookup(ip);
    if(e){
        /* 红线：命中一律 true（stale 亦先用旧 MAC 保通路）。stale 时异步补发
           一次确认 request（内部 1s 节流），probes 记账至 PROBE_MAX 为止；
           仅首次补发打印。 */
        if((uint32_t)(ticks-e->seen_tick)>=ARP_REACH_TIMEOUT&&e->probes<ARP_PROBE_MAX){
            bool sent=arp_request(ip);
            if(sent){
                if(e->probes==0){kputs("[NET] ARP stale ");net_ip_print(ip);kputs(", re-probing\n");}
                e->probes++;
            }
        }
        memcpy6(mac,e->mac);return true;
    }
    NETSTAT_INC(arp_resolve_miss);
    arp_request(ip);
    return false;
}

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
        NETSTAT_INC(arp_reply_in);
        kputs("[NET] ARP reply from ");net_ip_print(spa);kputs("\n");
    }
}

/* 老化扫描（每 ARP_TICK_INTERVAL 由 net_poll 挂入，PIT IRQ0 上下文）：
 * 仅判死回收 —— probes 用尽且末次探测后 PROBE_TIMEOUT 仍无任何包确认。
 * O(8) 扫描、零分配、日志单条。倒序遍历配合紧凑删除。 */
static void arp_tick(void){
    uint32_t now=ticks;
    for(int i=(int)arp_cache_n-1;i>=0;i--){
        arp_entry_t *e=&arp_cache[i];
        if((uint32_t)(now-e->seen_tick)<ARP_REACH_TIMEOUT)continue;   /* fresh */
        if(e->probes>=ARP_PROBE_MAX&&(uint32_t)(now-e->req_tick)>=ARP_PROBE_TIMEOUT){
            kputs("[NET] ARP entry dropped (probe timeout) ");net_ip_print(e->ip);kputs("\n");
            NETSTAT_INC(arp_entry_expired);
            arp_cache_del(i);
        }
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

/* ═══════════ ICMP ═══════════ */
void icmp_handle(const uint8_t *seg,uint32_t seglen,uint32_t src_ip){
    if(seglen<8)return;
    const icmp_hdr_t *ih=(const icmp_hdr_t*)seg;
    if(ip_checksum(seg,seglen)!=0)return;
    if(ih->type==ICMP_TYPE_ECHO_REPLY&&ping_wait&&src_ip==ping_dst&&ntoh16(ih->id)==ping_id&&ntoh16(ih->seq)==ping_seq){ping_source=src_ip;ping_rx_tick=ticks;ping_received=true;return;}
    if(ih->type!=ICMP_TYPE_ECHO_REQUEST||ih->code!=0)return;
    uint8_t dmac[6];if(!arp_resolve(src_ip,dmac))return;
    uint8_t *out=begin_ip(src_ip,IP_PROTO_ICMP,dmac);if(!out)return;
    memcpy_u(out,seg,seglen);
    icmp_hdr_t *r=(icmp_hdr_t*)out;
    r->type=ICMP_TYPE_ECHO_REPLY;r->code=0;r->csum=0;
    r->csum=hton16(ip_checksum(out,seglen));
    if(end_ip(out,seglen,IP_PROTO_ICMP)){NETSTAT_INC(icmp_echo_out);kputs("[NET] ICMP echo reply -> ");net_ip_print(src_ip);kputs(" (");kput_dec(seglen-8);kputs("B)\n");}
}

static uint32_t ping_putc(char *out,uint32_t cap,uint32_t n,char c){if(n<cap)out[n]=c;return n+1;}
static uint32_t ping_puts(char *out,uint32_t cap,uint32_t n,const char *s){while(*s)n=ping_putc(out,cap,n,*s++);return n;}
static uint32_t ping_putdec(char *out,uint32_t cap,uint32_t n,uint32_t v){char b[10];uint32_t i=0;if(!v)return ping_putc(out,cap,n,'0');while(v&&i<sizeof(b)){b[i++]=(char)('0'+v%10u);v/=10u;}while(i)n=ping_putc(out,cap,n,b[--i]);return n;}
static uint32_t ping_putip(char *out,uint32_t cap,uint32_t n,uint32_t ip){const uint8_t *b=(const uint8_t*)&ip;for(uint32_t i=0;i<4;i++){n=ping_putdec(out,cap,n,b[i]);if(i<3)n=ping_putc(out,cap,n,'.');}return n;}
static uint32_t ping_finish(char *out,uint32_t cap,uint32_t n){if(!cap)return 0;if(n>=cap)n=cap-1;out[n]='\0';return n;}

int net_ping(uint32_t dst,uint16_t id,uint16_t seq,char *out,uint32_t out_len){
    uint8_t packet[8];icmp_hdr_t *h=(icmp_hdr_t*)packet;uint32_t start=ticks,last_send=0xffffffffu;bool sent=false;
    for(uint32_t i=0;i<out_len;i++)out[i]='\0';
    h->type=ICMP_TYPE_ECHO_REQUEST;h->code=0;h->csum=0;h->id=hton16(id);h->seq=hton16(seq);h->csum=hton16(ip_checksum(packet,sizeof(packet)));
    __asm__ volatile("sti" ::: "memory");
    while(!g_ip&&(uint32_t)(ticks-start)<300u)net_poll();
    start=ticks;ping_wait=true;ping_received=false;ping_dst=dst;ping_id=id;ping_seq=seq;
    while((uint32_t)(ticks-start)<300u){
        if(!sent&&(last_send==0xffffffffu||(uint32_t)(ticks-last_send)>=25u)){if(ip_send(dst,IP_PROTO_ICMP,packet,sizeof(packet))){ping_sent_count++;sent=true;}last_send=ticks;}
        if(ping_received){uint32_t elapsed=(uint32_t)(ping_rx_tick-start),n=0;n=ping_puts(out,out_len,n,"ping reply from ");n=ping_putip(out,out_len,n,ping_source);n=ping_puts(out,out_len,n," seq=");n=ping_putdec(out,out_len,n,seq);n=ping_puts(out,out_len,n," time=");n=ping_putdec(out,out_len,n,elapsed*10u);n=ping_puts(out,out_len,n,"ms\n");n=ping_finish(out,out_len,n);ping_received_count++;ping_wait=false;__asm__ volatile("cli" ::: "memory");kputs("[PING] reply from ");net_ip_print(ping_source);kputs(" seq=");kput_dec(seq);kputs(" time=");kput_dec(elapsed*10u);kputs("ms\n");return (int)n;}
        net_poll();
    }
    __asm__ volatile("cli" ::: "memory");ping_wait=false;uint32_t n=0;n=ping_puts(out,out_len,n,"ping timeout seq=");n=ping_putdec(out,out_len,n,seq);n=ping_puts(out,out_len,n,"\n");n=ping_finish(out,out_len,n);kputs("[PING] timeout seq=");kput_dec(seq);kputs("\n");return (int)n;
}
int net_ping_stats(char *out,uint32_t out_len){for(uint32_t i=0;i<out_len;i++)out[i]='\0';uint32_t loss=ping_sent_count?((uint32_t)(ping_sent_count-ping_received_count)*100u/ping_sent_count):100u,n=0;n=ping_puts(out,out_len,n,"--- ping statistics ---\n");n=ping_putdec(out,out_len,n,ping_sent_count);n=ping_puts(out,out_len,n," packets transmitted, ");n=ping_putdec(out,out_len,n,ping_received_count);n=ping_puts(out,out_len,n," received, ");n=ping_putdec(out,out_len,n,loss);n=ping_puts(out,out_len,n,"% packet loss\n");return (int)ping_finish(out,out_len,n);}

/* ═══════════ UDP ═══════════ */
#define UDP_SLOTS 8
#define UDP_RXBUF 2048
typedef struct {
    bool used,bound,owned;
    uint16_t lport;
    uint8_t rxb[UDP_RXBUF];      /* 线性包队列: [pkt_len(4)][src_ip(4)][sport(2)]payload... */
    uint32_t head,n;
} udp_sock_t;
static udp_sock_t udp_socks[UDP_SLOTS];
static socket_t udp_handles[UDP_SLOTS];
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

/* 秒→ticks（CATOS_DHCP_LEASE_SCALE 用法见定义处注释）。先乘后除保精度，
 * 上限钳制防 *100 回绕。SCALE=1 时编译器折叠为 secs*100，逐位等价旧换算。 */
static uint32_t dhcp_secs_to_ticks(uint32_t secs){
    if(secs>42949672u)secs=42949672u;
    return secs*(uint32_t)DHCP_TICKS_PER_SEC/(uint32_t)CATOS_DHCP_LEASE_SCALE;
}

/* ACK 落地租约：T1/T2 缺省 0.5·/0.875·lease（RFC 2131 §4.4.5）；
 * 服务端越界值（t1>t2、t2>lease）钳制；极短租期保证单调推进。
 * lease==0（option 51 缺失）→ dhcp_timed=false 维持死态语义。 */
static void dhcp_arm_lease(uint32_t lease_s,uint32_t t1_s,uint32_t t2_s){
    uint32_t lt,now=ticks,r1,r2;
    if(!lease_s){dhcp_timed=false;return;}   /* option 51 缺失 → 不挂截止 */
    lt=dhcp_secs_to_ticks(lease_s);
    if(!lt)lt=1;                             /* 大 SCALE 下四舍入零：按最短 1 tick 计 */
    r1=t1_s?dhcp_secs_to_ticks(t1_s):lt/2u;
    r2=t2_s?dhcp_secs_to_ticks(t2_s):lt-lt/8u;
    if(r2>lt)r2=lt;
    if(!r2)r2=1;
    if(r1>r2)r1=r2;
    if(!r1)r1=1;
    dhcp_t1_due=now+r1;dhcp_t2_due=now+r2;dhcp_expire_due=now+lt;
    dhcp_timed=true;
}

/* 续期重试退避步进：×7/4 封顶 30s（评审节奏，对照 linux ipconfig 指数退避）。
 * 仅用于 RENEWING/REBINDING；首取重试保持既有固定 2s 不动 —— fallback
 * 到达时刻（7×2s≈14s）是 tests/inject 套件的隐式预算，不得推迟。 */
static uint32_t dhcp_backoff_next(uint32_t w){
    w=w*7u/4u;
    if(w>DHCP_RETRY_CAP_SECS)w=DHCP_RETRY_CAP_SECS;
    return w;
}

/* mode 语义见 DHCP_MODE_*：BOOT 广播+ciaddr=0（首取路径逐字节不变）；
 * RENEW 单播 dhcp_server+ciaddr；REBIND 广播+ciaddr。
 * option 54(server-id)/50(requested-ip) 仅首取 REQUEST 携带（RFC 2131 §4.4.5 表 4）；
 * RENEW/REBIND 靠 ciaddr 标识租约。报文长度与 pad 布局保持 548B 不变。 */
static void dhcp_send(uint8_t type,uint8_t mode){
    uint8_t b[548],*o;                           /* 对齐 Linux bootp_pkt: 236 固定 + exten[312]，RFC2131 最小 300B */
    for(uint32_t i=0;i<548;i++)b[i]=0;
    b[0]=1;b[1]=1;b[2]=6;b[3]=0;*(uint32_t*)(b+4)=hton32(dhcp_xid);
    *(uint16_t*)(b+8)=0;*(uint16_t*)(b+10)=hton16(0x8000);memcpy_u(b+28,g_mac,6);
    if(mode!=DHCP_MODE_BOOT)*(uint32_t*)(b+12)=dhcp_ciaddr;   /* ciaddr（RENEW/REBIND） */
    o=b+236;o[0]=99;o[1]=130;o[2]=83;o[3]=99;o+=4;o[0]=53;o[1]=1;o[2]=type;o+=3;
    if(type==3&&mode==DHCP_MODE_BOOT){o[0]=54;o[1]=4;memcpy_u(o+2,&dhcp_server,4);o+=6;o[0]=50;o[1]=4;memcpy_u(o+2,&dhcp_offer,4);o+=6;}
    o[0]=55;o[1]=3;o[2]=1;o[3]=3;o[4]=6;o+=5;o[0]=255;
    if(mode==DHCP_MODE_RENEW)udp_send(dhcp_server,67,68,b,548);   /* 续租单播到 server */
    else udp_send(0xFFFFFFFFu,67,68,b,548);                        /* BOOT/REBIND 广播 */
    kputs("[NET] DHCP ");kputs(type==1?"DISCOVER\n":mode==DHCP_MODE_RENEW?"REQUEST(renew)\n":mode==DHCP_MODE_REBIND?"REQUEST(rebind)\n":"REQUEST\n");
}

/* 租约到期统一出口：清地址回 DISCOVER，重试计数清零后由既有
 * 「6 次失败→静态兜底」机器接管无服务场景。 */
static void dhcp_lease_expired(void){
    kputs("[NET] DHCP lease expired, rediscover\n");
    net_set_ip(0);net_set_gateway(0);net_set_subnet(0);g_dns=0;
    dhcp_ciaddr=0;dhcp_offer=0;dhcp_timed=false;dhcp_retries=0;
    dhcp_xid^=(uint32_t)ip_id+0x9e3779b9u;
    dhcp_state=DHCP_WAIT_OFFER;dhcp_wait=DHCP_RETRY_BASE_SECS;dhcp_last=ticks;
    dhcp_send(1,DHCP_MODE_BOOT);
}

static void dhcp_handle(const uint8_t *d,uint32_t n){
    if(n<240||d[0]!=2||d[1]!=1||d[2]!=6||ntoh32(*(const uint32_t*)(d+4))!=dhcp_xid)return;
    if(d[28]!=g_mac[0]||d[29]!=g_mac[1]||d[30]!=g_mac[2]||d[31]!=g_mac[3]||d[32]!=g_mac[4]||d[33]!=g_mac[5])return;
    if(d[236]!=99||d[237]!=130||d[238]!=83||d[239]!=99)return;
    uint8_t mt=0;uint32_t opt51=0,opt58=0,opt59=0;   /* option 51=lease(s) 58=T1(s) 59=T2(s)，均 4B 网络序 */
    uint32_t i=240;while(i<n&&d[i]!=255){if(d[i]==0){i++;continue;}if(i+1>=n||i+2+d[i+1]>n)break;uint8_t l=d[i+1];if(d[i]==53&&l)mt=d[i+2];else if(d[i]==51&&l==4){uint32_t v;memcpy_u(&v,d+i+2,4);opt51=ntoh32(v);}else if(d[i]==58&&l==4){uint32_t v;memcpy_u(&v,d+i+2,4);opt58=ntoh32(v);}else if(d[i]==59&&l==4){uint32_t v;memcpy_u(&v,d+i+2,4);opt59=ntoh32(v);}else if(d[i]==54&&l==4)memcpy_u(&dhcp_server,d+i+2,4);else if(d[i]==1&&l==4)memcpy_u(&dhcp_mask,d+i+2,4);else if(d[i]==3&&l>=4)memcpy_u(&dhcp_gw,d+i+2,4);else if(d[i]==6&&l==4)memcpy_u(&g_dns,d+i+2,4);i+=2+l;}
    if(mt==6){   /* NAK：任意态立即弃约重来（RFC 2131 §4.3.1）；清地址后走全新 DISCOVER，
                    计数清零，无服务场景仍由「6 次失败→静态兜底」兜住 */
        kputs("[NET] DHCP NAK, restart\n");
        net_set_ip(0);net_set_gateway(0);net_set_subnet(0);g_dns=0;
        dhcp_ciaddr=0;dhcp_offer=0;dhcp_timed=false;dhcp_retries=0;
        dhcp_xid^=(uint32_t)ip_id+0x9e3779b9u;
        dhcp_state=DHCP_WAIT_OFFER;dhcp_wait=DHCP_RETRY_BASE_SECS;dhcp_last=ticks;
        dhcp_send(1,DHCP_MODE_BOOT);
        return;
    }
    if(mt==2&&dhcp_state==DHCP_WAIT_OFFER){dhcp_offer=*(const uint32_t*)(d+16);dhcp_state=DHCP_WAIT_ACK;dhcp_send(3,DHCP_MODE_BOOT);dhcp_last=ticks;dhcp_wait=DHCP_RETRY_BASE_SECS;return;}
    if(mt==5&&(dhcp_state==DHCP_WAIT_ACK||dhcp_state==DHCP_RENEWING||dhcp_state==DHCP_REBINDING)){
        bool renewing=(dhcp_state!=DHCP_WAIT_ACK);
        dhcp_offer=*(const uint32_t*)(d+16);
        dhcp_ciaddr=dhcp_offer;   /* 后续 RENEW/REBIND 的 ciaddr（RFC §4.4.5 表 4） */
        net_set_ip(dhcp_offer);net_set_gateway(dhcp_gw);net_set_subnet(dhcp_mask);
        dhcp_arm_lease(opt51,opt58,opt59);
        if(renewing){kputs("[NET] DHCP ACK renew ip=");net_ip_print(g_ip);kputs("\n");}
        else{kputs("[NET] DHCP ACK ip=");net_ip_print(g_ip);kputs(" gw=");net_ip_print(g_gw);kputs(" mask=");net_ip_print(g_mask);kputs("\n");}
        /* 无租期信息（option 51 缺失）→ 维持旧 DONE 死态，不挂截止 */
        dhcp_state=dhcp_timed?DHCP_BOUND:DHCP_DONE;
        return;
    }
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
        NETSTAT_INC(udp_no_listener);
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
    else NETSTAT_INC(rx_drop_full);
    kputs("[NET] UDP :");kput_dec(dport);kputs(" <- ");net_ip_print(src_ip);kputs(":");kput_dec(sport);kputs(" ");kput_dec(dlen);kputs("B\n");
}

/* ═══════════ DNS 最小解析器（阶段5 第二棒）═══════════
 * 报文布局（RFC 1035 §4.1）:
 *   头 12B: ID(2) FLAGS(2: QR|Opcode|AA|TC|RD|RA|Z|RCODE) QDCOUNT(2)
 *           ANCOUNT(2) NSCOUNT(2) ARCOUNT(2)
 *   Question: QNAME(标签序列 05hello03com00) QTYPE(2=1 A) QCLASS(2=1 IN)
 *   Answer:   NAME TYPE CLASS TTL(4) RDLENGTH RDATA
 * 解析方向支持 RFC 1035 §4.1.4 名字解压缩：现实 resolver（含 slirp）应答
 * 必用压缩指针（如 owner=0xC00C 指回 Question），不支持则解析器不可用。
 * 压缩处理带三重护栏（只准回头 / 跳数上限 / 总消耗上限），见 dns_read_name()；
 * 查询发送侧仍为纯字面量标签名。
 * 轮询模型照抄 net_ping()：sti 进环、总超时 300 ticks、每 25 ticks 重发。 */
#define DNS_PORT          53u
#define DNS_QTYPE_A       1u
#define DNS_QCLASS_IN     1u
#define DNS_NAME_MAX      64u     /* 输入域名长度上限 */
#define DNS_QNAME_CAP     80u     /* 编码域名缓冲上限（含根终止 0，栈上 ≤80B 红线） */
#define DNS_TOTAL_TIMEOUT 300u    /* ticks @100Hz */
#define DNS_RESEND_TICKS  25u     /* 重发节拍（同 net_ping） */
#define DNS_CNAME_MAX     4u      /* CNAME 链最大跳数（跨重发查询累计） */
#define DNS_NAME_PTR_MAX  8u      /* 压缩指针跳转上限（环护栏之二） */
/* 错误码契约见 net.h（NETDNS_E*，与函数声明同处） */

/* RFC 1035 §4.1.4 名字读取/解压缩（仅解析方向）。从 msg[*off] 起读一个域名。
 * 字面量标签照常；前两 bit=11 为压缩指针，低 14 位为报文内偏移；
 * 0x40/0x80 前缀类别保留未用，一律判格式错误。安全护栏：
 *   1) 指针目标必须落在 [12, 当前指针位置) —— 报文头之后、指针自身之前，
 *      结构上排除前向引用与自指（每跳位置严格递减，环在数学上不可达）；
 *   2) 跳转次数上限 DNS_NAME_PTR_MAX；
 *   3) 全程消耗字节上限 = 报文长度 n；
 *   4) 所有数组访问先比边界，任何越界/畸形返回 false（fail-closed）。
 * 成功时 *off 推进到该名字在本报文字节流中的结束处（若从未进入指针区，
 * 即首个终止 0 或首指针之后——对调用者恒为"下一条目起点"）。
 * out!=NULL 时把解压结果（纯字面量标签序列 + 终止 0，与查询编码同构）
 * 写入 out 至多 cap 字节，*dlen（可空）回写解压后字节数。 */
static bool dns_read_name(const uint8_t *msg,uint32_t n,uint32_t *off,
                          uint8_t *out,uint32_t cap,uint32_t *dlen){
    uint32_t p=*off,jumps=0,used=0,ol=0;bool jumped=false;
    for(;;){
        if(p>=n)return false;                   /* 名字越过报文尾 */
        uint8_t l=msg[p];
        if(l==0){                               /* 终止 0 */
            if(out){if(ol+1>cap)return false;out[ol]=0;}
            if(dlen)*dlen=ol+1;                 /* 含终止 0，与查询编码 np 同语义 */
            if(!jumped)*off=p+1;
            return true;
        }
        if((l&0xC0)==0xC0){                     /* 压缩指针 */
            if(p+2>n)return false;              /* 指针第二字节越界 */
            uint32_t tgt=((uint32_t)(l&0x3F)<<8)|msg[p+1];
            if(tgt<12||tgt>=p)return false;     /* 只准回头：头之后、指针之前 */
            if(++jumps>DNS_NAME_PTR_MAX)return false;
            used+=2;if(used>n)return false;     /* 总消耗上限=报文长度 */
            if(!jumped)*off=p+2;                /* 流内终点=首个指针之后 */
            p=tgt;jumped=true;
            continue;
        }
        if(l&0xC0)return false;                 /* 0x40/0x80：保留类别拒绝 */
        if(l>=n-p)return false;                 /* 标签体越过报文尾 */
        if(out){
            if(ol+1u+l>cap)return false;        /* 解压输出越缓冲上限 */
            out[ol]=(uint8_t)l;memcpy_u(out+ol+1,msg+p+1,l);ol+=1u+l;
        }
        used+=1u+l;if(used>n)return false;
        p+=1u+l;
    }
}

int net_dns_resolve(const char *name,uint32_t *out_ip){
    if(!name||!out_ip)return NETDNS_EARGS;
    if(!g_dns)return NETDNS_ENORESOLVER;
    uint8_t pkt[12+DNS_QNAME_CAP+4];        /* 头+编码域名+QTYPE/QCLASS 单缓冲 */
    for(uint32_t i=0;i<sizeof(pkt);i++)pkt[i]=0;
    seq_gen+=0x9e3779b9u;                   /* txid 由 ISN 生成器派生 */
    uint16_t txid=(uint16_t)(seq_gen>>16);
    pkt[0]=(uint8_t)(txid>>8);pkt[1]=(uint8_t)txid; /* [FIX] 事务 ID 必须写入报文头：
        旧版仅派生 txid 用于收包过滤却从未上线，查询恒以 ID=0x0000 发出，
        应答被 id!=txid 过滤全部丢弃 → 恒 -110 超时（shell-wire 反汇编实证） */
    pkt[2]=0x01;pkt[5]=1;                   /* RD=1, QDCOUNT=1 */
    uint32_t np=12,labpos=0;
    for(uint32_t i=0;;i++){
        char c=name[i];
        if(c!='\0'&&i>=DNS_NAME_MAX)return NETDNS_EARGS;
        if(c=='.'||c=='\0'){
            uint32_t llen=i-labpos;
            if(llen==0||llen>63)return NETDNS_EARGS;         /* 空/超长标签 */
            if(np+1+llen>12+DNS_QNAME_CAP-1)return NETDNS_EARGS; /* 编码区上限 */
            pkt[np]=(uint8_t)llen;memcpy_u(pkt+np+1,name+labpos,llen);np+=1+llen;
            if(c=='\0')break;
            labpos=i+1;
        }else{
            bool ok=(c>='0'&&c<='9')||(c>='a'&&c<='z')||(c>='A'&&c<='Z')||c=='-';
            if(!ok)return NETDNS_EARGS;                      /* 标签字符白名单 */
        }
    }
    if(np==12)return NETDNS_EARGS;          /* 空名 */
    pkt[np++]=0;                            /* 根终止 */
    pkt[np]=0;pkt[np+1]=(uint8_t)DNS_QTYPE_A;pkt[np+3]=(uint8_t)DNS_QCLASS_IN;
    uint16_t qlen=(uint16_t)(np+4);
    /* 临时端口 + 内部直取 UDP 槽（不经 udp_open 免日志噪音）；语义同其内部赋值 */
    udp_sock_t *us=NULL;uint16_t lport=0;
    for(uint32_t t=0;t<4&&!us;t++){
        uint16_t p=(uint16_t)(0xC000u+((txid+t*97u)&0x1FFFu)); /* 49152..53247 临时段 */
        if(p==67||p==68||udp_sock_by_port(p))continue;
        us=udp_sock_find_free();if(us){us->used=true;us->bound=true;us->owned=false;us->lport=p;us->head=us->n=0;lport=p;}
    }
    if(!us)return NETDNS_ENORESOLVER;
    socket_t ts;ts.type=SOCK_UDP;ts.udp.lport=lport;ts.udp.slot=(uint8_t)(us-udp_socks);ts.udp.owned=0;
    /* 失败归因：串口日志与错误码共用；TO=超时，其余映射见函数尾 */
    enum { DNS_TO,DNS_FMT,DNS_RCODE,DNS_TRUNC,DNS_CNAME,DNS_NOA } cause=DNS_TO;
    static const char *const dns_reasons[]={"timeout","format","rcode","truncated","cname depth","no A record"};
    uint32_t rcode=0,ip=0,cn_hops=0;bool got=false;
    __asm__ volatile("sti" ::: "memory");
    uint32_t start=ticks;
    while(!g_ip&&(uint32_t)(ticks-start)<DNS_TOTAL_TIMEOUT)net_poll();   /* 等 DHCP 就绪（同 net_ping） */
    start=ticks;uint32_t last_send=0xFFFFFFFFu;
    uint8_t rxb[512];                        /* 经典 UDP DNS 上限 512B */
    while((uint32_t)(ticks-start)<DNS_TOTAL_TIMEOUT){
        if(last_send==0xFFFFFFFFu||(uint32_t)(ticks-last_send)>=DNS_RESEND_TICKS){
            (void)udp_send(g_dns,(uint16_t)DNS_PORT,lport,pkt,qlen);last_send=ticks;}
        for(;;){
            uint32_t sip;uint16_t sport;
            int n=udp_recvfrom(&ts,&sip,&sport,rxb,sizeof(rxb));
            if(n<0)break;
            if(n<12)continue;               /* 截断头：当垃圾丢弃 */
            uint32_t rn=(uint32_t)n;        /* 此处起 n∈[12,512]，转无符号免符号比较 */
            uint16_t id=(uint16_t)((rxb[0]<<8)|rxb[1]);
            if(id!=txid)continue;           /* 重发残留/无关包 */
            uint16_t flags=(uint16_t)((rxb[2]<<8)|rxb[3]);
            if(!(flags&0x8000))continue;    /* QR=0 非响应 */
            if(flags&0x000F){rcode=(uint32_t)(flags&0xF);cause=DNS_RCODE;break;}
            if(flags&0x0200){cause=DNS_TRUNC;break;}
            uint32_t qd=((uint32_t)rxb[4]<<8)|rxb[5],an=((uint32_t)rxb[6]<<8)|rxb[7];
            uint32_t off=12,last_cn=0xFFFFFFFFu;bool fmt=false;
            for(uint32_t q=0;q<qd;q++){if(dns_read_name(rxb,rn,&off,NULL,0,NULL)&&off+4<=rn)off+=4;else{fmt=true;break;}}
            for(uint32_t a=0;a<an&&!fmt;a++){
                if(!dns_read_name(rxb,rn,&off,NULL,0,NULL)){fmt=true;break;}
                if(off+10>rn){fmt=true;break;}
                uint16_t type=(uint16_t)((rxb[off]<<8)|rxb[off+1]);
                uint16_t cls=(uint16_t)((rxb[off+2]<<8)|rxb[off+3]);
                uint16_t rdlen=(uint16_t)((rxb[off+8]<<8)|rxb[off+9]);
                off+=10;
                if(off+rdlen>rn){fmt=true;break;}
                if(cls==(uint16_t)DNS_QCLASS_IN&&type==(uint16_t)DNS_QTYPE_A&&rdlen==4){memcpy_u(&ip,rxb+off,4);got=true;break;}
                if(type==(uint16_t)5&&rdlen){   /* CNAME rdata=域名（可压缩）：
                        先试解校验其确为合法名字且恰占 rdlen 字节，合格才留作重查目标 */
                    uint32_t probe=off;
                    if(dns_read_name(rxb,rn,&probe,NULL,0,NULL)&&probe-off==rdlen)last_cn=off;
                }
                off+=rdlen;
            }
            if(fmt&&cause==DNS_TO)cause=DNS_FMT;
            if(got||fmt)break;
            if(an){
                if(last_cn==0xFFFFFFFFu){cause=DNS_NOA;break;}  /* 应答走完：无 A 亦无可信 CNAME */
                if(cn_hops>=DNS_CNAME_MAX){cause=DNS_CNAME;break;} /* CNAME 链 >4 跳 */
                uint32_t roff=last_cn,olen=0;
                /* 解压 CNAME 目标直接覆写查询包 QNAME 区（容量同查询编码上限，
                 * dns_read_name 越界即格式错）；A 记录 rdata 定长 4B 不涉及名字 */
                if(!dns_read_name(rxb,rn,&roff,pkt+12,DNS_QNAME_CAP,&olen)||olen<2){cause=DNS_FMT;break;}
                cn_hops++;
                pkt[12+olen]=0;pkt[13+olen]=(uint8_t)DNS_QTYPE_A;   /* QTYPE=A(1) */
                pkt[14+olen]=0;pkt[15+olen]=(uint8_t)DNS_QCLASS_IN; /* QCLASS=IN(1) */
                qlen=(uint16_t)(16+olen);
                seq_gen+=0x9e3779b9u;txid=(uint16_t)(seq_gen>>16); /* 新 txid：旧查询残留应答被 id 过滤丢弃 */
                pkt[0]=(uint8_t)(txid>>8);pkt[1]=(uint8_t)txid;
                last_send=0xFFFFFFFFu;          /* 回外层循环立即发送新查询 */
                break;
            }
            break;                          /* an==0 合规空响应：继续等重发 */
        }
        if(got||cause!=DNS_TO)break;
        net_poll();
    }
    __asm__ volatile("cli" ::: "memory");
    us->used=false;us->bound=false;           /* 归还临时槽位 */
    if(got){
        kputs("[NET] DNS ");kputs(name);kputs(" -> ");net_ip_print(ip);kputs("\n");
        *out_ip=ip;                           /* 仅成功时写 */
        return 0;
    }
    kputs("[NET] DNS ");kputs(name);kputs(" fail (");kputs(dns_reasons[cause]);
    if(cause==DNS_RCODE){kputs("=");kput_dec(rcode);}
    kputs(")\n");
    return cause==DNS_TO?NETDNS_ETIMEOUT:cause==DNS_RCODE?NETDNS_EREFUSED:NETDNS_EARGS;
}

socket_t *udp_open(uint16_t lport){
    udp_sock_t *s=udp_sock_find_free();if(!s)return NULL;
    s->used=true;s->bound=true;s->owned=false;s->lport=lport;s->head=s->n=0;
    socket_t *sock=&udp_handles[s-udp_socks];
    sock->type=SOCK_UDP;sock->udp.lport=lport;sock->udp.slot=(uint8_t)(s-udp_socks);sock->udp.owned=0;
    kputs("[NET] UDP socket open :");kput_dec(lport);kputs("\n");
    return sock;
}

int udp_sendto(socket_t *s,uint32_t dst_ip,uint16_t dst_port,const uint8_t *data,uint32_t len){
    if(!s||s->type!=SOCK_UDP)return -1;
    if(len>1472)return -1;
    return udp_send(dst_ip,dst_port,s->udp.lport,data,len)?0:-1;
}

int udp_recvfrom(socket_t *s,uint32_t *src_ip,uint16_t *src_port,uint8_t *buf,uint32_t max_len){
    if(!s||s->type!=SOCK_UDP)return -1;
    udp_sock_t *u=(s->udp.owned&&s->udp.slot<UDP_SLOTS)?&udp_socks[s->udp.slot]:udp_sock_by_port(s->udp.lport);if(!u||u->n==0)return -1;
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
    struct { uint32_t seq; uint16_t len; bool used; uint8_t data[TCP_MSS]; } ooo[4];
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
} tcp_conn_t;
static tcp_conn_t tcp_conns[TCP_MAX_CONNS];
static socket_t  tcp_socks[TCP_MAX_CONNS];
static socket_t  tcp_handles[TCP_MAX_CONNS];
static tcp_conn_t *tcp_conn_find_listen(uint16_t port);
static void tcp_drop_pending(uint16_t port);
static void tcp_cc_init(tcp_conn_t *c);
static bool tcp_seq_after(uint32_t a,uint32_t b){return (int32_t)(a-b)>0;}
static bool tcp_seq_before(uint32_t a,uint32_t b){return (int32_t)(a-b)<0;}
static bool tcp_put_pkt(tcp_conn_t *c,uint8_t flags,uint32_t seq,uint32_t ack,const uint8_t *data,uint32_t dlen); /* 问题1[HIGH]: 改为返回发送成败 */
static void tcp_rto_rearm(tcp_conn_t *c);
static void tcp_parse_opts(tcp_conn_t *c,const uint8_t *opt,uint32_t n,bool syn){
    while(n){uint8_t kind=opt[0];if(kind==0)break;if(kind==1){opt++;n--;continue;}if(n<2||opt[1]<2||opt[1]>n)break;
        uint8_t olen=opt[1];
        if(kind==4&&olen==2&&syn)c->sack_ok=true;
        if(kind==2&&olen==4&&syn){
            /* 阶段3 MSS/窗口边界：记录对端宣告 MSS（RFC 9293 §3.7.1：
             * "the other side should send no segments larger than the
             * advertised value"）。0 值非法（RFC 793 规定 MSS 选项最小
             * 合法值 1），忽略之。发送侧 clamp 见 tcp_xmit_pending()。 */
            uint16_t m=ntoh16(*(const uint16_t*)(opt+2));
            if(m)c->peer_mss=m;
        }
        if(kind==5&&!syn&&c->sack_ok&&olen>=10&&((olen-2u)&7u)==0){
            /* RFC 2018 §3 块布局；RFC 6675 §6.2：校验并裁剪到本端发送窗口。 */
            uint32_t count=(olen-2u)/8u;
            c->sack_n=0;
            for(uint32_t i=0;i<count&&c->sack_n<2;i++){
                uint32_t l,r;bool dup=false;
                memcpy_u(&l,opt+2+i*8,4);memcpy_u(&r,opt+6+i*8,4);
                l=ntoh32(l);r=ntoh32(r);
                if(!tcp_seq_before(l,r))continue;             /* 逆序/空块 */
                if(tcp_seq_after(r,c->snd_nxt))continue;      /* 越过发送前沿 */
                if(tcp_seq_before(r,c->snd_una))continue;     /* 完全过期(DSACK 区间) */
                if(tcp_seq_before(l,c->snd_una))l=c->snd_una; /* 前缘裁剪到 snd_una */
                for(uint32_t j=0;j<c->sack_n;j++)if(c->sack_left[j]==l&&c->sack_right[j]==r){dup=true;break;}
                if(dup)continue;                              /* 同一报文内重复块不重复登记 */
                c->sack_left[c->sack_n]=l;c->sack_right[c->sack_n++]=r;
            }
        }
        opt+=olen;n-=olen;
    }
}
static uint32_t tcp_sack_blocks(tcp_conn_t *c){uint32_t n=0;for(int i=0;i<4;i++)if(c->ooo[i].used)n++;return n>2?2:n;}
static uint32_t tcp_build_opts(tcp_conn_t *c,uint8_t *o,uint8_t flags){
    uint32_t n=0;
    if(flags&TCP_FLAG_SYN){
        /* MSS 选项（kind=2,len=4,值1460）：此前本端从不宣告 MSS，对端只能按
         * RFC 793 默认 536B 假设（真实链路下浪费带宽），且无从约束其对我们的
         * 分段尺寸。现随 SYN/SYN-ACK 宣告本机 MSS（RFC 9293 §3.7.1）。
         * 与 SACK-permitted 同发时共 8B，off_res 由 tcp_put_pkt 按 olen 统一
         * 计算，20+8=28 ≤ 60 上限。 */
        o[n++]=2;o[n++]=4;o[n++]=(uint8_t)(TCP_MSS>>8);o[n++]=(uint8_t)TCP_MSS;
    }
    if((flags&TCP_FLAG_SYN)&&c->sack_ok){o[n++]=1;o[n++]=1;o[n++]=4;o[n++]=2;}
    else if((flags&TCP_FLAG_ACK)&&c->sack_ok){uint32_t blocks=tcp_sack_blocks(c);if(blocks){o[n++]=1;o[n++]=1;o[n++]=5;o[n++]=(uint8_t)(2+8*blocks);for(int i=0;i<4&&blocks;i++)if(c->ooo[i].used){uint32_t a=hton32(c->ooo[i].seq),b=hton32(c->ooo[i].seq+c->ooo[i].len);memcpy_u(o+n,&a,4);n+=4;memcpy_u(o+n,&b,4);n+=4;blocks--;}}}
    while(n&3){o[n++]=1;}return n;
}
static void tcp_rx_append(tcp_conn_t *c,const uint8_t *data,uint32_t len){if(c->rxn+len<=TCP_BUF_SIZE){memcpy_u(c->rxb+c->rxn,data,len);c->rxn+=len;}}
static void tcp_merge_ooo(tcp_conn_t *c){
    /* 接收侧 OOO 队列整理（对照 Linux tcp_ofo_queue/tcp_data_queue 的 prune）：
       丢弃完全过期段、裁剪跨越 rcv_nxt 的部分重叠段，再级联交付。 */
    bool again;
    do{
        again=false;
        for(int i=0;i<4;i++){
            uint32_t end;
            if(!c->ooo[i].used)continue;
            end=c->ooo[i].seq+c->ooo[i].len;
            if(!tcp_seq_after(end,c->rcv_nxt)){ /* 过期段：整体丢弃，防槽位泄漏 */
                c->ooo_bytes-=c->ooo[i].len;c->ooo[i].used=false;again=true;continue;
            }
            if(tcp_seq_before(c->ooo[i].seq,c->rcv_nxt)){ /* 部分重叠：裁掉已确认前缘 */
                uint32_t trim=c->rcv_nxt-c->ooo[i].seq;
                memcpy_u(c->ooo[i].data,c->ooo[i].data+trim,(uint32_t)c->ooo[i].len-trim);
                c->ooo_bytes-=trim;c->ooo[i].seq=c->rcv_nxt;c->ooo[i].len=(uint16_t)(end-c->rcv_nxt);
                again=true;
            }
            if(c->ooo[i].seq!=c->rcv_nxt)continue;          /* 前方仍有空洞 */
            if(c->rxn+c->ooo[i].len>TCP_BUF_SIZE)continue;  /* 接收缓冲满：留在缓存等应用读走 */
            tcp_rx_append(c,c->ooo[i].data,c->ooo[i].len);
            c->rcv_nxt+=c->ooo[i].len;c->ooo_bytes-=c->ooo[i].len;c->ooo[i].used=false;again=true;
        }
    }while(again);
}
static bool tcp_queue_ooo(tcp_conn_t *c,uint32_t seq,const uint8_t *data,uint32_t len){
    uint32_t end=seq+len;if(len==0||len>TCP_MSS||c->ooo_bytes+len>TCP_BUF_SIZE)return false;
    if(!tcp_seq_after(end,c->rcv_nxt))return false;
    if(!tcp_seq_after(seq,c->rcv_nxt)){uint32_t trim=c->rcv_nxt-seq;seq+=trim;data+=trim;len-=trim;}
    for(int i=0;i<4;i++)if(c->ooo[i].used&&tcp_seq_before(seq,c->ooo[i].seq+c->ooo[i].len)&&tcp_seq_before(c->ooo[i].seq,seq+len))return false;
    for(int i=0;i<4;i++)if(!c->ooo[i].used){c->ooo[i].used=true;c->ooo[i].seq=seq;c->ooo[i].len=(uint16_t)len;memcpy_u(c->ooo[i].data,data,len);c->ooo_bytes+=len;return true;}
    return false;
}
static bool tcp_accept_data(tcp_conn_t *c,uint32_t seq,const uint8_t *data,uint32_t len){
    /* 非按序（过期/重复/部分重叠）统一交给 OOO 队列裁决：
       过期与重叠被拒后由调用方重发当前 rcv_nxt 的 ACK；跨界段裁剪前缘后缓存。 */
    if(seq!=c->rcv_nxt)return tcp_queue_ooo(c,seq,data,len);
    if(len<=TCP_MSS&&c->rxn+len<=TCP_BUF_SIZE){tcp_rx_append(c,data,len);c->rcv_nxt+=len;tcp_merge_ooo(c);return true;}
    return false;
}

static void tcp_tx_reset(tcp_conn_t *c){
    for(uint32_t i=0;i<TCP_TX_SEG_MAX;i++)c->tx[i].used=false;
    c->tx_n=0;
}
static void tcp_tx_add(tcp_conn_t *c,uint32_t seq,uint32_t len){
    if(!len||len>TCP_MSS)return;
    /* 记分板上限截断（对照 Linux 无上限 retransmit 队列的降级方案）：
       满时把新段并入尾项而不是丢弃 —— 否则溢出区间脱离跟踪，对端 SACK
       无法映射到任何条目，选择性重传对该区域永久失效，只能退化到
       RTO go-back-N（RFC 6675 §4：未确认区间须保持 SACK 可映射）。 */
    if(c->tx_n>=TCP_TX_SEG_MAX){
        if(seq==(uint32_t)(c->tx[TCP_TX_SEG_MAX-1].seq+c->tx[TCP_TX_SEG_MAX-1].len)
           &&(uint32_t)c->tx[TCP_TX_SEG_MAX-1].len+len<=TCP_BUF_SIZE)
            c->tx[TCP_TX_SEG_MAX-1].len=(uint16_t)(c->tx[TCP_TX_SEG_MAX-1].len+len);
        return;
    }
    c->tx[c->tx_n].seq=seq;c->tx[c->tx_n].len=(uint16_t)len;
    c->tx[c->tx_n].used=true;c->tx[c->tx_n].sacked=false;
    c->tx[c->tx_n].lost=false;c->tx[c->tx_n].retransmitted=false;c->tx_n++;
}
static void tcp_tx_ack(tcp_conn_t *c,uint32_t ack){
    uint32_t out=0;
    for(uint32_t i=0;i<c->tx_n;i++){
        uint32_t end;
        if(!c->tx[i].used)continue;
        end=c->tx[i].seq+c->tx[i].len;
        if(!tcp_seq_after(end,ack))continue;
        if(tcp_seq_before(c->tx[i].seq,ack)){
            c->tx[i].seq=ack;c->tx[i].len=(uint16_t)(end-ack);
            c->tx[i].sacked=false;c->tx[i].lost=false;c->tx[i].retransmitted=false;
        }
        c->tx[out++]=c->tx[i];
    }
    c->tx_n=(uint8_t)out;
    for(;out<TCP_TX_SEG_MAX;out++)c->tx[out].used=false;
}
static void tcp_tx_sack(tcp_conn_t *c){
    uint32_t high=c->snd_una;
    for(uint32_t b=0;b<c->sack_n;b++)if(tcp_seq_after(c->sack_right[b],high))high=c->sack_right[b];
    for(uint32_t i=0;i<c->tx_n;i++){
        uint32_t end;bool covered=false;
        if(!c->tx[i].used)continue;
        end=c->tx[i].seq+c->tx[i].len;
        /* 每包重新裁定 sacked/lost（RFC 6675 §4 以当前 SACK 集为准；对照 Linux
           tcp_sacktag_walk 同步重算）：对端 renege 撤销先前 SACK 时旧标记不得残留，
           否则被撤销的段将永远不被选择性重传。 */
        for(uint32_t b=0;b<c->sack_n;b++)
            if(!tcp_seq_before(c->tx[i].seq,c->sack_left[b])&&
               !tcp_seq_after(end,c->sack_right[b])){covered=true;break;}
        c->tx[i].sacked=covered;
        /* RFC 6675: any un-SACKed byte below HighAck => lost. Testing only the entry END
           missed prefix holes whose end == HighAck (head of entry unacked, tail SACKed),
           delaying recovery to RTO instead of selective retransmit. */
        c->tx[i].lost=!covered&&tcp_seq_before(c->tx[i].seq,high);
    }
}
static bool tcp_tx_retransmit_lost(tcp_conn_t *c){
    for(uint32_t i=0;i<c->tx_n;i++)if(c->tx[i].used&&c->tx[i].lost&&!c->tx[i].sacked&&!c->tx[i].retransmitted){
        uint32_t off=c->tx[i].seq-c->snd_una;
        if(tcp_seq_before(c->tx[i].seq,c->snd_una)||off+c->tx[i].len>c->snd_used)continue;
        /* 问题1[MEDIUM]: 发送失败不标 retransmitted（continue 试下一段/留给下一 SACK 轮次或 RTO 兜底），返回值 true/false 语义不变 */
        if(!tcp_put_pkt(c,TCP_FLAG_ACK|TCP_FLAG_PSH,c->tx[i].seq,c->rcv_nxt,c->sndb+off,c->tx[i].len))continue;
        c->tx[i].retransmitted=true;c->rtt_retransmitted=true;tcp_rto_rearm(c);
        kputs("[NET] TCP SACK: re-xmit ");kput_dec(c->tx[i].len);kputs("B\n");
        NETSTAT_INC(tcp_sack_rexmit);
        return true;
    }
    return false;
}
static void tcp_tx_clear_marks(tcp_conn_t *c){
    for(uint32_t i=0;i<c->tx_n;i++){c->tx[i].sacked=false;c->tx[i].lost=false;c->tx[i].retransmitted=false;}
}

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

socket_t *tcp_accept_socket(socket_t *s){
    if(!s||s->type!=SOCK_TCP_LISTEN)return NULL;
    uint16_t port=s->tcp.conn->lport;
    for(int i=0;i<TCP_MAX_CONNS;i++){
        tcp_conn_t *c=&tcp_conns[i];
        if(c->used&&c->state==TCP_ESTABLISHED&&c->lport==port&&!c->accepted){
            for(int j=0;j<TCP_MAX_CONNS;j++)if(tcp_handles[j].type==SOCK_CLOSED){
                c->accepted=true;tcp_handles[j]=(socket_t){SOCK_TCP_ESTAB,{.tcp={c}}};return &tcp_handles[j];
            }
            return NULL;
        }
    }
    return NULL;
}

int tcp_set_backlog(socket_t *s,uint32_t backlog){
    if(!s||s->type!=SOCK_TCP_LISTEN||!s->tcp.conn)return -22;
    if(backlog==0)backlog=1;
    if(backlog>TCP_MAX_CONNS)backlog=TCP_MAX_CONNS;
    s->tcp.conn->backlog=(uint8_t)backlog;
    return 0;
}

void tcp_abort_socket(socket_t *s){
    if(!s||!s->tcp.conn)return;
    s->tcp.conn->used=false;s->tcp.conn->state=TCP_CLOSED;
    s->tcp.conn->rto_deadline=0;s->tcp.conn->persist_deadline=0;
    s->type=SOCK_CLOSED;
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

#define TCP_RTO_INIT   30u   /* 300ms @100Hz, preserved minimum for this PIT */
#define TCP_RTO_MAX    240u  /* 2.4s, existing stack bound */
/* 阶段3：send/recv 错误码区分化（对照 linux-ref/include/uapi/asm-generic/
 * errno-base.h:11 EAGAIN=11、:104 ECONNRESET=104）。
 * 语义依据：
 *   - 缓冲满非阻塞写 → -EAGAIN（Linux tcp_sendmsg 队列满且 O_NONBLOCK，
 *     linux-ref/net/ipv4/tcp.c:1359 sk_stream_wait_memory 失败路径返回
 *     -EAGAIN）；
 *   - 连接被 RST 复位后的 recv/send → -ECONNRESET（Linux tcp_reset() 置
 *     sk_err=ECONNRESET 并清空接收队列，linux-ref/net/ipv4/tcp_input.c
 *     tcp_reset()；后续 recv/send 直接上报该错误）。 */
#define CATOS_EAGAIN      11u
#define CATOS_ECONNRESET 104u
/* M1: R2 放弃阈值 —— RFC 9293 §3.8.3(c)「When the number of transmissions of
   the same segment reaches a threshold R2 greater than R1, close the
   connection」(MUST-20，继承 RFC 1122 §4.2.3.5 的 R1/R2 模型)。
   SYN-ACK 是连接建立的唯一赌注(RFC 9293 §3.8.1)，取更紧的 3 次；
   数据/FIN 重传取 5 次。达到阈值后释放连接槽位，不再无限退避重发。 */
#define TCP_RTO_RETRY_SYNRCVD 3u
#define TCP_RTO_RETRY_DATA    5u
static void tcp_persist_arm(tcp_conn_t *c){if(!c->persist_deadline)c->persist_deadline=ticks+TCP_RTO_INIT;}
static void tcp_persist_clear(tcp_conn_t *c){c->persist_deadline=0;c->persist_backoff=0;}
static void tcp_persist_retry(tcp_conn_t *c){if(c->persist_backoff<6)c->persist_backoff++;uint32_t d=TCP_RTO_INIT<<c->persist_backoff;if(d>TCP_RTO_MAX)d=TCP_RTO_MAX;c->persist_deadline=ticks+d;}
static uint32_t rto_base(tcp_conn_t *c){uint32_t r=c->rto_ticks?c->rto_ticks:TCP_RTO_INIT;return r<TCP_RTO_INIT?TCP_RTO_INIT:r>TCP_RTO_MAX?TCP_RTO_MAX:r;}
static uint32_t rto_now(tcp_conn_t *c){uint32_t r=rto_base(c)<<c->rto_backoff;return r>TCP_RTO_MAX?TCP_RTO_MAX:r;}
static void tcp_rto_arm(tcp_conn_t *c){c->rto_deadline=ticks+rto_now(c);c->rto_backoff=0;c->rto_attempts=0;}
static void tcp_rto_rearm(tcp_conn_t *c){c->rto_deadline=ticks+rto_now(c);}
static void tcp_rto_retry(tcp_conn_t *c){
    if(c->rto_backoff<6)c->rto_backoff++;
    c->rto_attempts++;               /* M1: 记入 R2 计数，见 TCP_RTO_RETRY_* 与 RFC 9293 §3.8.3(a) */
    c->rto_deadline=ticks+rto_now(c);
}
static void tcp_cc_init(tcp_conn_t *c){
    c->rto_ticks=TCP_RTO_INIT;c->rtt_stamp=0;c->rtt_seq=0;c->srtt_ticks=0;
    c->rttvar_ticks=0;c->rtt_pending=false;c->rtt_retransmitted=false;
    c->cwnd=TCP_MSS;c->ssthresh=TCP_BUF_SIZE;c->dupacks=0;c->fast_recovery=false;c->recover_seq=0;
}
static void tcp_rtt_sample(tcp_conn_t *c,uint32_t sample){
    if(!sample)sample=1; /* RFC 6298 §2.4: 亚tick样本钳到最小值1，不得静默丢弃 */
    if(!c->srtt_ticks){c->srtt_ticks=sample;c->rttvar_ticks=sample/2u;}
    else {uint32_t d=c->srtt_ticks>sample?c->srtt_ticks-sample:sample-c->srtt_ticks;
        c->rttvar_ticks=(3u*c->rttvar_ticks+d)/4u;
        c->srtt_ticks=(7u*c->srtt_ticks+sample)/8u;}
    uint32_t r=c->srtt_ticks+4u*c->rttvar_ticks;
    c->rto_ticks=r<TCP_RTO_INIT?TCP_RTO_INIT:r>TCP_RTO_MAX?TCP_RTO_MAX:r;
    kputs("[NET] TCP RTT sample=");kput_dec(sample);kputs(" RTO=");kput_dec(c->rto_ticks);kputs("\n");
}
static void tcp_loss_window(tcp_conn_t *c,uint32_t in_flight){
    uint32_t half=in_flight/2u;
    c->ssthresh=half<2u*TCP_MSS?2u*TCP_MSS:half;
    c->cwnd=TCP_MSS;c->dupacks=0;c->fast_recovery=false;
}

static tcp_conn_t *tcp_conn_find_free(void){for(int i=0;i<TCP_MAX_CONNS;i++)if(!tcp_conns[i].used)return &tcp_conns[i];return NULL;}
static tcp_conn_t *tcp_conn_find_peer(uint32_t ip,uint16_t sport){for(int i=0;i<TCP_MAX_CONNS;i++)if(tcp_conns[i].used&&tcp_conns[i].peer_ip==ip&&tcp_conns[i].peer_port==sport)return &tcp_conns[i];return NULL;}
static tcp_conn_t *tcp_conn_find_listen(uint16_t port){for(int i=0;i<TCP_MAX_CONNS;i++)if(tcp_conns[i].used&&tcp_conns[i].state==TCP_LISTEN&&tcp_conns[i].lport==port)return &tcp_conns[i];return NULL;}
static uint32_t tcp_pending_count(uint16_t port){
    uint32_t n=0;
    for(int i=0;i<TCP_MAX_CONNS;i++){
        tcp_conn_t *c=&tcp_conns[i];
        if(c->used&&!c->accepted&&c->lport==port&&
           (c->state==TCP_SYN_RECEIVED||c->state==TCP_ESTABLISHED))n++;
    }
    return n;
}
static void tcp_drop_pending(uint16_t port){
    for(int i=0;i<TCP_MAX_CONNS;i++){
        tcp_conn_t *c=&tcp_conns[i];
        if(c->used&&!c->accepted&&c->lport==port&&
           (c->state==TCP_SYN_RECEIVED||c->state==TCP_ESTABLISHED)){
            c->used=false;c->state=TCP_CLOSED;c->rto_deadline=0;
            c->persist_deadline=0;c->tw_until=0;
        }
    }
}
static void tcp_send_rst_ack(uint32_t dst_ip,uint16_t src_port,uint16_t dst_port,uint32_t seq,uint8_t in_flags,uint32_t dlen){
    uint8_t dmac[6];if(!arp_resolve(dst_ip,dmac))return;
    uint8_t *seg=begin_ip(dst_ip,IP_PROTO_TCP,dmac);if(!seg)return;
    tcp_hdr_t *t=(tcp_hdr_t*)seg;t->src_port=hton16(src_port);t->dst_port=hton16(dst_port);
    if(in_flags&TCP_FLAG_ACK){t->seq=hton32(seq);t->ack_seq=0;t->flags=TCP_FLAG_RST;}
    else{t->seq=0;t->ack_seq=hton32(seq+dlen+((in_flags&(TCP_FLAG_SYN|TCP_FLAG_FIN))?1u:0u));t->flags=TCP_FLAG_RST|TCP_FLAG_ACK;}
    t->off_res=0x50;t->window=0;t->csum=0;t->urgent=0;
    t->csum=hton16(ip_checksum_pseudo(g_ip,dst_ip,IP_PROTO_TCP,20,seg,20));end_ip(seg,20,IP_PROTO_TCP);
}
socket_t *net_socket_open(uint32_t type){
    if(type==2){for(int i=0;i<UDP_SLOTS;i++)if(!udp_socks[i].used){udp_socks[i]=(udp_sock_t){0};udp_socks[i].used=true;udp_socks[i].owned=true;udp_handles[i]=(socket_t){SOCK_UDP_UNBOUND,{.udp={(uint16_t)0,(uint8_t)i,1}}};return &udp_handles[i];}return NULL;}
    if(type==1){for(int i=0;i<TCP_MAX_CONNS;i++)if(!tcp_conns[i].used){tcp_conns[i]=(tcp_conn_t){0};tcp_conns[i].used=true;tcp_conns[i].state=TCP_CLOSED;tcp_handles[i]=(socket_t){SOCK_TCP_UNBOUND,{.tcp={&tcp_conns[i]}}};return &tcp_handles[i];}return NULL;}
    return NULL;
}
/* 阶段3 SWS（silly-window syndrome）避免 + 通告窗口单一出口。
 * 对照 linux-ref/net/ipv4/tcp_output.c:3314 __tcp_select_window()：
 *   free_space < full_space>>1 时，若 free_space < min(allowed_space>>4, mss)
 *   → 通告 0。本栈 full_space=allowed_space=TCP_BUF_SIZE=4096、mss=1460，
 *   化简为：0 < free < TCP_MSS → 通告 0；其余通告实际剩余空间。
 * 死锁自检：通告 0 后对端 persist 探测会持续到来；本端应用一旦 recv() 腾出
 * 缓冲，tcp_recv() 依据 adv_win 检测「显著打开」立即补发窗口更新 ACK
 * （见 tcp_window_update_ack），无滞留死锁。 */
static uint32_t tcp_advertise_window(const tcp_conn_t *c){
    uint32_t free=TCP_BUF_SIZE-c->rxn;
    if(free&&free<TCP_MSS)return 0;
    return free;
}
/* recv() 腾空接收缓冲后调用：窗口较上次通告「至少翻倍且非零」时立即发
 * bare ACK 唤醒可能停在零窗口/persist 的对端 —— RFC 793 §3.7 窗口更新
 * 义务；对照 linux-ref/net/ipv4/tcp.c:1551 __tcp_cleanup_rbuf()：
 *   new_window >= 2 * rcv_window_now  → time_to_ack = true。
 * 仅在仍会继续收数据的同步态发送（CLOSE_WAIT 及之后对端已 FIN，同 Linux
 * RCV_SHUTDOWN 跳过逻辑）。 */
static void tcp_window_update_ack(tcp_conn_t *c){
    uint32_t nw;
    if(c->state!=TCP_ESTABLISHED)return;
    nw=tcp_advertise_window(c);
    if(nw&&(uint32_t)c->adv_win<nw&&nw>=2u*(uint32_t)c->adv_win){
        kputs("[NET] TCP window reopen ACK ");kput_dec(nw);kputs("B\n");
        tcp_put_pkt(c,TCP_FLAG_ACK,c->snd_nxt,c->rcv_nxt,NULL,0);
    }
}
static bool tcp_put_pkt(tcp_conn_t *c,uint8_t flags,uint32_t seq,uint32_t ack,const uint8_t *data,uint32_t dlen){
    uint8_t dmac[6];if(!arp_resolve(c->peer_ip,dmac))return false;   /* 问题1[HIGH]: 上报解析失败 */
    uint8_t *seg=begin_ip(c->peer_ip,IP_PROTO_TCP,dmac);if(!seg)return false;   /* 问题1[HIGH]: TX 环耗尽上报失败 */
    tcp_hdr_t *t=(tcp_hdr_t*)seg;
    t->src_port=hton16(c->lport);t->dst_port=hton16(c->peer_port);
    t->seq=hton32(seq);t->ack_seq=hton32(ack);
    uint8_t opts[20];uint32_t olen=tcp_build_opts(c,opts,flags);
    t->off_res=(uint8_t)(((20u+olen)/4u)<<4);t->flags=flags;
    uint16_t win=(uint16_t)tcp_advertise_window(c);            /* 动态通告接收窗口（SWS 规则见上） */
    c->adv_win=win;                                            /* 记录实际通告值供窗口更新 ACK 判定 */
    t->window=hton16(win);t->csum=0;t->urgent=0;
    memcpy_u(seg+20,opts,olen);memcpy_u(seg+20+olen,data,dlen);
    t->csum=hton16(ip_checksum_pseudo(g_ip,c->peer_ip,IP_PROTO_TCP,(uint16_t)(20+olen+dlen),seg,20+olen+dlen));
    return end_ip(seg,20+olen+dlen,IP_PROTO_TCP);   /* 问题1[HIGH]: submit 失败同样上报 */
}

/* Send buffered data that fits in the current peer window. */
static void tcp_xmit_pending(tcp_conn_t *c){
    uint32_t send_win=c->peer_win<c->cwnd?c->peer_win:c->cwnd;
    if(!send_win){if(c->snd_used>c->snd_nxt-c->snd_una)tcp_persist_arm(c);return;}
    uint32_t eff_mss=c->peer_mss?(uint32_t)c->peer_mss:(uint32_t)TCP_MSS;
    if(eff_mss>TCP_MSS)eff_mss=TCP_MSS;
    do{
        uint32_t in_flight=c->snd_nxt-c->snd_una;
        if(in_flight>=send_win||c->snd_used<=in_flight)break;
        uint32_t n=c->snd_used-in_flight;
        uint32_t room=send_win-in_flight;
        if(n>room)n=room;
        if(n>eff_mss)n=eff_mss;
        /* 问题1[HIGH]: 发送失败(ARP 未解析/TX 环耗尽)时不推进 snd_nxt、不入
           scoreboard、不重臂 RTO，直接退出填窗循环 —— 数据留在 sndb 待真实
           重传/续发，杜绝整窗"幻影发送"被 RTO 放弃误杀连接。 */
        if(!tcp_put_pkt(c,TCP_FLAG_ACK|TCP_FLAG_PSH,c->snd_nxt,c->rcv_nxt,
                    c->sndb+in_flight,n))break;
        if(!c->rtt_pending){c->rtt_stamp=ticks;c->rtt_seq=c->snd_nxt+n;c->rtt_pending=true;c->rtt_retransmitted=false;}
        c->snd_nxt+=n;
        tcp_tx_add(c,c->snd_nxt-n,n);
        tcp_rto_rearm(c);
        tcp_persist_clear(c);
    }while(1);
}
int tcp_send(socket_t *s,const uint8_t *data,uint32_t len);
void tcp_close(socket_t *s);

socket_t *tcp_listen(uint16_t port){
    tcp_conn_t *c=tcp_conn_find_free();if(!c)return NULL;
    c->used=true;c->state=TCP_LISTEN;c->backlog=TCP_MAX_CONNS;c->lport=port;c->peer_ip=0;c->peer_port=0;c->accepted=false;c->dead=false;
    c->rxn=0;c->snd_used=0;c->snd_una=c->snd_nxt=c->snd_isn=0;c->rto_deadline=0;c->rto_backoff=0;c->tw_until=0;c->persist_deadline=0;c->persist_backoff=0;
    tcp_tx_reset(c);
    tcp_cc_init(c);     /* cc_init 不覆盖 rto_attempts/ooo/sack 状态 */
    c->rto_attempts=0;  /* 问题5[INFO]: 清上一世连接残留 R2 计数 */
    c->peer_mss=0;c->adv_win=0;c->sack_ok=false;c->sack_n=0;   /* 问题5[INFO]: 清 MSS/通告窗/SACK 协商残留 */
    for(int i=0;i<4;i++)c->ooo[i].used=false;   /* 问题5[INFO]: 清 OOO 记分板(兼 SACK 块来源) */
    c->ooo_bytes=0;
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
    /* 0.1 旧化身回收（tcp80 二次连接超时根因）：同一 4 元组上残留于关闭中/
       关闭后状态(FIN_WAIT_1, FIN_WAIT_2, CLOSING, LAST_ACK, CLOSE_WAIT,
       TIME_WAIT) 的旧 TCB 会遮蔽监听者 —— 新 SYN 落到旧 TCB 后既无 SYN 分支
       也无响应，客户端只能干等超时。收到纯 SYN(无 ACK)时按"TIME-WAIT 化身替换"
       语义回收旧槽位，让下方 LISTEN 分支重建全新连接。
       依据：RFC 9293 §3.10.7.4 第四步要求对同步态上的裸 SYN 至少回应
       <SEQ=0><ACK=SEG.SEQ+SEG.LEN><CTL=RST,ACK>（旧代码连回包都没有，违反
       "MUST respond"精神）；进一步采用 RFC 1337 讨论过、Linux
       tcp_minisocks.c tcp_timewait_state_process() 同款的化身替换策略，
       以满足本阶段"端口复用/多连接 accept"目标。 */
    if(c&&(flags&TCP_FLAG_SYN)&&!(flags&TCP_FLAG_ACK)&&
       (c->state==TCP_TIME_WAIT||c->state==TCP_LAST_ACK||c->state==TCP_CLOSE_WAIT||
        c->state==TCP_CLOSING||c->state==TCP_FIN_WAIT_1||c->state==TCP_FIN_WAIT_2)){
        kputs("[NET] TCP stale conn (");kput_dec(c->state);
        kputs(") recycled for new SYN\n");
        c->used=false;c->state=TCP_CLOSED;c->rto_deadline=0;
        c->persist_deadline=0;c->tw_until=0;
        c=NULL;   /* 注意：若应用仍持有该 conn 的 ESTAB 句柄，后续调用由
                     state!=ESTABLISHED 守卫拒绝（与 RST/close 路径既有语义一致） */
    }
    if(!c){
        tcp_conn_t *l=tcp_conn_find_listen(dport);
        if((flags&TCP_FLAG_SYN)&&l){
            if(tcp_pending_count(dport)>=l->backlog){
                kputs("[NET] TCP accept queue full, RST\n");
                tcp_send_rst_ack(src_ip,dport,sport,seq,flags,dlen);
                NETSTAT_INC(tcp_rst_sent);
                return;
            }
            c=tcp_conn_find_free();
            if(!c){kputs("[NET] TCP conn table full, RST\n");tcp_send_rst_ack(src_ip,dport,sport,seq,flags,dlen);NETSTAT_INC(tcp_rst_sent);return;}
            /* 问题3[MED]: 关中断完成全部字段初始化后，最后单条 used=true 发布
               （pushfl 保存/恢复原 IF 状态，同 process.c context_switch 惯用法）。
               取代 df995a8 的"四元组最先落位"缓解 —— 彼案只缩小未闭合：
               used=true 与 rcv_isn/cc/scoreboard 初始化之间仍有窗口且编译器可
               重排。IF=0 全程屏蔽重入后，发布序不再敏感；重复 SYN 在 CS 外
               要么看不到该槽(走本分支 backlog 检查)，要么看到完整 TCB(走
               :850 duplicate-SYN 重发 SYN-ACK 路径)。 */
            {
                uint32_t eflags;
                __asm__ volatile("pushfl\n\tpopl %0\n\tcli":"=r"(eflags)::"memory");
                c->state=TCP_SYN_RECEIVED;
                c->lport=dport;c->peer_ip=src_ip;c->peer_port=sport;c->peer_win=ntoh16(h->window);
                c->accepted=false;c->rxn=0;c->snd_used=0;
                tcp_tx_reset(c);
                c->test_sent=false;c->test_closed=false;c->persist_deadline=0;c->persist_backoff=0;c->dead=false;
                tcp_cc_init(c);
                tcp_parse_opts(c,seg+20,hlen-20,true);
                c->rcv_isn=seq;c->rcv_nxt=seq+1;
                c->snd_isn=seq_gen++;c->snd_nxt=c->snd_isn+1;c->snd_una=c->snd_nxt;
                c->used=true;   /* 发布点：此后 find_peer 可见完整 TCB */
                __asm__ volatile("pushl %0\n\tpopfl"::"r"(eflags):"memory");
            }
            kputs("[NET] TCP SYN :");kput_dec(dport);kputs(" <- ");net_ip_print(src_ip);kputs(":");kput_dec(sport);kputs(" -> SYN-ACK\n");
            tcp_put_pkt(c,TCP_FLAG_SYNACK,c->snd_isn,c->rcv_nxt,NULL,0);
            tcp_rto_arm(c);                    /* SYN-ACK 需要重传保护 */
            return;
        }
        kputs("[NET] TCP :");kput_dec(dport);kputs(" no listener, RST\n");
        /* RST:no_listener —— 复用 tcp_send_rst_ack（与 backlog 满/表满路径同源）。
           旧实现手搓裸 RST(无 ACK 标志,ack_seq=0,seq=对端SYN序号)，违反
           RFC 9293 §3.10.7.4 step4：对无 ACK 的 SYN 应回
           <SEQ=0><ACK=SEG.SEQ+SEG.LEN><CTL=RST,ACK>。
           BSD 派生栈（含 QEMU slirp）在 SYN_SENT 态要求 RST 带 ACK 才接受，
           裸 RST 被静默丢弃 -> slirp 停留 SYN_SENT 重发 SYN -> 宿主侧超时，
           hostfwd 回不来 RST/EOF（blackbox rst:no_listener FAIL 根因）。 */
        tcp_send_rst_ack(src_ip,dport,sport,seq,flags,dlen);
        NETSTAT_INC(tcp_rst_sent);
        return;
    }

    /* RFC 793 duplicate SYN handling: keep the half-open state and repeat
       the SYN-ACK so a lost control reply does not strand the peer. */
    if(c->state==TCP_SYN_RECEIVED&&(flags&TCP_FLAG_SYN)&&seq==c->rcv_isn){
        tcp_put_pkt(c,TCP_FLAG_SYNACK,c->snd_isn,c->rcv_nxt,NULL,0);tcp_rto_arm(c);return;
    }

    /* 1. RST 处理 —— 必须先于 ACK/数据处理（RFC 9293 §3.10.7.4 事件顺序）。
       M3 盲收防御，RFC 5961 §3.2.1 / RFC 9293 §3.10.7.4 第二步三检查
       （原文逐条对应，本栈无 SYN-SENT 态故略去其分支）：
         (1) RST 且 SEG.SEQ 在接收窗口外          → 静默丢弃；
         (2) RST 且 SEG.SEQ == RCV.NXT            → MUST 执行复位；
         (3) RST 窗口内但 != RCV.NXT              → 回 challenge-ACK
               <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK> 后丢弃该段；
       旧实现无条件接受任意序号的 RST，可被盲注第三方一键拆除连接。 */
    if(flags&TCP_FLAG_RST){
        uint32_t rcv_win=(uint32_t)(TCP_BUF_SIZE-c->rxn);
        if(seq!=c->rcv_nxt&&tcp_seq_after(seq,c->rcv_nxt)&&tcp_seq_before(seq,(uint32_t)(c->rcv_nxt+rcv_win))){
            kputs("[NET] TCP blind-RST rejected, challenge ACK\n");
            tcp_put_pkt(c,TCP_FLAG_ACK,c->snd_nxt,c->rcv_nxt,NULL,0);
            return;
        }
        if(seq==c->rcv_nxt){kputs("[NET] TCP RST(valid seq) -> CLOSED\n");}
        else{kputs("[NET] TCP RST out-of-window dropped\n");return;}
        c->dead=true;   /* E2：死亡标记先于槽位释放 —— conn 存储在被复用前保持
                           可读，此后对该 fd 的 send/recv 上报 -ECONNRESET */
        c->used=false;c->state=TCP_CLOSED;
        c->rto_deadline=0;c->persist_deadline=0;c->tw_until=0;
        return;
    }

    /* 2. 记录对端窗口 */
    uint16_t old_win=c->peer_win;
    c->peer_win=ntoh16(h->window);
    /* persist 清除需 ACK 门槛（阶段3 A2）：任意来源的段（含乱序数据/重复段）
       都可能携带非零窗口字段；未经序号/ACK 校验就清除 persist 会让零窗口
       探测被注入流量干扰停摆。已建立态的对端合法段必带 ACK 标志
       （RFC 9293 §3.3 表：ESTABLISHED 态所有段均置 ACK）。 */
    if((flags&TCP_FLAG_ACK)&&c->peer_win)tcp_persist_clear(c);
    else if((flags&TCP_FLAG_ACK)&&!c->peer_win&&c->snd_used>(uint32_t)(c->snd_nxt-c->snd_una))tcp_persist_arm(c);   /* 问题4[LOW]: arm 加 ACK 门，与上行 clear 对称 */
    /* 阶段3 A1：对端在携带数据的段里把窗口降为 0 时（非 dup-ACK 路径），
       tcp_xmit_pending()（仅在 ACK 推进路径调用）没有机会武装 persist ——
       此处按「观测到零窗口且尚有未发送数据」直接武装，对照 Linux
       tcp_ack_update_window()/tcp_send_probe0() 对零窗口状态的持续跟踪
       （linux-ref/net/ipv4/tcp_timer.c:391 tcp_probe_timer 的触发前提即
       零窗口 + 写队列非空）。tcp_persist_arm 幂等（deadline 已设则不动）。 */
    c->sack_n=0;
    tcp_parse_opts(c,seg+20,hlen-20,false);

    /* 3. 通用 ACK 处理：推进 snd_una，回收发送缓冲（Linux tcp_ack） */
    if(flags&TCP_FLAG_ACK){
        uint32_t old_una=c->snd_una,in_flight=c->snd_nxt-c->snd_una;
        bool sack_retx=false;
        if(c->sack_n)tcp_tx_sack(c);
        if(ack==c->snd_una&&in_flight&&c->peer_win<=old_win){
            c->dupacks++;
            if(c->sack_n)sack_retx=tcp_tx_retransmit_lost(c);
            if(c->dupacks==3){
                tcp_loss_window(c,in_flight);
                c->dupacks=3;c->cwnd=c->ssthresh+3u*TCP_MSS;c->fast_recovery=true;c->recover_seq=c->snd_nxt;
                kputs("[NET] TCP fast retransmit\n");
                if(!sack_retx){
                    if(c->sack_n)sack_retx=tcp_tx_retransmit_lost(c);
                }
                if(!sack_retx){
                    /* 问题2[LOW]: 快速重传发送失败则不进 fast_recovery（回退标记），仅 rearm RTO 兜底 */
                    if(tcp_put_pkt(c,TCP_FLAG_ACK|TCP_FLAG_PSH,c->snd_una,c->rcv_nxt,c->sndb,in_flight>TCP_MSS?TCP_MSS:in_flight)){
                        c->rtt_retransmitted=true;tcp_rto_rearm(c);
                    } else {
                        c->fast_recovery=false;tcp_rto_rearm(c);
                    }
                }
            } else if(c->fast_recovery&&c->dupacks>3){c->cwnd+=TCP_MSS;tcp_xmit_pending(c);}
        } else if(ack==c->snd_una&&c->peer_win>old_win){
            c->dupacks=0;tcp_xmit_pending(c);
        } else if(tcp_seq_after(ack,c->snd_una)&&!tcp_seq_after(ack,c->snd_nxt)){   /* 问题2[MED-HIGH]: 回绕安全(原裸 unsigned 比较)；<= 语义保持 */
            uint32_t acked=ack-c->snd_una;
            if(acked>c->snd_used)acked=c->snd_used;
            if(c->rtt_pending&&!tcp_seq_before(ack,c->rtt_seq)){   /* 问题2[MED-HIGH]: >= 语义回绕安全化 */
                if(!c->rtt_retransmitted){tcp_rtt_sample(c,ticks-c->rtt_stamp);c->rtt_pending=false;}
                else c->rtt_pending=false; /* Karn: 抑制采样同时清 pending，避免旧时间戳滞留 */
            }
            c->snd_una=ack;
            if(acked){memcpy_u(c->sndb,c->sndb+acked,c->snd_used-acked);c->snd_used-=acked;}
            tcp_tx_ack(c,ack);
            if(acked){
                if(c->cwnd<c->ssthresh)c->cwnd+=acked>TCP_MSS?TCP_MSS:acked;
                else {uint32_t inc=(TCP_MSS*acked)/(c->cwnd?c->cwnd:TCP_MSS);c->cwnd+=inc?inc:1;}
            }
            /* 问题3[LOW]: fast recovery 退出比较回绕安全化(原裸 ack>=c->recover_seq unsigned 比较)，语义等价于回绕安全 >= */
            if(c->fast_recovery&&(tcp_seq_after(ack,c->recover_seq)||ack==c->recover_seq)){c->cwnd=c->ssthresh;c->fast_recovery=false;}
            c->dupacks=0;c->rto_backoff=0;c->rto_attempts=0; /* 进度事件：R2 计数按段重置(RFC 9293 §3.8.3(a)) */
            kputs("[NET] TCP ack=");kput_dec(ack);kputs(" una=");kput_dec(c->snd_una);kputs(" sndb=");kput_dec(c->snd_used);kputs(" cwnd=");kput_dec(c->cwnd);kputs("\n");
            if(!c->sack_n||!tcp_tx_retransmit_lost(c))tcp_xmit_pending(c);
            if(c->snd_nxt==c->snd_una)c->rto_deadline=0;
            else if(!c->rto_deadline)tcp_rto_rearm(c);
        } else if(ack<old_una||ack>c->snd_nxt){
            /* Invalid ACK does not advance send state. */
        }
    }

    /* 4. 按状态机推进 */
    switch(c->state){
    case TCP_SYN_RECEIVED:
        if((flags&TCP_FLAG_ACK)&&ack==c->snd_nxt){
            c->state=TCP_ESTABLISHED;
            c->rto_deadline=0;
            /* R2 计数按"同一段"语义重置（RFC 9293 §3.8.3(a)）：SYN-ACK 段被
               确认后其重传计数不得泄漏到数据段——否则 SYN 阶段若重传过
               SYN-ACK，DATA 阶段可用的 R2 额度会被预先吃掉（L3B 实测：SYN
               阶段 1 次 + DATA 阶段 4 次即触发 give-up，实际只重传 4 次）。 */
            c->rto_attempts=0;
            c->rto_backoff=0;
            kputs("[NET] TCP ESTABLISHED ");net_ip_print(src_ip);kputs(":");kput_dec(sport);kputs("\n");
        }
        if(dlen){tcp_accept_data(c,seq,data,dlen);tcp_put_pkt(c,TCP_FLAG_ACK,c->snd_nxt,c->rcv_nxt,NULL,0);}
        return;
    case TCP_ESTABLISHED:
    case TCP_FIN_WAIT_1:
    case TCP_FIN_WAIT_2:
    case TCP_CLOSE_WAIT:
    case TCP_CLOSING:
        if(dlen){
            bool in_order=seq==c->rcv_nxt;bool accepted=tcp_accept_data(c,seq,data,dlen);
            if(accepted){
                kputs(in_order?"[NET] TCP data ":"[NET] TCP out-of-order cached ");kput_dec(dlen);kputs("B <- ");net_ip_print(src_ip);kputs("\n");
            }else{
                kputs(tcp_seq_after(seq,c->rcv_nxt)?"[NET] TCP out-of-order cached\n":"[NET] TCP duplicate/overlap, re-ACK\n");
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
        if((flags&TCP_FLAG_FIN)&&seq+dlen+1u==c->rcv_nxt){
            tcp_put_pkt(c,TCP_FLAG_ACK,c->snd_nxt,c->rcv_nxt,NULL,0);return;
        }
        if((flags&TCP_FLAG_ACK)&&ack>=c->snd_nxt){
            kputs("[NET] TCP LAST_ACK done -> CLOSED\n");
            c->used=false;c->state=TCP_CLOSED;c->rto_deadline=0;
        }
        return;
    case TCP_TIME_WAIT:
        if((flags&TCP_FLAG_FIN)||dlen)tcp_put_pkt(c,TCP_FLAG_ACK,c->snd_nxt,c->rcv_nxt,NULL,0);
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
            if(!c->test_sent){
                /* SACK 边界测试入口：一次排队 16x90B=1440B，16 段 > scoreboard
                   上限 TCP_TX_SEG_MAX(8)，可触发上限截断/ACK 回收/双缺口路径。 */
                uint8_t buf[90];
                int ok=0,k,j;
                for(k=0;k<16;k++){
                    int n;
                    for(j=0;j<(int)sizeof(buf);j++)buf[j]=(uint8_t)('A'+(k*(int)sizeof(buf)+j)%26);
                    n=tcp_send(&ts,buf,sizeof(buf));
                    if(n!=(int)sizeof(buf))break;
                    ok++;
                }
                c->test_sent=true;
                kputs("[NET] TCP test send ");kput_dec(ok);kputs("x90B\n");
            }else if(!c->test_closed&&c->snd_used==0&&c->snd_nxt==c->snd_una){
                tcp_close(&ts);c->test_closed=true;kputs("[NET] TCP test close requested\n");
            }
        }
        if(c->persist_deadline&&(int32_t)(ticks-c->persist_deadline)>=0){
            uint32_t in_flight=c->snd_nxt-c->snd_una;
            if(c->peer_win||c->snd_used<=in_flight){tcp_persist_clear(c);
            }else{
                tcp_put_pkt(c,TCP_FLAG_ACK|TCP_FLAG_PSH,c->snd_una,c->rcv_nxt,c->sndb,1);
                /* 阶段3 E3(Karn, RFC 1122 §4.2.2.17)：persist 探测是对未确认
                   字节的重传，置 rtt_retransmitted 抑制其 ACK 产生虚假 RTT 采样
                   （与 RTO 重传路径 net.c tcp_rto_retry/fast retransmit 同口径） */
                c->rtt_retransmitted=true;
                NETSTAT_INC(tcp_persist_probe);
                kputs("[NET] TCP persist probe 1B\n");tcp_persist_retry(c);
            }
        }
        if(c->rto_deadline&&(int32_t)(ticks-c->rto_deadline)>=0){
            /* M1：重传放弃 —— 同段连续重传超过 R2 阈值时释放连接槽位
               RFC 9293 §3.8.3(c) MUST-20，RFC 1122 §4.2.3.5 R1/R2 模型 */
            uint8_t r2=(c->state==TCP_SYN_RECEIVED)?TCP_RTO_RETRY_SYNRCVD:TCP_RTO_RETRY_DATA;
            if(c->rto_attempts>=r2){
                kputs("[NET] TCP RTO give-up (attempts=");kput_dec(c->rto_attempts);
                kputs(" >= R2=");kput_dec(r2);kputs("), releasing conn\n");
                c->used=false;c->state=TCP_CLOSED;c->rto_deadline=0;c->persist_deadline=0;c->tw_until=0;
                continue;
            }
            if(c->state==TCP_SYN_RECEIVED){
                NETSTAT_INC(tcp_rto_rexmit);
                kputs("[NET] TCP RTO: re-SYN-ACK\n");
                tcp_put_pkt(c,TCP_FLAG_SYNACK,c->snd_isn,c->rcv_nxt,NULL,0);
                tcp_rto_retry(c);
            }else if(c->state==TCP_LAST_ACK){
                NETSTAT_INC(tcp_rto_rexmit);
                kputs("[NET] TCP RTO: re-FIN\n");
                tcp_put_pkt(c,TCP_FLAG_FINACK,c->snd_nxt-1,c->rcv_nxt,NULL,0);
                tcp_rto_retry(c);
            }else if((c->state==TCP_FIN_WAIT_1||c->state==TCP_CLOSING)&&!c->snd_used){
                NETSTAT_INC(tcp_rto_rexmit);
                kputs("[NET] TCP RTO: re-FIN\n");
                tcp_put_pkt(c,TCP_FLAG_FINACK,c->snd_nxt-1,c->rcv_nxt,NULL,0);
                tcp_rto_retry(c);
            }else if(c->snd_used){
                uint32_t in_flight=c->snd_nxt-c->snd_una;
                if(in_flight>c->snd_used)in_flight=c->snd_used;
                tcp_tx_clear_marks(c); /* SACK is advisory; peer may renege after RTO. */
                tcp_loss_window(c,in_flight);c->rtt_retransmitted=true;
                NETSTAT_INC(tcp_rto_rexmit);
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
    tcp_conn_t *c=s->tcp.conn;if(!c)return -1;
    /* 阶段3 E2：RST 复位后的写 → -ECONNRESET。必须先于 state 判定：
       RST 处理器已置 state=CLOSED，否则会误入 -1（假 EAGAIN）分支。
       对照 Linux tcp_reset() 置 sk_err=ECONNRESET 后 sendmsg 直接上报。 */
    if(c->dead)return -(int)CATOS_ECONNRESET;
    if(c->state!=TCP_ESTABLISHED)return -1;
    if(len==0)return 0;                    /* 零长度写保持合法 no-op 返回 0 */
    if(len>1460)len=1460;
    if(len>TCP_BUF_SIZE-c->snd_used)len=TCP_BUF_SIZE-c->snd_used;
    if(len==0)return -(int)CATOS_EAGAIN;   /* 缓冲满非阻塞语义，sock_xlate 直通
                                              （原「收缩到 0 返回 0」歧义消除；
                                              部分写语义本身不变） */
    memcpy_u(&c->sndb[c->snd_used],data,len);
    c->snd_used+=len;
    tcp_xmit_pending(c);
    return (int)len;
}

int tcp_recv(socket_t *s,uint8_t *buf,uint32_t max_len){
    if(!s||s->type!=SOCK_TCP_ESTAB)return -1;
    tcp_conn_t *c=s->tcp.conn;if(!c)return -1;
    /* 阶段3 E2：RST 复位后的读 → -ECONNRESET 而非哨兵 -1（假 EAGAIN）。
       本栈 RST 不清接收队列，但残留数据随连接作废，直接上报错误。 */
    if(c->dead)return -(int)CATOS_ECONNRESET;
    if(c->rxn==0){
        if(c->state==TCP_CLOSE_WAIT||c->state==TCP_LAST_ACK||c->state==TCP_TIME_WAIT)return 0;
        return -1;
    }
    uint32_t n=c->rxn;if(n>max_len)n=max_len;
    memcpy_u(buf,c->rxb,n);
    if(c->rxn>n)memcpy_u(c->rxb,c->rxb+n,c->rxn-n);
    c->rxn-=n;
    tcp_window_update_ack(c);   /* SWS 开窗：缓冲显著腾出立即补发 bare ACK
                                   （tcp_advertise_window 注释中的死锁自检闭环） */
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

void net_poll(void){
    e1000_poll();tcp_tick();
    if((int32_t)(ticks-arp_scan_deadline)>=0){arp_scan_deadline=ticks+ARP_TICK_INTERVAL;arp_tick();}
    /* ─── DHCP 租约生命周期（阶段5 第四棒）───
     * 三段截止检查各 O(1)、(int32_t) 回绕安全、PIT IRQ0(net_poll) 上下文零分配零长操作。
     * BOUND --T1--> RENEWING(单播 REQUEST(renew)) --T2--> REBINDING(广播 REQUEST(rebind))
     *   --expire--> 清地址回 DISCOVER；过期判定优先于 T1/T2（长时间停走时一次到位）。
     * 不变量：进入 BOUND 必有 dhcp_timed=true（否则停在 DONE），故截止比较免判空。 */
    uint32_t now=ticks;
    switch(dhcp_state){
    case DHCP_BOUND:
        if((int32_t)(now-dhcp_expire_due)>=0)dhcp_lease_expired();
        else if((int32_t)(now-dhcp_t1_due)>=0){
            kputs("[NET] DHCP T1 renew due\n");
            {   /* 预热 server MAC：首取流程从未单播过，直接发会撞 ARP miss 丢一轮 */
                uint8_t m[6];arp_resolve(dhcp_server,m);
            }
            dhcp_state=DHCP_RENEWING;
            dhcp_retries=0;dhcp_wait=DHCP_RETRY_BASE_SECS;dhcp_last=now;
            dhcp_xid^=(uint32_t)ip_id+0x9e3779b9u;
            dhcp_send(3,DHCP_MODE_RENEW);
        }
        break;
    case DHCP_RENEWING:
        if((int32_t)(now-dhcp_expire_due)>=0)dhcp_lease_expired();
        else if((int32_t)(now-dhcp_t2_due)>=0){          /* 单播续租未果，转广播 */
            kputs("[NET] DHCP T2 rebind due\n");
            dhcp_state=DHCP_REBINDING;
            dhcp_retries=0;dhcp_wait=DHCP_RETRY_BASE_SECS;dhcp_last=now;
            dhcp_xid^=(uint32_t)ip_id+0x9e3779b9u;
            dhcp_send(3,DHCP_MODE_REBIND);
        }
        else if(dhcp_wait&&(uint32_t)(now-dhcp_last)>=dhcp_wait*100u){   /* 单播退避重试 */
            dhcp_wait=dhcp_backoff_next(dhcp_wait);dhcp_last=now;
            dhcp_send(3,DHCP_MODE_RENEW);
        }
        break;
    case DHCP_REBINDING:
        if((int32_t)(now-dhcp_expire_due)>=0)dhcp_lease_expired();
        else if(dhcp_wait&&(uint32_t)(now-dhcp_last)>=dhcp_wait*100u){   /* 广播退避重试 */
            dhcp_wait=dhcp_backoff_next(dhcp_wait);dhcp_last=now;
            dhcp_send(3,DHCP_MODE_REBIND);
        }
        break;
    default:break;   /* 首取各态/DONE 由下方既有机器处理 */
    }
    /* 首取重试 + 静态兜底：触发条件（dhcp_retries++>=6）与地址值保持既有资产原样 */
    if((dhcp_state==DHCP_WAIT_OFFER||dhcp_state==DHCP_WAIT_ACK)&&dhcp_wait&&(uint32_t)(ticks-dhcp_last)>=dhcp_wait*100u){
        if(dhcp_retries++>=6){
            dhcp_wait=0;
            net_set_ip(hton32(0x0A00020F));net_set_gateway(hton32(0x0A000202));net_set_subnet(hton32(0xFFFFFF00));g_dns=hton32(0x0A000203);dhcp_state=DHCP_DONE;kputs("[NET] DHCP failed, fallback static\n");
            dhcp_timed=false;
        }else{
            dhcp_xid^=(uint32_t)ip_id+0x9e3779b9u;dhcp_send(1,DHCP_MODE_BOOT);dhcp_state=DHCP_WAIT_OFFER;dhcp_wait=2;dhcp_last=ticks;   /* 首取节奏原样：固定 2s */
        }
    }
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
    /* 探测网关 MAC（无回应也不阻塞，收包路径会自行补缓存） */
    dhcp_xid=0x12340000u^ip_id;dhcp_retries=0;dhcp_wait=2;dhcp_state=DHCP_DISCOVER;dhcp_send(1,DHCP_MODE_BOOT);dhcp_last=ticks;dhcp_state=DHCP_WAIT_OFFER;
    dhcp_ciaddr=0;dhcp_t1_due=0;dhcp_t2_due=0;dhcp_expire_due=0;dhcp_timed=false;
    /* 演示服务: UDP :7 echo; TCP :81 is acceptance-only.
       TCP :80 由 ring3 ext_socktest 绑定服务（blackbox 契约）：
       H2/EADDRINUSE 加固后内核演示监听会令 ring3 bind(:80) 恒返 -98，
       旧「静默附着」路径已删除，故内核不再占用 :80。 */
    /* tcp_listen(80); */
    tcp_listen(81);
    udp_open(7);
}
