/*
 * net_arp.c - Cat-OS 网络栈 ARP 模块
 * 由 net.c 单体机械拆分而来（纯代码搬移，零行为变更）；跨模块内部符号见 net_internal.h。
 */
#include "net.h"
#include "net_internal.h"
#include "e1000.h"
#include "kernel.h"
#include "interrupts.h"
#include <stddef.h>
#include <stdint.h>

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
void arp_handle(const uint8_t *p,uint32_t len){
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

/* 周期调度闸（原 net_poll:1588 内联语句逐字搬移，时序不变） */
void arp_poll(void){
    if((int32_t)(ticks-arp_scan_deadline)>=0){arp_scan_deadline=ticks+ARP_TICK_INTERVAL;arp_tick();}
}
