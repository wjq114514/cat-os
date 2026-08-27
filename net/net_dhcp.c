/*
 * net_dhcp.c - Cat-OS 网络栈 DHCP 客户端全状态机模块
 * 由 net.c 单体机械拆分而来（纯代码搬移，零行为变更）；跨模块内部符号见 net_internal.h。
 */
#include "net.h"
#include "net_internal.h"
#include "e1000.h"
#include "kernel.h"
#include "interrupts.h"
#include <stddef.h>
#include <stdint.h>

static uint32_t dhcp_xid, dhcp_offer, dhcp_server, dhcp_mask, dhcp_gw;
static uint32_t dhcp_last, dhcp_wait;
static uint32_t dhcp_ciaddr;         /* 网络序：当前租约地址，RENEW/REBIND REQUEST 的 ciaddr */
static uint8_t dhcp_state, dhcp_retries;
/* 租约截止（绝对 ticks，比较一律 (int32_t)(ticks-due)>=0 回绕安全）；
 * dhcp_timed=false 表示无租期信息（option 51 缺失）——三截止不生效，
 * 维持旧 DHCP_DONE 死态语义。 */
static uint32_t dhcp_t1_due,dhcp_t2_due,dhcp_expire_due;
static bool dhcp_timed;
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

void dhcp_handle(const uint8_t *d,uint32_t n){
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
void dhcp_tick(void){
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

/* 启动探测（原 net_init:1658-1660 内联语句逐字搬移） */
void dhcp_start(void){
    /* 探测网关 MAC（无回应也不阻塞，收包路径会自行补缓存） */
    dhcp_xid=0x12340000u^ip_id;dhcp_retries=0;dhcp_wait=2;dhcp_state=DHCP_DISCOVER;dhcp_send(1,DHCP_MODE_BOOT);dhcp_last=ticks;dhcp_state=DHCP_WAIT_OFFER;
    dhcp_ciaddr=0;dhcp_t1_due=0;dhcp_t2_due=0;dhcp_expire_due=0;dhcp_timed=false;
}
