/*
 * net_tcp.c - Cat-OS 网络栈 TCP 模块（状态机/拥塞控制/SACK/RTO 全量）
 * 由 net.c 单体机械拆分而来（纯代码搬移，零行为变更）；跨模块内部符号见 net_internal.h。
 */
#include "net.h"
#include "net_internal.h"
#include "e1000.h"
#include "kernel.h"
#include "interrupts.h"
#include <stddef.h>
#include <stdint.h>

uint32_t seq_gen=0x12340000; /* 本地 TCP ISN 生成器（原 net.c:32，net_dns.c 经 net_internal.h 只读派生 txid） */
/* ═══════════ TCP ═══════════ */
tcp_conn_t tcp_conns[TCP_MAX_CONNS];
static socket_t  tcp_socks[TCP_MAX_CONNS];
socket_t  tcp_handles[TCP_MAX_CONNS];
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

void tcp_tx_reset(tcp_conn_t *c){
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
void tcp_cc_init(tcp_conn_t *c){
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
tcp_conn_t *tcp_conn_find_listen(uint16_t port){for(int i=0;i<TCP_MAX_CONNS;i++)if(tcp_conns[i].used&&tcp_conns[i].state==TCP_LISTEN&&tcp_conns[i].lport==port)return &tcp_conns[i];return NULL;}
static uint32_t tcp_pending_count(uint16_t port){
    uint32_t n=0;
    for(int i=0;i<TCP_MAX_CONNS;i++){
        tcp_conn_t *c=&tcp_conns[i];
        if(c->used&&!c->accepted&&c->lport==port&&
           (c->state==TCP_SYN_RECEIVED||c->state==TCP_ESTABLISHED))n++;
    }
    return n;
}
void tcp_drop_pending(uint16_t port){
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
void tcp_tick(void){
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
