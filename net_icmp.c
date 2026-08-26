/*
 * net_icmp.c - Cat-OS 网络栈 ICMP echo/ping 模块
 * 由 net.c 单体机械拆分而来（纯代码搬移，零行为变更）；跨模块内部符号见 net_internal.h。
 */
#include "net.h"
#include "net_internal.h"
#include "e1000.h"
#include "kernel.h"
#include "interrupts.h"
#include <stddef.h>
#include <stdint.h>

static bool ping_wait,ping_received;
static uint32_t ping_dst,ping_source,ping_rx_tick;
static uint16_t ping_id,ping_seq,ping_sent_count,ping_received_count;
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
