/*
 * net_udp.c - Cat-OS 网络栈 UDP 模块
 * 由 net.c 单体机械拆分而来（纯代码搬移，零行为变更）；跨模块内部符号见 net_internal.h。
 */
#include "net.h"
#include "net_internal.h"
#include "e1000.h"
#include "kernel.h"
#include "interrupts.h"
#include <stddef.h>
#include <stdint.h>

/* ═══════════ UDP ═══════════（原 net.c:333 段注释；UDP_SLOTS/UDP_RXBUF/udp_sock_t 见 net_internal.h） */
udp_sock_t udp_socks[UDP_SLOTS];
socket_t udp_handles[UDP_SLOTS];
udp_sock_t *udp_sock_by_port(uint16_t port){for(int i=0;i<UDP_SLOTS;i++)if(udp_socks[i].used&&udp_socks[i].bound&&udp_socks[i].lport==port)return &udp_socks[i];return NULL;}
udp_sock_t *udp_sock_find_free(void){for(int i=0;i<UDP_SLOTS;i++)if(!udp_socks[i].used)return &udp_socks[i];return NULL;}

bool udp_send(uint32_t dst_ip,uint16_t dst_port,uint16_t src_port,const uint8_t *data,uint32_t len){
    uint8_t dmac[6];if(!arp_resolve(dst_ip,dmac))return false;
    uint8_t *seg=begin_ip(dst_ip,IP_PROTO_UDP,dmac);if(!seg)return false;
    udp_hdr_t *u=(udp_hdr_t*)seg;
    u->src_port=hton16(src_port);u->dst_port=hton16(dst_port);u->len=hton16((uint16_t)(8+len));u->csum=0;
    memcpy_u(seg+8,data,len);
    return end_ip(seg,8+len,IP_PROTO_UDP);
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

short udp_socket_poll(socket_t *s, short events)
{
    udp_sock_t *u;
    short revents = 0;

    if (!s || (s->type != SOCK_UDP && s->type != SOCK_UDP_UNBOUND))
        return NET_POLLNVAL;

    if (s->type == SOCK_UDP_UNBOUND)
        return 0;

    u = (s->udp.slot < UDP_SLOTS && udp_socks[s->udp.slot].used)
        ? &udp_socks[s->udp.slot] : udp_sock_by_port(s->udp.lport);
    if (!u)
        return NET_POLLERR | NET_POLLHUP;

    /* A queued datagram is the UDP equivalent of readable stream data.
     * A bound Cat-OS UDP socket has no local send queue, so sendto() can
     * accept a datagram whenever the descriptor is valid. */
    if ((events & NET_POLLIN) && u->n)
        revents |= NET_POLLIN;
    if (events & NET_POLLOUT)
        revents |= NET_POLLOUT;
    return revents;
}
