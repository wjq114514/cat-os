/*
 * net_dns.c - Cat-OS 网络栈 DNS 解析器模块
 * 由 net.c 单体机械拆分而来（纯代码搬移，零行为变更）；跨模块内部符号见 net_internal.h。
 */
#include "net.h"
#include "net_internal.h"
#include "e1000.h"
#include "kernel.h"
#include "interrupts.h"
#include <stddef.h>
#include <stdint.h>

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
