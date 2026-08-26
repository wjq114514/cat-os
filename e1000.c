#include "e1000.h"
#include "kernel.h"
#include "paging.h"
#include "pci.h"
#include "interrupts.h"
#include "net.h"
#include <stdint.h>
/* 环大小宏（所有消费点均在 e1000.c：描述符页/buffer 数组、RDLEN/TDLEN/RDT、
 * submit/poll 的模运算、init 打印）。RX 维持 8 不动以保持基线行为；
 * TX 扩容 8→32：tcp_put_pkt→begin_ip→e1000_tx_alloc 在 TX 环耗尽时返回 NULL，
 * 上层只能整段放弃发送留待重传，扩容直接降低耗尽概率。 */
#define RX_N 8
#define TX_N 32
#define CTRL 0x0000
#define STATUS 0x0008
#define EERD 0x0014
#define MDIC 0x0010
/* MDIC 位域（偏移 0x0010；与 Linux e100 驱动及 QEMU set_mdic 一致的编码）：
 * [15:0] DATA 读/写数据   [20:16] REGADD PHY 寄存器号   [25:21] PHYADD PHY 地址
 * [27:26] OP（01b=写，10b=读）  [28] R Ready（硬件置位）  [29] I 中断使能  [30] Error */
#define MDIC_OP_READ (0x08000000u)
#define MDIC_PHY_INT (0x1u<<21)  /* 内部 PHY 地址 01h */
#define MDIC_READY   (0x10000000u)
/* MII 标准寄存器（IEEE 802.3 clause 22） */
#define MII_BMCR 0              /* 控制：bit15 复位 bit11 掉电 bit12 自协商 */
#define MII_BMSR 1              /* 状态 1：bit2 Link Status（锁存低有效） */
#define MII_BMSR_LINK (1u<<2)
/* MSI 编译期开关：默认 0 = 走 INTx(irq11)，QEMU 基线行为零变化。
 * 置 1 后 e1000_init 会调用 enable_msi()（真机步骤见该函数注释）。 */
#define E1000_MSI_ENABLE 0
#define RCTL 0x0100
#define TCTL 0x0400
#define TIPG 0x0410
#define IMS 0x00D0
#define ICR 0x00C0
#define RDBAL 0x2800
#define RDBAH 0x2804
#define RDLEN 0x2808
#define RDH 0x2810
#define RDT 0x2818
#define TDBAL 0x3800
#define TDBAH 0x3804
#define TDLEN 0x3808
#define TDH 0x3810
#define TDT 0x3818
#define RAL 0x5400
#define RAH 0x5404
typedef struct {uint64_t addr;uint16_t len;uint8_t cso,cmd,status,css;uint16_t special;} __attribute__((packed)) desc_t;
static volatile uint8_t *mmio;static desc_t *rx,*tx;static uintptr_t rxp[RX_N],txp[TX_N],rbuf[RX_N],tbuf[TX_N];static uint8_t mac[6];static uint32_t rx_last,tx_next;
static inline uint32_t rd(uint32_t o){return *(volatile uint32_t *)(mmio+o);}static inline void wr(uint32_t o,uint32_t v){*(volatile uint32_t *)(mmio+o)=v;}
static bool eirq(uint8_t q,void *a){(void)q;(void)a;uint32_t s=rd(ICR);return s!=0;}
/* MII 寄存器读（MDIC 偏移协议）：写 OP=READ+PHYADD+REGADD 到 MDIC，
 * 轮询 Ready(bit28)，取回 DATA[15:0]。带超时护栏，真机 PHY 不响应时返 0xFFFF。 */
static uint16_t mii_read(uint8_t reg){
    wr(MDIC,MDIC_OP_READ|MDIC_PHY_INT|(((uint32_t)reg&0x1f)<<16));
    for(int t=0;t<200000;t++){if(rd(MDIC)&MDIC_READY)return (uint16_t)(rd(MDIC));}
    return 0xffffu;
}
static void eeprom(void){for(int i=0;i<3;i++){wr(EERD,1u|((uint32_t)i<<8));for(int t=0;t<10000;t++)if(rd(EERD)&0x10){uint16_t v=(uint16_t)(rd(EERD)>>16);mac[i*2]=v&255;mac[i*2+1]=v>>8;break;}}kputs("[OK] e1000 MAC = ");for(int i=0;i<6;i++){kput_hex32(mac[i]);if(i!=5)kputs(":");}kputs("\n");}
/* ══════════ MSI 启用通路（编译期默认关：E1000_MSI_ENABLE=0 时不调用） ══════════
 * 基于 pci.c（commit 40fffc4）已探测的 MSI capability 地址。真机启用步骤：
 *   1. 自行走 capability 链（Status.bit4 → Cap Ptr @0x34）定位 cap id=0x05；
 *      pci.c 只在扫描时打印 msi@off/addr/data，未导出设备句柄，故此处复用
 *      pci_read_config 重走一遍（只读配置空间，无副作用）。
 *   2. Message Address（cap+4）= 0xFEE00000（Local APIC 基址；bit3 Redirection
 *      Hint=0、bit2 Delivery Mode=00b → Fixed/physical 投递到 CPU0）。
 *      64bit capable 时 Message Upper Address（cap+8）写 0。
 *   3. Message Data（32bit 格式 cap+8 / 64bit 格式 cap+12）低 8 位 = 向量号。
 *      取 IRQ11 对应向量 0x20+11=0x2B，高位保持 0 = edge 触发固定投递。
 *      注意：该向量必须与 IDT 接线一致——MSI 不经 PIC/IOAPIC 缩放，
 *      irq_register_handler(11,...) 的 INTx 路径映射不适用，启用前须先接好
 *      IDT[0x2B]→eirq，否则中断静默丢失。
 *   4. Per-Vector Masking capable（control.bit8）时存在 Mask Bits 寄存器
 *      （32bit 格式 cap+0x0C / 64bit 格式 cap+0x10），其复位值为全 1（全屏蔽）；
 *      必须对所用向量的 mask 位清零（本驱动单向量 → bit0），否则中断永远到不了。
 *   5. 最后置 control.bit0 = MSI Enable；随后可置 Command.bit10 INTx Disable
 *      封死传统引脚，防止同一事件双报。
 * INTx 回退策略：enable_msi() 返回后若超时窗口内收不到中断（链路有流量而
 * ICR 恒为 0），清 control.bit0 关 MSI、清 Command.bit10 放行 INTx 引脚即可
 * 回退；本文件的 IMS 武装与 irq_register_handler(11,eirq,0) 全程保留不动，
 * 两种模式共用同一 ISR。 */
static void __attribute__((unused)) enable_msi(uint8_t bus,uint8_t dev,uint8_t fn){
    uint16_t st=pci_read_config(bus,dev,fn,6,2);
    if(!(st&0x0010))return;                                  /* 无 capability 链 */
    uint8_t off=(uint8_t)pci_read_config(bus,dev,fn,0x34,1);
    for(int g=0;g<48&&off>=0x40&&!(off&3);g++){
        if((uint8_t)pci_read_config(bus,dev,fn,off,1)==0x05)break;
        uint8_t next=(uint8_t)pci_read_config(bus,dev,fn,(uint8_t)(off+1),1);
        if(!next||next==off)return;
        off=next;
    }
    if(off<0x40||(off&3)||(uint8_t)pci_read_config(bus,dev,fn,off,1)!=0x05)return;
    uint16_t mc=(uint16_t)pci_read_config(bus,dev,fn,(uint8_t)(off+2),2);
    uint8_t is64=(uint8_t)((mc>>7)&1);
    pci_write_config(bus,dev,fn,(uint8_t)(off+4),4,0xFEE00000u);          /* Msg Addr */
    if(is64)pci_write_config(bus,dev,fn,(uint8_t)(off+8),4,0);            /* Upper Addr */
    pci_write_config(bus,dev,fn,(uint8_t)(is64?off+12:off+8),2,(uint16_t)(0x20+11)); /* Data: vector */
    if(mc&0x0100){                                                        /* per-vector mask */
        uint8_t mo=(uint8_t)(is64?off+16:off+12);
        uint32_t mask=pci_read_config(bus,dev,fn,mo,4);
        pci_write_config(bus,dev,fn,mo,4,mask&~1u);                       /* 开放 bit0 向量 */
    }
    pci_write_config(bus,dev,fn,(uint8_t)(off+2),2,(uint16_t)(mc|1));     /* MSI Enable */
    uint16_t cmd=(uint16_t)pci_read_config(bus,dev,fn,4,2);
    pci_write_config(bus,dev,fn,4,2,(uint16_t)(cmd|0x0400));              /* INTx Disable */
}
void e1000_init(void){uint32_t id=pci_read_config(0,3,0,0,4);if((id&0xffff)!=0x8086||id>>16!=0x100e){kputs("[OK] e1000 absent\n");return;}uint32_t bar=pci_read_config(0,3,0,0x10,4)&~0xFu;mmio=(volatile uint8_t*)ioremap(bar,0x20000,_PAGE_RW|_PAGE_PCD);pci_write_config(0,3,0,4,2,pci_read_config(0,3,0,4,2)|4);wr(CTRL,rd(CTRL)|4);for(volatile int i=0;i<100000;i++);wr(CTRL,(rd(CTRL)&~4)|0x40|0x20);eeprom();wr(RAL,mac[0]|(mac[1]<<8)|(mac[2]<<16)|(mac[3]<<24));wr(RAH,mac[4]|(mac[5]<<8)|0x80000000);rx=(desc_t*)phys_to_virt(rxp[0]=pmm_alloc_page());tx=(desc_t*)phys_to_virt(txp[0]=pmm_alloc_page());for(int i=0;i<RX_N;i++){if(i)rxp[i]=pmm_alloc_page();rbuf[i]=pmm_alloc_page();rx[i].addr=rbuf[i];rx[i].status=0;}for(int i=0;i<TX_N;i++){if(i)txp[i]=pmm_alloc_page();tbuf[i]=pmm_alloc_page();tx[i].addr=tbuf[i];tx[i].status=1;}wr(RDBAL,rxp[0]);wr(RDBAH,0);wr(RDLEN,RX_N*16);wr(RDH,0);wr(RDT,RX_N-1);wr(TDBAL,txp[0]);wr(TDBAH,0);wr(TDLEN,TX_N*16);wr(TDH,0);wr(TDT,0);wr(RCTL,2|4|8|0x10|0x8000|0x04000000);wr(TCTL,2|8|(15u<<4)|(63u<<12));wr(TIPG,8u|(8u<<10)|(6u<<20));
#if E1000_MSI_ENABLE
    enable_msi(0,3,0);   /* 真机启用：先接好 IDT 向量 0x2B 再开此开关（见 enable_msi 注释） */
#endif
wr(IMS,0x80|0x04);irq_register_handler(11,eirq,0);
/* PHY 链路检测：读 BMCR(0) 供诊断，读 BMSR(1) 两次——IEEE 802.3 cl22 的
 * Link Status 为锁存低有效，第一次读清除自上次读取以来锁存的失败态，
 * 第二次读才是实时值。QEMU e1000 内部 PHY 恒报 up，输出与基线一致。 */
{uint16_t bmcr=mii_read(MII_BMCR);uint16_t bmsr=mii_read(MII_BMSR);bmsr=mii_read(MII_BMSR);
 kputs("[OK] RX ring ready (8 desc) / TX ring ready (32 desc)\n");
 if(bmsr&MII_BMSR_LINK)kputs("[OK] link up\n");
 else{kputs("[WARN] e1000 link down bmsr=");kput_hex32(bmsr);kputs(" bmcr=");kput_hex32(bmcr);kputs("\n");}
 kputs("[OK] e1000 waiting for packets...\n");}}
void e1000_get_mac(uint8_t out[6]){for(int i=0;i<6;i++)out[i]=mac[i];}
uint8_t *e1000_tx_alloc(void){if(!mmio)return NULL;if(!(tx[tx_next].status&1))return NULL;return (uint8_t*)phys_to_virt(tbuf[tx_next]);}
int e1000_tx_submit(uint32_t len){uint32_t n=tx_next;if(!(tx[n].status&1))return -1;tx[n].addr=tbuf[n];if(len<60){for(uint32_t i=len;i<60;i++)((uint8_t*)phys_to_virt(tbuf[n]))[i]=0;len=60;}tx[n].len=(uint16_t)len;tx[n].cso=0;tx[n].cmd=0x0B;tx[n].status=0;tx[n].css=0;tx[n].special=0;wr(TDT,(n+1)%TX_N);tx_next=(n+1)%TX_N;static uint8_t dbg; if(!dbg){dbg=1;kputs("[NET] TX submit tdt=");kput_dec(rd(TDT));kputs(" tdh=");kput_dec(rd(TDH));kputs(" tctl=");kput_hex32(rd(TCTL));kputs(" cmd=");kput_hex32(tx[n].cmd);kputs(" status=");kput_hex32(tx[n].status);kputs("\n");}return 0;}
void e1000_poll(void){if(!mmio)return;uint32_t i=rx_last;if(!(rx[i].status&1))return;uint8_t *p=(uint8_t*)phys_to_virt((uintptr_t)rx[i].addr);net_handle_packet(p,rx[i].len);rx[i].status=0;rx_last=(i+1)%RX_N;wr(RDT,i);}
