#include "e1000.h"
#include "kernel.h"
#include "paging.h"
#include "pci.h"
#include "interrupts.h"
#include "net.h"
#include <stdint.h>
#define N 8
#define CTRL 0x0000
#define STATUS 0x0008
#define EERD 0x0014
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
static volatile uint8_t *mmio;static desc_t *rx,*tx;static uintptr_t rxp[N],txp[N],rbuf[N],tbuf[N];static uint8_t mac[6];static uint32_t rx_last,tx_next;
static inline uint32_t rd(uint32_t o){return *(volatile uint32_t *)(mmio+o);}static inline void wr(uint32_t o,uint32_t v){*(volatile uint32_t *)(mmio+o)=v;}
static bool eirq(uint8_t q,void *a){(void)q;(void)a;uint32_t s=rd(ICR);return s!=0;}
static void eeprom(void){for(int i=0;i<3;i++){wr(EERD,1u|((uint32_t)i<<8));for(int t=0;t<10000;t++)if(rd(EERD)&0x10){uint16_t v=(uint16_t)(rd(EERD)>>16);mac[i*2]=v&255;mac[i*2+1]=v>>8;break;}}kputs("[OK] e1000 MAC = ");for(int i=0;i<6;i++){kput_hex32(mac[i]);if(i!=5)kputs(":");}kputs("\n");}
void e1000_init(void){uint32_t id=pci_read_config(0,3,0,0,4);if((id&0xffff)!=0x8086||id>>16!=0x100e){kputs("[OK] e1000 absent\n");return;}uint32_t bar=pci_read_config(0,3,0,0x10,4)&~0xFu;mmio=(volatile uint8_t*)ioremap(bar,0x20000,_PAGE_RW|_PAGE_PCD);pci_write_config(0,3,0,4,2,pci_read_config(0,3,0,4,2)|4);wr(CTRL,rd(CTRL)|4);for(volatile int i=0;i<100000;i++);wr(CTRL,(rd(CTRL)&~4)|0x40|0x20);eeprom();wr(RAL,mac[0]|(mac[1]<<8)|(mac[2]<<16)|(mac[3]<<24));wr(RAH,mac[4]|(mac[5]<<8)|0x80000000);rx=(desc_t*)phys_to_virt(rxp[0]=pmm_alloc_page());tx=(desc_t*)phys_to_virt(txp[0]=pmm_alloc_page());for(int i=0;i<N;i++){if(i){rxp[i]=pmm_alloc_page();txp[i]=pmm_alloc_page();}rbuf[i]=pmm_alloc_page();tbuf[i]=pmm_alloc_page();rx[i].addr=rbuf[i];rx[i].status=0;tx[i].addr=tbuf[i];tx[i].status=1;}wr(RDBAL,rxp[0]);wr(RDBAH,0);wr(RDLEN,N*16);wr(RDH,0);wr(RDT,N-1);wr(TDBAL,txp[0]);wr(TDBAH,0);wr(TDLEN,N*16);wr(TDH,0);wr(TDT,0);wr(RCTL,2|4|8|0x10|0x8000|0x04000000);wr(TCTL,2|8|(15u<<4)|(63u<<12));wr(TIPG,8u|(8u<<10)|(6u<<20));wr(IMS,0x80|0x04);irq_register_handler(11,eirq,0);kputs("[OK] RX ring ready (8 desc) / TX ring ready (8 desc)\n[OK] link up\n[OK] e1000 waiting for packets...\n");}
void e1000_get_mac(uint8_t out[6]){for(int i=0;i<6;i++)out[i]=mac[i];}
uint8_t *e1000_tx_alloc(void){if(!mmio)return NULL;if(!(tx[tx_next].status&1))return NULL;return (uint8_t*)phys_to_virt(tbuf[tx_next]);}
int e1000_tx_submit(uint32_t len){uint32_t n=tx_next;if(!(tx[n].status&1))return -1;tx[n].addr=tbuf[n];if(len<60){for(uint32_t i=len;i<60;i++)((uint8_t*)phys_to_virt(tbuf[n]))[i]=0;len=60;}tx[n].len=(uint16_t)len;tx[n].cso=0;tx[n].cmd=0x0B;tx[n].status=0;tx[n].css=0;tx[n].special=0;wr(TDT,(n+1)%N);tx_next=(n+1)%N;static uint8_t dbg; if(!dbg){dbg=1;kputs("[NET] TX submit tdt=");kput_dec(rd(TDT));kputs(" tdh=");kput_dec(rd(TDH));kputs(" tctl=");kput_hex32(rd(TCTL));kputs(" cmd=");kput_hex32(tx[n].cmd);kputs(" status=");kput_hex32(tx[n].status);kputs("\n");}return 0;}
void e1000_poll(void){if(!mmio)return;uint32_t i=rx_last;if(!(rx[i].status&1))return;uint8_t *p=(uint8_t*)phys_to_virt((uintptr_t)rx[i].addr);net_handle_packet(p,rx[i].len);rx[i].status=0;rx_last=(i+1)%N;wr(RDT,i);}
