#include "pci.h"
#include "kernel.h"
#include "paging.h"
static inline void outl(uint16_t p,uint32_t v){__asm__ volatile("outl %0,%1"::"a"(v),"Nd"(p));}
static inline uint32_t inl(uint16_t p){uint32_t v;__asm__ volatile("inl %1,%0":"=a"(v):"Nd"(p));return v;}
uint32_t pci_read_config(uint8_t b,uint8_t d,uint8_t f,uint8_t o,uint8_t s){outl(0xCF8,0x80000000u|((uint32_t)b<<16)|((uint32_t)d<<11)|((uint32_t)f<<8)|(o&0xFC));uint32_t v=inl(0xCFC)>>(8*(o&3));return s==1?v&0xFF:s==2?v&0xFFFF:v;}
void pci_write_config(uint8_t b,uint8_t d,uint8_t f,uint8_t o,uint8_t s,uint32_t v){uint32_t old=pci_read_config(b,d,f,o&0xFC,4),sh=8*(o&3),mask=s==1?0xFFu:s==2?0xFFFFu:0xFFFFFFFFu;outl(0xCF8,0x80000000u|((uint32_t)b<<16)|((uint32_t)d<<11)|((uint32_t)f<<8)|(o&0xFC));outl(0xCFC,(old&~(mask<<sh))|((v&mask)<<sh));}
static int get(uint8_t b,uint8_t d,uint8_t f,pci_device_t *p){
    uint32_t id=pci_read_config(b,d,f,0,4);
    if((id&0xFFFF)==0xFFFF)return 0;
    uint32_t c=pci_read_config(b,d,f,8,4);
    p->bus=b;p->dev=d;p->fn=f;p->vendor=id;p->device=id>>16;p->class_code=c>>24;p->subclass=c>>16;
    p->header_type=pci_read_config(b,d,f,0xE,1);
    p->msi_cap_off=0;p->msi_ctrl=0;p->msi_64bit=0;p->msi_msg_addr=0;p->msi_msg_data=0;
    p->msix_cap_off=0;p->msix_table_size=0;p->msix_table_bar=0;p->msix_table_off=0;
    p->msix_pba_bar=0;p->msix_pba_off=0;
    return 1;
}
static void probe_caps(pci_device_t *p){
    uint16_t st=pci_read_config(p->bus,p->dev,p->fn,6,2);
    if(!(st&0x0010))return;
    uint8_t off=(uint8_t)pci_read_config(p->bus,p->dev,p->fn,0x34,1);
    for(int g=0;g<48&&off>=0x40&&!(off&3);g++){
        uint8_t id=(uint8_t)pci_read_config(p->bus,p->dev,p->fn,off,1);
        uint8_t next=(uint8_t)pci_read_config(p->bus,p->dev,p->fn,(uint8_t)(off+1),1);
        if(id==0x05&&!p->msi_cap_off){
            p->msi_cap_off=off;
            uint16_t mc=(uint16_t)pci_read_config(p->bus,p->dev,p->fn,(uint8_t)(off+2),2);
            p->msi_ctrl=mc;
            p->msi_64bit=(uint8_t)((mc>>7)&1);
            p->msi_msg_addr=pci_read_config(p->bus,p->dev,p->fn,(uint8_t)(off+4),4);
            p->msi_msg_data=(uint16_t)pci_read_config(p->bus,p->dev,p->fn,(uint8_t)(p->msi_64bit?off+12:off+8),2);
        }else if(id==0x11&&!p->msix_cap_off){
            p->msix_cap_off=off;
            uint16_t mc=(uint16_t)pci_read_config(p->bus,p->dev,p->fn,(uint8_t)(off+2),2);
            p->msix_table_size=(uint16_t)((mc&0x7FF)+1);
            uint32_t t=pci_read_config(p->bus,p->dev,p->fn,(uint8_t)(off+4),4);
            p->msix_table_bar=(uint8_t)(t&7);p->msix_table_off=t&~7u;
            uint32_t pb=pci_read_config(p->bus,p->dev,p->fn,(uint8_t)(off+8),4);
            p->msix_pba_bar=(uint8_t)(pb&7);p->msix_pba_off=pb&~7u;
        }
        if(!next||next==off)break;
        off=next;
    }
}
static void print_bar(const pci_device_t *p,uint8_t i){uint8_t o=0x10+4*i;uint32_t v=pci_read_config(p->bus,p->dev,p->fn,o,4);if(!v)return;pci_write_config(p->bus,p->dev,p->fn,o,4,0xFFFFFFFF);uint32_t m=pci_read_config(p->bus,p->dev,p->fn,o,4);pci_write_config(p->bus,p->dev,p->fn,o,4,v);uint32_t mask=(v&1)?0xFFFFFFFCu:0xFFFFFFF0u,size=(~(m&mask))+1;kputs(" BAR");kput_dec(i);kputs((v&1)?" IO=":" MMIO=");kput_hex32(v&mask);kputs(" size=");kput_hex32(size);if(!(v&1)&&p->vendor==0x8086&&(p->device==0x100E||p->device==0x100F)){void *map=ioremap(v&mask,size,_PAGE_RW|_PAGE_PCD);kputs(" mapped=");kput_hex32((uint32_t)map);} }
static uint8_t bus_q[256],bus_vis[32];
static void pci_walk(uint8_t cl,uint8_t sub,pci_class_callback_t cb,void *arg,int verbose){
    for(int i=0;i<32;i++)bus_vis[i]=0;
    bus_q[0]=0;bus_vis[0]=1;
    unsigned head=0,tail=1;
    while(head<tail){
        uint8_t b=bus_q[head++];
        if(verbose){kputs("[OK] PCI scanning bus ");kput_dec(b);kputs("\n");}
        for(uint8_t d=0;d<32;d++){
            uint8_t n=1;pci_device_t p;
            if(!get(b,d,0,&p))continue;
            if(p.header_type&0x80)n=8;
            for(uint8_t f=0;f<n;f++){
                if(!get(b,d,f,&p))continue;
                probe_caps(&p);
                if(cb&&p.class_code==cl&&(sub==0xFF||p.subclass==sub)){cb(&p,arg);continue;}
                if(!verbose)continue;
                kputs("[OK] PCI ");kput_dec(b);kputs(":");kput_dec(d);kputs(".");kput_dec(f);
                kputs(" id=");kput_hex32(((uint32_t)p.vendor<<16)|p.device);
                kputs(" class=");kput_hex32(((uint32_t)p.class_code<<8)|p.subclass);
                if(p.class_code==0x06&&p.subclass==0x04){
                    uint8_t sec=(uint8_t)pci_read_config(b,d,f,0x19,1),sbo=(uint8_t)pci_read_config(b,d,f,0x1A,1);
                    kputs(" bridge sec=");kput_dec(sec);kputs(" sub=");kput_dec(sbo);
                    if(sec&&sec!=0xFF&&!(bus_vis[sec>>3]&(1u<<(sec&7)))&&tail<256){
                        bus_vis[sec>>3]|=(uint8_t)(1u<<(sec&7));bus_q[tail++]=sec;
                    }
                }
                if(p.msi_cap_off){
                    kputs(" msi@");kput_hex32(p.msi_cap_off);
                    kputs(" addr=");kput_hex32(p.msi_msg_addr);
                    kputs(" data=");kput_hex32(p.msi_msg_data);
                    if(p.msi_64bit)kputs(" 64b");
                }
                if(p.msix_cap_off){
                    kputs(" msix@");kput_hex32(p.msix_cap_off);
                    kputs(" table=BAR");kput_dec(p.msix_table_bar);
                    kputs("+");kput_hex32(p.msix_table_off);
                    kputs(" n=");kput_dec(p.msix_table_size);
                }
                uint8_t bars=(p.header_type&0x7F)==0?6:2;
                for(uint8_t i=0;i<bars;i++)print_bar(&p,i);
                kputs("\n");
            }
        }
    }
}
void pci_find_class(uint8_t class_code,uint8_t subclass,pci_class_callback_t cb,void *arg){pci_walk(class_code,subclass,cb,arg,0);}
void pci_init(void){kputs("[OK] PCI config mechanism #1 recursive scan (bridge aware, MSI/MSI-X probe)\n");pci_walk(0,0,NULL,NULL,1);}
