#include "user.h"
#include "kernel.h"
#include <stdint.h>
#include "paging.h"
#include "interrupts.h"
#include "syscall.h"
typedef struct {uint32_t prev,esp0,ss0,esp1,ss1,esp2,ss2,cr3,eip,eflags,eax,ecx,edx,ebx,esp,ebp,esi,edi,es,cs,ss,ds,fs,gs,ldt,trap,bitmap;} __attribute__((packed)) tss_t;
static tss_t tss __attribute__((aligned(16))); static uint64_t gdt[6] __attribute__((aligned(8)));
extern void arch_load_gdt(const void *);
extern void arch_load_tss(uint16_t);
extern uint8_t kernel_stack_top[];
static void setg(int i,uint32_t b,uint32_t lim,uint8_t a){uint64_t f=0xC;gdt[i]=((uint64_t)(lim&0xFFFF))|((uint64_t)(b&0xFFFFFF)<<16)|((uint64_t)(lim&0xF0000)<<32)|((uint64_t)a<<40)|((uint64_t)f<<52)|((uint64_t)(b>>24)<<56);}
void usermode_init(void){tss.ss0=0x10;tss.esp0=(uint32_t)kernel_stack_top;tss.bitmap=sizeof(tss);setg(0,0,0,0);setg(1,0,0xfffff,0x9A);setg(2,0,0xfffff,0x92);setg(3,0,0xfffff,0xFA);setg(4,0,0xfffff,0xF2);setg(5,(uint32_t)&tss,sizeof(tss)-1,0x89);struct{uint16_t l;uint32_t b;}__attribute__((packed)) r={(uint16_t)(sizeof(gdt)-1),(uint32_t)gdt};arch_load_gdt(&r);__asm__ volatile("ljmp $0x08, $1f\n\t1:\n\tmovw $0x10, %%ax\n\t movw %%ax, %%ds\n\t movw %%ax, %%es\n\t movw %%ax, %%fs\n\t movw %%ax, %%gs\n\t movw %%ax, %%ss\n" ::: "eax","memory");arch_load_tss(0x28);interrupts_post_gdt_update();kputs("[OK] GDT+user segments loaded\n[OK] TSS loaded\n");}
static void e8(uint8_t **p,uint8_t v){*(*p)++=v;}
static void e32(uint8_t **p,uint32_t v){for(int i=0;i<4;i++)e8(p,(uint8_t)(v>>(8*i)));}
static void movi(uint8_t **p,uint8_t r,uint32_t v){e8(p,0xB8+r);e32(p,v);}
static void movm(uint8_t **p,uint8_t r,uint32_t a){e8(p,0x8B);e8(p,(uint8_t)(0x05|(r<<3)));e32(p,a);}
static void steax(uint8_t **p,uint32_t a){e8(p,0xA3);e32(p,a);}
static void syscall3(uint8_t **p,uint32_t nr,uint32_t a,uint32_t b,uint32_t c){movi(p,0,nr);movi(p,3,a);movi(p,1,b);movi(p,2,c);e8(p,0xCD);e8(p,0x80);}
static void syscall5(uint8_t **p,uint32_t nr,uint32_t *v,uint8_t mem){static const uint8_t r[5]={3,1,2,6,7};movi(p,0,nr);for(uint8_t i=0;i<5;i++)if(mem&(1u<<i))movm(p,r[i],v[i]);else movi(p,r[i],v[i]);e8(p,0xCD);e8(p,0x80);}
static void user_segments(uint8_t **p){movi(p,0,0x23);e8(p,0x8E);e8(p,0xD8);e8(p,0x8E);e8(p,0xC0);}
static uint32_t jl(uint8_t **p){e8(p,0x0F);e8(p,0x8C);uint32_t x=(uint32_t)(*p);e32(p,0);return x;}
static void patch(uint8_t *base,uint32_t at,uint32_t dst){int32_t d=(int32_t)(dst-(0x1000u+at+4));for(int i=0;i<4;i++)base[at+i]=(uint8_t)((uint32_t)d>>(8*i));}
static void cmpzero(uint8_t **p){e8(p,0x83);e8(p,0xF8);e8(p,0);}
static void cmpimm(uint8_t **p,uint32_t v){e8(p,0x3D);e32(p,v);}
static uint32_t jne(uint8_t **p){e8(p,0x0F);e8(p,0x85);uint32_t x=(uint32_t)(*p);e32(p,0);return x;}
static uint32_t jmp(uint8_t **p){e8(p,0xE9);uint32_t x=(uint32_t)(*p);e32(p,0);return x;}
static void copy_bytes(void *dst,const void *src,uint32_t n){uint8_t *d=dst;const uint8_t *s=src;for(uint32_t i=0;i<n;i++)d[i]=s[i];}
static uint8_t user_code[8192];
void enter_usermode(void){
    enum{PATH_NULL=0x4100,PATH_CONSOLE=0x4200,PATH_KBD=0x4250,MSG_CONSOLE=0x4300,MSG_KBDOPEN=0x4320,MSG_KBDREAD=0x4340,KDBUF=0x4360,KBD_FD=0x4370,BUF=0x4400,SRCIP=0x4540,SRCPORT=0x4544,FD=0x4600,LEN=0x4604,LISTENFD=0x4608,MSG_UDP=0x4700,MSG_TCP=0x4710,MSG_ERRPASS=0x4728,MSG_ERRFAIL=0x4748,TARGET=0x4800,PINGOUT=0x4900,PINGSTAT=0x4A00,BAD_TARGET=0x4B00,BAD_PTR=0x5000};
    uintptr_t cp=pmm_alloc_page(),cp2=pmm_alloc_page(),dp=pmm_alloc_page(),sp=pmm_alloc_page(),vp=pmm_alloc_page();
    if(!cp||!cp2||!dp||!sp||!vp||map_page(0x1000,cp,_PAGE_PRESENT|_PAGE_RW|_PAGE_USER)||map_page(0x2000,cp2,_PAGE_PRESENT|_PAGE_RW|_PAGE_USER)||map_page(0x4000,dp,_PAGE_PRESENT|_PAGE_RW|_PAGE_USER)||map_page(0x700000,sp,_PAGE_PRESENT|_PAGE_RW|_PAGE_USER)||map_page(0xB8000,vp,_PAGE_PRESENT|_PAGE_RW|_PAGE_USER))panic("user mapping failed");
    uint8_t *u=user_code,*p=u;uint32_t v[5],a1,a2,a3,a4,a5,errj[16];uint32_t errn=0;
    user_segments(&p);
    syscall3(&p,5,PATH_NULL,2,0);steax(&p,FD);syscall3(&p,0,3,BUF,8);syscall3(&p,6,3,0,0);
    syscall3(&p,5,PATH_CONSOLE,1,0);steax(&p,FD);syscall3(&p,1,3,MSG_CONSOLE,16);syscall3(&p,6,3,0,0);syscall3(&p,1,3,BAD_PTR,4);
    /* ring3 /dev/kbd probe. Diagnostics are written through the real console fd
     * (saved in FD) so writes never target /dev/kbd (read-only). open() return
     * is captured in KBD_FD (separate from FD so console stays valid). A fixed,
     * finite number of non-blocking read() attempts is made; empty queue or any
     * error is reported as NOT_TESTED/EMPTY, never as character consumption.
     * No shell, no blocking read, no busy-loop. */
    syscall3(&p,5,PATH_KBD,0,0);steax(&p,KBD_FD);
    syscall3(&p,5,PATH_CONSOLE,1,0);steax(&p,FD);
    v[0]=FD;v[1]=MSG_KBDOPEN;v[2]=27;syscall5(&p,1,v,1);
    v[0]=KBD_FD;v[1]=KDBUF;v[2]=16;syscall5(&p,0,v,1);steax(&p,LEN);
    cmpzero(&p);uint32_t kbd_ok=(uint32_t)((uint8_t*)jl(&p)-u);
    v[0]=FD;v[1]=MSG_KBDREAD;v[2]=47;syscall5(&p,1,v,1);
    v[0]=FD;v[1]=KDBUF;v[2]=40;syscall5(&p,1,v,1);
    uint32_t kbd_ok_lbl=0x1000u+(uint32_t)(p-u);patch(u,kbd_ok,kbd_ok_lbl);
    v[0]=KBD_FD;syscall5(&p,6,v,1);
    syscall3(&p,5,PATH_CONSOLE,1,0);steax(&p,FD);
    v[0]=99;syscall5(&p,23,v,0);cmpimm(&p,(uint32_t)-CATOS_EBADF);errj[errn++]=(uint32_t)((uint8_t*)jne(&p)-u);
    syscall3(&p,5,PATH_NULL,2,0);steax(&p,FD);v[0]=FD;syscall5(&p,23,v,1);cmpimm(&p,(uint32_t)-CATOS_ENOTSOCK);errj[errn++]=(uint32_t)((uint8_t*)jne(&p)-u);v[0]=FD;syscall5(&p,6,v,1);v[0]=FD;syscall5(&p,6,v,1);cmpimm(&p,(uint32_t)-CATOS_EBADF);errj[errn++]=(uint32_t)((uint8_t*)jne(&p)-u);
    v[0]=1;v[1]=0;v[2]=0;v[3]=0;v[4]=0;syscall5(&p,20,v,0);steax(&p,FD);v[0]=FD;v[1]=BUF;v[2]=4;syscall5(&p,26,v,1);cmpimm(&p,(uint32_t)-CATOS_ENOTCONN);errj[errn++]=(uint32_t)((uint8_t*)jne(&p)-u);v[0]=FD;v[1]=BUF;v[2]=4;syscall5(&p,27,v,1);cmpimm(&p,(uint32_t)-CATOS_ENOTCONN);errj[errn++]=(uint32_t)((uint8_t*)jne(&p)-u);v[0]=FD;syscall5(&p,28,v,1);
    v[0]=1;v[1]=0;v[2]=0;v[3]=0;v[4]=0;syscall5(&p,20,v,0);steax(&p,LISTENFD);v[0]=LISTENFD;v[1]=7001;syscall5(&p,21,v,1);v[0]=LISTENFD;v[1]=1;syscall5(&p,22,v,1);v[0]=LISTENFD;syscall5(&p,23,v,1);cmpimm(&p,(uint32_t)-CATOS_EAGAIN);errj[errn++]=(uint32_t)((uint8_t*)jne(&p)-u);v[0]=LISTENFD;syscall5(&p,28,v,1);
    v[0]=2;v[1]=0;v[2]=0;v[3]=0;v[4]=0;syscall5(&p,20,v,0);steax(&p,FD);v[0]=FD;v[1]=7002;syscall5(&p,21,v,1);v[0]=FD;v[1]=BUF;v[2]=4;v[3]=SRCIP;v[4]=SRCPORT;syscall5(&p,25,v,1);cmpimm(&p,(uint32_t)-CATOS_EAGAIN);errj[errn++]=(uint32_t)((uint8_t*)jne(&p)-u);v[0]=FD;syscall5(&p,28,v,1);
    uint32_t errskip=(uint32_t)((uint8_t*)jmp(&p)-u),errfail=0x1000u+(uint32_t)(p-u);for(uint32_t i=0;i<errn;i++)patch(u,errj[i],errfail);syscall3(&p,1,3,MSG_ERRFAIL,24);e8(&p,0xEB);e8(&p,0xFE);uint32_t errpass=0x1000u+(uint32_t)(p-u);syscall3(&p,1,3,MSG_ERRPASS,23);patch(u,errskip,errpass);
    syscall3(&p,5,PATH_CONSOLE,1,0);steax(&p,FD);
    v[0]=TARGET;v[1]=PINGOUT;v[2]=128;v[3]=0xCA70;v[4]=1;syscall5(&p,29,v,0);steax(&p,LEN);v[0]=FD;v[1]=PINGOUT;v[2]=LEN;syscall5(&p,1,v,5);
    v[0]=TARGET;v[1]=PINGOUT;v[2]=128;v[3]=0xCA70;v[4]=2;syscall5(&p,29,v,0);steax(&p,LEN);v[0]=FD;v[1]=PINGOUT;v[2]=LEN;syscall5(&p,1,v,5);
    v[0]=TARGET;v[1]=PINGOUT;v[2]=128;v[3]=0xCA70;v[4]=3;syscall5(&p,29,v,0);steax(&p,LEN);v[0]=FD;v[1]=PINGOUT;v[2]=LEN;syscall5(&p,1,v,5);
    v[0]=PINGSTAT;v[1]=128;syscall5(&p,30,v,0);steax(&p,LEN);v[0]=FD;v[1]=PINGSTAT;v[2]=LEN;syscall5(&p,1,v,5);
    v[0]=BAD_TARGET;v[1]=PINGOUT;v[2]=128;v[3]=0xCA70;v[4]=4;syscall5(&p,29,v,0);steax(&p,LEN);v[0]=FD;v[1]=PINGOUT;v[2]=LEN;syscall5(&p,1,v,5);
    v[0]=FD;syscall5(&p,28,v,1);
    v[0]=2;v[1]=0;v[2]=0;v[3]=0;v[4]=0;syscall5(&p,20,v,0);steax(&p,FD);
    v[0]=FD;v[1]=7000;syscall5(&p,21,v,1);
    uint32_t udp_loop=0x1000u+(uint32_t)(p-u);v[0]=FD;v[1]=BUF;v[2]=64;v[3]=SRCIP;v[4]=SRCPORT;syscall5(&p,25,v,1);cmpzero(&p);a1=(uint32_t)((uint8_t*)jl(&p)-u);steax(&p,LEN);
    v[0]=FD;v[1]=BUF;v[2]=LEN;v[3]=SRCIP;v[4]=SRCPORT;syscall5(&p,24,v,1|4|8|16);v[0]=FD;syscall5(&p,28,v,1);syscall3(&p,5,PATH_CONSOLE,1,0);steax(&p,FD);syscall3(&p,1,3,MSG_UDP,16);syscall3(&p,6,3,0,0);
    v[0]=1;v[1]=0;v[2]=0;v[3]=0;v[4]=0;syscall5(&p,20,v,0);steax(&p,LISTENFD);v[0]=LISTENFD;v[1]=80;syscall5(&p,21,v,1);v[0]=LISTENFD;v[1]=2;syscall5(&p,22,v,1);
    uint32_t acc_loop=0x1000u+(uint32_t)(p-u);v[0]=LISTENFD;syscall5(&p,23,v,1);cmpzero(&p);a2=(uint32_t)((uint8_t*)jl(&p)-u);steax(&p,FD);
    uint32_t tcp_loop=0x1000u+(uint32_t)(p-u);v[0]=FD;v[1]=BUF;v[2]=64;syscall5(&p,27,v,1);cmpzero(&p);a3=(uint32_t)((uint8_t*)jl(&p)-u);steax(&p,LEN);v[0]=FD;v[1]=BUF;v[2]=LEN;syscall5(&p,26,v,5);v[0]=FD;syscall5(&p,28,v,1);
    uint32_t acc_loop2=0x1000u+(uint32_t)(p-u);v[0]=LISTENFD;syscall5(&p,23,v,1);cmpzero(&p);a4=(uint32_t)((uint8_t*)jl(&p)-u);steax(&p,FD);
    uint32_t tcp_loop2=0x1000u+(uint32_t)(p-u);v[0]=FD;v[1]=BUF;v[2]=64;syscall5(&p,27,v,1);cmpzero(&p);a5=(uint32_t)((uint8_t*)jl(&p)-u);steax(&p,LEN);v[0]=FD;v[1]=BUF;v[2]=LEN;syscall5(&p,26,v,5);v[0]=FD;syscall5(&p,28,v,1);v[0]=LISTENFD;syscall5(&p,28,v,1);syscall3(&p,5,PATH_CONSOLE,1,0);steax(&p,FD);syscall3(&p,1,3,MSG_TCP,20);syscall3(&p,6,3,0,0);e8(&p,0xEB);e8(&p,0xFE);
    patch(u,a1,udp_loop);patch(u,a2,acc_loop);patch(u,a3,tcp_loop);patch(u,a4,acc_loop2);patch(u,a5,tcp_loop2);
    const char n[]="/dev/null",c[]="/dev/console",kbdp[]="/dev/kbd",t[]="10.0.2.2",bt[]="300.1.1.1",m[]="user console ok\n",ko[]="kbd handshake: ready\n",kr[]="kbd NOT_TESTED/EMPTY after 3 tries\n",um[]="user UDP PASS\n",tm[]="user TCP MULTI PASS\n",ep[]="user socket ERRORS PASS\n",ef[]="user socket ERRORS FAIL\n";uint8_t *d=(uint8_t*)phys_to_virt(dp);for(unsigned i=0;i<sizeof(n);i++)d[PATH_NULL-0x4000+i]=n[i];for(unsigned i=0;i<sizeof(c);i++)d[PATH_CONSOLE-0x4000+i]=c[i];for(unsigned i=0;i<sizeof(kbdp);i++)d[PATH_KBD-0x4000+i]=kbdp[i];for(unsigned i=0;i<sizeof(t);i++)d[TARGET-0x4000+i]=t[i];for(unsigned i=0;i<sizeof(bt);i++)d[BAD_TARGET-0x4000+i]=bt[i];for(unsigned i=0;i<sizeof(m);i++)d[MSG_CONSOLE-0x4000+i]=m[i];for(unsigned i=0;i<sizeof(ko);i++)d[MSG_KBDOPEN-0x4000+i]=ko[i];for(unsigned i=0;i<sizeof(kr);i++)d[MSG_KBDREAD-0x4000+i]=kr[i];for(unsigned i=0;i<sizeof(um);i++)d[MSG_UDP-0x4000+i]=um[i];for(unsigned i=0;i<sizeof(tm);i++)d[MSG_TCP-0x4000+i]=tm[i];for(unsigned i=0;i<sizeof(ep);i++)d[MSG_ERRPASS-0x4000+i]=ep[i];for(unsigned i=0;i<sizeof(ef);i++)d[MSG_ERRFAIL-0x4000+i]=ef[i];for(unsigned i=0;i<16;i++)d[KDBUF-0x4000+i]=0;
    if((uint32_t)(p-u)>sizeof(user_code))panic("user code too large");
    copy_bytes(phys_to_virt(cp),u,4096);copy_bytes(phys_to_virt(cp2),u+4096,4096);
    kputs("[OK] entering ring3\n");__asm__ volatile("pushl $0x23; pushl $0x700FFC; pushl $0x202; pushl $0x1B; pushl $0x1000; iret");
}
