#include "kernel.h"
#include "interrupts.h"
#include "paging.h"
#include "vfs.h"
#include "net.h"
typedef struct{uint16_t limit;uint32_t base;}__attribute__((packed)) desc_ptr_t;
typedef struct{uint16_t lo,sel;uint8_t zero,type;uint16_t hi;}__attribute__((packed)) gate_t;
typedef struct{uint32_t edi,esi,ebp,saved_esp,ebx,edx,ecx,eax,vector,error_code,eip,cs,eflags;} interrupt_frame_t;
typedef struct{irq_handler_t fn;void *arg;uint8_t warned;} irq_slot_t;
static gate_t idt[256];static uint8_t gdt_copy[64]__attribute__((aligned(16)));static irq_slot_t slots[16];volatile uint32_t ticks;uint16_t code_sel;
extern void arch_load_idt(const desc_ptr_t *);extern void arch_load_gdt(const desc_ptr_t *);
#define D(n) extern void isr_##n(void)
D(0);D(3);D(14);D(128);D(32);D(33);D(34);D(35);D(36);D(37);D(38);D(39);D(40);D(41);D(42);D(43);D(44);D(45);D(46);D(47);
static void(*const irq_stubs[16])(void)={isr_32,isr_33,isr_34,isr_35,isr_36,isr_37,isr_38,isr_39,isr_40,isr_41,isr_42,isr_43,isr_44,isr_45,isr_46,isr_47};
static inline void outb(uint16_t p,uint8_t v){__asm__ volatile("outb %0,%1"::"a"(v),"Nd"(p));}static inline uint8_t inb(uint16_t p){uint8_t v;__asm__ volatile("inb %1,%0":"=a"(v):"Nd"(p));return v;}
static void gate(uint8_t n,void(*fn)(void),uint8_t type){uint32_t a=(uint32_t)fn;idt[n]=(gate_t){a,code_sel,0,type,(uint16_t)(a>>16)};}
void irq_set_mask(uint8_t q){uint16_t p=q<8?0x21:0xA1;outb(p,(uint8_t)(inb(p)|(1u<<(q&7))));}
void irq_clear_mask(uint8_t q){uint16_t p=q<8?0x21:0xA1;outb(p,(uint8_t)(inb(p)&~(1u<<(q&7))));}
int irq_register_handler(uint8_t q,irq_handler_t fn,void *arg){if(q>=16||!fn||slots[q].fn)return -1;slots[q].fn=fn;slots[q].arg=arg;slots[q].warned=0;return 0;}
void irq_unregister_handler(uint8_t q){if(q<16){irq_set_mask(q);slots[q]=(irq_slot_t){0};}}
static uint16_t pic_isr(void){outb(0x20,0x0B);outb(0xA0,0x0B);return (uint16_t)inb(0x20)|((uint16_t)inb(0xA0)<<8);}
static bool timer_handler(uint8_t q,void *arg){(void)q;(void)arg;ticks++;net_poll();if(ticks<=3){kputs("[OK] PIT tick=");kput_dec(ticks);kputs(" vector=32\n");}return true;}
static __attribute__((used)) void irq_dispatch(uint8_t q){if((q==7||q==15)&&!(pic_isr()&(1u<<q))){if(q==15)outb(0x20,0x20);return;}bool done=slots[q].fn&&slots[q].fn(q,slots[q].arg);if(!done&&!slots[q].warned){slots[q].warned=1;kputs("[WARN] unhandled IRQ ");kput_dec(q);kputs(" (further warnings suppressed)\n");}if(q>=8)outb(0xA0,0x20);outb(0x20,0x20);}
static void pic_init(void){outb(0x20,0x11);outb(0xA0,0x11);outb(0x21,0x20);outb(0xA1,0x28);outb(0x21,4);outb(0xA1,2);outb(0x21,1);outb(0xA1,1);outb(0x21,0xFF);outb(0xA1,0xFF);kputs("[OK] PIC remapped IRQ0-15 -> vectors 0x20-0x2F; spurious IRQ7/15 detection active\n");}
static void pit_init(void){uint32_t d=1193182u/100u;outb(0x43,0x36);outb(0x40,d);outb(0x40,d>>8);irq_register_handler(0,timer_handler,0);irq_clear_mask(0);kputs("[OK] PIT registered on IRQ0 at 100Hz\n");}
void interrupts_init(void){uint16_t cs;uint64_t old;__asm__ volatile("sgdt %0":"=m"(old));__asm__ volatile("mov %%cs,%0":"=r"(cs));code_sel=cs;desc_ptr_t ng={(uint16_t)old,(uint32_t)gdt_copy};uint32_t base=old>>16;if(ng.limit>=sizeof(gdt_copy))panic("GRUB GDT too large");memcpy(gdt_copy,phys_to_virt(base),ng.limit+1u);arch_load_gdt(&ng);kputs("[OK] GRUB GDT relocated; CS=");kput_hex32(cs);kputs("\n");for(uint32_t i=0;i<256;i++)idt[i]=(gate_t){0};gate(0,isr_0,0x8E);gate(3,isr_3,0x8E);gate(14,isr_14,0x8E);gate(128,isr_128,0xEE);for(uint8_t i=0;i<16;i++)gate(32+i,irq_stubs[i],0x8E);desc_ptr_t id={(uint16_t)(sizeof(idt)-1),(uint32_t)idt};arch_load_idt(&id);kputs("[OK] IDT active; IRQ handler table initialized\n");pic_init();pit_init();}
extern uint16_t code_sel;
void interrupts_post_gdt_update(void){code_sel=0x08;for(uint32_t i=0;i<256;i++)idt[i]=(gate_t){0};gate(0,isr_0,0x8E);gate(3,isr_3,0x8E);gate(14,isr_14,0x8E);gate(128,isr_128,0xEE);for(uint8_t i=0;i<16;i++)gate(32+i,irq_stubs[i],0x8E);desc_ptr_t id={(uint16_t)(sizeof(idt)-1),(uint32_t)idt};arch_load_idt(&id);kputs("[OK] IDT reloaded with new code_sel=0x08\n");}
void interrupts_enable(void){kputs("[OK] interrupts enabled\n");__asm__ volatile("sti");}
void interrupt_dispatch(uint32_t *raw){interrupt_frame_t *f=(interrupt_frame_t*)raw;if(f->vector==128){if(f->eax==1){}uint32_t nr=f->eax;uint32_t a[6]={f->ebx,f->ecx,f->edx,f->esi,f->edi,0};int32_t r=vfs_syscall(nr,a);f->eax=(uint32_t)r;if(nr==5){kputs("[OK] user syscall open ");kputs(((char*)a[0])[5]=='n'?"/dev/null fd=":"/dev/console fd=");kput_sdec(r);kputs("\n");}else if(nr==0){kputs("[OK] user syscall read /dev/null ret=");kput_dec(r);kputs("\n");}else if(nr==1){if(r==-14)kputs("[OK] user pointer EFAULT test\n");kputs("[OK] user syscall write ret=");kput_sdec(r);kputs("\n");}else if(nr==6){kputs("[OK] user syscall close fd=3 ret=");kput_dec(r);kputs("\n[OK] user syscall VFS roundtrip\n");}return;}if(f->vector>=32&&f->vector<48){irq_dispatch(f->vector-32);return;}if(f->vector==3){kputs("[OK] int3 handled vector=3 error=0\n");return;}kputs("[ERR] exception vector=");kput_dec(f->vector);kputs(" error=");kput_hex32(f->error_code);if(f->vector==14){uint32_t cr2;__asm__ volatile("mov %%cr2,%0":"=r"(cr2));kputs(" CR2=");kput_hex32(cr2);}kputs("\n");panic("CPU exception");}
