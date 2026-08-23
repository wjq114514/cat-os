#include "keyboard.h"
#include "kernel.h"
#include "interrupts.h"
#include <stdint.h>

static char q[256]; static uint8_t h,t,shift;
static void putc_q(char c){uint8_t n=(uint8_t)(h+1);if(n==t)return;q[h]=c;h=n;}
static inline void ob(uint16_t p,uint8_t v){__asm__ volatile("outb %0,%1"::"a"(v),"Nd"(p));}
static inline uint8_t ib(uint16_t p){uint8_t v;__asm__ volatile("inb %1,%0":"=a"(v):"Nd"(p));return v;}

/* Set-1 (PC/AT) scancode -> character, indexed directly by scancode so that
 * keys after the non-printing gaps (0x0E Backspace, 0x0F Tab, 0x1C Enter,
 * 0x1D LCtrl, 0x2A/0x36 Shift, 0x38 LAlt, 0x39 Space) stay aligned.
 * lo = unshifted US QWERTY, hi = Shifted. 0 = unhandled/ignored. */
static const char lo[0x40]={
    /*0x00*/0,0,'1','2','3','4','5','6',
    /*0x08*/'7','8','9','0','-','=',0,0,
    /*0x10*/'q','w','e','r','t','y','u','i',
    /*0x18*/'o','p','[',']',0,0,'a','s',
    /*0x20*/'d','f','g','h','j','k','l',';',
    /*0x28*/'\'','`',0,'\\','z','x','c','v',
    /*0x30*/'b','n','m',',','.','/',0,0,
    /*0x38*/0,0,0,0,0,0,0,0,
};
static const char hi[0x40]={
    /*0x00*/0,0,'!','@','#','$','%','^',
    /*0x08*/'&','*','(',')','_','+',0,0,
    /*0x10*/'Q','W','E','R','T','Y','U','I',
    /*0x18*/'O','P','{','}',0,0,'A','S',
    /*0x20*/'D','F','G','H','J','K','L',':',
    /*0x28*/'"','~',0,'|','Z','X','C','V',
    /*0x30*/'B','N','M','<','>','?',0,0,
    /*0x38*/0,0,0,0,0,0,0,0,
};

static bool kh(uint8_t n,void*a){
    (void)n;(void)a;
    uint8_t s=ib(0x60);
    if(s&0x80){ /* key release; only the Shift latch state is tracked */
        if((s&0x7f)==0x2a||(s&0x7f)==0x36)shift=0;
        return true;
    }
    if(s==0x2a||s==0x36){shift=1;return true;}
    if(s==0x1c){putc_q('\n');return true;}
    if(s==0x39){putc_q(' ');return true;}
    if(s<sizeof(lo)){
        char c=(shift?hi:lo)[s];
        if(c)putc_q(c);
    }
    return true;
}
void keyboard_init(void){while(ib(0x64)&1)(void)ib(0x60);ob(0x64,0xAA);for(volatile int i=0;i<10000&&!((ib(0x64)&1));i++);(void)ib(0x60);ob(0x64,0xAE);irq_register_handler(1,kh,0);irq_clear_mask(1);kputs("[OK] keyboard IRQ1 active\n");}
/*
 * /dev/kbd read semantics (safe, non-blocking):
 * keyboard_getchar() drains one decoded scancode byte from the IRQ1 ring
 * buffer. If no characters are buffered it returns -1 immediately. There is
 * no scheduler, task queue, sleep(), yield() or wakeup() in this kernel, so
 * blocking on an empty keyboard queue is not safe and is deliberately not
 * attempted. Consumers must treat -1 (and a vfs_read() return of 0 when no
 * bytes were buffered) as "no input right now" rather than EOF, and may poll
 * again later. The ring is only written by the IRQ1 handler; reads happen in
 * normal context, so a -1/0 return is a transient low-water state, not an
 * error and not end-of-stream.
 */
int keyboard_getchar(void){if(t==h)return -1;return q[t++];}