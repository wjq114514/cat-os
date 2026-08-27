/* keyboard.c — PS/2 键盘驱动（Set-1 协议 + E0/E1 状态机）
 *
 * Wave 2 更新（2026-08-27 shell 增强）：
 *   - Ctrl 键状态追踪：Ctrl+letter → 控制字符（0x01-0x1A）
 *   - 箭头键 E0 序列 → ANSI 转义序列输出（↑↓←→）
 *   - Ctrl+C=3(CINTR), Ctrl+Z=26(CSUSP), Ctrl+D=4(CEOF),
 *     Ctrl+L=12(CFF), Ctrl+U=21(CWERASE)
 */
#include "keyboard.h"
#include "kernel.h"
#include "interrupts.h"
#include <stdint.h>

static char q[256]; static uint8_t h,t,shift,ctrl;
static void putc_q(char c){uint8_t n=(uint8_t)(h+1);if(n==t)return;q[h]=c;h=n;}
/* 多字节序列入队：ESC [ A / ESC [ B / ESC [ C / ESC [ D */
static void putc_q_str(const char *s){while(*s)putc_q(*s++);}
static inline void ob(uint16_t p,uint8_t v){__asm__ volatile("outb %0,%1"::"a"(v),"Nd"(p));}
static inline uint8_t ib(uint16_t p){uint8_t v;__asm__ volatile("inb %1,%0":"=a"(v):"Nd"(p));return v;}

/* ── Set-1 协议 ────────────────────────────────────────────────────── */
#define KB_BREAK_BIT    0x80u
#define KB_EXT_PREFIX   0xE0u
#define KB_PAUSE_PREFIX 0xE1u
#define KB_PAUSE_TRAIL  7u

typedef enum { KS_BASE = 0, KS_E0, KS_E1 } kbstate_t;
static kbstate_t ks;
static uint8_t   e1_left;

/* Set-1 scancode → char（lo=unshifted, hi=shifted） */
static const char lo[0x40]={
    /*0x00*/0,0,'1','2','3','4','5','6',
    /*0x08*/'7','8','9','0','-','=','\b','\t',
    /*0x10*/'q','w','e','r','t','y','u','i',
    /*0x18*/'o','p','[',']','\n',0,'a','s',
    /*0x20*/'d','f','g','h','j','k','l',';',
    /*0x28*/'\'','`',0,'\\','z','x','c','v',
    /*0x30*/'b','n','m',',','.','/',0,0,
    /*0x38*/0,' ',0,0,0,0,0,0,
};
static const char hi[0x40]={
    /*0x00*/0,0,'!','@','#','$','%','^',
    /*0x08*/'&','*','(',')','_','+','\b','\t',
    /*0x10*/'Q','W','E','R','T','Y','U','I',
    /*0x18*/'O','P','{','}','\n',0,'A','S',
    /*0x20*/'D','F','G','H','J','K','L',':',
    /*0x28*/'"','~',0,'|','Z','X','C','V',
    /*0x30*/'B','N','M','<','>','?',0,0,
    /*0x38*/0,' ',0,0,0,0,0,0,
};

/* E0 扩展 make 码：箭头键 → ANSI 转义序列 */
typedef struct { uint8_t code; const char *seq; } extmap_t;
static const extmap_t ext_map[]={
    {0x48, "\x1b[A"},   /* Up    */
    {0x50, "\x1b[B"},   /* Down  */
    {0x4D, "\x1b[C"},   /* Right */
    {0x4B, "\x1b[D"},   /* Left  */
    {0x47, "\x1b[H"},   /* Home  */
    {0x4F, "\x1b[F"},   /* End   */
    {0x53, "\x7f"},     /* Delete → DEL (0x7F) */
    {0x1C, "\n"},       /* Keypad Enter */
    {0x35, "/"},        /* Keypad /     */
    {0, 0}
};

/* Ctrl 键扫描码（左=0x1D, 右=0xE0 0x1D） */
#define SC_LCTRL  0x1D
#define SC_LALT   0x38
#define SC_LSHIFT 0x2A
#define SC_RSHIFT 0x36

static bool kh(uint8_t n,void*a){
    (void)n;(void)a;
    uint8_t s=ib(0x60);

    /* ── E1 Pause 尾字节：整段吞掉 ── */
    if(ks==KS_E1){
        if(--e1_left==0u)ks=KS_BASE;
        return true;
    }

    /* ── E0 扩展键 ── */
    if(ks==KS_E0){
        ks=KS_BASE;
        if(s&KB_BREAK_BIT){
            /* 扩展断码：追踪 Ctrl/RAlt 释放 */
            if((s&0x7f)==SC_LCTRL) ctrl=0;
            return true;
        }
        /* 扩展 make：查 ANSI 序列表 */
        for(const extmap_t*e=ext_map;e->code;e++){
            if(e->code==s){
                /* Ctrl+箭头暂不映射（终端仿真器通常不发此序列） */
                putc_q_str(e->seq);
                return true;
            }
        }
        /* 未映射扩展键（RCtrl/RAlt/GUI） */
        return true;
    }

    if(s==KB_EXT_PREFIX){ks=KS_E0;return true;}
    if(s==KB_PAUSE_PREFIX){ks=KS_E1;e1_left=KB_PAUSE_TRAIL;return true;}

    /* ── 断码：追踪 Shift/Ctrl/Alt 释放 ── */
    if(s&KB_BREAK_BIT){
        uint8_t code=s&0x7f;
        if(code==SC_LSHIFT||code==SC_RSHIFT) shift=0;
        else if(code==SC_LCTRL) ctrl=0;
        else if(code==SC_LALT) { /* Alt 释放，暂无操作 */ }
        return true;
    }

    /* ── Make 码 ── */
    if(s==SC_LSHIFT||s==SC_RSHIFT){shift=1;return true;}
    if(s==SC_LCTRL){ctrl=1;return true;}
    if(s==SC_LALT){return true;}  /* Alt：静默 */

    if(s<sizeof(lo)){
        char c=(shift?hi:lo)[s];
        if(!c) return true;

        /* Ctrl 模式：抑制大写，输出控制字符 */
        if(ctrl){
            if(c>='a'&&c<='z') c=(char)(c-'a'+1);
            else if(c>='A'&&c<='Z') c=(char)(c-'A'+1);
            else if(c=='[') c=0x1B;  /* Ctrl+[ → ESC */
            else return true;        /* 其他 Ctrl+符号：忽略 */
        }

        putc_q(c);
    }
    return true;
}

void keyboard_init(void){
    while(ib(0x64)&1)(void)ib(0x60);
    ob(0x64,0xAA);
    for(volatile int i=0;i<10000&&!((ib(0x64)&1));i++);
    (void)ib(0x60);
    ob(0x64,0xAE);
    irq_register_handler(1,kh,0);
    irq_clear_mask(1);
    kputs("[OK] keyboard IRQ1 active (Ctrl+key + arrow ANSI enabled)\n");
}

int keyboard_getchar(void){if(t==h)return -1;return q[t++];}
