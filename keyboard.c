#include "keyboard.h"
#include "kernel.h"
#include "interrupts.h"
#include <stdint.h>

static char q[256]; static uint8_t h,t,shift;
static void putc_q(char c){uint8_t n=(uint8_t)(h+1);if(n==t)return;q[h]=c;h=n;}
static inline void ob(uint16_t p,uint8_t v){__asm__ volatile("outb %0,%1"::"a"(v),"Nd"(p));}
static inline uint8_t ib(uint16_t p){uint8_t v;__asm__ volatile("inb %1,%0":"=a"(v):"Nd"(p));return v;}

/* ── Set-1 protocol layer：前缀/标记值集中命名，handler 内不出现新魔法数 ── */
#define KB_BREAK_BIT    0x80u /* Set-1 断码 = make | 0x80                       */
#define KB_EXT_PREFIX   0xE0u /* 扩展键前缀（箭头/RCtrl/RAlt/GUI...）           */
#define KB_PAUSE_PREFIX 0xE1u /* Pause 前缀                                     */
#define KB_PAUSE_TRAIL  7u    /* E1 之后固定吞掉的尾字节：14 77 E1 F0 34 F0 77 */

/* ── E0/E1 前缀解析状态机（known-issue 2）──────────────────────────────────
 * kh() 运行于 IRQ1 上下文：状态只允许静态存储，本文件零动态分配。
 * PS/2 每个扫描码字节各触发一次 IRQ1，故每字节推进一拍。
 * 状态转移：
 *   KS_BASE --0xE0--> KS_E0            （进入扩展键两字节序列）
 *   KS_BASE --0xE1--> KS_E1(e1_left=7) （Pause 整串吞掉，见下）
 *   KS_E0   --any  --> KS_BASE         （E0 序列严格两字节，处理完必回）
 *   KS_E1   --tail --> (e1_left==0) -> KS_BASE
 * KS_E1 中间字节（含序列内嵌的第二个 E1 与 F0）按数据吞掉，绝不重新入机。 */
typedef enum {
    KS_BASE = 0, /* 下一个字节是普通 Set-1 make/break */
    KS_E0,       /* 已见 E0：下一字节是扩展 make/break */
    KS_E1        /* 已见 E1(Pause)：吞 KB_PAUSE_TRAIL 个尾字节 */
} kbstate_t;
static kbstate_t ks;      /* 静态零初始化 == KS_BASE */
static uint8_t   e1_left; /* Pause 序列剩余待吞字节数 */

/* Set-1 (PC/AT) scancode -> character, indexed directly by scancode so that
 * keys after the non-printing gaps stay aligned.
 * lo = unshifted US QWERTY, hi = Shifted. 0 = unhandled/ignored.
 * 控制键已补齐（known-issue 3）：0x0E='\b'(8)、0x0F='\t'(9)、
 * 0x1C='\n'、0x39=' '（后两者由原 if 特例并入表驱动）。
 * Shift+Tab 明确定义为与 Tab 相同输出 '\t'；Shift+Backspace 输出 '\b'
 * —— 消费方（/dev/kbd 字节流读者）无字段导航概念，不引入反向 Tab。
 * >=0x40 的码（NumLock 0x45、ScrollLock 0x46、小键盘 0x47+、F10-F12）
 * 在表界之外，由边界检查安全忽略——这是既定策略而非遗漏。 */
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

/* E0 扩展 make 码白名单表（稀疏，用 {code,char} 对 + 零哨兵结尾；
 * 基础表保持原直接索引组织不变）。凡不在表内者一律忽略：
 *   - E0 0x14 右Ctrl / E0 0x38 右Alt：与左键同权——LCtrl/LAlt 在 lo/hi 中
 *     本就是 0 不产字符，扩展键同样静默，断码走 break 分支丢弃。
 *   - 箭头 E0 48(Up)/4B(Left)/4D(Right)/50(Down)：选「忽略」方案。
 *     理由：/dev/kbd 消费方（vfs kread → ring3 echo probe/shell）是面向
 *     行的字节流读者，没有 ANSI 转义序列解析器；注入 "ESC [ A" 四字节会
 *     污染行输入并虚增读出计数。将来若有消费方支持转义序列，再在此表加
 *     条目即可（行为升级点已隔离在本表）。
 *   - 小键盘/Home 簇、GUI 键（E0 5B/5C/5D）：忽略。
 * E0 断码永远到不了本表：kh() 的 break-bit 测试先于查表丢弃之，
 * 包括假想的 E0+F0（Set-1 不产生 F0；若出现，其 bit7 使它落入丢弃路径，
 * 状态复位，绝不会被当作 make 0xF0 查表——known-issue 2 的防误判要求）。 */
typedef struct { uint8_t code; char ch; } extmap_t;
static const extmap_t ext_lo[]={
    {0x1C,'\n'}, /* Keypad Enter */
    {0x35,'/'},  /* Keypad /     */
    {0,0}        /* 哨兵终止符   */
};

static bool kh(uint8_t n,void*a){
    (void)n;(void)a;
    uint8_t s=ib(0x60);
    if(ks==KS_E1){ /* Pause 尾字节：整段吞掉，内嵌 E1/F0 不重新入机 */
        if(--e1_left==0u)ks=KS_BASE;
        return true;
    }
    if(ks==KS_E0){
        ks=KS_BASE; /* E0 序列恰两字节：无论收到什么都回 BASE */
        if(s&KB_BREAK_BIT)return true; /* 扩展断码丢弃（含假想 E0+F0，见表注）*/
        for(const extmap_t*e=ext_lo;e->code;e++)
            if(e->code==s){putc_q(e->ch);break;}
        return true; /* 未映射扩展 make（RCtrl/RAlt/箭头/GUI）：定义性忽略 */
    }
    if(s==KB_EXT_PREFIX){ks=KS_E0;return true;}
    if(s==KB_PAUSE_PREFIX){ks=KS_E1;e1_left=KB_PAUSE_TRAIL;return true;}
    if(s&KB_BREAK_BIT){ /* 基础断码：仅维护 Shift 锁存（known-issue 1），
                           其余断码全部丢弃 → 长按不再重复注入字符 */
        if((s&0x7f)==0x2a||(s&0x7f)==0x36)shift=0;
        return true;
    }
    if(s==0x2a||s==0x36){shift=1;return true;}
    if(s<sizeof(lo)){ /* 界外码：NumLock/ScrollLock/小键盘/F10+ 安全忽略 */
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
