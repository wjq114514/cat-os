#include "rtc.h"
#include "kernel.h"
#include <stdint.h>
static inline void ob(uint16_t p,uint8_t v){__asm__ volatile("outb %0,%1"::"a"(v),"Nd"(p));}static inline uint8_t ib(uint16_t p){uint8_t v;__asm__ volatile("inb %1,%0":"=a"(v):"Nd"(p));return v;}static uint8_t cv(uint8_t x){return (uint8_t)((x&15)+((x>>4)*10));}
rtc_time_t rtc_get_time(void){rtc_time_t t;ob(0x70,0);t.second=cv(ib(0x71));ob(0x70,2);t.minute=cv(ib(0x71));ob(0x70,4);t.hour=cv(ib(0x71));ob(0x70,7);t.day=cv(ib(0x71));ob(0x70,8);t.month=cv(ib(0x71));ob(0x70,9);t.year=2000+cv(ib(0x71));return t;}
void rtc_init(void){rtc_time_t t=rtc_get_time();kputs("[OK] RTC ");kput_dec(t.year);kputs("-");kput_dec(t.month);kputs("-");kput_dec(t.day);kputs(" ");kput_dec(t.hour);kputs(":");kput_dec(t.minute);kputs(":");kput_dec(t.second);kputs("\n");}
