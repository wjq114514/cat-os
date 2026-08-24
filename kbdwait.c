#include "kbdwait.h"
#include "keyboard.h"
#include "interrupts.h"
#include <stdint.h>

int keyboard_getchar_blocking(uint32_t timeout_ms){
    if(!timeout_ms)return keyboard_getchar();
    uint32_t start=ticks,budget=timeout_ms/10u;
    if(!budget)budget=1;
    for(;;){
        int c=keyboard_getchar();
        if(c>=0)return c;
        if(ticks-start>=budget)return -1;
        __asm__ volatile("sti; hlt");
    }
}
