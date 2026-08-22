#ifndef CATOS_KERNEL_H
#define CATOS_KERNEL_H

#include <stdint.h>

void kputs(const char *s);
void kput_hex32(uint32_t value);
void kput_dec(uint32_t value);
void kput_sdec(int32_t value);
void panic(const char *message) __attribute__((noreturn));

#endif
