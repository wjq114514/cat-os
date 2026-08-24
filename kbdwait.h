#ifndef CATOS_KBDWAIT_H
#define CATOS_KBDWAIT_H
#include <stdint.h>
#define KBD_BLOCK_TIMEOUT_MS 5000u
int keyboard_getchar_blocking(uint32_t timeout_ms);
#endif
