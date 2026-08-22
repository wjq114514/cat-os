#ifndef CATOS_INTERRUPTS_H
#define CATOS_INTERRUPTS_H
#include <stdint.h>
#include <stdbool.h>
typedef bool (*irq_handler_t)(uint8_t irq, void *arg);
void interrupts_init(void);
void interrupt_dispatch(uint32_t *frame);
void irq_set_mask(uint8_t irq);
void irq_clear_mask(uint8_t irq);
void interrupts_enable(void);
void interrupts_post_gdt_update(void);
int irq_register_handler(uint8_t irq, irq_handler_t handler, void *arg);
void irq_unregister_handler(uint8_t irq);
#endif
void interrupts_post_gdt_update(void);
