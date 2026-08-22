#include <stddef.h>
#include <stdint.h>

#include "kernel.h"
#include "multiboot.h"
#include "paging.h"
#include "interrupts.h"
#include "syscall.h"
#include "process.h"
#include "netring.h"
#include "pci.h"
#include "e1000.h"
#include "net.h"
#include "keyboard.h"
#include "ide.h"
#include "rtc.h"
#include "user.h"
#include "vfs.h"

#define VGA_W   80u
#define VGA_H   25u
#define COLOR   0x0Eu
#define COM1    0x3F8u

static volatile uint16_t *vga;
static uint32_t vga_pos;

static inline void outb(uint16_t port, uint8_t val) {
    __asm__ volatile("outb %0, %1" :: "a"(val), "Nd"(port));
}

static inline uint8_t inb(uint16_t port) {
    uint8_t val;
    __asm__ volatile("inb %1, %0" : "=a"(val) : "Nd"(port));
    return val;
}

static void serial_init(void) {
    outb(COM1 + 1, 0x00);
    outb(COM1 + 3, 0x80);
    outb(COM1 + 0, 0x03);
    outb(COM1 + 1, 0x00);
    outb(COM1 + 3, 0x03);
    outb(COM1 + 2, 0xC7);
    outb(COM1 + 4, 0x0B);
}

static void serial_putc(char c) {
    for (uint32_t spin = 0; spin < 100000; ++spin) {
        if (inb(COM1 + 5) & 0x20) {
            break;
        }
    }
    outb(COM1, (uint8_t)c);
}

static void vga_putc(char c) {
    if (!vga) {
        return;
    }

    if (c == '\n') {
        vga_pos += VGA_W - (vga_pos % VGA_W);
    } else {
        if (vga_pos >= VGA_W * VGA_H) {
            vga_pos = 0;
        }
        vga[vga_pos++] = (uint16_t)((COLOR << 8) | (uint8_t)c);
    }
}

void kputs(const char *s) {
    while (*s) {
        serial_putc(*s);
        vga_putc(*s);
        ++s;
    }
}

void kput_hex32(uint32_t value) {
    static const char hex[] = "0123456789ABCDEF";
    kputs("0x");
    for (int shift = 28; shift >= 0; shift -= 4) {
        char c = hex[(value >> (uint32_t)shift) & 0xFu];
        serial_putc(c);
        vga_putc(c);
    }
}

void kput_dec(uint32_t value) {
    char buf[11];
    uint32_t i = 0;

    if (value == 0) {
        kputs("0");
        return;
    }

    while (value && i < sizeof(buf)) {
        buf[i++] = (char)('0' + (value % 10u));
        value /= 10u;
    }

    while (i) {
        char c = buf[--i];
        serial_putc(c);
        vga_putc(c);
    }
}

void kput_sdec(int32_t value) {
    if (value < 0) {
        kputs("-");
        kput_dec((uint32_t)(-(value + 1)) + 1u);
        return;
    }
    kput_dec((uint32_t)value);
}

void panic(const char *message) {
    kputs("[ERR] ");
    kputs(message);
    kputs("\n");
    for (;;) {
        __asm__ volatile("cli; hlt");
    }
}

static void vga_init_via_ioremap(void) {
    vga = (volatile uint16_t *)ioremap(0x000B8000u, PAGE_SIZE,
                                       _PAGE_RW | _PAGE_PCD | _PAGE_PWT);
    if (!vga) {
        panic("ioremap(VGA) failed");
    }
    vga_pos = 0;
    kputs("[OK] VGA mapped through ioremap window\n");
}

void kernel_main(uint32_t magic, uint32_t mb_info_phys) {
    serial_init();
    kputs("[OK] COM1 ready in higher-half C\n");
    kputs("[OK] kernel_main virtual address ");
    kput_hex32((uint32_t)(uintptr_t)&kernel_main);
    kputs("\n");

    if (magic != MULTIBOOT_BOOTLOADER_MAGIC) {
        panic("bad multiboot magic");
    }
    kputs("[OK] multiboot magic 0x2BADB002\n");

    paging_init(mb_info_phys);

    interrupts_init();
    syscall_init();
    process_init();
    netring_init();
    pci_init();
    e1000_init();
    net_init();
    keyboard_init();
    ide_init();
    rtc_init();
    usermode_init();
    vfs_init();
    interrupts_enable();kputs("[OK] pre-enter_usermode\n");
    enter_usermode();
    __asm__ volatile("int3");

    vga_init_via_ioremap();
    kputs("cat-OS higher-half paging online\n");
    kputs("[OK] PMM managed pages: total=");
    kput_dec(pmm_total_pages());
    kputs(" free=");
    kput_dec(pmm_free_pages());
    kputs(" limit=");
    kput_hex32((uint32_t)pmm_managed_limit());
    kputs("\n");

    uintptr_t dma_page = pmm_alloc_dma_page();
    if (!dma_page || dma_page >= ISA_DMA_LIMIT) {
        panic("DMA <=16MiB page allocation failed");
    }
    kputs("[OK] DMA-capable page reserved/tested at ");
    kput_hex32((uint32_t)dma_page);
    kputs("\n");
    pmm_free_page(dma_page);

    kputs("[OK] cat-OS up and running in the higher half ^.^\n");

    for (;;) {
        net_poll();
        __asm__ volatile("hlt");
    }
}
