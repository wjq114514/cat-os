/* Link the kernel in the higher half while keeping its physical load at 1MiB. */
ENTRY(_start)

KERNEL_VIRT_BASE = 0xC0000000;
KERNEL_PHYS_LOAD = 0x00100000;
KERNEL_VIRT_LOAD = KERNEL_VIRT_BASE + KERNEL_PHYS_LOAD;

SECTIONS
{
    . = KERNEL_VIRT_LOAD;
    __kernel_start = .;

    .text ALIGN(4K) : AT(ADDR(.text) - KERNEL_VIRT_BASE) {
        KEEP(*(.multiboot))
        *(.text*)
    }

    .rodata ALIGN(4K) : AT(ADDR(.rodata) - KERNEL_VIRT_BASE) {
        *(.rodata*)
    }

    .data ALIGN(4K) : AT(ADDR(.data) - KERNEL_VIRT_BASE) {
        *(.data*)
    }

    __kernel_bss_start = .;
    __kernel_phys_load_end = __kernel_bss_start - KERNEL_VIRT_BASE;

    .bss ALIGN(4K) : AT(ADDR(.bss) - KERNEL_VIRT_BASE) {
        *(COMMON)
        *(.bss*)
    }

    . = ALIGN(4K);
    __kernel_end = .;
    __kernel_phys_start = __kernel_start - KERNEL_VIRT_BASE;
    __kernel_phys_end = __kernel_end - KERNEL_VIRT_BASE;

    /* Physical alias used by the Multiboot address-field entry in boot.asm. */
    _start_phys = _start - KERNEL_VIRT_BASE;

    /DISCARD/ : {
        *(.comment)
        *(.note*)
        *(.eh_frame*)
    }
}
