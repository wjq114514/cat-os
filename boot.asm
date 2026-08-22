; i686 higher-half multiboot1 entry.
;
; GRUB loads this ELF image at physical 1MiB.  The linker gives all kernel
; symbols higher-half VMAs (0xC0000000 + physical), but the ELF entry points to
; _start - KERNEL_VIRTUAL_BASE so the first instructions execute with paging
; disabled at low physical addresses.

BITS 32

KERNEL_VIRTUAL_BASE equ 0xC0000000
PDE_HIGH_INDEX      equ (KERNEL_VIRTUAL_BASE >> 22) ; 768

_PAGE_PRESENT       equ 0x001
_PAGE_RW            equ 0x002
_PAGE_PSE           equ 0x080
_PAGE_BOOT_4M       equ (_PAGE_PRESENT | _PAGE_RW | _PAGE_PSE)

MULTIBOOT_MAGIC     equ 0x1BADB002
MULTIBOOT_FLAGS     equ 0x00010003 ; page-align + meminfo + physical address fields
MULTIBOOT_CHECKSUM  equ -(MULTIBOOT_MAGIC + MULTIBOOT_FLAGS)

section .multiboot
align 4
multiboot_header:
    dd MULTIBOOT_MAGIC
    dd MULTIBOOT_FLAGS
    dd MULTIBOOT_CHECKSUM
    dd multiboot_header - KERNEL_VIRTUAL_BASE ; header_addr
    dd __kernel_phys_start                   ; load_addr
    dd __kernel_phys_load_end                ; load_end_addr
    dd __kernel_phys_end                     ; bss_end_addr
    dd _start - KERNEL_VIRTUAL_BASE          ; entry_addr

section .text
global _start
extern kernel_main
extern __kernel_phys_start
extern __kernel_phys_load_end
extern __kernel_phys_end

_start:
    cli

    ; Preserve the multiboot registers before serial/paging setup clobbers them.
    mov [boot_magic - KERNEL_VIRTUAL_BASE], eax
    mov [boot_mbi   - KERNEL_VIRTUAL_BASE], ebx

    ; Use a temporary low stack until the higher-half alias is active.
    mov esp, boot_stack_top - KERNEL_VIRTUAL_BASE

    call serial_init
    mov esi, msg_boot_enter - KERNEL_VIRTUAL_BASE
    call serial_puts

    call setup_temp_paging
    mov esi, msg_temp_paging - KERNEL_VIRTUAL_BASE
    call serial_puts

    ; Install the temporary page directory.  It maps:
    ;   0x00000000..0x003fffff -> 0x00000000..0x003fffff
    ;   0xc0000000..0xc03fffff -> 0x00000000..0x003fffff
    mov eax, boot_page_directory - KERNEL_VIRTUAL_BASE
    mov cr3, eax

    ; i686 supports 4MiB pages via CR4.PSE; use them for the bootstrap map.
    mov eax, cr4
    or eax, 0x00000010
    mov cr4, eax

    mov eax, cr0
    or eax, 0x80000000          ; CR0.PG
    mov cr0, eax

    ; We are still executing through the low identity mapping here.
    mov esi, msg_paging_enabled - KERNEL_VIRTUAL_BASE
    call serial_puts

    ; Switch EIP to the higher-half alias with an absolute jump.
    mov eax, higher_half_entry
    jmp eax

higher_half_entry:
    ; From here on, code and stack addresses are higher-half virtual addresses.
    mov esp, kernel_stack_top
    mov esi, msg_high_half
    call serial_puts

    push dword [boot_mbi]
    push dword [boot_magic]
    call kernel_main

.halt:
    cli
    hlt
    jmp .halt

setup_temp_paging:
    push eax
    push ecx
    push edi

    mov edi, boot_page_directory - KERNEL_VIRTUAL_BASE
    xor eax, eax
    mov ecx, 1024
    rep stosd

    mov eax, _PAGE_BOOT_4M
    mov [boot_page_directory - KERNEL_VIRTUAL_BASE + 0 * 4], eax
    mov [boot_page_directory - KERNEL_VIRTUAL_BASE + PDE_HIGH_INDEX * 4], eax

    pop edi
    pop ecx
    pop eax
    ret

serial_init:
    push eax
    push edx

    mov dx, 0x3F8 + 1
    xor al, al
    out dx, al                    ; disable interrupts
    mov dx, 0x3F8 + 3
    mov al, 0x80
    out dx, al                    ; enable divisor latch
    mov dx, 0x3F8 + 0
    mov al, 0x03
    out dx, al                    ; divisor low: 38400 baud
    mov dx, 0x3F8 + 1
    xor al, al
    out dx, al                    ; divisor high
    mov dx, 0x3F8 + 3
    mov al, 0x03
    out dx, al                    ; 8N1
    mov dx, 0x3F8 + 2
    mov al, 0xC7
    out dx, al                    ; FIFO on, clear, 14-byte threshold
    mov dx, 0x3F8 + 4
    mov al, 0x0B
    out dx, al                    ; IRQs enabled, RTS/DSR set

    pop edx
    pop eax
    ret

serial_putc:
    push eax
    push edx
    mov ah, al
.wait:
    mov dx, 0x3F8 + 5
    in al, dx
    test al, 0x20
    jz .wait
    mov al, ah
    mov dx, 0x3F8
    out dx, al
    pop edx
    pop eax
    ret

serial_puts:
    push eax
    push esi
.next:
    lodsb
    test al, al
    jz .done
    call serial_putc
    jmp .next
.done:
    pop esi
    pop eax
    ret

section .rodata
msg_boot_enter:      db "[OK] boot.asm entered at low 1MiB load address", 10, 0
msg_temp_paging:     db "[OK] temporary 4MiB identity+higher-half map ready", 10, 0
msg_paging_enabled:  db "[OK] CR4.PSE and CR0.PG enabled", 10, 0
msg_high_half:       db "[OK] jumped to higher-half entry", 10, 0

section .bss
align 4096
boot_page_directory:
    resd 1024

align 16
boot_stack_bottom:
    resb 16384
boot_stack_top:

align 16
kernel_stack_bottom:
    resb 16384
kernel_stack_top:

align 4
boot_magic:
    resd 1
boot_mbi:
    resd 1

section .note.GNU-stack noalloc noexec nowrite progbits
