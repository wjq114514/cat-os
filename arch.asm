BITS 32
section .text
global arch_load_idt
global arch_load_gdt
global arch_load_tss
extern interrupt_dispatch
arch_load_idt:
 mov eax,[esp+4]
 lidt [eax]
 ret
arch_load_gdt:
 mov eax,[esp+4]
 lgdt [eax]
 ret
arch_load_tss:
 mov ax,[esp+4]
 ltr ax
 ret
%macro I 1
global isr_%1
isr_%1:
 push dword 0
 push dword %1
 jmp isr_common
%endmacro
%assign n 0
%rep 32
I n
%assign n n+1
%endrep
%assign n 32
%rep 16
I n
%assign n n+1
%endrep
I 128
isr_common:
 pusha
 push esp
 call interrupt_dispatch
 add esp,4
 popa
 add esp,8
 iretd
section .note.GNU-stack noalloc noexec nowrite progbits
