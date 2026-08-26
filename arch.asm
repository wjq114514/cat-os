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
%rep 14
I n
%assign n n+1
%endrep
; #PF already pushes an error code before entering the stub.
global isr_14
isr_14:
 push dword 14
 jmp isr_common_error
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
isr_common_error:
 ; COW fork 接线修复（2026-08）：#PF 时 CPU 已压入真实错误码、stub 只补压了
 ; vector，故 popa 后 add esp,8 恰好跳过 [vector][error_code]，ESP 即指向 EIP，
 ; iretd 可正确返回重执行触发指令。原多出的一条 add esp,4 会吞掉 EIP——
 ; iretd 把 CS 槽当 EIP 弹出，任何 #PF（含 ring3 COW 写陷阱）必三重故障；
 ; 现与 isr_common 对无错误码向量的已验证算术严格对齐。
 pusha
 push esp
 call interrupt_dispatch
 add esp,4
 popa
 add esp,8
 iretd
section .note.GNU-stack noalloc noexec nowrite progbits
