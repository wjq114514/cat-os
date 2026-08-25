/*
 * catos_syscall.h —— libc 私有头：int 0x80 内联封装（code9 · 非公共 ABI）
 * ─────────────────────────────────────────────────────────────────────────────
 * 仅供 libc 源码与测试编译单元使用，不安装、不出现在公共接口面。
 *
 * 调用约定逐字对齐 shell_user.c 的 syscall3（该写法已在 ring3 shell 上验证）：
 *   EAX = nr；EBX,ECX,EDX → a[0..2]；返回值 sign-extend 写回 EAX，负值 -errno。
 *   "b"/"c"/"d" 作为输入约束：int 0x80 由内核中断入口保存/恢复现场
 *   （interrupt_frame_t 全量压栈 + iretd），除 EAX 外寄存器内容可假设不变，
 *   与 shell_user.c 同一依据。本库以 -fno-pic -fno-pie 编译，
 *   EBX 不承担 GOT 基址，可安全用作传参。
 *
 * 本库最多用到 3 个参数位；ESI/EDI（a[3]/a[4]）暂无使用方。
 */

#ifndef CATOS_LIBC_SYSCALL_PRIV_H
#define CATOS_LIBC_SYSCALL_PRIV_H

static inline int catos_syscall3(unsigned nr, unsigned a0, unsigned a1,
                                 unsigned a2)
{
    int ret;
    __asm__ volatile("int $0x80"
                     : "=a"(ret)
                     : "a"(nr), "b"(a0), "c"(a1), "d"(a2)
                     : "memory");
    return ret;
}

/* VFS 兼容 ABI 号段（vfs.h / syscall.c 核实）。nr=3 是 close 别名雷区，
 * 永不使用 —— 见 stdio.h 头注释 L8 审计块引用。 */
#define CATOS_SYS_READ_NR  0u
#define CATOS_SYS_WRITE_NR 1u
#define CATOS_SYS_EXIT_NR  12u

#endif /* CATOS_LIBC_SYSCALL_PRIV_H */
