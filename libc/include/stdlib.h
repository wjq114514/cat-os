/*
 * stdlib.h —— Cat-OS 最小用户态 C 库：内存分配与进程退出声明（code9 · 并行任务）
 * ─────────────────────────────────────────────────────────────────────────────
 * malloc/free 为纯用户态实现（静态池 + 空闲链表），原因：内核当前不存在任何
 * 内存类 syscall —— 号表全量核实（syscall.h）：0=read 1=write 5=open 6=close
 * 11=exec 12=exit 13=wait + socket 族 20..28/29/30，无 brk/mmap/sbrk。
 *
 * exit() 使用 nr=12（CATOS_SYS_EXIT，syscall.c code2 追加段）。
 */

#ifndef CATOS_LIBC_STDLIB_H
#define CATOS_LIBC_STDLIB_H

#ifndef CATOS_LIBC_SIZE_T_DEFINED
#define CATOS_LIBC_SIZE_T_DEFINED
typedef __SIZE_TYPE__ size_t;
#endif

#ifndef CATOS_LIBC_NULL_DEFINED
#define CATOS_LIBC_NULL_DEFINED
#define NULL ((void *)0)
#endif

/* 分配 size 字节，16 字节对齐；失败返回 NULL（池耗尽或请求过大）。
 * size==0 按标准允许的实现返回一个可 free 的最小块。 */
void *malloc(size_t size);

/* 释放 p；p==NULL 无操作。野指针/越界指针/重复释放被防御性忽略
 * （魔数 + 池边界校验，ring3 下无 panic 通道）。 */
void free(void *p);

/* 终止当前 ring3 进程（nr=12 exit syscall），不返回。
 * 注意：内核 PCB 暂无退出码字段（process.h 定稿无此成员），
 * status 当前仅作 ABI 占位传递。 */
void exit(int status) __attribute__((noreturn));

#endif /* CATOS_LIBC_STDLIB_H */
