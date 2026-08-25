#ifndef CATOS_PROCESS_H
#define CATOS_PROCESS_H

/*
 * Cat-OS 进程调度器接口。
 *
 * 设计依据（行号级）：
 *  - linux-ref/kernel/sched/core.c:1445-1464：RR 类任务在 tick 中轮转
 *    time_slice 的 round-robin 语义（本实现为协作式 yield，见 sched_yield）；
 *  - linux-ref/kernel/sched/core.c:4607 p->rt.time_slice = sched_rr_timeslice：
 *    时间片字段对应 PCB 中的 tick 预留；
 *  - linux-ref/kernel/sched/core.c:3977/:1207 is_idle_task(rq->curr)：
 *    pid0 作为 idle/内核上下文兜底 —— 本实现 pcb[0] 同概念。
 */

#include <stdint.h>

/* 五态模型（任务书规定）：语义对照 Linux TASK_* 位集。 */
typedef enum {
    PROC_CREATED = 0,   /* 已分配 PCB，栈未就绪 */
    PROC_READY,         /* 在就绪队列中等待调度 */
    PROC_RUNNING,       /* 当前 CPU 正在此上下文上执行 */
    PROC_BLOCKED,       /* 等待事件（本 milestone 仅定义，无睡眠/唤醒原语）*/
    PROC_TERMINATED     /* 已退出，待回收 */
} proc_state_t;

/* 地址空间句柄：沿用旧版 process.h 字段布局保证兼容。
 * page_dir 为页目录物理地址；0 表示沿用当前内核页目录
 * （共享目录模式：paging.c 未暴露独立地址空间创建 API）。 */
typedef struct { uint32_t page_dir, heap_base, stack_top; } address_space_t;

/* 上下文类型：内核态例程 or ring3 用户程序。 */
typedef enum { PROC_CTX_KERNEL = 0, PROC_CTX_USER } proc_ctx_t;

/* 任务书规定：进程表上限 32。下标即 pid；pcb[0] 为内核/idle 保留位
 * （Linux idle_task 对应物，core.c:3977 同概念），永不入就绪队列。 */
#define MAX_PROCESSES 32u

typedef struct process {
    uint32_t        pid;
    proc_state_t    state;
    address_space_t as;
    proc_ctx_t      ctx_type;
    void          (*entry)(void);   /* PROC_CTX_KERNEL 的内核入口 */
    uint32_t        user_entry;     /* PROC_CTX_USER 的 ring3 EIP (e_entry) */
    uint32_t        user_esp;       /* ring3 初始 ESP */
    uint32_t        kstack_phys;    /* 内核栈物理页；0=未分配/已回收 */
    uint32_t        ksp;            /* context_switch 后的内核 ESP 快照 */
    struct process *next_ready;     /* 就绪队列单向链指针 */
} process_t;

extern process_t pcb[MAX_PROCESSES];

void     process_init(void);
int      create_process(void (*entry)(void), uint32_t page_dir);
int      create_user_process(uint32_t user_entry, uint32_t page_dir,
                             uint32_t user_esp);
void     sched_yield(void);
void     sched_preempt_tick(void);   /* stage4: IRQ0 时钟抢占钩子 */
void     sched_start(void);
void     sched_launch(void);
void     exit_process(int pid);
uint32_t process_current_pid(void);

#endif /* CATOS_PROCESS_H */
