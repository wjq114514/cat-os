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

/* ═══════════════════════════════════════════════════════════════════════════
 * COW fork 内核侧核心（对照 linux-ref/kernel/fork.c kernel_clone()/copy_process()
 * 的"复制-入队-双返回"骨架，不照搬代码；本轮不接 syscall 编号，供下一轮
 * int 0x80 包装或内核例程直接调用）。
 *
 * 契约：
 *   int pid = process_fork(void);
 *   if (pid < 0)  { 仅父进程会看到：-1 上下文非法 / -12 ENOMEM }
 *   if (pid == 0) { 子进程执行流 } else { 父进程：pid=子 pid }
 *
 * 返回值布置（寄存器约定）：
 *   - 父进程：普通 C 返回，eax=子 pid（slot 下标即 pid，同 create_process）；
 *     callee-saved/eflags 由包装器现场恢复，对调用方等价一次普通函数调用。
 *   - 子进程：首次被调度时经 fork_child_resume_stub 恢复到"调用点之后"
 *     （call process_fork 的下一条指令），eax 强制 0；ebx/esi/edi/ebp/eflags
 *     与父在调用点的活值逐一相同（包装器入口捕获）；内核栈 [调用点, 栈顶)
 *     区间逐字节镜像到子栈同偏移 —— 子的后续 C 执行环境与父完全同构。
 *
 * 资源语义：
 *   - 地址空间：paging_clone_address_space() COW 克隆（可写用户页父子共享
 *     RO+COW、ref=2；写自陷时私有化）；子拥有独立页目录与内核栈页。
 *   - fd_table 取舍：本内核 VFS fd 表是全局单例（vfs.c fds[VFS_MAX_FD]，
 *     PCB 无该字段），fork 采用浅共享（零拷贝零计数）——所有进程共享同一
 *     打开文件集合，任一 close 全体可见。引入每进程 fd 表需改禁区 vfs.c，
 *     与 syscall 编号一并留待下一轮。
 *   - 调度：子 PROC_READY 入就绪队列尾，由既有 schedule_next()/抢占 tick
 *     自然派发（调度器入口零改动）；首次派发走 context_switch 标准路径。
 *
 * 限制（本轮）：
 *   - 仅 PROC_CTX_KERNEL 例程上下文可调（pcb[0]/idle 拒绝）；
 *   - ring3 fork 需下一轮 syscall 接线：在 int80 中断帧上克隆
 *     （child 帧 eax=0、parent 帧 eax=pid），复用本轮 clone/fault 地基。
 * ═══════════════════════════════════════════════════════════════════════════ */
int process_fork(void);

#endif /* CATOS_PROCESS_H */
