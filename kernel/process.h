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

/* 五态模型（任务书规定）：语义对照 Linux TASK_* 位集。PROC_BLOCKED 自
 * fork/waitpid/信号里程碑起具备真实睡眠/唤醒语义：进入 = process_wait_block()
 * （置态后 sched_yield 不回队），唤醒 = exit_process_code() 扫描匹配等待者改
 * READY 并重新入队（对照 Linux TASK_UNINTERRUPTIBLE + try_to_wake_up 裁剪版）。 */
typedef enum {
    PROC_CREATED = 0,   /* 已分配 PCB，栈未就绪（空槽 memset 态） */
    PROC_READY,         /* 在就绪队列中等待调度 */
    PROC_RUNNING,       /* 当前 CPU 正在此上下文上执行 */
    PROC_BLOCKED,       /* 阻塞等待事件（waitpid；唤醒源见 exit_process_code）*/
    PROC_TERMINATED     /* 已退出，待 wait 收割（zombie）或惰性回收 */
} proc_state_t;

/* 地址空间句柄：沿用旧版 process.h 字段布局保证兼容。
 * page_dir 为页目录物理地址；0 表示沿用当前内核页目录
 * （共享目录模式：paging.c 未暴露独立地址空间创建 API）。 */
typedef struct { uint32_t page_dir, heap_base, stack_top; } address_space_t;

/* 上下文类型：内核态例程 or ring3 用户程序。 */
typedef enum { PROC_CTX_KERNEL = 0, PROC_CTX_USER } proc_ctx_t;

/* 任务书规定：进程表上限 32。下标即 pid；pcb[0] 为内核/idle 保留位
 * （Linux idle_task 对应物，core.c:3977 同概念）。[STARVATION-FIX 2026-08-26]
 * pcb[0] 不再绝对免入队：IRQ0 抢占量子到期时与其他 RUNNING 上下文同等
 * 重入队轮转（sched_preempt_tick）——寄居其上的 enter_usermode() ring3 探针
 * 依赖该路径在常驻 shell REPL 存活期间继续获得 CPU（详见 process.c
 * sched_preempt_tick 注释）；就绪队列空时仍由 schedule_next() 兜底回落。 */
#define MAX_PROCESSES 32u

/* ── 信号最小集固定编号（Linux x86 对齐；nginx M1 数据面，无 handler 框架）──
 * pending 位图为 PCB 内 uint32_t 位图（bit<<sig），仅本三号 + sig==0 探活受
 * 支持；其余编号 kill 层直接 -EINVAL。默认动作：SIGKILL/SIGTERM=终止，
 * SIGCHLD=忽略留待 wait 收割（投递点 = 目标进程下次 int80 返回前）。 */
#define CATOS_SIGKILL    9u   /* linux-ref include/uapi/asm-generic/signal-defs.h 族 */
#define CATOS_SIGTERM   15u
#define CATOS_SIGCHLD   17u
#define CATOS_SIGNAL_MAX 31u /* pending 位图容量上界（uint32_t） */

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
    /* ── 进程家族/退出/信号数据面（fork/waitpid/kill 里程碑）──────────── */
    uint32_t        ppid;           /* 父 pid；0=内核直系（不可被 wait）*/
    int32_t         exit_code;      /* TERMINATED 后有效：正常退出=(code&0xFF)<<8，
                                     * 信号致死=sig&0x7F（Linux wait status 编码）*/
    uint32_t        sig_pending;    /* 信号 pending 位图，bit (1u<<sig) */
    uint32_t        wait_target;    /* BLOCKED 等待者：目标子 pid / -1=任意子；
                                     * 仅 state==PROC_BLOCKED 期间有意义 */
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
/* 带退出码的终止（waitpid 数据面）：exit_process(pid) 等价 exit_process_code(pid,0)。
 * code 传入时即按 Linux wait status 编码：正常退出调用方传 (code&0xFF)<<8；
 * 信号致死路径传 sig&0x7F。副作用：记录 exit_code、唤醒匹配的 BLOCKED 等待父、
 * 给存活父置 SIGCHLD pending、对濒死进程的孤儿子女做摘链/zombie 预收割。 */
void     exit_process_code(int pid, int code);
uint32_t process_current_pid(void);

/* ── waitpid 内核原语（syscall.c sys_waitpid 以三段循环组装阻塞语义）──────── */
/* 单次扫描：在 current 的子女（ppid==current->pid 且槽位在用）中找 target
 * （-1=任意）已 TERMINATED 者。命中返回子 pid 并经 *code_out 带出编码化
 * exit_code（不收割，收割由 process_wait_reap 完成）；有活子但无 zombie 返回 0；
 * 无匹配子女返回 -ECHILD。单核无抢占窗口内 scan+copy-out+reap 天然原子。 */
int      process_wait_scan(int target, int32_t *code_out);
/* 阻塞原语：current 置 PROC_BLOCKED + 记录等待目标 + sched_yield()（BLOCKED
 * 不回队，既有语义）；被 exit_process_code 唤醒改 READY 入队后本函数返回，
 * 调用方必须重跑 scan（唤醒可能是多子女竞争下的"虚假唤醒"）。禁止忙等。 */
void     process_wait_block(int target);
/* 收割 zombie：释放残留内核栈/私有目录并 memset 清槽（slot 可复用）。 */
void     process_wait_reap(int pid);

/* ── kill 语义核心（nr=35 数据面；返回 0 / -EINVAL / -ESRCH）─────────────────
 * SIGKILL → 对目标直接 exit_process_code(编码 sig)；SIGTERM/SIGCHLD → 仅置
 * 目标 pending 位（投递点 = 目标下次 syscall 返回前，见 syscall.c 投递器）；
 * sig==0 为存在性探活。自杀（pid==current）走同一路径自然成立。 */
int      process_kill(uint32_t pid, uint32_t sig);

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
 *   - ring3 fork 由下方 process_fork_user() 承接（nr=33 已接线）。
 * ═══════════════════════════════════════════════════════════════════════════ */
int process_fork(void);

/* ═══════════════════════════════════════════════════════════════════════════
 * nr=33 FORK 接线：ring3 int 0x80 中断帧上的 fork（syscall.c sys_fork 调用）。
 *
 * 与 process_fork() 的分工：本函数服务 PROC_CTX_USER 调用方——int80 已把
 * 完整用户现场（pusha×8 + [vector][err] + iret 五连）压在父进程私有内核栈顶
 * （arch.asm isr_128 布局），子进程无需克隆内核 C 栈尾，而是以"恢复到 ring3
 * 调用点之后"的方式重建现场。
 *
 * 返回值布置（寄存器约定，与 process_fork 契约同源）：
 *   - 父进程：普通 C 返回 → interrupts.c 写回帧 eax=子 pid；其余 gp 寄存器
 *     经既有 popa/iretd 原样还原（ring3 sc5() 无 clobber 契约依赖此）；
 *   - 子进程：首次派发经 context_switch 进入 fork_user_resume_stub：
 *     重装 ds/es/fs/gs=0x23 → 按父被陷时的 pusha 快照逆序弹回全部 gp 寄存器
 *     （eax 强制 0）→ iretd 回到 int $0x80 下一条指令、同一 user ESP/EFLAGS。
 *     即子进程视角 = "fork 调用返回了 0"，其余寄存器与父逐一相同。
 *
 * 中断帧定位（无 interrupts.c 配合的强签名扫描）：自本函数栈帧锚点向栈顶
 * 扫描 [w[0]==128][w[1]==0][user eip][cs==0x1B][IF][uesp][ss==0x23] 六元组，
 * 唯一命中即 vector 槽；gp 快照按 frame_t 相对偏移取回。扫描失败拒绝 fork
 * （-1），绝不凭猜测克隆。
 *
 * 资源语义：地址空间 paging_clone_address_space() COW 克隆（写缺页走 ISR14
 * 已接线路径）；fd_table 全局单例浅共享（同 process_fork 注释）；ppid/信号
 * 位图清零初始化，exit_code=0。调度：子 PROC_READY 入队尾，零改动复用既有
 * schedule_next()/抢占 tick。
 *
 * 限制（诚实声明）：legacy 共享目录进程（page_dir==0）fork 后，共享目录中
 * 可写用户页被双侧标 RO+COW，其他同目录进程的写意图 syscall 缓冲区在首次
 * 写缺页前会得 -EFAULT（user_access_ok 查 RW 位）；每进程 fd 表仍留待禁区
 * 解锁。 ═══════════════════════════════════════════════════════════════════ */
int process_fork_user(void);

#endif /* CATOS_PROCESS_H */
