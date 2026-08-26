/*
 * Cat-OS 进程调度器（单 CPU，协作式 round-robin + 内核栈切换）。
 *
 * 依据（行号级）：
 *  - linux-ref/kernel/sched/core.c:1445-1464：RR tick 轮转语义；
 *    本 milestone 无时钟钩子可用（interrupts.c:23 timer_handler 已注册在
 *    IRQ0，且 irq_register_handler 为单槽 interrupts.c:20），故为协作式：
 *    进程显式调用 sched_yield() 触发轮转；
 *  - linux-ref/kernel/sched/core.c:4607：time_slice 概念（PCB 字段预留）；
 *  - linux-ref/kernel/sched/core.c:3977/:1207：idle task 兜底 —— pcb[0] 同概念；
 *  - 寄存器保存集 = callee-saved + eflags（Linux __switch_to_asm /
 *    Xv6 swtch() 最小切换集）；esp0 经 TSS 切换（x86 SDM Vol.3 §7.2.2，
 *    ring3->ring0 中断取栈来源），对应任务书"TSS esp0 切换内核栈"。
 */
#include "kernel.h"
#include "paging.h"
#include "process.h"

#include <stddef.h>

/* paging.c:26 全局符号（paging.h 未声明原型）。 */
extern void *memset(void *dst, int value, size_t n);

process_t pcb[MAX_PROCESSES];

static process_t *ready_head;
static process_t *ready_tail;
static process_t *current;      /* 正在运行的上下文，process_init 后恒非空 */

#define USER_CS         0x1Bu   /* usermode.c:13 setg(3,...,0xFA)->RPL3 代码 */
#define USER_DS         0x23u   /* setg(4,...,0xF2)->RPL3 数据               */
#define EFLAGS_IF_SET   0x202u

static void schedule_next(void);
static void process_trampoline(void);
static int process_alloc_slot(void);

/* ---------------------------------------------------------------------------
 * TSS esp0 更新 —— 不触碰锁定的 usermode.c：
 * sgdt 取当前 GDT 基址，解析描述符 5（usermode.c:13
 * setg(5,(uint32_t)&tss,sizeof(tss)-1,0x89)，描述符基址位布局 SDM Vol.3
 * §3.4.5），直接写 tss.esp0（packed 偏移 +4，usermode.c:7 字段序 prev,esp0）。
 * ------------------------------------------------------------------------- */
#define GDT_TSS_DESC_IDX  5u
#define TSS_OFFSETOF_ESP0 4u

static void arch_set_tss_esp0(uint32_t esp0)
{
    struct { uint16_t limit; uint32_t base; } __attribute__((packed)) gdtr;

    __asm__ volatile("sgdt %0" : "=m"(gdtr));

    const volatile uint32_t *desc =
        (const volatile uint32_t *)(uintptr_t)(gdtr.base +
                                               GDT_TSS_DESC_IDX * 8u);
    uint32_t lo = desc[0];
    uint32_t hi = desc[1];

    /* 类型字段校验（SDM Vol.3 §7.2.3）：0x89 = available 32-bit TSS；
     * 0x8B = busy 32-bit TSS —— arch_load_tss 的 ltr 执行后 CPU 会自动
     * 置位描述符 busy 位，因此运行期读到的一定是 0x8B。
     * [BUGFIX] 原校验只认 0x89，导致 esp0 永不更新、恒为初始 kernel_stack_top；
     * 用户进程每次 int 0x80 都在 kernel_main 栈上展开中断帧，踩掉 pcb[0].ksp
     * 保存的现场，exit 切回后 iret 弹垃圾 -> page fault CR2=0x8 死机。 */
    uint32_t tss_type = (hi >> 8) & 0xFFu;
    if (tss_type != 0x89u && tss_type != 0x8Bu) {
        kputs("[WARN] sched: GDT desc5 not a TSS (type=");
        kput_hex32(tss_type);
        kputs("), esp0 not updated\n");
        return;
    }
    uint32_t tss_base = (lo >> 16) | ((hi & 0xFFu) << 16) | (hi & 0xFF000000u);
    *(volatile uint32_t *)(tss_base + TSS_OFFSETOF_ESP0) = esp0;
}

/* ---------------------------------------------------------------------------
 * 上下文切换：仅保存/恢复 callee-saved + eflags。
 *
 * 栈镜像布局（恢复视角，低地址 -> 高地址）：
 *   [edi][esi][ebx][ebp][eflags][eip]
 *
 * 恢复路径从 popl %edi 续跑、ret 回到原调用者 —— 对 C ABI 等价于
 * "本函数正常返回"，caller-saved 寄存器跨调用允许失效，故 -O2 健全。
 * 首次运行进程由 build_initial_frame() 按同一布局伪造镜像，ret 落入
 * process_trampoline()。
 * ------------------------------------------------------------------------- */
static void __attribute__((noinline, noclone))
context_switch(uint32_t *prev_ksp_out, uint32_t next_ksp)
{
    __asm__ volatile(
        "pushfl\n\t"
        "pushl %%ebp\n\t"
        "pushl %%ebx\n\t"
        "pushl %%esi\n\t"
        "pushl %%edi\n\t"
        "movl %%esp, (%0)\n\t"      /* 快照当前内核 ESP -> prev->ksp */
        "movl %1, %%esp\n\t"        /* 载入 next 的内核 ESP          */
        "popl %%edi\n\t"
        "popl %%esi\n\t"
        "popl %%ebx\n\t"
        "popl %%ebp\n\t"
        "popfl\n\t"
        "ret\n\t"
        :
        : "r"(prev_ksp_out), "r"(next_ksp)
        : "memory", "cc");
}

/* 新进程初始内核栈镜像（槽位顺序与 context_switch 恢复序列一一对应）。 */
static void build_initial_frame(process_t *p)
{
    uint32_t *sp = (uint32_t *)(void *)
        ((uint8_t *)phys_to_virt(p->kstack_phys) + PAGE_SIZE);

    *(--sp) = (uint32_t)(uintptr_t)&process_trampoline; /* eip: 'ret' 目标 */
    *(--sp) = EFLAGS_IF_SET;                            /* eflags          */
    *(--sp) = 0u;                                       /* ebp             */
    *(--sp) = 0u;                                       /* ebx             */
    *(--sp) = 0u;                                       /* esi             */
    *(--sp) = 0u;                                       /* edi             */
    p->ksp = (uint32_t)(uintptr_t)sp;
}

/* ---------------------------------------------------------------------------
 * 新上下文首跑跳板：设置 TSS.esp0 / 可选 cr3，然后进入进程本体。
 * ------------------------------------------------------------------------- */
static void process_trampoline(void)
{
    process_t *p = current;

    /* 内核栈就绪后立即登记 esp0：此后该进程 ring3 触发的中断/系统调用
     * 将落在本进程自己的内核栈上（任务书要求的 esp0 切换语义）。 */
    arch_set_tss_esp0((uint32_t)(uintptr_t)phys_to_virt(p->kstack_phys) +
                      PAGE_SIZE);

    /* page_dir==0 表示共享当前目录；非 0 则切换 cr3（flush 由 mov cr3 隐式完成）。 */
    if (p->as.page_dir != 0u) {
        __asm__ volatile("movl %0, %%cr3" :: "r"(p->as.page_dir) : "memory");
    }

    if (p->ctx_type == PROC_CTX_KERNEL) {
        p->entry();
        /* 例程正常返回视为退出（兜底回收，等价 POSIX exit(0)）。 */
        exit_process((int)p->pid);
        for (;;) {
            sched_yield();      /* 不应到达：exit 已让出且不再入队 */
        }
    }

    /* ---- PROC_CTX_USER：iret 进 ring3 ----
     * 栈帧与 usermode.c:60 的既有移交完全同构：
     *   push SS(0x23)/ESP/FLAGS(0x202)/CS(0x1B)/EIP 后 iretd。 */
    __asm__ volatile(
        "movw %0, %%ax\n\t"
        "movw %%ax, %%ds\n\t"
        "movw %%ax, %%es\n\t"
        "movw %%ax, %%fs\n\t"
        "movw %%ax, %%gs\n\t"
        "pushl %1\n\t"              /* SS    */
        "pushl %2\n\t"              /* ESP   */
        "pushl %3\n\t"              /* EFLAGS*/
        "pushl %4\n\t"              /* CS    */
        "pushl %5\n\t"              /* EIP   */
        "iretl\n\t"
        :
        : "i"(USER_DS), "r"(USER_DS), "r"(p->user_esp),
          "i"(EFLAGS_IF_SET), "r"(USER_CS), "r"(p->user_entry)
        : "ax", "memory");

    for (;;) {                  /* iretd 不返回，防御性停机 */
        __asm__ volatile("hlt");
    }
}

/* ---------------------------------------------------------------------------
 * 就绪队列（FIFO 单向链，round-robin 入队尾/出队头）。
 * ------------------------------------------------------------------------- */
static void ready_enqueue(process_t *p)
{
    p->next_ready = NULL;
    if (ready_tail) {
        ready_tail->next_ready = p;
    } else {
        ready_head = p;
    }
    ready_tail = p;
}

/* 出队下一个 READY 进程；顺带惰性回收队列中残留的 TERMINATED 进程资源
 * （回收发生在"别人的栈"上，绝不释放 current 正踩着的栈）。 */
static process_t *pick_next(void)
{
    while (ready_head) {
        process_t *p = ready_head;
        ready_head = p->next_ready;
        if (ready_tail == p) {
            ready_tail = NULL;
        }
        p->next_ready = NULL;

        if (p->state == PROC_READY) {
            return p;
        }
        if (p->state == PROC_TERMINATED && p->kstack_phys != 0u) {
            pmm_free_page(p->kstack_phys);      /* 延迟回收点 */
            p->kstack_phys = 0u;
        }
    }
    return NULL;
}

/* pcb[0] idle 循环：队列空时 CPU 停机省电，任何中断（PIT/键盘等）
 * 将唤醒并重新检查就绪队列。 */
static void __attribute__((noreturn)) sched_idle(void)
{
    for (;;) {
        __asm__ volatile("hlt");
    }
}

/* ---------------------------------------------------------------------------
 * 公开 API。
 * ------------------------------------------------------------------------- */

/* ---------------------------------------------------------------------------
 * COW fork（契约全文见 process.h process_fork 注释）。
 *
 * 三段式实现：
 *   process_fork          —— 汇编包装器：入口处捕获父进程调用点的完整寄存器
 *                            现场（callee-saved×4 + eflags + 返回地址槽），
 *                            调 C 核心，父路径原样弹回现场后 ret（eax=子 pid）；
 *   process_fork_kernel   —— C 核心：COW 克隆地址空间 + 克隆内核栈尾 +
 *                            组装子进程首派发镜像 + 入就绪队列；
 *   fork_child_resume_stub —— 子进程首次被 context_switch 派发时的 eip：
 *                            从栈顶魔数槽恢复调用点 esp、清 eax 后 ret，
 *                            精确落在"call process_fork 的下一条指令"。
 *
 * 子进程栈镜像布置（自高向低；克隆区与镜像区零重叠）：
 *   c_top-len .. c_top-1   父 [调用点RA槽, 栈顶) 的逐字节镜像（len 同偏移）
 *   im[0..4]               edi/esi/ebx/ebp/eflags（cap 捕获值）
 *   im[5]                  &fork_child_resume_stub   （context_switch 的 ret 目标）
 *   im[6]                  magic = c_top-len         （stub 用 (%esp) 取走）
 *   child->ksp = &im[0]
 *
 * 对照 linux-ref/kernel/fork.c：copy_process()(复制)+wake_up_new_task()(入队)
 * 对应本核心；ret_from_fork 恢复对应 stub；父直接拿到 pid 对应 fork 返回约定。
 * ------------------------------------------------------------------------- */
extern void fork_child_resume_stub(void);   /* 下方内联汇编定义 */

int process_fork_kernel(const uint32_t *cap);

__asm__(
    ".text\n"
    ".align 4\n"
    "fork_child_resume_stub:\n\t"
    "movl (%esp), %esp\n\t"     /* 栈顶即魔数槽（im[6] 已被 ret 消费） */
    "xorl %eax, %eax\n\t"       /* 子进程返回值恒 0 */
    "ret\n\t"
);

/* 不用 C 写包装器的原因：编译器前奏（push 寄存器/帧指针省略策略）会让
 * "调用点现场"的捕获点漂移；汇编保证捕获恰在函数入口，语义稳定。 */
__asm__(
    ".text\n"
    ".align 4\n"
    ".globl process_fork\n"
    ".type process_fork, @function\n"
    "process_fork:\n\t"
    "pushfl\n\t"
    "pushl %ebp\n\t"
    "pushl %ebx\n\t"
    "pushl %esi\n\t"
    "pushl %edi\n\t"            /* esp=cap：[edi][esi][ebx][ebp][eflags][RA][caller…] */
    "pushl %esp\n\t"
    "call process_fork_kernel\n\t"
    "addl $4, %esp\n\t"
    "popl %edi\n\t"
    "popl %esi\n\t"
    "popl %ebx\n\t"
    "popl %ebp\n\t"
    "popfl\n\t"                 /* 含 IF 在内的父现场统一由此恢复（核心内 cli） */
    "ret\n\t"
    ".size process_fork, .-process_fork\n"
);

/* fd_table 取舍说明（任务书要求写明）：本内核 VFS fd 表为全局单例
 * （vfs.c fds[VFS_MAX_FD]，PCB 无 per-process 字段），fork 取浅共享——
 * 零拷贝零引用计数，父子与全体既有进程共用同一打开文件集合；
 * 代价是无独立 fd 空间/close 传播。每进程 fd 表涉及禁区 vfs.c 改动，
 * 与 syscall 编号一并留待下一轮统一规划。 */
int process_fork_kernel(const uint32_t *cap)
{
    process_t *parent;
    process_t *child;
    uintptr_t kstack;
    uint32_t child_pd = 0u;
    uint32_t cr3_now;
    uintptr_t p_tail, p_top, c_top, len;
    uint32_t *im;
    int slot;

    if (!current || current == &pcb[0]) {       /* idle/内核主上下文不可为父 */
        kputs("[WARN] fork: rejected (no runnable parent)\n");
        return -1;
    }
    parent = current;
    if (parent->ctx_type != PROC_CTX_KERNEL || parent->kstack_phys == 0u) {
        /* ring3 fork 属下一轮 syscall 接线（需在 int80 中断帧上克隆）。 */
        kputs("[WARN] fork: kernel-context only this round\n");
        return -1;
    }

    __asm__ volatile("cli" ::: "memory");   /* 至入队完成；IF 由包装器 popfl 还原 */

    slot = process_alloc_slot();
    if (slot < 0) {
        kputs("[WARN] fork: process table full\n");
        return -1;
    }
    kstack = pmm_alloc_page();
    if (!kstack) {
        memset(&pcb[slot], 0, sizeof(pcb[slot]));
        return -12;                             /* ENOMEM */
    }

    /* 父地址空间取 cr3 实值而非 parent->as.page_dir：legacy 进程
     * （page_dir==0 共享内核目录跑 shell/sock_abi 的现网形态）同样可 fork。 */
    __asm__ volatile("mov %%cr3, %0" : "=r"(cr3_now));
    if (paging_clone_address_space(cr3_now, &child_pd) != 0) {
        memset(&pcb[slot], 0, sizeof(pcb[slot]));
        pmm_free_page(kstack);
        return -12;                             /* clone 内部已自回滚 */
    }

    /* 内核栈尾克隆：父 [调用点, 栈顶) → 子同偏移。溢出防御上限留 64B。 */
    p_tail = (uintptr_t)cap + 5u * sizeof(uint32_t);    /* RA 槽 = 调用点 esp */
    p_top = (uintptr_t)phys_to_virt(parent->kstack_phys) + PAGE_SIZE;
    c_top = (uintptr_t)phys_to_virt(kstack) + PAGE_SIZE;
    len = p_top - p_tail;
    if (len == 0u || len > PAGE_SIZE - 64u) {
        paging_destroy_address_space(child_pd);
        memset(&pcb[slot], 0, sizeof(pcb[slot]));
        pmm_free_page(kstack);
        return -1;
    }
    memcpy((void *)(c_top - len), (const void *)p_tail, len);

    child = &pcb[slot];
    memcpy(child, parent, sizeof(*child));  /* 结构整体复制后改写差异字段 */

    /* 子首派发 context_switch 镜像（槽序=恢复序列，布局论证见函数头）。 */
    im = (uint32_t *)(c_top - len - 7u * sizeof(uint32_t));
    im[0] = cap[0];
    im[1] = cap[1];
    im[2] = cap[2];
    im[3] = cap[3];
    im[4] = cap[4];                                     /* eflags（含 IF） */
    im[5] = (uint32_t)(uintptr_t)&fork_child_resume_stub;
    im[6] = (uint32_t)(c_top - len);                    /* magic 槽 */
    child->ksp = (uint32_t)(uintptr_t)im;

    child->pid = (uint32_t)slot;                        /* 下标即 pid（既有约定） */
    child->as.page_dir = child_pd;                      /* 私有 COW 目录 */
    child->kstack_phys = (uint32_t)kstack;
    child->next_ready = NULL;
    child->state = PROC_READY;
    ready_enqueue(child);

    kputs("[OK] COW fork: parent pid=");
    kput_dec(parent->pid);
    kputs(" child pid=");
    kput_dec((uint32_t)slot);
    kputs(" pd=");
    kput_hex32(child_pd);
    kputs("\n");
    return slot;                        /* 父进程经包装器拿到 eax=子 pid */
}

/* 任务书要求标记串：" [OK] process scheduler initialized"。 */
void process_init(void)
{
    memset(pcb, 0, sizeof(pcb));

    /* pcb[0]：内核/idle 上下文（core.c:3977 idle_task 对应物），
     * page_dir=0 表示沿用启动页目录。分配独立内核栈页 + 构建 idle 帧，
     * 修复 exit 后切回 pcb[0] 时栈内容被踩导致的 CR2=0x8 崩溃：*
     *   - 独立栈：build_initial_frame 不踩内核代码区（phys_to_virt(0)）
     *   - TSS.esp0 可指向有效栈（pid=0 运行时中断不掉到已回收页）
     *   - idle 帧 ret 到 sched_idle 停机循环，不依赖易损的 kernel_main 栈 */
    pcb[0].pid = 0u;
    pcb[0].state = PROC_RUNNING;
    pcb[0].ctx_type = PROC_CTX_KERNEL;
    pcb[0].as.page_dir = 0u;
    {   uintptr_t idle_page = pmm_alloc_page();
        if (idle_page) {
            pcb[0].kstack_phys = (uint32_t)idle_page;
            pcb[0].entry = sched_idle;  /* trampoline 会 ret 到这里 */
            pcb[0].ksp = 0u;   /* build_initial_frame 将构建帧指向 trampoline */
            build_initial_frame(&pcb[0]);
            /* 注意：build_initial_frame 设 eip=process_trampoline，
             * trampoline 读 p->entry 并调用它 -> sched_idle 循环 */
        }
    }
    current = &pcb[0];
    ready_head = ready_tail = NULL;

    kputs("[OK] process scheduler initialized (32 slots, round-robin, idle=pid0)\n");
}

uint32_t process_current_pid(void)
{
    return current ? current->pid : 0u;
}

static int process_alloc_slot(void)
{
    for (uint32_t i = 1u; i < MAX_PROCESSES; ++i) {   /* pid0 保留 */
        if (pcb[i].state == PROC_CREATED && pcb[i].kstack_phys == 0u &&
            pcb[i].pid == 0u) {
            return (int)i;
        }
    }
    return -1;
}

/* 任务书签名：create_process(entry, page_dir)。创建内核态例程进程并入队。 */
int create_process(void (*entry)(void), uint32_t page_dir)
{
    if (!entry) {
        return -1;
    }
    int slot = process_alloc_slot();
    if (slot < 0) {
        kputs("[WARN] sched: process table full\n");
        return -1;
    }
    process_t *p = &pcb[slot];

    uintptr_t stack_page = pmm_alloc_page();
    if (!stack_page) {
        kputs("[WARN] sched: no page for kernel stack\n");
        return -1;
    }

    memset(p, 0, sizeof(*p));
    p->pid = (uint32_t)slot;
    p->state = PROC_CREATED;
    p->ctx_type = PROC_CTX_KERNEL;
    p->entry = entry;
    p->as.page_dir = page_dir;
    p->as.stack_top = (uint32_t)(uintptr_t)phys_to_virt(stack_page) + PAGE_SIZE;
    p->kstack_phys = (uint32_t)stack_page;
    p->ksp = 0u;                    /* 首次派发时 build_initial_frame */

    p->state = PROC_READY;
    ready_enqueue(p);
    return slot;
}

/* 用户态进程变体：entry 为 ELF e_entry，user_esp 通常为 ELF_USER_STACK_SP。 */
int create_user_process(uint32_t user_entry, uint32_t page_dir, uint32_t user_esp)
{
    if (user_entry == 0u || user_esp == 0u) {
        return -1;
    }
    int slot = process_alloc_slot();
    if (slot < 0) {
        kputs("[WARN] sched: process table full\n");
        return -1;
    }
    process_t *p = &pcb[slot];

    uintptr_t stack_page = pmm_alloc_page();
    if (!stack_page) {
        kputs("[WARN] sched: no page for kernel stack\n");
        return -1;
    }

    memset(p, 0, sizeof(*p));
    p->pid = (uint32_t)slot;
    p->state = PROC_CREATED;
    p->ctx_type = PROC_CTX_USER;
    p->user_entry = user_entry;
    p->user_esp = user_esp;
    p->as.page_dir = page_dir;
    p->as.stack_top = user_esp;
    p->kstack_phys = (uint32_t)stack_page;
    p->ksp = 0u;

    p->state = PROC_READY;
    ready_enqueue(p);
    return slot;
}

/* 协作式让出：RUNNING -> READY 入队尾，随后轮转（core.c RR tick 语义的
 * 显式触发版本）。TERMINATED/BLOCKED 进程调用则纯让出不回队。 */
void sched_yield(void)
{
    process_t *prev = current;

    if (!prev || prev == &pcb[0]) {
        return;                     /* idle 无可让 */
    }
    if (prev->state == PROC_RUNNING) {
        prev->state = PROC_READY;
        ready_enqueue(prev);
    }
    schedule_next();
}

/* 时钟抢占钩子（stage4）：量子到期且就绪队列非空时轮转一次。
 * 量子取 100 tick（100Hz PIT => 1s）：单行串口 write 最长 ~224 字符 × ~87µs/字符
 * ≈ 19ms << 一个时间片，保证测试 marker 行不被抢占撕裂（可 grep）。
 * pcb[0]（内核/idle 上下文）免重入队：其 ksp 快照即 IRQ 现场本身，
 * schedule_next() 队列空时自然回落 pcb[0] 续跑 iret 尾声；状态保持 RUNNING
 * 属良性捷径，与 exit_process 的 idle 兜底路径同构（注释明示防误改）。 */
#define SCHED_PREEMPT_QUANTUM_TICKS 100u
static uint32_t preempt_tick_cnt;

void sched_preempt_tick(void)
{
    preempt_tick_cnt++;
    if (preempt_tick_cnt < SCHED_PREEMPT_QUANTUM_TICKS) {
        return;
    }
    preempt_tick_cnt = 0u;

    if (!ready_head) {
        return;                     /* 就绪队列空：无可轮转 */
    }

    process_t *prev = current;
    if (prev && prev != &pcb[0] && prev->state == PROC_RUNNING) {
        prev->state = PROC_READY;
        ready_enqueue(prev);
    } else if (!prev) {
        return;
    }
    schedule_next();
}

/* 启动调度：把调用者（kernel_main）登记为 pcb[0]，轮转直至就绪队列清空
 * （全部 READY 进程 TERMINATED）后返回 kernel_main 上下文。 */
void sched_start(void)
{
    kputs("[OK] scheduler start: draining ready queue\n");
    schedule_next();                /* 无 READY 时立即返回 */
    kputs("[OK] scheduler returned to kernel context (queue empty)\n");
}

/* 终态移交：派发下一个就绪进程且不期望返回（用户态 shell 场景，
 * 语义等同旧 enter_usermode() 的 jmp$ 终态移交）。 */
void sched_launch(void)
{
    kputs("[OK] scheduler launch: handing CPU to next ready process\n");
    schedule_next();
}

/* 任务书 API：标记终止并回收资源。
 * 自杀路径（current==p）：栈不能立刻释放——context_switch 还要在其上
 * 保存现场，故仅置状态，物理页由 pick_next() 的惰性回收点释放；
 * 外部 kill 路径：若目标不在运行中，立即回收。 */
void exit_process(int pid)
{
    if (pid <= 0 || pid >= (int)MAX_PROCESSES) {
        return;
    }
    process_t *p = &pcb[pid];
    if (p->state == PROC_TERMINATED) {
        return;
    }

    kputs("[OK] sched: exit pid=");
    kput_dec((uint32_t)pid);
    kputs("\n");

    p->state = PROC_TERMINATED;

    /* [COW] 私有地址空间回收（fork 子进程路径）：用户页 ref-- 归零才还 PMM，
     * 内核半区共享不动（paging.c destroy）。page_dir==0 的 legacy 进程
     * （shell/sock_abi/探针，跑共享内核目录）不进此分支 —— 现有行为不变。
     * 自杀路径必须先切回内核目录再销毁：销毁会拆掉正踩着的用户映射；
     * 切表安全的前提是内核半区在所有目录逐字相同（clone 语义保证）。 */
    if (p->as.page_dir != 0u && p->as.page_dir != paging_kernel_pd_phys()) {
        if (current == p) {
            __asm__ volatile("movl %0, %%cr3"
                             :: "r"(paging_kernel_pd_phys()) : "memory");
        }
        paging_destroy_address_space(p->as.page_dir);
        p->as.page_dir = 0u;
    }

    if (current != p) {
        if (p->kstack_phys != 0u) {
            pmm_free_page(p->kstack_phys);
            p->kstack_phys = 0u;
        }
    } else {
        /* 自杀路径：置 TERMINATED 后照常 schedule_next()。
         * 队列空时 pick_next() 兜底回落 pcb[0] —— 其 ksp 保存的是
         * 首次抢占时的 IRQ 现场，iret 尾声即恢复 enter_usermode()
         * 驻留的 ring3 探针，tcp81/串口服务随之复活（stage4 设计语义）。
         * 历史：曾因 TSS.esp0/GDT 错位导致恢复必崩（CR2≈0x8）而临时
         * 改为 cli;hlt 停机，但停机会连探针一并杀死（blackbox 5/18 回归实证）；
         * TSS 修复后恢复路径已验证安全，回归正常调度。 */
        schedule_next();
        /* 不可达防御：若调度器异常返回则安全停机，绝不带病续跑 */
        for(;;){ __asm__ volatile("cli; hlt"); }
    }
}

/* 核心派发：选出 next 并切换。prev 现场（含 C 局部变量所在内核栈）
 * 由各进程私有内核栈天然保存。 */
static void schedule_next(void)
{
    process_t *next = pick_next();

    if (!next) {
        next = &pcb[0];             /* 队列空 -> 回 idle/kernel 上下文 */
    }
    if (next == current) {
        /* [FIX] 轮转/让出后唯一就绪者是自己：pick_next 已将其出队，若直接
         * return 会留下"state=READY 却不在队列"的孤儿 —— 下个量子因
         * state!=RUNNING 拒绝再入队，随后队列空回落 pcb[0]，该任务被永久
         * 遗弃（单常驻任务每量子必现）。还原 RUNNING 以维持"current 恒
         * RUNNING"不变式；exit 路径不会命中本分支（TERMINATED 不回队列）。 */
        if (next->state == PROC_READY) {
            next->state = PROC_RUNNING;
        }
        return;
    }

    process_t *prev = current;
    current = next;
    next->state = PROC_RUNNING;

    /* [DBG-TEMP] 调度切换观测（定位 exit 后 iret 崩溃，诊断完删除） */
    kputs("[DBG] sw prev="); kput_hex32((uint32_t)(uintptr_t)prev);
    kputs(" pnxt="); kput_hex32((uint32_t)(uintptr_t)next);
    kputs(" pksp="); kput_hex32(prev ? prev->ksp : 0u);
    kputs(" nksp="); kput_hex32(next->ksp);
    kputs("\n");

    /* stage4 抢占语义：每次切换进程都必须刷新 TSS.esp0 到新进程的私有内核栈，
     * 否则下一个 int0x80/IRQ 会落到旧进程的内核栈上（已被回收/释放）导致踩踏。
     * pcb[0] 的 idle 栈在 process_init 中分配，确保这里条件成立。 */
    if (next->kstack_phys != 0u) {
        arch_set_tss_esp0((uint32_t)(uintptr_t)phys_to_virt(next->kstack_phys) +
                          PAGE_SIZE);
    }

    /* [COW] 地址空间切换：引入私有页目录（fork 子）后，context_switch 只换栈
     * 不换表，必须在此刷新 cr3 —— 共享目录进程(as.page_dir==0)落内核目录，
     * 私有目录进程落其自身目录。mov cr3 隐式 flush 非 GLOBAL 项；内核半区
     * 在所有目录中逐字相同（clone 保证），故本函数后续代码执行不受影响。 */
    {
        uint32_t want_cr3 = (next->as.page_dir != 0u)
                                ? next->as.page_dir
                                : paging_kernel_pd_phys();
        uint32_t have_cr3;
        __asm__ volatile("mov %%cr3, %0" : "=r"(have_cr3));
        if (have_cr3 != want_cr3) {
            __asm__ volatile("movl %0, %%cr3" :: "r"(want_cr3) : "memory");
        }
    }

    if (next->ksp == 0u) {
        build_initial_frame(next);  /* 首次派发 */
    }
    context_switch(&prev->ksp, next->ksp);
}
