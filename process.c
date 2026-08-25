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

    if (next->ksp == 0u) {
        build_initial_frame(next);  /* 首次派发 */
    }
    context_switch(&prev->ksp, next->ksp);
}
