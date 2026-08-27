#include <stddef.h>
#include <stdint.h>

#include "kernel.h"
#include "multiboot.h"
#include "paging.h"
#include "interrupts.h"
#include "syscall.h"
#include "process.h"
#include "netring.h"
#include "pci.h"
#include "e1000.h"
#include "net.h"
#include "keyboard.h"
#include "ide.h"
#include "rtc.h"
#include "user.h"
#include "vfs.h"
#include "elf.h"
#include "shell_bin.h"
#include "sock_abi_bin.h"   /* stage4: 内嵌 sock_abi 测试 ELF */
#include "httpd_bin.h"      /* httpd 接线: 内嵌 ring3 HTTP 守护 ELF */

#define VGA_W   80u
#define VGA_H   25u
#define COLOR   0x0Eu
#define COM1    0x3F8u

static volatile uint16_t *vga;
static uint32_t vga_pos;

static inline void outb(uint16_t port, uint8_t val) {
    __asm__ volatile("outb %0, %1" :: "a"(val), "Nd"(port));
}

static inline uint8_t inb(uint16_t port) {
    uint8_t val;
    __asm__ volatile("inb %1, %0" : "=a"(val) : "Nd"(port));
    return val;
}

static void serial_init(void) {
    outb(COM1 + 1, 0x00);
    outb(COM1 + 3, 0x80);
    outb(COM1 + 0, 0x03);
    outb(COM1 + 1, 0x00);
    outb(COM1 + 3, 0x03);
    outb(COM1 + 2, 0xC7);
    outb(COM1 + 4, 0x0B);
}

static void serial_putc(char c) {
    for (uint32_t spin = 0; spin < 100000; ++spin) {
        if (inb(COM1 + 5) & 0x20) {
            break;
        }
    }
    outb(COM1, (uint8_t)c);
}

static void vga_putc(char c) {
    if (!vga) {
        return;
    }

    if (c == '\n') {
        vga_pos += VGA_W - (vga_pos % VGA_W);
    } else {
        if (vga_pos >= VGA_W * VGA_H) {
            vga_pos = 0;
        }
        vga[vga_pos++] = (uint16_t)((COLOR << 8) | (uint8_t)c);
    }
}

void kputs(const char *s) {
    while (*s) {
        serial_putc(*s);
        vga_putc(*s);
        ++s;
    }
}

void kput_hex32(uint32_t value) {
    static const char hex[] = "0123456789ABCDEF";
    kputs("0x");
    for (int shift = 28; shift >= 0; shift -= 4) {
        char c = hex[(value >> (uint32_t)shift) & 0xFu];
        serial_putc(c);
        vga_putc(c);
    }
}

void kput_dec(uint32_t value) {
    char buf[11];
    uint32_t i = 0;

    if (value == 0) {
        kputs("0");
        return;
    }

    while (value && i < sizeof(buf)) {
        buf[i++] = (char)('0' + (value % 10u));
        value /= 10u;
    }

    while (i) {
        char c = buf[--i];
        serial_putc(c);
        vga_putc(c);
    }
}

void kput_sdec(int32_t value) {
    if (value < 0) {
        kputs("-");
        kput_dec((uint32_t)(-(value + 1)) + 1u);
        return;
    }
    kput_dec((uint32_t)value);
}

void panic(const char *message) {
    kputs("[ERR] ");
    kputs(message);
    kputs("\n");
    for (;;) {
        __asm__ volatile("cli; hlt");
    }
}

static void vga_init_via_ioremap(void) {
    vga = (volatile uint16_t *)ioremap(0x000B8000u, PAGE_SIZE,
                                       _PAGE_RW | _PAGE_PCD | _PAGE_PWT);
    if (!vga) {
        panic("ioremap(VGA) failed");
    }
    vga_pos = 0;
    kputs("[OK] VGA mapped through ioremap window\n");
}

void kernel_main(uint32_t magic, uint32_t mb_info_phys) {
    serial_init();
    kputs("[OK] COM1 ready in higher-half C\n");
    kputs("[OK] kernel_main virtual address ");
    kput_hex32((uint32_t)(uintptr_t)&kernel_main);
    kputs("\n");

    if (magic != MULTIBOOT_BOOTLOADER_MAGIC) {
        panic("bad multiboot magic");
    }
    kputs("[OK] multiboot magic 0x2BADB002\n");

    paging_init(mb_info_phys);

    interrupts_init();
    syscall_init();
    process_init();
    netring_init();
    pci_init();
    e1000_init();
    net_init();
    keyboard_init();
    ide_init();
    rtc_init();
    boot_epoch = rtc_get_epoch();
    usermode_init();
    vfs_init();
    interrupts_enable();kputs("[OK] pre-enter_usermode\n");
    enter_usermode();
    /* Old inline tests done. Load and launch the ring3 shell via ELF loader. */
    {
        uint32_t entry;
        int rc = elf_load(shell_user_elf, shell_user_elf_len, &entry);
        if (rc < 0) {
            kputs("[ERR] shell ELF load failed: ");
            kput_sdec(rc);
            kputs("\n");
        } else {
            kputs("[OK] shell ELF loaded, entry=");
            kput_hex32(entry);
            kputs("\n");
            int pid = create_user_process(entry, 0, ELF_USER_STACK_SP);
            if (pid < 0) {
                kputs("[ERR] create_user_process failed\n");
            } else {
                kputs("[OK] shell process pid=");
                kput_dec((uint32_t)pid);
                kputs(", launching scheduler\n");
                sched_launch();
            }
        }
    }

    vga_init_via_ioremap();
    kputs("cat-OS higher-half paging online\n");
    kputs("[OK] PMM managed pages: total=");
    kput_dec(pmm_total_pages());
    kputs(" free=");
    kput_dec(pmm_free_pages());
    kputs(" limit=");
    kput_hex32((uint32_t)pmm_managed_limit());
    kputs("\n");

    uintptr_t dma_page = pmm_alloc_dma_page();
    if (!dma_page || dma_page >= ISA_DMA_LIMIT) {
        panic("DMA <=16MiB page allocation failed");
    }
    kputs("[OK] DMA-capable page reserved/tested at ");
    kput_hex32((uint32_t)dma_page);
    kputs("\n");
    pmm_free_page(dma_page);

    kputs("[OK] cat-OS up and running in the higher half ^.^\n");

    for (;;) {
        net_poll();
        __asm__ volatile("hlt");
    }
}


/* ===========================================================================
 * stage4: IRQ0 tick 钩子 —— 三阶段 autorun：
 *   phase1  boot 后延迟拉起内嵌 sock_abi 测试进程；
 *   phase2  sock_abi 流程完成后（PCB 转 PROC_TERMINATED）自动 exec 内嵌
 *           ring3 shell REPL（shell_user.elf，常驻 for(;;) 读 /dev/kbd）；
 *   phase3  shell 就绪后 exec 内嵌 httpd 守护（httpd.elf，常驻 listen :7000）。
 *           时序契约：sock_abi → 探针 → shell → httpd。
 *
 * 为什么放 tick 里而不是 kernel_main 顺序执行：enter_usermode() 的 ring3 探针
 * 以 jmp $ 终态驻留（usermode.c，用户锁定文件），kernel_main 中其后代码不可达；
 * IRQ0 每 tick 都会进入本钩子（中断驱动），是探针存活期间唯一可靠的内核入口。
 *
 * 栈布局（互不重叠，elf_load_ex 参数化栈底防 PTE 盲写覆盖）：
 *   探针     0x700000..0x701000（usermode.c iret 帧 SP=0x700FFC）
 *   sock_abi 0x702000..0x703000（CATOS_SOCKABI_*，elf.h）
 *   shell    0x704000..0x705000（下方 CATOS_SHELL_*；段本体在 0x3ff000/0x400000）
 *   httpd    0x706000..0x707000（CATOS_HTTPD_*；段本体在 0x4ff000/0x500000，
 *            与 shell 段位错开 —— 共享页目录下两常驻进程段不得重叠）
 *
 * 调度：create_user_process 入队后由 sched_preempt_tick() 的量子轮转接管 CPU，
 * 与探针进程并存分时；sock_abi exit 后队列回落探针并即刻派发 shell；
 * shell 阻塞读键盘时 kbdwait 走 sti;hlt 睡眠，IRQ0/net_poll 不受影响。
 * shell REPL 常驻不退出（仅 'exit' 命令走 sys_exit）；届时队列照旧回落探针。
 *
 * 失败策略：两阶段任一失败仅打日志不 panic —— autorun 是增强路径，绝不能
 * 拖垮已全绿的 blackbox/inject 回归基线；shell 不可用时探针 jmp $ 循环即兜底。
 * =========================================================================== */

/* stage4: shell 进程专用栈布局 —— 与探针/sock_abi 栈页互不重叠（见上）。 */
#define CATOS_SHELL_STACK_BASE 0x704000u
#define CATOS_SHELL_USER_SP    (CATOS_SHELL_STACK_BASE + 4096u)

/* httpd 接线: 守护进程专用栈布局 —— 探针 0x700000/sock_abi 0x702000/shell
 * 0x704000 之后顺延一页。elf_load_ex 对已映射 vaddr 是覆盖写 PTE，栈页重叠
 * 即踩掉先驻程序现场；httpd 与 shell 常驻并存，必须独立页。 */
#define CATOS_HTTPD_STACK_BASE 0x706000u
#define CATOS_HTTPD_USER_SP    (CATOS_HTTPD_STACK_BASE + 4096u)

void stage4_autorun_tick(void)
{
    static int sock_done;        /* phase1 已执行（无论成败） */
    static int shell_done;       /* phase2 已执行（一次性）   */
    static int httpd_done;       /* phase3 已执行（一次性）   */
    static int32_t sock_pid = -1;
    uint32_t entry;

    /* ---- phase1: 延迟 2s 拉起 sock_abi 测试进程 ---- */
    if (!sock_done) {
        if (ticks < 200u)           /* 避开启动期日志洪峰 */
            return;
        sock_done = 1;

        if (sock_abi_elf_len == 0u) {
            /* 镜像未链接进来：视为流程已完结，直接放行 phase2 进 shell */
            kputs("[WARN] stage4: sock_abi image not linked\n");
            return;
        }
        kputs("[OK] stage4: launching sock_abi test process\n");
        int segs = elf_load_ex(sock_abi_elf, sock_abi_elf_len, &entry,
                               CATOS_SOCKABI_STACK_BASE);
        if (segs < 0) {
            kputs("[ERR] stage4: sock_abi elf_load_ex failed: ");
            kput_sdec(segs);
            kputs("\n");
            return;                 /* 装载失败：流程视作完结，下 tick 进 shell */
        }
        int pid = create_user_process(entry, 0u, CATOS_SOCKABI_USER_SP);
        if (pid < 0) {
            kputs("[ERR] stage4: create_user_process(sock_abi) failed\n");
            return;
        }
        sock_pid = pid;
        kputs("[OK] stage4: sock_abi pid=");
        kput_dec((uint32_t)pid);
        kputs(" entry=");
        kput_hex32(entry);
        kputs("\n");
        return;
    }

    /* ---- phase3: shell 就绪后 exec 内嵌 httpd 守护（常驻；一次性）----
     * ⚠️ 源码位置在 phase2 之前，但时序严格晚于 phase2：仅当 shell_done
     * 已置位（phase2 在更早 tick 完成）才进入本块；未就绪时必须【落穿】
     * 到下方 phase2，绝不可提前 return —— 否则 phase2 被永远挡在本函数外，
     * shell_done 恒不置位，三阶段互相死等。
     *
     * httpd 链接于 0x500000、栈页 0x706000，与 shell(0x400000/0x704000)
     * 互不重叠，单一共享页目录下可常驻并存；accept 空转靠调度量子轮转让出。
     * 失败策略同前：仅日志不 panic，shell/httpd 互不依赖对方存活。 */
    if (!httpd_done && shell_done) {
        httpd_done = 1;

        if (httpd_elf_len == 0u) {
            kputs("[WARN] stage4: httpd image not linked\n");
        } else {
            kputs("[OK] stage4: exec embedded httpd daemon\n");
            int segs3 = elf_load_ex(httpd_elf, httpd_elf_len, &entry,
                                    CATOS_HTTPD_STACK_BASE);
            if (segs3 < 0) {
                kputs("[ERR] stage4: httpd elf_load_ex failed: ");
                kput_sdec(segs3);
                kputs("\n");
            } else {
                int pid3 = create_user_process(entry, 0u, CATOS_HTTPD_USER_SP);
                if (pid3 < 0) {
                    kputs("[ERR] stage4: create_user_process(httpd) failed\n");
                } else {
                    kputs("[OK] stage4: httpd pid=");
                    kput_dec((uint32_t)pid3);
                    kputs(" entry=");
                    kput_hex32(entry);
                    kputs(" (resident daemon, listen :7000)\n");
                }
            }
        }
    }

    /* ---- phase2: sock_abi 流程完成后 exec 内嵌 shell REPL（一次性）---- */
    if (shell_done)
        return;
    /* sock_abi 已成功创建的场合：等它 exit（exit_process 置 TERMINATED，
     * 终态恒定不复用 —— process_alloc_slot 只认 memset 过的空槽）。
     * 未创建（镜像缺失/装载失败）则流程视作已完结。 */
    if (sock_pid > 0 && pcb[sock_pid].state != PROC_TERMINATED)
        return;
    shell_done = 1;

    if (shell_user_elf_len == 0u) {
        kputs("[WARN] stage4: shell image not linked; probe loop stays\n");
        return;                     /* 探针 jmp $ 即兜底驻留 */
    }
    kputs("[OK] stage4: exec embedded shell REPL\n");
    int segs = elf_load_ex(shell_user_elf, shell_user_elf_len, &entry,
                           CATOS_SHELL_STACK_BASE);
    if (segs < 0) {
        kputs("[ERR] stage4: shell elf_load_ex failed: ");
        kput_sdec(segs);
        kputs("\n");
        return;                     /* 探针 jmp $ 兜底 */
    }
    int pid = create_user_process(entry, 0u, CATOS_SHELL_USER_SP);
    if (pid < 0) {
        kputs("[ERR] stage4: create_user_process(shell) failed\n");
        return;                     /* 探针 jmp $ 兜底 */
    }
    kputs("[OK] stage4: shell pid=");
    kput_dec((uint32_t)pid);
    kputs(" entry=");
    kput_hex32(entry);
    kputs(" (resident REPL, stdin=/dev/kbd)\n");
}
