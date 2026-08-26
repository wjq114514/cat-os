#include <stddef.h>
#include <stdint.h>

#include "kernel.h"
#include "multiboot.h"
#include "paging.h"

#define MAX_DIRECT_MAP_PHYS (IOREMAP_BASE - KERNEL_VIRT_BASE) /* 768MiB */
#define MAX_MANAGED_PAGES   (MAX_DIRECT_MAP_PHYS / PAGE_SIZE)
#define BITMAP_WORDS        (MAX_MANAGED_PAGES / 32u)

extern char __kernel_start[];
extern char __kernel_end[];

static page_directory_t kernel_page_directory __attribute__((aligned(PAGE_SIZE)));
static uint32_t pmm_bitmap[BITMAP_WORDS]; /* 1 bit set means reserved/allocated. */
/* ── 物理页引用计数（COW fork 地基）─────────────────────────────────────────
 * 预算：MAX_DIRECT_MAP_PHYS=768MiB → MAX_MANAGED_PAGES=196608 页 × 1B =
 * 192KiB 静态 BSS（随内核镜像常驻；128MiB 实机仅前 32768 项有意义，
 * 其余恒 0）。选 BSS 而非 PMM 动态分配的理由：零初始化依赖、无分配顺序
 * 约束；代价是 128MiB 下永久占用 48 页物理内存（可忽略）。
 * GRUB 依 multiboot bss_end_addr(boot.asm:31) 清零，pmm_init 里仍显式
 * memset 兜底并确立"bitmap⇔refcnt"不变式。 */
static uint8_t page_refcnt[MAX_MANAGED_PAGES];
static uint32_t managed_pages;
static uint32_t free_page_count;
static uint32_t next_page_idx;
static uint32_t next_dma_page_idx;
static uintptr_t managed_limit_phys;
static uintptr_t direct_map_limit_phys;
static uintptr_t ioremap_next = IOREMAP_BASE;
static int final_paging_active;
static uint32_t kernel_pd_phys_cache;

void *memset(void *dst, int value, size_t n) {
    uint8_t *p = (uint8_t *)dst;
    while (n--) {
        *p++ = (uint8_t)value;
    }
    return dst;
}

void *memcpy(void *dst, const void *src, size_t n) {
    uint8_t *d = (uint8_t *)dst;
    const uint8_t *s = (const uint8_t *)src;
    while (n--) {
        *d++ = *s++;
    }
    return dst;
}

static uintptr_t align_up(uintptr_t value, uintptr_t align) {
    return (value + align - 1u) & ~(align - 1u);
}

static uintptr_t align_down(uintptr_t value, uintptr_t align) {
    return value & ~(align - 1u);
}

static void bitmap_set(uint32_t idx) {
    pmm_bitmap[idx / 32u] |= (1u << (idx % 32u));
}

static void bitmap_clear(uint32_t idx) {
    pmm_bitmap[idx / 32u] &= ~(1u << (idx % 32u));
}

static int bitmap_test(uint32_t idx) {
    return (pmm_bitmap[idx / 32u] & (1u << (idx % 32u))) != 0;
}

/* ── COW/地址空间公共辅助（user_access_ok 与 fork 路径共用）──────────────── */
static inline uint32_t read_cr3(void) {
    uint32_t v;
    __asm__ volatile("mov %%cr3, %0" : "=r"(v));
    return v;
}

/* 取 pd_phys 目录中 va 的 PTE 指针（经直映可写）；PDE 缺席/PSE 叶子返回 NULL。
 * 调用方保证 va 属用户半区时 pd_phys 非 0 且页对齐。 */
static pte_t *walk_pte(uint32_t pd_phys, uintptr_t va) {
    const page_directory_t *pd = (const page_directory_t *)phys_to_virt(pd_phys);
    pde_t pde = pd->entries[PDE_INDEX(va)];
    if ((pde & _PAGE_PRESENT) == 0u || (pde & _PAGE_PSE) != 0u) {
        return NULL;
    }
    page_table_t *pt = (page_table_t *)phys_to_virt(pde & PAGE_FRAME_MASK);
    return &pt->entries[PTE_INDEX(va)];
}

static void mark_page_free(uint32_t idx) {
    if (idx >= managed_pages) {
        return;
    }
    if (bitmap_test(idx)) {
        bitmap_clear(idx);
        ++free_page_count;
        page_refcnt[idx] = 0u;   /* 不变式：bitmap 清位 ⇔ refcnt==0 */
    }
}

static void mark_page_used(uint32_t idx) {
    if (idx >= managed_pages) {
        return;
    }
    if (!bitmap_test(idx)) {
        bitmap_set(idx);
        --free_page_count;
        page_refcnt[idx] = 1u;   /* 新占用者恰一个；COW 共享再走 page_ref_inc */
    }
}

static void mark_range_free(uintptr_t start, uintptr_t end) {
    start = align_up(start, PAGE_SIZE);
    end = align_down(end, PAGE_SIZE);
    if (end <= start) {
        return;
    }
    if (end > managed_limit_phys) {
        end = managed_limit_phys;
    }
    for (uintptr_t p = start; p < end; p += PAGE_SIZE) {
        mark_page_free((uint32_t)(p >> PAGE_SHIFT));
    }
}

static void mark_range_used(uintptr_t start, uintptr_t end) {
    start = align_down(start, PAGE_SIZE);
    end = align_up(end, PAGE_SIZE);
    if (end <= start) {
        return;
    }
    if (end > managed_limit_phys) {
        end = managed_limit_phys;
    }
    for (uintptr_t p = start; p < end; p += PAGE_SIZE) {
        mark_page_used((uint32_t)(p >> PAGE_SHIFT));
    }
}

static uintptr_t mmap_entry_end32(const struct multiboot_mmap_entry *entry) {
    if (entry->addr_high != 0) {
        return 0;
    }
    if (entry->len_high != 0 || entry->addr_low + entry->len_low < entry->addr_low) {
        return 0xFFFFFFFFu;
    }
    return entry->addr_low + entry->len_low;
}

static uintptr_t discover_memory_limit(const struct multiboot_info *mbi) {
    uintptr_t limit = 16u * 1024u * 1024u;

    if ((mbi->flags & MULTIBOOT_INFO_MEMORY) != 0) {
        limit = (uintptr_t)(mbi->mem_upper + 1024u) * 1024u;
    }

    if ((mbi->flags & MULTIBOOT_INFO_MEM_MAP) != 0) {
        uintptr_t mmap_end = mbi->mmap_addr + mbi->mmap_length;
        for (uintptr_t p = mbi->mmap_addr; p < mmap_end;) {
            const struct multiboot_mmap_entry *entry =
                (const struct multiboot_mmap_entry *)phys_to_virt(p);
            uintptr_t end = mmap_entry_end32(entry);
            if (entry->type == MULTIBOOT_MEMORY_AVAILABLE && end > limit) {
                limit = end;
            }
            p += entry->size + sizeof(entry->size);
        }
    }

    if (limit > MAX_DIRECT_MAP_PHYS) {
        limit = MAX_DIRECT_MAP_PHYS;
    }
    if (limit < 4u * 1024u * 1024u) {
        limit = 4u * 1024u * 1024u;
    }
    return align_down(limit, PAGE_SIZE);
}

static void pmm_init(uint32_t mbi_phys) {
    const struct multiboot_info *mbi = (const struct multiboot_info *)phys_to_virt(mbi_phys);

    managed_limit_phys = discover_memory_limit(mbi);
    managed_pages = (uint32_t)(managed_limit_phys >> PAGE_SHIFT);
    free_page_count = 0;
    next_page_idx = 0;
    next_dma_page_idx = KERNEL_PHYS_LOAD >> PAGE_SHIFT;

    for (uint32_t i = 0; i < BITMAP_WORDS; ++i) {
        pmm_bitmap[i] = 0xFFFFFFFFu;
    }
    memset(page_refcnt, 0, sizeof(page_refcnt)); /* GRUB 已清 BSS，兜底确立不变式 */

    if ((mbi->flags & MULTIBOOT_INFO_MEM_MAP) != 0) {
        uintptr_t mmap_end = mbi->mmap_addr + mbi->mmap_length;
        for (uintptr_t p = mbi->mmap_addr; p < mmap_end;) {
            const struct multiboot_mmap_entry *entry =
                (const struct multiboot_mmap_entry *)phys_to_virt(p);
            uintptr_t start = entry->addr_high ? 0xFFFFFFFFu : entry->addr_low;
            uintptr_t end = mmap_entry_end32(entry);
            if (entry->type == MULTIBOOT_MEMORY_AVAILABLE && end > start) {
                mark_range_free(start, end);
            }
            p += entry->size + sizeof(entry->size);
        }
    } else if ((mbi->flags & MULTIBOOT_INFO_MEMORY) != 0) {
        mark_range_free(0x00100000u, managed_limit_phys);
    }

    /* Keep legacy/firmware memory, the kernel image, and GRUB data reserved. */
    mark_range_used(0, 0x00100000u);
    mark_range_used(virt_to_phys(__kernel_start), virt_to_phys(__kernel_end));
    mark_range_used(mbi_phys, mbi_phys + PAGE_SIZE);
    if ((mbi->flags & MULTIBOOT_INFO_MEM_MAP) != 0) {
        mark_range_used(mbi->mmap_addr, mbi->mmap_addr + mbi->mmap_length);
    }

    direct_map_limit_phys = PDE_ALIGN_UP(managed_limit_phys);
    if (direct_map_limit_phys > MAX_DIRECT_MAP_PHYS) {
        direct_map_limit_phys = MAX_DIRECT_MAP_PHYS;
    }

    kputs("[OK] PMM bitmap initialized from multiboot mmap\n");
}

static inline void load_cr3(uintptr_t phys) {
    __asm__ volatile("mov %0, %%cr3" :: "r"(phys) : "memory");
}

static inline void invlpg(uintptr_t virt) {
    __asm__ volatile("invlpg (%0)" :: "r"(virt) : "memory");
}

static void enable_pse(void) {
    uintptr_t cr4;
    __asm__ volatile("mov %%cr4, %0" : "=r"(cr4));
    cr4 |= 0x00000010u;
    __asm__ volatile("mov %0, %%cr4" :: "r"(cr4));
}

static void build_kernel_page_directory(void) {
    memset(&kernel_page_directory, 0, sizeof(kernel_page_directory));

    for (uintptr_t phys = 0; phys < direct_map_limit_phys; phys += PDE_SIZE) {
        uintptr_t virt = KERNEL_VIRT_BASE + phys;
        kernel_page_directory.entries[PDE_INDEX(virt)] =
            (pde_t)(phys | _PAGE_PRESENT | _PAGE_RW | _PAGE_PSE | _PAGE_GLOBAL);
    }

    kputs("[OK] higher-half direct map prepared: ");
    kput_hex32((uint32_t)KERNEL_VIRT_BASE);
    kputs(".. ");
    kput_hex32((uint32_t)(KERNEL_VIRT_BASE + direct_map_limit_phys));
    kputs("\n");
}

void paging_init(uint32_t multiboot_info_phys) {
    pmm_init(multiboot_info_phys);
    build_kernel_page_directory();
    enable_pse();
    /* [COW 前提] CR0.WP=1：x86 复位默认 WP=0 时，supervisor 写完全无视
     * PTE.RW（SDM Vol.3 §4.6），ring0 例程对 RO+COW 页的写不会触发 #PF，
     * 写时复制对内核态进程彻底失效。Linux 同样在 head_32.S 置 WP。
     * 对既有路径零影响：内核写用户缓冲一律走直映别名（RW 大页），
     * 不经用户 VA；用户 VA 上的 RO 本就该拦。 */
    {
        uintptr_t cr0;
        __asm__ volatile("mov %%cr0, %0" : "=r"(cr0));
        if ((cr0 & 0x00010000u) == 0u) {   /* CR0.WP */
            __asm__ volatile("mov %0, %%cr0" :: "r"(cr0 | 0x00010000u)
                             : "memory");
            kputs("[OK] CR0.WP enabled (COW prerequisite)\n");
        }
    }
    kernel_pd_phys_cache = (uint32_t)virt_to_phys(&kernel_page_directory);
    load_cr3(kernel_pd_phys_cache);
    final_paging_active = 1;
    kputs("[OK] final kernel page directory loaded; low identity map removed\n");
}

static uintptr_t pmm_alloc_from(uint32_t start_idx, uint32_t end_idx, uint32_t *cursor) {
    if (end_idx > managed_pages) {
        end_idx = managed_pages;
    }
    if (start_idx >= end_idx) {
        return 0;
    }

    uint32_t span = end_idx - start_idx;
    uint32_t begin = *cursor;
    if (begin < start_idx || begin >= end_idx) {
        begin = start_idx;
    }

    for (uint32_t n = 0; n < span; ++n) {
        uint32_t idx = start_idx + ((begin - start_idx + n) % span);
        if (!bitmap_test(idx)) {
            mark_page_used(idx);
            *cursor = idx + 1;
            if (*cursor >= end_idx) {
                *cursor = start_idx;
            }
            return (uintptr_t)idx << PAGE_SHIFT;
        }
    }

    return 0;
}

uintptr_t pmm_alloc_page(void) {
    return pmm_alloc_from(KERNEL_PHYS_LOAD >> PAGE_SHIFT, managed_pages, &next_page_idx);
}

uintptr_t pmm_alloc_dma_page(void) {
    uint32_t dma_end = ISA_DMA_LIMIT >> PAGE_SHIFT;
    return pmm_alloc_from(KERNEL_PHYS_LOAD >> PAGE_SHIFT, dma_end, &next_dma_page_idx);
}

void pmm_free_page(uintptr_t phys) {
    if ((phys & (PAGE_SIZE - 1u)) != 0 || phys >= managed_limit_phys) {
        return;
    }
    mark_page_free((uint32_t)(phys >> PAGE_SHIFT));
}

/* ── 物理页引用计数 API（COW fork 地基）────────────────────────────────────
 * 语义与 linux-ref/include/linux/mm.h page_ref_* 同族：饱和方向取"宁可
 * 泄漏不可提前释放"。单核无锁；#PF 中断门内调用天然原子。 */
static int refcnt_overflow_warned;

uint32_t page_ref_get(uintptr_t phys) {
    uint32_t idx = (uint32_t)(phys >> PAGE_SHIFT);
    if ((phys & (PAGE_SIZE - 1u)) != 0u || idx >= managed_pages) {
        return 0u;
    }
    return page_refcnt[idx];
}

void page_ref_inc(uintptr_t phys) {
    uint32_t idx = (uint32_t)(phys >> PAGE_SHIFT);
    if ((phys & (PAGE_SIZE - 1u)) != 0u || idx >= managed_pages) {
        return;
    }
    if (page_refcnt[idx] >= 250u) {   /* 合法上限 ≤ MAX_PROCESSES(32)，不可达 */
        if (!refcnt_overflow_warned) {
            refcnt_overflow_warned = 1;
            kputs("[WARN] page refcount saturation (leaked reference?)\n");
        }
        return;
    }
    ++page_refcnt[idx];
}

uint32_t page_ref_dec(uintptr_t phys) {
    uint32_t idx = (uint32_t)(phys >> PAGE_SHIFT);
    if ((phys & (PAGE_SIZE - 1u)) != 0u || idx >= managed_pages) {
        return 0u;
    }
    if (page_refcnt[idx] == 0u) {     /* 下溢=引用记账被破坏，拒绝继续减 */
        if (!refcnt_overflow_warned) {
            refcnt_overflow_warned = 1;
            kputs("[WARN] page refcount underflow (double put?)\n");
        }
        return 0u;
    }
    return --page_refcnt[idx];
}

uintptr_t pmm_managed_limit(void) {
    return managed_limit_phys;
}

uint32_t pmm_total_pages(void) {
    return managed_pages;
}

uint32_t pmm_free_pages(void) {
    return free_page_count;
}

int map_page(uintptr_t virt, uintptr_t phys, uint32_t flags) {
    if (!final_paging_active) {
        return -1;
    }
    if (((virt | phys) & (PAGE_SIZE - 1u)) != 0) {
        return -2;
    }

    uint32_t pdi = PDE_INDEX(virt);
    uint32_t pti = PTE_INDEX(virt);
    pde_t pde = kernel_page_directory.entries[pdi];

    if ((pde & _PAGE_PRESENT) != 0 && (pde & _PAGE_PSE) != 0) {
        return -3; /* Do not split large direct-map leaves in this tiny kernel. */
    }

    page_table_t *pt;
    if ((pde & _PAGE_PRESENT) == 0) {
        uintptr_t pt_phys = pmm_alloc_page();
        if (!pt_phys) {
            return -4;
        }
        pt = (page_table_t *)phys_to_virt(pt_phys);
        memset(pt, 0, sizeof(*pt));
        kernel_page_directory.entries[pdi] =
            (pde_t)(pt_phys | _PAGE_PRESENT | _PAGE_RW |
                    (flags & (_PAGE_USER | _PAGE_PWT | _PAGE_PCD)));
    } else {
        pt = (page_table_t *)phys_to_virt(pde & PAGE_FRAME_MASK);
    }

    pt->entries[pti] = (pte_t)((phys & PAGE_FRAME_MASK) |
                               _PAGE_PRESENT |
                               (flags & (_PAGE_RW | _PAGE_USER | _PAGE_PWT |
                                         _PAGE_PCD | _PAGE_GLOBAL)));
    invlpg(virt);
    return 0;
}
/* ── 用户指针可达性预检（uaccess 前置校验，paging.c:330 原单行实现重构）────
 * 返回 1=允许访问；0=拒绝（调用方统一译为 -EFAULT：vfs.c:16/21、syscall.c:33）。
 *
 * 【L6/code6 修复】零长缓冲语义对齐 Linux：
 *   Linux copy_to_user()/copy_from_user()（lib/usercopy.c；arch/x86/lib/
 *   copy_user_*.S 按 count 执行搬运）在 n==0 时不产生任何用户态访存；
 *   即便 access_ok(to,n) 拒绝该指针，copy_*_user 也只是跳过拷贝原样返回
 *   n==0 —— 对调用方等价于成功。且 access_ok(NULL,0) 在 x86 上本就通过
 *   （NULL 属用户地址空间，__range_not_ok(0,0,TASK_SIZE_MAX)==0）。
 *   故本函数区分两种情形：
 *     len==0（含 buf==NULL）→ 合法，返回 1（不触碰任何页表项）；
 *     len>0 且 v<0x1000（NULL/低页洞）→ 返回 0，调用方给 -EFAULT。
 *   行为影响面（全部向 Linux/POSIX 收敛）：read/write/send/recv 等
 *   len==0 由旧 EFAULT 变为成功返回 0；net 层零长安全性已核
 *   （tcp_send net.c:940 显式 len==0→return 0；udp_send net.c:229
 *   len=0 → 纯头部 8B 数据报；memcpy_u(_,_,0) 无副作用）。 */
int user_access_ok(uintptr_t v, size_t n, uint32_t w)
{
    /* 零长缓冲永不解引用：v 取任意值（含 NULL）一律放行。依据见上。 */
    if (n == 0) {
        return 1;
    }
    /* 低页洞 + 上界检查。0xBFC00000u = KERNEL_VIRT_BASE - 4MiB 守护带，
     * 用户段不得触入内核直接映射区（与 syscall.c:32 user_range_ok 同源阈值）。 */
    if (v < 0x1000u || n > 0xBFC00000u - v) {
        return 0;
    }

    uintptr_t e = v + n;
    /* 逐页遍历 PDE/PTE：要求 PRESENT+USER，写意图另查 _PAGE_RW。
     * [COW] 遍历对象改为当前 cr3 目录（原硬编码 kernel_page_directory）：
     * fork 子进程跑私有页目录，其用户页只存在于自身目录中，按全局目录
     * 判定会把合法缓冲误杀成 EFAULT。legacy 进程 cr3 即内核目录，等价。
     * 本内核用户页均为急切全量映射（usermode.c:34），无 demand paging，
     * 故"PRESENT 即可达"语义保持自洽（NOTE 见函数尾审查记录）。 */
    const page_directory_t *cur_pd = (const page_directory_t *)phys_to_virt(read_cr3());
    for (uintptr_t p = v; p < e; p = (p & ~(PAGE_SIZE - 1u)) + PAGE_SIZE) {
        pde_t d = cur_pd->entries[PDE_INDEX(p)];
        if (!(d & _PAGE_PRESENT) || !(d & _PAGE_USER)) {
            return 0;
        }
        if (d & _PAGE_PSE) {
            continue;
        }
        page_table_t *t = (page_table_t *)phys_to_virt(d & PAGE_FRAME_MASK);
        pte_t x = t->entries[PTE_INDEX(p)];
        /* [COW] RW 被清但带 _PAGE_COW 的用户页 = fork 共享的逻辑可写页，
         * 写意图放行（真实写动作触发 #PF 由 paging_handle_cow_fault 复制）。
         * 对照 Linux：access_ok 本就不查 PTE RW，写保护交由真实 #PF。 */
        if (!(x & _PAGE_PRESENT) || !(x & _PAGE_USER) ||
            (w && !(x & _PAGE_RW) && !(x & _PAGE_COW))) {
            return 0;
        }
    }
    return 1;
}

/* ── code6 顺带审查记录（按严重度；均未在本轮扩张修复面）─────────────────
 * TODO(code6,HIGH): 上界检查无符号下溢 —— 当 v >= 0xBFC00000u 时
 *   `0xBFC00000u - v` 回绕为巨大值致上界检查失效；e=v+n 亦可回绕令循环体
 *   整体跳过而错误 return 1（例：v=0xFFFFFF00,n=0x200 → 直接放行）。
 *   当前由页表遍历的 _PAGE_USER 检查兜底（内核区 PDE 无 USER 位），属
 *   纵深防御缺口而非当下可达漏洞。修法一行：条件追加 `|| v >= 0xBFC00000u`。
 *   注：syscall.c:195「无整数溢出」的既有结论仅覆盖 ping_stats 合法入参，
 *   不覆盖恶意高地址入参。
 * TODO(code6,MED): PSE 分支 continue 跳过写意图检查 —— 大页未校验
 *   _PAGE_RW。现网不可达：build_kernel_page_directory 大页均为 RW 且无
 *   USER 位；map_page 拒绝分裂 PSE 叶子（返回 -3），不存在“用户只读大页”
 *   形态。若未来引入，需补 `(w && !(d & _PAGE_RW))`。
 * TODO(code6,LOW): 非 PSE 路径仅校验 PTE._PAGE_RW 未校验 PDE._PAGE_RW；
 *   x86 硬件取 PDE∧PTE RW 合集。现网不可达（map_page 所建 PD 项恒带 RW）。
 * NOTE(code6,INFO): “PRESENT 即可达”与 Linux access_ok 仅做区间检查、
 *   缺页交由真实访存 #PF 处理的模型不同；引入惰性分配/COW 时须重审本函数，
 *   避免把未驻留用户页误判 EFAULT。 */
/* [COW 复审 2026-08] 上述 NOTE 已落实：①遍历对象改为当前 cr3 目录（fork
 * 私有页目录进程不再被误判）；②COW 页（RO+COW 标记）对写意图放行，真实
 * 写动作由 #PF→paging_handle_cow_fault 私有化；③COW 页恒 PRESENT，
 * "PRESENT 即可达"语义不受影响。PSE 分支 TODO 维持原判（不可达）。 */

void *ioremap(uintptr_t phys, size_t size, uint32_t flags) {
    if (!size) {
        return NULL;
    }

    uintptr_t page_off = phys & (PAGE_SIZE - 1u);
    uintptr_t phys_page = align_down(phys, PAGE_SIZE);
    uintptr_t total = align_up(size + page_off, PAGE_SIZE);
    uintptr_t virt = ioremap_next;

    if (virt + total < virt || virt + total > IOREMAP_BASE + IOREMAP_SIZE) {
        return NULL;
    }

    uint32_t map_flags = flags | _PAGE_PRESENT | _PAGE_RW | _PAGE_PCD;
    for (uintptr_t off = 0; off < total; off += PAGE_SIZE) {
        if (map_page(virt + off, phys_page + off, map_flags) != 0) {
            return NULL;
        }
    }

    ioremap_next += total;
    return (void *)(virt + page_off);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * COW fork 内核地基（本轮：为 nginx master/worker 模型铺路，未接 syscall）。
 * 对照 linux-ref/kernel/fork.c 思路（不照搬代码）：
 *   dup_mmap→copy_page_range: 可写页 RO+COW 双侧标记、ref++（本文件 clone）；
 *   exit_mm→unmap_page_range: ref-- 归零才还 PMM（destroy）；
 *   do_wp_page: ref>1 复制私有页、双方 ref--；ref==1 恢复 RW（fault 路径）。
 * 差异：无 vma/反向映射，COW 判定直接编码在 PTE avail bit11。
 * ═══════════════════════════════════════════════════════════════════════════ */

uint32_t paging_kernel_pd_phys(void) {
    return kernel_pd_phys_cache;
}

/* ── 地址空间销毁 ── 退出路径回收：用户半区数据页 ref-- 归零还 PMM，
 * PT 页私有直接释放；内核半区（大页 GLOBAL 直映/ioremap）逐字共享，绝不动。
 * 只读共享页（如 fork 继承的 text）由最后一个退出者释放 —— 与 Linux
 * tee 页账本同语义。 */
void paging_destroy_address_space(uint32_t pd_phys) {
    if (pd_phys == 0u || (pd_phys & (PAGE_SIZE - 1u)) != 0u) {
        return;
    }
    if (pd_phys == kernel_pd_phys_cache) {
        kputs("[WARN] destroy_as: refuse kernel page directory\n");
        return;
    }
    if (pd_phys == read_cr3()) {   /* 防御：正踩着的目录只告警不拆 */
        kputs("[WARN] destroy_as: refuse live cr3 (leak instead of crash)\n");
        return;
    }

    page_directory_t *pd = (page_directory_t *)phys_to_virt(pd_phys);
    for (uint32_t pdi = 0; pdi < PDE_INDEX(KERNEL_VIRT_BASE); ++pdi) {
        pde_t pde = pd->entries[pdi];
        if ((pde & _PAGE_PRESENT) == 0u || (pde & _PAGE_PSE) != 0u) {
            continue;
        }
        uintptr_t pt_phys = pde & PAGE_FRAME_MASK;
        page_table_t *pt = (page_table_t *)phys_to_virt(pt_phys);
        for (uint32_t pti = 0; pti < PTRS_PER_TABLE; ++pti) {
            pte_t pte = pt->entries[pti];
            if ((pte & _PAGE_PRESENT) == 0u) {
                continue;
            }
            if (page_ref_dec(pte & PAGE_FRAME_MASK) == 0u) {
                pmm_free_page(pte & PAGE_FRAME_MASK);
            }
        }
        pmm_free_page(pt_phys);
        pd->entries[pdi] = 0u;
    }
    pmm_free_page(pd_phys);
}

/* ── 两阶段 COW 克隆 ────────────────────────────────────────────────────────
 * 阶段 A：增量分配子 PD/PT（唯一失败点），失败即回滚已处理 PDI：
 *         恢复父侧 RW/去 COW + ref-- + 释放 PT/PD —— 父空间零副作用。
 * 阶段 B：无分配纯搬运（infallible）：用户可写页双侧 RO+COW+ref++；
 *         只读/非 USER 页原样共享 ref++；内核半区 PDE 逐字复制。
 * 收尾：当前 cr3==父目录时重载一次，令父侧 RO 降级对 TLB 生效
 * （GLOBAL 内核项不受影响）。 */
int paging_clone_address_space(uint32_t parent_pd_phys, uint32_t *child_pd_phys_out) {
    if (parent_pd_phys == 0u || (parent_pd_phys & (PAGE_SIZE - 1u)) != 0u ||
        child_pd_phys_out == NULL) {
        return -12;
    }

    const page_directory_t *ppd = (const page_directory_t *)phys_to_virt(parent_pd_phys);
    uintptr_t child_pd = pmm_alloc_page();
    if (!child_pd) {
        return -12;
    }
    page_directory_t *cpd = (page_directory_t *)phys_to_virt(child_pd);
    memset(cpd, 0, sizeof(*cpd));

    const uint32_t user_pdis = PDE_INDEX(KERNEL_VIRT_BASE);   /* 768 */
    uint32_t pdi;
    for (pdi = 0; pdi < user_pdis; ++pdi) {
        pde_t pde = ppd->entries[pdi];
        if ((pde & _PAGE_PRESENT) == 0u || (pde & _PAGE_PSE) != 0u) {
            continue;
        }
        uintptr_t pt_phys = pmm_alloc_page();
        if (!pt_phys) {
            goto rollback;
        }
        /* 子 PDE：镜像父侧 USER/PWT/PCD，PT 页本身内核私管（RW 无妨，硬件取 PDE∧PTE 合集） */
        cpd->entries[pdi] = (pde_t)(pt_phys | _PAGE_PRESENT | _PAGE_RW |
                                    (pde & (_PAGE_USER | _PAGE_PWT | _PAGE_PCD)));

        page_table_t *ppt = (page_table_t *)phys_to_virt(pde & PAGE_FRAME_MASK);
        page_table_t *cpt = (page_table_t *)phys_to_virt(pt_phys);
        for (uint32_t pti = 0; pti < PTRS_PER_TABLE; ++pti) {
            pte_t pte = ppt->entries[pti];
            if ((pte & _PAGE_PRESENT) == 0u) {
                cpt->entries[pti] = 0u;
                continue;
            }
            if ((pte & _PAGE_USER) != 0u && (pte & _PAGE_RW) != 0u) {
                /* 可写用户页 → 父子同物理页、双侧 RO+COW（任务书 b)） */
                cpt->entries[pti] = (pte_t)((pte & PAGE_FRAME_MASK) |
                                            _PAGE_PRESENT | _PAGE_USER |
                                            _PAGE_COW);
                ppt->entries[pti] = cpt->entries[pti];
            } else {
                /* 只读用户页 / 非 USER 页 → 原样共享，不标记（任务书 b)）；
                 * ref++ 保证任一方退出后另一方不踩已释放页 */
                cpt->entries[pti] = pte;
            }
            page_ref_inc(pte & PAGE_FRAME_MASK);
        }
    }

    /* 内核半区逐字复制：GLOBAL 大页直映 + ioremap 窗口天然共享，不标记 */
    for (uint32_t kpdi = user_pdis; kpdi < PTRS_PER_TABLE; ++kpdi) {
        cpd->entries[kpdi] = ppd->entries[kpdi];
    }

    if (read_cr3() == parent_pd_phys) {
        load_cr3(parent_pd_phys);   /* 刷新非 GLOBAL TLB：父侧 RO 降级生效 */
    }
    *child_pd_phys_out = (uint32_t)child_pd;
    return 0;

rollback:
    /* 回滚 [0, pdi)：凡子侧带 COW 位者恢复父侧 RW 并 ref--；原样共享者 ref--。 */
    for (uint32_t undo = 0; undo < pdi; ++undo) {
        pde_t pde = cpd->entries[undo];
        if ((pde & _PAGE_PRESENT) == 0u) {
            continue;
        }
        page_table_t *cpt = (page_table_t *)phys_to_virt(pde & PAGE_FRAME_MASK);
        pte_t *pppt = walk_pte(parent_pd_phys, ((uintptr_t)undo << PDE_SHIFT));
        for (uint32_t pti = 0; pti < PTRS_PER_TABLE; ++pti) {
            pte_t cpte = cpt->entries[pti];
            if ((cpte & _PAGE_PRESENT) == 0u) {
                continue;
            }
            uintptr_t phys = cpte & PAGE_FRAME_MASK;
            if ((cpte & _PAGE_COW) != 0u && pppt != NULL) {
                pppt[pti] = (pte_t)(phys | _PAGE_PRESENT | _PAGE_USER | _PAGE_RW);
            }
            page_ref_dec(phys);
        }
        pmm_free_page(pde & PAGE_FRAME_MASK);
    }
    pmm_free_page(child_pd);
    return -12;
}

/* ── 写缺页 COW 路径（任务书 c)）──
 * 前置：IDT 中断门 IF=0，单核下与调度/其他 #PF 天然互斥。
 * ref>1 → 分配新页拷贝 4KB、旧页 ref--（父保持 RO+COW 待其自陷）、
 *         当前进程换新页 RW（对照 do_wp_page wp_page_reuse 对偶分支）；
 * ref==1 → 独占，原地恢复 RW 清 COW（do_wp_page 的 reuse 分支）。
 * 非 COW 缺页一律 -1 交回调用方走既有 panic 报告。 */
int paging_handle_cow_fault(uint32_t cr2, uint32_t error_code) {
    if ((error_code & 0x2u) == 0u) {          /* 只有写陷阱才可能是 COW */
        return -1;
    }
    if (cr2 >= KERNEL_VIRT_BASE) {            /* 用户半区才参与 COW */
        return -1;
    }

    pte_t *pte_p = walk_pte(read_cr3(), cr2);
    if (pte_p == NULL) {
        return -1;
    }
    pte_t pte = *pte_p;
    if ((pte & _PAGE_PRESENT) == 0u || (pte & _PAGE_USER) == 0u ||
        (pte & _PAGE_RW) != 0u || (pte & _PAGE_COW) == 0u) {
        return -1;                            /* 真 RO 违例/不存在页：非本模块 */
    }

    uintptr_t old_phys = pte & PAGE_FRAME_MASK;
    if (page_ref_get(old_phys) > 1u) {
        uintptr_t new_phys = pmm_alloc_page();
        if (!new_phys) {
            return -12;                       /* OOM：调用方决定 SIGKILL/panic */
        }
        memcpy(phys_to_virt(new_phys), phys_to_virt(old_phys), PAGE_SIZE);
        page_ref_dec(old_phys);
        *pte_p = (pte_t)(new_phys | _PAGE_PRESENT | _PAGE_USER | _PAGE_RW |
                         _PAGE_ACCESSED | _PAGE_DIRTY);
        invlpg(cr2);
        kputs("[OK] COW break va=");
        kput_hex32(cr2);
        kputs(" copy\n");
    } else {
        *pte_p = (pte_t)((pte | _PAGE_RW) & ~(_PAGE_COW));
        invlpg(cr2);
        kputs("[OK] COW rw-restore va=");
        kput_hex32(cr2);
        kputs("\n");
    }
    return 0;
}

/* ⚠️ 接线契约见 paging.h catos_page_fault_resolver 注释：interrupts.c
 * vector14 分支需于 panic 前经该指针调用；接线前无人引用，行为不变。 */
static int cow_resolver_default(uint32_t cr2, uint32_t error_code) {
    return paging_handle_cow_fault(cr2, error_code);
}
int (*catos_page_fault_resolver)(uint32_t cr2, uint32_t error_code) = cow_resolver_default;
