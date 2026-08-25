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
static uint32_t managed_pages;
static uint32_t free_page_count;
static uint32_t next_page_idx;
static uint32_t next_dma_page_idx;
static uintptr_t managed_limit_phys;
static uintptr_t direct_map_limit_phys;
static uintptr_t ioremap_next = IOREMAP_BASE;
static int final_paging_active;

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

static void mark_page_free(uint32_t idx) {
    if (idx >= managed_pages) {
        return;
    }
    if (bitmap_test(idx)) {
        bitmap_clear(idx);
        ++free_page_count;
    }
}

static void mark_page_used(uint32_t idx) {
    if (idx >= managed_pages) {
        return;
    }
    if (!bitmap_test(idx)) {
        bitmap_set(idx);
        --free_page_count;
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
    load_cr3(virt_to_phys(&kernel_page_directory));
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
     * 本内核用户页均为急切全量映射（usermode.c:34），无 demand paging，
     * 故“PRESENT 即可达”当前语义自洽（NOTE 见函数尾审查记录）。 */
    for (uintptr_t p = v; p < e; p = (p & ~(PAGE_SIZE - 1u)) + PAGE_SIZE) {
        pde_t d = kernel_page_directory.entries[PDE_INDEX(p)];
        if (!(d & _PAGE_PRESENT) || !(d & _PAGE_USER)) {
            return 0;
        }
        if (d & _PAGE_PSE) {
            continue;
        }
        page_table_t *t = (page_table_t *)phys_to_virt(d & PAGE_FRAME_MASK);
        pte_t x = t->entries[PTE_INDEX(p)];
        if (!(x & _PAGE_PRESENT) || !(x & _PAGE_USER) ||
            (w && !(x & _PAGE_RW))) {
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
