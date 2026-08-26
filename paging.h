#ifndef CATOS_PAGING_H
#define CATOS_PAGING_H

#include <stddef.h>
#include <stdint.h>
void *memcpy(void *dst, const void *src, size_t n);

#define KERNEL_VIRT_BASE   0xC0000000u
#define KERNEL_PHYS_LOAD   0x00100000u
#define KERNEL_VIRT_LOAD   (KERNEL_VIRT_BASE + KERNEL_PHYS_LOAD)

#define PAGE_SHIFT         12u
#define PAGE_SIZE          (1u << PAGE_SHIFT)
#define PAGE_MASK          (~(PAGE_SIZE - 1u))
#define PDE_SHIFT          22u
#define PDE_SIZE           (1u << PDE_SHIFT)
#define PDE_MASK           (~(PDE_SIZE - 1u))
#define PTRS_PER_TABLE     1024u

#define IOREMAP_BASE       0xF0000000u
#define IOREMAP_SIZE       0x08000000u
#define ISA_DMA_LIMIT      0x01000000u

/* Linux-style x86 page flag names, trimmed to the i686 subset we use now. */
#define _PAGE_PRESENT      0x001u
#define _PAGE_RW           0x002u
#define _PAGE_USER         0x004u
#define _PAGE_PWT          0x008u
#define _PAGE_PCD          0x010u
#define _PAGE_ACCESSED     0x020u
#define _PAGE_DIRTY        0x040u
#define _PAGE_PSE          0x080u
#define _PAGE_GLOBAL       0x100u

/* ── COW fork 地基（本轮新增）───────────────────────────────────────────────
 * _PAGE_COW：PTE/PDE avail 位 bit11（SDM Vol.3 §4.4.2 软件可用位，硬件不碰）。
 * 编码约定（与 Linux copy_present_pte() 的 "写意图页 → RO+COW 标记" 思路对齐，
 * 但 Linux 把 COW 判定放在 vma 层，本内核无 vma，直接编码进 PTE avail 位）：
 *   可写用户页被 fork 共享时  => PRESENT|USER|COW，RW 清零；
 *   写缺页(#PF error&2)且 COW => paging_handle_cow_fault() 复制或恢复 RW；
 *   只读用户页/内核大页共享   => 原样复制映射，不置 COW（永远不参与写时复制）。
 * 约束：仅用户半区（< KERNEL_VIRT_BASE）非 PSE 叶子允许出现 COW 位；
 *       map_page() 不传播 avail 位，COW 位只能由 fork/fault 路径直接改 PTE。 */
#define _PAGE_COW          0x800u

#define PAGE_FRAME_MASK    0xFFFFF000u
#define PDE_4M_FRAME_MASK  0xFFC00000u

#define PAGE_ALIGN_UP(x)   (((uintptr_t)(x) + PAGE_SIZE - 1u) & PAGE_MASK)
#define PAGE_ALIGN_DOWN(x) ((uintptr_t)(x) & PAGE_MASK)
#define PDE_ALIGN_UP(x)    (((uintptr_t)(x) + PDE_SIZE - 1u) & PDE_MASK)

#define PDE_INDEX(x)       ((((uintptr_t)(x)) >> PDE_SHIFT) & 0x3FFu)
#define PTE_INDEX(x)       ((((uintptr_t)(x)) >> PAGE_SHIFT) & 0x3FFu)

typedef uint32_t pte_t;
typedef uint32_t pde_t;

typedef struct page_table {
    pte_t entries[PTRS_PER_TABLE];
} __attribute__((aligned(PAGE_SIZE))) page_table_t;

typedef struct page_directory {
    pde_t entries[PTRS_PER_TABLE];
} __attribute__((aligned(PAGE_SIZE))) page_directory_t;

static inline void *phys_to_virt(uintptr_t phys) {
    return (void *)(phys + KERNEL_VIRT_BASE);
}

static inline uintptr_t virt_to_phys(const void *virt) {
    return (uintptr_t)virt - KERNEL_VIRT_BASE;
}

void paging_init(uint32_t multiboot_info_phys);
int map_page(uintptr_t virt, uintptr_t phys, uint32_t flags);
int user_access_ok(uintptr_t virt, size_t len, uint32_t write);
void *ioremap(uintptr_t phys, size_t size, uint32_t flags);

uintptr_t pmm_alloc_page(void);
uintptr_t pmm_alloc_dma_page(void);
void pmm_free_page(uintptr_t phys);
uintptr_t pmm_managed_limit(void);
uint32_t pmm_total_pages(void);
uint32_t pmm_free_pages(void);

/* ── 物理页引用计数（COW fork 地基，4KB 粒度）──────────────────────────────
 * 存储：paging.c 静态 BSS 数组 page_refcnt[MAX_MANAGED_PAGES]（uint8_t，
 * 768MiB 预算 → 196608 × 1B = 192KiB；128MiB 实机仅前 32768 项有意义）。
 * 不变式：bitmap 置位 ⇔ refcnt≥1；pmm_alloc_* 置 1，pmm_free_page 清 0。
 * uint8_t 饱和上限 250：合法共享深度 ≤ MAX_PROCESSES(32)，饱和不可达，
 * 触发即告警（防引用泄漏静默累积）。 */
uint32_t page_ref_get(uintptr_t phys);
void     page_ref_inc(uintptr_t phys);
/* 返回减量后的计数值；调用方据 0 判定可 pmm_free_page。 */
uint32_t page_ref_dec(uintptr_t phys);

/* ── COW 地址空间服务（process.c fork 路径专用）────────────────────────── */
uint32_t paging_kernel_pd_phys(void);
/* 两阶段 COW 克隆当前 parent_pd_phys（通常传读 cr3 的现值；允许传内核目录
 * —— legacy 进程 page_dir==0 跑在共享内核目录上同样可 fork）：
 *   先一次性分配子 PD+全部用户 PT（失败即回滚，父地址空间零副作用）；
 *   再逐 PDI 复制：可写用户页父子同物理页、双侧改 RO+COW、ref++；
 *   只读页/非 USER 页原样共享 ref++（不标记）；内核半区 PDE 逐字复制。
 * 成功 *child_pd_phys_out = 子目录物理地址并刷新当前 cr3 的 TLB；
 * 失败返回 -12（ENOMEM），父空间已回滚原状。 */
int paging_clone_address_space(uint32_t parent_pd_phys, uint32_t *child_pd_phys_out);
/* 销毁私有地址空间：释放用户 PT/数据页（ref-- 归零才还 PMM），内核半区不动。
 * 拒绝销毁内核目录或当前 cr3 正踩着的目录（防御性泄漏优于崩溃）。 */
void paging_destroy_address_space(uint32_t pd_phys);
/* 写缺页 COW 路径。返回 0=已解决（iretd 重执行触发指令）；负数=非本模块
 * 职责(-1)或内存耗尽(-12)，调用方走原有异常报告路径。
 * 运行上下文约束：IDT 中断门内 IF=0，单核天然原子。 */
int paging_handle_cow_fault(uint32_t cr2, uint32_t error_code);

/* ── ⚠️ page fault 接线点（需 orchestrator 协调 interrupts.c，本轮未接线）───
 * interrupts.c interrupt_dispatch() vector==14 分支在 panic 前加：
 *     extern int (*catos_page_fault_resolver)(uint32_t, uint32_t);
 *     if (f->vector == 14) {
 *         uint32_t cr2; __asm__ volatile("mov %%cr2,%0":"=r"(cr2));
 *         if (catos_page_fault_resolver &&
 *             catos_page_fault_resolver(cr2, f->error_code) == 0)
 *             return;                    // 已解决，iretd 重执行指令
 *     }
 * 默认指向 paging_handle_cow_fault；接线前该指针存在但无人调用，行为不变。 */
extern int (*catos_page_fault_resolver)(uint32_t cr2, uint32_t error_code);

#endif
