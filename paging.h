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

#endif
