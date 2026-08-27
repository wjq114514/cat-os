#include "kernel.h"

/*
 * Cat-OS ELF32 (i386 LSB, ET_EXEC) 急切式加载器。
 *
 * 依据（行号级）：
 *  - linux-ref/fs/binfmt_elf.c:829  load_elf_binary()：整体解析流程原型；
 *  - linux-ref/fs/binfmt_elf.c:127  padzero() 与 :433 调用点：
 *      [p_filesz,p_memsz) 区间按页补零 —— 本文件 zero-fill 循环的依据；
 *  - linux-ref/fs/binfmt_elf.c:1296 create_elf_tables() / :1372 ELF_PLAT_INIT：
 *      auxv/寄存器初始化，本 milestone 不做（用户栈仅对齐，无 argv/auxv）；
 *  - paging.h 的 _PAGE_PRESENT|_PAGE_RW|_PAGE_USER + paging.c:292 map_page()：
 *      任务书指定的用户页映射原语；map_page 对已存在 PTE 无条件覆盖
 *      （paging.c:322-325）并 invlpg（paging.c:327）。
 */
#include "elf.h"
#include "kernel.h"
#include "paging.h"

#include <stddef.h>

/* paging.c:26 提供全局符号 memset()（paging.h 未声明，此处自行声明）。 */
extern void *memset(void *dst, int value, size_t n);

/* ---- Elf32 数据结构：与 linux-ref/include/linux/elf.h 的
 * struct elfhdr/elf32_phdr 同布局（x86_32 小端，packed 保证无填充）。 ---- */
typedef struct {
    uint8_t  e_ident[16];       /* [0..3]=\x7fELF [4]=ELFCLASS32 [5]=LSB [6]=EV_CURRENT */
    uint16_t e_type;            /* 2 = ET_EXEC */
    uint16_t e_machine;         /* 3 = EM_386 */
    uint32_t e_version;
    uint32_t e_entry;           /* 程序入口 */
    uint32_t e_phoff;           /* program header 表文件偏移 */
    uint32_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
} __attribute__((packed)) elf32_ehdr_t;

typedef struct {
    uint32_t p_type;            /* 1 = PT_LOAD */
    uint32_t p_offset;
    uint32_t p_vaddr;           /* 目标用户虚拟地址（任务书映射目标）*/
    uint32_t p_paddr;
    uint32_t p_filesz;
    uint32_t p_memsz;           /* >= p_filesz，差值为 bss 补零区 */
    uint32_t p_flags;
    uint32_t p_align;
} __attribute__((packed)) elf32_phdr_t;

#define ELFCLASS32      1u
#define ELFDATA2LSB     1u
#define EV_CURRENT      1u
#define ELF_MAGIC0      0x7fu        /* ELF 魔数字节 0: \x7f */
#define ET_EXEC         2u
#define EM_386          3u
#define PT_LOAD         1u

#define ELF_IDENT_MAG0  0u
#define ELF_IDENT_CLASS 4u
#define ELF_IDENT_DATA  5u
#define ELF_IDENT_VER   6u

#define ENOMEM          12
#define EFAULT          14
#define ENOEXEC         8

/* 用户区间上界：与 paging.c:354 user_access_ok 的 0xBFC00000 守护带同源，
 * 用户段一律不得触入内核直接映射区。 */
#define CATOS_USER_LIMIT 0xBFC00000u

static uint32_t min_u32(uint32_t a, uint32_t b) { return a < b ? a : b; }
static uint32_t max_u32(uint32_t a, uint32_t b) { return a > b ? a : b; }

/* 分配并清零一个物理页，映射到当前页目录用户区：任务书指定
 * paging.c:292 map_page() 与 _PAGE_PRESENT|_PAGE_RW|_PAGE_USER 组合；
 * 失败回收物理页。成功时经 *phys_out 交还帧地址（内核经 phys_to_virt
 * 直接映射窗口填充内容，与页目录当前激活状态无关）。 */
static int map_user_page(uintptr_t virt, uintptr_t *phys_out) {
    uintptr_t phys = pmm_alloc_page();
    if (!phys) {
        return -ENOMEM;
    }
    memset(phys_to_virt(phys), 0, PAGE_SIZE);
    if (map_page(virt, phys, _PAGE_PRESENT | _PAGE_RW | _PAGE_USER) != 0) {
        pmm_free_page(phys);
        return -ENOMEM;
    }
    *phys_out = phys;
    return 0;
}

int elf_load(const void *image, size_t len, uint32_t *entry_out)
{
    /* stage4: 默认栈基址=任务书 0x700000，行为与原 elf_load 完全兼容。 */
    return elf_load_ex(image, len, entry_out, ELF_USER_STACK_BASE);
}

/*
 * elf_load_ex - elf_load 的参数化栈底版本（stage4）。
 * stack_base 必须页对齐、落在 [PAGE_SIZE, CATOS_USER_LIMIT-PAGE_SIZE]，
 * 且不得与本镜像任何段、也不得与已驻留程序（boot 探针 @0x700000 栈）
 * 的段/栈重叠 —— map_page 对已映射 vaddr 无条件覆盖写 PTE（paging.c），
 * 重叠即毁先驻程序现场。
 */
int elf_load_ex(const void *image, size_t len, uint32_t *entry_out,
                uintptr_t stack_base)
{
    const uint8_t *base = (const uint8_t *)image;

    if (!image || !entry_out || len < sizeof(elf32_ehdr_t)) {
        return -ENOEXEC;
    }
    if ((stack_base & (PAGE_SIZE - 1u)) != 0u ||
        stack_base < PAGE_SIZE ||
        stack_base > CATOS_USER_LIMIT - PAGE_SIZE) {
        kputs("[ERR] elf_load_ex: bad stack_base\n");
        return -EINVAL;
        }

    /* -- 鉴别字段校验（对应 binfmt_elf.c load_elf_binary 开头的
     *    memcmp(ELFMAG)/elf_check_arch/elf_check_type 链）-- */
    const elf32_ehdr_t *eh = (const elf32_ehdr_t *)base;
    if (eh->e_ident[ELF_IDENT_MAG0] != ELF_MAGIC0 ||
        eh->e_ident[1] != 'E' || eh->e_ident[2] != 'L' || eh->e_ident[3] != 'F') {
        kputs("[ERR] elf_load: bad magic\n");
        return -ENOEXEC;
    }
    if (eh->e_ident[ELF_IDENT_CLASS] != ELFCLASS32 ||
        eh->e_ident[ELF_IDENT_DATA] != ELFDATA2LSB ||
        eh->e_ident[ELF_IDENT_VER] != EV_CURRENT) {
        kputs("[ERR] elf_load: not ELF32 LSB EV_CURRENT\n");
        return -ENOEXEC;
    }
    if (eh->e_type != ET_EXEC || eh->e_machine != EM_386) {
        kputs("[ERR] elf_load: not ET_EXEC/EM_386\n");
        return -ENOEXEC;
    }
    if (eh->e_phentsize != sizeof(elf32_phdr_t)) {
        kputs("[ERR] elf_load: bad e_phentsize\n");
        return -ENOEXEC;
    }

    /* 表越界防护：phdr 表必须完整落在镜像内（防畸形 e_phoff/e_phnum）。 */
    uint64_t tbl_end = (uint64_t)eh->e_phoff +
                       (uint64_t)eh->e_phnum * (uint64_t)eh->e_phentsize;
    if (tbl_end > (uint64_t)len) {
        kputs("[ERR] elf_load: phdr table out of image\n");
        return -EFAULT;
    }

    /* ---- PT_LOAD 遍历装载（binfmt_elf.c:940 附近的 PT_LOAD 分支语义：
     *      每段 mmap 到 p_vaddr、拷贝 filesz、padzero 补齐 memsz）---- */
    uint32_t segs = 0;
    for (uint32_t i = 0; i < eh->e_phnum; ++i) {
        const elf32_phdr_t *ph =
            (const elf32_phdr_t *)(base + eh->e_phoff + i * sizeof(elf32_phdr_t));

        if (ph->p_type != PT_LOAD) {
            continue;   /* 非 PT_LOAD（DYNAMIC/NOTE 等）本加载器忽略 */
        }
        if (ph->p_memsz < ph->p_filesz ||
            ph->p_offset > len ||
            (uint64_t)ph->p_offset + ph->p_filesz > (uint64_t)len) {
            kputs("[ERR] elf_load: segment out of image\n");
            return -EFAULT;
        }
        /* 用户区边界：低页洞 + 内核守护带（对齐 user_access_ok 语义）。 */
        if (ph->p_vaddr < 0x1000u ||
            (uint64_t)ph->p_vaddr + ph->p_memsz > CATOS_USER_LIMIT) {
            kputs("[ERR] elf_load: segment outside user range\n");
            return -EFAULT;
        }

        uint32_t seg_vstart = PAGE_ALIGN_DOWN(ph->p_vaddr);
        uint32_t seg_vend   = PAGE_ALIGN_UP((uintptr_t)ph->p_vaddr + ph->p_memsz);

        for (uint32_t vpage = seg_vstart; vpage < seg_vend; vpage += PAGE_SIZE) {
            uintptr_t frame = 0;
            int rc = map_user_page(vpage, &frame);
            if (rc != 0) {
                return rc;
            }
            /* 文件内容与本页的交集拷贝；交集之外保持补零状态
             * （padzero binfmt_elf.c:127 的按页等价实现）。
             * 目标经 phys_to_virt 直接映射窗口访问（paging.h:52-60）。 */
            uint32_t copy_lo = max_u32(vpage, ph->p_vaddr);
            uint32_t copy_hi = min_u32(vpage + PAGE_SIZE,
                                       ph->p_vaddr + ph->p_filesz);
            if (copy_lo < copy_hi) {
                uint8_t *dst = (uint8_t *)phys_to_virt(frame);
                memcpy(dst + (copy_lo - vpage),
                       base + ph->p_offset + (copy_lo - ph->p_vaddr),
                       copy_hi - copy_lo);
            }
        }

        segs++;
        kputs("[OK] ELF PT_LOAD seg ");
        kput_dec(segs);
        kputs(" vaddr=");
        kput_hex32(ph->p_vaddr);
        kputs(" filesz=");
        kput_dec(ph->p_filesz);
        kputs(" memsz=");
        kput_dec(ph->p_memsz);
        kputs("\n");
    }

    if (segs == 0) {
        kputs("[ERR] elf_load: no PT_LOAD segment\n");
        return -ENOEXEC;
    }

    /* ---- 用户栈：stage4 起由调用方指定栈底（默认 0x700000 兼容原语义）。 ---- */
    uintptr_t stack_frame = 0;
    if (map_user_page(stack_base, &stack_frame) != 0) {
        return -ENOMEM;
    }
    kputs("[OK] ELF user stack ");
    kput_hex32((uint32_t)stack_base);
    kputs("..");
    kput_hex32((uint32_t)(stack_base + PAGE_SIZE));
    kputs(" SP=");
    kput_hex32((uint32_t)(stack_base + PAGE_SIZE));
    kputs("\n");

    *entry_out = eh->e_entry;
    return (int)segs;
}
