#ifndef CATOS_ELF_H
#define CATOS_ELF_H

/*
 * Cat-OS ELF32 加载器对外接口。
 *
 * 解析流程依据 linux-ref/fs/binfmt_elf.c:829 load_elf_binary()：
 *   1) 校验 elfhdr 魔数/类别/字节序/机器类型（binfmt_elf.c:840 起的
 *      ELF_MAGIC/ELF_CLASS/ELF_DATA 检查链）；
 *   2) 遍历 program header，仅处理 PT_LOAD 段；
 *   3) 每段按页映射并拷贝 p_filesz 字节，[p_filesz,p_memsz) 补零——
 *      对应 binfmt_elf.c:127 padzero()（调用点 :433）对 bss 页的清零语义。
 *
 * 与 Linux 的差异（milestone 简化，均有注释标注）：
 *   - 无 demand paging：整段急切全量映射（与 usermode.c:34 既有用户页
 *     映射策略一致，paging.c:359 注释亦确认"急切全量映射"为当前语义）；
 *   - 单一共享内核页目录：本内核 paging.c 尚未暴露"创建独立地址空间"
 *     API（paging.c 锁定中），故映射进当前目录的低半区（<0xC0000000），
 *     进程隔离留给后续 milestone。
 */

#include <stddef.h>
#include <stdint.h>

/* 任务书规定的用户栈布局：栈底页 @0x700000，初始 SP = 0x700000+4096。
 * （usermode.c:34/60 旧探针同样使用 0x700000 页；map_page() 为无条件
 * 覆盖写 PTE，paging.c:322-325，故复用安全。） */
#define ELF_USER_STACK_BASE 0x700000u
#define ELF_USER_STACK_SP   (ELF_USER_STACK_BASE + 4096u)

/* stage4: sock_abi 测试进程专用栈布局 —— 与 boot 探针栈(0x700000..0x701000)
 * 不重叠；elf_load_ex 参数化栈底正是为此并存场景而设。 */
#define CATOS_SOCKABI_STACK_BASE 0x702000u
#define CATOS_SOCKABI_USER_SP    (CATOS_SOCKABI_STACK_BASE + 4096u)

/*
 * elf_load - 解析并装载一个 ET_EXEC ELF32 LSB 镜像到当前页目录用户区。
 * @image:     镜像首地址（内核可读）
 * @len:       镜像长度（字节）
 * @entry_out: 成功时写出 e_entry
 * 返回值：>0 = 装载的 PT_LOAD 段数；<0 = -errno。
 */
int elf_load(const void *image, size_t len, uint32_t *entry_out);

/*
 * elf_load_ex - 同 elf_load，但允许指定用户栈底页（stage4）。
 * @stack_base: 栈底虚拟地址（必须页对齐、>=0x1000、<=用户区上界-页大小）；
 *              初始 SP = stack_base + PAGE_SIZE。
 *
 * 为什么需要它：map_page() 对已映射 vaddr 是无条件覆盖写 PTE
 * （paging.c map_page 直接赋值 pt->entries[pti]），而任务书默认栈页
 * 0x700000 已被 boot 探针/usermode 占用为活动栈。当第二个 ring3 程序
 * 需要与既有驻留程序并存时（stage4 sock_abi autorun vs boot 探针），
 * 必须为后来者指定互不重叠的栈基址，否则 elf_load 的固定栈映射会
 * 把先驻留程序的栈页重映射到新物理帧，造成其现场丢失/数据踩踏。
 * 调用方负责保证 stack_base 不与任何在驻程序的用户段重叠。
 */
int elf_load_ex(const void *image, size_t len, uint32_t *entry_out,
                uintptr_t stack_base);

#endif /* CATOS_ELF_H */
