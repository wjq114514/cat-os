/*
 * stdlib.c —— Cat-OS 最小用户态 C 库：malloc/free + exit 实现（code9 · 并行任务）
 * ─────────────────────────────────────────────────────────────────────────────
 * 内存来源（设计依据，动手前已核实）：
 *   内核不存在内存类 syscall —— syscall.h 号表全量核对：0/1/5/6/11..13 +
 *   socket 族 20..30，无 brk/mmap/sbrk。故分配器为纯用户态实现：
 *   静态池落在本文件 .bss，链接后位于 [0x400000,...) 用户合法区
 *   （user_range_ok，syscall.c：下限 0x400000）。
 *   池 64 KiB + 程序镜像（shell 实测约 9 KB）« 用户栈页 0x700000，
 *   距栈底余量 >600 KiB，无碰撞风险。
 *
 * 算法：bump 式首适应 + 空闲链表 + 物理相邻合并。
 *   - 初始态：整池为单个空闲块（首次 malloc 即 bump 分裂）；
 *   - malloc：空闲链表 first-fit；余量足够则分裂出剩余空闲块；
 *   - free ：魔数+边界防御校验 → 标记空闲 → O(块数) 扫描全池重建
 *     合并后的空闲链表（块序列恒连续铺满池，不变量由初始态与分裂规则
 *     共同保证）。free 为 O(n) 是精简实现的已知取舍。
 * 非线程安全/非信号安全：Cat-OS ring3 当前为协作式单进程调度，无需锁。
 */

#include "stdlib.h"
#include "catos_syscall.h"

typedef __UINTPTR_TYPE__ catos_uintptr_t;

typedef struct catos_block {
    unsigned int size;              /* 载荷字节数（不含头，16 对齐）      */
    struct catos_block *next_free;  /* 空闲链表 next；占用块恒为 NULL    */
    unsigned int magic;             /* 已初始化标记（防野指针/重复释放） */
} catos_block_t;

#define CATOS_HEAP_POOL_BYTES (64u * 1024u)
#define CATOS_ALIGN           16u
/* sizeof(catos_block_t)==12（i386）→ 头部对齐上取整到 16 */
#define CATOS_HDR_BYTES \
    ((unsigned int)(sizeof(catos_block_t) + (CATOS_ALIGN - 1u)) & \
     ~(CATOS_ALIGN - 1u))
#define CATOS_MAGIC_USED 0xC7A051B0u /* CAt-OS B0undary */
#define CATOS_MAGIC_FREE 0xC7A051B1u

static unsigned char catos_heap_pool[CATOS_HEAP_POOL_BYTES]
    __attribute__((aligned(CATOS_ALIGN)));
static catos_block_t *catos_free_head; /* NULL = 尚未初始化 */

/* 池内物理块链步进：下一块头地址（块序列连续铺满池的不变量） */
static catos_block_t *next_block(catos_block_t *b)
{
    return (catos_block_t *)(void *)((char *)b + CATOS_HDR_BYTES + b->size);
}

/* 全池扫描重建空闲链表，物理相邻空闲块就地合并 */
static void heap_coalesce(void)
{
    catos_block_t *cur = (catos_block_t *)(void *)catos_heap_pool;
    catos_block_t *tail =
        (catos_block_t *)(void *)(catos_heap_pool + CATOS_HEAP_POOL_BYTES);
    catos_block_t **link = &catos_free_head;
    catos_block_t *run = (catos_block_t *)0; /* 当前连续空闲段首块 */

    while (cur < tail) {
        if (cur->magic == CATOS_MAGIC_FREE) {
            if (run != (catos_block_t *)0) {
                run->size += CATOS_HDR_BYTES + cur->size; /* 并入前段 */
            } else {
                run = cur;
                *link = cur;
                link = &cur->next_free;
            }
        } else {
            run = (catos_block_t *)0;
        }
        cur = next_block(cur);
    }
    *link = (catos_block_t *)0;
}

void *malloc(size_t size)
{
    catos_block_t **prev;
    catos_block_t *b;
    unsigned int req;

    if (catos_free_head == (catos_block_t *)0) {
        /* 首次调用：整池初始化为单一空闲块 */
        b = (catos_block_t *)(void *)catos_heap_pool;
        b->size = CATOS_HEAP_POOL_BYTES - CATOS_HDR_BYTES;
        b->magic = CATOS_MAGIC_FREE;
        b->next_free = (catos_block_t *)0;
        catos_free_head = b;
    }

    if (size == 0u)
        size = 1u;
    /* 上取整溢出/超池防护：size_t 宽度不定，先按池上限截断判断 */
    if (size > (size_t)CATOS_HEAP_POOL_BYTES)
        return (void *)0;

    req = ((unsigned int)size + (CATOS_ALIGN - 1u)) & ~(CATOS_ALIGN - 1u);

    prev = &catos_free_head;
    for (b = catos_free_head; b != (catos_block_t *)0;
         prev = &b->next_free, b = b->next_free) {
        if (b->size < req)
            continue;
        if (b->size >= req + CATOS_HDR_BYTES + CATOS_ALIGN) {
            /* 余量可容纳「新块头 + 最小载荷」→ 分裂 */
            catos_block_t *rem =
                (catos_block_t *)(void *)((char *)b + CATOS_HDR_BYTES + req);
            rem->size = b->size - req - CATOS_HDR_BYTES;
            rem->magic = CATOS_MAGIC_FREE;
            rem->next_free = b->next_free;
            *prev = rem; /* 剩余块顶替原链位 */
            b->size = req;
        } else {
            *prev = b->next_free; /* 整块交付 */
        }
        b->magic = CATOS_MAGIC_USED;
        b->next_free = (catos_block_t *)0;
        return (char *)b + CATOS_HDR_BYTES;
    }
    return (void *)0; /* 池耗尽或无单块可满足 */
}

void free(void *p)
{
    catos_block_t *b;
    char *pool_lo = (char *)catos_heap_pool;
    char *pool_hi = pool_lo + CATOS_HEAP_POOL_BYTES;

    if (p == (void *)0)
        return;
    if (((catos_uintptr_t)p & (catos_uintptr_t)(CATOS_ALIGN - 1u)) != 0u)
        return; /* 非 16 对齐：不可能是本分配器产物 */

    b = (catos_block_t *)(void *)((char *)p - CATOS_HDR_BYTES);
    if ((char *)b < pool_lo || (char *)p > pool_hi ||
        (char *)p + b->size > pool_hi)
        return; /* 越界指针 */
    if (b->magic != CATOS_MAGIC_USED)
        return; /* 未初始化 / 已释放（重复释放）/ 野指针 */

    b->magic = CATOS_MAGIC_FREE;
    heap_coalesce(); /* O(块数)：合并并重建空闲链表（LIFO push 被其覆盖） */
}

void exit(int status)
{
    (void)catos_syscall3(CATOS_SYS_EXIT_NR, (unsigned)status, 0u, 0u);
    for (;;)
        ; /* 内核已摘除本进程；此行为编译器要求的不可达兜底 */
}
