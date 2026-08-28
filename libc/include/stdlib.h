/*
 * stdlib.h —— Cat-OS 最小用户态 C 库：内存分配与进程退出声明（code9 · 并行任务）
 * ─────────────────────────────────────────────────────────────────────────────
 * malloc/free 为纯用户态实现（静态池 + 空闲链表），原因：内核当前不存在任何
 * 内存类 syscall —— 号表全量核实（syscall.h）：0=read 1=write 5=open 6=close
 * 11=exec 12=exit 13=wait + socket 族 20..28/29/30，无 brk/mmap/sbrk。
 *
 * exit() 使用 nr=12（CATOS_SYS_EXIT，syscall.c code2 追加段）。
 */

#ifndef CATOS_LIBC_STDLIB_H
#define CATOS_LIBC_STDLIB_H

#ifndef CATOS_LIBC_SIZE_T_DEFINED
#define CATOS_LIBC_SIZE_T_DEFINED
typedef __SIZE_TYPE__ size_t;
#endif

#ifndef CATOS_LIBC_NULL_DEFINED
#define CATOS_LIBC_NULL_DEFINED
#define NULL ((void *)0)
#endif

/* 分配 size 字节，16 字节对齐；失败返回 NULL（池耗尽或请求过大）。
 * size==0 按标准允许的实现返回一个可 free 的最小块。 */
void *malloc(size_t size);

/* 释放 p；p==NULL 无操作。野指针/越界指针/重复释放被防御性忽略
 * （魔数 + 池边界校验，ring3 下无 panic 通道）。 */
void free(void *p);

/* 终止当前 ring3 进程（nr=12 exit syscall），不返回。
 * 注意：内核 PCB 暂无退出码字段（process.h 定稿无此成员），
 * status 当前仅作 ABI 占位传递。 */
void exit(int status) __attribute__((noreturn));

/* ── 环境变量（纯用户态实现，存储经 malloc/free 动态增长）─────────────
 * environ 为 NULL 结尾的字符串指针数组，每项形如 "NAME=value"。
 * 初始为空表；进程无 exec 传参通道前恒由 setenv/putenv 构造。 */
extern char **environ;

/* 返回 name 对应的 value 指针（指向 "NAME=value" 内部偏移）；
 * 不存在/name 非法返回 NULL。返回值在下次环境变更前有效。 */
char *getenv(const char *name);

/* 设置/覆盖 name=value。已存在且 overwrite==0 → 保持原值并返回 0；
 * 成功返回 0；参数非法（NULL/空名/含 '='）或分配失败返回 -1。
 * 存储由库内部分配；替换 unsetenv 移除时同步回收。 */
int setenv(const char *name, const char *value, int overwrite);

/* 移除 name。成功 0；不存在或参数非法返回 -1。 */
int unsetenv(const char *name);

/* 将调用方构造的 "NAME=value" 字符串纳入环境（不拷贝）。
 * ⚠️ 所有权转移：此后该指针归环境所有，库永不 free 它，
 *   调用方亦不得释放/改写（精简实现取舍：不做槽位所有权回收）。
 * 同名旧项被顶替（若旧项为 setenv 创建则回收）；无 '=' 或分配失败返回 -1。 */
int putenv(char *string);

/* ── 数值转换（基础版：空白跳过、正负号、base 2..36 / 0=自动识别）────
 * base==0：0x/0X 前缀→16，前导 0→8，其余→10。
 * 溢出饱和：strtol→LONG_MAX/LONG_MIN，strtoul→ULONG_MAX，
 * 且置 errno=ERANGE（errno.h）。未消费任何数字：*endptr=nptr，返回 0。
 * endptr 可为 NULL（不需要时）。strtoul 接受 '-'（结果按无符号回绕，
 * 标准语义；本实现选择同时置 errno=ERANGE 以显式暴露该非常规输入）。 */
long strtol(const char *nptr, char **endptr, int base);
unsigned long strtoul(const char *nptr, char **endptr, int base);

int atoi(const char *s);
long atol(const char *s);
long long strtoll(const char *nptr, char **endptr, int base);
int abs(int x);
long labs(long x);

void qsort(void *base, size_t nmemb, size_t size,
           int (*compar)(const void *, const void *));
void *bsearch(const void *key, const void *base, size_t nmemb, size_t size,
              int (*compar)(const void *, const void *));

void srandom(unsigned int seed);
long random(void);
int rand(void);
void srand(unsigned int seed);

#define RAND_MAX 2147483647

char *realpath(const char *path, char *resolved);

#endif /* CATOS_LIBC_STDLIB_H */
