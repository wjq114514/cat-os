/*
 * shell_user.c —— Cat-OS 最小 ring3 shell（code2 · 并行任务）
 * ─────────────────────────────────────────────────────────────────────────────
 * 目标形态：ELF32 i386 LSB ET_EXEC，由内核 exec syscall 经 elf_load() 装载，
 * 入口 _start 以 ring3 特权级运行。禁止 libc —— 仅依赖 int 0x80 系统调用。
 *
 * int 0x80 调用约定（依据 interrupts.c interrupt_dispatch vector==128 分支）：
 *   EAX = nr；EBX,ECX,EDX,ESI,EDI → a[0..4]；返回值 sign-extend 写回 EAX，
 *   负值为 -errno。本程序最多用到 3 个参数位（EBX/ECX/EDX）。
 *
 * 所用系统调用号（对照 vfs.h VFS 兼容 ABI 与 syscall.c code2 追加段）：
 *   nr=0  read(fd,buf,len)      fd0 = stdin（vfs_init 安装为 /dev/kbd，
 *                               阻塞读带超时；超时返回 0 → 本 shell 轮询）
 *   nr=1  write(fd,buf,len)     fd1 = stdout（/dev/console）
 *   nr=5  open(path,flags)      本版本未用（保留示例注释）
 *   nr=11 exec(path)            CATOS_SYS_EXEC（syscall.c code2 追加）
 *   nr=12 exit(status)          CATOS_SYS_EXIT
 *
 * 链接布局约束（user_range_ok，syscall.c）：用户代码/数据须落在
 * [0x400000, 0xBFC00000)；链接基址取 0x400000（-Ttext），栈由 elf_load
 * 映射于 ELF_USER_STACK_BASE=0x700000（elf.h），二者互不重叠。
 *
 * 编译：见 Makefile 「── code2: ring3 shell ──」段
 *   gcc -m32 -ffreestanding -nostdlib -fno-pie ... -c shell_user.c
 *   ld   -m elf_i386 -nostdlib -static -e _start -Ttext=0x400000
 */

#include <stdint.h>

typedef int32_t (*syscall_fn)(void);

/* ── int 0x80 三参封装 ─────────────────────────────────────────────────────
 * "b"/"c"/"d" 为 early-clobber：int 0x80 处理器会破坏 EAX 之外的寄存器状态
 * 不可假设，故全部列入 clobber；内核返回值经 sign-extend 写回 EAX。
 * 本程序以 -fno-pic -fno-pie 编译，EBX 不承担 GOT 基址，可安全用作传参。 */
static int32_t syscall3(uint32_t nr, uint32_t a0, uint32_t a1, uint32_t a2)
{
    int32_t ret;
    __asm__ volatile("int $0x80"
                     : "=a"(ret)
                     : "a"(nr), "b"(a0), "c"(a1), "d"(a2)
                     : "memory");
    return ret;
}

/* VFS 兼容 ABI 薄封装（nr 对照 vfs_syscall：0=read 1=write 5=open 6=close） */
static int32_t sys_read(uint32_t fd, void *buf, uint32_t len)
{
    return syscall3(0u, fd, (uint32_t)buf, len);
}
static int32_t sys_write(uint32_t fd, const void *buf, uint32_t len)
{
    return syscall3(1u, fd, (uint32_t)buf, len);
}
/* code2 追加号（syscall.c）：11=exec(path) 12=exit(status) */
static int32_t sys_exec(const char *path)
{
    return syscall3(11u, (uint32_t)path, 0u, 0u);
}
static int32_t sys_exit(uint32_t status)
{
    return syscall3(12u, status, 0u, 0u);
}

#define CATOS_SYS_EXEC 11u
#define CATOS_SYS_EXIT 12u
#define SHELL_LINE_MAX 128u

/* ── 极小运行时（无 libc）──────────────────────────────────────────────── */
static uint32_t kstrlen(const char *s)
{
    uint32_t n = 0;
    while (s[n] != '\0')
        n++;
    return n;
}
/* 返回 <0/0/>0；仅要求同 cat-os$ 场景下的字典序一致性 */
static int kstrcmp(const char *a, const char *b)
{
    while (*a != '\0' && *a == *b) {
        a++;
        b++;
    }
    return (int)(unsigned char)*a - (int)(unsigned char)*b;
}

static void print(const char *s)
{
    (void)sys_write(1u, s, kstrlen(s));
}

/* ── 读一行（轮询 stdin=/dev/kbd）────────────────────────────────────────
 * /dev/kbd 的 kread（vfs.c）阻塞至 KBD_BLOCK_TIMEOUT_MS，超时返回 0：
 * r==0 视为「暂无输入」继续轮询而非出错。可见字符即时回显到 console；
 * 支持 '\b'/DEL 退格（回显 "\b \b" 抹除）；'\n'/'\r' 结束本行。
 * 返回行长度（不含终止 NUL）；缓冲恒以 '\0' 结尾。 */
static int32_t read_line(char *buf, uint32_t max)
{
    uint32_t len = 0;
    for (;;) {
        char c;
        int32_t r = sys_read(0u, &c, 1u);
        if (r <= 0)
            continue; /* 超时空转或瞬时失败：继续轮询 */
        if (c == '\n' || c == '\r') {
            print("\n");
            buf[len] = '\0';
            return (int32_t)len;
        }
        if (c == '\b' || c == 127) {
            if (len > 0u) {
                len--;
                print("\b \b");
            }
            continue;
        }
        if (c >= 32 && c < 127 && len + 1u < max) {
            buf[len++] = c;
            (void)sys_write(1u, &c, 1u); /* 回显 */
        }
        /* 其余控制字符丢弃；满行后续输入丢弃直到换行 */
    }
}

/* 取首个 token（就地截断）；返回 token 首指针，*rest 置为参数区首地址
 * （跳过空格；无参数时指向 ""）。空行返回 0。 */
static char *next_token(char **rest)
{
    char *s = *rest;
    while (*s == ' ')
        s++;
    if (*s == '\0') {
        *rest = s;
        return (char *)0;
    }
    char *tok = s;
    while (*s != '\0' && *s != ' ')
        s++;
    if (*s == ' ') {
        *s = '\0';
        s++;
        while (*s == ' ')
            s++;
    }
    *rest = s;
    return tok;
}

static void cmd_echo(const char *args)
{
    if (*args == '\0') {
        print("\n");
        return;
    }
    print(args);
    print("\n");
}

static void cmd_help(void)
{
    print("Cat-OS shell commands:\n");
    print("  echo <text>   print text\n");
    print("  help          list commands\n");
    print("  exec <path>   load and run an ELF32 program via exec syscall\n");
    print("  exit          terminate this shell (exit syscall)\n");
}

/* exec <path>：路径指针直传内核；EFAULT/EINVAL 等负 errno 原样展示 */
static void cmd_exec(const char *path)
{
    if (*path == '\0') {
        print("exec: usage: exec <path>\n");
        return;
    }
    int32_t pid = sys_exec(path);
    if (pid < 0) {
        print("exec: failed (errno ");
        /* 极小十进制输出（pid>=-38 足够两位）*/
        char eb[5];
        int32_t e = -pid;
        int i = 0;
        if (e == 0)
            eb[i++] = '0';
        while (e > 0) {
            eb[i++] = (char)('0' + (e % 10));
            e /= 10;
        }
        char out[8];
        int j = 0;
        out[j++] = '-';
        while (i > 0)
            out[j++] = eb[--i];
        out[j++] = ')';
        out[j++] = '\n';
        (void)sys_write(1u, out, (uint32_t)j);
        return;
    }
    /* 成功：内核已创建用户进程并调度；正常情况下本调用点之后
     * shell 自身仍驻留（协作式调度），打印新 pid 作确认。 */
    print("exec: spawned user process pid=");
    char pb[4];
    int i = 0;
    int32_t p = pid;
    if (p == 0)
        pb[i++] = '0';
    while (p > 0) {
        pb[i++] = (char)('0' + (p % 10));
        p /= 10;
    }
    char out[6];
    int j = 0;
    while (i > 0)
        out[j++] = pb[--i];
    out[j++] = '\n';
    (void)sys_write(1u, out, (uint32_t)j);
}

static void shell_repl(void)
{
    static char line[SHELL_LINE_MAX]; /* .bss，位于 0x400xxx 用户合法区 */

    print("\nCat-OS minimal shell (ring3)\n");
    print("type 'help' for commands\n");
    for (;;) {
        print("cat-os$ ");
        int32_t n = read_line(line, SHELL_LINE_MAX);
        if (n <= 0)
            continue; /* 空行：重新出提示符 */
        char *rest = line;
        char *cmd = next_token(&rest);
        if (cmd == (char *)0)
            continue;
        if (kstrcmp(cmd, "echo") == 0) {
            cmd_echo(rest);
        } else if (kstrcmp(cmd, "help") == 0) {
            cmd_help();
        } else if (kstrcmp(cmd, "exec") == 0) {
            cmd_exec(rest);
        } else if (kstrcmp(cmd, "exit") == 0) {
            print("bye\n");
            (void)sys_exit(0u); /* 不返回：内核标记进程 TERMINATED */
        } else {
            print(cmd);
            print(": command not found\n");
        }
    }
}

/* ── ELF 入口 ─────────────────────────────────────────────────────────────
 * 无 crt0：进入时栈已由调度器置为 ELF_USER_STACK_SP（elf.h），
 * 无需初始化任何运行时（freestanding，无 .init_array 需求）。 */
__attribute__((noreturn)) void _start(void)
{
    shell_repl();
    /* shell_repl 不返回；此兜底保证语义上不可达的出口仍走 exit syscall */
    for (;;)
        (void)sys_exit(1u);
}
