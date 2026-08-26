/*
 * httpd.c —— Cat-OS 最小 HTTP 服务端（userland/httpd · M0 形态：单进程阻塞循环）
 * ─────────────────────────────────────────────────────────────────────────────
 * 设计依据：docs/MINIMAL_HTTPD_DESIGN.md（M0 = §6 L0 档：内嵌固定内容，无文件系统）。
 * ABI 契约：docs/SOCKET_API.md、docs/RING3_SYSCALL_ABI.md、syscall.h。
 * 封装范式：照抄 tests/user_sock_abi/user_sock_abi_test.c 的 sc5 内联 int $0x80，
 *           寄存器映射据 interrupts.c interrupt_dispatch vector==128 实证：
 *           EAX=nr；EBX,ECX,EDX,ESI,EDI → a[0..4]；返回值 sign-extend 写回 EAX，
 *           负值为 -errno。本文件零 libc 链接依赖（freestanding 自洽，可 -nostdlib）。
 *
 * ★ 文件锁合规声明：本文件为 userland/httpd/ 下【新增】文件，零改动仓库既有文件
 *   （不接 Makefile、不改 kernel.c 内嵌逻辑；接线由 orchestrator 统一安排）。
 *
 * ── 依赖的 syscall 编号清单 ────────────────────────────────────────────────
 *   VFS 组（nr<20 经 vfs_syscall）：
 *     nr=1  write(fd,buf,len)   banner / 逐连接访问日志 → /dev/console
 *     nr=5  open(path,flags)    打开 "/dev/console"(O_WRONLY=1) 取日志 fd；
 *                               ⚠️ 失败返回 -1（非 errno，RING3_SYSCALL_ABI §3.1），
 *                               本程序失败即回退 fd=1（vfs_init 已装 stdout=/dev/console）
 *                               （M0 全程持有该 fd，无需 nr=6 关闭；socket 关闭见 nr=28）
 *   socket 组（house ABI 五参封顶、无 sockaddr 结构，bind 直传端口号）：
 *     nr=20 socket(type)        type=1 SOCK_STREAM；表满 -EMFILE
 *     nr=21 bind(fd,port)       port=80（内核 net_init 已让出 :80，见 net.c net_init
 *                               注释「TCP :80 由 ring3 服务绑定」契约）
 *     nr=22 listen(fd,backlog)  backlog=16（内部截到 TCP_MAX_CONNS=16，net.h:67）
 *     nr=23 accept(fd)          空队列返 -EAGAIN（非阻塞轮询语义，无 ring3 阻塞 accept）
 *     nr=26 send(fd,buf,len)    收缩式部分写契约（net.c tcp_send）：返回值可为部分字节数，
 *                               可为 0（缓冲满歧义 TODO(code2)）→ 游标推进 + 重试上限，
 *                               宁可截断响应不可死循环
 *     nr=27 recv(fd,buf,len)    >0 数据；0=EOF（状态机判定 CLOSE_WAIT 族）；-EAGAIN=
 *                               暂无数据（预算内重试防慢速客户端占死唯一服务槽）
 *     nr=28 close(socket_fd)    唯一 socket-aware 关闭路径（ESTAB→FIN）；Connection:close
 *                               语义由「发完响应即 nr=28 close」实现
 *   进程组：
 *     nr=12 exit(status)        仅初始化致命失败路径使用；连接级任何异常一律收敛到
 *                               「close(cfd) + 回 accept」，主循环永不退出（设计稿 §5）
 *
 * ── 尚未可用的依赖（接线缺口，诚实声明，运行时 NOT_TESTED 直至接线）──────────
 *   ① exec(nr=11)：当前 sys_exec 嵌入分支仅匹配 "/bin/shell"，本 ELF 无加载路径。
 *      需 orchestrator 接线（Makefile 目标 httpd.o/.elf/.bin/内嵌头 + kernel.c 或
 *      syscall.c 白名单注册），接线前本文件价值 = ABI 规约 + 编译期自检。
 *   ② ring3 yield/nanosleep 类 syscall 不存在（设计稿 §4.2 新缺口 Y6'）：
 *      accept 空转采用策略 B/C 折中 —— 连续 EAGAIN 计数，每 64 次插入一段短忙等软化。
 *   ③ house ABI accept 无对端地址出参（SOCKET_API.md §4.3）：日志只记 fd/path/status。
 *
 * ── 行为规约（M0）─────────────────────────────────────────────────────────
 *   · 只解析请求行 METHOD SP PATH [SP VERSION]；版本宽容（1.0/1.1/缺省皆可）。
 *   · 非 GET 方法 → 405（Allow: GET）；畸形请求行 / 路径非'/'开头 / 含".."/
 *     长度>256 → 400；其余一律 200 text/plain，正文固定 "hello from cat-os httpd"
 *     （无文件系统，路径不存在概念）。
 *   · 响应恒带 Content-Length 与 Connection: close；发送完成后 close(cfd)。
 *   · 异常路径（recv<=0、EAGAIN 超预算、send<0、重试超限）：直接关连接回 accept，
 *     不崩溃、不退出主进程——单进程模型的存活即服务可用性。
 *   · 栈预算：用户栈仅 1 页 4KB（elf.h:30-31，设计稿 §7-L7）→ 请求/响应缓冲全部放
 *     .bss 静态区，栈上只留小标量。
 *
 * ── 验收方法（QEMU hostfwd 已备：tests/qemu_run.sh，18080→guest:80）──────────
 *   orchestrator 接线并启动后，宿主机执行：
 *     curl -s http://127.0.0.1:18080/
 *       预期输出：hello from cat-os httpd
 *     curl -s -o /dev/null -w '%{http_code}\n' -X POST http://127.0.0.1:18080/
 *       预期输出：405
 *     curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:18080/bad path 畸形行
 *       （手工 nc 发垃圾行）预期输出：400
 *   串口应见 "[HTTPD]" 启动 banner 与逐连接日志；100 连接串行无 panic、无 fd 泄漏。
 */

#include <stdint.h>

/* ── ABI 常量镜像（源 syscall.h / vfs.h / net.h；锁定不可改，本地同步副本）──── */
#define NR_WRITE       1u
#define NR_OPEN        5u
#define NR_EXIT        12u

#define NR_SOCKET      20u
#define NR_BIND        21u
#define NR_LISTEN      22u
#define NR_ACCEPT      23u
#define NR_SEND        26u
#define NR_RECV        27u
#define NR_CLOSE_SOCK  28u   /* socket 关闭唯一合法编号；绝不用 nr=6/nr=3 关 socket */

#define SOCK_STREAM_C  1u    /* CATOS_SOCK_STREAM */
#define O_WRONLY_C     1u    /* vfs.h O_WRONLY */

#define EAGAIN         (-11) /* CATOS_EAGAIN */

#define HTTPD_PORT     80u   /* 内核 net_init 契约：ring3 服务专用端口 */
#define LISTEN_BACKLOG 16u   /* TCP_MAX_CONNS（net.h:67），listen 内部自动截断 */

#define REQ_MAX            2048u       /* 设计稿 §4.3 上限（用户栈仅 4KB → 缓冲在 .bss）*/
#define RESP_MAX           512u
#define PATH_LEN_MAX       256u        /* 设计稿 §4.3 路径归一化上限 */
#define RECV_EAGAIN_BUDGET 2000000u    /* 慢速客户端防占死唯一服务槽的重试预算 */
#define SEND_IDLE_CAP      1000000u    /* send 返 0（缓冲满歧义）的退避重试上限 */

/* 解析结论 */
#define ST_200 0
#define ST_405 1
#define ST_400 2

/* 固定内容（L0 内嵌档；Content-Length 必须与正文严格一致） */
static const char body_ok[]  = "hello from cat-os httpd";
#define BODY_OK_LEN 23u
static const char body_405[] = "method not allowed";
static const char body_400[] = "bad request";

/* ── int 0x80 五参封装（范式照抄 tests/user_sock_abi/user_sock_abi_test.c sc5）─ */
static int32_t sc5(uint32_t nr, uint32_t a0, uint32_t a1, uint32_t a2,
                   uint32_t a3, uint32_t a4)
{
    int32_t ret;
    __asm__ volatile("int $0x80"
                     : "=a"(ret)
                     : "a"(nr), "b"(a0), "c"(a1), "d"(a2), "S"(a3), "D"(a4)
                     : "memory");
    return ret;
}

/* ── socket 组薄封装（参数布局 = docs/RING3_SYSCALL_ABI.md §3.2 house ABI）──── */
static int32_t s_socket(uint32_t type)             { return sc5(NR_SOCKET, type, 0, 0, 0, 0); }
static int32_t s_bind(int32_t fd, uint32_t port)   { return sc5(NR_BIND, (uint32_t)fd, port, 0, 0, 0); }
static int32_t s_listen(int32_t fd, uint32_t bl)   { return sc5(NR_LISTEN, (uint32_t)fd, bl, 0, 0, 0); }
static int32_t s_accept(int32_t fd)                { return sc5(NR_ACCEPT, (uint32_t)fd, 0, 0, 0, 0); }
static int32_t s_send(int32_t fd, const void *b, uint32_t len)
{ return sc5(NR_SEND, (uint32_t)fd, (uint32_t)(uintptr_t)b, len, 0, 0); }
static int32_t s_recv(int32_t fd, void *b, uint32_t len)
{ return sc5(NR_RECV, (uint32_t)fd, (uint32_t)(uintptr_t)b, len, 0, 0); }
static int32_t s_close(int32_t fd)                 { return sc5(NR_CLOSE_SOCK, (uint32_t)fd, 0, 0, 0, 0); }

/* ── VFS 组薄封装（nr 对照 vfs_syscall：1=write 5=open 6=close）────────────── */
static int32_t sys_write(uint32_t fd, const void *buf, uint32_t len)
{ return sc5(NR_WRITE, fd, (uint32_t)(uintptr_t)buf, len, 0, 0); }
static int32_t sys_open(const char *path, uint32_t flags)
{ return sc5(NR_OPEN, (uint32_t)(uintptr_t)path, flags, 0, 0, 0); }

__attribute__((noreturn)) static void sys_exit(uint32_t st)
{ (void)sc5(NR_EXIT, st, 0, 0, 0, 0); for (;;) { __asm__ volatile("hlt"); } }

/* ── 极小运行时（自洽实现，不依赖 libc 链接）───────────────────────────────── */
static uint32_t kstrlen(const char *s) { uint32_t n = 0; while (s[n]) n++; return n; }

/* 通用追加器：向 dst[cap] 的 pos 处追加字符串/十进制数，返回新 pos（截断安全） */
static uint32_t buf_put(char *dst, uint32_t cap, uint32_t pos, const char *s)
{
    while (*s) {
        if (pos >= cap - 1u) break;
        dst[pos++] = *s++;
    }
    dst[pos] = '\0';
    return pos;
}
static uint32_t buf_put_dec(char *dst, uint32_t cap, uint32_t pos, int32_t v)
{
    char t[12];
    uint32_t i = 0, u;
    if (v < 0) {
        if (pos < cap - 1u) dst[pos++] = '-';
        u = (uint32_t)(-(v + 1)) + 1u;
    } else {
        u = (uint32_t)v;
    }
    if (!u) t[i++] = '0';
    while (u) { t[i++] = (char)('0' + u % 10u); u /= 10u; }
    while (i && pos < cap - 1u) dst[pos++] = t[--i];
    dst[pos] = '\0';
    return pos;
}

/* ── 日志通道：open("/dev/console") 取 fd，失败回退 fd=1（stdout 同为 console）─ */
static int32_t logfd = 1;
static char logbuf[192];
static uint32_t log_pos;

static void log_str(const char *s)  { log_pos = buf_put(logbuf, sizeof(logbuf), log_pos, s); }
static void log_dec(int32_t v)      { log_pos = buf_put_dec(logbuf, sizeof(logbuf), log_pos, v); }
static void log_ch(char c)
{
    if (log_pos < sizeof(logbuf) - 1u)
        logbuf[log_pos++] = c;
    logbuf[log_pos] = '\0';
}
static void log_flush(void)         { (void)sys_write((uint32_t)logfd, logbuf, kstrlen(logbuf)); log_pos = 0; }

static void log_line(const char *s)
{
    log_pos = 0;
    log_str("[HTTPD] ");
    log_str(s);
    log_ch('\n');
    log_flush();
}

/* 访问日志单行：[HTTPD] conn fd=N st=200 path=... bytes=B（整行一次 write 保原子） */
static void log_access(int32_t fd, int st, const char *path, uint32_t bytes)
{
    log_pos = 0;
    log_str("[HTTPD] conn fd=");
    log_dec(fd);
    log_str(" st=");
    log_dec(st);
    log_str(" path=");
    log_str(path);
    log_str(" bytes=");
    log_dec((int32_t)bytes);
    log_ch('\n');
    log_flush();
}

/* ── 缓冲区（.bss 静态区，规避 4KB 用户栈限制，设计稿 §7-L7）────────────────── */
static char req_buf[REQ_MAX];    /* 请求累积缓冲 */
static char resp_buf[RESP_MAX];  /* 响应拼装缓冲（头+正文一体，远小于 MSS=1460 单段即可发） */
static uint32_t resp_len;

/* 响应拼装器 */
static void rb_reset(void)          { resp_len = 0; resp_buf[0] = '\0'; }
static void rb_s(const char *s)     { resp_len = buf_put(resp_buf, sizeof(resp_buf), resp_len, s); }
static void rb_dec(int32_t v)       { resp_len = buf_put_dec(resp_buf, sizeof(resp_buf), resp_len, v); }

/* ── accept 空转让（设计稿 §4.2 策略 B/C 折中：无 yield syscall，短忙等软化）─── */
static void soften(void)
{
    volatile uint32_t spin;
    for (spin = 0; spin < 4096u; spin++)
        ;
}

/* 子串检索：req_buf[0..total) 中是否含 "\r\n\r\n"（头块终结） */
static int has_header_end(uint32_t total)
{
    uint32_t i;
    if (total < 4u) return 0;
    for (i = 0; i + 3u < total; i++) {
        if (req_buf[i] == '\r' && req_buf[i+1u] == '\n' &&
            req_buf[i+2u] == '\r' && req_buf[i+3u] == '\n')
            return 1;
    }
    return 0;
}

/* req_buf[0..total) 中是否已有完整首行（"\r\n" 或 '\n' 出现） */
static int has_first_line(uint32_t total)
{
    uint32_t i;
    for (i = 0; i < total; i++) {
        if (req_buf[i] == '\n') return 1;
    }
    return 0;
}

/* ── 读请求：recv 直到 "\r\n\r\n" / EOF / 首行完整且超预算 / 错误 ──────────────
 * 返回 >=0：累积字节数（保证 req_buf NUL 结尾）；<0：异常，调用方直接关连接。
 * 契约依据 docs/SOCKET_API.md §3.5：0=EOF；-EAGAIN=暂无数据；其余负值=错误。 */
static int32_t recv_request(int32_t fd)
{
    uint32_t total = 0;
    uint32_t eagain = 0;

    req_buf[0] = '\0';
    for (;;) {
        int32_t n = s_recv(fd, req_buf + total, REQ_MAX - 1u - total);
        if (n > 0) {
            total += (uint32_t)n;
            if (total > REQ_MAX - 1u) total = REQ_MAX - 1u; /* 防御：clamp */
            req_buf[total] = '\0';
            if (has_header_end(total))
                return (int32_t)total;
            if (total >= REQ_MAX - 1u)
                return -1;                       /* 头超限：畸形流量，弃 */
            continue;
        }
        if (n == 0) {                            /* EOF：半开请求 */
            return has_first_line(total) ? (int32_t)total : -1;
        }
        if (n == EAGAIN) {
            if (++eagain > RECV_EAGAIN_BUDGET)
                return has_first_line(total) ? (int32_t)total : -1;
            continue;
        }
        return -1;                               /* 其他错误：直接关连接 */
    }
}

/* ── 请求行解析（仅首行；版本宽容；方法白名单=GET；路径归一化按设计稿 §4.3）────
 * 返回 ST_200/ST_405/ST_400；*path_out 指向 req_buf 内部（NUL 截断），仅在
 * 响应拼装期间有效（本程序单线程顺序处理，无重入风险）。 */
static int parse_request_line(uint32_t total, const char **path_out)
{
    uint32_t i = 0, ms, me, ps, pe, k;

    while (i < total && req_buf[i] != '\r' && req_buf[i] != '\n') i++;

    ms = 0;
    while (ms < i && req_buf[ms] == ' ') ms++;
    me = ms;
    while (me < i && req_buf[me] != ' ') me++;
    if (me == ms) return ST_400;                              /* 空 method */
    if (!(me - ms == 3u && req_buf[ms] == 'G' &&
          req_buf[ms + 1u] == 'E' && req_buf[ms + 2u] == 'T'))
        return ST_405;                                        /* 非 GET 一律 405 */

    while (me < i && req_buf[me] == ' ') me++;                /* 容忍多空格 */
    ps = me;
    pe = ps;
    while (pe < i && req_buf[pe] != ' ') pe++;
    if (pe == ps) return ST_400;                              /* 缺 PATH */
    if (req_buf[ps] != '/') return ST_400;                    /* 必须 '/' 开头 */
    if (pe - ps > PATH_LEN_MAX) return ST_400;                /* 路径过长 */
    for (k = ps; k + 1u < pe; k++) {
        if (req_buf[k] == '.' && req_buf[k + 1u] == '.')
            return ST_400;                                    /* 拒绝 ".." */
    }

    req_buf[pe] = '\0';   /* 安全：pe<i<=total<=REQ_MAX-1 */
    *path_out = req_buf + ps;
    return ST_200;
}

/* ── 响应生成（固定内存区拼接，设计稿 §4.4 格式）───────────────────────────── */
static void build_response(int st, const char *path)
{
    rb_reset();
    switch (st) {
    case ST_200:
        rb_s("HTTP/1.0 200 OK\r\n"
             "Content-Type: text/plain\r\n"
             "Content-Length: ");
        rb_dec((int32_t)BODY_OK_LEN);
        rb_s("\r\n"
             "Connection: close\r\n"
             "\r\n");
        rb_s(body_ok);
        break;
    case ST_405:
        rb_s("HTTP/1.0 405 Method Not Allowed\r\n"
             "Allow: GET\r\n"
             "Content-Type: text/plain\r\n"
             "Content-Length: ");
        rb_dec((int32_t)kstrlen(body_405));
        rb_s("\r\n"
             "Connection: close\r\n"
             "\r\n");
        rb_s(body_405);
        break;
    default: /* ST_400 */
        rb_s("HTTP/1.0 400 Bad Request\r\n"
             "Content-Type: text/plain\r\n"
             "Content-Length: ");
        rb_dec((int32_t)kstrlen(body_400));
        rb_s("\r\n"
             "Connection: close\r\n"
             "\r\n");
        rb_s(body_400);
        break;
    }
    (void)path; /* M0：路径不参与内容选择（无文件系统），仅入日志 */
}

/* ── 发送：游标推进式部分写循环（docs/SOCKET_API.md §3.4 收缩式部分写契约）─────
 * r>0 推进；r==0 视为发送缓冲满（TODO(code2) 歧义）→ 计数退避重试，超限放弃；
 * r<0 放弃。宁可截断不可死循环。返回 0=全量写完，-1=截断/失败。 */
static int send_all(int32_t fd, const char *buf, uint32_t len)
{
    uint32_t off = 0, idle = 0;
    while (off < len) {
        int32_t r = s_send(fd, buf + off, len - off);
        if (r < 0)
            return -1;
        if (r == 0) {
            if (++idle > SEND_IDLE_CAP)
                return -1;
            continue;
        }
        idle = 0;
        off += (uint32_t)r;
    }
    return 0;
}

/* ── 单连接处理：任何路径都收敛到 close(cfd)+回 accept，绝不影响主循环 ───────── */
static void process_conn(int32_t cfd)
{
    int32_t total;
    int st;
    const char *path = "(none)";

    total = recv_request(cfd);
    if (total < 0) {
        log_line("conn: recv incomplete/error, closing");
        (void)s_close(cfd);
        return;
    }

    st = parse_request_line((uint32_t)total, &path);
    build_response(st, path);

    if (send_all(cfd, resp_buf, resp_len) < 0)
        log_line("conn: send truncated/failed");
    log_access(cfd, st, path, resp_len);

    (void)s_close(cfd);   /* Connection: close 语义：nr=28 → FIN */
}

/* ── 初始化致命失败：记日志后退出（主循环开始后不再有任何退出路径）───────────── */
__attribute__((noreturn)) static void fatal(const char *what, int32_t err)
{
    log_pos = 0;
    log_str("[HTTPD] FATAL ");
    log_str(what);
    log_str(" err=");
    log_dec(err);
    log_ch('\n');
    log_flush();
    sys_exit(1u);
}

int main(void)
{
    int32_t lfd, r;
    uint32_t idle_rounds = 0;

    /* 启动 banner：open("/dev/console") 范式；失败回退 fd=1（同为目标设备） */
    r = sys_open("/dev/console", O_WRONLY_C);
    if (r >= 0) {
        logfd = r;
    } else {
        logfd = 1;   /* open 失败返回 -1（非 errno）；stdout 已是 /dev/console */
        log_line("open(/dev/console) failed, falling back to fd=1");
    }

    log_line("cat-os minimal httpd starting (M0: single-process blocking loop)");
    log_pos = 0;
    log_str("[HTTPD] ABI: socket=20 bind=21 listen=22 accept=23 send=26 recv=27 "
            "sock-close=28 | open=5 write=1 exit=12");
    log_ch('\n');
    log_flush();
    log_line("listening on port 80 (QEMU hostfwd 18080 -> guest:80)");

    lfd = s_socket(SOCK_STREAM_C);
    if (lfd <= 0)
        fatal("socket", lfd);

    r = s_bind(lfd, HTTPD_PORT);
    if (r < 0)
        fatal("bind", r);

    r = s_listen(lfd, LISTEN_BACKLOG);
    if (r < 0)
        fatal("listen", r);

    /* ── 主循环：accept → 处理 → close → 回 accept；永不退出 ── */
    for (;;) {
        int32_t cfd = s_accept(lfd);
        if (cfd > 0) {
            process_conn(cfd);
            idle_rounds = 0;
            continue;
        }
        if (cfd == EAGAIN) {
            /* 空队列：周期性插入忙等软化（无 yield/nanosleep syscall，Y6' 缺口） */
            if (((++idle_rounds) & 63u) == 0u)
                soften();
            continue;
        }
        /* 其他 accept 错误：记录但不中止主循环（限频：借 idle_rounds 走 soften） */
        log_pos = 0;
        log_str("[HTTPD] accept err=");
        log_dec(cfd);
        log_ch('\n');
        log_flush();
        soften();
    }
}

/* ELF 入口：无 crt0；栈由调度器置于 ELF_USER_STACK_SP=0x701000（elf.h），
 * 写法先例 shell_user.c / sock_abi 测试 _start。main 正常不返回（死循环）。 */
__attribute__((noreturn)) void _start(void)
{
    (void)main();
    for (;;)
        sys_exit(0u);
}
