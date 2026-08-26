/*
 * user_sock_abi_test.c —— Cat-OS 用户态 socket ABI 测试程序（code10 · tests-only）
 * ─────────────────────────────────────────────────────────────────────────────
 * 任务：NEXT_TASKS_AUTONOMOUS.md 阶段4 测试部分「维护 ABI 表和用户态最小测试程序」。
 *
 * ★ 文件锁合规声明：本文件为 tests/ 下【新增】文件，零改动仓库现有文件。
 *   内核侧（syscall.c/net.c/usermode.c 等）本轮只读。
 *
 * ── 触发路径现状（诚实声明，详见同目录 README.md §3）─────────────────────────
 *   当前 HEAD=09fb9b4 + 工作区状态下，ring3 程序加载仅有两条路径：
 *     ① kernel.c 引导时内嵌 elf_load(shell_user_elf) —— 仅 /bin/shell 镜像；
 *     ② exec(nr=11)：syscall.c sys_exec 嵌入分支仅匹配 "/bin/shell"，
 *        VFS 分支依赖常规文件，而 devfs 无常规文件（vfs.c nodes[] 名单）。
 *   ⇒ 本测试程序在当前内核上【无任何触发路径】，全部运行时用例 NOT_TESTED，
 *     绝不伪造 PASS。本文件的价值：ABI 语义的可执行规约 + 编译期自检 +
 *     未来任意 ELF exec 落地后的即插即用套件。
 *
 * ── int 0x80 调用约定（interrupts.c interrupt_dispatch vector==128 实证）────
 *   EAX = nr；EBX,ECX,EDX,ESI,EDI → a[0..4]；a[5] 恒 0；返回值 sign-extend
 *   写回 EAX，负值为 -errno。本程序需 5 参封装（sendto/recvfrom 用满 ESI/EDI）。
 *
 * ── 断言风格（照 tests/net_suite.py）────────────────────────────────────────
 *   每条断言一行：RESULT <id> <desc>: expect=<want> got=<got> PASS|FAIL|XFAIL|SKIP
 *   汇总：SUMMARY[user_sock_abi]: passed=N failed=M xfail=K skip=J
 *   收尾标记：USR_SOCK_ABI VERDICT rc=<0|2>（对齐 net_suite 的 EXIT_OK/EXIT_ASSERT；
 *   XFAIL/SKIP 不计入 rc）。全部经 write(1)=/dev/console → 串口原文可复核。
 *   注意：exit status 当前无处存储（PCB 无退出码字段，syscall.c sys_exit 注释），
 *   rc 以串口 VERDICT 行为准，exit(2) 参数为未来 wait() 预留。
 *
 * ── 期望值依据（逐条对应 README.md 用例表）──────────────────────────────────
 *   docs/RING3_SYSCALL_ABI.md §3.2/§5/§6、docs/SOCKET_API.md §3/§4；
 *   源码基准：syscall.c 工作区（M2 错误码骨架）、net.c 工作区、vfs.c L2、
 *   paging.c user_access_ok（n==0 放行；v<0x1000 拒绝；上界 0xBFC00000 算术必拒）。
 */

#include <stdint.h>

/* ── ABI 常量镜像（源 syscall.h / syscall.c；锁定不可改，故本地同步副本）──── */
#define NR_SOCKET    20u
#define NR_BIND      21u
#define NR_LISTEN    22u
#define NR_ACCEPT    23u
#define NR_SENDTO    24u
#define NR_RECVFROM  25u
#define NR_SEND      26u
#define NR_RECV      27u
#define NR_CLOSE28   28u
#define NR_READ      0u
#define NR_READ_L32  3u   /* Linux x86-32 read(2) 号；2026-08-26 L8 别名拆除后
                            * 与 nr==0 同走 vfs_read，不再是 close 别名 */
#define NR_OPEN      5u
#define NR_CLOSE6    6u   /* 普通文件关闭号（不感知 socket，kind 隔离 -EBADF） */
#define NR_WRITE     1u
#define NR_EXIT      12u

#define EFAULT       (-14)
#define EBADF        (-9)
#define EINVAL       (-22)
#define EAGAIN       (-11)
#define EADDRINUSE   (-98)
#define EMFILE       (-24)
#define ENOTCONN     (-107)
#define ENOTSOCK     (-88)
#define EMSGSIZE     (-90)
#define EADDRNOTAVAIL (-99)
#define ENOSYS       (-38)

#define SOCK_STREAM_C 1   /* CATOS_SOCK_STREAM */
#define SOCK_DGRAM_C  2   /* CATOS_SOCK_DGRAM  */

#define TCP_MAX_CONNS_C 64u   /* net.h:86（2026-08-26 容量第一档 16→64）*/
#define VFS_MAX_FD_C    32u   /* vfs.h:4（全局 fd 表容量；TCP 容量抬升后与
                               * 协议表共同决定 ring3 耗尽次序，见 S7n 注释）*/
#define UDP_SLOTS_C     8u    /* net.c:216（docs/SOCKET_API.md §2.2）*/
#define UDP_PAYLOAD_MAX 1472u /* MTU1500-20-8，syscall.c CATOS_UDP_PAYLOAD_MAX */

/* H2/D1 已知分歧（docs/SOCKET_API.md §4.1）：TCP 同端口重复 bind 当前走
 * 「附着」模式返回 0，目标语义为 -EADDRINUSE。断言自适应：修复前 XFAIL。 */
static const int32_t WANT_ATTACH_FIXED = -98;  /* 目标语义（修复后 PASS）*/
static const int32_t WANT_ATTACH_CUR   = 0;    /* 现状附着模式（XFAIL）*/

/* ── int 0x80 五参封装（写法对齐 shell_user.c syscall3 / libc catos_syscall.h；
 *     寄存器映射据 interrupts.c a[6]={ebx,ecx,edx,esi,edi,0} 实证）────────── */
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

/* ── socket 组薄封装（参数布局 = docs/RING3_SYSCALL_ABI.md §3.2）─────────── */
static int32_t s_socket(uint32_t type)            { return sc5(NR_SOCKET, type, 0, 0, 0, 0); }
static int32_t s_bind(int32_t fd, uint32_t port)  { return sc5(NR_BIND, (uint32_t)fd, port, 0, 0, 0); }
static int32_t s_listen(int32_t fd, uint32_t bl)  { return sc5(NR_LISTEN, (uint32_t)fd, bl, 0, 0, 0); }
static int32_t s_accept(int32_t fd)               { return sc5(NR_ACCEPT, (uint32_t)fd, 0, 0, 0, 0); }
static int32_t s_sendto(int32_t fd, const void *b, uint32_t len,
                        uint32_t ip, uint32_t pt)
{ return sc5(NR_SENDTO, (uint32_t)fd, (uint32_t)(uintptr_t)b, len, ip, pt); }
static int32_t s_recvfrom(int32_t fd, void *b, uint32_t len,
                          const void *ip_out, const void *pt_out)
{ return sc5(NR_RECVFROM, (uint32_t)fd, (uint32_t)(uintptr_t)b, len,
             (uint32_t)(uintptr_t)ip_out, (uint32_t)(uintptr_t)pt_out); }
static int32_t s_send(int32_t fd, const void *b, uint32_t len)
{ return sc5(NR_SEND, (uint32_t)fd, (uint32_t)(uintptr_t)b, len, 0, 0); }
static int32_t s_recv(int32_t fd, void *b, uint32_t len)
{ return sc5(NR_RECV, (uint32_t)fd, (uint32_t)(uintptr_t)b, len, 0, 0); }
static int32_t s_close(int32_t fd)                { return sc5(NR_CLOSE28, (uint32_t)fd, 0, 0, 0, 0); }

/* ── 极小运行时（无 libc；write(1)=/dev/console → VGA+COM1 双路）──────────── */
static uint32_t kstrlen(const char *s) { uint32_t n = 0; while (s[n]) n++; return n; }
static int32_t  sys_write(const char *s) { return sc5(NR_WRITE, 1u, (uint32_t)(uintptr_t)s, kstrlen(s), 0, 0); }
__attribute__((noreturn)) static void sys_exit(uint32_t st)
{ (void)sc5(NR_EXIT, st, 0, 0, 0, 0); for (;;) { __asm__ volatile("hlt"); } }

/* 行缓冲拼装器：整行单次 write，保证串口中该行原子可 grep
 * （内核每条 write 后会附打 "[OK] user syscall write ret=N" 日志行）。 */
static char    lb[224];
static uint32_t ln;
static void lb_reset(void) { ln = 0; }
static void lb_ch(char c) { if (ln < sizeof(lb) - 1u) lb[ln++] = c; }
static void lb_s(const char *s) { while (*s) lb_ch(*s++); }
static void lb_dec(int32_t v)
{
    char t[12]; uint32_t i = 0, u;
    if (v < 0) { lb_ch('-'); u = (uint32_t)(-(v + 1)) + 1u; } else u = (uint32_t)v;
    if (!u) t[i++] = '0';
    while (u) { t[i++] = (char)('0' + u % 10u); u /= 10u; }
    while (i) lb_ch(t[--i]);
}
static void lb_flush(void) { lb[ln] = '\0'; (void)sys_write(lb); ln = 0; }

/* ── 断言管道（对齐 net_suite.py 的 check()/note() 语义）─────────────────── */
static int g_pass, g_fail, g_xfail, g_skip;

static void chk(const char *id, const char *desc, int32_t got, int32_t want)
{
    lb_reset(); lb_s("RESULT "); lb_s(id); lb_ch(' '); lb_s(desc);
    lb_s(": expect="); lb_dec(want); lb_s(" got="); lb_dec(got);
    if (got == want) { g_pass++; lb_s(" PASS"); } else { g_fail++; lb_s(" FAIL"); }
    lb_ch('\n'); lb_flush();
}
/* 布尔型断言（cond: 0/1），用于 fd>0、计数区间等非单一 errno 断言 */
static void chk_cond(const char *id, const char *desc, int cond)
{
    chk(id, desc, cond ? 1 : 0, 1);
}
/* H2/D1 自适应断言：现状附着模式 → XFAIL（登记不掩盖）；已修复 → PASS */
static void chk_attach_deviation(const char *id, int32_t got)
{
    lb_reset(); lb_s("RESULT "); lb_s(id);
    lb_s(" tcp-dup-bind-target=-98 known-H2/D1-attach=0: got="); lb_dec(got);
    if (got == WANT_ATTACH_FIXED) { g_pass++; lb_s(" PASS (target semantics restored)"); }
    else if (got == WANT_ATTACH_CUR) { g_xfail++; lb_s(" XFAIL (H2/D1 attach-mode, documented deviation)"); }
    else { g_fail++; lb_s(" FAIL"); }
    lb_ch('\n'); lb_flush();
}
/* SKIP：无法在本触发路径下运行/需要外部驱动协作的用例（NOT_TESTED 登记处） */
static void skip(const char *id, const char *reason)
{
    lb_reset(); lb_s("RESULT "); lb_s(id); lb_s(" SKIP(NOT_TESTED): "); lb_s(reason);
    g_skip++; lb_ch('\n'); lb_flush();
}
/* INFO-CALL：结果不进入计数的行为性调用（歧义路径收尾等），留串口原文备查 */
static void info_call(const char *id, const char *what, int32_t r)
{
    lb_reset(); lb_s("INFO-CALL "); lb_s(id); lb_ch(' '); lb_s(what);
    lb_s(": r="); lb_dec(r); lb_s(" (not counted)");
    lb_ch('\n'); lb_flush();
}
static void info(const char *s)
{
    lb_reset(); lb_s("[USR_SOCK_ABI] "); lb_s(s); lb_ch('\n'); lb_flush();
}
static void section(const char *s)
{
    lb_reset(); lb_s("SECTION "); lb_s(s); lb_ch('\n'); lb_flush();
}

/* ── 共享状态与缓冲（.bss 位于用户合法区 [0x400000,0xBFC00000)，
 *     先例 shell_user.c "static char line[128]" 注释）────────────────────── */
static int32_t g_udp_bound;      /* 全程存活的已绑 UDP socket（S2 创建，S3/S4/S5 复用）*/
static uint8_t  iobuf[128];      /* 合法用户缓冲（发送/接收用）*/
static uint32_t rip_out;         /* recvfrom 出参：src_ip（4B 可写对象）*/
static uint16_t rpt_out;         /* recvfrom 出参：src_port（2B 可写对象）*/
static int32_t  kept[TCP_MAX_CONNS_C]; /* 资源耗尽用例 fd 收集器：按协议表容量
                                        * 常量取上界（fd 表 VFS_MAX_FD_C 更小时
                                        * 循环以终端错误码提前退出，不会越界）*/
/* 非法指针样本（值本身永不解引用——内核 user_access_ok 预检先行拒绝）：
 *   BAD_LO = 0x100       < 0x1000 低页洞（paging.c user_access_ok 第一判）
 *   BAD_HI = 0xBFC00000  上界哨兵：n > 0xBFC00000-v 算术必拒（v=上界,n≥1）*/
#define BAD_LO ((void *)0x100u)
#define BAD_HI ((void *)0xBFC00000u)
/* sendto 的目的地址：所有被断言的 sendto 路径均在 EFAULT/EMSGSIZE/EADDRNOTAVAIL
 * 预查处返回、不出网，故该值不影响结果确定性（注释明示防误读）。*/
#define DST_IP_ANY   0x0A000202u   /* 形似 slirp 网关 10.0.2.2 */
#define DST_PORT_ANY 5555u
/* 测试专用端口段 94xx：避开内核基线服务 :7/:81 与 ring3 探针常用端口 */

int main(void);

/* ════════════════════════ S1: socket() 分配与类型白名单 ═════════════════ */
static void suite_socket_basics(void)
{
    int32_t a, b, c;
    section("S1 socket(): type whitelist + allocation");
    a = s_socket(0u);            chk("S1a", "socket(type=0)_einval", a, EINVAL);
    b = s_socket(3u);            chk("S1b", "socket(type=3)_einval", b, EINVAL);
    a = s_socket(SOCK_STREAM_C); chk_cond("S1c", "socket(STREAM)_fd_positive", a > 0);
    if (a > 0) { c = s_close(a); chk("S1e", "close(stream_fd)", c, 0); }
    b = s_socket(SOCK_DGRAM_C);  chk_cond("S1d", "socket(DGRAM)_fd_positive", b > 0);
    if (b > 0) { c = s_close(b); chk("S1f", "close(dgram_fd)", c, 0); }
}

/* ════════════════════════ S2: bind 语义（含端口冲突）═════════════════════ */
static void suite_bind(void)
{
    int32_t v, ta, tb, tc, r;

    section("S2 bind(): port conflicts / type rules / bad-fd family");
    r = s_bind(g_udp_bound, 0u);
    chk("S2b", "bind_udp_port0_einval(non-Linux-divergence)", r, EINVAL);
    r = s_bind(g_udp_bound, 9401u); chk("S2c", "bind_udp_9401_ok", r, 0);
    r = s_bind(g_udp_bound, 9402u);
    chk("S2d", "re-bind_same_sock_newport_einval(type-driven)", r, EINVAL);

    v = s_socket(SOCK_DGRAM_C);  chk_cond("S2e", "setup_udp2_fd", v > 0);
    r = s_bind(v, 9401u);        chk("S2f", "bind_dup_udp_port_eaddrinuse", r, EADDRINUSE);
    if (v > 0) { r = s_close(v); info_call("S2z1", "close(conflict-probe-udp)", r); }

    r = s_bind(1, 9403u);        chk("S2g", "bind_consolefd_enotsock", r, ENOTSOCK);
    r = s_bind(-1, 80u);         chk("S2h", "bind_negfd_ebadf", r, EBADF);
    r = s_bind(5000, 80u);       chk("S2i", "bind_hugefd_ebadf", r, EBADF);

    ta = s_socket(SOCK_STREAM_C); chk_cond("S2j", "setup_tcp_a_fd", ta > 0);
    r = s_bind(ta, 9450u);        chk("S2k", "bind_tcp_9450_listener_ok", r, 0);
    tb = s_socket(SOCK_STREAM_C); chk_cond("S2l", "setup_tcp_b_fd", tb > 0);
    r = s_bind(tb, 9450u);        chk_attach_deviation("S2m", r);   /* H2/D1 自适应 */
    if (tb > 0) { r = s_close(tb); info_call("S2z2", "close(attach-mode-sock, ambiguous-path)", r); }
    if (ta > 0) { r = s_close(ta); info_call("S2z3", "close(tcp-listener-9450)", r); }

    tc = s_socket(SOCK_STREAM_C); chk_cond("S2n", "setup_tcp_c_fd", tc > 0);
    r = s_bind(tc, 9460u);        chk("S2o", "bind_tcp_9460_ok", r, 0);
    r = s_listen(tc, 8u);         chk("S2p", "listen_after_bind_backlog8_ok", r, 0);
    r = s_accept(tc);             chk("S2q", "accept_bound_listener_empty_queue_eagain", r, EAGAIN);
    if (tc > 0) { r = s_close(tc); info_call("S2z4", "close(tcp-listener-9460)", r); }
}

/* ════════════════════════ S3: listen(backlog) 语义 ══════════════════════ */
static void suite_listen(void)
{
    int32_t lu, l0, r;

    section("S3 listen(): unbound/UDP targets + backlog values");
    lu = s_socket(SOCK_STREAM_C); chk_cond("S3a", "setup_tcp_unbound_fd", lu > 0);
    r = s_listen(lu, 4u);          chk("S3b", "listen_before_bind_einval(L1-known-gap)", r, EINVAL);
    r = s_listen(g_udp_bound, 4u); chk("S3c", "listen_on_udp_socket_einval", r, EINVAL);
    l0 = s_socket(SOCK_STREAM_C);  chk_cond("S3d", "setup_tcp_l0_fd", l0 > 0);
    r = s_bind(l0, 9461u);         chk("S3e", "setup_bind_l0_9461", r, 0);
    r = s_listen(l0, 0u);          chk("S3f", "listen_backlog0_ok(treated-as-1-internally)", r, 0);
    r = s_listen(l0, 999u);        chk("S3g", "listen_backlog999_ok(clamped-to-TCP_MAX_CONNS_internally)", r, 0);
    r = s_listen(1, 4u);           chk("S3h", "listen_consolefd_enotsock", r, ENOTSOCK);
    r = s_listen(-7, 1u);          chk("S3i", "listen_negfd_ebadf", r, EBADF);
    if (l0 > 0) { r = s_close(l0); info_call("S3z1", "close(l0-listener)", r); }
    if (lu > 0) { r = s_close(lu); info_call("S3z2", "close(unbound-tcp)", r); }
}

/* ════════════════════════ S4: accept 语义 ═══════════════════════════════ */
static void suite_accept(int32_t listener)
{
    int32_t ub, r;

    section("S4 accept(): non-listen targets + non-blocking empty queue");
    r = s_accept(g_udp_bound); chk("S4a", "accept_on_udp_einval", r, EINVAL);
    ub = s_socket(SOCK_STREAM_C);
    r = s_accept(ub);          chk("S4b", "accept_on_unbound_tcp_einval", r, EINVAL);
    if (ub > 0) { r = s_close(ub); info_call("S4z1", "close(unbound-tcp)", r); }
    r = s_accept(1);           chk("S4c", "accept_consolefd_enotsock", r, ENOTSOCK);
    r = s_accept(12345);       chk("S4d", "accept_hugefd_ebadf", r, EBADF);
    r = s_accept(listener);    chk("S4e", "empty_queue_poll1_eagain", r, EAGAIN);
    r = s_accept(listener);    chk("S4f", "empty_queue_poll2_eagain", r, EAGAIN);
    r = s_accept(listener);    chk("S4g", "empty_queue_poll3_eagain", r, EAGAIN);
    skip("S4h", "backlog queue-depth & overflow-RST need external SYN driver "
                "(slirp hostfwd harness); planned marker protocol in README §7");
}

/* ════════════════════════ S5: sendto/recvfrom（UDP 数据面 + 指针校验）════ */
static void suite_udp_data(void)
{
    int32_t su, r;

    section("S5 sendto/recvfrom(): validation order + EFAULT + EAGAIN");
    su = s_socket(SOCK_DGRAM_C); chk_cond("S5a", "setup_udp_unbound_fd", su > 0);
    r = s_sendto(su, iobuf, 4u, DST_IP_ANY, DST_PORT_ANY);
    chk("S5b", "sendto_unbound_eaddrnotavail(M2-order:after-EFAULT/EMSGSIZE)", r, EADDRNOTAVAIL);
    r = s_recvfrom(su, iobuf, sizeof(iobuf), &rip_out, &rpt_out);
    chk("S5c", "recvfrom_unbound_queue_empty_eagain", r, EAGAIN);

    r = s_sendto(g_udp_bound, iobuf, UDP_PAYLOAD_MAX + 1u, DST_IP_ANY, DST_PORT_ANY);
    chk("S5d", "sendto_len1473_emsgsize", r, EMSGSIZE);
    r = s_sendto(g_udp_bound, iobuf, 4096u, DST_IP_ANY, DST_PORT_ANY);
    chk("S5e", "sendto_len4096_emsgsize", r, EMSGSIZE);
    r = s_sendto(g_udp_bound, BAD_LO, 16u, DST_IP_ANY, DST_PORT_ANY);
    chk("S5f", "sendto_lowptr_0x100_efault(user_range_precheck)", r, EFAULT);
    r = s_sendto(g_udp_bound, BAD_HI, 1u, DST_IP_ANY, DST_PORT_ANY);
    chk("S5g", "sendto_boundary_ptr_0xBFC00000_efault(arithmetic-reject)", r, EFAULT);

    r = s_recvfrom(g_udp_bound, BAD_LO, 64u, &rip_out, &rpt_out);
    chk("S5h", "recvfrom_badbuf_efault", r, EFAULT);
    r = s_recvfrom(g_udp_bound, iobuf, sizeof(iobuf), BAD_LO, &rpt_out);
    chk("S5i", "recvfrom_bad_ipout_efault(4B-out-object)", r, EFAULT);
    r = s_recvfrom(g_udp_bound, iobuf, sizeof(iobuf), &rip_out, BAD_HI);
    chk("S5j", "recvfrom_bad_portout_efault(2B-out-object)", r, EFAULT);
    r = s_recvfrom(g_udp_bound, iobuf, sizeof(iobuf), &rip_out, &rpt_out);
    chk("S5k", "recvfrom_bound_but_no_sender_eagain", r, EAGAIN);

    skip("S5l", "multi-socket directed-delivery isolation needs external UDP driver");
    skip("S5m", "len=1472 boundary acceptance goes on-wire (ARP/timing dependent); "
                "driver-assisted case");
    if (su > 0) { r = s_close(su); info_call("S5z1", "close(unbound-udp)", r); }
}

/* ════════════════════════ S6: send/recv 未连接行为 ══════════════════════ */
static void suite_tcp_unconnected(int32_t listener)
{
    int32_t tu, r;

    section("S6 send/recv(): ENOTCONN gate before pointer checks");
    tu = s_socket(SOCK_STREAM_C); chk_cond("S6a", "setup_tcp_unbound_fd", tu > 0);
    r = s_send(tu, iobuf, 4u);  chk("S6b", "send_on_unbound_tcp_enotconn", r, ENOTCONN);
    r = s_recv(tu, iobuf, 4u);  chk("S6c", "recv_on_unbound_tcp_enotconn", r, ENOTCONN);
    r = s_send(listener, iobuf, 4u); chk("S6d", "send_on_LISTEN_sock_enotconn", r, ENOTCONN);
    r = s_recv(listener, iobuf, 4u); chk("S6e", "recv_on_LISTEN_sock_enotconn", r, ENOTCONN);
    r = s_send(1, iobuf, 1u);   chk("S6f", "send_consolefd_enotsock", r, ENOTSOCK);
    r = s_recv(2, iobuf, 1u);   chk("S6g", "recv_stderrfd_enotsock", r, ENOTSOCK);
    r = s_send(-3, iobuf, 1u);  chk("S6h", "send_negfd_ebadf", r, EBADF);
    r = s_recv(4096, iobuf, 1u); chk("S6i", "recv_hugefd_ebadf", r, EBADF);
    skip("S6j", "ESTAB data-plane (partial-write/EAGAIN/EOF=0/send-EFAULT-on-ESTAB) "
                "needs an accepted connection from external driver; note send/recv "
                "EFAULT subcases are unreachable pre-ESTAB by design (ENOTCONN gate "
                "precedes pointer check, syscall.c M2 ordering)");
    if (tu > 0) { r = s_close(tu); info_call("S6z1", "close(unbound-tcp)", r); }
}

/* ════════════════════════ S7: FD 生命周期 / 资源耗尽 / 关闭语义 ══════════ */
static void suite_fd_lifecycle(void)
{
    int32_t f, g, h, h2, r, n, last, cnt;
    uint32_t cap;
    const int32_t kept_cap = (int32_t)(sizeof(kept) / sizeof(kept[0]));

    section("S7 close/double-close/fd-exhaustion/nr3-read(L8-defused)/recycle");

    f = s_socket(SOCK_DGRAM_C);  chk_cond("S7a", "setup_udp_fd", f > 0);
    r = s_close(f);              chk("S7b", "close_socket_nr28_ok", r, 0);
    r = s_close(f);              chk("S7c", "double_close_ebadf(fd-slot-freed)", r, EBADF);
    r = s_close(31);             chk("S7d", "close_never_opened_fd31_ebadf", r, EBADF);
    r = s_close(-1);             chk("S7e", "close_neg1_ebadf", r, EBADF);

    g = s_socket(SOCK_DGRAM_C);  chk_cond("S7f", "setup_udp_fd2", g > 0);
    r = sc5(6u, (uint32_t)g, 0, 0, 0, 0);
    chk("S7g", "nr6_alias_close_on_socket_ebadf(L8-kind-isolation)", r, EBADF);
    r = s_close(g);              chk("S7h", "nr28_close_ok_after_alias_reject", r, 0);

    h = s_socket(SOCK_DGRAM_C);  chk_cond("S7i", "setup_udp_fd3", h > 0);
    r = s_close(h);              chk("S7j", "close_for_reuse_test", r, 0);
    h2 = s_socket(SOCK_DGRAM_C); chk_cond("S7k", "reopen_fd", h2 > 0);
    chk_cond("S7l", "lowest_free_slot_reuse(vfs_fd_alloc-L2-policy)", h2 > 0 && h2 == h);
    r = s_close(h2);             chk("S7m", "close(reused_fd)", r, 0);

    /* L8 拆除回归（2026-08-26，内核 vfs.c 同步变更）：nr==3 已从 close 别名
     * 改挂 read 路径（Linux x86-32 read(2)=3）。用 open("/dev/null") 的普通
     * 文件 fd 连续两次 nr==3 读：旧别名下第一次即关 fd、第二次必 EBADF；
     * 新语义两次均返回 0（nullread），随后 nr==6 正常关闭、再读得 EBADF ——
     * 四条联合锁定「nr==3=read / nr==6=close / 关闭后 nr==3 尊重 EBADF」。
     * 注意：断言的是返回值而非 iobuf 内容（nullread 不写缓冲）。 */
    {
        int32_t nfd = sc5(NR_OPEN, (uint32_t)(uintptr_t)"/dev/null", 2u /*O_RDWR*/, 0, 0, 0);
        chk_cond("S7s", "open_devnull_plain_fd", nfd >= 0);
        if (nfd >= 0) {
            r = sc5(NR_READ_L32, (uint32_t)nfd, (uint32_t)(uintptr_t)iobuf, 16u, 0, 0);
            chk("S7t", "nr3_is_read_not_close(first_call_returns_0)", r, 0);
            r = sc5(NR_READ_L32, (uint32_t)nfd, (uint32_t)(uintptr_t)iobuf, 16u, 0, 0);
            chk("S7u", "fd_survives_nr3_call(close_alias_removed)", r, 0);
            r = sc5(NR_CLOSE6, (uint32_t)nfd, 0, 0, 0, 0);
            info_call("S7z5", "nr6_close(plain_file_still_works)", r);
            r = sc5(NR_READ_L32, (uint32_t)nfd, (uint32_t)(uintptr_t)iobuf, 16u, 0, 0);
            chk("S7v", "nr3_read_after_close_ebadf(read_path_validation)", r, EBADF);
        }
    }


    /* TCP 连接表/fd 表耗尽（2026-08-26 调和：容量第一档 16→64 后旧硬编码
     * [1,16] 失准——64 容量下全局 fd 表先满，实测 opened=25 即撞 VFS 上限）。
     * 鲁棒形式：循环开到终端错误码为止，成功数只断言相对区间，不硬编码次数：
     *   上界 cap_eff = min(TCP_MAX_CONNS_C(net.h:86)=64, VFS_MAX_FD_C(vfs.h:4)=32)
     *                 ——两条约束谁先到谁封顶，均不越过该值；
     *   下界 ≥1（本用例自身至少能开 1 条）。
     * 终端错误码恒为 -EMFILE(-24)，两条可能路径同码：
     *   · 协议表满：sys_socket → net_socket_open()==NULL → -EMFILE；
     *   · fd  表满：vfs_socket_install() 分配失败透传 -24（vfs.c:86）。
     * 基线占用（内核 :81 + httpd :7000 + 本进程 listener :9460 等）只影响
     * 落在区间内的具体开数，不参与断言。 */
    cap = (TCP_MAX_CONNS_C < VFS_MAX_FD_C) ? TCP_MAX_CONNS_C : VFS_MAX_FD_C;
    cnt = 0; last = 0;
    for (n = 0; n < kept_cap; n++) {
        r = s_socket(SOCK_STREAM_C);
        if (r < 0) { last = r; break; }
        kept[cnt++] = r;
    }
    chk_cond("S7n", "tcp_exhaustion_terminal_emfile_count_in_[1,cap_eff]",
             last == EMFILE && cnt >= 1 && cnt <= (int32_t)cap);
    lb_reset(); lb_s("[USR_SOCK_ABI] INFO tcp_exhaustion: opened="); lb_dec(cnt);
    lb_s(" terminal="); lb_dec(last);
    lb_s(" cap_eff=min(TCP_MAX_CONNS,");
    lb_dec((int32_t)VFS_MAX_FD_C);
    lb_s(") basis=net.h:86+vfs.h:4");
    lb_ch('\n'); lb_flush();
    while (cnt > 0) { info_call("S7z1", "close(exhausted-tcp)", s_close(kept[--cnt])); }
    r = s_socket(SOCK_STREAM_C);
    chk_cond("S7o", "tcp_slot_recycle_after_mass_close", r > 0);
    if (r > 0) { int32_t cr = s_close(r); info_call("S7z2", "close(recycled-tcp)", cr); }

    /* UDP 槽位耗尽：UDP_SLOTS=8（net.c:216），基线 udp_open(7) 占 1。*/
    cap = UDP_SLOTS_C; cnt = 0; last = 0;
    for (n = 0; n < kept_cap; n++) {
        r = s_socket(SOCK_DGRAM_C);
        if (r < 0) { last = r; break; }
        kept[cnt++] = r;
    }
    chk_cond("S7q", "udp_exhaustion_terminal_emfile_count_in_[1,8]",
             last == EMFILE && cnt >= 1 && cnt <= (int32_t)cap);
    lb_reset(); lb_s("[USR_SOCK_ABI] INFO udp_exhaustion: opened="); lb_dec(cnt);
    lb_s(" terminal="); lb_dec(last);
    lb_ch('\n'); lb_flush();
    while (cnt > 0) { info_call("S7z3", "close(exhausted-udp)", s_close(kept[--cnt])); }
    r = s_socket(SOCK_DGRAM_C);
    chk_cond("S7r", "udp_slot_recycle_after_mass_close", r > 0);
    if (r > 0) { int32_t cr = s_close(r); info_call("S7z4", "close(recycled-udp)", cr); }

    info("layering note (post cap-tier1): TCP cap=64 (net.h:86) >= VFS_MAX_FD=32 "
         "(vfs.h:4), so for ring3 socket storms the GLOBAL fd table co-binds or "
         "binds first; protocol caps still bind UDP(8) and kernel-side users. "
         "S7n/S7q therefore assert errno+interval only: terminal errno is "
         "-EMFILE via either path (net tables / vfs_socket_install vfs.c:86)");
}

/* ════════════════════════ S8: 杂项 ABI 完整性 ═══════════════════════════ */
static void suite_misc(void)
{
    int32_t r;
    section("S8 misc: unknown-nr routing");
    r = sc5(99u, 0, 0, 0, 0, 0); chk("S8a", "unknown_nr99_enosys", r, ENOSYS);
    r = sc5(17u, 0, 0, 0, 0, 0); chk("S8b", "vfs_gap_nr17_enosys(default-fallthrough)", r, ENOSYS);
}

/* ════════════════════════ 主流程 ════════════════════════════════════════ */
int main(void)
{
    int32_t listener, r;

    info("user-mode socket ABI test suite v1 (code10, tests-only)");
    info("expect-basis: syscall.c/net_tcp.c/vfs.c/paging.c @worktree HEAD=611b080+ "
         "(cap tier1: net.h:86 TCP_MAX_CONNS 16->64)");
    info("trigger-path note: requires arbitrary-ELF exec (NOT available at this "
         "head: sys_exec embedded branch matches only /bin/shell; devfs has no "
         "regular files). Runtime results are NOT_TESTED until wired.");
    info("marker contract: grep 'RESULT ' / 'SUMMARY[user_sock_abi]' / 'USR_SOCK_ABI VERDICT'");

    suite_socket_basics();

    /* 全局已绑 UDP socket：创建一次，贯穿 S2~S5（结束前统一回收）*/
    g_udp_bound = s_socket(SOCK_DGRAM_C);
    chk_cond("S2a", "setup_global_udp_fd", g_udp_bound > 0);

    suite_bind();
    suite_listen();

    listener = s_socket(SOCK_STREAM_C);
    chk_cond("S4s", "setup_listener_fd(for-S4/S6)", listener > 0);
    r = s_bind(listener, 9460u);  chk("S4t", "setup_bind_listener_9460", r, 0);
    r = s_listen(listener, 4u);   chk("S4u", "setup_listen_backlog4", r, 0);

    suite_accept(listener);
    suite_udp_data();
    suite_tcp_unconnected(listener);
    suite_fd_lifecycle();
    suite_misc();

    if (listener > 0) { r = s_close(listener); info_call("ENDz1", "close(main-listener)", r); }
    if (g_udp_bound > 0) { r = s_close(g_udp_bound); info_call("ENDz2", "close(global-udp)", r); }

    lb_reset();
    lb_s("SUMMARY[user_sock_abi]: passed="); lb_dec(g_pass);
    lb_s(" failed="); lb_dec(g_fail);
    lb_s(" xfail="); lb_dec(g_xfail);
    lb_s(" skip="); lb_dec(g_skip);
    lb_ch('\n'); lb_flush();

    lb_reset();
    lb_s("USR_SOCK_ABI VERDICT rc="); lb_dec(g_fail ? 2 : 0);
    lb_s(" (xfail/skip excluded; aligns net_suite.py EXIT_OK/EXIT_ASSERT)");
    lb_ch('\n'); lb_flush();

    sys_exit((uint32_t)(g_fail ? 2u : 0u));
}

/* ELF 入口：无 crt0；栈由调度器置于 ELF_USER_STACK_SP=0x701000（elf.h），
 * 写法先例 shell_user.c _start。*/
__attribute__((noreturn)) void _start(void)
{
    (void)main();
    for (;;)
        sys_exit(1u);
}
