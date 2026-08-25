/* syscall.c —— 系统调用分发（int 0x80）
 * ── code5 改动范围声明（Cat-OS 并行任务，文件锁：仅本文件可改）─────────────
 * M2 错误码混叠修复（sendto/recvfrom/send/recv 的错误传递骨架）
 * L1 listen-before-bind 语义（修复点在 net.c → 仅 TODO 注释）
 * L8 close 双重别名关系文档化（nr==3 ↔ nr==6 ↔ nr==28）
 * 各入口 EFAULT/EBADF/ENOTSOCK/EINVAL 严格性审计注释
 * net.c / vfs.c / usermode.c / paging.c 均属其他代理，需要配合处以 TODO(code2) 标注。
 */
#include "kernel.h"
#include "syscall.h"
#include "net.h"
#include "vfs.h"
#include "paging.h"

/* ── code2 改动范围声明（Cat-OS 并行任务，文件锁：本文件追加修改）───────
 * exec/exit/wait 进程类系统调用（nr=11..13）：
 *   - elf_load/create_user_process/exit_process 的实现在 elf.c/process.c
 *     （其他代理区域），本文件仅按任务书以 extern 声明对接，不 include
 *     elf.h/process.h —— 避免在并行窗口拉入其未提交中间态。
 *   - shell 镜像来自 shell_bin.h（本代理生成）；kernel.c 尚未 include 该头，
 *     故以 weak extern 引用，符号缺失时链接通过、运行时判空走 VFS 分支。
 *   - nr=11..13 落于 VFS 兼容层号段（<20）但 vfs_syscall 对其无分支
 *     （vfs.c default→-ENOSYS），故在 syscall_dispatch 前置拦截，无重叠。
 * 任务书原稿与头文件定稿的接口差异（create_process/双参 exit_process、
 * elf_load(path) 签名）已按 elf.h:44 / process.h:66-69 定稿适配，见回执。
 */
/* code2: 进程类系统调用号（syscall.h 锁定不可改，常量暂驻本文件；
 * TODO(解锁后): 迁入 syscall.h 与既有 CATOS_SYS_* 家族对齐——先例同 M2 的
 * CATOS_EMSGSIZE 驻留方案）。 */
#define CATOS_SYS_EXEC 11
#define CATOS_SYS_EXIT 12
#define CATOS_SYS_WAIT 13
#define CATOS_EPERM    1   /* linux-ref include/uapi/asm-generic/errno-base.h:7 */
#define CATOS_ENOENT   2   /* 同上 :2 */
#define CATOS_E2BIG    7   /* 同上 :8 */
#define CATOS_ECHILD  10   /* 同上 :11 */

/* code2: 对接其他代理实现的外部接口（签名逐字对照定稿头文件）：
 *   elf.h:44      int elf_load(const void *image, size_t len, uint32_t *entry_out);
 *                 （注意：镜像内存指针 + 长度，而非任务书原稿的 path 单参）
 *   process.h:66  int create_user_process(uint32_t user_entry, uint32_t page_dir,
 *                                         uint32_t user_esp);
 *   process.h:68  void exit_process(int pid);（单参，非任务书原稿双参）
 *   process.h:69  uint32_t process_current_pid(void); */
extern int elf_load(const void *image, unsigned int len, uint32_t *entry_out);
extern int create_user_process(uint32_t user_entry, uint32_t page_dir,
                               uint32_t user_esp);
extern void exit_process(int pid);
extern uint32_t process_current_pid(void);

/* code2: shell_bin.h 嵌入镜像（weak）。kernel.c 解锁并 #include "shell_bin.h"
 * 后符号生效；在此之前引用处地址为 0，sys_exec 判空回落 VFS 文件分支。
 * 数组名/类型与 xxd -i shell_user.elf 的输出逐字一致（shell_bin.h 头注释）。 */
extern unsigned char shell_user_elf[] __attribute__((weak));
extern unsigned int shell_user_elf_len __attribute__((weak));

/* code2: 与 elf.h 定稿值的本地同步副本（不 include elf.h 所致；改动需双侧同步）
 *   elf.h:31 ELF_USER_STACK_SP = ELF_USER_STACK_BASE+4096 = 0x701000。
 * 栈页本身由 elf_load 内部映射（elf.c:199 map_user_page），exec 无需重复映射。 */
#define CATOS_EXEC_USER_STACK_SP 0x701000u

/* ── M2: 补充错误码常量 ──────────────────────────────────────────────
 * 数值依据 linux-ref/include/uapi/asm-generic/errno.h：
 *   EMSGSIZE=90（errno.h:74）、EADDRNOTAVAIL=99（errno.h:83，注意不是 BSD 的 49）。
 * syscall.h 受本次文件锁限制不可改，常量暂驻本文件；
 * TODO(解锁后): 迁入 syscall.h 与既有 CATOS_E* 家族对齐。 */
#define CATOS_EMSGSIZE      90
#define CATOS_EADDRNOTAVAIL 99

/* ── M2: UDP 单报文负载上限（字节）＝Ethernet MTU 1500 − IPv4 头 20 − UDP 头 8 ──
 * 与 net.c udp_sendto() 内部检查同值（net.c:296）。在 syscall 层预检是为了立刻
 * 给出可区分的 -EMSGSIZE（对照 linux-ref/net/ipv4/ip_output.c:591：数据报超
 * 路径 MTU 返回 -EMSGSIZE）。
 * TODO(code2): 若 net.c 让 udp_sendto 直接返回 -EMSGSIZE，删除此处重复检查，
 * 交给 sock_xlate 直通即可（两处阈值需保持同步直至合并）。 */
#define CATOS_UDP_PAYLOAD_MAX 1472u

void syscall_init(void){kputs("[OK] syscall dispatcher initialized (native/Linux shim tables)\n");}
int user_range_ok(uint32_t p,uint32_t n){return p>=0x400000u&&n<=0xBFC00000u-p;}
static int bad_user(const void *p,uint32_t n,int write){return !user_access_ok((uintptr_t)p,n,write);}
static socket_t *sock_fd(int fd){return (socket_t*)vfs_socket_get(fd);}
/* EBADF/ENOTSOCK 判序（审计结论，保持不变）：fd 未打开/越界 → -EBADF；
 * 已打开但非 FILE_SOCKET → -ENOTSOCK。与 linux-ref/net/socket.c
 * sockfd_lookup_light 语义顺序一致（先 EBADF 后 ENOTSOCK）。
 * 负数 fd 安全：vfs_fd_exists/vfs_socket_get 均有 fd<0 边界检查（vfs.c）。 */
static int sock_err(int fd){return vfs_fd_exists(fd)?-CATOS_ENOTSOCK:-CATOS_EBADF;}

/* ── M2 错误码传递骨架（sock_xlate）────────────────────────────────────
 * 混叠根因（本次只读核实）：net.c 的 udp_sendto/udp_recvfrom/tcp_send/tcp_recv
 * 失败时一律返回哨兵 -1（net.c:294/300/932/944），上层无法区分
 * EMSGSIZE/EADDRNOTAVAIL/EAGAIN —— net.c 属 code2 区域，本文件只能建立传递骨架。
 * 翻译规则：
 *   r >= 0     → 成功，原样返回（字节数或 0）；
 *   r == -1    → 遗留无差别哨兵，按该调用点语义翻译为 fallback
 *                （socket 收发路径的 -1 统一含义是「暂无数据/暂不能发」→ -EAGAIN，
 *                与 Linux 非阻塞 socket 的 EAGAIN 一致）；
 *   其余 r < 0 → 视为 -errno 原样直通：code2 把底层改为返回区分性 -errno 后，
 *                本文件零改动即自动获得 EMSGSIZE/EADDRNOTAVAIL/EINVAL 区分能力。
 * 已知歧义：数值 -1 与 -EPERM 同值。
 * TODO(code2): 底层迁移到真实 -errno 后必须废止裸 -1 哨兵（对照模型：
 * linux-ref/net/socket.c:2246 __sys_sendto、2306 __sys_recvfrom —— 协议层
 * -errno 经 sock->ops 原样上抛，socket 层不做二次折叠）。 */
static int sock_xlate(int r,int fallback){
    if(r>=0)return r;
    if(r==-1)return fallback;
    return r;
}

/* ── code2: 进程类系统调用实现（exec/exit/wait）────────────────────────── */

/* 用户态路径拷贝：起始 1 字节预检 + 逐字节推进直至 NUL，上限 255 字节。
 * 扫描策略与 vfs_syscall nr==5 分支一致（超长按坏指针族 -EFAULT 收敛）。 */
static int sys_fetch_path(uint32_t uptr, char *kbuf)
{
    const char *p = (const char *)(uintptr_t)uptr;
    if (!user_access_ok((uintptr_t)p, 1u, 0)) return -CATOS_EFAULT;
    uint32_t i = 0;
    while (i < 255u) {
        if (!user_access_ok((uintptr_t)(p + i), 1u, 0)) return -CATOS_EFAULT;
        kbuf[i] = p[i];
        if (p[i] == '\0') return (int)i;
        i++;
    }
    return -CATOS_EFAULT; /* 未终止的超长路径 → 与 vfs nr==5 的 sl>=256 同语义 */
}

/* 本文件内无 strcmp（kernel.h 仅 kputs/kput_* 家族），最小字面量比较即可 */
static int sys_streq(const char *a, const char *b)
{
    while (*a != '\0' && *a == *b) { a++; b++; }
    return (*a == *b) ? 1 : 0;
}

/* exec 镜像暂存缓冲（内核 BSS）：当前 devfs 无常规文件可读，缓冲上限按
 * shell ELF 实测 9KB 留 4x 余量；未来接入块设备 fs 后建议改为按 inode 尺寸
 * 分配。TODO(code2): 接入真实 fs 后评估动态分配替代静态缓冲。 */
#define CATOS_EXEC_IMG_MAX 32768u
static uint8_t exec_img_buf[CATOS_EXEC_IMG_MAX];

/* exec(path)：
 *   ① 嵌入镜像分支：path=="/bin/shell" 且 shell_bin.h 符号已由 kernel.c 启用
 *      → 直接以 (shell_user_elf, shell_user_elf_len) 交 elf_load；
 *   ② VFS 分支：open(O_RDONLY)/循环 read/close 读满整个镜像（devfs 无常规
 *      文件时 open 即失败，透传其错误码；为未来 fs 预留完整通路）；
 *   ③ elf_load 校验并装载 PT_LOAD 段至当前页目录用户区（共享目录模式，
 *      process.h address_space_t 注释：page_dir=0 表示沿用当前内核页目录），
 *      成功后 create_user_process 以 entry + CATOS_EXEC_USER_STACK_SP 建
 *      ring3 进程，返回新 pid（>0）；各步失败透传 -errno。
 * 任务书原稿「返回 entry 地址」按定稿接口调整为返回新进程 pid —— entry 已
 * 消耗于 create_user_process，pid 是 ring3 调用方可用的有效句柄。 */
static int sys_exec(const uint32_t *a)
{
    char path[256];
    int plen = sys_fetch_path(a[0], path);
    if (plen < 0) return plen;

    const void *image = (void *)0;
    unsigned int ilen = 0u;

    if (&shell_user_elf != (void *)0 && shell_user_elf_len > 0u &&
        sys_streq(path, "/bin/shell")) {
        image = shell_user_elf;
        ilen = shell_user_elf_len;
    }
    if (image == (void *)0) {
        int fd = vfs_open(path, O_RDONLY); /* O_RDONLY=0，vfs.h:5 */
        if (fd < 0) return fd;
        unsigned int got = 0u;
        for (;;) {
            if (got >= CATOS_EXEC_IMG_MAX) { vfs_close(fd); return -CATOS_E2BIG; }
            int r = vfs_read(fd, exec_img_buf + got, CATOS_EXEC_IMG_MAX - got);
            if (r < 0) { vfs_close(fd); return r; }
            if (r == 0) break;
            got += (unsigned int)r;
        }
        vfs_close(fd);
        if (got == 0u) return -CATOS_ENOENT;
        image = exec_img_buf;
        ilen = got;
    }

    uint32_t entry = 0u;
    int segs = elf_load(image, ilen, &entry);
    if (segs < 0) return segs;
    /* page_dir=0：共享内核页目录（elf.h 注释确认 paging.c 未暴露独立地址
     * 空间 API，映射进当前目录低半区）；栈页由 elf_load 映射 @0x700000。 */
    return create_user_process(entry, 0u, CATOS_EXEC_USER_STACK_SP);
}

/* exit(status)：标记当前进程 TERMINATED（exit_process），调度器随即将
 * 上下文切走，本调用对 ring3 不再返回。status 暂无处存储 —— PCB 无退出码
 * 字段（process.h 定稿无此成员），待 wait 实装一并扩展。
 * TODO(code2): PCB 增加 exit_status 后于此记录，供 wait 收割上报。 */
static int sys_exit(const uint32_t *a)
{
    uint32_t pid = process_current_pid();
    if (pid == 0u) return -CATOS_EPERM; /* pcb[0]=idle/内核保留位（process.h:52），禁自杀 */
    (void)a[0]; /* status：见上注 */
    exit_process((int)pid);
    return 0;
}

/* wait(status_out)：stub —— 真实等待需要 PROC_BLOCKED 的睡眠/唤醒原语
 * （process.h 五态模型中该态仅定义，process.c 无 sleep/wakeup）。
 * 对照 linux-ref kernel/exit.c:1448：无（可收割）子进程 → -ECHILD。
 * TODO(code2): 阻塞原语就绪后实现子进程链表扫描 + 退出码回收。 */
static int sys_wait(const uint32_t *a)
{
    if (bad_user((const void *)(uintptr_t)a[0], 4u, 1)) return -CATOS_EFAULT;
    return -CATOS_ECHILD;
}

/* code2: 进程类分发入口（syscall_dispatch 前置拦截转发至此） */
static int proc_syscall(uint32_t nr, const uint32_t *a)
{
    switch (nr) {
    case CATOS_SYS_EXEC: return sys_exec(a);
    case CATOS_SYS_EXIT: return sys_exit(a);
    case CATOS_SYS_WAIT: return sys_wait(a);
    default: return -CATOS_ENOSYS;
    }
}

/* int 0x80 调用约定（据 interrupts.c interrupt_dispatch 核实）：
 *   EAX = 系统调用号；EBX,ECX,EDX,ESI,EDI → a[0..4]；a[5] 恒 0（用户态只有
 *   5 个传参寄存器）；n 恒为 6；返回值经 sign-extend 写回 EAX，负值为 -errno。
 * nr<20 整体委托 vfs_syscall（VFS 兼容 ABI：0=read/1=write/5=open/6=close，
 * 含 close 双别名，详见 nr==28 处 L8 说明块）。 */
int32_t syscall_dispatch(uint32_t nr,uint32_t n,const uint32_t *a){
    (void)n;if(!a)return -CATOS_EFAULT; /* 防御性守卫：现调用点 a 恒为内核栈数组非空 */
    /* code2: 进程类 nr=11..13 先于 VFS 兼容层分发。vfs_syscall 对未知 nr
     * 返回 -ENOSYS（vfs.c default 分支），与本组号段无重叠；前置拦截避免
     * exec/exit/wait 误入 VFS default 路径。 */
    if(nr>=11u&&nr<=13u)return proc_syscall(nr,a);
    if(nr<20)return vfs_syscall(nr,a);
    switch(nr){
    /* socket(type)：a[0]=type（house ABI 无 domain/protocol 形参）。
     * 白名单外 → -EINVAL（Linux 对非法 type 报 EPROTOTYPE/EPROTONOSUPPORT 族，
     * house 收敛为单一 EINVAL，已在 ABI 文档层面接受）。
     * net 表满 → -EMFILE；fd 安装失败 → 透传安装错误并回收 socket（防泄漏）。 */
    case CATOS_SYS_SOCKET:{
        if(a[0]!=CATOS_SOCK_DGRAM&&a[0]!=CATOS_SOCK_STREAM)return -CATOS_EINVAL;
        socket_t *s=net_socket_open(a[0]);if(!s)return -CATOS_EMFILE;
        int fd=vfs_socket_install(s);if(fd<0){net_socket_close(s);return fd;}return fd;
    }
    /* bind(fd,port)：a[1]=port（house ABI 无 sockaddr 结构，IPv4 隐含）。
     * net_socket_bind（net.c:497）契约：port==0 或类型不符 → -EINVAL(-22)；
     * 端口冲突/槽位占用 → -EADDRINUSE(-98)。映射正确，原样透传。
     * 分歧注记：Linux bind(port=0) 表示请求自动分配端口（最终 inet_autobind），
     * 此处为 -EINVAL —— 差异已知，归属 net.c 语义决策，不在本次范围。 */
    case CATOS_SYS_BIND:{socket_t *s=sock_fd((int)a[0]);if(!s)return sock_err((int)a[0]);return net_socket_bind(s,(uint16_t)a[1]);}
    /* listen(fd,backlog)：L1 语义缺口 —— 「未 bind 先 listen」当前得到 -EINVAL。
     * 根因定位（只读核实）：net.c tcp_set_backlog（net.c:535；预检报告所写
     * net.c:489 因 code2 工作区未提交改动而行号漂移）要求
     * s->type==SOCK_TCP_LISTEN，而未绑定 socket 是 SOCK_TCP_UNBOUND。
     * Linux 参照：__sys_listen（linux-ref/net/socket.c:1989）→ inet_listen 对
     * 未绑定 socket 先 inet_autobind（linux-ref/net/ipv4/af_inet.c:181）分配
     * 临时端口再转 LISTEN，返回 0。
     * 修复需选择空闲端口的分配逻辑（依赖 tcp_conn_find_listen 等 net.c 内部
     * 静态状态），无法在本文件内正确实现 → 按任务规则只加 TODO。 */
    case CATOS_SYS_LISTEN:{socket_t *s=sock_fd((int)a[0]);if(!s)return sock_err((int)a[0]);
        /* TODO(code2)(L1): 在 tcp_set_backlog 中为 SOCK_TCP_UNBOUND 增加自动绑定
         * （参照 af_inet.c:181 inet_autobind：挑选空闲 lport → state=TCP_LISTEN
         * → 返回 0），使 listen-before-bind 不再返回 -EINVAL；完成后本层无需改动。 */
        return tcp_set_backlog(s,a[1]);}
    /* accept(fd)：无 backlog 形参（backlog 由 listen 设置）。
     * 非 LISTEN 型 socket → -EINVAL（与 Linux 一致："socket is not listening"）；
     * 就绪队列为空 → -EAGAIN（accept 为非阻塞轮询语义；Linux 在 O_NONBLOCK 下
     * 同样返回 EAGAIN）。fd 安装失败 → 透传并以 tcp_abort_socket 回收连接。 */
    case CATOS_SYS_ACCEPT:{socket_t *s=sock_fd((int)a[0]);if(!s)return sock_err((int)a[0]);if(s->type!=SOCK_TCP_LISTEN)return -CATOS_EINVAL;socket_t *nxt=tcp_accept_socket(s);if(!nxt)return -CATOS_EAGAIN;int fd=vfs_socket_install(nxt);if(fd<0){tcp_abort_socket(nxt);return fd;}return fd;}
    /* sendto(fd,buf,len,dst_ip,dst_port)：
     *   a[0]=fd a[1]=buf a[2]=len a[3]=dst_ip(uint32) a[4]=dst_port(uint16)。
     * 与 Linux 六参布局（flags/addr/addrlen）不同：int 0x80 仅 5 个传参寄存器，
     * house ABI 收缩为五参、无 flags —— 见函数头调用约定注释。
     * 错误判定顺序（严格性审计定案，先参数后状态）：
     *   EBADF/ENOTSOCK → EFAULT(buf 用户区不可读) → EMSGSIZE(len>1472)
     *   → EADDRNOTAVAIL(SOCK_UDP_UNBOUND 未 bind) → 底层瞬时失败(如 ARP 未决)
     *   经 sock_xlate → EAGAIN。 */
    case CATOS_SYS_SENDTO:{
        socket_t *s=sock_fd((int)a[0]);if(!s)return sock_err((int)a[0]);
        if(bad_user((void*)a[1],a[2],0))return -CATOS_EFAULT;
        if(a[2]>CATOS_UDP_PAYLOAD_MAX)return -CATOS_EMSGSIZE; /* 依据见 CATOS_UDP_PAYLOAD_MAX 定义处 */
        /* 目标语义（阶段4 缺口清单 M2）：未 bind 的 UDP socket 上 sendto
         * → -EADDRNOTAVAIL（经 type 字段在本层可判，net.c 无需配合）。
         * 分歧注记：Linux 对未绑定 UDP 发送会 inet_autobind 分配临时源端口
         * （af_inet.c:181），并不返回 EADDRNOTAVAIL；Cat-OS 无临时端口分配器，
         * 显式拒绝使错误可区分。TODO(code2): 若日后实现 autobind 语义，应在
         * net.c 侧做并让 udp_sendto 返回 -EADDRNOTAVAIL，届时删除本检查。 */
        if(s->type==SOCK_UDP_UNBOUND)return -CATOS_EADDRNOTAVAIL;
        return sock_xlate(udp_sendto(s,a[3],(uint16_t)a[4],(const uint8_t*)a[1],a[2]),-CATOS_EAGAIN);
        /* TODO(code2): udp_sendto（net.c:294）目前把「类型不符」「len>1472」
         * 「底层发送失败」全部折叠为 -1，且对 TCP 型 socket 也走同一 -1；
         * 建议分别返回 -EOPNOTSUPP / -EMSGSIZE / -EAGAIN，sock_xlate 即直通。 */
    }
    /* recvfrom(fd,buf,len,src_ip_out,src_port_out)：
     *   a[3]=uint32_t*(4B 可写) a[4]=uint16_t*(2B 可写)。
     * EFAULT 严格性审计：三个用户区对象全部预检（buf/src_ip/src_port），比
     * Linux（两个地址出参可为 NULL）更严 —— net.c udp_recvfrom 虽容忍空指针，
     * 但 house ABI 层不允许；刻意收紧，保持不变。 */
    case CATOS_SYS_RECVFROM:{
        socket_t *s=sock_fd((int)a[0]);if(!s)return sock_err((int)a[0]);
        if(bad_user((void*)a[1],a[2],1)||bad_user((void*)a[3],4,1)||bad_user((void*)a[4],2,1))return -CATOS_EFAULT;
        /* 接收队列空（net.c:302 返回哨兵 -1）→ 非阻塞语义 -EAGAIN；
         * code2 改造后的区分性 -errno 由 sock_xlate 直通。 */
        int r=udp_recvfrom(s,(uint32_t*)a[3],(uint16_t*)a[4],(uint8_t*)a[1],a[2]);
        return sock_xlate(r,-CATOS_EAGAIN);
        /* TODO(code2): udp_recvfrom（net.c:300,309）在 dlen>max_len 时静默截断且
         * 余量随整包丢弃，无 MSG_TRUNC 等价上报；定截断语义时一并定返回码。 */
    }
    /* send(fd,buf,len)：仅 SOCK_TCP_ESTAB 可用，否则 -ENOTCONN（ring3 探针
     * usermode.c 对该断言有依赖；Linux tcp_sendmsg 对未连接 socket 同样属于
     * -ENOTCONN/-EPIPE 错误族）。 */
    case CATOS_SYS_SEND:{
        socket_t *s=sock_fd((int)a[0]);if(!s)return sock_err((int)a[0]);
        if(s->type!=SOCK_TCP_ESTAB)return -CATOS_ENOTCONN;
        if(bad_user((void*)a[1],a[2],0))return -CATOS_EFAULT;
        /* tcp_send（net.c）是部分写语义：>MSS(1460) 或发送缓冲不足时收缩并
         * 返回实际接受字节数（类似 write(2)，合法）。阶段3 code4 已落实错误码
         * 区分化：缓冲满 → -EAGAIN（非阻塞语义，sock_xlate 直通，零长度写仍
         * 返回 0）；连接被 RST 复位后 → -ECONNRESET 直通。原 TODO(code2) 就此
         * 结清。 */
        return sock_xlate(tcp_send(s,(const uint8_t*)a[1],a[2]),-CATOS_EAGAIN);
    }
    /* recv(fd,buf,len)：仅 SOCK_TCP_ESTAB 可用，否则 -ENOTCONN（探针依赖，同 send）。
     * tcp_recv（net.c）契约：无数据且对端已发 FIN（CLOSE_WAIT/LAST_ACK/
     * TIME_WAIT）→ 0 = EOF；未关闭且 rxn==0 → 哨兵 -1 → 此处译为 -EAGAIN；
     * 阶段3 code4 起，连接被 RST 复位 → -ECONNRESET 由 sock_xlate 直通
     * （不再以假 EAGAIN 掩盖复位事实）。 */
    case CATOS_SYS_RECV:{
        socket_t *s=sock_fd((int)a[0]);if(!s)return sock_err((int)a[0]);
        if(s->type!=SOCK_TCP_ESTAB)return -CATOS_ENOTCONN;
        if(bad_user((void*)a[1],a[2],1))return -CATOS_EFAULT;
        return sock_xlate(tcp_recv(s,(uint8_t*)a[1],a[2]),-CATOS_EAGAIN);
    }
    /* ── L8: close 的三条路径与双重别名关系 ──────────────────────────────
     * ① nr==28（CATOS_SYS_CLOSE，本 case）：唯一 socket-aware 关闭路径。
     *    fd 为 FILE_SOCKET → net_socket_close()（触发 TCP FIN / UDP 槽释放）
     *    成功后再 vfs_socket_close() 释放描述符；否则回落 vfs_close()（普通文件）。
     * ② nr==6：vfs_syscall（vfs.c:21）直接 vfs_close(a[0]) —— 不感知 socket。
     * ③ nr==3：vfs.c:21 中与 nr==6 逐字等价的第二分支（同为 vfs_close(a[0])），
     *    即 nr==6 ↔ nr==3 构成双重别名。
     * 关系与风险注记（审计结论）：
     *   - vfs_close 对 FILE_SOCKET 一律 -EBADF（vfs.c:16 kind!=FILE_VFS→-9），
     *     故 ②③ 不能用来关 socket、也不会绕过 socket 清理造成泄漏；别名只作用于
     *     普通文件描述符。socket 的正确关闭号只有 nr==28。
     *   - ⚠️ ABI 兼容性警告：Linux x86-32 中 nr==3 是 read(2)、nr==6 才是 close(2)；
     *     本内核 VFS ABI 却为 0=read/1=write/5=open/6=close 并把 3 别名到 close。
     *     按 Linux ABI 编写的 ring3 程序若以 nr=3 调 read，实际会关闭 fd。
     *     TODO(vfs.c 所有者，本文件锁内不动 vfs.c): 建议移除 nr==3 别名或改挂 read。
     *   - interrupts.c:31 对 nr==6 打印 "[OK] user syscall close fd=3 ..." 仅为
     *     探针演示日志（fd 恰为 3），与别名机制无关。
     * 审计附注：net_socket_close 对 SOCK_CLOSED 型返回 -EBADF(-9) 且不释放 fd，
     * 存在理论上的描述符滞留窗口（如 accept 失败 abort 之后）；契约属 net.c。
     * TODO(code2): net_socket_close 对已 CLOSED 型应幂等释放或由本层兜底
     * vfs_socket_close，二选一，避免 fd 泄漏。 */
    case CATOS_SYS_CLOSE:{if(sock_fd((int)a[0])){int r=net_socket_close(sock_fd((int)a[0]));if(r==0)vfs_socket_close((int)a[0]);return r;}return vfs_close((int)a[0]);}
    /* ping(target_txt,out,out_len,id,seq)：EFAULT 审计通过 —— 入参文本
     * bad_user(a[0],16,0)（IPv4 点分十进制最长 15+B）与输出缓冲
     * bad_user(a[1],a[2],1) 均预检；非法地址走「写错误串入 out」而非错误码，
     * 为既定演示语义，保持不变。 */
    case CATOS_SYS_PING:{uint32_t dst;if(bad_user((void*)a[0],16,0)||bad_user((void*)a[1],a[2],1))return -CATOS_EFAULT;if(!net_parse_ipv4((const char*)a[0],&dst)){static const char msg[]="ping: invalid address\n";uint32_t n=sizeof(msg)-1;for(uint32_t i=0;i<a[2];i++)((char*)a[1])[i]='\0';if(n>a[2])n=a[2];for(uint32_t i=0;i<n;i++)((char*)a[1])[i]=msg[i];return (int)n;}return net_ping(dst,(uint16_t)a[3],(uint16_t)a[4],(char*)a[1],a[2]);}
    /* ping_stats(out,out_len)：EFAULT 审计通过 —— a[1] 长度参与
     * user_access_ok 的 n<=0xBFC00000-v 上界判断，无整数溢出（paging.c:330）。 */
    case CATOS_SYS_PING_STATS:{if(bad_user((void*)a[0],a[1],1))return -CATOS_EFAULT;return net_ping_stats((char*)a[0],a[1]);}
    default:return -CATOS_ENOSYS;
    }
}
