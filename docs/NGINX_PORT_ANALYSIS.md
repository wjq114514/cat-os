# Cat-OS × nginx 1.x 移植预研报告（NGINX_PORT_ANALYSIS）

> **任务**：code3 并行任务 · 只读分析，仅新建本文档与 `MINIMAL_HTTPD_DESIGN.md`，零源码改动。
> **仓库基线**：`/home/wjqawa/osdev`，git log 最新提交 `6796bd6`（"net: harden tcp sack edge cases"；任务书所写 `0d4b583` 为其父提交，工作区另含多个并行任务的未提交改动，本文行号均指**当前工作区文件实测内容**）。
> **nginx 参考基准**：nginx 主线 **1.26.x**（src/os/unix/ 目录布局）。⚠️ 本机无 nginx 源码树副本（`find` 仅见运行时安装 `/usr/local/nginx`），故 nginx 侧引用给到**文件名 + 函数名**级；具体行号待取得对应版本源码后回填核实，凡未核实处一律标注「待验证」，不做臆造。
> **状态标记约定**：✅可验证 = 已由源码/文档直接证实；🔍待验证 = 结论合理但未运行复现或未核对原始源码；⛔不可行 = 以现有架构无法满足，需重大变更。

---

## 目录

1. [执行摘要](#1-执行摘要)
2. [Cat-OS 现状盘点（按子系统）](#2-cat-os-现状盘点按子系统)
3. [nginx 1.x 依赖清单与差距矩阵](#3-nginx-1x-依赖清单与差距矩阵)
4. [三档分级汇总](#4-三档分级汇总)
5. [分阶段移植路线图](#5-分阶段移植路线图)
6. [关键风险与架构决策点](#6-关键风险与架构决策点)
7. [与既有缺口编号体系的映射](#7-与既有缺口编号体系的映射)
8. [NOT_TESTED 清单](#8-not_tested-清单)

---

## 1. 执行摘要

| 问题 | 结论 |
|---|---|
| nginx 1.26 能否在 Cat-OS 当前状态下直接编译移植？ | **⛔不可行**。连配置文件都无法读取（devfs 无常规文件系统，vfs.c:20 设备名单仅五个 `/dev/*` 节点），且无 fork/epoll/signal/mmap 四大支柱 |
| 差距总量 | nginx 核心依赖约 40 项系统调用/能力中，Cat-OS 已覆盖 **11 项（绿）**，易补 **13 项（黄）**，需重大架构变更 **10 项（红）**（明细见 §4） |
| 正确的中间步骤 | **先自研最小 HTTP 服务（ring3 单进程 httpd）**——它几乎可以跑在**当前 ABI** 上（accept/recv/send/close 全部已具备），作为 nginx 移植的验收参照物与基础设施试金石，设计见 `MINIMAL_HTTPD_DESIGN.md` |
| 最大单项风险 | ① 事件就绪通知机制缺失（现网唯一"事件驱动"是 IRQ0 @100Hz tick 驱动的 `net_poll()` 忙轮询，interrupts.c:23）；② 单一全局页目录（paging.c:15 `kernel_page_directory` 静态实例，map_page 仅写此目录，paging.c:302），fork/地址空间隔离无从谈起 |

---

## 2. Cat-OS 现状盘点（按子系统）

### 2.1 网络（net.c，1018 行）

| 能力 | 现状 | 证据 | 状态 |
|---|---|---|---|
| TCP 被动开放全链路 | socket/bind/listen/accept/send/recv/close 七件套齐备，含 backlog（上限 16）、TIME_WAIT、RST、persist 探针 | net.c:681(tcp_listen)、533(accept)、971(close)；syscall 层 nr=20..28（syscall.h:16-26） | ✅ |
| TCP 主动开放 connect | **不存在**。`enum tcp_state` 预留了 `TCP_SYN_SENT`（net.h:47），但 net.h 公共 API 与 net.c 全文无任何 connect 实现（docs/SOCKET_API.md §4.4 同结论） | net.h:107-118 无声明；SOCKET_API.md §4.4 | ✅（缺口属实） |
| UDP | sendto/recvfrom 可用；ring3 必须 bind 后才能发（UNBOUND → -EADDRNOTAVAIL） | net.c:294/300；syscall.c sendto 分支 | ✅ |
| 可靠性机制 | SACK（≤2 块）/OOO 队列（4 槽）/scoreboard/RTO（300ms~2.4s）/NewReno 风格拥塞控制 | net.c:365-505, 583-605 | ✅ |
| 容量常量 | TCP 连接表 16、收发缓冲各 4096B、单段 ≤1460B、UDP 槽 8 个 | net.h:67-71；net.c:216-217 | ✅（对 nginx 属硬约束，见 §6） |
| 收包驱动模型 | `timer_handler`（IRQ0 @100Hz）每 tick 调 `net_poll()`；主循环亦忙轮询 | interrupts.c:23/26；kernel.c 主循环；net.c:1006 | ✅（架构瓶颈） |
| 错误码区分性 | 底层失败一律折叠为裸 `-1` 哨兵，syscall 层 `sock_xlate` 统一译为 `-EAGAIN` | net.c:295/297/302/946…；syscall.c sock_xlate | ✅（缺口 M2 登记在案） |

### 2.2 系统调用层（syscall.c，365 行 + syscall.h）

| 能力 | 现状 | 证据 | 状态 |
|---|---|---|---|
| ABI | int 0x80；EAX=nr，EBX/ECX/EDX/ESI/EDI→a[0..4]，a[5]≡0；返回值负数=-errno | docs/RING3_SYSCALL_ABI.md §2（interrupts.c:31 实证） | ✅ |
| 编号表 | VFS 组 nr<20（0=read/1=write/3&6=close/5=open）；socket 组 20-30；进程组 **11=exec/12=exit/13=wait**（code2 已实装拦截） | syscall.h:16-26；syscall.c 进程类分发前置拦截；vfs.c:92 | ✅ |
| exec | 已可用：嵌入镜像分支（/bin/shell weak 符号）+ VFS 文件分支 → `elf_load` → `create_user_process(entry, 0, 0x701000)` | syscall.c sys_exec；elf.h:31 | ✅ |
| exit | 标记 TERMINATED 并让出；**status 无处存储**（PCB 无该字段） | syscall.c sys_exit TODO 注释 | ✅ |
| wait | **stub，恒返回 -ECHILD**（无睡眠原语无法阻塞等待） | syscall.c sys_wait | ✅ |
| 错误码族 | EFAULT(14)/EBADF(9)/ENOTSOCK(88)/EINVAL(22)/EAGAIN(11)/EADDRINUSE(98)/EMFILE(24)/ENOTCONN(107)/ETIMEDOUT(110 定义未见返回路径)/EMSGSIZE(90)/EADDRNOTAVAIL(99)/EPERM(1)/ENOENT(2)/E2BIG(7)/ECHILD(10)，数值与 Linux 对齐 | syscall.h:5-15,27；syscall.c 常量区 | ✅ |

### 2.3 VFS（vfs.c，92 行 + vfs.h）

| 能力 | 现状 | 证据 | 状态 |
|---|---|---|---|
| 文件系统类型 | **纯 devfs**：/dev/null、/dev/console、/dev/kbd、/dev/zero、/dev/urandom 五节点，无目录、无常规文件 | vfs.c:20 nodes[] | ✅ |
| fd 表 | 容量 **32**（VFS_MAX_FD），文件与 socket 共表，最低空闲槽分配，std 流占 0-2 | vfs.h:4；vfs.c L2 改动注释 | ✅ |
| open 语义 | 失败返回 **-1（非 errno）**；flags 仅 O_RDONLY/O_WRONLY/O_RDWR，无 O_NONBLOCK/O_CREAT | vfs.c:66-67；vfs.h:5-7 | ✅ |
| 块设备 | IDE 主盘扇区读写已可用（512B/扇区，PIO），**但没有任何文件系统挂在上面** | ide.h:4；ide.c rw()；kernel.c ide_init 自检通过 | ✅ |

### 2.4 内存管理（paging.c，421 行）

| 能力 | 现状 | 证据 | 状态 |
|---|---|---|---|
| 物理内存 | bitmap PMM（multiboot mmap 解析），alloc/free/DMA 页 | paging.c:150-290 | ✅ |
| 映射能力 | `map_page(virt,phys,flags)` 可建 PDE/PTE 并 invlpg；ioremap 窗口 @0xF0000000 起 | paging.c:292-329, 402-421 | ✅ |
| 地址空间模型 | **单一全局 `kernel_page_directory` 静态实例**；所有映射（含 ELF 用户段）都进这一个目录的低半区（<0xC0000000）；无 per-process 页目录创建 API | paging.c:15, 302-306；elf.h 注释 | ✅（红线根因） |
| 内核堆 | **无 malloc/kmalloc/任何堆分配器**（全仓 grep 零命中），一切静态数组 | grep malloc/kmalloc *.c *.h → 空 | ✅ |
| demand paging/COW | 无；用户页急切全量映射 | paging.c:360-361 NOTE；elf.h 注释 | ✅ |

### 2.5 进程管理（process.c，393 行 / process.h，64 行）

> 任务书称"当前空壳"，实测**已被 code2/code 扩展为完整协作式调度器**（比任务书更新，如实记录）：

| 能力 | 现状 | 证据 | 状态 |
|---|---|---|---|
| 调度器 | 协作式 round-robin，MAX_PROCESSES=32 槽，五态模型（CREATED/READY/RUNNING/BLOCKED/TERMINATED） | process.h:37, 五态枚举；process.c schedule_next | ✅ |
| ring3 进程 | create_user_process（iret 入 ring3，TSS esp0 私有内核栈切换） | process.c create_user_process/process_trampoline | ✅ |
| BLOCKED 态 | **仅定义，无 sleep/wakeup 原语**（process.h 注释自述"本 milestone 仅定义"） | process.h 枚举注释 | ✅ |
| cr3 切换钩子 | trampoline 已支持 `p->as.page_dir != 0 时 mov cr3`——**硬件通路在，缺的是"造出一个新页目录"的上游 API** | process.c process_trampoline cr3 分支 | ✅ |
| fork/waitpid/kill/信号 | **全部不存在** | 全文无相关符号 | ✅ |

### 2.6 时间与其他

| 能力 | 现状 | 证据 | 状态 |
|---|---|---|---|
| 单调时钟 | `volatile uint32_t ticks` @100Hz（约 497 天回绕） | interrupts.c:11,23 | ✅ |
| 墙钟 | RTC BCD 读取，秒级精度，无 syscall 暴露 | rtc.c:4 | ✅ |
| 测试基建 | QEMU hostfwd 黑盒套件（18080→80 等）+ ring3 断言骨架（运行时 NOT_TESTED） | /tmp/cat-os-tests/README.md | ✅ |

---

## 3. nginx 1.x 依赖清单与差距矩阵

> nginx 侧依据：主线 1.26.x 源码布局（文件/函数名为稳定公开事实，**行号待取得源码后核实**）；Cat-OS 侧依据：§2 实测行号。

### 3.1 绿色档 —— 已满足（nginx 可直接使用或薄封装即可）

| # | nginx 依赖 | nginx 参考位置 | Cat-OS 现状 | 评估 | 状态 |
|---|---|---|---|---|---|
| G1 | socket()/bind/listen/accept | src/os/unix/ngx_socket.c、ngx_accept.c | nr=20/21/22/23，非阻塞语义原生（accept 空队列→EAGAIN） | house ABI 无 sockaddr 结构（bind 直接传端口号），需 shim 层翻译；backlog 截断到 16 | ✅可验证 |
| G2 | recv/send（TCP 收发，部分写语义） | src/os/unix/ngx_recv.c、ngx_unix_send.c | nr=26/27；tcp_send 为部分写（收缩返回实际字节）、recv EOF→0/无数据→EAGAIN，与 Unix 语义同型 | tcp_send 缓冲满可返回 0 造成歧义（TODO(code2) 已登记） | ✅可验证 |
| G3 | write/read（stderr 日志等） | src/os/unix/ngx_files.c（ngx_write_fd） | nr=1/0 写 /dev/console；stderr(fd2) 已装 | 日志落盘需黄档 F2 | ✅可验证 |
| G4 | close | src/os/unix/ngx_files.c | nr=28 socket-aware 关闭（FIN/回收）；nr=6 关普通文件 | ⚠️ nr=3 别名 close 与 Linux ABI 冲突（L8 审计），移植前必须裁决移除，否则按 Linux 语义写的代码调 read(3) 会误关 fd | ✅可验证 |
| G5 | UDP sendto/recvfrom | （mail/流模块及 DNS resolver 使用） | nr=24/25 可用；出参不可省略（严于 Linux） | resolver 若用 UDP 可通 | ✅可验证 |
| G6 | errno 数值体系（EAGAIN/EINPROGRESS/EADDRINUSE/EMFILE/ENOTCONN…） | include/uapi asm-generic | Cat-OS 错误码逐一对齐 Linux 数值 | M2 折叠哨兵修复后即完整 | ✅可验证 |
| G7 | /dev/urandom（ssl_session ticket 等随机源） | src/event/ngx_event_openssl.c | vfs.c:20 已提供 /dev/urandom | — | ✅可验证 |
| G8 | exec 族（仅 master 启动 worker 用 execve 或直接 fork 继续；二进制更新 upgrade 用 execve） | src/os/unix/ngx_process.c（ngx_execute_proc） | nr=11 exec 已可从 ELF 镜像拉起 ring3 进程 | 语义差异：Cat-OS exec 是"新建进程"而非"替换自身"，见 §6 决策 D3 | 🔍待验证 |
| G9 | 高分辨率单调时间（计时用，非必须精确） | src/core/ngx_times.c（ngx_monotonic_time） | ticks@100Hz（10ms 分辨率） | nginx 计时缓存粒度本就是 ~10ms 级（timer_resolution 默认），勉强够用；毫秒级 gettimeofday 见 Y9 | ✅可验证 |
| G10 | 协作多任务上下文（nginx 无线程依赖，单进程事件循环即可） | src/event/ngx_event.c 设计前提 | 调度器 + int 0x80 + ELF 加载链路已打通（shell_user.elf 已能跑） | — | ✅可验证 |
| G11 | TCP/IP 协议栈正确性（含窗口/重传/SACK） | 前提条件 | RFC 2018/6675/6298 简化版已在工作区落地并有 QEMU 黑盒套件 | 容量 16 连接是硬顶（§6 D5） | ✅可验证 |

### 3.2 黄色档 —— 缺失但可在现有架构内增量补齐

| # | nginx 依赖 | nginx 参考位置 | Cat-OS 现状 | 补齐方案概要 | 规模 | 状态 |
|---|---|---|---|---|---|---|
| Y1 | **connect()（客户端方向）** | src/os/unix/ngx_connect.c；upstream/proxy/mail 全依赖 | 完全缺失（状态机已预留 TCP_SYN_SENT，net.h:47） | net.c 增加 `net_socket_connect(s,ip,port)`：占 conn→发 SYN→SYN_SENT→等待 SYN-ACK；配合阻塞原语可同步等待 | 中 | 🔍待验证 |
| Y2 | **阻塞/睡眠唤醒原语**（nginx 大量 IO 初期可直接用阻塞 fd，epoll 前的过渡） | POSIX 语义 | PROC_BLOCKED 仅定义无机制（process.h） | PCB 加 wait_queue；sleep_on(event)/wakeup(event)；IRQ/tick 路径触发唤醒；sched_yield 改造为可睡眠 | 中 | 🔍待验证 |
| Y3 | **waitpid 收割**（master 必须 reap worker，防僵尸） | src/os/unix/ngx_process.c（ngx_wait_get→waitpid） | sys_wait stub 恒 -ECHILD；PCB 无 exit_status、无父子关系字段 | PCB 加 parent_pid/exit_status/children 链；exit 时记录；wait 扫描收割 | 小-中 | 🔍待验证 |
| Y4 | **内核堆分配器 kmalloc/free** | （内核侧支撑，nginx 用户态用 malloc） | 无堆（§2.4） | free-list/buddy 二选一，基于 pmm_alloc_page；先服务内核（exec 动态缓冲、fd 表扩容、页目录创建） | 小-中 | 🔍待验证 |
| Y5 | **独立页目录创建 API**（进程隔离前提，亦是 Y6/fork 前置） | mm/ 概念对照 linux-ref | map_page 只写全局目录（paging.c:302）；trampoline 已支持切 cr3（process.c） | 新增 `pgdir_create()/pgdir_switch()/pgdir_destroy()`：复制内核高半区 PDE（0xC0000000+）+ 清空低半区 | 中 | 🔍待验证 |
| Y6 | nanosleep/clock_nanosleep | src/os/unix/ngx_process_cycle.c（sleep 节流）等 | ticks 可用，无 syscall | nr 新增 nanosleep：阻塞原语 + tick 到期唤醒 | 小（依赖 Y2） | 🔍待验证 |
| Y7 | gettimeofday/clock_gettime（日志时间戳、$time_local） | src/core/ngx_times.c（ngx_time_update→gettimeofday） | RTC 墙钟（秒级）+ ticks（10ms），未合成暴露 | 合成 epoch（RTC 开机校准 + ticks 累加）暴露 syscall | 小 | 🔍待验证 |
| Y8 | fcntl(F_SETFL/F_GETFL, O_NONBLOCK/FD_CLOEXEC) | src/os/unix/ngx_socket.c（ngx_nonblocking） | flags 字段存在（file_t.flags）但不生效；socket 天生非阻塞 | file_t.flags 存取 + nr=fcntl；O_NONBLOCK 对 socket 可 no-op 成功（本来就非阻塞） | 小 | 🔍待验证 |
| Y9 | setsockopt/getsockopt（SO_REUSEADDR、TCP_NODELAY、SO_SNDBUF…） | src/http/ngx_http_upstream.c 等大量调用 | 完全缺失 | 先做白名单 no-op/直译：SO_REUSEADDR→net.c bind 冲突检查放宽开关；TCP_NODELAY→栈本就按段即时发送，no-op；其余 -ENOPROTOOPT | 小起 | 🔍待验证 |
| Y10 | shutdown(SHUT_WR/SHUT_RD) 半关闭 | src/os/unix/ngx_shutdown.c（keepalive/优雅关闭用） | 只有全关（tcp_close 发 FIN，net.c:971） | SHUT_WR→发 FIN 转 FIN_WAIT_1 保持读方向（栈已有这两态，net.h enum） | 小-中 | 🔍待验证 |
| Y11 | **只读文件系统 + stat/lseek/opendir 增强**（nginx.conf、html 根、错误日志、mime.types 全靠它） | src/core/ngx_conf_file.c（ngx_conf_parse 逐行读）、ngx_files.c | devfs 无常规文件；ide_read_sectors 可用（ide.h:4） | **romfs/FAT 只读**挂 IDE：inode→VFS_REG 接入 vfs_open/read/lseek/stat；opendir/readdir 供 include glob | 中-大 | 🔍待验证 |
| Y12 | writev（响应头+体合并发送） | src/os/unix/ngx_writev_chain.c | 无 syscall | nr 新增 writev(iovec)；或 shim 层拼接缓冲（性能损失可接受起步） | 小 | 🔍待验证 |
| Y13 | **fd 容量与 fd 生命周期加固**（nginx worker 默认 rlimit_nofile 1024/65536） | src/core/ngx_cycle.c（setrlimit 后继承） | VFS_MAX_FD=32（vfs.h:4）；CLOSED 型 socket 关闭有滞留窗口（SOCKET_API.md §3.6） | fds[] 改动态分配（依赖 Y4），扩到 ≥1024；修 net_socket_close CLOSED 型幂等释放 | 中 | 🔍待验证 |

### 3.3 红色档 —— 需要重大架构变更（当前设计下不可达）

| # | nginx 依赖 | nginx 参考位置 | 为什么现有架构做不到 | 变更需求 | 状态 |
|---|---|---|---|---|---|
| R1 | **fork()（master→worker 模型的根基）** | src/os/unix/ngx_process.c（ngx_spawn_process→fork）；ngx_process_cycle.c | ① 无 per-process 页目录（R2 前置）；② 无 COW/demand paging，急切复制整个 768MB 直映射不现实；③ PCB 无父子语义 | 页目录创建（Y5）+ 写时复制或缺页分配式 fork，或降级方案 vfork 式"spawn 共享只读镜像"（放弃 COW，接受内存翻倍） | ⛔→🔴（有降级路径） |
| R2 | mmap/munmap（匿名私有：nginx allocator 对大块分配走 mmap；加载共享对象等） | src/os/unix/ngx_shmem.c（MAP_ANON 分支）、src/core/ngx_slab_allocator.c 所在 zone 机制 | 无 per-process 地址空间管理器，map_page 是内核特权手工接口 | 用户态虚拟内存管理器（vm_map 结构 + 缺页处理程序；当前无 page fault handler——interrupts.c 未注册 #PF 处理逻辑） | ⛔ |
| R3 | **shm_open/MAP_SHARED 共享内存**（sharezone：限速 zone、cache、SSL session cache、历史 accept_mutex） | src/os/unix/ngx_shmem.c（ngx_shm_alloc） | MAP_SHARED 跨进程一致性要求同一物理页映射进多目录——单目录架构无从谈起；无 page fault 也做不了按需 | 依赖 Y5+R2 之后才能做"多目录同物理帧"；若只用最小 HTTP（无 proxy cache/limit_req zone）可整体回避 | ⛔（最小场景可回避） |
| R4 | **epoll/select/poll 就绪通知机制**（nginx 事件引擎的心脏，--with-select_module 最小 fallback 也需要 select 语义） | src/event/modules/ngx_epoll_module.c（默认 Linux）、ngx_select_module.c、ngx_poll_module.c；src/event/ngx_event_timer.c | 当前唯一的"异步"是 100Hz tick 里全员轮询 net_poll()（interrupts.c:23）；没有 fd→等待者注册表，没有"某 fd 可读"→"唤醒某进程"的通路；且 select/poll 需要先有 Y2 睡眠原语 | 内核事件子系统：① socket 层状态变化打就绪标记；② fd 注册表 + 睡眠队列；③ select(nr) 阻塞至任一 fd 就绪或超时。**这是移植 nginx 前最大的单体工程** | ⛔ |
| R5 | **signal 框架**（SIGHUP 重载/SIGUSR1 日志切割/SIGTERM-SIGQUIT 停机/SIGCHLD 收割；master 主循环靠 sigsuspend 等信号） | src/os/unix/ngx_process.c（ngx_signal_handler、signal 表）、ngx_process_cycle.c（ngx_sigsuspend） | 全内核无任何 signal 概念（grep 零命中）；int 0x80 ABI 无信号投递通路；进程无 handler 概念 | PCB 加 pending/mask/handlers；中断上下文向目标进程投递；ring3 trampoline 或 syscall 返回路径检查 pending。**最小化替代**：阶段 3 先做内核侧伪信号（仅 SIGCHLD/SIGTERM 三个固定语义，无用户 handler），nginx shim 层翻译 | ⛔（有最小化路径） |
| R6 | sendfile(2) 零拷贝发送 | src/os/unix/ngx_linux_sendfile_chain.c | 需要页缓存/page cache 概念（无 fs 更无 cache） | **官方逃生门：nginx 编译期 `--without-sendfile`**（auto/options 提供该开关），退化为 read+writev 链。故 R6 实为"性能项"而非"功能项" | ⛔（可禁用绕过） |
| R7 | socketpair + sendmsg/recvmsg(SCM_RIGHTS)（master↔worker channel，传监听 fd 与命令） | src/os/unix/ngx_channel.c、ngx_process_cycle.c | AF_UNIX 域不存在；无 ancillary 数据机制 | AF_UNIX socketpair（内核内存队列即可，无需真正协议栈）+ fd 跨进程转移（fd 表按进程分离之后才有意义）。**降级**：单 master 单 worker 且 worker 由 master spawn 时，listen fd 天然继承，channel 可先桩化 | ⛔（有桩化路径） |
| R8 | daemon()/setsid（后台化） | src/core/ngx_cycle.c（ngx_daemon） | 无会话/进程组概念 | 低价值：QEMU 环境前台跑即可，shim 层 no-op 返回 0 | ⛔（可 no-op 绕过） |
| R9 | setrlimit/getrlimit(RLIMIT_NOFILE/CORE)、getrusage | src/core/ngx_cycle.c、src/os/unix/ngx_process_cycle.c（worker rlimit） | 无 rlimit 体系 | shim 层返回固定值（nofile=当前 fd 表容量）；getrusage 返回静态合理值 | ⛔（可桩化绕过） |
| R10 | getpwnam/getgrnam/setuid/setgid（user directive 降权） | src/os/unix/ngx_user.c | 无用户体系 | 配置去掉 user 指令或 shim 返回固定 uid=0 | ⛔（可配置绕过） |

### 3.4 明确不在差距清单内的说明（避免臆造）

- **kqueue/inotify/eventport/AIO**：非 Linux 必需路径，nginx configure 会自动裁剪，无需关注。
- **线程/pthread**：nginx 默认构建不含线程池（thread pool 仅用于文件 IO offload，可选），多进程模型下无 pthread 依赖。
- **crypt()**：仅 auth_basic 使用；最小 HTTP 服务与静态站点场景可回避（nginx 编译期无 crypt 也能过，auth_basic 功能受限）。

---

## 4. 三档分级汇总

```
绿色 已满足        11 项 ── G1-G11（其中 G4 需先裁决 nr==3 别名、G8 语义偏差见 §6-D3）
黄色 易补          13 项 ── Y1-Y13（合计约为 2-4 个并行 milestone 的量）
红色 重大架构变更  10 项 ── R1-R10（其中 R6/R8/R9/R10 有官方开关或桩化逃生门，
                            R1/R3/R4/R5/R7 是真正的硬骨头）
```

**结论**：nginx "能不能跑起来"的分水岭在 **R4（事件就绪通知）+ R1（fork/spawn）+ Y11（文件系统）+ R5-min（信号子集）** 四件事上。四者齐备前，任何"直接移植"的尝试都会卡死在 configure/编译期或首启的 ngx_init_cycle。

---

## 5. 分阶段移植路线图

> 排序原则：每阶段产出**独立可验证的里程碑**；阶段 2 可与阶段 1 部分并行（minimal httpd 几乎不被黄档阻塞，详见 MINIMAL_HTTPD_DESIGN.md §2）。

### 阶段 1 —— 基础设施补课（预计 3-5 个 milestone）

| 工作项 | 对应档位 | 验收标准 |
|---|---|---|
| 1a. M2 收尾：废除底层裸 -1 哨兵，sock_xlate 直通区分性 errno | G6 | ext_socktest.py 全绿 + ring3 断言骨架（SEMANTICS_CURRENT=0 目标语义）PASS |
| 1b. L1/H2 修复：listen 自动绑定、bind 冲突报 -EADDRINUSE | G1 | 骨架 H2/L1 探针 PASS |
| 1c. kmalloc 堆分配器 | Y4 | 内核内压测：分配/释放万次无碎片失控、无重叠 |
| 1d. 睡眠唤醒原语（PROC_BLOCKED 实装） | Y2 | 双进程 ping-pong 通过管道式标志位互醒 1000 次 |
| 1e. waitpid + PCB 父子关系/exit_status | Y3 | shell 依次 exec 两个子进程并收割退出码 |
| 1f. pgdir_create/switch/destroy（独立地址空间） | Y5 | 两进程同名地址 0x400000 各写各值互不串扰 |
| 1g. connect() 主动开放 | Y1 | ring3 客户端连宿主机 python http server 完成 GET |
| 1h. nanosleep + gettimeofday 合成 | Y6/Y7 | sleep(1) 实测误差 <20ms；时间戳与宿主机 diff <1s |
| 1i. romfs（或 FAT 只读）挂载 IDE | Y11 | mount 后 open("/etc/nginx.conf") 可整读 |
| 1j. fd 表动态扩容至 ≥256 | Y13 | 并发打开 200 fd 无 EMFILE |

### 阶段 2 —— 最小 HTTP 服务（可与 1c 之后任意时点并行，详见 MINIMAL_HTTPD_DESIGN.md）

- **目标**：ring3 单进程 httpd，`accept → recv → 解析请求行 → 静态响应（romfs 文件或内嵌页面）→ send → close` 循环。
- **为什么先做它**：① 当前 ABI 即可支撑骨架（绿档 G1/G2/G3/G4 全覆盖）；② 为阶段 3 的事件框架提供**真实负载发生器**和回归基准；③ 它本身就是 nginx 移植后的对照组（功能/行为基线）。
- **验收**：宿主机 `curl http://localhost:18080/` 返回 200 与预期正文；并发 2 连接顺序服务正常；QEMU 套件纳入 CI。

### 阶段 3 —— 事件框架 + 多进程雏形（预计最大工程量，2-4 个大 milestone）

| 工作项 | 对应档位 | 说明 |
|---|---|---|
| 3a. 内核事件子系统：socket 状态变化→就绪标记→fd 注册表→`poll()` 语义 syscall（阻塞至就绪/超时） | R4 | **先 poll 后 select 后 epoll 语义**：poll 参数模型最简单，epoll 三件套（create/ctl/wait）在其上加一层即可；nginx configure 用 `--with-poll_module` 即可对接第一步成果 |
| 3b. spawn/fork：优先 vfork 式"克隆地址空间句柄 + CoW 缺页"或"急切复制低半区页表"（用户空间小则可行） | R1/Y5 | 决策点 D1（§6） |
| 3c. 信号最小集：SIGCHLD（收割联动 waitpid）/SIGTERM/SIGQUIT/SIGHUP 固定语义，暂不支持自定义 handler | R5-min | nginx master 逻辑 shim 层改写为轮询式查 pending 位图 |
| 3d. AF_UNIX socketpair（无 SCM_RIGHTS，channel 桩化） | R7-min | master→worker 传"请退出"用共享标志位替代 |
| 3e. fcntl/setsockopt/writev/shutdown 最小集 | Y8/Y9/Y12/Y10 | 白名单实现 |
| 3f. **里程碑验收：nginx configure 通过 + 首次以单 worker、poll 模块、--without-sendfile 启动，curl 取回静态页** |

### 阶段 4 —— 完整移植打磨

| 工作项 | 对应档位 |
|---|---|
| 4a. epoll 三件套语义（ngx_epoll_module 对接） | R4 完全体 |
| 4b. 真 fork/COW 或确认急切复制方案长期可用 | R1 定案 |
| 4c. MAP_SHARED 共享内存（仅当需要 limit_req/cache zone 时） | R3 |
| 4d. sendfile（若届时已有 page cache）或永久 --without-sendfile | R6 |
| 4e. rlimit/daemon/user 桩完善、平滑升级（SIGUSR2+execve 链路）或明确裁剪 | R8/R9/R10 |
| 4f. 性能与容量：TCP 连接表 16→≥1024、缓冲 4096→64KB 级、window scale 复核 | §6 D5 |

---

## 6. 关键风险与架构决策点

| # | 决策点 | 备选与建议 |
|---|---|---|
| D1 | fork 实现：COW vs 急切复制 vs vfork 式共享 | 用户空间目前上限 ~768MB 且急切映射；**建议先急切复制低半区页表**（页表本身仅 KB 级，数据页共享只读、写时再断 COW 可以后补），避免一步到位 COW 的复杂度 |
| D2 | 事件框架起点：poll vs select vs 直接 epoll | 建议 **poll 语义先行**（参数扁平、内核实现最简），nginx 侧 `--with-poll_module`；epoll 作为阶段 4 增强 |
| D3 | exec 语义偏差 | Cat-OS exec=新建进程返回 pid，Unix execve=替换自身不返回。nginx upgrade 路径用到后者；shim 层以"exit+spawn"模拟或明确裁剪平滑升级特性 |
| D4 | nr==3 close 别名（L8） | **必须在任何 Linux ABI 兼容代码进入前移除**，否则 read(fd=3) 会静默关 fd——这是移植路上最阴险的地雷 |
| D5 | 网络栈容量天花板 | TCP_MAX_CONNS=16 / 缓冲 4KB / backlog≤16（net.h:67-71）与 nginx 默认 worker_connections 1024 相差两个数量级；阶段 2 的 minimal httpd 就会感受到（并发 >16 即 RST，net.c:714） |
| D6 | 32 位地址空间 | i686 4GB/进程上限对 nginx worker 通常够用（每个连接 ~几十KB 级），但连接数上千时 4KB 收发缓冲×2×N 的内核侧占用需重新规划缓冲策略 |
| D7 | 时间精度 | 100Hz tick 对 nginx 计时够用，但对 RTO/keepalive_timeout 亚 10ms 粒度不足；引入 TSC 或 PIT 重编程留待阶段 3+ |

---

## 7. 与既有缺口编号体系的映射

| 缺口编号（出处 /tmp/cat-os-tests/README.md 及 docs/SOCKET_API.md §6） | 与本移植的关系 |
|---|---|
| H2（TCP bind 同端口"附着"返回 0） | 阻碍 nginx 的 SO_REUSEADDR 语义判断；阶段 1b 必修 |
| M2（错误码混叠） | nginx 高度依赖 errno 区分性（EAGAIN 驱动事件循环）；阶段 1a 必修 |
| L1（listen-before-bind -EINVAL） | nginx 标准 socket 初始化序列恰好是 socket→setsockopt(REUSEADDR)→**bind**→listen，多数情况先 bind，但 nginx 对部分 listen 项支持省略 address（隐式 autobind）；阶段 1b 一并修复 |
| C7（UDP 无监听静默丢弃，无 ICMP unreachable） | 影响 nginx resolver 判错速度；非阻塞项，登记观察 |
| D1/H2Q（附着后双 listener accept 归属） | 同 H2，阶段 1b 回归范围 |
| M1/M3/M4（编号已登记、主题待核实） | 待编号定义方补充后映射 |

---

## 8. NOT_TESTED 清单

| # | 条目 | 状态 |
|---|---|---|
| N1 | 本文全部 Cat-OS 行为条目均为**静态读码结论**（本任务零编译零运行），行号以工作区为准 | NOT_TESTED |
| N2 | nginx 侧引用为 1.26.x 布局的文件/函数名，**未经本地源码树核对**；行号一律未给出即为刻意留空 | 🔍待验证（取得源码后回填 §3 表格） |
| N3 | 阶段划分的工作量估计（milestone 数）为经验值 | 🔍待验证 |
| N4 | "minimal httpd 可跑在当前 ABI"这一论断的运行时证明 → 由 MINIMAL_HTTPD_DESIGN.md 的实施来闭环 | 🔍待验证 |

---

*文档结束。生成者：Cat-OS 并行任务 code3（nginx 移植预研）。约束遵守声明：本任务仅新建 `docs/NGINX_PORT_ANALYSIS.md` 与 `docs/MINIMAL_HTTPD_DESIGN.md` 两个文件；未修改任何 `.c/.h/.md` 既有文件；未触碰 usermode.c / OSDEV_PROJECT_NOTES.md / NEXT_TASKS_AUTONOMOUS.md；未执行 push/reset/rebase/delete。*
