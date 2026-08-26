# 《nginx 移植缺口清单与阶段路线》

> **生成日期**：2026-08-25  
> **来源**：planner 只读架构分析（基于 opencode agent log）  
> **基于**：HEAD 81514fc 前的工作区状态

---

## 1. syscall 缺口：nginx 最小集 vs 现有 ABI 逐项对照

| # | nginx 依赖系统调用 | nginx 代码位置（参考 1.26.x） | Cat-OS 现有编号/实现 | 状态 | 证据与替代方案 |
|---|---|---|---|---|---|
| S1 | `socket(AF_INET,SOCK_STREAM)` | `ngx_socket.c` | **nr=20** `CATOS_SYS_SOCKET` | ✅已有 | `syscall.c:260-264`；仅 `type` 参数，无 domain/protocol |
| S2 | `bind(fd, addr, addrlen)` | `ngx_socket.c` | **nr=21** `CATOS_SYS_BIND` | ✅已有/受限 | `syscall.c:270`：house ABI 仅 `(fd,port)`，无 sockaddr 结构；`port==0 → -EINVAL`（无自动端口分配）`net.c:511-518` |
| S3 | `listen(fd, backlog)` | `ngx_accept.c` | **nr=22** `CATOS_SYS_LISTEN` | ⚠️黄（L1） | `syscall.c:280-284`：未 bind 先 listen → `-EINVAL`（L1 缺口）；`backlog>16` 截断 `net.c:553-559` |
| S4 | `accept4/accept` | `ngx_accept.c` | **nr=23** `CATOS_SYS_ACCEPT` | ✅已有/受限 | `syscall.c:289`：非阻塞原生（空队列 `-EAGAIN`）；**不返回对端地址**（五寄存器限制）`net.c:919-933` 仅内核内路径 |
| S5 | `connect(fd, addr, addrlen)` | `ngx_connect.c`、upstream 全系 | **无编号** | ⛔缺失 | `net.h:107-118` 无声明；`TCP_SYN_SENT` 仅枚举预留 `net.h:62-65`；需新增 nr + `net_socket_connect` |
| S6 | `send/recv` (TCP) | `ngx_send.c`、`ngx_recv.c` | **nr=26/27** | ✅已有 | `syscall.c:334-354`：部分写语义、EOF=0、`-EAGAIN`、`-ENOTCONN`；**`send` 缓冲满可返回 0 歧义** `net.c:938-940` `syscall.c:341` |
| S7 | `sendto/recvfrom` (UDP) | resolver、mail | **nr=24/25** | ✅已有/受限 | `syscall.c:298-330`：出参不可省略（严于 Linux）；UDP 未 bind 发送 `-EADDRNOTAVAIL` |
| S8 | `write/read` (文件/日志) | `ngx_files.c` | **nr=1/0** | ✅已有 | `vfs.c:68`：仅 `/dev/*` 设备文件；**无常规文件系统**（见 §3） |
| S9 | `writev` | `ngx_writev_chain.c` | **无编号** | ⛔缺失 | 可 shim：用户态拼接单缓冲 `send`（首响应 ≤MSS 无损） |
| S10 | `readv` | 较少用 | **无编号** | ⛔缺失 | 暂不需，nginx 读端未用 readv |
| S11 | `select/poll/epoll` | `ngx_select_module.c`、`ngx_poll_module.c`、`ngx_epoll_module.c` | **无编号** | ⛔缺失（R4） | **最大单体工程**：当前仅 100Hz tick 全员轮询 `net_poll()` `interrupts.c:23`；需内核事件子系统 + `poll()` 语义 syscall（建议先 poll 后 epoll） |
| S12 | `dup/dup2` | `ngx_process.c` 重定向 | **无编号** | ⛔缺失 | fd 表共享同一分配器 `vfs.c:29-33`；可实现 `dup2` 逻辑（关闭目标 fd → 安装同 file_t） |
| S13 | `fcntl(fd, F_GETFL/SETFL, O_NONBLOCK)` | `ngx_nonblocking` | **无编号** | 🟡黄（Y8） | `file_t.flags` 字段存在 `vfs.h:14` 但不生效；socket 天生非阻塞，可 no-op 成功 |
| S14 | `ioctl` | 少用 | **无编号** | ⛔缺失 | 可 no-op 或 `-ENOTTY` |
| S15 | `fstat/stat` | `ngx_files.c`、配置解析 | **无编号** | ⛔缺失 | 依赖文件系统（见 §3 Y11 romfs） |
| S16 | `gettimeofday/clock_gettime` | `ngx_times.c` | **无编号** | 🟡黄（Y7） | RTC 秒级 + ticks 10ms `interrupts.c:11,23`；合成 epoch 暴露 syscall 即可 |
| S17 | `nanosleep/clock_nanosleep` | `ngx_process_cycle.c` | **无编号** | 🟡黄（Y6） | 依赖睡眠原语 Y2（`PROC_BLOCKED` 仅定义 `process.h:23`） |
| S18 | `fork` | `ngx_spawn_process` | **无编号** | ⛔缺失（R1） | 依赖独立页目录 Y5 + COW/急切复制；或降级 vfork 式 spawn 共享只读镜像 |
| S19 | `wait4/waitpid` | `ngx_wait_get` | **nr=13** `CATOS_SYS_WAIT` | 🟡黄（Y3） | `syscall.c:226-230` **stub 恒 `-ECHILD`**；PCB 无 `exit_status`/父子关系字段 `process.h:39-50` |
| S20 | `execve` 变体 | `ngx_execute_proc` | **nr=11** `CATOS_SYS_EXEC` | ⚠️语义偏差 | `syscall.c:157-207`：Cat-OS exec = **新建进程返回 pid**，非替换自身；nginx upgrade 路径需 shim 模拟 `exit+spawn` |
| S21 | `mmap/munmap` (MAP_ANON) | `ngx_shmem.c`、slab allocator | **无编号** | ⛔缺失（R2） | 无 per-process 地址空间管理器；`map_page` 只写全局目录 `paging.c:302`；无 #PF handler `interrupts.c:31` |
| S22 | `shm_open/MAP_SHARED` | `ngx_shmem.c` (sharezone) | **无编号** | ⛔缺失（R3） | 依赖 R2+Y5 多目录同物理帧；最小场景（无 proxy cache/limit_req zone）可整体回避 |
| S23 | `setsockopt/getsockopt` | `SO_REUSEADDR`、`TCP_NODELAY`、缓冲调优 | **无编号** | 🟡黄（Y9） | 白名单 no-op：`SO_REUSEADDR`→bind 冲突检查放宽；`TCP_NODELAY`→栈即时发送 no-op |
| S24 | `shutdown(fd, SHUT_WR/RD)` | `ngx_shutdown.c` keepalive | **无编号** | 🟡黄（Y10） | 栈已有 FIN_WAIT/LAST_ACK 状态 `net.h:61-65`；仅需发 FIN 保持读方向 |
| S25 | `close` (socket-aware) | 通用 | **nr=28** `CATOS_SYS_CLOSE` | ✅已有/陷阱 | **唯一 socket 关闭路径** `syscall.c:377`；**⚠️ nr==3 是 close 别名（L8）**：Linux `nr=3=read`，按 Linux ABI 写的 `read(fd=3)` 会**静默关 fd** `syscall.c:367-370` `vfs.c:86-90` —— **移植前必裁决移除** |
| S26 | `unlink/rename` | 日志切割、临时文件 | **无编号** | ⛔缺失 | 依赖可写文件系统（devfs 只读） |
| S27 | `getpeername/getsockname` | `$remote_addr`、access log | **无编号** | ⛔缺失 | accept 无对端地址出参；底层 `tcp_accept(s,&ip,&port)` 有能力 `net.c:919-933`，需新增 nr 或复用 |
| S28 | `kill/signals` (SIGHUP/TERM/CHLD) | `ngx_signal_handler` | **无编号** | ⛔缺失（R5） | 全内核无 signal 概念 `grep signal *.c *.h → 空`；最小化替代：内核侧伪信号（仅固定语义）+ shim 轮询 pending 位图 |
| S29 | `setpgid/setsid/daemon` | `ngx_daemon` | **无编号** | ⛔缺失（R8） | 无会话/进程组概念；QEMU 前台跑即可，shim no-op 返回 0 |
| S30 | `setrlimit/getrlimit` (RLIMIT_NOFILE) | `ngx_cycle.c` | **无编号** | ⛔缺失（R9） | shim 返回固定值（nofile=当前 fd 表容量 32） |
| S31 | `getuid/setuid/getpwnam` | `ngx_user.c` | **无编号** | ⛔缺失（R10） | 无用户体系；配置去掉 `user` 指令或 shim 返回 uid=0 |

---

## 2. libc 缺口：nginx 必需函数 vs 现有 libc/

| 现有 libc 函数（include/ 头为准） | 状态 | nginx 依赖点 | 备注 |
|---|---|---|---|
| `memset/memcpy/memmove/strlen/strcmp/strncmp/strcpy/strcat` (`string.h:28-38`) | ✅已有 | 通用解析/拷贝 | 纯实现，无 syscall |
| `malloc/free` (`stdlib.h:26-30`) | ✅已有/受限 | nginx pool allocator 可替代 | **64KB 静态池** `stdlib.c:32`；nginx 自带 slab/pool 分配器（`ngx_palloc`），**不依赖 libc malloc** |
| `exit` (`stdlib.h:35`) | ✅已有 | worker 退出 | nr=12 `CATOS_SYS_EXIT` |
| `write/putchar/puts/printf` (`stdio.h:37-50`) | ✅已有 | 错误日志、access log | 仅 fd=1 `/dev/console`；**无文件落盘**（需 Y11 romfs） |
| `va_list/va_start/va_arg/va_end` (`stdio.h:28-32`) | ✅已有 | printf 变参 | GCC 内建 |

| nginx 必需且**缺失**的 libc 函数 | 优先级 | 说明 |
|---|---|---|
| `memcmp` | 必须 | 配置解析、字符串比较 |
| `strchr/strrchr/strstr/strnstr` | 必须 | 请求行/头部解析、URI 匹配 |
| `strtol/strtoul/atoi` | 必须 | 端口号、Content-Length 解析 |
| `memcpy` 重叠安全已有 `memmove` | — | |
| `snprintf/vsnprintf` | 必须 | 头部生成、错误页格式化 |
| `time/localtime/gmtime/strftime` | 必须 | `$time_local`、Date 头、Last-Modified | 依赖 Y7 gettimeofday |
| `open/read/write/close/lseek` (文件 fd 版) | 必须 | 静态文件服务、nginx.conf 读取 | 依赖 Y11 romfs + VFS_REG |
| `opendir/readdir/closedir` | 必须 | `include` glob、目录索引 | 依赖 Y11 romfs 目录项 |
| `fcntl` (O_NONBLOCK/FD_CLOEXEC) | 必须 | socket 非阻塞、exec 后 fd 继承控制 | 依赖 Y8 内核 fcntl syscall |
| `poll/select/epoll` 封装 | 必须 | 事件引擎核心 | 依赖 R4 内核 poll syscall |
| `fork/vfork/execve/waitpid` 封装 | 必须 | master/worker 模型 | 依赖 R1/R18/R19 内核 syscall |
| `signal/sigaction/sigsuspend` | 必须 | master 信号处理 | 依赖 R28 信号框架 |
| `pthread_*` | 可裁剪 | nginx 默认**不启用线程池**（`--without-threads` 可过 configure） | 多进程模型下无 pthread 硬依赖 |
| `crypt` | 可裁剪 | 仅 `auth_basic` 使用 | 最小 HTTP 服务可回避 |
| `dlopen/dlsym` | 可裁剪 | 动态模块加载 | 静态编译 nginx 可完全回避 |

**结论**：nginx 核心**不依赖 libc malloc/free**（自带 pool/slab），现有 `string.h` `stdlib.h` `stdio.h` 基本覆盖字符串/内存/退出/控制台输出。**真正缺口集中在文件 I/O、时间、目录、事件循环、进程控制封装**——均对应内核 syscall 缺口。

---

## 3. 内核机制缺口

| 机制 | 现状 | 缺口评估 | 建议 |
|---|---|---|---|
| **COW fork / 进程地址空间隔离** | 并行开发中（任务书声称 "COW fork 正在并行开发"） | **关键前置 R1/R2/Y5**<br>- `paging.c:15` 单一全局 `kernel_page_directory` 静态实例<br>- `map_page` 仅写此目录 `paging.c:302-306`<br>- `process_trampoline` 已支持 `cr3` 切换 `process.c:136-138`（硬件通路在）<br>- **无 `pgdir_create/switch/destroy` API**<br>- **无 kmalloc/内核堆** `grep malloc/kmalloc *.c *.h → 空` | **按"将有"评估**：<br>1. 先补 `kmalloc`（Y4，服务页目录创建、fd 表扩容）<br>2. 再暴露 `pgdir_create()` 复制内核高半区 PDE（0xC0000000+）+ 清空低半区<br>3. fork 两条路：<br>   - **急切复制低半区页表**（用户空间小、页表仅 KB 级，可接受）<br>   - **vfork 式 spawn 共享只读镜像**（放弃 COW，接受内存翻倍，先跑通 nginx worker 模型）<br>4. COW 缺页分配留待阶段 4 优化 |
| **文件系统** | IDE PIO 磁盘已有（`ide.h:4` `ide.c rw()`），**无任何文件系统挂载** `vfs.c:20` 仅 devfs 5 节点 | nginx 需：`nginx.conf`、`mime.types`、静态 HTML、错误日志、access log | **建议先上 tar/romfs 只读镜像**：<br>- romfs 结构极简、只读、无写放大风险、镜像离线生成（`tools/mkromfs.py`）<br>- FAT 只读留作备选（实现量更大）<br>- 可写文件系统（ext2/FAT RW）留待阶段 4（日志落盘、nginx 热重载写 pid 文件） |
| **fd 继承 / close-on-exec** | fd 表共享同一 `fds[]` `vfs.c:14` `vfs.h:4`；`vfs_close` 拒收 socket `vfs.c:72`；**无 FD_CLOEXEC 标志**、**无进程隔离 fd 表**（单进程模型下未暴露） | fork 后子进程需继承 listen fd、关闭其余；exec 后自动关闭 CLOEXEC fd | 依赖：<br>1. 进程隔离 fd 表（每进程独立 `fds[]`，现为全局静态）<br>2. `file_t.flags` 加 `FD_CLOEXEC` 位<br>3. `exec` 路径扫描关闭 CLOEXEC fd<br>4. `fork` 复制 fd 表引用计数 |
| **wait/waitpid** | `nr=13` stub 恒 `-ECHILD` `syscall.c:226-230` | master 必须收割 worker 防僵尸 | PCB 增加 `parent_pid` `exit_status` `children` 链表；`exit_process` 记录退出码并唤醒父进程；`wait` 扫描收割 |
| **进程组 / 会话 / setsid** | 无 | `daemon()`、worker 进程组管理、终端信号传递 | 最小场景可回避（QEMU 前台）；阶段 4 补最小集：`setsid` 仅置 `pgrp=pid`，`kill(-pgid, sig)` 广播 |

---

## 4. 阶段路线

### M0 —— 最小 httpd 单进程阻塞循环（当前 ABI 能否跑通？）

**结论：✅ 可跑通骨架**，仅受限于**静态内容来源**与**accept 忙等**。

| 所需最小改动清单 | 文件/行号 | 说明 |
|---|---|---|
| 1. 编写 `apps/httpd.c` + `apps/sock.h`（内联 int 0x80 封装） | 新文件 | `MINIMAL_HTTPD_DESIGN.md §4.1` `sock.h` 模板；`ngx_accept` 语义对齐 `syscall.c:289` |
| 2. 静态内容 L0 内嵌镜像（`.rodata` 页面） | `apps/httpd.c` | `MINIMAL_HTTPD_DESIGN.md §6 L0`；`xxd -i` 注入，先例 `syscall.c:144 shell_bin.h` |
| 3. accept 忙等策略 C（空循环或读 `/dev/zero` 软化） | `apps/httpd.c` | **无 ring3 yield/nanosleep syscall**（新缺口 Y6'，`MINIMAL_HTTPD_DESIGN.md §4.2`）；QEMU 单核无害 |
| 4. 监听端口 **:7000**（避开内核演示 :80/:81 与测试 hostfwd） | `apps/httpd.c:68` | `NGINX_PORT_PLAN.md §3` 端口规划表；`net.c:1069-1079` 内核占用 :80/:81 |
| 5. `Makefile` 追加 `httpd.elf/bin/bin.h` 目标族（仿 shell 三件套） | `Makefile` | 低冲突并行；`NGINX_PORT_PLAN.md §5.2` |
| 6. 测试用例 `tests/http_suite.py`（blackbox） | 新文件 | `MINIMAL_HTTPD_DESIGN.md §8 A1-A7` |

**验收标准**（同 `MINIMAL_HTTPD_DESIGN.md §8`）：
- `curl http://127.0.0.1:18080/` 返回 200 + 内嵌正文（hostfwd 18080→guest:80 已就绪，但 httpd 监听 :7000 需追加 hostfwd 或手工 QEMU）
- 10 串行请求全成功、无 fd 泄漏
- 404/400/405 正确
- ≥8KB 响应完整传输（跨多次 `tcp_send` 分片验证发送游标）
- 1000 请求长稳无 panic

---

### M1 —— 多 worker fork（master/worker 模型雏形）

| 前置依赖 | 关键实施项 | 验收标准 |
|---|---|---|
| Y4 kmalloc（内核堆） | `pgdir_create/switch/destroy` (Y5) | 两进程同名地址 0x400000 各写各值互不串扰 |
| Y2 睡眠/唤醒原语（`PROC_BLOCKED` 实装） | fork 实现：优先**急切复制低半区页表**（用户空间小、页表 KB 级，可接受）或 **vfork 式共享只读镜像** | `shell` 依次 exec 两子进程并收割退出码（waitpid 工作） |
| Y3 waitpid + PCB 父子关系 + exit_status | `exit_process` 记录退出码；`wait` 扫描收割 | master fork 2 worker，master 收到 SIGCHLD 能 waitpid 回收 |
| R5-min 信号最小集（SIGCHLD/SIGTERM/SIGQUIT/SIGHUP 固定语义，无自定义 handler） | PCB 加 `pending/mask` 位图；中断上下文投递；ring3 trampoline 或 syscall 返回检查 pending | nginx shim 层轮询 pending 位图模拟 `sigsuspend` |

**验收**：`nginx -t` 配置测试通过（需 Y11 romfs 读取 nginx.conf）；master 启动 → fork 2 worker → `curl` 请求由 worker 处理 → master `kill -TERM` 优雅关闭。

---

### M2 —— 事件驱动（poll/epoll 就绪通知）

| 前置依赖 | 关键实施项 | 验收标准 |
|---|---|---|
| R4 内核事件子系统（核心工程） | 1. `e1000.c` RX 中断注册 `irq_register_handler` `interrupts.c:20`<br>2. `net_napi_poll(budget)` 预算循环（现为直通包装 `net.c:1065`）<br>3. 新增 `event.c`：fd→就绪位登记表（socket 状态变化打标：rxb 非空→readable；sndb 有余量→writable；ESTAB 入表→listener readable）<br>4. 新增 **nr=31 `poll(fds*, nfds, timeout_ticks)`** `syscall.h/syscall.c` | 1. 串口周期性 `[EVT] napi budget=<n> rx=<m>`<br>2. **并发 4 连接** python asyncio 探针：4 请求处理日志**交错**出现且全部 200（串行版必然顺序阻塞）<br>3. `poll(timeout=0)` 非阻塞语义探针 PASS |
| Y2 睡眠原语（poll 阻塞语义前置） | 骨架期允许忙轮询 `poll(timeout=0)`，阻塞语义后补 | nginx `--with-poll_module` configure 通过 |

**决策点 D2**：建议 **poll 语义先行**（参数扁平、内核实现最简），nginx 侧 `--with-poll_module`；epoll 作为阶段 4 增强。

---

### M3 —— 性能调优（netring/零拷贝/NAPI 对接）

| 优化项 | 依赖 | 说明 |
|---|---|---|
| netring 零拷贝收发 | `netring.h` 已存在 `net.h:5`；`net_napi_poll` 改造后可对接 | 避免 `tcp_send/recv` 拷贝；需 ring3 共享内存映射（依赖 R2 mmap） |
| TCP 连接表 16→≥1024 | `net.h:67 TCP_MAX_CONNS` | 硬约束，nginx 默认 `worker_connections 1024` 差两个数量级 |
| 发送/接收缓冲 4KB→64KB 级 | `net.h:70 TCP_BUF_SIZE` | 慢客户端反压、大响应吞吐 |
| Window Scale / SACK 完善 | 已有 SACK≤2 块 `net.c:329` | 高延迟链路吞吐 |
| sendfile 零拷贝 | R6（需 page cache） | **官方逃生门：`--without-sendfile` 永久禁用**，退化为 read+writev 链 |
| 定时器精度 100Hz→TSC/PIT 重编程 | D7 | RTO/keepalive_timeout 亚 10ms 粒度 |

---

## 5. 风险：硬阻塞项 vs 可 shim 项

| 类别 | 编号 | 项目 | 为什么硬阻塞 / 可如何 shim |
|---|---|---|---|
| **硬阻塞** | R4 | **事件就绪通知机制** | 无此机制 nginx 事件引擎无法工作；必须内核实现 `poll()` 语义，**单体工程量最大** |
| **硬阻塞** | R1/R2/Y5 | **fork + 独立地址空间** | master/worker 模型根基；无 pgdir_create 无法隔离；急切复制页表可降级但需 Y5 先行 |
| **硬阻塞** | Y11 | **只读文件系统** | nginx.conf/mime.types/html/error.log 全靠它；romfs 实现量中等但路径明确 |
| **硬阻塞** | R5-min | **信号最小集** | master 主循环靠 `sigsuspend` 等信号；无信号框架 master 无法优雅关闭/重载 |
| **硬阻塞** | L8 | **nr==3 close 别名** | **按 Linux ABI 写的代码 `read(fd=3)` 会静默关 fd**——这是移植路上最阴险的地雷，必须在任何 Linux ABI 兼容代码进入前移除 `vfs.c:86-90` `syscall.c:367-370` |
| **可 shim** | S5 | `connect` | 仅 upstream/proxy/mail/resolver 需；最小静态站点**完全回避** |
| **可 shim** | S9 | `writev` | 用户态拼接单缓冲 `send`；首响应 ≤MSS(1460) 无损 |
| **可 shim** | S13 | `fcntl(O_NONBLOCK)` | socket 天生非阻塞，no-op 返 0 即可 |
| **可 shim** | S16 | `gettimeofday` | 合成 epoch（RTC 开机校准 + ticks 累加）暴露 syscall，规模小 |
| **可 shim** | S23 | `setsockopt` 白名单 | `SO_REUSEADDR`→bind 冲突检查放宽开关；`TCP_NODELAY`→栈即时发送 no-op；其余 `-ENOPROTOOPT` |
| **可 shim** | S24 | `shutdown(SHUT_WR)` | 栈已有 FIN_WAIT 状态，仅需发 FIN 保持读方向 |
| **可 shim** | S27 | `getpeername` | accept 无对端地址；日志降级记 fd；或新增 nr 透出底层 `tcp_accept(s,&ip,&port)` 能力 |
| **可 shim** | R6 | `sendfile` | **官方开关 `--without-sendfile` 永久禁用**，非功能阻塞 |
| **可 shim** | R7 | `socketpair+SCM_RIGHTS` | 单 master 单 worker 且 worker 由 master spawn 时，listen fd 天然继承；channel 可共享标志位替代 |
| **可 shim** | R8/R9/R10 | `daemon/setrlimit/setuid` | QEMU 前台跑、固定值返回、配置裁剪均可绕过 |

---

## 关键决策点汇总（对应分析文档 D1-D7）

| 决策点 | 建议 | 依据 |
|---|---|---|
| **D1 fork 实现** | **先急切复制低半区页表**（页表 KB 级，数据页共享只读、写时再断 COW 后补） | 避免一步到位 COW 复杂度；用户空间上限 ~768MB 急切映射 |
| **D2 事件框架起点** | **poll 语义先行**（参数扁平、内核最简） | nginx `--with-poll_module` 对接；epoll 阶段 4 增强 |
| **D3 exec 语义偏差** | shim 层以 `exit+spawn` 模拟 `execve` 替换自身；或明确裁剪平滑升级特性 | Cat-OS exec=新建进程返回 pid，Unix execve |

[截断] — 原始日志中 D3 决策点的"依据"列内容不完整（截断于"Unix execve"），以下为日志中保留的原有文字。

---

## 附：证据锚点速查表

| 关键结论 | 文件:行号 |
|---|---|
| 单一全局页目录，无 per-process 地址空间 API | `paging.c:15,302-306` |
| 无内核堆分配器 | `grep malloc/kmalloc *.c *.h → 空` |
| TCP 连接表硬上限 16 | `net.h:67` |
| accept 无对端地址出参 | `syscall.c:289` `net.c:919-933` |
| connect 完全缺失 | `net.h:107-118` 无声明 |
| wait stub 恒 -ECHILD | `syscall.c:226-230` |
| 睡眠原语缺失 | `process.h:23` PROC_BLOCKED 仅定义 |
| nr==3 close 别名（Linux ABI 冲突） | `vfs.c:86-90` `syscall.c:367-370` |
| 错误码混叠（裸 -1 哨兵） | `syscall.c:109-113` `sock_xlate` |
| 100Hz tick 唯一驱动 | `interrupts.c:23,26` |
| fd 表容量 32 共享文件/ socket | `vfs.h:4` `vfs.c:14,29-33` |
| devfs 仅 5 设备节点 | `vfs.c:20` |
| ELF 加载共享内核页目录 | `elf.h:17-19` `syscall.c:196-197` |
| libc 仅 64KB 静态池 | `stdlib.c:32,41` |
| nginx 不依赖 libc malloc | nginx 自带 pool/slab 分配器 |

---

**总结论**：nginx 移植的**四大分水岭**（按依赖拓扑序）：
1. **Y11 romfs 只读文件系统**（配置/静态内容前置）
2. **R4 事件就绪通知 + poll() syscall**（事件引擎心脏）
3. **R1/Y5 fork + 独立地址空间**（master/worker 模型根基）
4. **R5-min 信号最小集**（master 优雅生命周期）

**建议执行顺序**：M0 httpd（当前 ABI 可跑通） → M1 fork/wait/信号最小集 → M2 poll/事件驱动 → M3 性能调优。**每阶段产出独立可验证里程碑**，回归资产连续累积。
