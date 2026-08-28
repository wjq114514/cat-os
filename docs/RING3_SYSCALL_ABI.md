# Cat-OS Ring3 `int 0x80` 系统调用 ABI 文档

> **修订记录（2026-08-26 · fork/waitpid/kill 波次，HEAD=`611b080`）**：新增**进程控制组 nr=33/34/35**（fork / waitpid / kill，nginx M1 三件套），编号已锁定；poll 后续实际分配为 `CATOS_SYS_POLL=168`，并非 nr=36。详见 §3.4。同波次 `syscall.h` 迁入 `CATOS_SYS_EXEC/EXIT/WAIT(11/12/13)` 与 errno 家族（EPERM=1、ESRCH=3、ENOENT=2、E2BIG=7、ECHILD=10），数值不变；`exit(status)` 的 status 自此被记录并经 waitpid 收割（Linux wait-status 编码）。nr=13 wait 保持恒 `-ECHILD` stub 行为不变。

> **修订记录（2026-08-26）**：依据 commit **289e9ce**（"kernel: remove nr==3 close alias — read(fd=3) no longer silently closes"；核对时工作区 HEAD=`fcc386e`）完成 L8 别名拆除的语义跟进——**nr==3 一律 read；close 仅保留 nr==6（VFS）/ nr==28（socket）**；另对照 `syscall.h` 核实 `CATOS_SYS_RESOLVE=31`、`CATOS_SYS_NET_STATS=32` 编号无误，本文档 §3.2 条目无缺漏。

> **版本说明**：本文主体是 2026-08-26 ABI 快照；当前 nginx 实现基线为 **`be876b6`**。nginx r4 及独立复验使用的 poll 入口为 nr=168，证据与当前 nginx 范围见 `docs/TEST_MATRIX.md`、`NOTES_NGINX_PORT.md`。本文其它 ABI 条目仍以未逐项运行复验为准。
> **行号基准**：文中 `文件:行号` 均指实现基线 `be876b6` 对应的当前源码内容；源码内部注释引用的行号（如 `syscall.c:88` 提及的 "net.c:497"）可能因其他改动而漂移，以本文标注的工作区实测行号为准。
> **整理方式**：纯读码归纳，零源码改动；未经运行时复验的行为均标注 NOT_TESTED / 待核实。

---

## 目录

- [1. 依据文件](#1-依据文件)
- [2. 调用约定总览（int 0x80 入口）](#2-调用约定总览int-0x80-入口)
- [3. 系统调用编号表](#3-系统调用编号表)
  - [3.1 VFS 组（nr < 20，委托 vfs_syscall）](#31-vfs-组-nr--20委托-vfs_syscall)
  - [3.2 网络/Socket 组（nr ≥ 20，syscall_dispatch 直辖）](#32-网络socket-组-nr--20syscall_dispatch-直辖)
  - [3.3 close 的两条路径与 L8 别名拆除记录](#33-close-的两条路径与-l8-别名拆除记录)
  - [3.4 进程控制组（nr=33/34/35，编号已锁定；poll=168）](#34-进程控制组nr334435编号已锁定poll168)
- [4. 参数寄存器约定](#4-参数寄存器约定)
- [5. 返回码约定](#5-返回码约定)
- [6. 用户指针校验规则（user_access_ok 语义）](#6-用户指针校验规则user_access_ok-语义)
- [7. 文件描述符分配规则](#7-文件描述符分配规则)
- [8. NOT_TESTED 与待核实清单](#8-not_tested-与待核实清单)

---

## 1. 依据文件

| 文件 | 工作区状态 | 本文引用的行号范围 |
|---|---|---|
| `syscall.c` | 当前主线实现（nginx 基线 `be876b6`） | 当前工作区行号 |
| `syscall.h` | 当前主线实现 | 当前工作区行号 |
| `vfs.c` | 当前主线实现（nginx 基线 `be876b6`） | 当前工作区行号 |
| `vfs.h` | 未修改 | 1–18 |
| `net.c` | 当前主线实现（SACK/OOO 已合入） | 实现基线对应行号 |
| `net.h` | 当前主线实现 | 实现基线对应行号 |
| `paging.c` | 当前主线实现 | 实现基线对应行号 |
| `interrupts.c` | 未修改 | 31（int 0x80 分发实证） |

---

## 2. 调用约定总览（int 0x80 入口）

依据 `syscall.c:62-66` 的约定注释，并经 `interrupts.c:31` 的分发实现逐项核实：

```
ring3                          ring0 (interrupts.c:31)                ring0 (syscall.c:67)
─────                          ───────────────────────                ────────────────────
mov eax, nr          ──►       f->eax == vector 128 ?                 syscall_dispatch(nr, 6, a)
mov ebx/ecx/edx/               uint32_t a[6] = { f->ebx, f->ecx,
     esi/edi, ...      │                        f->edx, f->esi, f->edi, 0 }
int 0x80 (0xCD 0x80) │         int32_t r = syscall_dispatch(nr,6,a);
取返回值 eax          ◄──       f->eax = (uint32_t)r;
```

| 项目 | 约定 | 证据 |
|---|---|---|
| 触发指令 | `int 0x80`（向量 128） | interrupts.c:31（`f->vector==128` 分支） |
| 系统调用号 | `EAX` | interrupts.c:31（`nr=f->eax`） |
| 参数寄存器 | `EBX, ECX, EDX, ESI, EDI` → `a[0..4]` | interrupts.c:31 数组初始化 |
| 第 6 参数 `a[5]` | **恒为 0**（用户态只有 5 个传参寄存器） | interrupts.c:31（数组第 6 元素填 0）；syscall.c:63-64 |
| 参数个数 `n` | 恒为 6（含恒 0 的 `a[5]`） | interrupts.c:31（`syscall_dispatch(nr,6,a)`） |
| 返回值 | sign-extend 后写回 `EAX`；**负值为 `-errno`** | interrupts.c:31（`f->eax=(uint32_t)r`）；syscall.c:64 |
| 分发路由 | `nr < 20` 整体委托 `vfs_syscall(nr, a)`；`nr ≥ 20` 进入 switch | syscall.c:69-70 |
| 入口守卫 | `a == NULL` → `-EFAULT`（防御性；现调用点 a 恒为内核栈数组非空） | syscall.c:68 |
| 未知 nr | `nr ≥ 20` 未匹配 → `-ENOSYS(-38)`；`0 ≤ nr < 20` 未匹配 → `-ENOSYS(-38)`（vfs.c:92 尾部 `return -38`） | syscall.c:197；vfs.c:92 |

ring3 侧生成方式参考（只读旁证，非本 ABI 的规范来源）：`usermode.c:19-20` 的代码生成器按 `mov eax,nr; mov r_i,v_i; int 0x80` 序列产出指令，寄存器映射表 `r[5]={3,1,2,6,7}` 即 EBX/ECX/EDX/ESI/EDI。

---

## 3. 系统调用编号表

### 3.1 VFS 组（nr < 20，委托 vfs_syscall）

实现在 `vfs.c:92` 单行分发表；错误码常量为硬编码数值（`-14`=EFAULT、`-9`=EBADF、`-38`=ENOSYS，与 `syscall.h:5-6,4` 数值一致）。

| nr | 名称 | 参数（a[i]） | 行为与校验 | 返回 | 证据 |
|---|---|---|---|---|---|
| 0 | read | a[0]=fd, a[1]=buf, a[2]=len | `vfs_read(fd,buf,len)`：fd 边界/空槽/kind≠FILE_VFS/无 read ops → `-EBADF(-9)`；buf 用户区不可写（w=1）→ `-EFAULT(-14)` | 成功=读取字节数 | vfs.c:68 |
| 1 | write | a[0]=fd, a[1]=buf, a[2]=len | `vfs_write(fd,buf,len)`：buf 用户区不可读（w=0）→ `-EFAULT(-14)`；fd 校验同 read | 成功=写入字节数 | vfs.c:68 |
| 3 | read（L8 别名已拆除） | a[0]=fd, a[1]=buf, a[2]=len | **一律 read，不再关闭 fd**（commit 289e9ce 移除 nr==3→`vfs_close` 兼容别名；close 仅 nr==6 VFS / nr==28 socket，见 §3.3）；参数与校验同 nr==0 | 成功=读取字节数 | commit 289e9ce（原文引用的 vfs.c:92 别名分支已删除，行号待复核） |
| 5 | open | a[0]=path, a[1]=flags | 路径首字节预检 `user_access_ok(path,1,0)`；随后逐字节扫描 `'\0'`，每字节均做可达性预检；**长度 ≥ 256 → `-EFAULT(-14)`** | 成功=新 fd；失败=**`-1`（非 errno！）** | vfs.c:92；devfs 名单 vfs.c:20 |
| 6 | **close 主号** | a[0]=fd | `vfs_close(a[0])`：负值/越界/空槽/kind≠FILE_VFS → `-EBADF(-9)`；成功清槽归还 | 0 / `-EBADF(-9)` | vfs.c:72, 92 |
| 其他 (<20) | — | — | 无匹配 → `-ENOSYS(-38)` | — | vfs.c:92 尾部 |

**open 的已知事实**：`vfs_open` 找不到设备名时返回 `-1`（vfs.c:67），经 nr==5 **原样透传**给 ring3 —— 即 open 失败的返回值是 `-1`，**不是** `-ENOENT` 等区分性 errno。这是现状行为，非笔误。
**devfs 设备名单**（vfs.c:20）：`/dev/null`、`/dev/console`、`/dev/kbd`、`/dev/zero`、`/dev/urandom`。

### 3.2 网络/Socket 组（nr ≥ 20，syscall_dispatch 直辖）

编号常量定义于 `syscall.h:16-27`。

| nr | 名称 | 参数（a[i]） | 关键前置校验（按判定顺序） | 底层调用 | 证据 |
|---|---|---|---|---|---|
| 20 | socket | a[0]=type | type ∉ {SOCK_DGRAM=2, SOCK_STREAM=1} → `-EINVAL`；内核表满 → `-EMFILE`；fd 安装失败 → 透传安装错误并回收 socket（防泄漏） | `net_socket_open` → `vfs_socket_install` | syscall.c:71-79；net.c:630-634 |
| 21 | bind | a[0]=fd, a[1]=port(uint16) | fd 校验（§5.2）后原样透传 net 层契约：port==0 或类型不符 → `-EINVAL(-22)`；端口/槽位冲突 → `-EADDRINUSE(-98)` | `net_socket_bind` | syscall.c:80-85；net.c:500-521 |
| 22 | listen | a[0]=fd, a[1]=backlog | fd 校验后透传；**未 bind 先 listen（SOCK_TCP_UNBOUND）→ `-EINVAL`**（L1 已知缺口，Linux 会 autobind） | `tcp_set_backlog` | syscall.c:86-99；net.c:538-544 |
| 23 | accept | a[0]=fd | 非 LISTEN 型 → `-EINVAL`；就绪队列为空 → `-EAGAIN`（非阻塞轮询）；fd 安装失败 → 透传并以 `tcp_abort_socket` 回收连接 | `tcp_accept_socket` → `vfs_socket_install` | syscall.c:100-104；net.c:523-536, 546-551 |
| 24 | sendto | a[0]=fd, a[1]=buf, a[2]=len, a[3]=dst_ip(u32), a[4]=dst_port(u16) | EBADF/ENOTSOCK → buf 不可读 EFAULT → len>1472 EMSGSIZE → SOCK_UDP_UNBOUND 未 bind EADDRNOTAVAIL → 底层瞬时失败经 sock_xlate 译为 EAGAIN | `udp_sendto` | syscall.c:105-128；net.c:294-298 |
| 25 | recvfrom | a[0]=fd, a[1]=buf, a[2]=len, a[3]=src_ip_out*(u32×1), a[4]=src_port_out*(u16×1) | fd 校验 → **三个用户区对象全部预检可写**（buf/4B/2B，比 Linux 更严，出参不可省略）EFAULT → 队列空经 sock_xlate 译为 EAGAIN | `udp_recvfrom` | syscall.c:129-143；net.c:300-313 |
| 26 | send | a[0]=fd, a[1]=buf, a[2]=len | 非 SOCK_TCP_ESTAB → `-ENOTCONN`；buf 不可读 → EFAULT；底层哨兵 -1 经 sock_xlate 译为 EAGAIN | `tcp_send` | syscall.c:144-157；net.c:935-945 |
| 27 | recv | a[0]=fd, a[1]=buf, a[2]=len | 非 SOCK_TCP_ESTAB → `-ENOTCONN`；buf 不可写 → EFAULT；EOF→0 / 无数据哨兵 -1 → EAGAIN（详见 §5.3） | `tcp_recv` | syscall.c:158-166；net.c:947-959 |
| 28 | close | a[0]=fd | **唯一 socket-aware 关闭路径**：FILE_SOCKET → `net_socket_close` 成功后接 `vfs_socket_close` 释放 fd；普通文件 → 回落 `vfs_close` | `net_socket_close` / `vfs_close` | syscall.c:167-188；net.c:553-563 |
| 29 | ping | a[0]=目标文本(≤16B), a[1]=out, a[2]=out_len, a[3]=id(u16), a[4]=seq(u16) | 文本不可读/out 不可写 → EFAULT；非法地址走「写错误串入 out」而非错误码（既定演示语义） | `net_parse_ipv4` + `net_ping` | syscall.c:189-193 |
| 30 | ping_stats | a[0]=out, a[1]=out_len | out 不可写 → EFAULT | `net_ping_stats` | syscall.c:194-196 |
| 31 | resolve | a[0]=name(域名文本，≤64B), a[1]=out_ip*(u32×1) | name 首字节不可读 / 扫描中任一字节不可读 → EFAULT；65B 内无终止 NUL（长度>64）→ EINVAL；out4 不可写 → EFAULT；成功(返回0)才写 *out_ip | `net_dns_resolve`（net.c） | syscall.c nr=31 分支；net.h NETDNS_E* |
| 32 | net_stats | a[0]=out(struct net_stats*), a[1]=cap(条目数,u32) | cap 先截断到 NET_STATS_COUNT(13) 再按 cap×4B 预检 out 可写 → EFAULT（截断先行，杜绝超大 cap×4 无符号回绕绕审）；cap==0 不触碰用户内存返回 0 | `net_stats_snapshot` | syscall.c:386-396；net.c arp_tick/net_stats_snapshot；net.h:75-97 |
| 其他 (≥20) | — | — | `-ENOSYS(-38)` | — | syscall.c:197 |

**nr=31 补充说明**（阶段5 第二棒；解压缩升级）：向 DHCP option 6 学得的 resolver（无 DHCP 时回落
slirp 惯例 `10.0.2.3`，见 net.c `g_dns`）发送 RD=1 的 A/IN 查询（UDP:53，随机 txid +
临时端口 49152..53247）；内部 sti 轮询至多 300 ticks、每 25 ticks 重发（net_ping 同款
节奏）。响应解析支持 RFC 1035 §4.1.4 名字解压缩（net.c `dns_read_name`）：压缩指针
带环保护——目标必须落在报文头(12B)之后且严格位于当前指针之前（只准回头，前向/自指
拒绝）、跳转 ≤8 次、全程消耗字节 ≤ 报文长度，任何越界/保留类别(0x40/0x80 前缀)
一律判响应畸形（fail-closed 保持）。answer 取首条 A 记录（rdlength==4 定长 IP，
不涉及名字）；CNAME 链最多跳 4：应答内扫描到链尾 A 则直接采用；若应答只有 CNAME，
则解压目标名覆写查询包 QNAME 换新 txid 立即重发查询（跳数跨重发累计，超限
`cname depth` 失败）。返回码：0 成功 / `-EINVAL(-22)` 域名非法或响应畸形 /
`-ENETUNREACH(-101)` 未配置 resolver / `-ETIMEDOUT(-110)` 超时 / `-ECONNREFUSED(-111)`
rcode!=0。串口观测：成功 `[NET] DNS <name> -> <ip>`，失败 `[NET] DNS <name> fail (<原因>)`。
ring3 参考：shell 内建 `resolve <host>` 命令（shell_user.c）。

**nr=32 补充说明**（阶段5 任务1；字段序随阶段5 第三棒尾追加更新）：out 按 `struct net_stats`
字段序线性接收计数器（13×uint32 连续无填充，字段布局即 ABI，见 net.h:80-97）；成功返回
**写入条目数** `min(cap, 13)`。第 13 项 `arp_entry_expired` 为阶段5 第三棒（ARP 老化）
尾部追加，既有 12 项顺序不变（旧消费方按 cap=12 取快照仍完全兼容）。ring3 参考：shell
内建 `netstat` 命令（shell_user.c，NS_* 索引已同步 NS_ARP_ENTRY_EXPIRED）。

### 3.3 close 的两条路径与 L8 别名拆除记录

> **2026-08-26 语义修订（commit 289e9ce）**：nr==3 → `vfs_close` 兼容别名已拆除。现行语义：**nr==3 一律 read**（不再有任何关闭副作用）；**close 仅存两条路径——nr==6（VFS 文件）与 nr==28（socket-aware）**。下列图表均为拆除后现状；保留的行号级证据以 289e9ce 之前的工作区为基准标注。

```
                    ┌─ nr==28 (CATOS_SYS_CLOSE) ──► FILE_SOCKET ?
ring3 close ────────┤        是 → net_socket_close() ─成功(r==0)→ vfs_socket_close()   [唯一 socket-aware 路径]
                    └─ nr==6 ────────────────────► vfs_close(a[0])   [VFS 主 close 号]

ring3 read（nr==0 或 nr==3）──────────────────► vfs_read(a[0],a[1],a[2])   [289e9ce 起 nr==3 一律 read，无关闭副作用]
```

| 要点 | 结论 | 证据 |
|---|---|---|
| close 号位 | close 仅 nr==6（VFS 文件主号）与 nr==28（FILE_SOCKET 走 net 清理、普通文件回落 `vfs_close`）；**nr==3 别名已拆除** | commit 289e9ce；vfs.c:72；syscall.c:174-177（行号为拆除前基准） |
| nr==3 现行语义 | **一律 read（同 nr==0 读路径），read(fd==3) 不再静默关闭**。历史行为：该别名分支曾与 nr==6 逐字等价，且 `vfs_close` 对 FILE_SOCKET 一律 `-EBADF(-9)`（vfs.c:72），故别名从未能触及 socket | commit 289e9ce；vfs.c:72（历史行为引证） |
| socket 正确关闭号 | 只有 nr==28 | syscall.c:168-170 |
| ⚠️ ABI 兼容性（拆除后） | house nr==3=read 与 Linux x86-32（nr==3=read(2)、nr==6=close(2)）对齐，旧「nr=3 调 read 实为关闭 a[0]」冲突警告解除；**破坏性变更面**：拆除前依赖「nr=3 关闭 fd」语义的既有 ring3 代码自 289e9ce 起改获 read 行为 | commit 289e9ce |
| 移除计划 | **已执行**：原「属 ABI 变更、超出锁内授权、留协调者裁决」事项由 289e9ce 终结（对应两处源码 TODO 注释的清理现状未逐一复核） | commit 289e9ce |
| 既有审计附注 | `net_socket_close` 对已 SOCK_CLOSED 型返回 `-EBADF(-9)` 且不释放 fd，存在理论上的描述符滞留窗口（TODO(code2)：幂等释放或本层兜底，二选一） | syscall.c:184-187；net.c:554 |

### 3.4 进程控制组（nr=33/34/35，编号已锁定；poll=168）

> **编号锁定声明（2026-08-26）**：`CATOS_SYS_FORK=33`、`CATOS_SYS_WAITPID=34`、`CATOS_SYS_KILL=35` 归 nginx M1（master/worker 硬阻塞三件套）任务专属；poll 已实际分配为 `CATOS_SYS_POLL=168`，其他后续编号仍须先登记。分发路由：`syscall_dispatch` 前置拦截 `(11..13 || 33..35)` → `proc_syscall`，poll 由主分发路由处理。常量定义于 `syscall.h`。

| nr | 名称 | 参数（a[i]） | 关键前置校验（按判定顺序） | 行为 | 返回 |
|---|---|---|---|---|---|
| 33 | fork | 无 | pcb[0]/idle 或内核例程上下文 → `-1`（该场景应直调内核 API `process_fork()`）；进程表满 / PMM 耗尽 → `-ENOMEM(-12)`；int80 中断帧签名扫描失败 → `-1`（绝不凭猜测克隆） | 在 int80 中断帧上 COW 克隆：子得私有页目录（可写用户页父子共享 RO+COW、ref=2，写缺页走 ISR14 已接线路径）+ 私有内核栈；fd_table 沿全局单例浅共享（见下） | **父=子 pid（>0），子=0**，负值=-errno |
| 34 | waitpid | a[0]=pid(int32), a[1]=status*(int32*, 可 NULL), a[2]=options | options≠0 / pid==0 / pid<-1 → `-EINVAL(-22)`；status 非 NULL 且不可写 4B → `-EFAULT(-14)`；无匹配子女 → `-ECHILD(-10)` | 阻塞至目标子女 TERMINATED 并收割其编码化退出码（阻塞原语 = PCB 置 `PROC_BLOCKED` 后让出，被 `exit_process_code` 唤醒重扫；零忙等）。多子女竞争唤醒安全（落败者 rescan 重阻塞） | 子 pid / `-EINVAL`/`-EFAULT`/`-ECHILD` |
| 35 | kill | a[0]=pid(u32), a[1]=sig(u32) | pid==0 / pid≥32 → `-EINVAL`；sig ∉ {0, 9, 15, 17} → `-EINVAL`（白名单外一律拒绝，含 >31 无位图位）；目标不存在 → `-ESRCH(-3)` | **SIGKILL(9)**：直接终止目标（外部路径即时回收内核栈；自杀路径即本调用不返回），wait-status 编码 `9`；**SIGTERM(15)/SIGCHLD(17)**：仅置目标 PCB pending 位即返回 0，投递点 = 目标下次任意 syscall 返回前（SIGTERM 默认动作终止、编码 15；SIGCHLD 默认忽略清位）；**sig==0**：存在性探活 | 0 / `-EINVAL`/`-ESRCH` |

**fork 返回的寄存器布置**（对照 Linux fork 语义）：父进程经既有 int80 popa/iretd 原样还原全部 gp 寄存器、eax 写回子 pid；子进程首次派发经 `fork_user_resume_stub` 重装 ds/es/fs/gs=0x23 后按父被陷时的 pusha 快照逆序弹回全部 gp 寄存器（**eax 强制 0**）并 iretd 回到 `int $0x80` 下一条指令、同一 user ESP/EFLAGS —— 子进程视角即「fork() 返回了 0」，其余寄存器与父逐一相同（ring3 封装若依赖 int80 不 clobber 寄存器——如 sock_abi 的 `sc5()`——父子两侧均成立）。

**wait-status 编码**（Linux wait(2) 兼容，`*status` 原样透传 PCB `exit_code` 字段）：

| 进程结局 | status 字 | ring3 解码 |
|---|---|---|
| 正常退出 `exit(code)` / 例程自然返回 | `(code & 0xFF) << 8` | `WIFEXITED(s)` ⇔ `(s & 0x7F)==0`；`WEXITSTATUS(s)` ⇔ `(s>>8) & 0xFF` |
| 被 SIGKILL/SIGTERM 终止（含投递点默认动作） | `sig & 0x7F` | `WIFSIGNALED(s)` ⇔ 低 7 位非零；`WTERMSIG(s)` ⇔ `s & 0x7F` |

**fd_table 继承语义**（按 `process.h process_fork` 契约注释落实）：本内核 VFS fd 表是全局单例（vfs.c `fds[VFS_MAX_FD]`，PCB 无 per-process 字段），fork 取**浅共享**——零拷贝零引用计数，父子的打开文件集合即全体进程共享的同一张表，任一 close 全体可见；无独立 fd 空间/close 传播语义。每进程 fd 表涉及禁区 vfs.c 改动，留待后续统一规划。

**信号数据面设计要点**：PCB 新增 `ppid / exit_code / sig_pending(uint32 位图) / wait_target` 四字段；固定编号 `CATOS_SIGKILL=9 / CATOS_SIGTERM=15 / CATOS_SIGCHLD=17`（process.h）。子进程终止时自动给存活父置 SIGCHLD pending（默认动作忽略，真实收割走 waitpid 扫描）；濒死进程的孤儿子女做 zombie 预收割或摘链（`ppid=0`，不重父 init 的最小语义）。已知限制：① fork 后未触碰的 COW 页 RW=0，写意图 syscall 缓冲区（recv/read 等 w=1 校验）落在其上会先得 `-EFAULT`——waitpid 的 status 出参已做 **COW 感知豁免**（PTE 带 `_PAGE_COW` 即视为写缺页可解，逐页走表校验，真只读段仍拒绝），其余写意图路径需先以一次用户态写触发私有化规避；② 长 sti 轮询型内核调用（resolve/ping）期间到达的 SIGTERM 延迟到该次返回时投递；③ 纯用户态自旋进程只有 SIGKILL 能即时终止；④ nr=13 wait 保持恒 `-ECHILD` stub，新代码一律用 nr=34。

---

## 4. 参数寄存器约定

统一布局：`EAX`=nr，`a[0..4]` = EBX/ECX/EDX/ESI/EDI，`a[5]≡0`。各调用的形参到寄存器的映射已在 §3 表格给出；补充三条设计差异注记（均为代码注释明示的既定决策）：

| 差异点 | house ABI 现状 | Linux 参照 | 决策出处 |
|---|---|---|---|
| socket 域/协议形参 | 仅 `type` 一个参数（无 domain/protocol） | `socket(domain,type,protocol)` 三参 | syscall.c:71-73 |
| sendto/recvfrom 形参 | 五参收缩版：无 flags，地址以裸 u32/u16 传递（无 sockaddr/addrlen） | 六参（含 flags/addr/addrlen） | syscall.c:105-108, 129-133 |
| bind 形参 | `(fd, port)`，IPv4 隐含，无 sockaddr | `(fd, addr, addrlen)` | syscall.c:80-82 |
| accept 形参 | `(fd)`，backlog 由 listen 设置 | `(fd, addr, addrlen)` | syscall.c:100-103 |
| listen(port=0) 语义分歧 | `bind(fd, port=0)` → `-EINVAL` | Linux port=0 表示自动分配端口（inet_autobind） | syscall.c:83-84（分歧已知，归属 net.c 语义决策） |
| sendto 于未 bind UDP | `-EADDRNOTAVAIL`（无临时端口分配器，显式拒绝使错误可区分） | Linux inet_autobind 自动分配临时端口 | syscall.c:117-123（M2 目标语义，TODO code2 若实现 autobind 则删本检查） |

---

## 5. 返回码约定

### 5.1 错误码数值表

| 常量 | 值 | 定义处 | 在本 ABI 中的语义 |
|---|---|---|---|
| `CATOS_ENOSYS` | 38 | syscall.h:4 | 未实现的系统调用号 |
| `CATOS_EFAULT` | 14 | syscall.h:5 | 用户指针校验失败（§6） |
| `CATOS_EBADF` | 9 | syscall.h:6 | fd 未打开 / 越界 / kind 不符（含对 FILE_SOCKET 调 vfs_close） |
| `CATOS_ENOTSOCK` | 88 | syscall.h:7 | fd 已打开但不是 socket（FILE_VFS） |
| `CATOS_EINVAL` | 22 | syscall.h:8 | 参数非法：type 白名单外、port==0、accept 非 LISTEN、listen-before-bind、bind 类型不符等 |
| `CATOS_EAGAIN` | 11 | syscall.h:9 | 非阻塞「暂不能做」：recvfrom/send/recv 底层哨兵 -1 的 fallback、accept 就绪队列为空、ARP 未决等瞬时失败 |
| `CATOS_EMFILE` | 24 | syscall.h:11 | socket 描述符表耗尽（VFS_MAX_FD=32 上限） |
| `CATOS_EADDRINUSE` | 98 | syscall.h:10 | bind 端口冲突 / UDP 槽位占用（TCP 同端口「附着」例外，见 SOCKET_API.md §H2） |
| `CATOS_ENOTCONN` | 107 | syscall.h:12 | send/recv 作用于非 SOCK_TCP_ESTAB 的 socket |
| `CATOS_ETIMEDOUT` | 110 | syscall.h:28 | （已定义；本次通读未见 dispatch 返回该值的路径——待核实用途） |
| `CATOS_EMSGSIZE` | 90 | **syscall.c:20**（暂驻 .c 文件，受文件锁限制未迁入 syscall.h） | sendto len > 1472 |
| `CATOS_EADDRNOTAVAIL` | 99 | **syscall.c:21**（同上） | sendto 作用于 SOCK_UDP_UNBOUND（未 bind） |

> EMSGSIZE/EADDRNOTAVAIL 数值依据 `linux-ref/include/uapi/asm-generic/errno.h`（syscall.c:16-17 注释：EMSGSIZE=90、EADDRNOTAVAIL=99，非 BSD 的 49）。

### 5.2 EBADF / ENOTSOCK 判序（严格性审计定案）

`syscall.c:35-39`：fd 校验统一走 `sock_fd()`（即 `vfs_socket_get`，vfs.c:75）+ `sock_err()`：

```
fd < 0 / fd ≥ 32 / 空槽            → sock_err 返回 -EBADF(-9)    [先判]
fd 已打开但 kind != FILE_SOCKET    → sock_err 返回 -ENOTSOCK(-88) [后判]
```

判序与 `linux-ref/net/socket.c` `sockfd_lookup_light` 一致（先 EBADF 后 ENOTSOCK）；负数 fd 由 `vfs_socket_get` 的 `fd<0` 边界检查兜底，无越界访问。

### 5.3 sock_xlate 错误传递骨架（M2）

`syscall.c:41-60`。背景：`net.c` 的 `udp_sendto`(294)/`udp_recvfrom`(300)/`tcp_send`(935)/`tcp_recv`(947) 失败时一律返回**哨兵 `-1`**，上层无法区分真实 errno。翻译规则：

| 底层返回 r | sock_xlate 输出 | 含义 |
|---|---|---|
| `r >= 0` | 原样返回 | 成功（字节数或 0） |
| `r == -1` | fallback（收发四路径统一传 `-EAGAIN`） | 「暂无数据/暂不能发」的非阻塞语义，与 Linux 非阻塞 socket 一致 |
| 其余 `r < 0` | **原样直通** | 待 net.c 底层改为区分性 `-errno` 后，本层零改动自动获得区分能力 |

**已知歧义**（代码注释自述，syscall.c:52）：数值 `-1` 与 `-EPERM` 同值。
**典型链路示例**：
- `recv` 无数据且连接未关闭：`tcp_recv` → -1（net.c:952）→ sock_xlate → **`-EAGAIN`**；
- `recv` 无数据且对端已 FIN（CLOSE_WAIT/LAST_ACK/TIME_WAIT）：`tcp_recv` → **0 = EOF**（net.c:951，syscall.c:159-160）；
- `sendto` 于已 bind UDP 但 ARP 未决等底层瞬时失败：`udp_sendto` → -1（net.c:297）→ **`-EAGAIN`**（syscall.c:110-112）；
- `send` 缓冲满：当前 `tcp_send` 返回 **`-EAGAIN`**；MSS/剩余空间仍会造成部分写，调用方必须推进游标并处理有限重试（`net/net_tcp.c:799-817`）。

### 5.4 各调用错误返回矩阵（工作区现状实测口径）

| 调用 | 可能的错误返回（按判定顺序） |
|---|---|
| socket | `-EINVAL`（type 白名单外）→ `-EMFILE`（表满）→ 安装错误透传 |
| bind | `-EBADF`/`-ENOTSOCK` → `-EINVAL`(port==0/类型不符) 或 `-EADDRINUSE`(冲突)（net.c:501,504,520） |
| listen | `-EBADF`/`-ENOTSOCK` → `-EINVAL`（非 LISTEN 型，含 UNBOUND=L1 缺口）（net.c:539） |
| accept | `-EBADF`/`-ENOTSOCK` → `-EINVAL`（非 LISTEN）→ `-EAGAIN`（队列空/无 handle 槽，net.c:532,535）→ 安装错误透传 |
| sendto | `-EBADF`/`-ENOTSOCK` → `-EFAULT` → `-EMSGSIZE`(len>1472) → `-EADDRNOTAVAIL`(UNBOUND) → `-EAGAIN`（其余全部折叠） |
| recvfrom | `-EBADF`/`-ENOTSOCK` → `-EFAULT`(三对象全检) → `-EAGAIN`（队列空） |
| send | `-EBADF`/`-ENOTSOCK` → `-ENOTCONN` → `-EFAULT` → `-EAGAIN`（哨兵折叠）或 **0**（缓冲满/len==0 收缩，见 §5.3） |
| recv | `-EBADF`/`-ENOTSOCK` → `-ENOTCONN` → `-EFAULT` → `-EAGAIN`（无数据）/ **0**（EOF） |
| close(28) | socket：`net_socket_close` 契约（`-EBADF` 对 CLOSED 型；UDP/TCP 各型成功 0，net.c:553-563）；文件：0/`-EBADF` |
| open(5) | 新 fd / **`-EFAULT`**(路径不可达或≥256B) / **`-1`**(无名设备，非 errno) |
| read/write(0/1) | ±字节数 / `-EBADF` / `-EFAULT` |
| ping(29) | 字节数（非法地址写串而非报错，syscall.c:190-192）/ `-EFAULT` |
| ping_stats(30) | 字节数 / `-EFAULT` |
| resolve(31) | 0（写 *out_ip）/ `-EFAULT`(name/out 审计) / `-EINVAL`(域名非法·长度>64·响应畸形) / `-ENETUNREACH`(未配置 resolver) / `-ETIMEDOUT` / `-ECONNREFUSED`(rcode!=0) |
| net_stats(32) | 条目数(≤13，cap 截断后直通) / `-EFAULT` / cap==0 → 0（不触碰用户内存） |
| fork(33) | 子 pid / 0（子）/ `-12`(ENOMEM：表满或 PMM 耗尽) / `-1`(pcb[0]/内核例程上下文/帧扫描失败) |
| waitpid(34) | 子 pid / `-EINVAL`(options≠0·pid==0·pid<-1) / `-EFAULT`(status 不可写) / `-ECHILD`(无匹配子女；含目标非我子女) |
| kill(35) | 0 / `-EINVAL`(pid==0·pid≥32·sig 白名单外) / `-ESRCH`(目标不存在)；SIGKILL 自杀路径不返回 |

---

## 6. 用户指针校验规则（user_access_ok 语义）

### 6.1 核心函数 `user_access_ok(v, n, w)`（paging.c:346-378）

| 步骤 | 规则 | 证据 |
|---|---|---|
| ① 零长放行 | `n == 0` → 返回 1（允许），**v 取任意值（含 NULL）一律放行**，不触碰页表 | paging.c:348-350；对齐 Linux `copy_to/from_user` 零长语义（L6/code6 修复，paging.c:333-345） |
| ② 低页洞拒绝 | `v < 0x1000`（NULL/低页洞）→ 返回 0（调用方译 `-EFAULT`） | paging.c:354 |
| ③ 上界检查 | `n > 0xBFC00000u - v` → 返回 0。`0xBFC00000` = KERNEL_VIRT_BASE − 4MiB 守护带，用户段不得触入内核直接映射区（与 syscall.c:32 `user_range_ok` 同源阈值） | paging.c:352-356 |
| ④ 逐页页表遍历 | 对 `[v, v+n)` 每页：PDE 需 `_PAGE_PRESENT+_PAGE_USER`（PSE 大页则跳过 PTE 级检查）；PTE 需 `_PAGE_PRESENT+_PAGE_USER`；**写意图（w≠0）另查 `_PAGE_RW`**。任一不满足 → 返回 0 | paging.c:358-377 |
| 返回值 | 1=允许访问；0=拒绝（调用方统一译为 `-EFAULT`：vfs.c:68、syscall.c:33） | paging.c:330-331 |

语义前提（paging.c:360-361 自述）：本内核用户页均为急切全量映射（usermode.c:34），无 demand paging，故「PRESENT 即可达」当前自洽；引入惰性分配/COW 时须重审（NOTE，paging.c:394-396）。

### 6.2 包装与使用矩阵

`bad_user(p, n, write)`（syscall.c:33）= `!user_access_ok(...)`，各调用使用情况：

| 调用点 | 校验对象与长度 | 写意图 w | 证据 |
|---|---|---|---|
| sendto | buf, len | 0（读用户数据） | syscall.c:115 |
| recvfrom | buf,len=1；src_ip_out,4=1；src_port_out,2=1（三对象全检，刻意严于 Linux——Linux 出参可为 NULL，house 不允许） | 1 | syscall.c:129-136 |
| send | buf, len | 0 | syscall.c:150 |
| recv | buf, len | 1 | syscall.c:164 |
| ping | 目标文本 16 字节(w=0)；out,out_len(w=1) | 混合 | syscall.c:193 |
| ping_stats | out, out_len（w=1；out_len 参与 `n<=0xBFC00000-v` 上界判断，合法入参无整数溢出） | 1 | syscall.c:194-195 |
| net_stats | out, cap×4B（w=1；cap 先截断到 NET_STATS_COUNT=13 再审计，上界恒 ≤52B 无回绕） | 1 | syscall.c:386-396 |
| open(nr==5, vfs.c:92) | path 首字节 1B(w=0)；此后**逐字节**预检直到 '\0'；累计长度 sl≥256 → `-EFAULT` | 0 | vfs.c:92 |
| read/write(nr==0/1) | vfs_read 对 buf(n,w=1)；vfs_write 对 buf(n,w=0)。注意 vfs_write 的检查**先于** fd 校验执行（顺序事实，vfs.c:68） | 见左 | vfs.c:68 |

### 6.3 辅助函数 `user_range_ok(p, n)`（syscall.c:32）

简单区间判断：`p >= 0x400000 && n <= 0xBFC00000-p`。由 `syscall.h:30` 导出；**本次通读在 dispatch 及 vfs/net 路径中未见任何调用点**（活跃校验路径全部走 `user_access_ok`）——其保留用途**待核实**（推测为早期简化版 uaccess，被 paging.c:353 注释提及为「同源阈值」）。

### 6.4 已知加固项（代码内 TODO，行为现状如实记录）

| 级别 | 问题 | 现状兜底 | 出处 |
|---|---|---|---|
| TODO(code6,HIGH) | 上界检查无符号下溢：`v >= 0xBFC00000` 时 `0xBFC00000u - v` 回绕致上界失效；`e=v+n` 亦可回绕令循环整体跳过而错误放行（例：v=0xFFFFFF00, n=0x200） | 页表遍历的 `_PAGE_USER` 检查兜底（内核区 PDE 无 USER 位），属纵深防御缺口而非当下可达漏洞；修法一行：条件追加 `\|\| v >= 0xBFC00000u` | paging.c:380-387 |
| TODO(code6,MED) | PSE 大页分支 `continue` 跳过写意图（RW）检查 | 现网不可达：大页均 RW 且无 USER 位；map_page 拒绝分裂 PSE 叶子 | paging.c:388-391 |
| TODO(code6,LOW) | 非 PSE 路径仅校验 PTE._PAGE_RW 未校验 PDE._PAGE_RW（硬件取两者 RW 合集） | 现网不可达（map_page 所建 PD 项恒带 RW） | paging.c:392-393 |
| INFO | 「PRESENT 即可达」与 Linux access_ok 纯区间检查模型不同 | 引入惰性分配/COW 时须重审 | paging.c:394-396 |

---

## 7. 文件描述符分配规则

依据 `vfs.c:7-33`（L2/code7 改动）与 `vfs.h:4`：

| 规则 | 内容 | 证据 |
|---|---|---|
| 表容量 | `VFS_MAX_FD = 32`；文件（FILE_VFS）与 socket（FILE_SOCKET）**共享同一张 `fds[]` 表与同一分配器** | vfs.h:4；vfs.c:14, 29-33 |
| 分配策略 | `vfs_fd_alloc()` 自 **fd=0 起线性扫描最低空闲槽位**（对照 linux-ref fs/file.c:569 alloc_fd 与 POSIX "lowest-numbered unused fd"；vfs.c:21-28 注释） | vfs.c:29-33 |
| 标准流占位 | `vfs_init` 安装 fd 0=/dev/kbd(stdin，阻塞读带超时)、fd 1=/dev/console(stdout)、fd 2=/dev/console(stderr)；安装失序打印 WARN 但不中止 | vfs.c:34-42 |
| 动态分配起点 | std 占住 0-2 后，首个动态分配自然落在 **fd=3**（兼容 usermode.c ring3 探针硬编码 fd=3 的既有依赖）；若某 std 未安装，分配器回落到含 0-2 在内的最低空闲槽（不硬性保留） | vfs.c:35-38 注释 |
| 释放与复用 | close 路径把 `fds[fd]` 清零即可被下次扫描重新命中（对照 __put_unused_fd）；vfs.c:46-64 内置自检验证 3/4/5 分配→关 4 复用 4→socket 占 6→关 3 复用 3 的闭环 | vfs.c:25-27, 46-64 |
| 耗尽契约 | 分配器返回 -1，由调用方翻译：socket 安装 → **`-EMFILE(-24)`**（vfs_socket_install）；open → **`-1`**（维持改动前契约） | vfs.c:27-28, 66-67, 73-74 |
| kind 隔离 | `vfs_close` 拒收 FILE_SOCKET（-EBADF）；`vfs_socket_get/vfs_socket_close` 只认 FILE_SOCKET —— 文件与 socket 的关闭互不可越界 | vfs.c:69-72, 75-76 |
| 存在性查询 | `vfs_fd_exists(fd)`：`0 ≤ fd < 32 && fds[fd] != 0`（供 sock_err 区分 EBADF/ENOTSOCK） | vfs.c:77 |

---

## 8. NOT_TESTED 与待核实清单

| # | 条目 | 状态 | 说明 |
|---|---|---|---|
| N1 | 本文大部分行为条目 | **以静态读码为主** | nginx r4 只覆盖 poll、TCP 被动服务、accept 地址出参、静态 FAT16 读取及 shell 辅助命令；不覆盖完整 ABI |
| N2 | 旧 ring3 socket 全场景断言骨架（P01–P09/H1P/H1B/H2P/H2Q…） | NOT_TESTED | `/tmp/cat-os-tests/user_ring3_socktest.c` 仍未接入；不要与仓库内 stage4 `user_sock_abi` 混淆，后者在 nginx fresh 串口中为 85 PASS / 0 FAIL / 4 skip |
| N3 | `sock_xlate` 的区分性 errno 直通能力 | 部分落地 | TCP 发送缓冲满已返回 `-EAGAIN`；其它底层裸 `-1` 仍可能折叠为 `-EAGAIN`，完整错误区分尚未完成 |
| N4 | `CATOS_ETIMEDOUT(110)` 的返回路径 | 待核实 | 常量已定义（syscall.h:27），本次通读未见 dispatch 返回该值的路径 |
| N5 | `user_range_ok` 的现存调用点 | 待核实 | 导出符号但未见调用（§6.3） |
| N6 | vfs.c:46-64 `[VFS-FD] selftest` | 代码内置自检，本任务未复跑 | 断言逻辑见 vfs.c:46-64，输出标记 `[VFS-FD] selftest PASS ...` |
| N7 | L1（listen 自动绑定）与 M 族错误码区分等加固 | **部分未完成** | H2 同端口 bind 已返回 `-EADDRINUSE`，但 listen 自动绑定和其它底层错误的完整区分仍是缺口；编号登记见 `docs/SOCKET_API.md` §6 |
| N8 | nr=32 `net_stats`（阶段5 任务1 新增） | **shell 路径已实测；直接 ABI 场景仍未单独覆盖** | nginx r4 与独立复验均通过 shell `netstat`；计数器写入点均为既有行为路径旁的单条 u32 自增 |
| N9 | nr=33/34/35 fork/waitpid/kill（2026-08-26 新增） | 见副本验收记录 | 契约见 §3.4；副本内已完成内核态冒烟（fork→COW 写缺页→waitpid 收割退出码）与 sock_abi 式 ring3 自证（F 族断言），主仓运行时复验归 orchestrator；已知限制四条见 §3.4 末 |
| N10 | nr=168 `poll` | **已实装；nginx r4 与独立复验均运行使用** | `kernel/syscall.h:54`、`kernel/syscall.c:458-525`；完整 epoll/select 仍未实现 |

---

*文档结束。主体为 2026-08-26 ABI 快照；poll=168、nginx r4 和独立复验关系回填于 2026-08-28。当前回填只更新文档，不修改源码。*
