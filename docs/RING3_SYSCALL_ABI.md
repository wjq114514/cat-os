# Cat-OS Ring3 `int 0x80` 系统调用 ABI 文档

> **版本说明**：本文档基于 **HEAD=`0d4b58342a1350d81eef82eb128c0c6fcd9df27c`**（"input: blocking read for /dev/kbd with timeout"）**+ 工作区未提交变更**（`git status` 显示 `net.c`/`paging.c`/`syscall.c`/`vfs.c`/`usermode.c`/`OSDEV_PROJECT_NOTES.md` 存在未提交修改，其中 `syscall.c`/`vfs.c`/`paging.c` 的改动内容已包含进本文依据）整理。
> **行号基准**：文中 `文件:行号` 均指**当前工作区文件内容**（含未提交改动）；源码内部注释引用的行号（如 `syscall.c:88` 提及的 "net.c:497"）可能因其他代理的并行改动而漂移，以本文标注的工作区实测行号为准。
> **整理方式**：纯读码归纳，零源码改动；未经运行时复验的行为均标注 NOT_TESTED / 待核实。

---

## 目录

- [1. 依据文件](#1-依据文件)
- [2. 调用约定总览（int 0x80 入口）](#2-调用约定总览int-0x80-入口)
- [3. 系统调用编号表](#3-系统调用编号表)
  - [3.1 VFS 组（nr < 20，委托 vfs_syscall）](#31-vfs-组-nr--20委托-vfs_syscall)
  - [3.2 网络/Socket 组（nr ≥ 20，syscall_dispatch 直辖）](#32-网络socket-组-nr--20syscall_dispatch-直辖)
  - [3.3 close 的三条路径与双重别名关系（L8）](#33-close-的三条路径与双重别名关系l8)
- [4. 参数寄存器约定](#4-参数寄存器约定)
- [5. 返回码约定](#5-返回码约定)
- [6. 用户指针校验规则（user_access_ok 语义）](#6-用户指针校验规则user_access_ok-语义)
- [7. 文件描述符分配规则](#7-文件描述符分配规则)
- [8. NOT_TESTED 与待核实清单](#8-not_tested-与待核实清单)

---

## 1. 依据文件

| 文件 | 工作区状态 | 本文引用的行号范围 |
|---|---|---|
| `syscall.c` | 已修改（未提交） | 1–199（全文） |
| `syscall.h` | 未修改 | 1–31 |
| `vfs.c` | 已修改（未提交） | 1–92（全文） |
| `vfs.h` | 未修改 | 1–18 |
| `net.c` | 已修改（未提交，SACK/OOO 改动） | 215–227, 259–313, 315–355, 500–563, 630–634, 935–959 |
| `net.h` | 未修改 | 61–84 |
| `paging.c` | 已修改（未提交） | 330–396 |
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
| 3 | **close 别名②** | a[0]=fd | `vfs_close(a[0])` —— 与 nr==6 分支**逐字等价**（L8 双重别名，见 §3.3）。⚠️ 与 Linux x86-32（nr=3=read）冲突 | 0 / `-EBADF(-9)` | vfs.c:92（`if(nr==3)return vfs_close(a[0]);`） |
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
| 32 | net_stats | a[0]=out(struct net_stats*), a[1]=cap(条目数,u32) | cap 先截断到 NET_STATS_COUNT(12) 再按 cap×4B 预检 out 可写 → EFAULT（截断先行，杜绝超大 cap×4 无符号回绕绕审）；cap==0 不触碰用户内存返回 0 | `net_stats_snapshot` | syscall.c:386-396；net.c:1212-1218；net.h:74-95 |
| 其他 (≥20) | — | — | `-ENOSYS(-38)` | — | syscall.c:197 |

**nr=31 补充说明**（阶段5 第二棒）：向 DHCP option 6 学得的 resolver（无 DHCP 时回落
slirp 惯例 `10.0.2.3`，见 net.c `g_dns`）发送 RD=1 的 A/IN 查询（UDP:53，随机 txid +
临时端口 49152..53247）；内部 sti 轮询至多 300 ticks、每 25 ticks 重发（net_ping 同款
节奏）。响应仅取 answer 首条 A 记录，CNAME 链最多跳 4；只认字面量标签名
（`05hello03com` 形式），遇 `0xC0` 压缩指针直接失败（防解引用越界，fail-closed 取舍：
压缩型 resolver 会得到 -EINVAL）。返回码：0 成功 / `-EINVAL(-22)` 域名非法或响应畸形 /
`-ENETUNREACH(-101)` 未配置 resolver / `-ETIMEDOUT(-110)` 超时 / `-ECONNREFUSED(-111)`
rcode!=0。串口观测：成功 `[NET] DNS <name> -> <ip>`，失败 `[NET] DNS <name> fail (<原因>)`。
ring3 参考：shell 内建 `resolve <host>` 命令（shell_user.c）。

**nr=32 补充说明**（阶段5 任务1）：out 按 `struct net_stats` 字段序线性接收计数器
（12×uint32 连续无填充，字段布局即 ABI，见 net.h:80-94）；成功返回**写入条目数**
`min(cap, 12)`。ring3 参考：shell 内建 `netstat` 命令（shell_user.c）。

### 3.3 close 的三条路径与双重别名关系（L8）

综合 `syscall.c:167-188` 与 `vfs.c:78-91` 的审计结论（行为未改，仅文档化）：

```
                    ┌─ nr==28 (CATOS_SYS_CLOSE) ──► FILE_SOCKET ?
                    │        是 → net_socket_close() ─成功(r==0)→ vfs_socket_close()   [唯一 socket-aware 路径]
ring3 close ────────┤                 否 → vfs_close()
                    ├─ nr==6 ────────────────────► vfs_close(a[0])   [主 close 号]
                    └─ nr==3 ────────────────────► vfs_close(a[0])   [别名③，分支与 nr==6 逐字等价]
```

| 要点 | 结论 | 证据 |
|---|---|---|
| 主号/别名 | 主 close 号为 nr==6；nr==3 是第二分支，二者构成**双重别名** | vfs.c:92；syscall.c:171-173 |
| 别名是否触及 socket | **否**。`vfs_close` 对 FILE_SOCKET 一律 `-EBADF(-9)`（vfs.c:72），故经 3/6 既不能关 socket、也不会绕过 TCP 清理造成泄漏 | vfs.c:72；syscall.c:174-177 |
| socket 正确关闭号 | 只有 nr==28 | syscall.c:168-170 |
| ⚠️ ABI 兼容性警告 | Linux x86-32 中 nr==3=read(2)、nr==6=close(2)；本内核为 0=read/1=write/5=open 并把 **3 别名到 close** —— 按 Linux ABI 编写的程序若以 nr=3 调 read，实际效果是**关闭 a[0]** | vfs.c:86-90；syscall.c:178-181 |
| 移除计划 | 属 ABI 变更，超出锁内授权，留协调者裁决（TODO 见两处注释） | vfs.c:90-91；syscall.c:181 |
| 既有审计附注 | `net_socket_close` 对已 SOCK_CLOSED 型返回 `-EBADF(-9)` 且不释放 fd，存在理论上的描述符滞留窗口（TODO(code2)：幂等释放或本层兜底，二选一） | syscall.c:184-187；net.c:554 |

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
- `send` 缓冲满隐患：`tcp_send` 可收缩到 0 字节并返回 **0**（net.c:938-940），调用方无法区分「成功 0 字节」与「缓冲满将忙等」——TODO(code2) 建议改返 `-EAGAIN`，0 仅保留于对端关闭场景（syscall.c:151-155）。

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
| net_stats(32) | 条目数(≤12，cap 截断后直通) / `-EFAULT` / cap==0 → 0（不触碰用户内存） |

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
| net_stats | out, cap×4B（w=1；cap 先截断到 NET_STATS_COUNT=12 再审计，上界恒 ≤48B 无回绕） | 1 | syscall.c:386-396 |
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
| N1 | 本文全部行为条目 | **NOT_TESTED（静态阅读结论）** | 本任务只读源码、未编译未运行；所有结论以工作区源码为准，未做运行时复验 |
| N2 | ring3 socket 全场景断言骨架（P01–P09/H1P/H1B/H2P/H2Q…） | NOT_TESTED | `/tmp/cat-os-tests/README.md` 明示：编译自检通过，**运行时 NOT_TESTED**（需阶段 1–3 接入 ring3 入口） |
| N3 | `sock_xlate` 的区分性 errno 直通能力 | 待落地 | 依赖 net.c 底层废除裸 `-1` 哨兵（TODO(code2)，syscall.c:53-55）；现状所有底层失败均折叠为 `-EAGAIN` |
| N4 | `CATOS_ETIMEDOUT(110)` 的返回路径 | 待核实 | 常量已定义（syscall.h:27），本次通读未见 dispatch 返回该值的路径 |
| N5 | `user_range_ok` 的现存调用点 | 待核实 | 导出符号但未见调用（§6.3） |
| N6 | vfs.c:46-64 `[VFS-FD] selftest` | 代码内置自检，本任务未复跑 | 断言逻辑见 vfs.c:46-64，输出标记 `[VFS-FD] selftest PASS ...` |
| N7 | L1（listen 自动绑定）、H2（bind 同端口）、M 族错误码区分等加固 | 未修复/进行中 | 缺口编号登记见 `docs/SOCKET_API.md` §6；本文档如实记录现状行为 |
| N8 | nr=32 `net_stats`（阶段5 任务1 新增） | NOT_TESTED（运行时） | 副本编译自检通过；ring3 实测入口为 shell 内建 `netstat`，计数器写入点均为既有行为路径旁的单条 u32 自增 |

---

*文档结束。生成者：Cat-OS 并行任务 code8（接口文档完善）。约束遵守声明：本任务仅新建 `docs/` 下文档，未修改任何 `.c/.h/.md` 既有文件，未触碰 net.c/usermode.c/OSDEV_PROJECT_NOTES.md/NEXT_TASKS_AUTONOMOUS.md，未执行 push/reset/rebase/delete。*
