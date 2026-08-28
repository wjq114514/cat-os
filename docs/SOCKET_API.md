# Cat-OS Socket API 现状文档

> **版本说明**：本文主体是 2026-08-25/26 的 socket API 快照；当前实现基线为 **`be876b6`**。当前容量与 nginx 依赖关系已按 `net/net.h`、`net/net_tcp.c` 和 `docs/TEST_MATRIX.md` 的后续实证回填。
> **当前验证边界（2026-08-28）**：nginx r4 与独立 fresh QEMU 复验已通过 `poll`/TCP 被动服务/静态 FAT16 文件读取；本文未把该专项扩展为完整 socket ABI 或完整 nginx 特性的 PASS。当前主线还修正了同端口 bind 冲突和 TCP 满缓冲返回值，历史段落中的旧行为以本注记为准。
> **行号基准**：`文件:行号` 指实现基线 `be876b6` 对应的源码内容；源码内部注释引用的旧行号可能因后续改动漂移，以本文实测行号为准。
> **整理方式**：纯读码归纳，零源码改动。RFC 对照仅限代码注释中明示的条目与可从代码直接验证的行为，不做臆测性推断。

---

## 目录

- [1. 依据文件](#1-依据文件)
- [2. 总览：socket 类型状态机与容量常量](#2-总览socket-类型状态机与容量常量)
- [3. 各系统调用行为（TCP/UDP）](#3-各系统调用行为tcpudp)
- [4. bind / listen / accept / connect 语义专述](#4-bind--listen--accept--connect-语义专述)
- [5. SACK / OOO 队列当前实现要点（RFC 2018/6675 对照）](#5-sack--ooo-队列当前实现要点rfc-20186675-对照)
- [6. 已知限制（缺口编号登记）](#6-已知限制缺口编号登记)
- [7. NOT_TESTED 与待核实清单](#7-not_tested-与待核实清单)

---

## 1. 依据文件

> 下方文件状态和行号主要保留 2026-08-25/26 的读码快照；当前源码已由后续提交收敛，
> 当前运行证据以 `docs/TEST_MATRIX.md`、nginx r4 结果文件和独立复验结果文件为准。

| 文件 | 工作区状态 | 本文引用的行号范围 |
|---|---|---|
| `net/net.c`、`net/net_tcp.c`、`net/net_udp.c` | 当前主线实现 | socket 状态、TCP 生命周期/收发、UDP 队列；历史行号只作追溯 |
| `net/net.h`、`net/net_internal.h` | 当前主线实现 | 类型、容量常量和连接结构定义 |
| `kernel/syscall.c`、`kernel/syscall.h` | 当前主线实现 | nr=20..32 socket 组；nr=168 poll；当前行号以源码为准 |
| `fs/vfs.c`、`fs/vfs.h` | 当前主线实现 | socket fd 安装/获取/关闭与普通文件 fd |

---

## 2. 总览：socket 类型状态机与容量常量

### 2.1 socket 类型（net.h:76）

```
SOCK_CLOSED ──┬── (UDP) SOCK_UDP_UNBOUND ──bind──► SOCK_UDP ──close(28)──► SOCK_CLOSED
              │        （net_socket_open(type=2) 创建，owned 槽位）
              └── (TCP) SOCK_TCP_UNBOUND ──bind──► SOCK_TCP_LISTEN ──accept──► SOCK_TCP_ESTAB
                        （net_socket_open(type=1) 创建，      │                     │
                          conn 处 TCP_CLOSED 态）             │close(28)            │close(28)→FIN
                                                              ▼                     ▼
                                                         SOCK_CLOSED           FIN_WAIT_1/LAST_ACK
                                                                              （conn 独立推进状态机）
```

类型枚举定义于 `net.h:76`：`SOCK_CLOSED, SOCK_UDP, SOCK_TCP_LISTEN, SOCK_TCP_ESTAB, SOCK_UDP_UNBOUND, SOCK_TCP_UNBOUND`。socket_t 结构为 type + udp(lport/slot/owned) / tcp(conn 指针) 的 union（net.h:78-84）。

### 2.2 容量与缓冲常量

| 常量 | 值 | 含义 | 出处 |
|---|---|---|---|
| `UDP_SLOTS` | 8 | UDP socket 槽位数 | net.c:216 |
| `UDP_RXBUF` | 2048 B | 单 UDP socket 接收缓冲（线性包队列：`[len4][src_ip4][sport2]payload...`） | net.c:217, 218-222 |
| `TCP_MAX_CONNS` | 64 | TCP 连接表容量（同时是 listen backlog 上限） | `net/net.h:86,97-101` |
| `TCP_MSS` | 1460 | 最大段长（也是单段上限） | net.h:69 |
| `TCP_BUF_SIZE` | 4096 | 收/发缓冲大小 | net.h:70 |
| `TCP_TX_SEG_MAX` | 8 | 发送侧 scoreboard 段数上限 | net.h:71 |
| `TCP_RX_WINDOW` | 65535 | （已定义；实际通告窗口改为动态 `TCP_BUF_SIZE - rxn`，net.c:643 —— 该宏现网用途待核实） | net.h:68 |
| OOO 队列 | 2 槽 × ≤MSS | 每连接乱序缓存槽位（总字节受 ooo_bytes ≤ TCP_BUF_SIZE 约束） | `net/net.h:91-96`、`net/net_tcp.c` |

---

## 3. 各系统调用行为（TCP/UDP）

系统调用层入口在 `syscall.c`（编号表详见 `docs/RING3_SYSCALL_ABI.md` §3.2）；本节按「syscall 层校验 → net.c 底层契约」两层记录。

### 3.1 socket(type=1 STREAM / 2 DGRAM)

| 步骤 | 行为 | 证据 |
|---|---|---|
| syscall 层 | type 白名单 {2,1}，否则 `-EINVAL`；`net_socket_open` 返回 NULL → `-EMFILE`；fd 安装失败回收 socket | syscall.c:75-79 |
| UDP 分支 | 占用 `udp_socks[]` 空槽（owned=true），句柄类型 **SOCK_UDP_UNBOUND**（尚未绑定端口） | net.c:631 |
| TCP 分支 | 占用 `tcp_conns[]` 空槽（state=TCP_CLOSED），句柄类型 **SOCK_TCP_UNBOUND** | net.c:632 |

### 3.2 sendto(fd,buf,len,dst_ip,dst_port) —— UDP 数据报发送

| 层 | 判定顺序 | 证据 |
|---|---|---|
| syscall | EBADF/ENOTSOCK → EFAULT(buf) → **EMSGSIZE(len>1472)** → **EADDRNOTAVAIL(SOCK_UDP_UNBOUND 未 bind)** → sock_xlate(-1→EAGAIN) | syscall.c:113-124 |
| net.c | `udp_sendto`：type≠SOCK_UDP → -1；len>1472 → -1；ARP 解析失败/IP 层发送失败 → -1（全部折叠为哨兵） | net.c:294-298 |

要点：
- 1472 = Ethernet MTU 1500 − IPv4 头 20 − UDP 头 8（syscall.c:23-29），syscall 层预检与 net.c 内部检查同值双保险；
- UDP 校验和置 0 不计算（net.c:233，IPv4 UDP 允许 0 表示不校验）;
- 若对 TCP 型 socket 调 sendto：syscall 层不拦（fd 是合法 socket、非 UNBOUND），落到 `udp_sendto` 的 type≠SOCK_UDP → -1 → **`-EAGAIN`**（错误折叠现状，关联缺口 M2）。

### 3.3 recvfrom(fd,buf,len,src_ip_out,src_port_out) —— UDP 数据报接收

| 层 | 行为 | 证据 |
|---|---|---|
| syscall | 三用户区对象全预检（buf/4B ip/2B port，均 w=1，不可省略出参——刻意严于 Linux）→ EFAULT；队列空 → sock_xlate(-1→**EAGAIN**) | syscall.c:129-143 |
| net.c | 从线性队列头取一整包：回填 src_ip/src_port；**dlen>max_len 时静默截断且余量随整包丢弃**（无 MSG_TRUNC 等价上报）；返回实际拷贝字节数 | net.c:300-313 |

接收队列入队侧（内核收包路径）：满则**丢弃整包**（无部分入队），每包记录 `[len][src_ip][sport][payload]`（net.c:273-281）。无监听者的 UDP 报文静默丢弃并打日志（net.c:266-270；README 关联缺口 C7：无 ICMP port unreachable）。

### 3.4 send(fd,buf,len) —— TCP 发送（部分写语义）

| 层 | 行为 | 证据 |
|---|---|---|
| syscall | 非 SOCK_TCP_ESTAB → `-ENOTCONN`（ring3 探针依赖此断言）→ EFAULT(buf) → sock_xlate | syscall.c:144-157 |
| net/net_tcp.c | `tcp_send`：len>1460 收缩到 MSS；超过发送缓冲余量再收缩；**缓冲耗尽返回 `-EAGAIN`**；正常返回实际接受字节数（类似 write 部分写）；数据进 `sndb` 缓冲后由 `tcp_xmit_pending` 受 cwnd/peer_win 约束发出 | `net/net_tcp.c:799-817` |

### 3.5 recv(fd,buf,len) —— TCP 接收

| 场景 | 返回 | 证据 |
|---|---|---|
| 非 ESTAB | syscall 层直接 `-ENOTCONN` | syscall.c:161-165 |
| rxn==0 且 state ∈ {CLOSE_WAIT, LAST_ACK, TIME_WAIT} | **0 = EOF**（对端已发 FIN 且无遗留数据） | net.c:950-952 |
| rxn==0 其余（连接仍在） | -1 → sock_xlate → **`-EAGAIN`**（非阻塞语义） | net.c:952；syscall.c:158-166 |
| 有数据 | min(rxn, max_len) 字节 + 缓冲前移 | net.c:954-958 |

注意 EOF 判定基于**状态机**而非显式「已见 FIN」标志：一旦连接推进到 CLOSE_WAIT/LAST_ACK/TIME_WAIT 且缓冲空即报 0。

### 3.6 close(nr==28)

`net_socket_close`（net.c:553-563）按类型分派：

| 原类型 | 动作 | 返回后 |
|---|---|---|
| SOCK_CLOSED | **不动作，返回 -EBADF(-9)，fd 不释放**（描述符滞留窗口，审计附注 TODO(code2)） | syscall.c:184-187 |
| SOCK_UDP | owned 槽归还（used/bound 清零） | fd 释放（vfs_socket_close） |
| SOCK_TCP_ESTAB | 走 `tcp_close`：ESTABLISHED→发 FIN 进 FIN_WAIT_1；CLOSE_WAIT→发 FIN 进 LAST_ACK；RTO 保护重传 FIN | fd 立即释放；连接由内核状态机/RTO/TIME_WAIT 收尾 |
| SOCK_TCP_UNBOUND | conn.used=false 回收连接槽 | fd 释放 |
| SOCK_TCP_LISTEN | `tcp_drop_pending(port)` 丢弃该端口所有半开/未 accept 连接，listener conn 回收 | fd 释放 |

TIME_WAIT 定长 200 ticks（@100Hz 即 2s）到期自动释放连接槽（net.c:862）。

---

## 4. bind / listen / accept / connect 语义专述

### 4.1 bind(fd, port)

`net_socket_bind`（net.c:500-521）：

| 入参状态 | 行为 | 返回 |
|---|---|---|
| s==NULL 或 port==0 | 拒绝 | `-EINVAL(-22)` |
| SOCK_UDP_UNBOUND | 槽位必须 owned 且未被占用；端口已被其他 UDP socket 绑定（`udp_sock_by_port`）→ 冲突；成功则转 SOCK_UDP 并清空接收队列 | 0 / `-EADDRINUSE(-98)` |
| SOCK_TCP_UNBOUND | 若同端口已存在 LISTEN conn（`tcp_conn_find_listen`）→ 拒绝并返回 `-EADDRINUSE`；否则本 conn 转 TCP_LISTEN、backlog 固定置 1、复位收发状态 | 0 / `-EADDRINUSE` |
| 其余类型（含重复 bind、CLOSED、ESTAB） | 拒绝 | `-EINVAL(-22)` |

分歧注记：Linux `bind(port=0)` 是请求自动分配端口；此处一律 `-EINVAL`（syscall.c:83-84 已知差异，归属 net.c 语义决策）。

### 4.2 listen(fd, backlog)

`tcp_set_backlog`（net.c:538-544）：

| 规则 | 内容 |
|---|---|
| 适用对象 | 仅 SOCK_TCP_LISTEN（**未 bind 先 listen 即 SOCK_TCP_UNBOUND → `-EINVAL`，L1 缺口**；Linux 会先 inet_autobind 再转 LISTEN，syscall.c:86-94 TODO(code2) 待修复） |
| backlog 取值 | 0 → 按 1 处理；> TCP_MAX_CONNS(64) → 截到 64 |
| 生效点 | backlog 存于 listener conn，SYN 到达时检查 `tcp_pending_count(port) >= backlog` 则回 RST（accept queue full，net.c:698-702） |
| 注意 | bind 路径创建的 listener backlog 固定为 1（net.c:510），需显式 listen 调大 |

### 4.3 accept(fd)

`tcp_accept_socket`（net.c:523-536）+ syscall 层（syscall.c:100-104）：

| 规则 | 内容 |
|---|---|
| 前置 | fd 必须是 SOCK_TCP_LISTEN，否则 syscall 层 `-EINVAL` |
| 就绪判定 | 扫描连接表：`state==TCP_ESTABLISHED && lport==listener.port && !accepted` |
| 无就绪连接 / 无空闲 handle 槽 | NULL → syscall 层 **`-EAGAIN`**（非阻塞轮询语义，Linux O_NONBLOCK 同型） |
| 成功 | 标记 accepted；从 `tcp_handles[16]` 找 SOCK_CLOSED 槽安装 ESTAB 句柄；新 fd 经 vfs_socket_install 分配 |
| fd 安装失败 | 透传安装错误并以 `tcp_abort_socket` 回收连接（防泄漏，syscall.c:104） |
| 对端信息 | syscall accept 支持可选 `sockaddr_in` 和长度出参；底层 `net_socket_peer()` 提供 peer_ip/peer_port，nginx r4 已经走通该最小路径 |

连接建立路径（被动开放）：SYN → 查 listener → backlog 满 RST / 连接表满 RST → 建 SYN_RECEIVED conn（记 ISN、协商选项）→ SYN-ACK（RTO 保护重传，net.c:715）→ ACK 到达转 ESTABLISHED（net.c:794-799）。重复 SYN 保半开重发 SYN-ACK（RFC 793 注释，net.c:732-736）。

### 4.4 connect —— **不存在**

| 事实 | 说明 |
|---|---|
| 无 connect 系统调用 | 编号表 nr 20–30 中无 connect（syscall.h:16-26）；`net.h` 公共 API 亦无任何 connect 函数声明（net.h:107-118） |
| TCP 仅被动开放 | 本栈作为服务器：内核演示服务监听 :80/:81（net_init，net.c:1004-1006）；ring3 可经 listen/accept 提供服务，但**无法主动向外部发起 TCP 连接** |
| UDP 方向性 | UDP 无 connect 概念本就正确；但 ring3 发送须先 bind（sendto 拦截 UNBOUND → EADDRNOTAVAIL，syscall.c:117-123），即 ring3 当前无法使用临时源端口发包 |

---

## 5. SACK / OOO 队列当前实现要点（RFC 2018/6675 对照）

> 本节行为来自实现基线中的 net.c；其中仍未有独立运行证据的条目继续按本节和 §7 标记，不因代码已合入就自动视为 PASS。

### 5.1 SACK 协商

| 项 | 实现 | RFC 对照 | 证据 |
|---|---|---|---|
| 使能协商 | SYN 段收到 option kind=4 (SACK-Permitted)、len=2 → 置 `sack_ok=true`；本端 SYN/SYN-ACK 亦通告 SACK-Permitted（NOP,NOP,4,2） | RFC 2018 §3 协商 | net.c:365-368, 390-392 |
| 作用范围 | sack_ok 为连接级标志；后续每个 ACK 段解析 kind=5 块时要求 `!syn && c->sack_ok` | — | net.c:369 |

### 5.2 接收对端 SACK 块（发送侧记分）

每 ACK 先 `c->sack_n=0` 再解析（net.c:742-743），块登记规则（net.c:369-385）：

| # | 规则 | RFC 对照（代码注释自述） |
|---|---|---|
| 1 | option 合法性：kind=5、非 SYN、sack_ok、olen≥10 且 `(olen-2)%8==0` | RFC 2018 §3 块布局（每块 left(4B)+right(4B) 大端） |
| 2 | 逆序/空块（left ≥ right）丢弃 | — |
| 3 | 右端越过发送前沿 snd_nxt 丢弃 | RFC 6675 §6.2「校验并裁剪到本端发送窗口」（注释原文） |
| 4 | 完全过期块（right ≤ snd_una，即 DSACK 型区间）丢弃 | 注释：完全过期(DSACK 区间) |
| 5 | 部分过期块左端裁剪到 snd_una | 注释：前缘裁剪到 snd_una |
| 6 | 同一报文内重复块去重 | 注释：同一报文内重复块不重复登记 |
| 7 | **最多登记 2 块**（sack_left/right[2]，net.c:329） | RFC 2018 允许任意块数；2 为实现裁剪（对照：本端对外也只通告 ≤2 块，§5.4） |

### 5.3 发送侧 scoreboard 与丢失判定

结构：`tx[TCP_TX_SEG_MAX=8]` 记录每段 seq/len/sacked/lost/retransmitted（net.c:333-338）；段随 `tcp_xmit_pending` 发出而登记（tcp_tx_add，net.c:443-448），随累计 ACK 裁剪/回收（tcp_tx_ack 支持部分 ACK 裁前缘，net.c:449-464）。

| 机制 | 实现 | RFC/Linux 对照 | 证据 |
|---|---|---|---|
| sacked/lost 重判定 | **每个携带 SACK 的 ACK 都全量重算**所有段的 covered/lost 标记（不以旧标记累加） | RFC 6675 §4 以当前 SACK 集为准；对照 Linux tcp_sacktag_walk 同步重算；目的：对端 renege 撤销先前 SACK 时旧标记不得残留 | net.c:465-484 |
| HighAck | max(snd_una, 所有登记块右端最大值) | RFC 6675 HighACK 概念 | net.c:465-467 |
| lost 判定 | `lost = !covered && seg.seq < HighAck`（只测段**起点**） | ⚠️ 代码注释自述偏差：RFC 6675 定义为「HighAck 以下任一 un-SACKed 字节」；只测起点会漏掉 end==HighAck 的前缀洞段（头部未确认、尾部已 SACK），使恢复延迟到 RTO 而非选择性重传 | net.c:479-482 |
| 选择性重传 | 重传 lost && !sacked && !retransmitted 的段（每次调用至多一段），置 retransmitted 并 rearma RTO | RFC 6675 §5/§7 简化版（单段轮替，无 rescue/credit 机制——对照差距如实记录） | net.c:485-495 |
| RTO 兜底 | RTO 触发时 `tcp_tx_clear_marks` 清全部标记（"SACK is advisory; peer may renege after RTO"）+ Reno loss window 减半窗 + 全量重传 in-flight | RFC 6675 §5.2（RTO 后应保留 SACK 记分的完整做法未实现，此处保守清零） | net.c:496-498, 904-911 |
| 快速重传/恢复 | dupacks==3：loss window（ssthresh=max(2·MSS, in_flight/2)，cwnd=MSS）后进 fast_recovery（cwnd=ssthresh+3·MSS，recover_seq=snd_nxt）；期间 dupacks>3 做 cwnd inflation（+MSS）；ack≥recover_seq 时 deflate 退出；SACK 重传优先于新数据发送 | RFC 6582(Reno/F-RTO 前身) 风格简化；SACK-aware recovery 的 NewReno 细节未实现 | net.c:750-764, 767-783, 593-597 |
| ACK 推进 | 累计 ACK 移动 snd_una、压缩 sndb 缓冲、tcp_tx_ack 回收段；RTT 采样（srtt/rttvar， Karn 过滤 retransmitted 段）驱动动态 RTO（init 300ms/max 2.4s @100Hz，指数退避 ≤6） | RFC 6298 风格 | net.c:767-783, 583-592, 565-577 |
| 零窗口 | persist 探针：1B 探测段 + 指数退避（≤6 档） | RFC 793 persist 机制简化 | net.c:567-569, 883-890 |

### 5.4 本端生成 SACK 块（接收侧通告）

| 项 | 实现 | RFC 对照 | 证据 |
|---|---|---|---|
| 块来源 | 直接取自接收侧 **OOO 队列占用槽**（ooo[i].seq..seq+len），块数=min(占用槽数,2)；无独立 SACK 记分板 | RFC 2018 §4（SACK 块应反映乱序数据排队情况——本实现以 OOO 队列为准，一致但粒度受限） | net.c:389-394 |
| 编码 | NOP,NOP,5,len + ≤2 块，尾部 NOP padding 至 4 字节对齐 | RFC 2018 §3 | net.c:392-394 |
| 时机 | 携带 ACK 标志的输出段均可能附带（tcp_build_opts 在 tcp_put_pkt 统一挂接） | — | net.c:641-645 |

### 5.5 接收侧 OOO 队列

结构：`ooo[2]`（seq/len≤MSS/data/used）+ 总量计数 `ooo_bytes`（`net/net_internal.h`）。

| 函数 | 规则 | 对照 | 证据 |
|---|---|---|---|
| `tcp_queue_ooo` | 拒绝：len==0、len>MSS、总量超 TCP_BUF_SIZE、右端不越过 rcv_nxt（完全过期）、与其他槽重叠；跨界段裁掉已确认前缘后入槽；槽满返回 false（调用方重发 rcv_nxt ACK） | Linux tcp_data_queue 入队前的 overlap 检查 | net.c:423-430 |
| `tcp_merge_ooo` | 循环整理直到不动点：① 完全过期段整体丢弃（防槽位泄漏）；② 部分重叠段裁剪前缘；③ seq==rcv_nxt 且接收缓冲有空间 → 级联交付（rcv_nxt 前推）；**缓冲满则留在 OOO 等应用读走**（不丢弃） | Linux tcp_ofo_queue/tcp_data_queue 的 prune（注释自述） | net.c:397-422 |
| `tcp_accept_data` | 统一入口：seq≠rcv_nxt 一律交 OOO 裁决（过期/重复/部分重叠被拒后由调用方重发当前 rcv_nxt 的 ACK）；按序段直接追加接收缓冲并触发 merge | — | net.c:431-437 |
| 调用点 | SYN_RECEIVED/ESTABLISHED 等 data 段处理；接受成功打 `out-of-order cached` 日志，拒绝打 `duplicate/overlap, re-ACK` | — | net.c:800, 807-815 |
| 上限行为 | 4 槽占满或总量超限时新乱序段被拒（仅重 ACK），等待应用读取释放 rxb 后才能级联交付 | RFC 2018 要求接收方不因 SACK 丢乱序数据；超限拒绝为本实现的资源约束（对照差距如实记录） | net.c:424, 417, 427-429 |

### 5.6 SACK 边界测试入口（内核内置）

TCP :81 演示服务在 ESTABLISHED 后一次性排队 16×90B=1440B（16 段 > scoreboard 上限 8），用于触发「上限截断/ACK 回收/双缺口」路径（net.c:863-881，改动说明见 diff 注释）。仓库根存在 qemu-sack-edge-t1~t6 运行日志，其结论不在本文档任务范围（NOT_TESTED，§7）。

---

## 6. 已知限制（缺口编号登记）

> 按任务要求**引用/记录缺口编号而不展开细节**。编号体系出处：`/tmp/cat-os-tests/README.md` 所引用的阶段 4 预检缺口清单；其中部分编号可在仓库源码注释与测试骨架注释中定位到对应主题，其余仅登记。

| 编号 | 主题（可考者） | 本文档内的对应位置 | 登记依据 |
|---|---|---|---|
| **H1** | 用户指针非法族 EFAULT（kernel ptr/NULL/未映射页/越界尾须报 EFAULT；边界内合法指针不得误报） | ABI 文档 §6 | `/tmp/cat-os-tests/user_ring3_socktest.c:99-100,202-214`（H1P/H1B 探针名） |
| **H2** | TCP bind 同端口语义：当前冲突返回 `-EADDRINUSE`，不再静默「附着」 | 本文 §4.1 | `net/net.c` bind 分支；网络回归资料与 `docs/TEST_MATRIX.md` |
| **M1** | 仅登记 | — | 仓库源码注释未见定义（待核实） |
| **M2** | 错误码区分性：底层裸 `-1` 哨兵混叠 EMSGSIZE/EADDRNOTAVAIL/EAGAIN；UDP payload 上限预检；UNBOUND sendto 显式拒绝 | 本文 §3.2-3.4；ABI 文档 §5.1/§5.3 | syscall.c:3,15-29,41-60,116-127 |
| **M3** | 仅登记 | — | 仓库源码注释未见定义（待核实） |
| **M4** | 仅登记 | — | 仓库源码注释未见定义（待核实） |
| **L1** | listen-before-bind 得 `-EINVAL`（缺 autobind） | 本文 §4.2 | syscall.c:86-98（TODO(code2)(L1)）；net.c:538-539 |
| **L2** | fd 分配策略（std 流占 0-2 + 最低空闲分配 + kind 隔离） | ABI 文档 §7（已在 code7 落地） | vfs.c:7-77 |
| **L3** | 仅登记 | — | 仓库源码注释未见定义（待核实） |
| **L4** | 仅登记 | — | 仓库源码注释未见定义（待核实） |
| **L5** | 仅登记 | — | 仓库源码注释未见定义（待核实） |
| **L6** | 零长缓冲误报 EFAULT（已修复：n==0 放行） | ABI 文档 §6.1 | paging.c:330-356（L6/code6 修复注记） |
| **L7** | 仅登记 | — | 仓库源码注释未见定义（待核实） |
| **L8** | close 双重别名关系文档化（nr=6/28；nr=3 为 read） | ABI 文档 §3.3（别名已移除） | commit `289e9ce`；当前 syscall/VFS close 路径 |

附注：`/tmp/cat-os-tests/README.md` 还出现缺口编号 C3（port 7 双重行为）、C7（无 ICMP unreachable）、D1（与 H2 同源的 TCP 附着语义）及 backlog 探针 A/B 两态记录，不在本任务指定登记范围（H1/H2/M1-M4/L1-L8），此处仅存目。

**本文档可直接核实的其他已知限制**（非编号体系，均为代码注释/结构自明事实）：

| 限制 | 证据 |
|---|---|
| 无 connect，ring3 不能主动外连 TCP | §4.4 |
| recvfrom 报文超长静默截断且余量丢弃，无 MSG_TRUNC 等价上报 | net.c:308；TODO 见 syscall.c:141-142 |
| tcp_send 缓冲满返回 `-EAGAIN`；部分写仍需调用方推进游标 | `net/net_tcp.c:799-817`；`kernel/syscall.c` send 分支 |
| net_socket_close 对 CLOSED 型返回 -EBADF 且 fd 滞留 | net.c:554；syscall.c:184-187 |
| lost 判定漏前缀洞（end==HighAck 场景延迟到 RTO） | net.c:479-482 注释自述 |
| SACK 登记块上限 2 / scoreboard 段上限 8 / OOO 槽上限 2，超限降级为普通重 ACK | `net/net.h:90-96`、`net/net_tcp.c` |
| UDP 校验和恒为 0 不计算 | net.c:233 |
| TIME_WAIT 固定 2s，无按 MSAS 协商 | net.c:825（注释 "2s"）、862 |
| ISN 生成器为静态递增初值（非随机） | net.c:30, 712 |
| ARP 缓存固定 8 表项（ARP_CACHE_MAX） | net.c:46-48 |

---

## 7. NOT_TESTED 与待核实清单

| # | 条目 | 状态 | 说明 |
|---|---|---|---|
| N1 | 本文大部分行为条目 | **以静态读码为主** | nginx r4 与独立复验只覆盖 poll、TCP 被动服务、accept 地址出参、静态 FAT16 读取及 shell 辅助命令；不覆盖完整 socket ABI |
| N2 | §5 SACK/OOO/scoreboard 加固行为（历史工作区改动） | **已由后续 QEMU inject 套件覆盖** | `docs/TEST_MATRIX.md` 记录 2026-08-26 run_all ALL GREEN；本文不重复计算套件断言 |
| N3 | 旧 ring3 socket 断言骨架运行时结果 | NOT_TESTED | `/tmp/cat-os-tests/user_ring3_socktest.c` 仍未接线；仓库内 stage4 `user_sock_abi` 已有 85 PASS / 0 FAIL / 4 skip，但不是同一骨架 |
| N4 | `TCP_RX_WINDOW(65535)` 现网用途 | 待核实 | 定义于 net.h:68；实际通告窗口为动态值（net.c:643），未见该宏参与计算 |
| N5 | M1/M3/M4/L3/L4/L5/L7 缺口语义 | 待核实 | 仓库与 /tmp/cat-os-tests 内均未检索到逐条定义；以协调者持有的缺口清单为准 |
| N6 | ring3 accept 的 `sockaddr_in` 出参 | **nginx r4 与独立复验已覆盖最小路径** | `kernel/syscall.c` accept 分支将 peer 地址写回用户缓冲；底层 helper 仍不是 ring3 直接 ABI |
| N7 | backlog 探针 A（排空）/B（RST）两态的实测归类 | NOT_TESTED | README 记录为「信息级」，结论未纳入本文档 |

---

*文档结束。主体为 2026-08-25/26 socket API 快照；当前容量值和 nginx 相关 ABI 关系回填于 2026-08-28。当前回填只更新文档，不修改源码。*
