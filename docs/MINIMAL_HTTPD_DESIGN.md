# Cat-OS 最小 HTTP 服务器设计（MINIMAL_HTTPD_DESIGN）

> **任务**：code3 并行任务 · 设计文档（nginx 移植的中间步骤，配套 `NGINX_PORT_ANALYSIS.md` §5 阶段 2）。
> **基线**：同 NGINX_PORT_ANALYSIS.md（工作区 HEAD=`6796bd6` + 未提交改动，行号均为实测）。
> **约束**：本文为设计稿，不附带任何源码；所有引用的现状能力均标注依据行号，未证实处标 🔍待验证。

---

## 目录

1. [目标与非目标](#1-目标与非目标)
2. [为什么它是 nginx 移植的正确中间步骤](#2-为什么它是-nginx-移植的正确中间步骤)
3. [总体架构](#3-总体架构)
4. [模块详细设计](#4-模块详细设计)
5. [主循环与系统调用逐条对照](#5-主循环与系统调用逐条对照)
6. [静态内容来源：三档实现策略](#6-静态内容来源三档实现策略)
7. [已知限制与边界行为](#7-已知限制与边界行为)
8. [验收标准](#8-验收标准)
9. [向阶段 3/4 的演进路径](#9-向阶段-34-的演进路径)

---

## 1. 目标与非目标

**目标**

| # | 目标 | 判据 |
|---|---|---|
| O1 | ring3 单进程 HTTP/1.0-ish 静态文件服务器 | curl 可取回页面 |
| G2 落点 | 完整跑通「socket→bind→listen→accept→recv→send→close」ring3 全链路 | QEMU hostfwd 套件纳入回归 |
| O3 | 为事件框架（NGINX_PORT_ANALYSIS R4）提供真实负载发生器与行为基线 | 并发/异常场景脚本化 |
| O4 | 暴露现有 ABI 在"服务器型负载"下的全部痛点清单 | 缺口回填至缺口编号体系 |

**非目标（刻意不做）**

- ❌ 多进程/多 worker（属 nginx 特性，阶段 3）
- ❌ keep-alive、pipelining、chunked（HTTP/1.1 高级特性；响应固定 `Connection: close`）
- ❌ CGI/proxy/upstream（依赖 connect=Y1 与 fork=R1）
- ❌ 动态路由、TLS
- ❌ 高并发（受 TCP 连接表 16 上限硬约束，见 §7）

---

## 2. 为什么它是 nginx 移植的正确中间步骤

1. **几乎零前置依赖**。所需系统调用全部落在绿档（G1-G4）：nr=20..28 socket 组 + nr=1 write。对照 NGINX_PORT_ANALYSIS §3.1，无需等待黄档任何一项即可开工——唯一的软依赖是静态内容来源（§6 提供三档策略，最低档连 romfs 都不用）。
2. **它是 nginx 的功能子集参照物**。nginx 移植完成后的第一个对照测试就是：同一请求序列在 httpd 与 nginx 上行为一致。
3. **它把"轮询式 accept"的痛提前暴露**。当前 accept 无连接返回 -EAGAIN（syscall.c ACCEPT 分支），单进程只能忙等或睡 tick——这正是催生 R4 事件框架的第一手需求证据。
4. **风险隔离**。httpd 是纯 ring3 用户程序（ELF 经 nr=11 exec 加载，syscall.c sys_exec），不碰内核一行代码，符合并行任务纪律。

---

## 3. 总体架构

```
┌─────────────────────────── Cat-OS 内核（不改动） ───────────────────────────┐
│  IRQ0@100Hz ticks ──► net_poll() ──► e1000 收包 ──► TCP 状态机(net.c)        │
│                                          │ ESTABLISHED 入 conn 表            │
│  int 0x80 分发(interrupts.c:31) ◄────────┘                                  │
└──────────────┬──────────────────────────────────────────────────────────────┘
               │ nr=20..28（house ABI 五参寄存器约定）
┌──────────────▼──────────────────────────────────────────────────────────────┐
│  httpd.elf（ring3，经 nr=11 exec 加载，栈 @0x701000，elf.h:31）              │
│                                                                             │
│   main:                                                                     │
│     lfd = socket(STREAM)          ; nr=20                                   │
│     bind(lfd, 80)                 ; nr=21                                   │
│     listen(lfd, 16)               ; nr=22（backlog 上限即 TCP_MAX_CONNS）   │
│   loop:                                                                     │
│     cfd = accept(lfd)            ─┐ nr=23；-EAGAIN 时 yield/sleep（§4.2）   │
│     n = recv(cfd, reqbuf, N)      ; nr=27；读满 \r\n\r\n 或 EOF             │
│     parse_request_line()          ; 纯用户态字符串解析                       │
│     resp = lookup(path)           ; §6 三档内容源                            │
│     send(cfd, header+body)        ; nr=26 循环部分写直至写尽                  │
│     close(cfd)                    ; nr=28 → FIN                              │
│   end loop                                                                  │
└─────────────────────────────────────────────────────────────────────────────┘
```

**进程模型**：单进程单线程。无并发服务能力——同一时刻只处理一个连接；其余连接停留在内核 backlog/conn 表中（容量上限见 §7-L1）。这是刻意的：把复杂度全部推迟到阶段 3。

---

## 4. 模块详细设计

### 4.1 socket 封装层（`sock.h`，用户态内联包装 int 0x80）

按 docs/RING3_SYSCALL_ABI.md §2 的调用约定生成：

```c
static inline long sys(long nr, long a, long b, long c, long d, long e) {
    long r; /* eax=nr, ebx=a, ecx=b, edx=c, esi=d, edi=e, int 0x80 */
    __asm__ volatile("int $0x80"
        : "=a"(r)
        : "a"(nr), "b"(a), "c"(b), "d"(c), "S"(d), "D"(e)
        : "memory");
    return r;
}
/* sock(STREAM)=sys(20,1,0,0,0,0)；bind(fd,port)=sys(21,fd,port,...)；以此类推 */
```

注意点（均有 ABI 文档背书）：
- 返回值负数为 -errno，直接判 `< 0`（RING3_SYSCALL_ABI.md §2）；
- a[5] 不存在，五参封顶——house ABI 无 sockaddr 结构，bind 直传端口号；
- close 必须走 **nr==28**（唯一 socket-aware 路径），绝不可用 nr==6/nr==3 关 socket（vfs_close 对 FILE_SOCKET 返 -EBADF 且 L8 别名有 read 冲突隐患，RING3_SYSCALL_ABI.md §3.3）。

### 4.2 accept 轮询与让出策略

accept 空队列返回 `-EAGAIN`（syscall.c ACCEPT 分支契约）。三种让出策略按优先级：

| 策略 | 实现 | 适用 |
|---|---|---|
| A（首选） | nanosleep/tick sleep —— **依赖 Y6 未落地，暂不可用** 🔍待验证 | 阶段 1h 之后 |
| B（现状可用） | `sched_yield` 语义缺失于 ring3（无对应 syscall！）→ 退化为短忙等：连续 EAGAIN 计数每 N 次插入一次空循环或读 /dev/zero 软化 | 当前 ABI 即可 |
| C | 直接忙等 spin（最简单，烧 CPU 但 QEMU 单核下无害） | 最小可行版 |

> ⚠️ 发现的新缺口（回填建议）：ring3 目前**没有 yield/nanosleep 类 syscall**（编号表 20-30 与 VFS 组均无），协作式调度对 ring3 不可触发——httpd 一旦进入忙等就独占 CPU 直到下一个外部中断。此缺口建议登记为 **Y6'（ring3 yield/nanosleep syscall）**，并列入阶段 1h。

### 4.3 接收与请求解析

- 缓冲区：栈上 `char req[2048]`（用户栈共 1 页 4KB @0x700000-0x701000，elf.h:30-31——缓冲不得超过 ~2KB 以留运行栈余量，否则需 elf_load 扩栈页，登记为可选增强）。
- 读循环：`recv` 直到出现 `\r\n\r\n` 或 EOF 或超计数上限（防慢速攻击占死唯一服务槽）。
- 解析范围**仅请求行**：`METHOD SP PATH SP VERSION CRLF`。方法白名单 {GET, HEAD}；PATH 归一化：拒绝含 `..`、长度 >256、非 `/` 开头 → 统一 400。其余头部**跳过不解析**（Host/UA 等对本服务无语义）。
- 版本宽容：`HTTP/1.0`、`HTTP/1.1`、甚至缺省版本（curl 默认 1.1，兼容即可）。

### 4.4 响应生成

```
HTTP/1.0 200 OK\r\n
Content-Type: <按扩展名查 4 项迷你 mime 表>\r\n
Content-Length: <n>\r\n
Connection: close\r\n
\r\n
<body>
```

- 发送：header 与 body 若能拼入一个 ≤1460B（TCP_MSS，net.h:69）缓冲则一次 send；否则先发 header 再循环 send body——**必须处理部分写**：tcp_send 是收缩式部分写语义（net.c:945-954），且缓冲满可返回 0（TODO(code2) 已知歧义），发送侧以「进度游标 + 总尝试上限」推进，超限即放弃关闭（宁可截断不可死循环）。
- 错误页：404/400/405/503 固定内嵌字符串。
- HEAD：与 GET 同解析，仅丢弃 body 保留 Content-Length。

### 4.5 日志

stdout（fd=1，/dev/console，vfs.c vfs_init 装 0-2）单行访问日志：
`[httpd] peer=<由 accept 无法获得对端地址，见下> path=/ len=200`

> ⚠️ 新缺口（回填建议）：house ABI 的 accept **不返回对端 IP/端口**（SOCKET_API.md §4.3：底层 tcp_accept(s,&ip,&port) 有此能力 net.c:929-943，但五寄存器限制下 syscall 层未透出）。日志只能记 fd。改进项：新增 nr 或复用 getpeername 语义——列入阶段 3e 白名单。

---

## 5. 主循环与系统调用逐条对照

| 步骤 | syscall (nr) | 参数映射（house ABI） | 失败处理 | 依据 |
|---|---|---|---|---|
| socket | 20 | a0=1(SOCK_STREAM) | <0 → 写 stderr 死循环退出 | syscall.c SOCKET case |
| bind | 21 | a0=lfd, a1=80 | -EADDRINUSE/-EINVAL → 报错退出（H2 修复后冲突可正确报错） | syscall.c BIND case |
| listen | 22 | a0=lfd, a1=16 | <0 → 报错退出 | syscall.c LISTEN case |
| accept | 23 | a0=lfd | -EAGAIN → §4.2 让出策略；其他 <0 → 报错退出 | syscall.c ACCEPT case |
| recv | 27 | a0=cfd, a1=req, a2=len | 0=EOF（半开请求）→ 断开重收下一连接；-EAGAIN → 让出后重试；<0 其他 → close 继续 | net.c:957-969 契约 |
| send | 26 | a0=cfd, a1=buf+off, a2=remain | ≥0 推进游标；0 → 计数退避重试；<0 → 放弃 close | net.c:945-954 部分写契约 |
| close | 28 | a0=cfd | <0 记录但不中止主循环 | syscall.c CLOSE case |

**状态机健壮性**：任一连接处理路径上的任何失败都收敛到「close(cfd) + 回到 accept」，绝不 exit 主进程——单进程模型的存活即服务可用性。

---

## 6. 静态内容来源：三档实现策略

| 档 | 方案 | 前置依赖 | 说明 |
|---|---|---|---|
| L0 内嵌镜像 | httpd ELF 自带 `.rodata` 页面（如 `/index.html` 一个页面 + favicon 占位）；path→内置符号查表 | **零依赖，当前即可做** | 编译期 `xxd -i` 注入，先例同 shell_bin.h 嵌入模式（syscall.c weak 符号分支） |
| L1 参数化内存盘 | 启动时从某处读若干文件进堆/静态区 | 同上 | 意义不大，L0 足够演示 |
| L2 romfs 只读挂载 | 内核 romfs on IDE（Y11）+ vfs_open/read/lseek 打通 VFS_REG | 阶段 1i | 真正意义的静态站点；同时打通 nginx.conf 读取通路，是阶段 3f 的前置 |

**建议**：先交付 L0（当天级工作量），L2 作为阶段 1i 的验收应用（"romfs 挂载成功 = httpd 能列出目录页"）。

---

## 7. 已知限制与边界行为

| # | 限制 | 根因（证据） | 影响 |
|---|---|---|---|
| L1 | 并发 ≤16 连接（实际有效并发=1 服务 + backlog 排队） | TCP_MAX_CONNS=16（net.h:67）；backlog 满 SYN→RST（net.c:708-711） | 压测工具并发参数须 ≤15 |
| L2 | 单请求体上限：只支持"头小请求"，无 body 读取 | 设计取舍（§4.3） | POST 一律 405 |
| L3 | 单次 send 有效载荷 ≤1460B，大响应多次 send | TCP_MSS=1460（net.h:69）、tcp_send clamp（net.c:948） | 发送游标逻辑必测 |
| L4 | 发送缓冲 4096B：响应大于 4KB 时 tcp_send 会收缩返回 | TCP_BUF_SIZE=4096（net.h:70）；net.c:949 | 游标推进必须容忍"一次只吞几百字节" |
| L5 | 无对端地址可见性 | house ABI accept 无出参（SOCKET_API.md §4.3） | 日志降级（§4.5） |
| L6 | 忙等能耗 | 无 ring3 yield/sleep syscall（§4.2 新缺口 Y6'） | QEMU 无碍；真实硬件费电 |
| L7 | 用户栈仅 4KB | elf.h:30-31 单栈页 | 解析缓冲+局部变量预算 ≤2KB；溢出即 #PF（现网大概率 panic，无 page fault handler） |
| L8 | TIME_WAIT 2s × 连接表 16 | net.c TIME_WAIT 定长（SOCKET_API.md §3.6） | 快速重启压测可能耗尽连接表 → RST，测试脚本需间隔 |

---

## 8. 验收标准

| # | 用例 | 通过判据 | 工具 |
|---|---|---|---|
| A1 | 冒烟 | `curl -s http://127.0.0.1:18080/` 返回 200 + 内嵌正文 | /tmp/cat-os-tests/qemu_run.sh（hostfwd 18080→80 已就绪） |
| A2 | 404/400/405 | 非存在路径/畸形请求行/POST 各返回对应码 | curl --data / 手工 nc |
| A3 | 顺序多连接 | 10 个串行请求全部成功，无 fd 泄漏（串口无 EMFILE） | for 循环 curl |
| A4 | backlog 边界 | 并发 14 连接：被服务前不 RST；并发 20：超额收到 RST 属预期 | python asyncio 探针 |
| A5 | 半开容错 | 发一半请求后断开，服务器回收 cfd 并继续服务下一请求 | nc 手工 |
| A6 | 大响应 | ≥8KB 响应完整到达（校验 md5） | curl | md5sum |
| A7 | 长稳 | 1000 请求串行打完，串口无 panic/[NET] error 持续增长 | ext_socktest.py 扩展用例 |

A1-A7 全部通过后，将 httpd 注册为阶段 2 出口里程碑，并把过程中确认的缺口（Y6'/getpeername 等）回填 NGINX_PORT_ANALYSIS.md 黄档表。

---

## 9. 向阶段 3/4 的演进路径

```
httpd v1（本文档，L0 内嵌内容，忙等 accept）
   │  + Y6'  yield/nanosleep syscall
   ├─► httpd v1.5：睡眠式 accept（CPU 让出，行为仍串行）
   │  + Y11  romfs/VFS_REG + lseek/stat
   ├─► httpd v2：真静态站点（目录列表、mime.types 文件化）——阶段 1i 验收载体
   │  + R4   内核 poll() 语义事件接口
   ├─► httpd v3：单进程事件驱动（poll 就绪集驱动 N 连接并发）——R4 的验收载体，
   │             结构上已等价于「nginx event engine 的骨架」
   │  + R1/R3/R5-min ……
   └─► nginx 1.26 移植（configure --with-poll_module --without-sendfile 起）
```

每一级演进都**复用上一级的请求解析/响应生成代码**，保证回归资产连续累积；v3 的事件循环代码结构将直接映射 nginx `ngx_process_events_and_timers` 的形态，为 shim 层编写提供活样例。

---

*文档结束。生成者：Cat-OS 并行任务 code3。约束遵守声明：本任务仅新建 `docs/MINIMAL_HTTPD_DESIGN.md` 与 `docs/NGINX_PORT_ANALYSIS.md`；未修改任何既有 `.c/.h/.md`；未触碰 usermode.c / OSDEV_PROJECT_NOTES.md / NEXT_TASKS_AUTONOMOUS.md；未执行 push/reset/rebase/delete。*
