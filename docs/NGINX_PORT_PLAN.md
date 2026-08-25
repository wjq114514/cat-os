# Cat-OS NGINX 移植实施设计（NGINX_PORT_PLAN）

> **任务**：code3 外围新功能 · NGINX 移植**可执行实施设计**。承接 `docs/NGINX_PORT_ANALYSIS.md`（预研：差距矩阵 G/Y/R 三档）与 `docs/MINIMAL_HTTPD_DESIGN.md`（httpd 设计稿），本文回答"**按什么顺序做、动哪些文件、怎么验收**"。
> **版本基线**：基于 **HEAD=`6796bd6`**（"net: harden tcp sack edge cases"）**+ 工作区未提交变更**（含 code4 在 `net.c` 的加固、code2 的 exec/wait 链路、code7 的 fd 分配、code9 的 libc、code10 的 tests/ 入库）。文中行号均为**当前工作区实测行号**，合入提交后会漂移。
> **硬约束**：本任务**只读源码 + 只写本文档**，零 `.c/.h/.md` 改动；禁止触碰 `net.c`（code4 锁）、`usermode.c`/`OSDEV_PROJECT_NOTES.md`（用户区）、`kernel.c`/`process.c`/`elf.c`/`shell_bin.h`/`shell_user.c`（shell 方向）、`docs/` 下既有四份文档（code8 交付，可引用不可改）；未执行 commit/push/reset/rebase/delete。
> **状态标记**：✅实测 = 本文作者已读码证实；🔗引用 = 转引自前置文档（未重复核实）；🔍待验证 = 合理推断未运行复现。

---

## 目录

1. [输入清单与阅读记录](#1-输入清单与阅读记录)
2. [现状盘点：能力 vs nginx 最小需求](#2-现状盘点能力-vs-nginx-最小需求)
3. [分层移植路线（Step 1→4）](#3-分层移植路线step-14)
4. [风险清单](#4-风险清单)
5. [与并行进度的衔接（文件锁矩阵）](#5-与并行进度的衔接文件锁矩阵)
6. [NOT_TESTED 清单](#6-not_tested-清单)

---

## 1. 输入清单与阅读记录

| # | 文件 | 工作区状态 | 本次使用方式 |
|---|---|---|---|
| I1 | `NGINX_PORT_ANALYSIS.md`（根目录同名文档已迁至 `docs/`） | 既有（03:07 产出） | 差距矩阵 G1-G11/Y1-Y13/R1-R10、决策点 D1-D7 直接沿用其编号 |
| I2 | `docs/MINIMAL_HTTPD_DESIGN.md` | 既有（03:10 产出） | Step 3 的 httpd 应用层设计直接落地为其 §3-§6 方案 |
| I3 | `docs/SOCKET_API.md` | 既有（code8） | 各 syscall 行为契约、缺口编号体系出处 |
| I4 | `docs/RING3_SYSCALL_ABI.md` | 既有（code8） | int 0x80 五参约定、EFAULT 审计口径（未全文复读，按引用使用）|
| I5 | `net.c`（1079 行） | **已修改·未提交（code4 加固）** | 全文精读；行号引用见各节 |
| I6 | `syscall.c`（365 行）/ `syscall.h` | 已修改·未提交 / 未修改 | 全文精读 |
| I7 | `tools/net-test.py`（78 行） | 未跟踪 | 黑盒注入测试范式参考 |
| I8 | `tests/`（qemu_run.sh、net_suite.py、wire_lib.py、run_all.sh） | 未跟踪（code10 入库） | 验收基建：slirp hostfwd 端口表、socket-netdev 注入模式 |
| I9 | `vfs.c`/`vfs.h`、`elf.h`、`process.c`/`process.h`、`interrupts.c`、`Makefile` | 混合（多为已修改·未提交） | 关键行号定点核实（fd 表、ELF 栈、调度五态、tick 驱动、构建规则）|

---

## 2. 现状盘点：能力 vs nginx 最小需求

### 2.1 现有网络/系统能力全景（✅实测）

**socket 组系统调用面**（`syscall.h:16-26`，分发于 `syscall.c:241-362`）：

| nr | 名称 | 状态 | 关键契约（底层依据） |
|---|---|---|---|
| 20 | socket(type) | ✅可用 | STREAM/DGRAM 白名单；表满 `-EMFILE`（syscall.c:241-249；net.c:653-656） |
| 21 | bind(fd,port) | ✅可用 | house ABI 无 sockaddr，直传端口号；冲突 `-EADDRINUSE`（**工作区 H2 已修**，net.c:526）；port==0 `-EINVAL`（net.c:511-535） |
| 22 | listen(fd,backlog) | ⚠️有缺口 | 未 bind 先 listen → `-EINVAL`（**L1 缺口**，syscall.c:261-268 TODO）；backlog>16 截断（net.c:553-559） |
| 23 | accept(fd) | ✅可用 | 非阻塞语义空队列 `-EAGAIN`；**不返回对端地址**（五寄存器限制；带出参版 `tcp_accept` net.c:990-1004 仅内核内路径） |
| 24 | sendto（UDP） | ✅可用 | len>1472 `-EMSGSIZE`；UNBOUND `-EADDRNOTAVAIL`（syscall.c:279-298） |
| 25 | recvfrom（UDP） | ✅可用 | 出参不可省略（严于 Linux）；超长静默截断（syscall.c:300-311） |
| 26 | send（TCP） | ✅可用 | 仅 ESTAB 否则 `-ENOTCONN`；部分写收缩语义；**收缩到 0 返回 0**（歧义，net.c:1006-1016） |
| 27 | recv（TCP） | ✅可用 | EOF=0（CLOSE_WAIT/LAST_ACK/TIME_WAIT 且缓冲空）；无数据 `-EAGAIN`（net.c:1018-1030） |
| 28 | close（socket-aware） | ✅可用 | 唯一 socket 关闭路径；CLOSED 型返 `-EBADF` 且 **fd 滞留不释放**（net.c:568-571，审计附注 TODO） |
| 29/30 | ping/ping_stats | ✅可用 | 与 HTTP 无关 |

**VFS 组**（nr<20 经 `vfs_syscall`，vfs.c:78-92）：0=read / 1=write / 5=open / **6=close / 3=close 别名（L8）**。devfs 仅 `/dev/{null,console,kbd,zero,urandom}` 五节点（vfs.c:20），**无常规文件**；fd 表容量 32（vfs.h:4），std 流占 0-2（vfs.c:34-42）。

**进程组**（nr=11..13，syscall.c:214-220 前置拦截）：11=exec（嵌入镜像分支仅认 `"/bin/shell"` + weak 符号，syscall.c:54,163-168；VFS 分支在纯 devfs 下 open 必败；镜像缓冲上限 `CATOS_EXEC_IMG_MAX=32768` syscall.c:137）；12=exit（status 无处存储）；13=wait（**stub 恒 `-ECHILD`**，syscall.c:207-212）。无 yield/nanosleep/fork/setsockopt/getpeername 编号。

**TCP 栈能力**（net.c）：被动开放全链路（SYN→SYN_RECEIVED→ESTABLISHED，net.c:740-790）；SACK≤2 块/OOO 4 槽/scoreboard 8 段/NewReno 风格拥塞控制（net.c:366-509）；动态 RTO 300ms~2.4s + persist 探针（net.c:580-618,949-959）；优雅关闭 FIN_WAIT/LAST_ACK/TIME_WAIT 200 ticks（net.c:858-919）。主动开放 connect **不存在**（`TCP_SYN_SENT` 仅枚举预留，net.h:62-65；公共 API 无声明，net.h:107-118）。

**收包驱动模型**：唯一驱动力是 IRQ0@100Hz → `timer_handler` → `net_poll()`（interrupts.c:23,26）→ `e1000_poll()+tcp_tick()`（net.c:1067）；e1000 **无 RX 中断注册**。`net_napi_poll()` 已存在但只是 `e1000_poll()` 直通包装（net.c:1065）——Step 4 的现成挂名点。

**工作区未提交加固（code4，合入前属"半成品"状态）**：H2 修复（bind 冲突返 -98，net.c:519-526）、M1 R2 重传放弃（SYN 3 次/数据 5 次，net.c:587-588,961-985）、M3 盲 RST 防御 challenge-ACK（net.c:789-800）、TIME-WAIT 化身替换（net.c:724-737）、scoreboard 满合并降级（net.c:450-461）。**本文所有"缺口已修"结论以此工作区状态为准，未提交前不得视为主干保证。**

### 2.2 nginx 最小需求对照（accept/read/write/close/setsockopt 等）

nginx 处理**一个静态 GET** 的最小内核需求序列 vs Cat-OS 现状：

| # | nginx 需求（ngx_*_module 对照见预研 §3） | Cat-OS 现状 | 判定 | HTTP 场景后果 |
|---|---|---|---|---|
| N1 | socket(AF_INET,SOCK_STREAM) | nr=20 ✅ | 绿 | — |
| N2 | setsockopt(SO_REUSEADDR) **在 bind 前** | **无 nr**，完全缺失 | **红（可桩化）** | nginx 标准初始化序列第一步即失败；shim 层必须 no-op 返 0，且依赖 H2 修复保证重复 bind 报错而非附着 |
| N3 | bind(addr:port) | nr=21 ✅（无 sockaddr 结构） | 绿（需 shim 翻译） | — |
| N4 | listen(backlog) | nr=22 ⚠️ L1 | 黄 | nginx 先 bind 后 listen，可绕过；backlog 期望 511 实际截 16 |
| N5 | **accept4/accept** | nr=23 ✅ 非阻塞原生 | 绿 | 无对端地址出参 → `$remote_addr`/日志/access 模块降级 |
| N6 | read/recv | nr=27（socket）/nr=0（文件）✅ | 绿 | 文件读依赖 Step 2 romfs |
| N7 | writev（响应头+体合并写） | **缺失** | 黄 | shim 层拼接单缓冲替代（首响应 ≤MSS 时无损） |
| N8 | write/send | nr=26 ✅ 部分写 | 绿 | 返回 0 歧义（M2 关联）需发送游标兜底 |
| N9 | **close** | nr=28 ✅；⚠️ nr==3 是 close 别名（L8） | 黄 | 按 Linux ABI 写的代码 `read(fd=3)` 会**误关 fd**——移植前必修（预研 D4） |
| N10 | setsockopt(TCP_NODELAY/SO_SNDBUF…) | **无 nr** | 红（白名单桩） | NODELAY 可 no-op（栈即时发送）；其余 `-ENOPROTOOPT` |
| N11 | epoll_wait（事件引擎心脏） | **无任何就绪通知机制** | **红（最大单体工程=R4）** | 见 Step 4 |
| N12 | fcntl(O_NONBLOCK) | 缺失（socket 天生非阻塞） | 黄（桩化返 0） | — |
| N13 | 文件系统（nginx.conf/html/mime.types/error.log） | devfs 无常规文件 | **红→黄（romfs 后）** | Step 2 前置 |
| N14 | fork/spawn worker、kill/signal、shm、rlimit、setuid | 全缺 | 红（预研 R1/R3/R5/R8-R10） | 最小场景整体回避：单进程模式 |

**结论**：nginx "最小可启动集" 的分水岭仍是预研 §4 四件事（R4 事件 + fork + fs + 信号子集）；但在到达 nginx 之前，**四个中间里程碑（Step 1-4）每一步都能在当前或近期能力内闭环验收**——这正是分层路线的意义。

---

## 3. 分层移植路线（Step 1→4)

### 总览

```
Step 1 内核态 httpd 雏形      ← 零新 syscall、零锁区改动（新文件+挂接点2行）
Step 2 静态文件服务（romfs）   ← 依赖 vfs 解锁；httpd 代码不变，内容源升级
Step 3 ring3 独立 httpd 进程   ← 依赖 exec 通路泛化；复用 Step1/2 的协议代码
Step 4 napi 风格事件循环骨架   ← 依赖 code4 提交 + 多个热区统筹；通往 nginx R4
```

每一级**复用上一级**的请求解析/响应生成代码（文本级拷贝即可，无 libc 依赖），回归资产连续累积。

### 端口规划（贯穿四步，避免撞车）✅实测依据

`net_init` 已占用：TCP :80、TCP :81（内核演示监听）、UDP :7（net.c:1069-1079）。H2 修复生效后，**ring3 再 bind(80) 必然 -EADDRINUSE**（net.c:526）。而 code10 的 `tests/qemu_run.sh` slirp 模式 hostfwd 表为：**18080→guest:80、18081→guest:81、18099→guest:9999、17007→udp:7、17000→udp:7000**（qemu_run.sh NETARGS，✅实测）。

| 阶段 | 服务 | 监听端口 | 宿主机验收入口 | 是否需改测试基建 |
|---|---|---|---|---|
| Step 1/2 | 内核态 httpd | **TCP :9999** | `curl 127.0.0.1:18099` | **否**（现成 hostfwd） |
| Step 3 | ring3 httpd | **TCP :7000**（避开全部已占端口） | 需 hostfwd tcp→7000 | **是**：qemu_run.sh 追加一条 hostfwd（code10 协调，追加式低冲突）；或验证期手工起 QEMU |
| （远期） | 真 nginx | :80 | 18080 | 需协调者裁掉 net_init 演示监听 |

### Step 1 —— 内核态 httpd 雏形（纯 net.c 公共 API + 现有内核设施）

**目标**：内核内最小 HTTP/1.0 响应器，验证「TCP 栈作为服务器承载真实应用协议」的端到端正确性。**不引入任何新 syscall、不改任何锁区文件主体**。

- **涉及文件**：
  - 新增 `httpd_kern.c`（内核态，唯一新代码文件）：`httpd_kern_init()`（调 `tcp_listen(9999)`——公共 API，net.h:108）+ `httpd_kern_tick()`（accept 轮询 `tcp_accept_socket` net.c:538-551 → `tcp_recv`/`tcp_send`/`tcp_close`，全部公共 API）；
  - `Makefile` OBJS 追加 `httpd_kern.o`（追加一行，低冲突，见 §5）；
  - **挂接点（串行等待项）**：`kernel.c` 主循环加 2 行 `httpd_kern_init(); … httpd_kern_tick();`——kernel.c 属 shell 方向锁区，代码先行入库、挂接等合并窗口（先例：kbdwait.c 独立文件模式）。
- **依赖前置**：
  1. code4 的 net.c 加固**合入**（H2/M1/M3 直接决定服务器健壮性；工作区虽已含，未提交前 Step 1 的回归基线不稳）；
  2. 无 syscall 依赖（纯内核函数调用）。
- **实施要点**：
  - `httpd_kern_tick` 在**主循环上下文**执行（勿挂 IRQ0 的 timer_handler→net_poll 路径——中断上下文跑协议解析与长字符串处理不可取；interrupts.c:23 的调用链仅供收包）；
  - accept 空闲即返回（内核态无阻塞问题，天然轮询）；每 tick 至多处理 1 连接，天然限流；
  - 响应为固定内嵌页面（`.rodata`），头部一次 `tcp_send`，body 按 MSS 游标分片，容忍部分写（tcp_send 收缩语义 net.c:1006-1016）与返回 0（计次放弃，阈值 32 次/tick 预算）；
  - 日志格式定死 `[HTTPD-K] <method> <path> <status> <bytes>B`，供串口断言。
- **验收标准（QEMU 串口/hostfwd）**：
  - `tests/qemu_run.sh --mode slirp` 引导后串口出现 `[NET] TCP listen :9999`（复用 tcp_listen 既有打印，net.c:703-705）；
  - 宿主机 `curl -s http://127.0.0.1:18099/` → `200` + 内嵌正文 md5 匹配；
  - 串口依次出现：`[NET] TCP SYN :9999 <- … -> SYN-ACK` → `[NET] TCP ESTABLISHED …` → `[HTTPD-K] GET / 200 <n>B` → `[NET] TCP FIN <-`；
  - `tests/net_suite.py` 追加 blackbox 用例（新文件，零冲突）：10 次串行请求全 200、畸形请求行回 400、POST 回 405、串口无 `[ERR]`/panic。

### Step 2 —— 静态文件服务（接 VFS：romfs 只读挂载）

**目标**：httpd 内容源从内嵌页面升级为真实文件；同时打通「块设备→文件系统→VFS_REG→read」通路——这是未来 nginx.conf/mime.types 的同一基础设施（预研 Y11）。

- **涉及文件**：
  - 新增 `romfs.c`/`romfs.h`：超级块解析（IDE 主盘固定扇区起）、inode 查找、挂载为 VFS_REG 节点集（inode_type_t 已预留 `VFS_REG`，vfs.h:8）；
  - `vfs.c`：nodes[] 注册 romfs 根下条目或 open 路径分流（**code7 锁区，串行等待**）；
  - `ide.c` 已具备扇区读写（预研 §2.3 ✅），无需改动预期内；
  - `httpd_kern.c`：lookup(path) 从内置表改为 vfs_open/vfs_read/lseek 语义；
  - 制作工具 `tools/mkromfs.py`（宿主机侧打包镜像 + dd 进磁盘映像）。
- **依赖前置**：
  1. Step 1 完成（回归基线在手）；
  2. **vfs.c 解锁**（code7 已落 L2 但仍持锁；romfs 接入必须排队）；
  3. kernel.c 挂接 romfs_mount（与 Step 1 挂接点同窗合并）。
- **实施要点**：
  - romfs 选型理由：只读、结构极简（无写放大风险）、镜像可离线生成；FAT 只读留作备选；
  - fd 压力评估：fd 表 32（vfs.h:4）− std 3 − listener 1 − conn ≤16 ⇒ 读文件 fd 预算充足，但**打开-读完-关闭必须严格配对**（CLOSED 型 socket fd 滞留 bug 尚未修，net.c:569——文件 fd 不受影响但纪律照守）；
  - Content-Type 按扩展名 4 项迷你表（html/htm/txt/png→octet-stream 兜底）；
  - ≥4KB 文件跨多次 tcp_send（TCP_BUF_SIZE=4096 发送缓冲收缩，net.h:70）。
- **验收标准（QEMU 串口）**：
  - 串口出现 `[VFS] romfs mounted: <N> files, <K>KB`（新打印，格式由本步定义）；
  - `curl 127.0.0.1:18099/index.html` 200 且内容 == 宿主机源文件（diff 校验）；
  - `curl …/sub/page.html` 子路径 200；不存在路径 404 + 串口 `[HTTPD-K] GET /nope 404 0B`；
  - ≥8KB 文件完整传输 md5 一致（验证跨缓冲分段发送）；
  - Step 1 全部旧用例不回退。

### Step 3 —— 独立 ring3 用户态 HTTP 服务进程（ELF 加载）

**目标**：httpd 迁出内核地址空间，成为经 nr=11 exec 拉起的 ring3 进程，走完整 int 0x80 socket 组。这是 `MINIMAL_HTTPD_DESIGN.md` 的落地步骤，也是 nginx 未来"用户态进程"形态的预演。

- **涉及文件**：
  - 新增 `apps/httpd.c`（ring3，SHELL_CFLAGS 同族编译，链接布局同 shell：`-Ttext=0x400000 -e _start`，Makefile SHELL_LDFLAGS 先例）+ `apps/sock.h` 内联 int 0x80 包装（MINIMAL_HTTPD_DESIGN §4.1 方案逐条可用）；
  - Makefile：`httpd.elf/bin/bin.h` 目标族（仿 shell 三件套规则，追加式）；
  - **exec 通路（关键串行项，二选一）**：
    - A：`syscall.c` sys_exec 嵌入分支泛化为镜像查表（现仅认 `"/bin/shell"`，syscall.c:163-168）——code5/code2 锁区排队；
    - B：等 Step 2 romfs 就绪，`exec("/romfs/httpd.elf")` 走 VFS 分支（syscall.c:169-186 通路已通，devfs 下才死）——**推荐 B，与 Step 2 天然衔接**；
  - `elf_load`/`create_user_process` 已可用（elf.h:38；process.c:275），无改动预期；
  - tests/ 追加 ring3 httpd 用例脚本。
- **依赖前置**：
  1. Step 2（选路线 B 时为硬前置）；
  2. httpd.elf ≤ **32KB**（CATOS_EXEC_IMG_MAX，syscall.c:137——VFS 分支同样整读进该缓冲）；
  3. 用户栈预算：单页 4KB @0x700000-0x701000（elf.h:28-29），请求缓冲+局部变量 ≤2KB，否则触发 #PF——**当前 vector 14 直接 panic**（interrupts.c:31），无 page fault handler 兜底；
  4. ring3 无 yield/nanosleep（Y6' 缺口）⇒ accept EAGAIN 后只能忙等（烧 CPU 但 QEMU 单核无害，MINIMAL_HTTPD_DESIGN §4.2 策略 C）。
- **实施要点**：
  - 监听 **TCP :7000**（端口规划见表）；close 一律 nr==28（L8：nr==3/6 对 socket 是 -EBADF 但绝不可混用）；
  - 发送循环：进度游标 + 总尝试上限（应对 send 返回 0 歧义 + EAGAIN 折叠，见 §4.1-M2 行）；
  - 日志经 write(1, /dev/console)（conwrite 逐字符 kputs，vfs.c:16）；
  - 进程健壮性铁律：任一连接失败收敛到 close+continue，绝不 exit——exit 后无人收割（wait stub -ECHILD），但也不产生僵尸危害（PCB 槽位 TERMINATED 可复用）。
- **验收标准（QEMU 串口/hostfwd）**：
  - 串口出现 ring3 输出 `[httpd] listening on :7000`（write 系统调用链路首次实战）；
  - `curl http://127.0.0.1:<hostfwd7000>/` 200（hostfwd 追加后）；
  - 串口可见 `[NET] TCP data <n>B <- 10.0.2.2`（内核收包日志，net.c:862-868 路径）与 httpd 用户态日志交织；
  - 100 次串行请求零 panic、零 `[ERR] exception`；半开连接（发一半断开）后服务继续；
  - `int3`/异常计数为零；QEMU 存活时长 ≥60s 长稳。

### Step 4 —— napi 风格事件循环骨架（通向 nginx R4）

**目标**：把「全员 tick 轮询」升级为「中断标记 + 预算轮询 + fd 就绪表 + poll() 语义」，形成 nginx event engine 的结构同构物。**这是四步中唯一触碰多个热区的步骤，必须串行统筹。**

- **涉及文件（全部热区，§5 串行）**：
  - `e1000.c/interrupts.c`：RX 中断注册（irq_register_handler 公共 API 已备，interrupts.c:20）→ ISR 内置 napi_schedule 位图，**不做重活**；
  - `net.c`：`net_napi_poll(budget)` 从直通包装（net.c:1065）改造为预算循环：收包≤budget 帧/次、超budget 留待下次、处理完重新使能中断；`net_poll()`（net.c:1067）保留 tick 兜底；
  - 新增 `event.c`：fd→就绪位登记表（socket 层状态变化处打标：rxb 非空→ readable；sndb 有余量→ writable；ESTABLISHED 入表→ listener readable）；
  - `syscall.h/syscall.c`：新增 nr=31 `poll(fds*, nfds, timeout_ticks)`（编号顺延 30 之后，不与既有冲突；锁区排队）；
  - `httpd`（内核版或 ring3 版）改造为事件驱动：单进程同时伺服 N 连接（突破串行模型）。
- **依赖前置**：
  1. **code4 提交**（net.c 归零锁）；
  2. Step 1-3 稳定回归（事件循环的正确性要用真实负载验证）;
  3. 睡眠/唤醒原语（预研 Y2，PROC_BLOCKED 目前仅有定义，process.h:23）为 poll 阻塞语义的前置——骨架期允许忙轮询 poll（timeout=0 语义），阻塞语义后补。
- **实施要点**：
  - napi 三要素对标：中断关闭收包→预算内批量处理→处理完开中断（Linux `net_rx_action` 结构同构）；当前 e1000 驱动的收包入口即 `e1000_poll`，改造面集中在调度时机；
  - 就绪表容量 = VFS_MAX_FD=32，位图一 uint32 即可；
  - poll 返回值与 revents 语义按 Linux 收敛（POLLIN/POLLOUT/POLLERR），为 nginx `--with-poll_module` 对接铺路（预研决策 D2）；
  - **验收重点从"功能"转向"并发"**：串行模型下不可能出现的交叉服务日志是本步的核心证据。
- **验收标准（QEMU 串口）**：
  - 串口出现 `[EVT] napi budget=<n> rx=<m>` 周期性输出（新打印）；
  - **并发 4 连接**（python asyncio 探针，≤15 安全线内）：4 个请求的 `[HTTPD]` 处理日志**交错**出现且全部 200——串行版此处必然顺序阻塞；
  - 高频小包压测（inject 模式，wire_lib.py）下串口无 `[WARN] unhandled IRQ` 风暴、无 conn 表耗尽 RST（16 上限内）；
  - poll(timeout=0) 非阻塞语义探针 PASS；阻塞语义标 🔍待验证（依赖 Y2）；
  - 达成后即满足预研阶段 3f「nginx configure 对接 poll 模块」的内核侧前提。

---

## 4. 风险清单

### 4.1 socket API 缺口 → HTTP 场景后果映射（阶段4 缺口编号 H1/H2/M1-M4/L1-L8）

> 编号体系出处：`docs/SOCKET_API.md` §6（转引 code8 登记）。「已修」均指**工作区未提交**状态。

| 编号 | 主题 | HTTP 场景后果 | 现状 | 对策落点 |
|---|---|---|---|---|
| **H1** | 用户指针 EFAULT 族完整性 | ring3 httpd 的 recv/send 缓冲若校验漏报 → 坏指针直达内核 memcpy；**当前无 page fault handler，#PF 即全局 panic**（interrupts.c:31）——一个畸形请求打崩整机 | 骨架已在（user_access_ok，syscall.c:100-102）；完整性待审计 | Step 3 验收加坏指针对抗用例；根治靠 page fault handler（超出本计划） |
| **H2** | TCP bind 同端口"附着"返 0 | 双 httpd 实例静默共享同一 TCB → 任一方 close 作废另一方 conn 指针（use-after-free 形态）；accept 归属混乱 | **已修（工作区）**：冲突返 -98（net.c:526） | code4 合入后回归双 bind 用例；Step 3 端口规划已规避 |
| **M1** | RTO R1/R2 度量与放弃 | 无 R2 阈值时黑洞对端无限重传占死 16 连接表 → 整站拒绝服务 | **已修（工作区）**：SYN 3 次/数据 5 次放弃释放（net.c:587-588,961-985） | 合入回归；压测加 10% 丢包场景 |
| **M2** | 错误码混叠（裸 -1 哨兵） | send 收缩到 0 **返回 0**（net.c:1010-1011）无法区分"缓冲满"与"成功 0 字节"；sock_xlate 把一切 -1 折叠 EAGAIN（syscall.c:103-110）→ 发送循环可能死转或误判断连 | 骨架在，区分性 errno 未下沉 | 应用层对策已定：进度游标+尝试上限（Step 1/3 实施要点）；根治=net.c 返真 errno（等 code4 后） |
| **M3** | 盲 RST（RFC 5961） | 伪造 RST 一键拆除任意活跃连接 → 静态站可被第三方 DoS | **已修（工作区）**：窗口外丢弃+challenge-ACK（net.c:789-800） | inject 用例回归（wire_lib.py 可造盲 RST） |
| **M4** | 仅登记，语义待定义方补充 | 无法评估 | 🔗SOCKET_API.md §6 | 编号定义落地后回填本表 |
| **L1** | listen-before-bind → -EINVAL | httpd 若按"socket→listen→bind"习惯序即失败；标准序 socket→bind→listen 可绕过 | 待修（syscall.c:265-268 TODO(code2)） | Step 3 apps/httpd.c 固定标准序；不阻塞 |
| **L2** | fd 分配策略 | std 流占 0-2、最低空闲、kind 隔离——httpd 首 socket=fd3 可预测；vfs_close 拒收 socket 防误关 | **已落地（code7）**（vfs.c:7-77） | 无动作 |
| **L3/L4/L5** | 仅登记 | 无法评估 | 🔗SOCKET_API.md §6 | 同 M4 |
| **L6** | 零长缓冲误报 EFAULT | recv(fd,buf,0) 类边界合法化 | **已修**（n==0 放行，paging.c:330-356 注记） | 无动作 |
| **L7** | 仅登记 | 无法评估 | 🔗SOCKET_API.md §6 | 同 M4 |
| **L8** | close 双别名（nr==3↔6↔28） | ring3 必须 nr==28 关 socket；**未来按 Linux ABI 写的代码 `read(fd=3)` 会静默关 fd**——nginx shim 移植前必修的地雷（预研 D4） | 已文档化未改行为（vfs.c:79-91） | 协调者裁决移除别名；此前所有自研代码守 nr==28 |

### 4.2 并发限制：TCP_MAX_CONNS=16 及派生天花板 ✅实测

| 资源 | 上限 | 出处 | HTTP 场景含义 |
|---|---|---|---|
| TCP 连接表 | **16** | net.h:67 | 同时存在（含 LISTEN/SYN_RCVD/ESTAB/FIN 族/TIME_WAIT）≤16；net_init 已常驻占 2 个（:80/:81 listener）+ udp_open 不占 TCP 表 |
| listen backlog | ≤16，bind 路径默认 **1** | net.c:553-559,528 | ring3 bind 后必须显式 listen(n)；溢出 SYN 直接 RST（net.c:740-743） |
| 收/发缓冲 | 各 4096B | net.h:70 | 单响应 >4KB 必跨多次 send；慢读客户端反压发送缓冲→send 收缩/返 0 |
| 单段 MSS | 1460B | net.h:69 | 发送分片粒度 |
| scoreboard/OOO | 8 段/4 槽 | net.h:71; net.c:326-327 | 乱序容忍有限，超限降级重 ACK（已并入 code4 加固语义） |
| TIME_WAIT | 200 ticks=2s 定长 | tcp_handle FIN 分支 | 快速重启压测：2s 内 >14 条短连接即触顶 RST——**测试脚本串行间隔须 >2s 或容忍 RST** |
| UDP 槽/缓冲 | 8 × 2048B | net.c:216-217 | 与 HTTP 主线无关，DNS resolver 远期受限 |
| fd 表 | 32 | vfs.h:4 | listener+16conn+3std=20，余量尚可；nginx rlimit_nofile 千级差距见预研 Y13 |

**压测纪律（写入 tests/http_suite.py 设计约束）**：并发探针 ≤15；串行长稳间隔 ≥50ms 且每 20 请求容忍一次重连；单响应基准 ≤4KB、大响应专项单独跑。

### 4.3 内核态 vs 用户态取舍（Step 1/2 vs Step 3/4）

| 维度 | 内核态 httpd（Step 1/2） | ring3 httpd（Step 3+） |
|---|---|---|
| 开发速度 | 快：直接函数调用，无 ABI 摩擦 | 慢：五参寄存器 ABI、无 libc 起步、4KB 栈预算 |
| 故障半径 | **解析 bug=内核 panic（无 PF handler）** | 崩进程不崩内核（但 PCB/调度简单，隔离弱于 Unix） |
| 地址空间 | 与内核共享单一页目录（paging.c 单目录，预研 §2.4） | 同目录低半区（elf.h 注释），隔离是"软"的，但至少 EFAULT 校验在环边界生效 |
| 性能 | 零切换开销 | 每请求 ~10 次 int 0x80（可接受） |
| 对 nginx 的代表性 | 低（nginx 永远不会住内核） | **高**：ABI 痛点（缺 setsockopt/writev/getpeername/yield）在此阶段全部暴露并回填缺口表 |
| 定位 | 协议正确性试验台 + romfs 验收载体 | 正式形态；此后内核 httpd 冻结退役 |

**取舍结论**：Step 1/2 的内核态是**脚手架而非终点**——它存在的唯一理由是在 exec 通路与 romfs 就绪前提供可验收载体；Step 3 完成后其代码冻结，仅保留 :9999 监听直至协调者裁撤 net_init 演示服务。

### 4.4 其他横切风险

| # | 风险 | 依据 | 缓解 |
|---|---|---|---|
| X1 | 端口撞车：ring3 bind(80) 撞内核演示监听 | net.c:1069-1079 + H2 修复 | §3 端口规划表强制执行 |
| X2 | httpd.elf 超 32KB 无法 exec | syscall.c:137 | 编译尺寸门禁（Makefile 目标内 `stat -c%s` 断言 ≤32768）|
| X3 | 栈溢出 → #PF → panic | elf.h:28-29 + interrupts.c:31 | 请求缓冲 ≤2KB 纪律 + Step 3 验收含深路径用例 |
| X4 | Makefile clean 连带删除自动生成头 | clean 规则 rm shell_bin.h（Makefile ✅实测） | httpd_bin.h 同规则纳入 clean，避免陈旧产物 |
| X5 | 无墙钟：日志/Last-Modified/If-Modified-Since 无从谈起 | RTC 未暴露 syscall（预研 Y7） | 本计划全程不发 Date 头（HTTP/1.0 宽容）；Y7 列入 nginx 前置 |
| X6 | code4 未提交期间行号漂移 | 本仓库并行惯例 | 本文所有"已修"结论绑定工作区快照，合入后需复核一轮 |

---

## 5. 与并行进度的衔接（文件锁矩阵）

### 5.1 本计划涉及的文件锁判定

| 文件/区域 | 当前归属（据工作区注释与任务书） | 本计划动作 | 并行性判定 |
|---|---|---|---|
| `net.c` | **code4 锁**（加固中） | 只读引用；Step 1-3 均**不要求改它** | Step 1-3 可与 code4 并行（靠公共 API 隔离）；Step 4 及 M2 根治**必须等 code4 提交** |
| `syscall.c`/`syscall.h` | code5/code2 链 | Step 4 新增 nr=31 poll；exec 泛化备选 A | **串行排队** |
| `vfs.c`/`vfs.h` | code7（L2 已落地仍持锁） | Step 2 romfs 接入 | **串行排队** |
| `kernel.c`/`process.c`/`elf.c`/`shell_bin.h`/`shell_user.c` | shell 方向 | Step 1 挂接点 2 行 + romfs 挂接 1 行 | **串行排队**（合并窗口一次性挂接） |
| `e1000.c`/`interrupts.c` | 未明确（RX 中断注册涉两者） | Step 4 中断化 | **串行排队**（与 code4 协调后统筹） |
| `usermode.c`/`OSDEV_PROJECT_NOTES.md` | 用户区 | **禁触**，本计划零引用改动 | — |
| `docs/` 既有四份 | code8 交付 | 只引用 | 可并行 |
| `Makefile` | M 状态（code2/code9 追加过） | Step 1-3 追加目标行 | **低冲突并行**：只追加不改动既有行，合并冲突面≈0；仍建议与 Makefile 最近编辑者打招呼 |
| `tools/net-test.py` | code3 资产 | 只读参考，不改动 | — |
| `tests/` | code10 入库 | **只新增** http_suite.py 等新文件；qemu_run.sh 追加 hostfwd 一条需其点头 | 新文件可并行；qemu_run.sh 改动低冲突排队 |

### 5.2 可立即并行开工（零锁区交集）

1. **Step 1 代码本体**：`httpd_kern.c` 全量编写 + 自测钩子（临时 main 或被协调者挂接前以编译门禁验证）；
2. **Step 3 应用代码**：`apps/httpd.c`/`apps/sock.h`——协议逻辑与 Step 1 同源，可在宿主机以 stub 头先行语法/逻辑验证；
3. **测试资产**：`tests/http_suite.py`（blackbox 用例按 §3 各步验收标准编写）、`tools/mkromfs.py`；
4. **romfs 镜像格式定稿**与样例站点内容。

### 5.3 必须串行等待的依赖链（拓扑序）

```
code4 合入(net.c 归零)
  └─► Step 1 挂接(kernel.c 2行, 合并窗口) ─► Step 1 验收(:9999)
        └─► vfs.c 解锁 ─► Step 2 romfs 接入 ─► Step 2 验收
              ├─► Step 3 路线B: exec("/romfs/httpd.elf") ─► ring3 验收
              └─► (备选A) syscall.c 排队: exec 泛化
                    └─► code4+code5+code10 全部归零 ─► Step 4 统筹(e1000/interrupts/net/syscall 四区)
                          └─► poll() nr=31 ─► nginx shim 前置达成
```

**协调者裁决点汇总**：① nr==3 close 别名去留（L8，阻塞一切 Linux ABI 兼容工作）；② net_init 演示监听(:80/:81)何时裁撤给真 nginx/httpd 让位；③ Step 4 四热区统筹排期；④ M1/M3/M4/L3/L4/L5/L7 编号定义方补语义。

---

## 6. NOT_TESTED 清单

| # | 条目 | 状态 |
|---|---|---|
| N1 | 本文全部行为/行号结论为**静态读码**所得，零编译零运行 | NOT_TESTED |
| N2 | code4 工作区加固（H2/M1/M3/化身回收/scoreboard 合并）的运行时回归 | NOT_TESTED（仓库根有 qemu-sack-edge-t1~t6 日志，结论核对不在本任务范围）|
| N3 | Step 1-4 各验收标准的可达性估计（尤其 :9999 hostfwd 链路与 32KB ELF 门禁数值） | 🔍待验证（首次执行时校准） |
| N4 | Step 4 并发 4 连接交叉服务在协作式调度下的实际表现（单核 QEMU，无时钟抢占下的公平性） | 🔍待验证 |
| N5 | M4/L3/L4/L5/L7 缺口语义 | 待编号定义方补充（同 SOCKET_API.md N5 口径） |
| N6 | nginx 1.26.x configure 对 `--with-poll_module` 的最小依赖面复核 | 🔗转引预研 §3/§5，未本地核对 nginx 源码树 |

---

*文档结束。生成者：Cat-OS 并行任务 code3（NGINX_PORT_PLAN 实施设计）。
约束遵守声明：本任务仅新建本文档 `docs/NGINX_PORT_PLAN.md` 一个文件；未修改任何既有 `.c/.h/.md`/Makefile/tests 资产；未触碰 net.c（code4）、usermode.c/OSDEV_PROJECT_NOTES.md（用户区）、kernel.c/process.c/elf.c/shell_bin.h/shell_user.c（shell 方向）、docs/ 下既有四份文档；未执行 commit/push/reset/rebase/delete。*
