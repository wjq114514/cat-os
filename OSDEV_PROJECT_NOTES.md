# OS Dev 项目备忘 (cat-os / /home/wjqawa/osdev)

## 用户目标
- 自主开发一个追求"极致网络性能"的操作系统内核
- 不追求完整 POSIX：内核内部用自有高性能接口，Linux ABI 作为选择性兼容 shim
- 移植 nginx 作为性能验证目标（重头戏），bash 等基础软件也要移植（shell 不急）

## 参考
- Linux 主源码已浅克隆到 /home/wjqawa/osdev/linux-ref（对照实现思路，不照搬、不加入构建依赖）
- 用 codex（HAPI agent）写代码，本机 /home/wjqawa/osdev 工作区

## 技术栈
- i686 (32位)，freestanding/nostdlib，nasm + gcc + ld + grub-mkrescue
- 编译: make (直至 make run)，QEMU 串口验证（-serial stdio/file）
- QEMU: qemu-system-i386 -cdrom os.iso -m 128M -display none -serial stdio -no-reboot -no-shutdown -netdev user,id=net0 -device e1000,netdev=net0

## 已完成里程碑
- higher-half 内核（虚拟基址 0xC0000000，物理 1MiB，分页 + 移除低地址恒等映射）
- GDT（复用 GRUB GDT 搬到 high-half 副本）、IDT 真正激活（lidt）
- PIC 8259A remap，PIT 100Hz tick，统一 IRQ 注册表，spurious IRQ7/15 检测
- PCI 枚举 + e1000 (8086:100E) 驱动：TX/RX DMA ring，能真实收发包（ARP 级）
- 注意：QEMU 的 e1000 不实现 RCTL.LBM loopback（/tmp/qemu-e1000.c 证实），RX 验收用 socket 注入
- syscall dispatcher + Linux ABI shim 骨架；netring/fixed-buffer 骨架（共享 ring、批量、doorbell、busy_poll，为性能铺路）
- PS/2 键盘、IDE(PIO)磁盘读写、RTC 时钟（阶段 A 设备驱动收尾，已验证）
- 阶段 B ring3 用户态切换 (TSS + GDT user segments + iret) + int 0x80 陷入/返回，验证通过
- VFS 抽象层（devfs: /dev/null, /dev/console, /dev/kbd, /dev/zero, /dev/urandom）
- fd_table + open/read/write/close syscall 接入（Linux ABI nr 5/3/0/1）
- 用户指针安全检查（user_access_ok、范围、PTE P|USER、跨页、路径长度限制）
- 完整 ring3 用户态 open/read/write/close 实测通过（/dev/null EOF、/dev/console write 输出、EFAULT 负向测试）

## 待办路线（用户确认的顺序）
阶段D 网络协议栈（ARP → IP → ICMP → UDP → TCP，内置 NAPI/批量/零拷贝/预分配缓冲池）→ 下一个
阶段E shell 移植 —— 用户明确：不急，靠后
nginx 移植是最终验证目标（master/worker + 事件循环模型，热路径零 fork，COW fork）

## 网络性能关键点（本喵分析，供后续参考）
性能大头不在传输层：是"拷贝(零拷贝)、中断(NAPI)、系统调用频率(批量)、锁竞争(per-CPU 无锁队列)"四个横向环节。

## 网卡驱动移植可行性（2026-08-22）
从 QEMU e1000 到真实硬件可行性高：
- e1000/e1000e 系列寄存器布局和 DMA ring 机制与当前驱动高度相似，改 PCI VID/PID 表 + 寄存器偏移微调
- 需要补：MSI/MSI-X 中断支持、PHY 链路检测、PCI 总线递归扫描
- 核心 TX/RX DMA ring 路径不需要重写

## 环境备注
- HAPI codex 进程由 nohup 手动拉起的孤儿进程（hub/runner/codex），key 需写进 systemd 或重启 runner 才生效
- 自动审批：60 秒超时兜底自动批准（用户接受，不动插件源码）
- 用户常新开对话省上下文，重要进度要记长期记忆
- 审批通知发送失败问题：HAPI 通知发到 event.unified_msg_origin，当前会话 event.send 可能失效，需用户在 QQ 群 /hapi bind

## 网络协议栈进度（2026-08-22）

### 已完成
- e1000 TX/RX DMA ring，QEMU socket 注入和 user/slirp 网络验证
- ARP、IPv4、ICMP Echo、UDP Echo
- TCP 基础监听、三次握手、按序接收、ACK 和 FIN 处理
- DHCP 客户端：`DISCOVER → OFFER → REQUEST → ACK`
  - 对照 Linux `linux-ref/net/ipv4/ipconfig.c`
  - 548 字节 BOOTP/DHCP payload、xid、chaddr、magic cookie、选项解析
  - QEMU user/slirp 实测获取：`10.0.2.15`，网关 `10.0.2.2`，掩码 `255.255.255.0`
  - 无 DHCP 服务器时重试并 fallback 到静态 `10.0.2.15`
- 修复 IP/ICMP/TCP 校验和写入时的网络字节序问题；对照抓包和 libslirp 校验定位
- TCP 第一阶段增强：
  - 每连接发送缓冲与 ACK 回收
  - `snd_una` / `snd_nxt` 跟踪
  - 对端窗口记录和动态接收窗口通告
  - RTO 超时重传与指数退避，实测 SYN-ACK 间隔约 `0.30s / 0.60s / 1.20s`
  - `FIN_WAIT_1`、`FIN_WAIT_2`、`CLOSE_WAIT`、`LAST_ACK`、`CLOSING`、`TIME_WAIT`
  - 乱序 FIN 防护、TIME_WAIT 槽位回收
- **本端数据 RTO 重传（TCP :81 测试入口）**：已端到端验证
  - 真实调用 `tcp_send()` 发送 `TCP-RTO-REAL`，ACK 不回复触发重传
  - 实测重传间隔：`0.01s(首次) / 0.31s(首次重传) / 0.91s(第二次重传)`，间隔约 300ms/600ms
  - 串口日志：`TCP test send 12B` → `TCP RTO: re-xmit 12B` ×2
- **主动关闭完整路径 `FIN_WAIT_1 → FIN_WAIT_2 → TIME_WAIT → 超时释放`**：已端到端验证
  - 串口日志完整记录：`FIN_WAIT_2` → `TIME_WAIT entered` → `TIME_WAIT expired`
- **TIME_WAIT 槽位复用**：已验证，TIME_WAIT 到期后用同一端口 (`41001`) 重新建立连接成功

### 已验证
- `tools/net-test.py` 回归：ARP、ICMP、UDP、TCP handshake/data、TCP FIN 均 PASS
- 编译通过，0 warning、0 error
- SYN-ACK RTO 专项：PASS，真实串口日志出现多次 `TCP RTO: re-SYN-ACK`
- 本端数据 RTO 重传专项：PASS（实测间隔 300ms/600ms）
- 主动关闭/TIME_WAIT 专项：PASS（串口日志完整路径 + 同端口 SYN-ACK 复用）
- 代码审查依据：Linux `net/ipv4/tcp_input.c`、`tcp_output.c`、`tcp_minisocks.c`；DHCP 依据 `net/ipv4/ipconfig.c`

### 尚未完成 / 证据缺口
- 尚未实现完整 TCP 拥塞控制（慢启动、拥塞避免、Reno/CUBIC/BBR）、SACK、RTT/RTO 精确估算和乱序缓存
- 尚未实现面向用户态的 socket API
- DHCP 租约续期、DNS 配置应用尚未完成

### 代码与提交状态
- GitHub：<https://github.com/wjq114514/cat-os>
- 已推送提交：
  - `5126dba`：ARP/IP/ICMP/UDP/TCP 阶段验收
  - `e10c82b`：DHCP、校验和字节序、显示格式修复
  - `74a52f5`：TCP 发送确认与重传状态机
- 当前工作树：`net.c` 有未提交修改（TCP :81 测试入口 + TIME_WAIT 日志增强）
- 当前 Codex/HAPI session：`21c58f8e`（用户配置为 5.6 luna max；HAPI 状态页显示模型为 `default`，未能独立确认底层模型名）

## 键盘交互进展（2026-08-24）

### 已完成并验证（有真实 QEMU/QMP 证据）
- **用户指针安全加固** (`a6d3bbe fix: validate user open path`)
  - 消除了 `CR2=0x11` page fault，user open path 现在做完整安全校验
- **usermode.c 构建修复** (`72d8358`)
  - 删除重复且未完成的 `append_read_diag` helper（implicit vprintf decl + redefinition）
  - `make clean && make`：退出码 0，0 warning/error
- **kbd 探针 fd 修复** (`b0c1fc7 usermode: add observable kbd probe`)
  - 串口原文：`kbd handshake: ready` + `kbd read ok` + `user socket ERRORS PASS`
  - fd 处理修复，消息长度精确匹配
- **PS/2 扫描码映射修复** (`3910a93 input: fix PS/2 scancode table alignment`)
  - **Bug**：旧实现用字符串表 `lo[s-2]`，`'a'`(0x1E) 取 `lo[28]='g'` → QMP 注入 `a` 被解码为 `g`
  - **修复**：改为按扫描码直接索引的 64 字节表，`0x1E='a'`、`0x30='b'`，Shift 上档表 `0x1E='A'`
  - 真实 QEMU + QMP `input-send-event` 注入验证（全部 PASS）：
    | 注入 | 期望 | 串口读出 | 判定 |
    |:----:|:----:|:--------:|:----:|
    | `a` | `a` | `a` read_ret=1 | **PASS** |
    | `b` | `b` | `b` read_ret=1 | **PASS** |
    | `1` | `1` | `1` read_ret=1 | **PASS** |
    | `shift+a` | `A` | `A` read_ret=1 | **PASS** |
    | `a,b,1,shift+a` | `ab1A` | `ab1A` read_ret=4 | **PASS** |
  - 验证脚本：`/tmp/catos_kbd_verify.py`，证据文件：`/tmp/catos-kbd-verify/*.serial`
- **ring3 `/dev/kbd` 非阻塞空队列读取**：PASS
  - 串口原文：`kbd NOT_TESTED/EMPTY (1 try)` → 队列空时正确返回 0，不崩溃
- **网络基线回归**：PASS（ping 3/3、0% 丢包，socket 错误处理全通过）
- 无 page fault、`CR2`、panic 或 CPU exception

### 未提交改动（工作树）
- `usermode.c`：line echo probe（3 次有限重试版本，+61/-15）
  - 新增 `je` (jump equal) helper
  - kbd 探针从一次性读取改为 3 次有限重试循环
  - 增加计数器、`MSG_KBDNT`("kbd NOT_TESTED (3 tries)
")、`MSG_KBDHEX`("kbd HEX: ")
  - **状态**：代码已写，构建通过，但尚未用 QMP 实测验证非空读取场景
- 备份文件：`usermode.c.preprobe`、`vfs.c.user-unstaged.bak`（未跟踪）

### 已知问题与缺陷
1. **break 码处理不完整**：`keyboard.c` 的 `kh()` 只按 `s&0x7f` 匹配 0x2A/0x36（Shift），普通键 break 码会进入 make 路径 → 长按/连击重复字符风险
2. **E0 扩展扫描码状态机未实现**：箭头键、Num、Ctrl/Alt 等扩展键无法正确映射或静默丢失；E0+F0 断码可能按 0xF0 误处理
3. **Tab、Backspace 缺项**：扫描码在表中为 0 被忽略
4. **非阻塞读取时序脆弱**：QMP 注入与 ring3 唯一一次非阻塞 read 之间存在竞态窗口，单次读取容易错过注入字符
5. **阻塞式 `/dev/kbd` read 未实现**：当前 `keyboard_getchar()` 纯非阻塞，队列空直接返回 -1，无 yield/sleep/wakeup 机制

### 阻塞问题（自动化开发环境）
- **本地模型 RPM 限流**：Qwen 3.8 27B 持续 `429 rpm exhausted` / `token plan limit exhausted`，已持续数天，子代理无法执行任何任务
- **子代理无 admin 权限**：QQ `1105693640`（Scheduler）不在 AstrBot `admins` 列表，`astrbot_execute_shell` / `astrbot_execute_python` 被拒
- **HAPI codex 不可用**：session `21c58f8e` 可能已失效或模型配额耗尽
- **建议**：把 Scheduler QQ 加入 admins 列表（WebUI → Config → General Config），或换用在线模型处理关键任务

### 后续计划（优先级排序）
1. **验证并提交 line echo probe**：对当前未提交的 `usermode.c` 3-retry 版本做全新 QEMU + QMP 注入实测，确认非空读取场景后提交
2. **实现最小 shell 骨架**：在 `usermode.c` 中实现 `help`/`exit` 命令循环，循环读取 `/dev/kbd`，回车匹配命令，用 QMP 注入 `help
` 和 `exit
` 实测
3. **实现阻塞式 `/dev/kbd` read**：在 `keyboard_getchar()` 中增加 yield/sleep 机制（需 kernel 侧 scheduler 配合），或用 PIT 计数等待
4. **修复 break 码处理**：在 `keyboard.c` 的 `kh()` 中正确识别普通键 break（0xF0 前缀或 `s&0x80`），避免长按重复
5. **实现 E0 扩展扫描码状态机**：处理 `0xE0` 前缀序列，支持箭头键、Ctrl/Alt 等扩展键
6. **补充 Tab/Backspace 映射**：在扫描码表中增加 0x0F(Tab)、0x0E(Backspace) 的处理
7. **回到阶段 D 网络协议栈完善**：socket API、拥塞控制（慢启动/拥塞避免/Reno）、SACK、RTT 精确估算、DHCP 租约续期
---

## 2026-08-25 自动化推进收工总结（蓝叶指令：全线停工）

### 本次推进成果（阶段1~4 全部落地，HEAD=df995a8）
- 阶段1 SACK 边界: 6796bd6
- 阶段2 TCP 生命周期: 09fb9b4 等5commit（RFC5961 RST三分/EADDRINUSE/stale-SYN回收/RTO放弃/no_listener RST+ACK）
- 阶段3 窗口与阻塞: b6a7db5（persist timer/SWS避免/MSS宣告解析/零窗口/recv开窗ACK/EAGAIN+ECONNRESET）+ 58d55a9 Karn亚tick RTT钳位(RFC 6298)
- 阶段4 用户态ELF exec: c38a72f（sock_abi内嵌ELF+TSS/exit生命周期修复+socket ABI测试基建81断言）+ e56d018 inject SYN断言修正
- 收尾: df995a8 SYN半初始化TCB竞态修复（四元组最先落位，sack_t8僵尸连接根因）

### 最终测试证据（全部真机 QEMU 串口背书）
- blackbox 19/19 | inject 6例全PASS | lifecycle L1 10/10、L3A 6/6、L4 6/6
- user_sock_abi: 81 PASS / 0 FAIL / 4 skip（ring3 真机跑通）
- 崩溃修复链闭环：exit后park绷带 -> TSS根因修复 -> 绷带拆除 -> S5e EMSGSIZE优先级 -> SYN竞态重排

### 工作区遗留状态
- usermode.c、本笔记：用户区未提交改动（按约定保留）
- 未跟踪：.opencode/、opencode.json（运行器配置）、备份文件x2
- /tmp 下测试脚本（TW1/TW2/TB1/RSTL2/L3B harness修复版）未入库，如需长期保留应搬入 tests/

### 停工声明
- 查岗 cron 已删除，所有子代理任务终止，不再派发新任务
- 下次开工建议：L3B采样竞态脚本入库、TW/TB harness从/tmp迁移进tests/、keyboard break码/E0扩展码（见上文已知问题）
