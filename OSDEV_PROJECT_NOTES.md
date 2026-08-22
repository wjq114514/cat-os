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