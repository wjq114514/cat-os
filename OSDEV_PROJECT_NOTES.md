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
