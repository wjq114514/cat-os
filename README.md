# Cat-OS

Cat-OS 是一个面向操作系统和网络协议栈学习的教学型 i686 内核项目，运行
在 freestanding/nostdlib 环境中，使用 GRUB 启动并在 QEMU 中验证。项目重点
是理解启动、分页、中断、驱动、网络协议和用户态系统调用之间的连接，不是
完整的 POSIX 操作系统。

## 当前已验证

当前代码和已有真实 QEMU、串口、脚本证据确认了以下能力：

- 内核启动、高地址内核映射、GDT/IDT、PIT，以及进入 ring3 用户态。
- e1000 虚拟网卡上的 ARP、IPv4、ICMP Echo、UDP 和 TCP 基础收发。
- 用户态 `ping 10.0.2.2`：3 个 Echo Request 得到 3 个 Reply，统计为 0% 丢包；
  非法地址路径输出 `ping: invalid address`。
- 最小用户态 socket 接口的 UDP echo 和 TCP echo，串口/测试输出均有
  `UDP echo PASS`、`TCP echo PASS`。
- TCP Reno 拥塞控制、动态 RTT/RTO、接收端乱序缓存和 SACK，以及发送端
  SACK scoreboard/选择性重传已有对应回归或专项证据。

这些项目不是对完整协议或完整 API 的承诺。特别是部分极端边界压力测试、
真实物理网卡和完整用户态网络工具链仍未完成。

## 构建

依赖 32 位 GCC/ld、NASM、GRUB 工具和 QEMU：

```sh
make clean && make
```

生成的 `os.iso` 可用 `make run` 或类似下面的命令启动：

```sh
qemu-system-i386 -cdrom os.iso -m 128M -display none \
  -serial stdio -no-reboot -no-shutdown \
  -netdev user,id=net0 -device e1000,netdev=net0
```

## 网络测试

在 QEMU user/slirp 网络下，用户态启动路径会通过 DHCP 获取通常为
`10.0.2.15` 的地址，并可执行：

```text
ping 10.0.2.2
```

原始网络回归脚本为：

```sh
python3 tools/net-test.py
```

该脚本适合 QEMU socket backend 的注入式 ARP/IP 测试，但 socket backend 不
提供 slirp 的 DHCP 服务；启动路径还包含 DHCP fallback 和用户态测试时序，
因此必须按实际启动状态等待或注入。不能把 socket backend 下因 DHCP/时序
导致的超时当成协议 PASS。临时专项脚本和日志放在 `/tmp`，不属于仓库内容。

ICMP 实现遵循 RFC 791 的 IPv4 头校验、RFC 792 的 Echo 类型/code、标识和
序号字段，并参考 RFC 1122 的主机 Echo 行为。Linux 对照源码主要是
`linux-ref/net/ipv4/icmp.c`、`ip_output.c`、`route.c`、`net/socket.c` 和
`net/ipv4/af_inet.c`；本项目只采用适合静态池和简化 syscall ABI 的必要部分。

## 当前限制与后续计划

- 用户态 socket ABI 是最小实验接口，不是完整 POSIX socket；阻塞、并发进程
  FD 隔离、DNS、poll/select 等能力仍有限或未实现。
- TCP 高级恢复路径、重复/重叠/双缺口等部分边界压力测试还需要更稳定的
  可重复注入覆盖。
- 当前主要在 QEMU e1000 上验证，真实网卡、MSI/MSI-X、PHY 和更完整的 DMA
  错误恢复尚未完成。
- 后续计划包括网络工程完整性和性能测量、最小 HTTP 应用验证，以及在基础
  设施稳定后进行 nginx 移植预研。

本项目当前仍处于实验和教学阶段。日志中的 PASS 只代表对应测试环境和
测试输入下的真实结果，不代表生产级兼容性或性能保证。
