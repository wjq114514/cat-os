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
- nginx 1.26.2 已完成 Cat-OS 交叉构建和嵌入：shell 可启动单进程 nginx，
  通过 FAT16 只读配置盘提供静态文件，`/` 返回 200，缺失路径返回 404。
- nginx 运行路径使用 `poll` 事件模块；shell 同时提供 `nginx`、`netstat` 和
  `ping <IPv4>` 命令。shell 还保留 `help`、`resolve`、`exec`、`ls`、`cat`、
  `history` 和 `exit` 等最小交互命令；本次 nginx 专项只逐项验收前三个命令。
  该结果是静态 HTTP 最小闭环，不代表完整 POSIX/nginx 特性已经移植。

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

## nginx 移植

nginx 1.26.2 的源码、Cat-OS POSIX shim 和构建脚本均在仓库内。构建链会生成
`nginx_bin.h`，再由 Makefile 将 nginx ELF 嵌入内核：

```sh
./build-nginx.sh
make clean && make -j2
```

当前运行配置见 `nginx.conf`：nginx 使用 `master_process off` 和 `poll`，监听
guest `:8080`，从 FAT16 只读盘的 `/mnt/fat/WWW` 提供静态文件。shell 中可执行：

```text
nginx
netstat
ping 10.0.2.2
```

一次 fresh QEMU 验收使用 host `18098 -> guest:8080` 和 FAT16 测试盘：

```sh
qemu-system-x86_64 -cdrom os.iso -m 128M -display none \
  -serial file:/tmp/catos-nginx-rebuild-20260828r4.serial \
  -no-reboot -no-shutdown \
  -netdev user,id=net0,hostfwd=tcp:127.0.0.1:18098-:8080 \
  -device e1000,netdev=net0 \
  -drive file=/tmp/catos-nginx-config-20260828.img,format=raw,if=ide,index=0,media=disk \
  -boot d
```

验收原文保存在 `/tmp/catos-nginx-rebuild-20260828r4.result`，结果为
`QEMU final rc=0` 和 `OVERALL: PASS`。完整改动、限制和源码依据见
`NOTES_NGINX_PORT.md`、`docs/NGINX_PORT_ANALYSIS.md`、
`docs/NGINX_GAP_ANALYSIS.md` 和 `docs/NGINX_PORT_PLAN.md`。

随后又用独立的 fresh QEMU 驱动复验了相同的 shell/HTTP 主路径，修正了驱动必须等待
`kbd handshake: ready` 后再注入命令的时序问题。该次证据为
`/tmp/catos-nginx-doc-verify.result` 与 `/tmp/catos-nginx-doc-verify.serial`，结果同样
为 `QEMU final rc=0` 和 `OVERALL: PASS`；host 端口为 `18100 -> guest:8080`。

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

- 用户态 socket ABI 是最小实验接口，不是完整 POSIX socket；完整阻塞/唤醒、并发进程
  FD 隔离以及 `epoll`/`select` 等能力仍有限或未实现。DNS、`poll` 和基础时间接口
  已有最小实现，但不等价于完整 POSIX 语义。
- TCP 高级恢复路径、重复/重叠/双缺口等部分边界压力测试还需要更稳定的
  可重复注入覆盖。
- 当前主要在 QEMU e1000 上验证，真实网卡、MSI/MSI-X、PHY 和更完整的 DMA
  错误恢复尚未完成。
- 后续计划包括网络工程完整性和性能测量，以及 nginx 完整特性所需的
  master/worker、upstream、可写文件系统、epoll 和容量扩展。

当前 nginx 仍是单进程、静态 HTTP 验证形态；master/worker 热升级、完整 signal、
upstream/connect、可写日志文件系统、epoll 和高并发容量仍是后续工作。本项目
仍处于实验和教学阶段。日志中的 PASS 只代表对应测试环境和测试输入下的真实
结果，不代表生产级兼容性或性能保证。
