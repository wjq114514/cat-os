# Cat-OS 后续自主任务清单

> 目标：在用户一次确认后，由 Codex 按顺序自主推进、编译、测试、修复和提交。除非遇到不可逆操作、远端 push、需求冲突或高风险架构变更，否则不要每个子任务都停下来询问。
>
> 强制规则：每个子任务开始前阅读相关项目源码和 `linux-ref/` 参考源码，并在汇报中给出函数/行号与 RFC 依据。所有 PASS 必须来自真实 QEMU、串口、tcpdump 或测试脚本证据；无法触发标记 `NOT_TESTED`，失败标记 `FAIL`。临时脚本放 `/tmp`，不要提交。

## 当前基线

- 已推送：`287482a net: add TCP SACK scoreboard selective retransmit`
- 已完成并验证：ARP/IP/ICMP/UDP/TCP 基础栈、Reno、动态 RTT/RTO、接收端 OOO/SACK、发送端 SACK scoreboard/选择性重传、ring3 UDP/TCP echo。
- ping 用户态任务已实现并真实验证核心链路：`ping 10.0.2.2`，3/3 reply、0% loss；非法地址路径已有验证。
- 当前工作区包含历史未提交改动，任何提交前必须检查 diff，禁止误提交无关文件。
- 当前不应自动 push；每次 push 必须单独得到用户明确确认。

## 总体执行协议

1. 先读取：`OSDEV_PROJECT_NOTES.md`、本文件、当前 `git status`、最近提交和相关源码。
2. 选择下一个尚未完成的子任务，写出简短计划后直接执行；不要重复询问已经明确的需求。
3. 每个逻辑阶段都执行 `make clean && make`。
4. 每个子任务结束时汇报：改动文件、源码/RFC依据、测试证据、FAIL/NOT_TESTED、剩余风险。
5. 子任务通过后创建一个小而清晰的本地 commit；提交前检查 diff，不能混入临时文件、构建产物或其他阶段改动。
6. 不得 push。需要 push 时停止并等待用户明确指令。
7. 如发现当前基线回归，优先修复回归，不扩展新功能。

## 阶段 0：ping 任务收尾审查

- 检查 ping 相关未提交 diff，确认 IPv4 checksum、ICMP checksum、超时、统计、非法地址处理均有实际证据。
- 检查是否误把测试入口、临时脚本或无关改动混入。
- 补跑：`make clean && make`、原网络回归、ring3 UDP/TCP echo、用户态 ping。
- 如证据完整，提交：`user: add minimal ping command`。
- 若 socket backend 因 DHCP/时序不能稳定触发，保留 `NOT_TESTED`，不可伪造 PASS。

## 阶段 1：TCP/SACK 边界与恢复路径

- 补充重复段、部分重叠段、过期段、非法/越界/重复 SACK block、双缺口、scoreboard 上限、ACK 回收、序号回绕测试。
- 对照 `linux-ref/net/ipv4/tcp_input.c`、`tcp_output.c`、`tcp_timer.c`，以及 RFC 793/9293、2018、5681、6675。
- 检查 SACK 不推进 `snd_una`、不重复登记、已 SACK 段不重传、SACK-only ACK 立即补缺口、RTO 兜底正确。
- 通过后提交：`net: harden tcp sack edge cases`。

## 阶段 2：TCP 生命周期与连接管理

- 完善 FIN/RST、半关闭、同时关闭、控制报文重传、异常断开。
- 完善 TIME-WAIT、端口复用、SYN backlog、accept 队列。
- 参考 `linux-ref/net/ipv4/tcp_minisocks.c`、`tcp_input.c`、`tcp_output.c`、`tcp_timer.c`，RFC 793/9293/1122。
- 测试主动关闭、被动关闭、RST、重复 SYN、半关闭、多连接 accept、资源耗尽。
- 通过后按逻辑拆分提交，不要一个超大 commit。

## 阶段 3：TCP 窗口与阻塞语义

- 实现/修正零窗口、persist timer、窗口更新 ACK、接收缓冲满、MSS/窗口边界、序号回绕。
- 明确 `send/recv/accept` 的 `EAGAIN`、关闭、非法 FD、非法用户指针行为。
- 保持 socket ABI 不变；参考 Linux socket/TCP 源码与 RFC 793/9293/5681。
- 通过后提交：`net: harden tcp window and blocking semantics`。

## 阶段 4：用户态 socket API 加固

- 完善 `listen(backlog)` 与 accept 队列。
- 多连接并发、UDP 多 socket、端口冲突、地址过滤。
- FD 资源耗尽、重复 close、非 socket FD、非法指针、未连接 send/recv。
- 维护 ABI 表和用户态最小测试程序。
- 参考项目 syscall/VFS/FD 源码与 `linux-ref/net/socket.c`、`af_inet.c`。

## 阶段 5：网络工程完整性

按风险从低到高执行：

1. ARP 缓存老化、重试、失败回收。
2. DHCP 租约续期、超时和 fallback 状态机。
3. DNS 配置应用及最小 DNS 查询/解析；先明确用户态接口。
4. 网络错误统计、诊断输出和可复现测试。

参考 `linux-ref/net/ipv4/arp.c`、DHCP/UDP 相关实现、RFC 826、2131、1035、1122。

## 阶段 6：性能优化

在正确性稳定后执行：

- RX/TX 批量处理。
- 预分配 packet buffer pool，明确所有权和回收。
- NAPI 风格轮询或中断合并的最小实现。
- 减少协议层拷贝。
- 只有在生命周期和错误恢复清楚后才考虑零拷贝。

每项都要有基线与优化后测量，不得只凭代码审查宣称性能提升。参考 Linux NAPI、sk_buff、page pool 相关 `linux-ref` 代码。

## 阶段 7：真实网卡与应用验证

- 选定目标网卡/驱动和 DMA/中断模型，先完成可行性分析。
- 在真实硬件或更接近硬件的 QEMU 环境验证 ARP/IP/ICMP/UDP/TCP。
- 补最小 libc socket wrapper、进程/文件接口所需支持。
- 先做小型 HTTP 客户端/服务端，再开始 nginx 移植预研。
- shell 移植放在网络基础设施稳定之后。

## 停止条件

遇到以下情况必须暂停并向用户报告，不要擅自继续：

- 需要 push、force push、重写历史或删除用户改动。
- 需要大规模改变已有 ABI，且无法兼容。
- 需要引入无法审查来源的外部代码。
- 真实测试与代码预期冲突，且可能影响已有网络栈。
- 发现工作区历史改动归属不明，无法安全拆分 commit。

## 最终目标

形成可启动、可进入用户态、能执行 `ping`、能通过 UDP/TCP socket API，并逐步具备运行真实网络应用（最终目标为 nginx）的 Cat-OS 网络系统。

## 2026-08-25 Round1 推进记录（orchestrator 授权回填）

### 已落地 commit（db5ec07..70f6965）

| commit | 内容 |
|--------|------|
| 70f6965 | kernel 告警修复 |
| 1a77c6e | libc host_test 入口 + heap-ready 解耦 |
| 36fd594 | net TCP 五缺陷修复（幻影发送·序号回绕ACK·SYN竞态cli/sti闭合·persist ACK门·listen槽位残留） |
| 453818f | input 键盘 break码+E0状态机+Tab/Backspace |
| f4173ce | test const |
| db5ec07 | test 三新用例（tw_recycle/backlog_probe/l3b_race）+ docs/TEST_MATRIX.md |

### 验证证据

- `make clean && make`：0 warning
- `run_all`：全绿，含三新用例（backlog_probe 容量模型修正为 listen 占槽后 14 半开）
- `make check user_sock_abi`：81 PASS / 0 FAIL / 4 skip
- 键盘 QMP 注入：5/5（ab1A 回归 + Tab + Backspace + break不重复 + E0箭头无垃圾字节）

### 遗留与下一步

- 阶段5 顺序：统计计数器(nr32) → DNS(nr31) → ARP老化 → DHCP续期（net.c 串行）
- 审查遗留：MED 悬垂 fd → TCB 架构问题未修
- usermode.c 用户区改动中发现 kbd_done/kbd_empty 跳转别名问题（只报告不改动，等用户处理）

---

本节由 orchestrator 回填，原始协议条款不变。

## 2026-08-26 并行波次记录（orchestrator 授权回填）

### 已落地 commit（d934511..611b080，共 10 笔，均未 push）

| commit | 内容 |
|--------|------|
| 7852fb9 | kernel: stage4 在 sock_abi 之后拉起常驻 ring3 shell REPL |
| f9e226b | net: ARP 缓存老化、探测节流与失败回收；新增 arp_entry_expired 计数器 |
| 289e9ce | kernel: 拆除 nr==3 close 别名——read(fd=3) 不再静默关闭（L8 别名拆除） |
| a6752ca | net: DNS 名字解压缩，带指针环路防护 |
| 7a6d754 | usermode: kbd_done 标签别名坠入空重试路径修复（用户保留区自行落地） |
| 4acd797 | kernel: 消除 pcb[0] 饥饿；定义 /dev/kbd 多读者 FCFS 策略 |
| b9530ff | net: DHCP 租约续期状态机——T1/T2/expire、NAK 处理、仅续期退避 |
| fcc386e | kernel+userland: httpd 守护接线进 stage4（pid3，listen :7000）；run-httpd target |
| 61f86c7 | docs: ABI 修订记录（nr==3 语义）+ 测试矩阵 2026-08-26 波次 |
| 611b080 | net: 网络单体拆分为按协议模块（net_tcp.c 等），为并行开发铺路 |

docs 落点补充：除专笔 61f86c7 外，f9e226b/a6752ca 各随带 docs/RING3_SYSCALL_ABI.md 同步更新。

### 在途待提交（工作区 M 文件已核实，reconcile 进行中）

- TCP 64 连接扩容：net.h / net_internal.h / net_tcp.c（diff 中 "64" 扩容参数密集出现）
- nr=33/34/35 fork/waitpid/kill：process.c/h、syscall.c/h（+331 行主实现）
- dhcp_lease 用例：tests/net_suite.py
- S7n/backlog 对齐：reconcile 进行中，勿抢先提交

### 新开工

- e1000 真机加固
- FAT16 M-B0 块设备层
- 内存探测 E820
- poll 事件子系统设计
- 物理机移植评估

### 阶段宣告与下一主线

- **阶段 5（网络工程完整性）宣告完成**：ARP 老化（f9e226b）、DHCP 续期（b9530ff）、DNS 解析与解压缩（46ff839+a6752ca）、统计计数器均已落地。
- 下一主线 = nginx M1（fork/waitpid 已就绪待合入）→ M2 poll → 文件系统。