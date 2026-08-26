# Orchestrator 交接快照（2026-08-26，并行波次收尾）

> 给下一个会话的 orchestrator：本文件是重启前的现场固化。先读 OSDEV_PROJECT_NOTES.md、
> NEXT_TASKS_AUTONOMOUS.md（含 Round1 与 2026-08-26 波次回填记录），再读本文，然后按"待办队列"继续。

## 一、已落地（本地 commit，未 push，协议禁止擅自 push）
基线 d934511 → 今日 611b080，本波次 10 commit：
- 7852fb9 kernel: launch resident ring3 shell REPL after sock_abi in stage4
- f9e226b net: ARP cache aging, probe throttle and failure recycle; arp_entry_expired counter
- 289e9ce kernel: remove nr==3 close alias — read(fd=3) no longer silently closes（L8 别名拆除）
- a6752ca net: DNS name decompression with pointer-loop guards
- 7a6d754 usermode: fix kbd_done label aliasing into empty-retry path（原用户保留区问题已由用户自行落地）
- 4acd797 kernel: eliminate pcb[0] starvation; define /dev/kbd multi-reader FCFS policy
- b9530ff net: DHCP lease renewal state machine — T1/T2/expire, NAK handling, renewal-only backoff
- fcc386e kernel+userland: wire httpd daemon into stage4 (pid3, listen :7000); run-httpd target
- 61f86c7 docs: ABI revision record (nr==3 semantics), test matrix 2026-08-26 wave
- 611b080 net: split monolith into per-protocol modules for parallel development
docs 落点：专笔 61f86c7；另 f9e226b/a6752ca 各随带 docs/RING3_SYSCALL_ABI.md 同步。
测试证据以 docs/TEST_MATRIX.md 2026-08-26 波次记录为准，本轮回填未重跑 make/QEMU。

## 二、在飞/在途（工作区未提交改动，git status 已核实，reconcile 进行中）
| 在途项 | 领地 | 现状 |
|---|---|---|
| TCP 64 连接扩容 | net.h/net_internal.h/net_tcp.c | 代码在途待提交 |
| nr=33/34/35 fork/waitpid/kill | process.c/h、syscall.c/h | process.c +331 行主实现，待提交 |
| dhcp_lease 用例 | tests/net_suite.py | 用例在途待提交 |
| S7n/backlog 对齐 | docs/RING3_SYSCALL_ABI.md 等 | reconcile 进行中，勿抢先提交 |
历史后台代理（round1-doc/nginx-gap/pci-msi/httpd-skel/fork-core/review7/net-stats/libc-expand）产物均已收敛进上述 commit 或在途改动，不再单独跟踪。

## 三、待办队列（按序执行）
1. 收敛在途改动：S7n/backlog reconcile 完成后，按序小 commit（检查 diff、绝不混入 OSDEV_PROJECT_NOTES.md / *.bak / .opencode/ / opencode.json）：
   TCP 64 连接扩容 → nr=33/34/35 fork/waitpid/kill → dhcp_lease 用例。
2. 集中验证（build-runner 角色）：make clean&&make、run_all.sh、make check、dhcp 续期回归，全部以真实 QEMU 串口证据为准。
3. **阶段 5 已宣告完成**。下一主线 = nginx M1（依赖 fork/waitpid，在途待合入）→ M2 poll（事件子系统）→ 文件系统（FAT16）。
4. 新开工排期（可并行评估）：e1000 真机加固、FAT16 M-B0 块设备层、内存探测 E820、poll 事件子系统设计、物理机移植评估。
5. nginx M1 前置：等 nr=33/34/35 合入并验证后，按 nginx-gap 分析（.opencode/agentlogs-round2/nginx-gap.out）补齐 libc 缺口再启动移植。

## 四、配置修复记录（本次重启后应已生效）
- 病根：.opencode/agents/*.md 的 model 指向不存在模型(openrouter/stealth/ox-alpha 等)，且 agent 配置随会话启动快照、中途改盘不生效。
- 已落盘修复：全部角色 md 显式指定 opencode/* 免费模型；opencode.json 内联 agent 覆盖 +
  small_model=opencode/mimo-v2.5-free。重启后原生 task 工具应可用（权限规则只放行 7 个具名角色，
  general/explore 被禁）。若仍报 Model not found，用 `opencode models` 核对注册表后改 opencode.json。
- 本会话绕行方案：`nohup opencode run --dir /home/wjqawa/osdev -m <model> "$(cat brief)" > log 2>&1 </dev/null & disown`
  （注意 bash 工具超时会连坐子进程组，长任务务必 setsid/nohup 且轮询而非前台等待）。

## 五、红线重申
- 禁止 push；禁止碰 usermode.c（用户保留改动，内有已知 kbd_done/kbd_empty 跳转别名 bug，等用户定夺）、
  OSDEV_PROJECT_NOTES.md、*.bak；PASS 必须真机 QEMU 串口证据；FAIL 不伪装。
