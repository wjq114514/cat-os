# Orchestrator 交接快照（2026-08-28，nginx 文档同步）

> 给下一个会话的 orchestrator：以下 2026-08-26 波次内容保留为历史记录；当前状态以本节和
> `NEXT_TASKS_AUTONOMOUS.md` 的 2026-08-28 回填为准。先读相关源码、nginx 移植笔记和
> 测试证据，再按当前缺口继续，不要从已经完成的 M0 重新开工。

## 当前状态（2026-08-28）

- nginx 实现基线为 `be876b6`，已完成并已 push 到 `origin/master`；当前新增内容只属于文档和验证复核。
- nginx 1.26.2 单进程静态 HTTP、FAT16 配置盘、shell `nginx`/`netstat`/`ping` 已通过
  fresh QEMU r4 和独立复验；证据为 `/tmp/catos-nginx-rebuild-20260828r4.result`、
  `/tmp/catos-nginx-doc-verify.result` 及对应 `.serial`。
- 两次均明确为 `QEMU final rc=0`、`OVERALL: PASS`；独立串口还确认 stage4 `user_sock_abi`
  为 85 PASS / 0 FAIL / 4 skip。完整 master/worker、signal、upstream/connect、
  可写日志、epoll 和高并发仍是未完成项。
- 未发现遗留的 `git add`、QEMU、nginx 或构建进程。当前只应提交相关文档；
  `.opencode/`、`attic/`、归档、`objs/` 和测试日志等生成物保持不动。

## 一、历史已落地（2026-08-26 波次）
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

## 二、历史在途记录（已收敛）
| 历史记录项 | 领地 | 当前状态 |
|---|---|---|
| TCP 64 连接扩容 | net.h/net_internal.h/net_tcp.c | 已由 `6270daf` 等后续提交收敛 |
| nr=33/34/35 fork/waitpid/kill | process.c/h、syscall.c/h | 已由 `84fb50d` 等后续提交收敛 |
| dhcp_lease 用例 | tests/net_suite.py | 已进入后续测试资料 |
| S7n/backlog 对齐 | docs/RING3_SYSCALL_ABI.md 等 | 已进入后续测试矩阵 |
历史后台代理（round1-doc/nginx-gap/pci-msi/httpd-skel/fork-core/review7/net-stats/libc-expand）
产物均已收敛；当前没有遗留的代码提交进程。

## 三、当前待办队列（按序执行）
1. 完成 nginx 相关 README、测试矩阵、分析/计划和交接资料同步；提交前只暂存这些文档。
2. 用 r4 和独立复验的 `.result` + `.serial`、源码行号和 `git diff --check` 做证据/格式复核；不得把
   未覆盖的完整 nginx 能力写成 PASS。
3. 后续主线是完整 nginx 缺口：进程生命周期与 signal、upstream/connect、可写日志、epoll、
   共享内存和容量；每个子项先查本地 nginx/Linux 参考源码，再真实 QEMU 验证。
4. 新开工排期（可并行评估）：e1000 真机加固、物理机移植评估及 nginx 完整特性拆分；不得
   重复已经完成的单进程静态 M0。

## 四、配置修复记录（本次重启后应已生效）
- 病根：.opencode/agents/*.md 的 model 指向不存在模型(openrouter/stealth/ox-alpha 等)，且 agent 配置随会话启动快照、中途改盘不生效。
- 已落盘修复：全部角色 md 显式指定 opencode/* 免费模型；opencode.json 内联 agent 覆盖 +
  small_model=opencode/mimo-v2.5-free。重启后原生 task 工具应可用（权限规则只放行 7 个具名角色，
  general/explore 被禁）。若仍报 Model not found，用 `opencode models` 核对注册表后改 opencode.json。
- 本会话绕行方案：`nohup opencode run --dir /home/wjqawa/osdev -m <model> "$(cat brief)" > log 2>&1 </dev/null & disown`
  （注意 bash 工具超时会连坐子进程组，长任务务必 setsid/nohup 且轮询而非前台等待）。

## 五、红线重申
- nginx 实现提交 `be876b6` 已在 `origin/master`；文档提交是否 push 由当前用户指令决定。
- 禁止碰 usermode.c（用户保留改动，内有已知 kbd_done/kbd_empty 跳转别名 bug，等用户定夺）、
  OSDEV_PROJECT_NOTES.md、*.bak；PASS 必须真机 QEMU 串口证据；FAIL 不伪装。
