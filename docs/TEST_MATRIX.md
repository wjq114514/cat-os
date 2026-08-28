# Cat-OS 测试矩阵（TEST_MATRIX）

> **版本说明**：网络套件历史验证波次以 **HEAD=`9cd8bbf`**、`fcc386e` 等记录为准；当前文档回填基于 **HEAD=`be876b6`**（2026-08-28 nginx 移植提交）。历史基线 **HEAD=`df995a8`**（2026-08-25 自动化推进收工总结）与 `tests/` 入库基线 **HEAD=`6796bd6`** 保留用于追溯。
> **整理方式**：初版为纯读档归纳（`tests/README.md`、`tests/run_all.sh`、`tests/net_suite.py` 用例名、`OSDEV_PROJECT_NOTES.md`「最终测试证据」「停工声明」章节），零源码改动，未跑 QEMU、未做构建。
> **2026-08-26 更新方式**：依据任务书已核实事实追加证据行/修订过期行（2026-08-26 验证波次、netstat nr=32 真机证据升级、新落地待验证项、`9cd8bbf` 调度修复摘录），零源码改动，本次更新仅编辑本文件。
> **证据纪律**：文中数字只引用文档既有记载与上述已核实事实，不做推算。
> **2026-08-26 二次增量**：基线推进至 HEAD=`fcc386e`（httpd 接线 stage4，commit 标题口径）；追加二次波次证据、六项新落地已验证项与 qemu_run.sh :7000 hostfwd 待验证标注（§1/§2/§4 增量修订），零源码改动，本次仅编辑本文件。
> **2026-08-28 nginx 增量**：追加 nginx 1.26.2 单进程静态 HTTP 的 fresh-QEMU r4 专项验收，并完成独立驱动复验；证据为各自的结果文件 + 串口文件，不计入 `net_suite.py` 的断言总数。

---

## 目录

- [1. 测试套件总表](#1-测试套件总表)
- [2. 已知覆盖缺口清单](#2-已知覆盖缺口清单)
- [3. 证据规则](#3-证据规则)
- [4. 已知问题与修复记录](#4-已知问题与修复记录)

---

## 1. 测试套件总表

| 套件名 | 运行命令 | 覆盖范围 | 最近证据结果 |
|---|---|---|---|
| blackbox（slirp hostfwd 黑盒） | `./qemu_run.sh --mode slirp --iso ../os.iso --serial <bb.serial> -- python3 ./net_suite.py --suite blackbox --serial <bb.serial> --json <bb.json>`（单次引导跑全部阶段） | DHCP/hostfwd 链路就绪、ring3 socket 错误路径探针、UDP 单 socket 回显与 recvfrom 地址捕获、TCP 多连接顺序 accept/回显/关闭、no-listener RST、无监听 UDP 静默丢包（存目 C7）、内核 UDP echo :7（存目 C3）、内核 banner 服务顺序×5+并发×8（:81）、backlog 占满两态记录（INFO）、全程无 panic/CPU exception/CR2=/[ERR] 底线扫描 | **19/19 PASS**（2026-08-25）；2026-08-26 波次复验通过（run_all ALL GREEN 74/74 组成部分）；二次波次（HEAD=`fcc386e`）复验 **19/19**，tcp81:parallel 单次抖动经复跑两轮全绿、判定为时序非回归 |
| inject（原始帧注入，每用例独立引导） | 默认经 `./run_all.sh`（`CATOS_INJECT_CASES="sack_t1 sack_t2 sack_t5 sack_t8 rst_l1"`）；单用例：`./qemu_run.sh --mode socket ... -- python3 ./net_suite.py --suite inject --case sack_t1 ...` | SACK 记分簿去重/合并（t1）、跨层重叠段 trim+cascade（t2）、双空洞并发管理（t5）、32 位序号回绕语义（t8）、RST 有效性校验三态 challenge-ACK/静默丢弃/复位（rst_l1）；生命周期用例 tw_recycle（TW 回收）/backlog_probe（backlog 探测）/l3b_race（L3B 竞态）；对应 HEAD `6796bd6` 的 SACK/RST 加固 | **inject 8 例全 PASS**（2026-08-26，run_all ALL GREEN 74/74 组成部分；2026-08-25 曾 6 例全 PASS） |
| lifecycle 边缘（L 系列 harness） | L1/L3A/L4 由 /tmp 下 ox_* 封装驱动；TW/TB/L3B 方向已落地为 inject 用例 tw_recycle/backlog_probe/l3b_race（随 run_all 编排，见上行） | RST 三分生命周期（L1）、stale-SYN 回收/RTO 放弃等生命周期边缘（L3A）、no_listener RST+ACK 等（L4）；TW 回收/backlog 探测/L3B 采样竞态；为阶段 2 TCP 生命周期加固（09fb9b4 等 5 commit）的配套证据 | **L1 10/10、L3A 6/6、L4 6/6 PASS**（2026-08-25）；TW/TB/L3B 方向 2026-08-26 经 inject 用例全绿 |
| user_sock_abi（ring3 socket ABI） | ring3 真机运行（socket ABI 测试基建） | socket ABI 用户态断言面，含崩溃修复链闭环回归项（exit 后 park 绷带→TSS 根因修复→绷带拆除→S5e EMSGSIZE 优先级→SYN 竞态重排 df995a8） | **81 PASS / 0 FAIL / 4 skip**（2026-08-26 首轮口径）；二次波次及当前 nginx fresh 串口均为 **85 PASS / 0 FAIL / 4 skip**（含 commit `289e9ce` L8 新增的 4 条锁定断言） |
| run_all.sh 一键编排 | `cd /home/wjqawa/osdev/tests && ./run_all.sh`（产物默认 `/tmp/catos-tests-run-<ts>/`） | [1/4] bash -n / ast.parse / py_compile 语法门禁 → [2/4] blackbox → [3/4] inject（每用例新引导；harness 故障 rc∈{3,4,5} 重试≤3，断言失败 rc=2 永不重试）→ [4/4] status.txt + JSON 结构化汇总 | 2026-08-26 波次：make **0 warning** + **ALL GREEN 74/74 断言**（blackbox 19 + inject 8 用例含 tw_recycle/backlog_probe/l3b_race）；编排与门禁逻辑见 `tests/run_all.sh:36-150`；2026-08-26 二次波次 ALL GREEN 复现（blackbox 19/19 含 tcp81:parallel 抖动复跑两轮全绿） |
| 中断流动专项 | 专项验证（统一命令未在本表登记；记录要点见 §4 verify3/SUMMARY.md 摘录） | 中断驱动的数据流动性：15s 观测窗字节曲线单调增长 + QMP `query-status` 确认 running | **PASS**（2026-08-26，调度修复后波次） |
| netstat 真机探针（nr=32） | QMP 逐键注入驱动 netstat 执行（串口日志 `/tmp/opencode/verify2/netstat_phaseA.serial`、`netstat_phaseB.serial`） | 真机返回 `[S]32→ret=12`；12 个计数字段经 phaseA/phaseB 两次快照解析成功 | **PASS**（2026-08-26，原 NOT_TESTED 已消除） |
| nginx fresh QEMU r4 + 独立复验（专用验收） | 构建完成后启动 `qemu-system-x86_64`，hostfwd `18098→guest:8080`（r4）或 `18100→guest:8080`（复验），挂载 `/tmp/catos-nginx-config-20260828.img`；通过 shell 触发 `nginx`、`netstat`、`ping 10.0.2.2` | shell 启动、FAT16 配置盘、HTTP `/` 200、`/missing` 404、重复启动保护、网络计数器、ICMP Echo；r4 另做临时诊断扫描 | **PASS**（2026-08-28；r4 为 `/tmp/catos-nginx-rebuild-20260828r4.result` + `.serial`，独立复验为 `/tmp/catos-nginx-doc-verify.result` + `.serial`；两次均 `QEMU final rc=0`、`OVERALL: PASS`） |

注：blackbox/inject 逐断言清单见 `tests/README.md` §用例 ↔ 功能/缺口映射；编号口径遵循 `docs/SOCKET_API.md` §缺口登记表。
注：nginx 专项由独立验收脚本驱动，不产生 `net_suite.py` 的 JSON；该行的 PASS 只由上述 `.result` 与 `.serial` 共同背书。

---

## 2. 已知覆盖缺口清单

提取自 `OSDEV_PROJECT_NOTES.md`「工作区遗留状态」「停工声明」及 keyboard 相关章节：

| # | 缺口 | 现状记载 | 影响 |
|---|---|---|---|
| G1 | **L3B 采样竞态脚本未入库** | 笔记停工声明明确列为下次开工建议第一条：「L3B采样竞态脚本入库」；其「harness修复版」仅存在于 /tmp（见 G2 同源风险）。**2026-08-26 缓解进展**：L3B 方向已落地为 inject 用例 `l3b_race` 并随 run_all ALL GREEN 通过（见 §1） | RTT 采样抑制（Karn）相关的竞态复现脚本无仓库内载体，证据不可复跑；用例化后复跑载体已具备 |
| G2 | **TW/TB harness 曾居 /tmp，未入库即面临丢失** | 「工作区遗留状态」：「/tmp 下测试脚本（TW1/TW2/TB1/RSTL2/L3B harness修复版）未入库，如需长期保留应搬入 tests/」；停工声明建议「TW/TB harness从/tmp迁移进tests/」。/tmp 不持久，一旦清理即丢失。**2026-08-26 缓解进展**：TW/backlog 方向已落地为 inject 用例 `tw_recycle`/`backlog_probe` 并随 run_all ALL GREEN 通过（见 §1） | 窗口（TW）与 backlog（TB）方向边缘验证无长期资产，lifecycle L 系列后续轮次可能无法复现；用例化后风险收敛 |
| G3 | **keyboard 输入类探针缺项（input 方向无自动化覆盖）** | 笔记「已知问题与缺陷」：① break 码处理不完整——`kh()` 只按 `s&0x7f` 匹配 0x2A/0x36，普通键 break 码走 make 路径→长按重复风险；② E0 扩展扫描码状态机未实现——箭头键/Num/Ctrl/Alt 静默丢失，E0+F0 断码可能按 0xF0 误处理；③ Tab(0x0F)、Backspace(0x0E) 扫描码表中为 0 被忽略；④ 非阻塞读取时序脆弱——QMP 注入与 ring3 唯一一次非阻塞 read 间存在竞态窗口；⑤ 阻塞式 `/dev/kbd` read 未实现（队列空返回 -1，无 yield/sleep/wakeup）。`tests/README.md`「范围外」亦载明 /tmp 下 catos_kbd_* 属 input 方向、不在网络套件范围 | 键盘路径零自动化断言，break/E0/Tab/Backspace 均无回归防线；停工声明将「keyboard break码/E0扩展码」列为下次开工事项 |
| G4 | **旧 ring3 socket 探针骨架未接线** | `tests/README.md` §尚未接线：`/tmp/cat-os-tests/user_ring3_socktest.c`（P01–P09/H1P/H1B/H2P… int 0x80 直调骨架）覆盖 H1/H2/M2/L1/L2/L6/L8 逐条断言，待接入 ring3 入口后在原处回填实测证据；它不同于已由 stage4 自动拉起的 `tests/user_sock_abi/user_sock_abi_test.c`，后者已有 85/0/4 串口结果 | 旧骨架对应的 H/M/L 逐条断言仍未接线，相关项保持 NOT_TESTED；stage4 套件结果单独计入上方 `user_sock_abi` 行 |
| G5 | **现状锁定型断言（修复后须同步改断言）** | `udpdead:silent_drop`（存目 C7：无 ICMP port unreachable）、`udp7:echo`（存目 C3：port 7 内核 echo vs ring3 探针双重行为）、`backlog_probe:*` 两态记录 A=排空/B=RST 仅 INFO 挂起判 FAIL | 这些断言锁定的是当前行为而非目标行为，对应缺口修复时必须同步更新断言，否则产生假 FAIL |
| G6 | **nr=31 DNS resolve（已验证）** | DHCP option 6 学习 `g_dns=10.0.2.3` 已落地；名字解压缩升级（commit `a6752ca`）后 localhost/example.org 双通，真机证据已回填 | **已实证**（2026-08-26 双通） |
| G7 | **交互 shell 命令增量（部分完成）** | shell 的 `nginx`、`netstat`、`ping <IPv4>` 已在 2026-08-28 r4 和独立 fresh QEMU 中通过；`help`、`resolve`、`exec`、`ls`、`cat`、`history`、`exit` 已接线但未由本专项逐项验收 | 两组 `.result` + `.serial` 双证据 PASS；未逐项覆盖部分保持 NOT_TESTED |
| G8 | **ARP 老化（已验证）** | 老化/probe 节流/失败回收落地（commit `f9e226b`，含 `arp_entry_expired` 计数器），42s stale 重发实证 | **已实证**（2026-08-26） |
| G9 | **L8 close 别名拆除（已验证）** | 别名已拆除（commit `289e9ce`），sock_abi 新增 4 条锁定断言：nr=3 一律 read；close 仅 nr=6 VFS / nr=28 socket | **已实证**（2026-08-26，make check 85 PASS） |

---

## 3. 证据规则

以下规则整理自 `tests/run_all.sh`、`tests/net_suite.py` 退出码契约与笔记「最终测试证据」口径：

### 3.1 PASS 的背书要求

- **`net_suite.py` 的 PASS 必须真机 QEMU 串口背书**：每条套件断言须有 `*.serial`（串口原文证据）+ `*.json`（结构化结果 `{suite, cases:{...:{passed,failed,hard_fails,results[],exit_code}}, exit_code}`）双产物落盘于 `CATOS_TEST_OUT`，缺任一不得记 PASS。独立的 nginx r4 专项不属于该套件，按上一条注释使用 `.result` + `.serial`。
- 断言风格统一为「命令 + 退出码 + 串口原文」三要素（`tests/README.md` 口径）；inject 用例还要求 `wait_serial` 命中内核日志行（如 `duplicate/overlap, re-ACK`、`cached 15B`）。
- inject 用例假设全新内核状态：必须经 `qemu_run.sh --mode socket` 或 `run_all.sh` 驱动（每用例一颗新 QEMU）；不带 `--case` 连跑全部仅为便利，会共享同一引导，不构成独立用例级证据。

### 3.2 NOT_TESTED 标注规则

- QEMU 缺失或 ISO 缺失：`run_all.sh` 打印 `NOT_TESTED (no qemu/no iso)` 并以 **0** 退出（环境问题不算失败），status.txt 落 `NOT_TESTED` 行。
- 已登记但未接线的探针（如 G4 的 ring3 骨架）：在接线回填实测证据前，相关缺口一律标注 NOT_TESTED，禁止以读码推断替代实测。

### 3.3 FAIL 与重试规则

- **断言失败 rc=2 永不重试**：这是真实回归信号，CI 侧严禁用重试掩盖；status.txt 记 `<label> FAIL rc=2`，run_all 最终退出码 1。
- **harness/环境故障 rc∈{3,4,5} 重试≤3 次**（QEMU 启动失败 3 / 引导超时 4 / 线缆故障 5）；耗尽后 status.txt 记 `<label> HARNESS rc=<rc>`——HARNESS 不是 FAIL，但也不得计为 PASS，须在报告中如实区分。
- 其他非预期 rc 直接落账为 FAIL，不做解释性豁免。

### 3.4 退出码契约速查

| 工具 | 退出码语义 |
|---|---|
| `qemu_run.sh` | `0`=成功（含 cmd rc=0）；`2`=cmd 断言失败；`3`=QEMU 启动失败；`4`=引导超时；`64`=用法错误 |
| `net_suite.py` | `0`=全部断言通过；`2`=存在断言失败；`5`=harness/环境故障（可整轮重试）；`64`=用法错误 |
| `run_all.sh` | `0`=全绿（含 NOT_TESTED 放行）；`1`=存在失败 |

---

## 4. 已知问题与修复记录

| 日期 | 问题 | 状态 | 证据/要点摘录 |
|---|---|---|---|
| 2026-08-26 | 调度器 IRQ0 抢占导致黑屏 | **已修复**（commit `9cd8bbf`） | 验证记录 `verify3/SUMMARY.md` 要点：修复后波次 make 0 warning；run_all ALL GREEN 74/74 断言（blackbox 19 + inject 8 用例含 tw_recycle/backlog_probe/l3b_race）；`make check` sock_abi 81 PASS / 0 FAIL / 4 skip；中断流动专项 PASS |
| 2026-08-26 | 二次验证波次（HEAD=`fcc386e`，涵盖 commit `289e9ce` L8 别名拆除及其后 kernel/net/userland 落地） | **已完成** | run_all **ALL GREEN**：blackbox **19/19**（tcp81:parallel 单次抖动，复跑两轮全绿 → 判定时序非回归）；`make check` **85 PASS / 0 FAIL / 4 skip**（含 L8 新锁定断言 ×4）。新落地已验证项：① ARP 老化（`f9e226b`）42s stale 重发实证；② DNS 解压缩（`a6752ca`）localhost/example.org 双通；③ DHCP 续期状态机（`b9530ff`）副本 LEASE_SCALE 验证；④ httpd M0 守护（`fcc386e`）curl×10 @18082 全 200、与 REPL 共存；⑤ pcb[0] 饥饿修复（`4acd797`）blackbox 恢复；⑥ L8 别名拆除（`289e9ce`）4 条锁定断言。**待验证**：qemu_run.sh 尚无 :7000 hostfwd（intfix 遗留），httpd :7000 外部可达性黑盒覆盖挂起 |
| 2026-08-26 | 二次验证波次（HEAD=`fcc386e`，涵盖 commit `289e9ce` L8 别名拆除及其后 kernel/net/userland 落地） | **已完成** | run_all **ALL GREEN**：blackbox **19/19**（tcp81:parallel 单次抖动，复跑两轮全绿 → 判定时序非回归）；`make check` **85 PASS / 0 FAIL / 4 skip**（含 L8 新锁定断言 ×4）。新落地已验证项：① ARP 老化（`f9e226b`）42s stale 重发实证；② DNS 解压缩（`a6752ca`）localhost/example.org 双通；③ DHCP 续期状态机（`b9530ff`）副本 LEASE_SCALE 验证；④ httpd M0 守护（`fcc386e`）curl×10 @18082 全 200、与 REPL 共存；⑤ pcb[0] 饥饿修复（`4acd797`）blackbox 恢复；⑥ L8 别名拆除（`289e9ce`）4 条锁定断言。历史记录中的 `:7000` hostfwd 待验证项已在后续测试资料中清偿 |
| 2026-08-28 | nginx 1.26.2 最小移植闭环（实现基线=`be876b6`） | **已完成（范围受限）** | fresh QEMU r4 与独立复验：FAT16 挂载、shell `nginx` 启动、HTTP `/` 200 + `/missing` 404、`netstat`、`ping`、重复启动保护全 PASS；两次结果均明确 `QEMU final rc=0`、`OVERALL: PASS`。独立复验前修正了驱动等待 shell ready 的时序；master/worker、upstream、可写日志、epoll 和高并发不在本次 PASS 范围内 |

---

*本文档为纯文档产物；未修改任何 `.c/.h/.asm/Makefile/linker.ld`、`OSDEV_PROJECT_NOTES.md` 或 `usermode.c`。2026-08-26 更新保留历史口径；2026-08-28 增量仅追加 nginx 专项验收与实现基线状态。*
