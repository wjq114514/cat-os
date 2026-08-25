# Cat-OS 测试矩阵（TEST_MATRIX）

> **版本说明**：本文档基于 **HEAD=`df995a8`**（2026-08-25 自动化推进收工总结口径）与 `tests/` 入库基线 **HEAD=`6796bd6`** 整理。
> **整理方式**：纯读档归纳（`tests/README.md`、`tests/run_all.sh`、`tests/net_suite.py` 用例名、`OSDEV_PROJECT_NOTES.md`「最终测试证据」「停工声明」章节），零源码改动，未跑 QEMU、未做构建。
> **证据纪律**：文中「最近证据结果」只引用上述文档实际记载的数字与日期，不做推算。

---

## 目录

- [1. 测试套件总表](#1-测试套件总表)
- [2. 已知覆盖缺口清单](#2-已知覆盖缺口清单)
- [3. 证据规则](#3-证据规则)

---

## 1. 测试套件总表

| 套件名 | 运行命令 | 覆盖范围 | 最近证据结果 |
|---|---|---|---|
| blackbox（slirp hostfwd 黑盒） | `./qemu_run.sh --mode slirp --iso ../os.iso --serial <bb.serial> -- python3 ./net_suite.py --suite blackbox --serial <bb.serial> --json <bb.json>`（单次引导跑全部阶段） | DHCP/hostfwd 链路就绪、ring3 socket 错误路径探针、UDP 单 socket 回显与 recvfrom 地址捕获、TCP 多连接顺序 accept/回显/关闭、no-listener RST、无监听 UDP 静默丢包（存目 C7）、内核 UDP echo :7（存目 C3）、内核 banner 服务顺序×5+并发×8（:81）、backlog 占满两态记录（INFO）、全程无 panic/CPU exception/CR2=/[ERR] 底线扫描 | **19/19 PASS**（2026-08-25） |
| inject（原始帧注入，每用例独立引导） | 默认经 `./run_all.sh`（`CATOS_INJECT_CASES="sack_t1 sack_t2 sack_t5 sack_t8 rst_l1"`）；单用例：`./qemu_run.sh --mode socket ... -- python3 ./net_suite.py --suite inject --case sack_t1 ...` | SACK 记分簿去重/合并（t1）、跨层重叠段 trim+cascade（t2）、双空洞并发管理（t5）、32 位序号回绕语义（t8）、RST 有效性校验三态 challenge-ACK/静默丢弃/复位（rst_l1）；对应 HEAD `6796bd6` 的 SACK/RST 加固 | **inject 6 例全 PASS**（2026-08-25） |
| lifecycle 边缘（L 系列 harness，脚本居 /tmp 未入库） | 由 /tmp 下 ox_* 封装驱动（TW/TB/L3B harness 状态见 §2 缺口清单） | RST 三分生命周期（L1）、stale-SYN 回收/RTO 放弃等生命周期边缘（L3A）、no_listener RST+ACK 等（L4）；为阶段 2 TCP 生命周期加固（09fb9b4 等 5 commit）的配套证据 | **L1 10/10、L3A 6/6、L4 6/6 PASS**（2026-08-25） |
| user_sock_abi（ring3 socket ABI） | ring3 真机运行（socket ABI 测试基建 81 断言，随 c38a72f 入库） | socket ABI 用户态断言面，含崩溃修复链闭环回归项（exit 后 park 绷带→TSS 根因修复→绷带拆除→S5e EMSGSIZE 优先级→SYN 竞态重排 df995a8） | **81 PASS / 0 FAIL / 4 skip**（2026-08-25） |
| run_all.sh 一键编排 | `cd /home/wjqawa/osdev/tests && ./run_all.sh`（产物默认 `/tmp/catos-tests-run-<ts>/`） | [1/4] bash -n / ast.parse / py_compile 语法门禁 → [2/4] blackbox → [3/4] inject（每用例新引导；harness 故障 rc∈{3,4,5} 重试≤3，断言失败 rc=2 永不重试）→ [4/4] status.txt + JSON 结构化汇总 | 编排与门禁逻辑见 `tests/run_all.sh:36-150` |

注：blackbox/inject 逐断言清单见 `tests/README.md` §用例 ↔ 功能/缺口映射；编号口径遵循 `docs/SOCKET_API.md` §缺口登记表。

---

## 2. 已知覆盖缺口清单

提取自 `OSDEV_PROJECT_NOTES.md`「工作区遗留状态」「停工声明」及 keyboard 相关章节：

| # | 缺口 | 现状记载 | 影响 |
|---|---|---|---|
| G1 | **L3B 采样竞态脚本未入库** | 笔记停工声明明确列为下次开工建议第一条：「L3B采样竞态脚本入库」；其「harness修复版」仅存在于 /tmp（见 G2 同源风险） | RTT 采样抑制（Karn）相关的竞态复现脚本无仓库内载体，证据不可复跑 |
| G2 | **TW/TB harness 曾居 /tmp，未入库即面临丢失** | 「工作区遗留状态」：「/tmp 下测试脚本（TW1/TW2/TB1/RSTL2/L3B harness修复版）未入库，如需长期保留应搬入 tests/」；停工声明建议「TW/TB harness从/tmp迁移进tests/」。/tmp 不持久，一旦清理即丢失 | 窗口（TW）与 backlog（TB）方向边缘验证无长期资产，lifecycle L 系列后续轮次可能无法复现 |
| G3 | **keyboard 输入类探针缺项（input 方向无自动化覆盖）** | 笔记「已知问题与缺陷」：① break 码处理不完整——`kh()` 只按 `s&0x7f` 匹配 0x2A/0x36，普通键 break 码走 make 路径→长按重复风险；② E0 扩展扫描码状态机未实现——箭头键/Num/Ctrl/Alt 静默丢失，E0+F0 断码可能按 0xF0 误处理；③ Tab(0x0F)、Backspace(0x0E) 扫描码表中为 0 被忽略；④ 非阻塞读取时序脆弱——QMP 注入与 ring3 唯一一次非阻塞 read 间存在竞态窗口；⑤ 阻塞式 `/dev/kbd` read 未实现（队列空返回 -1，无 yield/sleep/wakeup）。`tests/README.md`「范围外」亦载明 /tmp 下 catos_kbd_* 属 input 方向、不在网络套件范围 | 键盘路径零自动化断言，break/E0/Tab/Backspace 均无回归防线；停工声明将「keyboard break码/E0扩展码」列为下次开工事项 |
| G4 | **ring3 socket 探针骨架未接线** | `tests/README.md` §尚未接线：`/tmp/cat-os-tests/user_ring3_socktest.c`（P01–P09/H1P/H1B/H2P… int 0x80 直调骨架）覆盖 H1/H2/M2/L1/L2/L6/L8 逐条断言，待接入 ring3 入口后在原处回填实测证据；M1/M3/M4/L3/L4/L5/L7 仅登记（SOCKET_API.md 口径：待核实） | H/H2/M/L 各缺口只有登记无逐条断言证据，接线前一律 NOT_TESTED |
| G5 | **现状锁定型断言（修复后须同步改断言）** | `udpdead:silent_drop`（存目 C7：无 ICMP port unreachable）、`udp7:echo`（存目 C3：port 7 内核 echo vs ring3 探针双重行为）、`backlog_probe:*` 两态记录 A=排空/B=RST 仅 INFO 挂起判 FAIL | 这些断言锁定的是当前行为而非目标行为，对应缺口修复时必须同步更新断言，否则产生假 FAIL |

---

## 3. 证据规则

以下规则整理自 `tests/run_all.sh`、`tests/net_suite.py` 退出码契约与笔记「最终测试证据」口径：

### 3.1 PASS 的背书要求

- **PASS 必须真机 QEMU 串口背书**：每条 PASS 须有 `*.serial`（串口原文证据）+ `*.json`（结构化结果 `{suite, cases:{...:{passed,failed,hard_fails,results[],exit_code}}, exit_code}`）双产物落盘于 `CATOS_TEST_OUT`，缺任一不得记 PASS。
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

*本文档为纯文档产物；未修改任何 `.c/.h/.asm/Makefile/linker.ld`、`OSDEV_PROJECT_NOTES.md` 或 `usermode.c`。*
