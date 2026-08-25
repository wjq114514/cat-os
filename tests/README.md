# Cat-OS tests/ —— 测试基建正式化（code10）

本目录把原先散落在 `/tmp/cat-os-tests/` 与 `/tmp/*.py` 的临时测试资产**改进后入库**。
原型一律保留在 /tmp 原样不动（供 code4 复用）；本目录为唯一维护版。

- 仓库：`/home/wjqawa/osdev`，入库基线 HEAD=`6796bd6`（net: harden tcp sack edge cases）
- 本目录只新增文件，未修改仓库任何现有文件（net.c/usermode.c/kernel.c 等均未触碰）

## 文件清单

| 文件 | 作用 | 来源与改进 |
|---|---|---|
| `qemu_run.sh` | 统一 QEMU 启动封装：串口落盘、slirp hostfwd / socket-netdev 双模式、参数化、就绪等待、可选执行测试命令并透传退出码 | 合并自 `qemu_run.sh` + `run_sack_edge.sh` + `ox_run_lifecycle.sh` 三套临时封装；新增 `--mode/--hold/--keep/--boot-timeout`、tag 化残留回收、结构化收尾行 |
| `net_suite.py` | 测试用例整合：blackbox(hostfwd) 全部阶段 + inject(原始帧注入) 核心子集；保留「命令+退出码+串口原文」断言风格；支持 JSON 报告 | blackbox 移植自 `ext_socktest.py`；inject 取 `sack_edge.py` 核心 t1/t2/t5/t8 与 `ox_lifecycle_edge.py` L1 |
| `wire_lib.py` | 注入套件共享线缆层：帧构造/校验和/SACK 选项、Wire 类、接收状态机、drain() 泵、coalescing-aware 区间工具 | 合并自 `sack_edge.py`(W) 与 `ox_lifecycle_edge.py`(W2)；collect() 采用 **W2 padding-aware 最终形态**（按 IP 总长裁剪 payload，bare challenge-ACK 不再误判为带数据） |
| `run_all.sh` | 一键编排：语法门禁 → blackbox → inject（每用例新引导）→ 结构化汇总；harness 故障重试≤3、断言失败永不重试 | 替代 `run_all.sh`；不再做 make/ring3 骨架编译（见下「范围外」） |
| `README.md` | 本文档 | — |

## 快速开始

```sh
cd /home/wjqawa/osdev/tests

# 冒烟：启动 QEMU(slirp) → 等 guest:80 就绪 → hold 5s → 回收
./qemu_run.sh --iso ../os.iso --serial /tmp/smoke.serial --hold 5

# 黑盒全套（单次引导跑完所有 hostfwd 阶段）
./qemu_run.sh --mode slirp --serial /tmp/bb.serial -- \
  python3 ./net_suite.py --suite blackbox --serial /tmp/bb.serial --json /tmp/bb.json

# 注入单用例（每用例必须新引导内核！）
./qemu_run.sh --mode socket --serial /tmp/t1.serial -- \
  python3 ./net_suite.py --suite inject --case sack_t1 --serial /tmp/t1.serial --json /tmp/t1.json

# 一键全量
./run_all.sh                       # 产物默认在 /tmp/catos-tests-run-<ts>/
CATOS_INJECT_CASES="sack_t1 rst_l1" ./run_all.sh   # 自选注入用例
```

### qemu_run.sh 退出码
`0`=成功（含 cmd rc=0）；`2`=cmd 断言失败；`3`=QEMU 启动失败；`4`=引导超时；`64`=用法错误。

### net_suite.py 退出码
`0`=全部断言通过；`2`=存在断言失败（真实回归信号，CI 勿重试掩盖）；`5`=harness/环境故障（线缆中断等，可整轮重试）；`64`=用法错误。
`run_all.sh` 已按此语义编排重试。

## 用例 ↔ 功能/缺口映射

编号口径遵循 `docs/SOCKET_API.md` §缺口登记表（H1/H2/M1-M4/L1-L8）；
C3/C7/D1 为该文附注中的存目编号。M1/M3/M4/L3/L4/L5/L7 在 SOCKET_API.md 中为
「仅登记（待核实）」，此处不强行挂靠。

### blackbox 套件（hostfwd 黑盒，驱动内核演示服务 + ring3 探针）

| 断言名 | 验证点 | 功能/缺口关联 |
|---|---|---|
| `boot:guest80_reachable` / `boot:guest81_reachable` | DHCP(DNS 兜底)+hostfwd 链路就绪 | 网络栈初始化端到端健康 |
| `serial:user socket ERRORS PASS` | ring3 探针错误路径全过：EBADF/ENOTSOCK/ENOTCONN/EAGAIN/double-close | ABI 错误码面健康度（H1/H2/L1 的运行时旁证；逐项断言见下方 ring3 骨架行） |
| `udp7000:reply` + `serial:user UDP PASS` | UDP 单 socket 回显、recvfrom 地址捕获 | UDP 用户态通路 |
| `tcp80:roundtrip#*` + `serial:user TCP MULTI PASS` | TCP 多连接顺序 accept/回显/关闭 | TCP 用户态多连接 |
| `rst:no_listener_*` | 无监听端口 RST（或 connect refused） | net.c tcp_handle no-listener 路径 |
| `udpdead:silent_drop` | 无监听 UDP 静默丢包 | 存目 C7：无 ICMP port unreachable（现状行为锁定，修复 C7 后需同步改此断言） |
| `udp7:echo` | 内核 UDP echo 服务 | 存目 C3：port 7 双重行为（内核 echo vs ring3 探针） |
| `tcp81:seq#*` / `tcp81:parallel` | 内核 banner 服务顺序×5 + 并发×8（conn 表容量内） | 内核 TCP 并发能力 |
| `backlog_probe:*`（INFO） | backlog 占满后第 5 条连接两态记录（A=排空/B=RST），仅挂起判 FAIL | listen backlog 行为存档 |
| `serial:final_scan` | 全程无 panic / CPU exception / CR2= / [ERR] | 稳定性底线 |

### inject 套件（原始帧注入，每用例独立引导；对应 HEAD 6796bd6 的 SACK/RST 加固）

| 用例 | 验证点 | 关联 |
|---|---|---|
| `sack_t1` | in-order ACK 推进；已交付重复不重 ACK；OOO 缓存并发 SACK；dup-OOO 单次登记（无双槽）；补洞合并恰好交付一次；串口 `duplicate/overlap, re-ACK` 与裸 `out-of-order cached` 行 | SACK 记分簿去重/合并正确性（SACK 加固组） |
| `sack_t2` | 跨层重叠段 trim+cascade 至 base+20；合并后 SACK 清空；过期 X 重发时 ACK 稳定；串口 `cached 15B` | 重叠裁剪与级联推进（SACK 加固组） |
| `sack_t5` | 双空洞同时持有且 ACK 钉住；补洞 1 后 ACK=b+40 且 G2 区间幸存；补洞 2 后 ACK=b+70 | 多 SACK 块并发管理（SACK 加固组） |
| `sack_t8` | 序号跨 2^32 顺序交付（ACK==4）；回绕后 OOO/SACK=(0x10,0x1A)；过期段拒绝（有符号比较）；回绕前 dup 拒绝；回绕点重叠排队；级联完成 ACK==0x1A | 32 位序号回绕语义（SACK 加固组，含 harness 侧修正注记） |
| `rst_l1` | 窗内非精确 RST→challenge-ACK 且连接存活；窗上方/窗下方 RST→静默丢弃；精确 seq RST→复位；关闭后数据遇 RST/no-listener | RST 有效性校验三态（移植自 ox_lifecycle_edge.L1，TCP 安全加固组） |

### 尚未接线（NOT_TESTED，归属 ring3/shell 方向任务）

`/tmp/cat-os-tests/user_ring3_socktest.c`（P01–P09/H1P/H1B/H2P… int 0x80 直调骨架，
双语义模式 `-DSEMANTICS_CURRENT=1/0`）覆盖以下缺口的**逐条**断言，待其接入 ring3
入口后在原处回填实测证据：

| 缺口 | 语义 | 骨架探针 |
|---|---|---|
| H1 | 用户指针非法族须 EFAULT、合法指针不得误报 | H1P/H1B |
| H2（同源 D1） | TCP bind 同端口：现状静默「附着」返 0，目标 EADDRINUSE | H2P |
| M2 | 底层 -1 哨兵混叠 EMSGSIZE/EADDRNOTAVAIL/EAGAIN；UDP 上限预检；UNBOUND sendto 显式拒绝 | M2 组 |
| L1 | listen-before-bind 应 `-EINVAL`（缺 autobind） | L1 组 |
| L2 | fd 分配策略（0-2 std 流占用+最低空闲+kind 隔离，code7 已落地） | P01–P09 回归 |
| L6 | 零长缓冲误报 EFAULT（code6 已修复，n==0 放行） | 回归项 |
| L8 | close 双重别名关系（nr==3↔6↔28，已文档化） | 回归项 |
| M1/M3/M4/L3/L4/L5/L7 | 仅登记（SOCKET_API.md 口径：待核实，以协调者清单为准） | — |

## CI 化要点

- **结构化输出**：每个套件/用例可 `--json <path>` 输出 `{suite, cases:{<name>:{passed,failed,hard_fails,results[],exit_code}}, exit_code}`；`run_all.sh` 汇总表即由这些 JSON 生成。
- **退出码契约**：断言失败(2)与环境故障(5/3/4)严格分离，runner 只对后者重试——避免掩盖真回归。
- **fresh-boot 隔离**：inject 用例假设全新内核状态；务必经 `qemu_run.sh --mode socket` 或 `run_all.sh` 驱动（每用例一颗新 QEMU）。`net_suite.py --suite inject` 不带 `--case` 连跑全部仅为便利，会共享同一引导。
- **参数化**：hostfwd 端口（`P_TCP80/P_TCP81/P_DEAD_TCP/P_UDP7/P_UDP7000/P_DEAD_UDP`）、wire 端口（`CATOS_WIRE_PORT`）、内存（`CATOS_MEM`）、QEMU 路径（`CATOS_QEMU`）、迭代数（`TCP81_SEQ/TCP81_PAR`）、boot 超时（`CATOS_BOOT_TIMEOUT`）均可环境变量覆盖，便于并行 CI 分配端口。
- **inject 目标端口前提**：inject 用例握手 `CATOS_INJECT_DPORT`（默认 81）。
  历史教训：内核曾同时在 :80/:81 挂 LISTEN，2026-08-25 commit 6796bd6 起
  net.c 仅保留 `tcp_listen(81)`；若未来内核监听端口再变，改此环境变量即可，
  无需改用例代码。
- **产物**：`*.serial`（串口原文证据）与 `*.json`（结构化结果）都落在 `CATOS_TEST_OUT`。

## 范围外（有意不做）

- **make 构建**：Makefile 归 code9 可能追加，避免双改；构建健康检查留在构建侧任务。
- **ring3 骨架接线**：usermode.c/shell 方向禁碰（用户区/code4/shell 任务所有）；骨架仍居 /tmp。
- **输入类探针**：/tmp 下 kbd 相关脚本（catos_kbd_* 等）属 input 方向，不在本网络套件范围。

## 原型对照表（/tmp 原样保留，勿改）

| 入库文件 | 原型 |
|---|---|
| tests/qemu_run.sh | /tmp/cat-os-tests/qemu_run.sh、/tmp/run_sack_edge.sh、/tmp/ox_run_lifecycle.sh |
| tests/net_suite.py (blackbox) | /tmp/cat-os-tests/ext_socktest.py |
| tests/net_suite.py (inject) | /tmp/sack_edge.py(t1/t2/t5/t8)、/tmp/ox_lifecycle_edge.py(L1) |
| tests/wire_lib.py | /tmp/sack_edge.py(W/状态机)、/tmp/ox_lifecycle_edge.py(W2 collect) |
| tests/run_all.sh | /tmp/cat-os-tests/run_all.sh |

注：`/tmp/lifecycle_edge.py` 曾被并行派发覆写，L 系列以 `/tmp/ox_*.py` 为准；
`/tmp/tcp_lifecycle_edges.py` 等其余历史探针已被上述整合覆盖或废弃，不再搬运。
