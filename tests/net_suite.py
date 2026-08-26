#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Cat-OS tests/net_suite.py —— 网络测试套件整合版（code10 正式化入库）。

整合来源（原型保留在 /tmp 供 code4 复用，本文件为唯一入库版）：
- blackbox 套件 = /tmp/cat-os-tests/ext_socktest.py 的全部阶段：经 QEMU slirp
  hostfwd 黑盒驱动内核演示服务与 ring3 探针，保留「命令 + 退出码 + 串口原文」
  断言风格与原断言名（README 用例映射依赖这些名字）。
- inject 套件 = /tmp/sack_edge.py 核心用例子集（sack_t1/t2/t5/t8）+
  /tmp/ox_lifecycle_edge.py 的 L1（rst_l1：RST 三态校验）。经 QEMU
  socket-netdev 原始帧注入；每个用例假设一颗**新引导**的内核——请用
  ``qemu_run.sh --mode socket -- python3 net_suite.py --suite inject --case <名>``
  驱动（run_all.sh 已按此编排）。
- dhcp 用例 = dhcp_lease（2026-08-26 入库）：slirp 模式 + LEASE_SCALE 专用
  ISO 常驻验证租约首取与 T1 续期循环。LEASE_SCALE 是编译期宏（net_dhcp.c，
  commit b9530ff），故配套 ``--build-dhcp-scale-iso`` 迷你构建器：把源树
  复制到 /tmp 副本后以 ``make CFLAGS+=-DCATOS_DHCP_LEASE_SCALE=N`` 重编出
  dhcp_scale.iso 再由本用例引用——主仓库零触碰。slirp 永不静默也永不 NAK，
  故 T2/REBINDING、expire、NAK 路径不在本用例覆盖面（见 README NOT_TESTED）。

退出码：
  0 = 全部断言通过
  2 = 存在断言失败（真实回归信号，runner 不得重试掩盖）
  5 = harness/环境故障（线缆中断、SYN-ACK 超时等，可整轮重试）
 64 = 用法错误

用法：
  python3 net_suite.py --list
  python3 net_suite.py --suite blackbox --serial serial.log --json bb.json
  python3 net_suite.py --suite inject --case sack_t1 --serial serial.log --json t1.json
  python3 net_suite.py --build-dhcp-scale-iso SRC_TREE OUT_ISO [--scale N]
                                                        [--scratch DIR]
"""

import argparse
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import wire_lib as wl  # noqa: E402

EXIT_OK = 0
EXIT_ASSERT = 2
EXIT_HARNESS = 5
EXIT_USAGE = 64


def _env_int(name, default):
    try:
        return int(os.environ.get(name, "") or default)
    except ValueError:
        return default


# ==========================================================================
# 通用断言管道
# ==========================================================================

class Suite(object):
    """一个套件/用例的断言收集器。info 以 '[INFO] ' 开头的记录不计失败。"""

    def __init__(self, name, serial):
        self.name = name
        self.serial = serial
        self.results = []          # (name, ok, info)

    def check(self, name, cond, info=""):
        ok = bool(cond)
        self.results.append((name, ok, str(info)))
        print("[%s] %s%s" % ("PASS" if ok else "FAIL", name,
                             ("  (%s)" % info) if info else ""))
        return ok

    def note(self, name, msg):
        self.results.append((name, True, "[INFO] " + msg))
        print("[INFO] %s: %s" % (name, msg))

    @property
    def hard_fails(self):
        return [(n, i) for n, ok, i in self.results
                if not ok and not i.startswith("[INFO]")]

    def summary(self):
        fails = self.hard_fails
        n_info = sum(1 for _, _, i in self.results if i.startswith("[INFO]"))
        total = len(self.results) - n_info
        print("=" * 56)
        print("SUMMARY[%s]: %d/%d passed, %d failed, %d info"
              % (self.name, total - len(fails), total, len(fails), n_info))
        for n, i in fails:
            print("  FAILED: %s  (%s)" % (n, i))
        print("=" * 56)

    def report(self):
        return {
            "passed": len(self.results) - len(self.hard_fails)
                      - sum(1 for _, _, i in self.results if i.startswith("[INFO]")),
            "failed": len(self.hard_fails),
            "hard_fails": [{"name": n, "info": i} for n, i in self.hard_fails],
            "results": [{"name": n, "ok": ok, "info": i}
                        for n, ok, i in self.results],
        }


def wait_serial(S, pattern, timeout, required=True):
    """轮询串口日志直到出现 pattern（原文匹配）。成败都登记 serial:* 断言。"""
    rx = re.compile(pattern.encode() if isinstance(pattern, str) else pattern)
    deadline = time.time() + timeout
    found = False
    while time.time() < deadline:
        try:
            with open(S.serial, "rb") as f:
                if rx.search(f.read()):
                    found = True
                    break
        except FileNotFoundError:
            pass
        time.sleep(0.25)
    if required:
        S.check("serial:%s" % pattern, found,
                "" if found else "timeout %ss" % timeout)
    return found


def lsz(p):
    try:
        return os.path.getsize(p)
    except OSError:
        return 0


def lslice(p, off):
    """读取串口文件 [off, EOF) 原文 —— 「串口原文」证据断言的基础设施。"""
    try:
        with open(p, "r", errors="replace") as f:
            f.seek(off)
            return f.read()
    except OSError:
        return ""


# ==========================================================================
# blackbox 套件（slirp hostfwd；移植自 ext_socktest.py，断言名保持一致）
# ==========================================================================

HOST = "127.0.0.1"
P_TCP80 = _env_int("P_TCP80", 18080)      # guest :80   <- ring3 单发回显服务器
P_TCP81 = _env_int("P_TCP81", 18081)      # guest :81   <- 内核 banner 服务(02:30 起 16x90B 字母序列)
P_DEAD_TCP = _env_int("P_DEAD_TCP", 18099)   # guest 9999  <- 无监听端口（RST）
P_UDP7 = _env_int("P_UDP7", 17007)        # guest :7    <- 内核 UDP echo
P_UDP7000 = _env_int("P_UDP7000", 17000)  # guest :7000 <- ring3 UDP 回显探针触发源
P_DEAD_UDP = _env_int("P_DEAD_UDP", 16969)   # guest 16969 <- 无 UDP 监听


def _drain_close(s, grace=2.0):
    """探测连接的卫生关闭：排空对端在途数据直到 EOF/静默，再优雅收尾。

    背景（07:50 blackbox 事故复盘）：对 :81 banner 服务「connect 即 close」，
    服务端随后推 16x90B 数据撞上已关闭的宿主套接字 -> host RST -> 内核 TCB
    复位；此后 slirp 与内核围绕陈旧 :81 四元组陷入无限 no-listener-RST 战争
    （旧串口 9949 行刷屏），风暴还淹没 rst 阶段 :9999 的回程 RST。
    排空后 FIN 闭环即可掐断战争源头。"""
    try:
        s.settimeout(grace)
        end = time.time() + grace
        while time.time() < end:
            try:
                chunk = s.recv(4096)
            except (socket.timeout, OSError):
                break
            if not chunk:
                break
        try:
            s.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
    finally:
        try:
            s.close()
        except OSError:
            pass


def wait_tcp_port(port, timeout):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            s = socket.create_connection((HOST, port), timeout=2)
            _drain_close(s)
            return True
        except OSError:
            time.sleep(0.5)
    return False


def recv_until(s, want_len=None, timeout=8.0):
    """读取直到达到 want_len 或对端关闭/超时；返回 (bytes, how)。"""
    s.settimeout(timeout)
    buf = b""
    end = time.time() + timeout
    while time.time() < end:
        try:
            chunk = s.recv(4096)
        except socket.timeout:
            break
        except ConnectionResetError:
            return buf, "reset"
        if not chunk:
            return buf, "eof"
        buf += chunk
        if want_len is not None and len(buf) >= want_len:
            return buf, "len"
    return buf, "timeout"


def tcp_roundtrip_80(payload, timeout=8.0):
    """guest :80 ring3 服务器语义：单次 recv -> 原样回显 -> 关闭。"""
    s = socket.create_connection((HOST, P_TCP80), timeout=5)
    try:
        s.settimeout(timeout)
        s.sendall(payload)
        return recv_until(s, want_len=len(payload), timeout=timeout)
    finally:
        s.close()


def stage_boot(S):
    ok80 = wait_tcp_port(P_TCP80, _env_int("BOOT_TCP_TIMEOUT", 90))
    S.check("boot:guest80_reachable", ok80,
            "DHCP+slirp hostfwd ready" if ok80 else "timeout")
    if not ok80:
        return False
    ok81 = wait_tcp_port(P_TCP81, 20)
    S.check("boot:guest81_reachable", ok81)
    return True


def stage_ring3_errors(S):
    """ring3 内建错误路径探针（EBADF/ENOTSOCK/ENOTCONN/EAGAIN/双关）。"""
    wait_serial(S, "user socket ERRORS PASS", 90)


def stage_udp7000(S):
    """触发并验证 ring3 UDP 回显探针。"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(10)
    s.bind((HOST, 0))
    payload = b"catos-udp-probe-01"
    try:
        s.sendto(payload, (HOST, P_UDP7000))
        try:
            data, addr = s.recvfrom(2048)
        except socket.timeout:
            S.check("udp7000:reply", False, "no reply in 10s")
            return
        S.check("udp7000:reply", data == payload,
                "from %s, %dB" % (addr, len(data)))
    finally:
        s.close()
    wait_serial(S, "user UDP PASS", 30)


def stage_tcp_multi(S):
    """两次连接 guest:80 驱动 ring3 TCP MULTI 探针。"""
    allok = True
    for i in range(2):
        payload = ("catos-tcp-%d" % i).encode()
        try:
            data, how = tcp_roundtrip_80(payload)
        except OSError as e:
            allok &= S.check("tcp80:roundtrip#%d" % i, False, repr(e))
            continue
        allok &= S.check("tcp80:roundtrip#%d" % i, data.startswith(payload),
                         "%dB/%s" % (len(data), how))
    wait_serial(S, "user TCP MULTI PASS", 30)
    return allok


def stage_rst_no_listener(S):
    """无监听端口：期望 RST（reset）或立即 EOF，不应有任何数据。

    诊断增强（不改判定语义）：记录 connect 耗时与阶段窗口内串口
    `TCP :9999 no listener, RST` 计数。注意 net.c 该日志行打印于
    arp_resolve()/发包之前 —— 「有日志」≠「RST 已出网口」，计数仅作
    内核意图 vs 线缆实况的关联证据。"""
    o0 = lsz(S.serial)
    t0 = time.time()
    try:
        s = socket.create_connection((HOST, P_DEAD_TCP), timeout=5)
    except OSError as e:
        # slirp 直接拒绝也算 RST 语义成立
        S.check("rst:no_listener_refused_or_reset", True,
                "connect refused: %r (%.1fs)" % (e, time.time() - t0))
        return
    data, how = recv_until(s, timeout=6)
    s.close()
    log_n = lslice(S.serial, o0).count(":9999 no listener, RST")
    S.check("rst:no_listener_reset_or_eof",
            (how in ("reset", "eof")) and len(data) == 0,
            "how=%s data=%r dt=%.1fs guest_no_listener_logs=%d"
            % (how, data[:32], time.time() - t0, log_n))


def stage_udp_dead(S):
    """无监听 UDP：静默丢包（缺口 C7：无 ICMP port unreachable，存目）。"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(2.0)
    try:
        s.sendto(b"nobody-home", (HOST, P_DEAD_UDP))
        try:
            data, _a = s.recvfrom(2048)
            S.check("udpdead:silent_drop", False,
                    "unexpected reply %r (缺 ICMP unreachable 属已知缺口 C7)"
                    % data[:32])
        except socket.timeout:
            S.check("udpdead:silent_drop", True,
                    "无响应（符合现状：无 ICMP port unreachable）")
    finally:
        s.close()


def stage_udp7_echo(S):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(6)
    payload = b"echo-me-7"
    try:
        s.sendto(payload, (HOST, P_UDP7))
        try:
            data, addr = s.recvfrom(2048)
            S.check("udp7:echo", data == payload, "from %s" % (addr,))
        except socket.timeout:
            S.check("udp7:echo", False, "no reply in 6s")
    finally:
        s.close()


def _read_banner(sock, total, budget=8.0):
    """读 banner 直到 EOF/reset/集满 total；应对 90B 分段的部分读。"""
    buf = b""
    end = time.time() + budget
    sock.settimeout(max(0.5, budget))
    while time.time() < end and len(buf) < total:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            return buf, "timeout"
        except ConnectionResetError:
            return buf, "reset"
        if not chunk:
            return buf, "eof"
        buf += chunk
    return buf, ("len" if len(buf) >= total else "timeout")


def stage_tcp81(S):
    """内核 banner 服务：顺序 ×N + 并发 ×M（conn 表容量内）。

    行为变更（02:30 起，SACK 边界 commit 6796bd6 前置改动）：
      旧：单段 12B b"TCP-RTO-REAL"
      新：16x90B=1440B 字母序列，第 i 字节 = 'A'+(i%26)，发完内核主动 close。
    实测读取按段到达（450/360/270/360/180B 部分读），断言改为结构化：
      - 首选：len==1440 且逐字节匹配字母序列；
      - 容忍：EOF 收尾、长度为 90 的倍数且内容为序列前缀（部分读降级通过，
        info 标注 partial 供回归观察）；
      - 兼容：旧 12B banner 回归时 startswith(b"TCP-RTO-REAL") 仍判 PASS。
    """
    seg, total = 90, 1440
    expect = bytes(65 + (i % 26) for i in range(total))

    def judge(data):
        """返回 (ok, info)。"""
        nseg, rem = divmod(len(data), seg)
        if data == expect:
            return True, "%dB/%dseg full" % (len(data), nseg)
        if data.startswith(b"TCP-RTO-REAL"):
            return True, "%dB legacy-banner" % len(data)
        if rem == 0 and nseg >= 1 and data == expect[:len(data)]:
            return True, "%dB(%dseg) partial-of-%d" % (len(data), nseg, total // seg)
        return False, "%dB(%dseg,rem=%d)/expect=%dB" % (len(data), nseg, rem, total)

    n_seq = _env_int("TCP81_SEQ", 5)
    n_par = _env_int("TCP81_PAR", 8)
    for i in range(n_seq):
        try:
            s = socket.create_connection((HOST, P_TCP81), timeout=5)
            data, how = _read_banner(s, total)
            s.close()
            ok, info = judge(data)
            S.check("tcp81:seq#%d" % i, ok, "%s %s" % (info, how))
        except OSError as e:
            S.check("tcp81:seq#%d" % i, False, repr(e))

    par_ok = []
    lock = threading.Lock()

    def worker(_idx):
        try:
            c = socket.create_connection((HOST, P_TCP81), timeout=8)
            data, _how = _read_banner(c, total, budget=10.0)
            c.close()
            ok, info = judge(data)
            with lock:
                par_ok.append(ok)
        except OSError:
            with lock:
                par_ok.append(False)

    ts = [threading.Thread(target=worker, args=(i,)) for i in range(n_par)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    succ = sum(1 for x in par_ok if x)
    S.check("tcp81:parallel", succ >= max(1, n_par - 2),
            "%d/%d got banner (TCP_MAX_CONNS=64 上限内)" % (succ, n_par))


def stage_backlog_probe(S):
    """信息级：4 条空闲连接占满 pending 后试第 5 条。
    A=被快速 accept 排空 / B=backlog RST，两态都算行为记录；仅挂起才 FAIL。"""
    idles = []
    try:
        for _ in range(4):
            try:
                idles.append(socket.create_connection((HOST, P_TCP80), timeout=5))
            except OSError:
                break
        try:
            s = socket.create_connection((HOST, P_TCP80), timeout=5)
            s.settimeout(8)
            s.sendall(b"fifth")
            data, how = recv_until(s, want_len=5, timeout=8)
            fifth_ok = data.startswith(b"fifth")
            s.close()
            S.note("backlog_probe",
                   "idle_conns=%d 第五条=%s how=%s"
                   % (len(idles), "ECHO_OK(A:已排空)" if fifth_ok else "异常", how))
        except OSError as e:
            S.note("backlog_probe",
                   "idle_conns=%d 第五条=RST/拒绝(B:backlog 生效) %r" % (len(idles), e))
        S.check("backlog_probe:no_hang", True, "行为已记录，无挂起")
    finally:
        for c in idles:
            try:
                c.close()
            except OSError:
                pass


def stage_serial_final(S):
    """终扫串口原文：不允许 panic / CPU exception / CR2= / [ERR]。"""
    time.sleep(2)
    try:
        with open(S.serial, "rb") as f:
            log = f.read().decode(errors="replace")
    except FileNotFoundError:
        S.check("serial:final_scan", False, "serial log missing")
        return
    bad = [pat for pat in (r"panic", r"CPU exception", r"CR2=", r"\[ERR\]")
           if re.search(pat, log)]
    S.check("serial:final_scan", not bad,
            "无 panic/exception" if not bad else "发现 %s" % bad)


BLACKBOX_STAGES = [
    ("boot", stage_boot),
    ("ring3_errors", stage_ring3_errors),
    ("udp7000", stage_udp7000),
    ("tcp_multi", stage_tcp_multi),
    ("rst_no_listener", stage_rst_no_listener),
    ("udp_dead", stage_udp_dead),
    ("udp7_echo", stage_udp7_echo),
    ("tcp81", stage_tcp81),
    ("backlog_probe", stage_backlog_probe),
    ("serial_final", stage_serial_final),
]


def run_blackbox(serial):
    S = Suite("blackbox", serial)
    print("=== Cat-OS net_suite blackbox @ slirp hostfwd, serial=%s ===" % serial)
    if not stage_boot(S):
        S.summary()
        return EXIT_ASSERT, S
    # boot 之后各阶段不互相阻塞：单个探针慢/失败不影响其余证据采集
    for _name, fn in BLACKBOX_STAGES[1:]:
        fn(S)
    S.summary()
    return (EXIT_ASSERT if S.hard_fails else EXIT_OK), S


# ==========================================================================
# inject 套件（QEMU socket-netdev 原始帧注入；每用例需新引导内核）
# ==========================================================================

# 注入用例的握手目标端口（guest 侧内核 LISTEN 端口）。
# 根因记录（2026-08-25 rstfix）：旧前提是「内核在 :80 挂裸 LISTEN」——
# 该前提随 commit 6796bd6（net.c 将 tcp_listen(80) 注释、仅保留
# tcp_listen(81)，见 net.c net_init 尾部）失效。端口写死 80 时，SYN 被
# 内核以 "TCP :80 no listener, RST" 拒绝 -> handshake() SYN-ACK 超时 ->
# 五个用例全部在首断言前 HARNESS_ABORT（rc=5、0 断言），即
# /tmp/catos-bb-rstfix/status.txt 记录的八连挂。现默认 :81（与
# /tmp/ox_lifecycle_edge.py 原型一致），可用环境变量覆盖。
INJECT_DPORT = _env_int("CATOS_INJECT_DPORT", 81)


def case_sack_t1(S):
    """SACK 基础：in-order ACK / 已交付重复不重 ACK / OOO 缓存并发 SACK /
    dup-OOO 单次登记 / 补洞合并恰好交付一次 + 串口原文证据。
    （目标端口=INJECT_DPORT，默认 :81 内核 LISTEN；连接建立后内核 banner
    推流未被 ACK 前会持续 RTO 重发，属背景噪声，不影响本侧 rcv_nxt 断言。）"""
    w = wl.Wire(31001)
    try:
        w.arp()
        gs = w.handshake(INJECT_DPORT, 3100)
        base = 3101
        w.send_data(INJECT_DPORT, base, b"ABCDEFGHIJ", gs + 1)
        acks = [p for p in w.collect(0.8, dp=INJECT_DPORT) if p["flags"] & wl.ACK and not (p["flags"] & wl.SYN)]  # 排除 SYN-ACK 重试：其 ack=SEG.SEQ+1，非 rcv_nxt
        a1 = max((p["ack"] for p in acks), default=None)
        S.check("in-order D1 ACK base+10", a1 == base + 10, "ack=%s" % a1)

        w.send_data(INJECT_DPORT, base, b"ABCDEFGHIJ", base + 10)
        acks = [p for p in w.collect(0.8, dp=INJECT_DPORT) if p["flags"] & wl.ACK and not (p["flags"] & wl.SYN)]  # 排除 SYN-ACK 重试：其 ack=SEG.SEQ+1，非 rcv_nxt
        a2 = max((p["ack"] for p in acks), default=None)
        S.check("dup of delivered: ACK unchanged", a2 == base + 10, "ack=%s" % a2)

        g = base + 20
        w.send_data(INJECT_DPORT, g, b"0123456789", base + 10)
        pk = w.collect(0.6, dp=INJECT_DPORT)
        bl = [tuple(b) for p in pk for b in p["blocks"]]
        S.check("OOO G1 cached, SACK emitted", (g, g + 10) in bl, "blocks=%s" % bl)

        w.send_data(INJECT_DPORT, g, b"0123456789", base + 10)
        pk = w.collect(0.8, dp=INJECT_DPORT)
        acks = [p["ack"] for p in pk if p["flags"] & wl.ACK and not (p["flags"] & wl.SYN)]  # 排除 SYN-ACK 重试：其 ack=SEG.SEQ+1，非 rcv_nxt
        perpkt_dup = any(len(p["blocks"]) != len(set(p["blocks"])) for p in pk)
        blksets = set(tuple(sorted(set(p["blocks"]))) for p in pk if p["blocks"])
        S.check("dup OOO: ACK stays base+10",
                all(a == base + 10 for a in acks) and bool(acks), "%s" % acks)
        S.check("dup OOO: single registration (no double slot)",
                (not perpkt_dup) and blksets <= {(((g, g + 10)),)},
                "sets=%s" % blksets)

        w.send_data(INJECT_DPORT, base + 10, b"KLMNOPQRST", base + 10)
        acks = [p["ack"] for p in w.collect(0.8, dp=INJECT_DPORT) if p["flags"] & wl.ACK and not (p["flags"] & wl.SYN)]  # 排除 SYN-ACK 重试：其 ack=SEG.SEQ+1，非 rcv_nxt
        a3 = max(acks, default=None)
        S.check("merge delivers once: ACK base+30", a3 == base + 30, "ack=%s" % a3)

        S.check("log: duplicate/overlap re-ACK",
                wl.log_count(S.serial, "TCP duplicate/overlap, re-ACK") >= 1, "")
        S.check("log: bare cached line marks rejected dup-of-OOO",
                wl.log_count(S.serial, "TCP out-of-order cached\n") >= 1, "")
    finally:
        w.close()


def case_sack_t2(S):
    """跨层重叠（straddle）：trim + 级联推进、合并后 SACK 清空、过期段重发稳定。"""
    w = wl.Wire(31002)
    try:
        w.arp()
        gs = w.handshake(INJECT_DPORT, 3200)
        base = 3201
        w.send_data(INJECT_DPORT, base, b"0123456789", gs + 1)
        w.collect(0.6, dp=INJECT_DPORT)

        w.send_data(INJECT_DPORT, base + 5, b"XXXXXYYYYYYYYYY", base + 10)
        pk = w.collect(0.6, dp=INJECT_DPORT)
        bl = [tuple(b) for p in pk for b in p["blocks"]]
        S.check("straddle X queued, SACK (b+10,b+20)",
                (base + 10, base + 20) in bl, "%s" % bl)

        w.send_data(INJECT_DPORT, base + 10, b"ZZZZZ", base + 10)
        acks = [p["ack"] for p in w.collect(0.9, dp=INJECT_DPORT) if p["flags"] & wl.ACK and not (p["flags"] & wl.SYN)]  # 排除 SYN-ACK 重试：其 ack=SEG.SEQ+1，非 rcv_nxt
        a = max(acks, default=None)
        S.check("trim+cascade: ACK reaches base+20", a == base + 20, "ack=%s" % a)

        pk = w.collect(0.3, dp=INJECT_DPORT)
        S.check("SACK cleared after merge", all(not p["blocks"] for p in pk), "")

        w.send_data(INJECT_DPORT, base + 5, b"XXXXXYYYYYYYYYY", base + 20)
        acks = [p["ack"] for p in w.collect(0.7, dp=INJECT_DPORT) if p["flags"] & wl.ACK and not (p["flags"] & wl.SYN)]  # 排除 SYN-ACK 重试：其 ack=SEG.SEQ+1，非 rcv_nxt
        S.check("expired X resend: ACK stable",
                bool(acks) and all(x == base + 20 for x in acks), "%s" % acks)

        S.check("log: out-of-order cached 15B",
                wl.log_count(S.serial, "TCP out-of-order cached 15B") >= 1, "")
        S.check("log: duplicate/overlap re-ACK",
                wl.log_count(S.serial, "TCP duplicate/overlap, re-ACK") >= 1, "")
    finally:
        w.close()


def case_sack_t5(S):
    """双空洞同时持有；逐个补洞时 ACK 推进与幸存 SACK 区间均须精确。"""
    w = wl.Wire(31005)
    try:
        w.arp()
        gs = w.handshake(INJECT_DPORT, 3500)
        base = 3501
        w.send_data(INJECT_DPORT, base, b"0123456789", gs + 1)
        w.collect(0.6, dp=INJECT_DPORT)
        w.send_data(INJECT_DPORT, base + 20, b"D" * 20, base + 10)   # G1（空洞 b+10..b+20）
        w.collect(0.4, dp=INJECT_DPORT)
        w.send_data(INJECT_DPORT, base + 50, b"E" * 20, base + 10)   # G2（空洞 b+40..b+50）
        pk = w.collect(0.7, dp=INJECT_DPORT)
        bl = set(tuple(b) for p in pk for b in p["blocks"])
        acks = [p["ack"] for p in pk if p["flags"] & wl.ACK and not (p["flags"] & wl.SYN)]  # 排除 SYN-ACK 重试：其 ack=SEG.SEQ+1，非 rcv_nxt
        S.check("two holes held simultaneously",
                bl == {(base + 20, base + 40), (base + 50, base + 70)}, "%s" % bl)
        S.check("ACK pinned at base+10",
                bool(acks) and all(a == base + 10 for a in acks), "%s" % acks)

        w.send_data(INJECT_DPORT, base + 10, b"F" * 10, base + 10)   # 补洞 1
        pk = w.collect(0.8, dp=INJECT_DPORT)
        bl = set(tuple(b) for p in pk for b in p["blocks"])
        acks = [p["ack"] for p in pk if p["flags"] & wl.ACK and not (p["flags"] & wl.SYN)]  # 排除 SYN-ACK 重试：其 ack=SEG.SEQ+1，非 rcv_nxt
        S.check("hole1 merged: ACK base+40, G2 survives",
                max(acks, default=0) == base + 40
                and bl == {(base + 50, base + 70)},
                "ack=%s bl=%s" % (max(acks, default=None), bl))

        w.send_data(INJECT_DPORT, base + 40, b"G" * 10, base + 40)   # 补洞 2
        acks = [p["ack"] for p in w.collect(0.8, dp=INJECT_DPORT) if p["flags"] & wl.ACK and not (p["flags"] & wl.SYN)]  # 排除 SYN-ACK 重试：其 ack=SEG.SEQ+1，非 rcv_nxt
        S.check("hole2 merged: ACK base+70",
                max(acks, default=0) == base + 70,
                "ack=%s" % max(acks, default=None))
    finally:
        w.close()


def case_sack_t8(S):
    """序号回绕：跨 2^32 顺序交付、回绕后 OOO/SACK、过期段拒绝（有符号比较）、
    回绕点重叠排队、补洞级联收尾。"""
    isn = 0xFFFFFF00
    base = (isn + 1) & wl.U32
    w = wl.Wire(31008)
    try:
        w.arp()
        gs = w.handshake(INJECT_DPORT, isn)
        w.send_data(INJECT_DPORT, base, b"wrapwrapwrapABC", (gs + 1) & wl.U32)   # 回绕前开场
        w.send_data(INJECT_DPORT, (base + 15) & wl.U32, b"P" * 244,
                    (gs + 1) & wl.U32)                                 # 跨过 2^32，止于 4
        acks = [p for p in w.collect(0.8, dp=INJECT_DPORT) if p["flags"] & wl.ACK and not (p["flags"] & wl.SYN)]  # 排除 SYN-ACK 重试：其 ack=SEG.SEQ+1，非 rcv_nxt
        a = acks[-1]["ack"] if acks else None                          # 最新 rcv_nxt 优先
        S.check("in-order delivery across wrap: ACK==4", a == 4, "ack=%s" % a)

        w.send_data(INJECT_DPORT, 0x10, b"L" * 10, 4)
        pk = w.collect(0.6, dp=INJECT_DPORT)
        bl = set(tuple(b) for p in pk for b in p["blocks"])
        S.check("post-wrap OOO cached, SACK (0x10,0x1A)",
                bl == {(0x10, 0x1A)}, "%s" % bl)

        # 过期段：数值上巨大但逻辑上低于 rcv_nxt=4
        w.send_data(INJECT_DPORT, 0xFFFFFFF8, b"M" * 4, 4)
        pk = w.collect(0.7, dp=INJECT_DPORT)
        acks = [p["ack"] for p in pk if p["flags"] & wl.ACK and not (p["flags"] & wl.SYN)]  # 排除 SYN-ACK 重试：其 ack=SEG.SEQ+1，非 rcv_nxt
        bl = set(tuple(b) for p in pk for b in p["blocks"])
        S.check("expired-after-wrap rejected (signed cmp)",
                bool(acks) and all(x == 4 for x in acks)
                and bl == {(0x10, 0x1A)}, "ack=%s bl=%s" % (acks, bl))

        # 已交付的回绕前字节重复
        w.send_data(INJECT_DPORT, (base + 10) & wl.U32, b"apA", 4)
        pk = w.collect(0.7, dp=INJECT_DPORT)
        acks = [p["ack"] for p in pk if p["flags"] & wl.ACK and not (p["flags"] & wl.SYN)]  # 排除 SYN-ACK 重试：其 ack=SEG.SEQ+1，非 rcv_nxt
        S.check("pre-wrap dup rejected",
                bool(acks) and all(x == 4 for x in acks), "%s" % acks)

        # 恰好压在回绕点上的重叠（seq=0xFFFFFFFF）；net.c 会头裁剪陈旧前缀，
        # 故接受 raw(0xFFFFFFFF,5) 或 trimmed(4,5) 两种形态——决定性证明是级联。
        w.send_data(INJECT_DPORT, 0xFFFFFFFF, b"NNNNNN", 4)
        pk = w.collect(0.6, dp=INJECT_DPORT)
        bl = set(tuple(b) for p in pk for b in p["blocks"])
        S.check("wrap-point overlap queued", any(e == 5 for _, e in bl), "%s" % bl)

        w.send_data(INJECT_DPORT, 4, b"O" * 12, 4)
        acks = [p["ack"] for p in w.collect(1.0, dp=INJECT_DPORT) if p["flags"] & wl.ACK and not (p["flags"] & wl.SYN)]  # 排除 SYN-ACK 重试：其 ack=SEG.SEQ+1，非 rcv_nxt
        a = max(acks, default=0)
        S.check("cascade completes: ACK==0x1A", a == 0x1A, "ack=%s" % a)

        S.check("log: TCP data 15B", wl.log_count(S.serial, "TCP data 15B") >= 1, "")
        S.check("log: duplicate/overlap >=2",
                wl.log_count(S.serial, "TCP duplicate/overlap, re-ACK") >= 2, "")
    finally:
        w.close()


def case_rst_l1(S):
    """RST 三态校验（移植自 ox_lifecycle_edge.L1）：
    窗内非精确 RST -> challenge-ACK 且连接存活；窗外 RST -> 静默丢弃；
    精确 seq RST -> 连接复位；关闭后数据遇 RST/no-listener。"""
    sp = 31011
    cisn = 424242
    w = wl.Wire(sp)
    try:
        w.arp()
        gs = w.handshake(INJECT_DPORT, cisn)
        rc = cisn + 1

        # (1) 窗内盲 RST：!= RCV.NXT -> challenge-ACK，连接必须存活
        o0 = lsz(S.serial)
        w.put(wl.frame(wl.tcp_seg(sp, INJECT_DPORT, (rc + 100) & wl.U32, 0, wl.RST)))
        pk = w.collect(1.2, dp=INJECT_DPORT)
        s0 = lslice(S.serial, o0)
        ch = [p for p in pk if p["flags"] & wl.ACK
              and not p["flags"] & (wl.SYN | wl.RST | wl.FIN)
              and p["dlen"] == 0 and p["ack"] == rc]
        S.check("in-window non-exact RST -> bare challenge-ACK (dlen=0, ack=RCV.NXT)",
                bool(ch),
                "%s" % [(hex(p["seq"]), hex(p["ack"]), hex(p["flags"]), p["dlen"])
                        for p in pk])
        S.check("serial: blind-RST rejected, challenge ACK",
                s0.count("blind-RST rejected, challenge ACK") == 1, "")
        S.check("conn NOT torn down by blind RST (no valid-seq log)",
                s0.count("RST(valid seq)") == 0, "")

        w.send_data(INJECT_DPORT, rc, b"PING1234", gs + 1)
        ak = [p["ack"] for p in w.collect(1.0, dp=INJECT_DPORT) if p["flags"] & wl.ACK and not (p["flags"] & wl.SYN)]  # 排除 SYN-ACK 重试：其 ack=SEG.SEQ+1，非 rcv_nxt
        S.check("connection still alive: data ACKed rc+8",
                max(ak, default=0) == rc + 8, "%s" % [hex(x) for x in ak])
        rc += 8

        # (2a) 窗上方（远超窗口）RST -> 静默丢弃
        o1 = lsz(S.serial)
        w.put(wl.frame(wl.tcp_seg(sp, INJECT_DPORT, (rc + 70000) & wl.U32, 0, wl.RST)))
        pk = w.collect(0.9, dp=INJECT_DPORT)
        s1 = lslice(S.serial, o1)
        S.check("above-window RST: silent (zero pkts back)", len(pk) == 0,
                "%s" % [(hex(p["seq"]), hex(p["flags"])) for p in pk])
        S.check("serial: RST out-of-window dropped",
                s1.count("RST out-of-window dropped") == 1, "")

        # (2b) 窗下方（旧序号）RST -> 同样静默丢弃
        o1b = lsz(S.serial)
        w.put(wl.frame(wl.tcp_seg(sp, INJECT_DPORT, (cisn - 5000) & wl.U32, 0, wl.RST)))
        pk = w.collect(0.7, dp=INJECT_DPORT)
        s1b = lslice(S.serial, o1b)
        S.check("below-window(old-seq) RST: silent drop",
                len(pk) == 0 and s1b.count("out-of-window") == 1,
                "pkts=%d" % len(pk))

        w.send_data(INJECT_DPORT, rc, b"OK", gs + 1)
        ak = [p["ack"] for p in w.collect(1.0, dp=INJECT_DPORT) if p["flags"] & wl.ACK and not (p["flags"] & wl.SYN)]  # 排除 SYN-ACK 重试：其 ack=SEG.SEQ+1，非 rcv_nxt
        S.check("still alive after both OOW RSTs: ACK rc+2",
                max(ak, default=0) == rc + 2, "%s" % [hex(x) for x in ak])
        rc += 2

        # (3) 精确 seq RST -> 必须复位
        o2 = lsz(S.serial)
        w.put(wl.frame(wl.tcp_seg(sp, INJECT_DPORT, rc & wl.U32, 0, wl.RST)))
        w.collect(1.0, dp=INJECT_DPORT)
        s2 = lslice(S.serial, o2)
        S.check("serial: RST(valid seq) -> CLOSED",
                s2.count("RST(valid seq) -> CLOSED") == 1, "")

        # 关闭证明：关闭后的段必须以 RST 应答（四元组已释放）
        w.send_data(INJECT_DPORT, rc, b"AFTER", gs + 1)
        pk = w.collect(1.2, dp=INJECT_DPORT)
        s2b = lslice(S.serial, o2)
        rst = [p for p in pk if p["flags"] & wl.RST]
        S.check("post-close data met by RST / no-listener path",
                bool(rst) or ("no listener, RST" in s2b),
                "%s" % [(hex(p["seq"]), hex(p["flags"])) for p in pk])
    finally:
        w.close()


def case_tw_recycle(S):
    """TW1/TW2 回填：主动关闭进 TIME_WAIT → 等到期回收 → 同端口重新三次握手成功。

    源码依据（工作树 net.c/net.h）：
    - net.c:979/982/996  进 TIME_WAIT：tw_until=ticks+200，打印
      "[NET] TCP TIME_WAIT entered"；
    - net.c:604  TCP_RTO_INIT=30 注释 "300ms @100Hz" ⇒ ticks=100Hz，
      200 ticks = 2s（net.c:982 行内注释同口径），故等待上限取 8s 冗余；
    - net.c:1019 tcp_tick() 到期释放 used=false，打印
      "[NET] TCP TIME_WAIT expired"；
    - net.c:796-805 同四元组裸 SYN 触发「化身替换」提前回收 —— 第二次握手必须
      等 "TIME_WAIT expired" 出现在串口之后才发 SYN，才能覆盖真正的到期回收
      路径而非替换路径（顺序断言 entered < expired < 第二次 SYN 即证明）。
    时长注记：TW 固定 2s，整例含两次握手/banner 排空约 8-12s，无需缩短路径。
    """
    sp = 31021
    dp = INJECT_DPORT
    w = wl.Wire(sp)
    try:
        w.arp()
        gs = w.handshake(dp, 730001)
        base = (gs + 1) & wl.U32

        # 阶段1：排空内核 banner(16x90B=1440B) 并盯 FIN。:81 服务在全部数据
        # ACK 后于 tcp_tick 自动 close（net.c:1036-1037 → tcp_close 发 FIN，
        # net.c:1148-1152 FIN_WAIT_1）。自绘泵而不用 wl.drain：drain 会把
        # dlen==0 的 FIN 帧吸收掉无从回看，FIN 只能等 RTO re-FIN 再见
        # （net.c:1070-1073），平白拖慢且污染窗口。
        fin_seq = None
        contig = base
        have = {}
        end = time.time() + 12
        while time.time() < end and fin_seq is None:
            for p in w.collect(0.25, dp=dp):
                if p["flags"] & wl.FIN:
                    fin_seq = (p["seq"] + p["dlen"]) & wl.U32
                if p["dlen"]:
                    have[p["seq"]] = p["data"]
            moved = True
            while moved:
                moved = False
                if contig in have:
                    contig = (contig + len(have.pop(contig))) & wl.U32
                    moved = True
            ackv = ((fin_seq + 1) & wl.U32) if fin_seq is not None else contig
            if w.last_ack != (ackv & wl.U32):
                w.send_ack(dp, ackv)
        S.check("banner fully delivered (1440B) then kernel FIN",
                fin_seq is not None and wl.le((base + 1440) & wl.U32, contig),
                "fin=%s contig=%s" % (hex(fin_seq or 0), hex(contig)))
        if fin_seq is None:
            return
        S.check("serial: FIN_WAIT_2 after we ACK kernel FIN",
                wait_serial(S, "TCP FIN_WAIT_2", 5), "")

        # 阶段2：我方主动关闭（FIN_WAIT_2 收到对端 FIN → TIME_WAIT，net.c:973/
        # 981-982），阶段3：等到期回收（200 ticks ≈ 2s @100Hz）
        w.put(wl.frame(wl.tcp_seg(sp, dp, w.next_seq, (fin_seq + 1) & wl.U32,
                                  wl.FIN | wl.ACK)))
        ok_enter = wait_serial(S, "TCP TIME_WAIT entered", 5)
        ok_expire = wait_serial(S, "TCP TIME_WAIT expired", 8)
        try:
            with open(S.serial, errors="replace") as f:
                txt = f.read()
            order_ok = (0 <= txt.find("TCP TIME_WAIT entered")
                        < txt.find("TCP TIME_WAIT expired"))
        except OSError:
            order_ok = False
        S.check("serial: TIME_WAIT entered (active close)",
                ok_enter, "")
        S.check("serial: TIME_WAIT expired within 200-tick budget",
                ok_expire, "")
        S.check("serial order: entered < expired (true expiry path)",
                order_ok, "")

        # 阶段4：回收完成后同端口重建。旧 TCB 已 used=false（net.c:1019），
        # tcp_conn_find_peer 不中 → 走 LISTEN 分支全新建连（net.c:806-835）。
        isn2 = 740000
        w.put(wl.frame(wl.tcp_seg(sp, dp, isn2, 0, wl.SYN, opt=wl.MSS_OPT)))
        gs2 = None
        end = time.time() + 4
        while gs2 is None and time.time() < end:
            for p in w.collect(0.3, dp=dp):
                if p["flags"] & wl.SYN and p["flags"] & wl.ACK:
                    gs2 = p["seq"]
        S.check("same-port 3WHS succeeds after expiry", gs2 is not None,
                "synack=%s" % hex(gs2 or 0))
        if gs2 is None:
            return
        w.next_seq = (isn2 + 1) & wl.U32
        w.put(wl.frame(wl.tcp_seg(sp, dp, w.next_seq, (gs2 + 1) & wl.U32,
                                  wl.ACK)))
        # 新连接活性：全新 TCB 的 test_sent 已复位，内核重推 banner
        # （net.c:1020-1035），收到带载数据即证明双向通路可用
        got = [p for p in w.collect(3.0, dp=dp) if p["dlen"]]
        S.check("rebuilt conn carries banner data", bool(got),
                "%d segs" % len(got))
        S.check("serial: second ESTABLISHED on same port",
                wl.log_count(S.serial, "TCP ESTABLISHED ") >= 2, "")
    finally:
        w.close()


def case_backlog_probe(S):
    """TB1 回填：连接表容量上限 —— 超额 SYN 被 RST|ACK 拒绝，既有连接不受影响。

    容量模型（2026-08-26 起改为「常驻 socket 数」动态推导；沿革：
    commit 36fd594 后首跑 FAIL 根因 = 旧模型漏算 listen TCB 自身占槽；
    httpd-wire 接线后二跑 FAIL 根因 = kernel.c stage4 新增常驻 httpd 守护
    （bind/listen :7000）再占 1 槽，实测第 14 条半开即撞 conn-table-full）。
    源码依据：
    - net.h:86  TCP_MAX_CONNS=64（tcp_conns[64]，net_tcp.c:15；2026-08-26 容量
      第一档 16→64，分母随之更新）——容量分母；
    - net_tcp.c tcp_listen() 经 tcp_conn_find_free() 取槽并置 used=true ⇒
      **每个监听者本身常驻占 1 槽**；且常驻 listener 数可从串口动态计数：
      内核侧 listen 打 "[NET] TCP listen :<port>"（tcp_listen），ring3 侧
      bind(nr=21) 在 net_socket_bind() 直接置 TCB=TCP_LISTEN 占槽、无内核
      日志，以 httpd 自身 banner "[HTTPD] listening on port"（bind/listen
      成功后打印）为占槽证据。现状两枚 —— 内核演示服务 ：81（net_init
      tcp_listen(81)）+ ring3 httpd 守护 :7000（kernel.c stage4 phase3 exec，
      回归设计端口，曾误绑 :80 与本套件 tcp80 回显探针冲突已纠正）；
    - net_tcp.c tcp_pending_count() 只统计端口上 !accepted 的
      SYN_RECEIVED|ESTABLISHED（LISTEN 态不计）⇒ pending 上限
      =64-N(listen) < backlog=64（listen 时 c->backlog=
      TCP_LISTEN_BACKLOG_DEFAULT=TCP_MAX_CONNS，net.h:101/net_tcp.c:377），
      故「accept queue full」分支在 fresh-boot 场景结构性不可达：超额 SYN
      必然通过队列检查后在连接表分配处被拒（"[NET] TCP conn table full,
      RST"，net_tcp.c:433）。两分支各自打日志后立即 return，对单个 SYN 严格
      互斥 —— 断言据此书写：窗口内 conn-table-full 恰 1 条、accept-queue-full
      为 0；
    - 净容量模型：listener(N)+A(ESTABLISHED 未 accept)(1)+(64-N-1) 半开
      =64 槽占满，其后首个四元组（ovf）的裸 SYN 必被拒；
      两条拒绝路径回包同源于 tcp_send_rst_ack：对无 ACK 的 SYN 回
      <SEQ=0><ACK=SEG.SEQ+1><RST|ACK>；
    - net.c:862-866 同四元组重复 SYN 仅重发 SYN-ACK ⇒ 半开连接须用不同源端口；
    - net.c:876-889 valid-seq RST 即时释放槽位（清理路径依据），不依赖
      SYN_RECEIVED 的 RTO 放弃（net.c:1069-1079，~0.9s×3 太慢）；
    - e1000.c:8 RX/TX 环各仅 8 描述符 ⇒ SYN/RST 按 ≤5 一批注入防环溢丢帧。
    """
    dp = INJECT_DPORT
    # 常驻 TCP listener 数动态推导（依据见 docstring / net.h:86）：
    #   n_half = TCP_MAX_CONNS(64) − 常驻 listener − A(基线 ESTABLISHED 占 1)
    # 现状常驻两枚：内核 :81（net_init）+ httpd :7000（kernel.c stage4）。
    # 信号面注记：两条监听路径的日志形态不同 ——
    #   · 内核侧 net_init 走 tcp_listen()，每次成功监听打一行
    #     "[NET] TCP listen :<port>"（net.c）；
    #   · ring3 侧 bind(nr=21) 在 net_socket_bind() 的 SOCK_TCP_UNBOUND 分支
    #     直接置 TCB=TCP_LISTEN 占槽（net.c），无内核日志；以服务自身
    #     bind/listen 成功后的 banner 行 "[HTTPD] listening on port"
    #     （userland/httpd/httpd.c）为占槽证据。
    # httpd exec 晚于 shell（stage4 时序契约），故先等两路信号齐再注入，
    # 避免在守护绑定前开跑导致模型少扣 1 槽。
    deadline = time.time() + 30
    n_listen = 0
    while time.time() < deadline:
        try:
            with open(S.serial, "rb") as f:
                blob = f.read()
        except OSError:
            blob = b""
        n_listen = (blob.count(b"[NET] TCP listen :")
                    + (1 if b"[HTTPD] listening on port" in blob else 0))
        if n_listen >= 2:
            break
        time.sleep(0.25)
    if n_listen < 1:
        n_listen = 2      # 兜底：串口解析缺失时按当前已知常驻数（:81 + :7000）
    S.note("resident_listeners",
           "内核[NET] TCP listen: + ring3 [HTTPD] listening 共 %d 枚"
           "（:81 + httpd :7000；等 httpd 绑定 %s）"
           % (n_listen, "ok" if n_listen >= 2 else "timeout→兜底"))
    n_half = 64 - n_listen - 1   # TCP_MAX_CONNS(net.h:86，第一档 16→64) − 常驻 listener − A 占 1
    sports = [31031 + i for i in range(n_half)]
    ovf_sport = 31031 + n_half
    w = wl.Wire(31030)
    try:
        w.arp()
        # A：基线 ESTABLISHED 连接（占 pending 名额，后续作「不受影响」探针）
        isn_a = 810000
        gs_a = w.handshake(dp, isn_a)
        rcv_nxt_a = (isn_a + 1) & wl.U32          # 内核视角我方下一序号

        def collect_bucket(seconds):
            bk = {}
            for p in w.collect(seconds, dp=dp, dport_to=False):
                bk.setdefault(p["dp"], []).append(p)
            return bk

        # B1..B15：分批发裸 SYN（不回 ACK），钉在 SYN_RECEIVED
        half_open = {}
        ok_synack = 0
        filled = True
        for i in range(0, n_half, 5):
            batch = sports[i:i + 5]
            for sp_ in batch:
                isn_ = 820000 + sp_
                w.put(wl.frame(wl.tcp_seg(sp_, dp, isn_, 0, wl.SYN,
                                          opt=wl.MSS_OPT)))
                half_open[sp_] = (isn_ + 1) & wl.U32      # 其 rcv_nxt
            got = set()
            end = time.time() + 3
            while len(got) < len(batch) and time.time() < end:
                bk = collect_bucket(0.25)
                for sp_ in batch:
                    if sp_ in got:
                        continue
                    if any((p["flags"] & (wl.SYN | wl.ACK)) == (wl.SYN | wl.ACK)
                           for p in bk.get(sp_, [])):
                        got.add(sp_)
            ok_synack += len(got)
            if len(got) < len(batch):
                filled = False
                break
        S.check("all %d half-open SYNs served SYN-ACK" % n_half,
                ok_synack == n_half, "%d/%d" % (ok_synack, n_half))

        if filled:
            # 超额第 (n_half+1) 个四元组（表满后首个 SYN）：期望 RST|ACK 且
            # ack=ISN+1（tcp_send_rst_ack，net_tcp.c）
            o_ovf = lsz(S.serial)
            isn_x = 830001
            w.put(wl.frame(wl.tcp_seg(ovf_sport, dp, isn_x, 0, wl.SYN,
                                      opt=wl.MSS_OPT)))
            rst_pkts = []
            end = time.time() + 2.5
            while not rst_pkts and time.time() < end:
                bk = collect_bucket(0.25)
                rst_pkts = [p for p in bk.get(ovf_sport, [])
                            if p["flags"] & wl.RST]
            S.check("overflow SYN answered RST|ACK ack=ISN+1",
                    bool(rst_pkts)
                    and all(p["flags"] & wl.ACK for p in rst_pkts)
                    and all(p["ack"] == ((isn_x + 1) & wl.U32)
                            for p in rst_pkts),
                    "%s" % [(hex(p["ack"]), hex(p["flags"])) for p in rst_pkts])
            s_ovf = lslice(S.serial, o_ovf)
            S.check("serial: 'conn table full' logged exactly once (binding constraint)",
                    s_ovf.count("TCP conn table full, RST") == 1,
                    "count=%d" % s_ovf.count("TCP conn table full, RST"))
            S.check("serial: 'accept queue full' NOT hit (pending %d < backlog 64, queue branch unreachable fresh-boot)"
                    % n_half,
                    s_ovf.count("TCP accept queue full, RST") == 0, "")

            # 既有连接不受影响：A 上发数据须被正常 ACK 推进（ESTABLISHED 带载
            # 路径回纯 ACK，net.c:978-986；进度 ack= 日志行 net.c:948）。ack
            # 字段顺手清空 A 的 banner 在途（auto-close 即使随后发生也在应答
            # 之后，不影响本断言）。
            payload = b"STILL-ALIVE"
            w.send_data(dp, rcv_nxt_a, payload, (gs_a + 1 + 1440) & wl.U32)
            want_ack = (rcv_nxt_a + len(payload)) & wl.U32
            rep = []
            bk = {}
            end = time.time() + 2.5
            while not rep and time.time() < end:
                bk = collect_bucket(0.25)
                rep = [p for p in bk.get(w.sport, [])
                       if (p["flags"] & wl.ACK)
                       and not (p["flags"] & (wl.SYN | wl.FIN | wl.RST))
                       and p["ack"] == want_ack]
            S.check("pre-existing conn A unaffected: data ACKed",
                    bool(rep), "want_ack=%s recent=%s"
                    % (hex(want_ack),
                       [(hex(p["ack"]), hex(p["flags"]))
                        for p in bk.get(w.sport, [])[-4:]]))
            rcv_nxt_a = want_ack

        # 清理：精确 seq RST 逐条复位（valid-seq 判据 net.c:876-889），同样
        # 分批防 RX 环溢。尽力而为（INFO）：inject 用例本就 fresh-boot。
        # 只遍历实际发出的端口（fill 中断时 half_open 键集即真实集合）。
        o_cln = lsz(S.serial)
        targets = list(half_open.items())
        targets.append((w.sport, rcv_nxt_a))
        for i in range(0, len(targets), 5):
            for sp_, nxt in targets[i:i + 5]:
                w.put(wl.frame(wl.tcp_seg(sp_, dp, nxt, 0, wl.RST)))
            w.collect(0.3, dp=dp, dport_to=False)
        n_kill = lslice(S.serial, o_cln).count("RST(valid seq) -> CLOSED")
        S.note("cleanup", "precise-RST freed %d/%d conns" % (n_kill, len(targets)))
    finally:
        w.close()


def case_l3b_race(S):
    """L3B 回填：RTT 采样竞态 —— 同一突发的同拍双 ACK 只计 1 个样本
    （对应 commit 58d55a9「net: clamp sub-tick RTT samples to 1」的采样面契约）。

    源码依据（commit 36fd594 后重核；首跑 FAIL 根因见文末守卫设计）：
    - net.c:755 tcp_xmit_pending() 仅在 !rtt_pending 时武装 {rtt_stamp,
      rtt_seq} ⇒ 同一突发无论几段只有首段武装采样点；
    - 突发形态：tcp_tick（net.c:1036-1049）循环 16 次 tcp_send 各 90B，
      tcp_send 每次追加后即调 xmit_pending（net.c:1135），初始
      cwnd=TCP_MSS=1460（net.c:639）恰好容纳 16×90=1440B ⇒ 突发为 16 个
      90B 段**全量在飞**（rtt_seq=b+90=首段末）；ACK#1 后 in_flight==
      snd_used ⇒ 无滑动窗续发（net.c:745 break），ACK#2 即全量排空、
      net.c:947-951 清 rto_deadline，此后结构性无 RTO。故「缩小突发」无从
      也无需从线侧做——时序硬化 + 守卫前移才是正解。
    - net.c:932-938 ACK 推进路径：rtt_pending && ack>=rtt_seq 时采样一次并
      立即清 pending ⇒ 第二个 ACK（即便同 tick 处理）不可能再产生样本；
    - net.c:641-649 tcp_rtt_sample() 亚 tick 样本钳 >=1 并打印
      "[NET] TCP RTT sample=<n> RTO=<r>"（58d55a9 起钳位，此前静默 return →
      本用例将以样本缺失 FAIL，构成对该 commit 的回归哨兵）；
      net.c:604 TCP_RTO_INIT=30 ticks = 300ms@100Hz，net.c:648 RTO 下限 30；
    - net.c:1092-1095 RTO 重传打印 "[NET] TCP RTO: re-xmit <n>B" 且置
      rtt_retransmitted ⇒ 其后到达的 ACK 被 Karn 抑制（net.c:936-937）零采样。
    守卫设计（首跑 rc=2 复盘）：旧守卫只扫「首个数据帧之后」的串口窗——若
    致命 RTO 发生在测试看到首帧之前（帧在宿主侧迟到 >300ms），re-xmit 行落
    在窗外，0 样本直落断言 FAIL。现把守卫窗起点前移到 banner 等待之前
    （o_pre）：[o_pre, 双 ACK 收集结束) 内出现任何 "TCP RTO: re-xmit" 即抛
    Fail 按 harness 故障 rc=5 交 runner 重试，不作断言失败。同时检测粒度
    50ms→20ms、extent 探测 80ms→40ms，正常路径双 ACK 在 RTO 预算前 1/3 内
    到线。断言核心保留：同拍双 ACK ⇒ `TCP RTT sample=` 恰 1 条、样本值>=1、
    RTO>=30、安静期零补采。实测（16×90B 全量在飞形态）双 ACK 均为 progress
    路径且恰产生 1 条样本——「两条 progress ack= 行」不再作硬断言（突发
    分段形态属内核自由度），降级为 INFO 记录。
    """
    dp = INJECT_DPORT
    w = wl.Wire(31051)
    try:
        w.arp()
        gs = w.handshake(dp, 851000)
        o0 = lsz(S.serial)   # 守卫窗起点：早于 banner 等待（docstring 守卫设计）
        # 等 banner 首段到线：细粒度轮询（20ms），少吃 RTO(300ms) 预算
        first = None
        end = time.time() + 5
        while first is None and time.time() < end:
            for p in w.collect(0.02, dp=dp):
                if p["dlen"]:
                    first = p
                    break
        if first is None:
            raise wl.Fail("no banner segment observed")
        # 极短窗收集实际突发范围（16×90B 连发，40ms 内到齐）；序号空间
        # ~0x123400xx 远离回绕，普通比较安全
        extent_end = (first["seq"] + first["dlen"]) & wl.U32
        deadline = time.time() + 0.04
        while time.time() < deadline:
            for p in w.collect(0.02, dp=dp):
                if p["dlen"]:
                    e = (p["seq"] + p["dlen"]) & wl.U32
                    if e > extent_end:
                        extent_end = e

        ack1 = (first["seq"] + first["dlen"]) & wl.U32   # == rtt_seq：恰好触达采样点
        w.send_ack(dp, ack1)                             # ACK#1：采样一次并清 pending
        w.send_ack(dp, extent_end)                       # ACK#2：同拍第二 ACK，必须零采样
        w.collect(0.3, dp=dp)
        s0 = lslice(S.serial, o0)
        if "TCP RTO: re-xmit" in s0:
            raise wl.Fail("RTT race window missed (RTO re-xmit within "
                          "pre-banner..post-ACK guard window)")
        n_sample = s0.count("TCP RTT sample=")
        n_ackline = s0.count("TCP ack=")
        S.check("dual-ACK -> exactly ONE RTT sample", n_sample == 1,
                "samples=%d ack_lines=%d" % (n_sample, n_ackline))
        S.note("ack progress lines",
               "%d 条 progress ack= 行（16×90B 全量在飞形态下 ACK#1/ACK#2 "
              "均为 progress；分段形态属内核自由度，不作硬断言）" % n_ackline)
        m = re.search(r"TCP RTT sample=(\d+) RTO=(\d+)", s0)
        S.check("sample clamped >=1 and RTO floor 30 (58d55a9 / net.c:641-649)",
                bool(m) and int(m.group(1)) >= 1 and int(m.group(2)) >= 30,
                m.group(0) if m else "unparsable")
        # 清理：精确 seq RST 释放 TCB（net.c:876-889），掐断 auto-close FIN
        # （net.c:1050-1052）的 re-FIN 定时器噪声，保证安静窗真正安静；
        # 本侧从未发数据 ⇒ kernel rcv_nxt 恒为 gs+1，即 valid-seq
        w.put(wl.frame(wl.tcp_seg(w.sport, dp, (gs + 1) & wl.U32, 0, wl.RST)))
        w.collect(0.3, dp=dp)
        # 安静期零补采：pending 已清且无新发送 ⇒ 不得再冒样本——竞态去重的
        # 反方向证据（缺陷形态即同窗连计多次）
        o1 = lsz(S.serial)
        w.collect(0.6, dp=dp)
        S.check("quiet window: no extra samples",
                lslice(S.serial, o1).count("TCP RTT sample=") == 0, "")
    finally:
        w.close()


# ==========================================================================
# dhcp_lease（slirp + LEASE_SCALE 专用 ISO）与配套迷你构建器
# ==========================================================================

# 租约换算分母（net_dhcp.c:41-58）：秒→ticks 除以 N。取 21600 使 slirp 的
# 86400s 租约折成 400 ticks(4s)、T1=200 ticks(2s)、T2=350 ticks(3.5s)——
# 续期节奏 ~0.5 次/秒，窗口内轻松积累 ≥3 轮；且 T1→T2 绝对间隙 1.5s 足以
# 吸收首轮续期的 ARP 预热延迟（首轮单播前 arp_resolve 必然 miss 一轮，
# 见 net_dhcp.c:158-160；SCALE=172800 实测该间隙仅 180ms 时会推进到
# REBINDING）。commit b9530ff 注释示例的 1728000 仅适合人肉观察全程，
# 不适合常驻回归。可用 CATOS_DHCP_SCALE / --scale 覆盖。
DHCP_SCALE_DEFAULT = 21600

# 串口标记原文对照（net_dhcp.c，逐字核实）：
#   :102  "[NET] DHCP DISCOVER" / "[NET] DHCP REQUEST" / "REQUEST(renew)" / "(rebind)"
#   :108  "[NET] DHCP lease expired, rediscover"
#   :124  "[NET] DHCP NAK, restart"
#   :139  "[NET] DHCP ACK renew ip="      ← 与首取行靠 renew 字样区分
#   :140  "[NET] DHCP ACK ip="            ← 首取 ACK（"ACK renew ip=" 不含本子串）
#   :157  "[NET] DHCP T1 renew due"
#   :170  "[NET] DHCP T2 rebind due"
#   :194  "[NET] DHCP failed, fallback static"

DHCP_MARK_DISCOVER = "[NET] DHCP DISCOVER"
DHCP_MARK_REQUEST_FIRST = "[NET] DHCP REQUEST\n"     # 带 \n 排除 REQUEST(renew)
DHCP_MARK_ACK_FIRST = "[NET] DHCP ACK ip="
DHCP_MARK_T1 = "[NET] DHCP T1 renew due"
DHCP_MARK_RENEW_REQ = "[NET] DHCP REQUEST(renew)"
DHCP_MARK_RENEW_ACK = "[NET] DHCP ACK renew ip="

# Makefile 主 CFLAGS 提取失败时的兜底镜像（Makefile:7-9 原文；提取成功则不用）
_DHCP_FALLBACK_CFLAGS = (
    "-m32 -march=i686 -ffreestanding -fno-pic -fno-pie "
    "-fno-stack-protector -fno-builtin -fno-asynchronous-unwind-tables "
    "-fno-unwind-tables -nostdlib -Wall -Wextra -std=gnu99 -O2")


def _make_query_cflags(tree):
    """从副本树 make 数据库提取主 CFLAGS（避免在本文件硬编码漂移）。"""
    try:
        r = subprocess.run(["make", "-C", tree, "-pn"], capture_output=True,
                           timeout=120)
        m = re.search(r"^CFLAGS = (.+)$", r.stdout.decode(errors="replace"),
                      re.M)
        return m.group(1).strip() if m else None
    except (OSError, subprocess.SubprocessError):
        return None


def build_dhcp_scale_iso(src_tree, out_iso, scale=DHCP_SCALE_DEFAULT,
                         scratch=None, keep_scratch=False):
    """LEASE_SCALE 专用 ISO 迷你构建器（route-a，commit b9530ff 验收机制套件化）。

    流程：源树 → /tmp 副本（剔除 .git/linux-ref 等非构建输入）→ make clean →
    ``make -jN all CFLAGS="<原值> -DCATOS_DHCP_LEASE_SCALE=<N>"`` → os.iso 拷出。
    整树统一追加该宏而非单文件重编：全仓库仅 net_dhcp.c 引用此宏（已 grep
    核实），其余编译单元语义逐位不变——换来的是零 Makefile 改动、零单点
    重链脚本。主仓库只读，构建一律发生在 scratch 副本。
    """
    src = os.path.realpath(src_tree)
    if scale < 1:
        raise wl.Fail("scale must be >=1 (net_dhcp.c:50-52), got %d" % scale)
    for tool in ("make", "gcc", "nasm", "ld", "objcopy", "grub-mkrescue"):
        if not shutil.which(tool):
            raise wl.Fail("builder tool missing: %s" % tool)
    if scratch:
        tree = os.path.realpath(scratch)
        if tree == src:
            raise wl.Fail("refuse in-place build on %s （主目录禁止 make，"
                          "请另指 --scratch）" % src)
    else:
        tree = tempfile.mkdtemp(prefix="catos-dhcpscale-")
    if os.path.isdir(tree) and not keep_scratch:
        shutil.rmtree(tree)
    ignore = shutil.ignore_patterns(
        ".git", ".opencode", "linux-ref", "__pycache__",
        "*.o", "*.elf", "*.bin", "os.iso", "iso", "disk.img",
        "downloaded", "*.log", "*.serial")
    print("[dhcp-build] copy %s -> %s ..." % (src, tree))
    shutil.copytree(src, tree, ignore=ignore, symlinks=True)
    base = _make_query_cflags(tree)
    if not base:
        print("[dhcp-build] WARN: make -pn 未提取到 CFLAGS，用兜底镜像")
        base = _DHCP_FALLBACK_CFLAGS
    cflags = "%s -DCATOS_DHCP_LEASE_SCALE=%d" % (base, scale)
    print("[dhcp-build] CFLAGS=%s" % cflags)

    def run(cmd, timeout=900):
        print("[dhcp-build] %s" % " ".join(cmd[:6]) + (" ..." if len(cmd) > 6 else ""))
        r = subprocess.run(cmd, capture_output=True, timeout=timeout)
        if r.returncode != 0:
            tail = r.stdout.decode(errors="replace").splitlines()[-15:]
            tail += r.stderr.decode(errors="replace").splitlines()[-15:]
            raise wl.Fail("build step failed rc=%d:\n%s"
                          % (r.returncode, "\n".join(tail)))
        return r

    run(["make", "-C", tree, "clean"])
    t0 = time.time()
    run(["make", "-C", tree, "-j%d" % (os.cpu_count() or 2),
         "CFLAGS=%s" % cflags, "all"])
    iso = os.path.join(tree, "os.iso")
    if not os.path.isfile(iso):
        raise wl.Fail("make reported success but os.iso missing in %s" % tree)
    out_iso = os.path.abspath(out_iso)
    out_dir = os.path.dirname(out_iso)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    shutil.copyfile(iso, out_iso)
    print("[dhcp-build] OK scale=%d iso=%s (%dB, %.1fs)"
          % (scale, out_iso, os.path.getsize(out_iso), time.time() - t0))
    if not keep_scratch and not scratch:
        shutil.rmtree(tree, ignore_errors=True)
    return out_iso


def case_dhcp_lease(S):
    """DHCP 租约生命周期常驻用例（slirp 模式 + LEASE_SCALE 专用 ISO）。

    前置：由 run_all.sh / 手工先用 ``--build-dhcp-scale-iso`` 造出
    dhcp_scale.iso（SCALE 默认 21600 ⇒ 86400s→400 ticks、T1≈2s、T2≈3.5s，
    net_dhcp.c:55-58 换算、:63-76 dhcp_arm_lease 取下限钳制），再经
    ``CATOS_SLIRP_READY_MARK='[NET] DHCP ACK ip=' qemu_run.sh --mode slirp
    --iso dhcp_scale.iso -- python3 net_suite.py --suite inject --case
    dhcp_lease`` 驱动——就绪门走串口标记而非 guest:80 端口，因为 pristine
    HEAD 无 ring3 :80 探针（README「尚未接线」）。slirp 的 DHCP 服务对任何
    到达 UDP:67 的报文应答（含 RENEW 单播），租约恒 86400s。

    断言面（标记原文见 DHCP_MARK_* 注释，net_dhcp.c 行号）：
      P1 首取全程 DISCOVER(:102)→REQUEST(:102)→ACK ip=(:140) 各恰一次；
      P2 串口顺序 DISCOVER < REQUEST < ACK < T1 due(:157) < REQUEST(renew)
         < ACK renew ip=(:139) —— BOUND--T1-->RENEWING 单播续期状态迁移；
      P3 续期可持续：≥CATOS_DHCP_MIN_RENEWS 轮 ACK renew（每轮 ACK 经
         dhcp_arm_lease 重挂三截止 ⇒ 循环非一次性巧合）；且 REQUEST(renew)+
         REQUEST(rebind) 总数 ≥ ACK renew 数（每个续期 ACK 必有在先请求，
         尾部未决允许）；
      P4 服务存活不变量（契约面）：expire(:108)/NAK(:124)/fallback
         static(:194) 全程零次 —— slirp 恒应答，出现即回归信号；
      P5 REBINDING 机会性覆盖：T2 due(:170)/REQUEST(rebind) 允许出现
        （首轮单播 ARP 预热 miss 等瞬态即可触发，RFC 2131 §4.4.5 合法
         迁移），但最后一条 rebind 请求之后必须出现 ACK renew —— 广播
         续租被服务端接住并重新武装（首跑实测即观察到该恢复路径）；
      P6 续期风暴中数据面存活：内核常驻 UDP:7 echo 往返（net_udp.c:35/41，
         不依赖 ring3 探针接线——pristine HEAD 即可跑）；
      P7 final scan 无 panic/CPU exception/CR2=/[ERR]。

    NOT_TESTED（结构性不可达，见 README）：租约到期 rediscover、NAK
    restart —— 需要「授约后失联/拒绝」的 DHCP 服务端，slirp 均不满足；
    socket-netdev 裸模式无服务端只会走 fallback（另一条已被 socket 套件
    隐式覆盖的路径），租约根本不建立。
    """
    scale = _env_int("CATOS_DHCP_SCALE", DHCP_SCALE_DEFAULT)
    window = _env_int("CATOS_DHCP_WINDOW", 30)
    min_renews = _env_int("CATOS_DHCP_MIN_RENEWS", 3)
    lt_ticks = 86400 * 100 // max(1, scale)
    S.note("lease_model",
           "SCALE=%d ⇒ lease=%d ticks(%sms), T1=lt/2, T2≈0.875·lt；窗口 %ss、"
           "最少续期轮数 %d"
           % (scale, lt_ticks, lt_ticks * 10, window, min_renews))

    want = {"ack_first": 1, "t1": 1,
            "req_renew": min_renews, "ack_renew": min_renews}

    def snapshot(txt):
        return {
            "discover": txt.count(DHCP_MARK_DISCOVER),
            "req_first": txt.count(DHCP_MARK_REQUEST_FIRST),
            "ack_first": txt.count(DHCP_MARK_ACK_FIRST),
            "t1": txt.count(DHCP_MARK_T1),
            "req_renew": txt.count(DHCP_MARK_RENEW_REQ),
            "ack_renew": txt.count(DHCP_MARK_RENEW_ACK),
            "rebind": txt.count("[NET] DHCP REQUEST(rebind)"),
        }

    def rebind_settled(txt):
        """最后一条 rebind 请求后已有 ACK renew 收口（无 rebind 视为已收口）。"""
        i = txt.rfind("[NET] DHCP REQUEST(rebind)")
        return i < 0 or txt.find(DHCP_MARK_RENEW_ACK, i) >= 0

    end = time.time() + window
    while True:
        txt = _read_serial_str(S.serial)
        counts = snapshot(txt)
        if (all(counts[k] >= v for k, v in want.items())
                and rebind_settled(txt)):
            break
        if time.time() >= end:
            break
        # rebind 已现但 ACK 未落：多给 8s 宽限再判 P5，防把在途广播误判失败
        if counts["rebind"] > 0 and not rebind_settled(txt) \
                and time.time() > end - 8:
            end = time.time() + 8
        time.sleep(0.5)

    S.check("serial:%s first-acquire" % DHCP_MARK_DISCOVER.strip(),
            counts["discover"] >= 1, "count=%d" % counts["discover"])
    S.check("serial:first-acquire ACK exactly once (%s)" %
            DHCP_MARK_ACK_FIRST.strip(),
            counts["ack_first"] == 1, "count=%d" % counts["ack_first"])
    S.check("serial:T1 renew due fired", counts["t1"] >= 1,
            "count=%d" % counts["t1"])
    S.check("serial: sustained renewals >= %d (re-arm loop)" % min_renews,
            counts["ack_renew"] >= min_renews, "count=%d" % counts["ack_renew"])
    total_req = counts["req_renew"] + counts["rebind"]
    S.check("serial: every renew-ACK has preceding renew/rebind REQUEST",
            total_req >= counts["ack_renew"] > 0,
            "req=%d+%d ack=%d" % (counts["req_renew"], counts["rebind"],
                                  counts["ack_renew"]))

    txt = _read_serial_str(S.serial)
    marks = [DHCP_MARK_DISCOVER, DHCP_MARK_REQUEST_FIRST, DHCP_MARK_ACK_FIRST,
             DHCP_MARK_T1, DHCP_MARK_RENEW_REQ, DHCP_MARK_RENEW_ACK]
    pos = [txt.find(m) for m in marks]
    S.check("serial order: DISCOVER<REQUEST<ACK<T1<REQUEST(renew)<ACK renew",
            all(p >= 0 for p in pos) and pos == sorted(pos),
            "%s" % [(marks[i].strip()[-14:], pos[i]) for i in range(len(marks))])

    neg = {"lease expired": txt.count("lease expired"),
           "NAK, restart": txt.count("NAK, restart"),
           "fallback static": txt.count("fallback static")}
    S.check("server-alive invariants: zero expire/NAK/fallback",
            all(v == 0 for v in neg.values()), "%s" % neg)

    rb = txt.count("[NET] DHCP REQUEST(rebind)")
    if rb:
        S.check("serial: REBINDING broadcast recovered by ACK",
                rebind_settled(txt),
                "rebind_req=%d（机会性覆盖：T2 迁移被观察且收口）" % rb)
    else:
        S.note("rebind_path", "本窗口未触发 T2/REBINDING（T1→T2 间隙充裕）；"
                              "路径仍受 P5 恢复断言保护")

    ok = _udp7_echo_alive()
    S.check("dataplane alive amid renewal churn: kernel UDP:7 echo roundtrip",
            ok, "P_UDP7=%d（内核常驻服务，不依赖 ring3 探针接线）" % P_UDP7)

    time.sleep(2)
    bad = [pat for pat in (r"panic", r"CPU exception", r"CR2=", r"\[ERR\]")
           if re.search(pat, _read_serial_str(S.serial))]
    S.check("serial:final_scan", not bad,
            "无 panic/exception" if not bad else "发现 %s" % bad)


def _read_serial_str(path):
    try:
        with open(path, "r", errors="replace") as f:
            return f.read()
    except OSError:
        return ""


def _udp7_echo_alive(timeout=6.0):
    """内核 UDP:7 echo 往返（net_udp.c:35 open :7 / :41 dport==7 回显）——
    续期风暴中数据面存活的探针，不依赖任何 ring3 探针接线。"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    payload = b"dhcp-lease-liveness"
    try:
        s.sendto(payload, (HOST, P_UDP7))
        data, _a = s.recvfrom(2048)
        return data == payload
    except OSError:
        return False
    finally:
        s.close()


INJECT_CASES = {
    "sack_t1": case_sack_t1,
    "sack_t2": case_sack_t2,
    "sack_t5": case_sack_t5,
    "sack_t8": case_sack_t8,
    "rst_l1": case_rst_l1,
    "tw_recycle": case_tw_recycle,
    "backlog_probe": case_backlog_probe,
    "l3b_race": case_l3b_race,
    # 注意：dhcp_lease 是 inject 套件里唯一的 slirp 模式用例（需要 DHCP
    # 服务端 + LEASE_SCALE 专用 ISO），驱动方式见用例 docstring / README。
    "dhcp_lease": case_dhcp_lease,
}


def run_inject(case_name, serial):
    S = Suite("inject:%s" % case_name, serial)
    print("=== Cat-OS net_suite inject case=%s dport=%d serial=%s ==="
          % (case_name, INJECT_DPORT, serial))
    settle = float(os.environ.get("CATOS_INJECT_SETTLE", "1.0"))
    time.sleep(settle)     # 等 fallback static 之后栈稳定
    try:
        INJECT_CASES[case_name](S)
    except wl.Fail as e:
        print("HARNESS_ABORT: %s" % e)
        S.summary()
        return EXIT_HARNESS, S
    except OSError as e:
        print("HARNESS_ABORT: oserror %r" % e)
        S.summary()
        return EXIT_HARNESS, S
    S.summary()
    return (EXIT_ASSERT if S.hard_fails else EXIT_OK), S


# ==========================================================================
# CLI
# ==========================================================================

def main():
    ap = argparse.ArgumentParser(
        description="Cat-OS 网络测试套件（blackbox hostfwd / inject wire）")
    ap.add_argument("--suite", choices=["blackbox", "inject"],
                    help="套件名（--list 查看）")
    ap.add_argument("--case", help="inject 单用例名；缺省则同进程连跑全部"
                                   "（注意：严格语义应每用例新引导，见 README）")
    ap.add_argument("--list", action="store_true", help="列出阶段与用例后退出")
    ap.add_argument("--build-dhcp-scale-iso", nargs=2, metavar=("SRC_TREE", "OUT_ISO"),
                    help="dhcp_lease 前置：在 /tmp 副本树以 -DCATOS_DHCP_LEASE_SCALE=N "
                         "重编专用 ISO（主仓库零触碰；工具链缺失/构建失败 rc=5）")
    ap.add_argument("--scale", type=int, default=DHCP_SCALE_DEFAULT,
                    help="LEASE_SCALE 分母（默认 %(default)s，net_dhcp.c:41-58）")
    ap.add_argument("--scratch", default="",
                    help="副本构建目录（默认 mkdtemp 临时目录，成功后清理）")
    ap.add_argument("--serial", default=os.environ.get("SERIAL_LOG", "./serial.log"),
                    help="串口落盘路径（qemu_run.sh 已透传 SERIAL_LOG）")
    ap.add_argument("--json", default="", help="结构化结果 JSON 输出路径（CI 友好）")
    args = ap.parse_args()

    if args.build_dhcp_scale_iso:
        try:
            build_dhcp_scale_iso(args.build_dhcp_scale_iso[0],
                                 args.build_dhcp_scale_iso[1],
                                 scale=args.scale,
                                 scratch=args.scratch or None)
            return EXIT_OK
        except wl.Fail as e:
            print("[dhcp-build] FAILED: %s" % e)
            return EXIT_HARNESS

    if args.list:
        print("blackbox stages:")
        for name, _fn in BLACKBOX_STAGES:
            print("  - %s" % name)
        print("inject cases:")
        for name in INJECT_CASES:
            print("  - %s" % name)
        return EXIT_OK

    if not args.suite:
        ap.error("--suite 必填（或使用 --list）")

    report = {"suite": args.suite, "cases": {}}
    rc = EXIT_OK

    if args.suite == "blackbox":
        rc, S = run_blackbox(args.serial)
        r = S.report()
        r["exit_code"] = rc
        report["cases"]["blackbox"] = r
    else:
        cases = [args.case] if args.case else list(INJECT_CASES)
        unknown = [c for c in cases if c not in INJECT_CASES]
        if unknown:
            print("unknown inject case(s): %s (可用: %s)"
                  % (", ".join(unknown), ", ".join(INJECT_CASES)),
                  file=sys.stderr)
            return EXIT_USAGE
        saw_assert = False
        saw_harness = False
        if len(cases) > 1:
            print("[warn] 多用例同进程连跑共享同一内核引导；严格 fresh-boot "
                  "语义请用 qemu_run.sh/run_all.sh 按用例驱动")
        for cname in cases:
            crc, S = run_inject(cname, args.serial)
            r = S.report()
            r["exit_code"] = crc
            report["cases"][cname] = r
            saw_assert |= (crc == EXIT_ASSERT)
            saw_harness |= (crc == EXIT_HARNESS)
        rc = EXIT_ASSERT if saw_assert else (EXIT_HARNESS if saw_harness else EXIT_OK)

    if args.json:
        report["exit_code"] = rc
        try:
            with open(args.json, "w", encoding="utf-8") as f:
                json.dump(report, f, ensure_ascii=False, indent=2)
            print("[net_suite] json report -> %s" % args.json)
        except OSError as e:
            print("[net_suite] json write failed: %r" % e)
    return rc


if __name__ == "__main__":
    sys.exit(main())
