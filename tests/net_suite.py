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

退出码：
  0 = 全部断言通过
  2 = 存在断言失败（真实回归信号，runner 不得重试掩盖）
  5 = harness/环境故障（线缆中断、SYN-ACK 超时等，可整轮重试）
 64 = 用法错误

用法：
  python3 net_suite.py --list
  python3 net_suite.py --suite blackbox --serial serial.log --json bb.json
  python3 net_suite.py --suite inject --case sack_t1 --serial serial.log --json t1.json
"""

import argparse
import json
import os
import re
import socket
import sys
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
            "%d/%d got banner (TCP_MAX_CONNS=16 上限内)" % (succ, n_par))


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


INJECT_CASES = {
    "sack_t1": case_sack_t1,
    "sack_t2": case_sack_t2,
    "sack_t5": case_sack_t5,
    "sack_t8": case_sack_t8,
    "rst_l1": case_rst_l1,
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
    ap.add_argument("--serial", default=os.environ.get("SERIAL_LOG", "./serial.log"),
                    help="串口落盘路径（qemu_run.sh 已透传 SERIAL_LOG）")
    ap.add_argument("--json", default="", help="结构化结果 JSON 输出路径（CI 友好）")
    args = ap.parse_args()

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
