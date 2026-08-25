#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Cat-OS tests/wire_lib.py —— 注入式网络用例的共享线缆层（code10 正式化入库）。

来源与改进（原型保留在 /tmp 供 code4 复用，本文件为唯一入库版）：
- 帧构造 / 校验和 / SACK 选项 / 状态机：移植自 /tmp/sack_edge.py（stage-3 版）。
- Wire.collect() 采用 /tmp/ox_lifecycle_edge.py 中 W2 的最终形态：感知以太网最小
  帧 padding，按 IP 头总长裁剪 payload，避免 bare challenge-ACK 被误判成带数据。
- 通道：QEMU ``-netdev socket,id=net0,listen=127.0.0.1:<port>`` 的原始帧注入；
  线格式 = 4 字节大端长度前缀 + 完整以太网帧（与上述两个原型的 harness 一致）。

仅依赖标准库；在宿主机侧运行；绝不写仓库任何文件。
"""

import os
import socket
import struct
import time

H = "127.0.0.1"
WIRE_PORT = int(os.environ.get("CATOS_WIRE_PORT", "12345"))
GUEST_IP = "10.0.2.15"    # 内核 DHCP 失败后的 static fallback 地址
HOST_IP = "192.168.1.1"   # 注入方伪装的对端 IP
GUEST_MAC = bytes.fromhex("52 54 00 aa bb cc")   # 原型中收发两侧共用同一 MAC

FIN = 1
SYN = 2
RST = 4
PSH = 8
ACK = 16
U32 = 0xFFFFFFFF
MSS_OPT = b"\x01\x01\x04\x02"


class Fail(Exception):
    """线缆/环境级故障（区别于断言失败）：上层 runner 可据此整轮重试。"""


# --------------------------------------------------------------------------
# 帧构造
# --------------------------------------------------------------------------

def cs(b):
    """Internet checksum。"""
    if len(b) & 1:
        b += b"\0"
    s = sum(struct.unpack("!%dH" % (len(b) // 2), b))
    while s >> 16:
        s = (s & 65535) + (s >> 16)
    return (~s) & 65535


def ip_pkt(p):
    h = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(p), 1, 0, 64, 6, 0,
                    socket.inet_aton(HOST_IP), socket.inet_aton(GUEST_IP))
    return h[:10] + struct.pack("!H", cs(h)) + h[12:] + p


def frame(p):
    return GUEST_MAC + GUEST_MAC + b"\x08\x00" + ip_pkt(p)


def tcp_seg(sp, dp, seq, ack, fl, data=b"", opt=b"", win=4096):
    off = (20 + len(opt)) // 4
    h = struct.pack("!HHIIBBHHH", sp, dp, seq, ack, off << 4, fl, win, 0, 0) + opt
    pseudo = (socket.inet_aton(HOST_IP) + socket.inet_aton(GUEST_IP)
              + b"\x00\x06" + struct.pack("!H", len(h) + len(data)))
    q = h[:16] + b"\x00\x00" + h[18:]
    q = q[:16] + struct.pack("!H", cs(pseudo + q + data)) + q[18:]
    return q + data


def sack_opt(blocks):
    if not blocks:
        return b""
    return (b"\x01\x01\x05" + bytes((2 + 8 * len(blocks),))
            + b"".join(struct.pack("!II", a & U32, b & U32) for a, b in blocks))


def lt(a, b):
    """wrap-aware a < b"""
    return ((a - b) & U32) >= 0x80000000


def le(a, b):
    return a == b or lt(a, b)


# --------------------------------------------------------------------------
# Wire：原始帧通道（padding-aware collect 为 W2 改进版）
# --------------------------------------------------------------------------

class Wire(object):
    """一条连到 QEMU socket-netdev 监听端的原始以太网帧通道。"""

    def __init__(self, sport, host=H, port=None, connect_timeout=5, rx_timeout=0.2):
        self.sport = sport
        self.s = socket.create_connection((host, port or WIRE_PORT), connect_timeout)
        self.s.settimeout(rx_timeout)
        self.next_seq = 1      # 客户端侧 seq 游标（纯 ACK 可复用它）
        self.last_ack = None

    def close(self):
        try:
            self.s.close()
        except OSError:
            pass

    def put(self, f):
        self.s.sendall(struct.pack("!I", len(f)) + f)

    def _raw(self):
        h = self.s.recv(4)
        if len(h) != 4:
            raise Fail("wire closed")
        n = struct.unpack("!I", h)[0]
        b = b""
        while len(b) < n:
            x = self.s.recv(n - len(b))
            if not x:
                raise Fail("wire closed")
            b += x
        return b

    def serve_arp(self, f):
        # 应答线上任何 ARP 请求（guest ip、fallback 网关 10.0.2.2 等）。
        # 我们是这条线上唯一对端；不回应会令内核 ARP 重试拖慢注入节奏。
        if f[12:14] == b"\x08\x06" and f[20:22] == b"\x00\x01":
            spa_req = f[28:32]
            tpa_req = f[38:42]
            rep = struct.pack("!HHBBH6s4s6s4s", 1, 0x800, 6, 4, 2,
                              GUEST_MAC, tpa_req, f[6:12], spa_req)
            self.put(f[6:12] + GUEST_MAC + struct.pack("!H", 0x806) + rep)

    def collect(self, seconds, dp=None):
        """收集 seconds 秒内的 TCP 段，返回 dict 列表（padding-aware）。"""
        out = []
        end = time.time() + seconds
        while time.time() < end:
            try:
                f = self._raw()
            except socket.timeout:
                continue
            except OSError:
                raise Fail("wire error")
            self.serve_arp(f)
            if len(f) < 54 or f[12:14] != b"\x08\x00" or f[23] != 6:
                continue
            sp_ = struct.unpack("!H", f[34:36])[0]
            dp_ = struct.unpack("!H", f[36:38])[0]
            if dp is not None and (sp_ != dp or dp_ != self.sport):
                continue
            seq, ack = struct.unpack("!II", f[38:46])
            off = (f[46] >> 4) * 4
            flags = f[47]
            ip_len = struct.unpack("!H", f[16:18])[0]
            payload = f[34 + off:max(34 + off, 14 + ip_len)]
            blocks = []
            o = f[54:34 + off]
            i = 0
            while i < len(o):
                k = o[i]
                if k == 0:
                    break
                if k == 1:
                    i += 1
                    continue
                if i + 1 >= len(o):
                    break
                n = o[i + 1]
                if k == 5 and n >= 10 and (n - 2) % 8 == 0:
                    for j in range((n - 2) // 8):
                        blocks.append(struct.unpack("!II",
                                                    o[i + 2 + j * 8:i + 10 + j * 8]))
                if n < 2:
                    break
                i += n
            out.append(dict(seq=seq, ack=ack, flags=flags, dlen=len(payload),
                            data=payload, blocks=blocks))
        return out

    def arp(self):
        req = struct.pack("!HHBBH6s4s6s4s", 1, 0x800, 6, 4, 1,
                          GUEST_MAC, socket.inet_aton(HOST_IP),
                          b"\0" * 6, socket.inet_aton(GUEST_IP))
        self.put(b"\xff" * 6 + GUEST_MAC + struct.pack("!H", 0x806) + req)
        end = time.time() + 5
        while time.time() < end:
            try:
                f = self._raw()
            except socket.timeout:
                continue
            except OSError:
                raise Fail("wire error")
            self.serve_arp(f)
            if f[12:14] == b"\x08\x06" and f[20:22] == b"\x00\x02":
                return
        raise Fail("ARP timeout")

    def handshake(self, dport, isn, win=4096):
        self.put(frame(tcp_seg(self.sport, dport, isn, 0, SYN, opt=MSS_OPT, win=win)))
        gs = None
        end = time.time() + 6
        while gs is None and time.time() < end:
            for p in self.collect(0.3, dp=dport):
                if p["flags"] & SYN and p["flags"] & ACK:
                    gs = p["seq"]
        if gs is None:
            raise Fail("SYN-ACK timeout")
        self.next_seq = (isn + 1) & U32
        self.put(frame(tcp_seg(self.sport, dport, self.next_seq,
                               (gs + 1) & U32, ACK, win=win)))
        return gs

    def send_data(self, dport, seq, data, ackv, win=4096, opt=b""):
        self.next_seq = (seq + len(data)) & U32
        self.put(frame(tcp_seg(self.sport, dport, seq & U32, ackv & U32,
                               ACK | PSH, data, opt=opt, win=win)))

    def send_ack(self, dport, ackv, win=4096, opt=b"", seqv=None):
        if seqv is None:
            seqv = self.next_seq
        self.last_ack = ackv & U32
        self.put(frame(tcp_seg(self.sport, dport, seqv & U32, self.last_ack,
                               ACK, opt=opt, win=win)))


# --------------------------------------------------------------------------
# 接收状态机与 coalescing-aware 区间工具
# --------------------------------------------------------------------------

def mk_state(base):
    return {"have": {}, "contig": base, "base": base, "buf": {}}


def absorb(state, p, seen, rexmits):
    if not p["dlen"]:
        return
    key = (p["seq"], p["dlen"])
    if key in seen:
        rexmits.append(key)
    else:
        seen.add(key)
    state["have"][p["seq"]] = p["data"]


def advance(state):
    moved = True
    while moved:
        moved = False
        b = state["contig"]
        if b in state["have"]:
            d = state["have"].pop(b)
            buf = state["buf"]
            for i, ch in enumerate(d):
                buf[(b + i) & U32] = ch   # 绝对字节序号键，跨回绕仍可校验
            state["contig"] = (b + len(d)) & U32
            moved = True


def check_integrity(state, n, gen):
    """逻辑流 [base, base+n) 的每个字节都必须已交付且匹配生成器。"""
    buf = state["buf"]
    base = state["base"]
    miss = 0
    bad = 0
    samples = []
    for o in range(n):
        v = buf.get((base + o) & U32)
        e = gen(o)
        if v is None:
            miss += 1
        elif v != e:
            bad += 1
            if len(samples) < 4:
                samples.append((o, v, e))
    return miss, bad, samples


def segs_of(keys):
    return [(s & U32, (s + l) & U32) for s, l in keys]


def within(keys, lo, hi):
    """所有重传段都落在 [lo,hi] 内（无外来/junk 诱发区间）。"""
    return all(le(lo, a) and le(b, hi) for a, b in segs_of(keys))


def holes_covered(keys, holes):
    """每个 [lo,hi) 空洞都被重传段之并完全铺满。"""
    iv = sorted(segs_of(keys))

    def cov(lo, hi):
        cur = lo
        while lt(cur, hi):
            nxt = None
            for a, b in iv:
                if le(a, cur) and lt(cur, b) and (nxt is None or lt(nxt, b)):
                    nxt = b
            if nxt is None:
                return False
            cur = nxt
        return True

    return all(cov(lo, hi) for lo, hi in holes)


def drain(w, dport, state, target, seen, rexmits, win=4096, budget=10.0,
          ack_always=False):
    """累积 ACK 泵，直到 contig >= target。仅在 contig 前进时发 ACK，
    且 ACK 值封顶于 target——超出 pin 点的数据保持未确认。"""
    last = None
    end = time.time() + budget
    while time.time() < end and lt(state["contig"], target):
        got = w.collect(0.25, dp=dport)
        changed = False
        for p in got:
            absorb(state, p, seen, rexmits)
        advance(state)
        if state["contig"] != last:
            last = state["contig"]
            changed = True
        if changed or (ack_always and got):
            ackv = target if lt(target, state["contig"]) else state["contig"]
            w.send_ack(dport, ackv, win=win)
    # 即使 contig 提前满足 target 也补一发封顶 ACK（此前选择重传轮里数据可能
    # 已抢先到达）；若循环恰好已 ACK 在该处则跳过，避免多余 dup-ACK。
    ackv = target if lt(target, state["contig"]) else state["contig"]
    if w.last_ack != (ackv & U32):
        w.send_ack(dport, ackv, win=win)
    return state["contig"]


def log_count(logpath, pat):
    """串口原文计数；日志缺失返回 -1（由调用方决定成败语义）。"""
    try:
        with open(logpath, "r", errors="replace") as fh:
            return fh.read().count(pat)
    except OSError:
        return -1
