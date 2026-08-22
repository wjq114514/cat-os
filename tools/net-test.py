#!/usr/bin/env python3
import socket, struct, sys, time

HOST, PORT = "127.0.0.1", 12345
GIP = socket.inet_aton("10.0.2.15")
HIP = socket.inet_aton("192.168.1.1")
HMAC = bytes.fromhex("52 54 00 aa bb cc")

def csum(b):
    if len(b) & 1: b += b"\0"
    s = sum(struct.unpack("!%dH" % (len(b)//2), b))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def eth(dst, src, typ, payload): return dst + src + struct.pack("!H", typ) + payload
def ip(src, dst, proto, payload, ident=1):
    h = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20+len(payload), ident, 0, 64, proto, 0, src, dst)
    return h[:10] + struct.pack("!H", csum(h)) + h[12:] + payload
def arp(op, sha, spa, tha, tpa):
    return struct.pack("!HHBBH6s4s6s4s", 1, 0x0800, 6, 4, op, sha, spa, tha, tpa)

class Wire:
    def __init__(self): self.s = socket.create_connection((HOST, PORT), 5); self.gmac = None
    def send(self, f): self.s.sendall(struct.pack("!I", len(f)) + f)
    def recv(self, timeout=3):
        self.s.settimeout(timeout); h = self.s.recv(4)
        if len(h) != 4: raise RuntimeError("socket closed")
        n, b = struct.unpack("!I", h)[0], b""
        while len(b) < n:
            x = self.s.recv(n-len(b))
            if not x: raise RuntimeError("socket closed")
            b += x
        return b
    def wait_ip(self, proto, pred=lambda p: True):
        end = time.time() + 5
        while time.time() < end:
            f = self.recv(max(.1, end-time.time()))
            if f[12:14] == b"\x08\x06":
                a = f[14:];
                if a[6:8] == struct.pack("!H", 1) and a[24:28] == HIP:
                    self.gmac = a[8:14]
                    self.send(eth(self.gmac, HMAC, 0x0806, arp(2, HMAC, HIP, self.gmac, GIP)))
                continue
            if f[12:14] == b"\x08\0" and len(f) >= 34 and f[23] == proto and pred(f): return f
        raise TimeoutError("target frame timeout")

def main():
    w = Wire(); ok = True
    def check(name, fn):
        nonlocal ok
        try: fn(); print("PASS", name)
        except Exception as e: ok=False; print("FAIL", name, e)
    w.send(eth(b"\xff"*6, HMAC, 0x0806, arp(1, HMAC, HIP, b"\0"*6, GIP)))
    def do_arp():
        end = time.time() + 5
        while time.time() < end:
            f = w.recv(max(.1, end-time.time()))
            if f[12:14] != b"\x08\x06": continue
            a = f[14:]
            if struct.unpack("!H", a[6:8])[0] == 2:
                w.gmac = f[0:6]
                return
        raise TimeoutError("ARP reply timed out")
    check("ARP reply", do_arp)
    magic=b"NET-ICMP-MAGIC"; ic=struct.pack("!BBHHH",8,0,0,0x1234,1)+magic; ic=ic[:2]+struct.pack("!H",csum(ic))+ic[4:]
    w.send(eth(w.gmac,HMAC,0x0800,ip(HIP,GIP,1,ic)))
    check("ICMP echo", lambda: (lambda f: (_ for _ in ()).throw(AssertionError()) if f[34]!=0 or f[42:42+len(magic)]!=magic else None)(w.wait_ip(1)))
    data=b"udp-magic"; u=struct.pack("!HHHH",40000,7,8+len(data),0)+data
    w.send(eth(w.gmac,HMAC,0x0800,ip(HIP,GIP,17,u))); check("UDP echo", lambda: (_ for _ in ()).throw(AssertionError()) if w.wait_ip(17)[42:42+len(data)]!=data else None)
    seq=1000; syn=struct.pack("!HHII BBHHH",40000,80,seq,0,0x50,2,65535,0,0)
    w.send(eth(w.gmac,HMAC,0x0800,ip(HIP,GIP,6,syn))); f=w.wait_ip(6); guest_seq=struct.unpack("!I",f[38:42])[0]; assert f[47]&3==2
    client_ack=guest_seq+1
    a=struct.pack("!HHII BBHHH",40000,80,seq+1,client_ack,0x50,16,65535,0,0); w.send(eth(w.gmac,HMAC,0x0800,ip(HIP,GIP,6,a)))
    payload=b"tcp-magic"; d=struct.pack("!HHII BBHHH",40000,80,seq+1,client_ack,0x50,24,65535,0,0)+payload
    w.send(eth(w.gmac,HMAC,0x0800,ip(HIP,GIP,6,d))); af=w.wait_ip(6); assert struct.unpack("!I",af[42:46])[0]==seq+1+len(payload); print("PASS TCP handshake/data")
    fin=struct.pack("!HHII BBHHH",40000,80,seq+1+len(payload),client_ack,0x50,17,65535,0,0); w.send(eth(w.gmac,HMAC,0x0800,ip(HIP,GIP,6,fin))); print("PASS TCP FIN")
    return 0 if ok else 1
if __name__ == "__main__": sys.exit(main())
