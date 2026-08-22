#!/usr/bin/env python3
import socket
import struct
import sys
import time

host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
port = int(sys.argv[2]) if len(sys.argv) > 2 else 12345
dst = bytes.fromhex("ff ff ff ff ff ff")
src = bytes.fromhex("52 54 00 aa bb cc")
arp = struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1)
arp += src + bytes((192, 168, 1, 1))
arp += bytes(6) + bytes((10, 0, 2, 15))
frame = dst + src + struct.pack("!H", 0x0806) + arp

with socket.create_connection((host, port), timeout=5) as sock:
    # QEMU stream socket netdev uses a big-endian 32-bit length prefix.
    sock.sendall(struct.pack("!I", len(frame)) + frame)
    time.sleep(2)
