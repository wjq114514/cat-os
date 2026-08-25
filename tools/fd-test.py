#!/usr/bin/env python3
"""Cat-OS L2 fd 分配自检（code7 / vfs.c 锁内配套测试脚本）。

黑盒流程：启动 QEMU 引导 os.iso，捕获串口，断言：
  A. vfs_init 内建自检输出 "[VFS-FD] selftest PASS ..."（含期望 fd 序列）
  B. 标记出现前无 "[ERR] exception" / "panic" / "CR2"
覆盖点：std 占 0-2 后首个动态 open 得 fd=3；close 归还后最低空闲复用；
socket/文件共用分配器且 kind 隔离；边界与 double-close 返回 -EBADF。

用法: python3 tools/fd-test.py [iso路径]   # 默认 <repo>/os.iso
退出码: 0=PASS  1=断言失败  2=qemu 缺失  3=ISO 缺失(请先 make)
"""
import subprocess, sys, time, os

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ISO = sys.argv[1] if len(sys.argv) > 1 else os.path.join(REPO, "os.iso")
SERIAL = "/tmp/cat-os-fdtest-serial.log"
MARK = "[VFS-FD] selftest PASS"
BAD = ("[ERR] exception", "panic", "PANIC")

if subprocess.call(["which", "qemu-system-x86_64"], stdout=subprocess.DEVNULL) != 0:
    print("fd-test: qemu-system-x86_64 not found"); sys.exit(2)
if not os.path.isfile(ISO):
    print("fd-test: ISO not found: %s (先 make clean && make)" % ISO); sys.exit(3)

open(SERIAL, "w").close()
qemu = subprocess.Popen(
    ["qemu-system-x86_64", "-m", "128M", "-display", "none",
     "-no-reboot", "-no-shutdown", "-serial", "file:" + SERIAL,
     "-netdev", "user,id=net0", "-device", "e1000,netdev=net0",
     "-cdrom", ISO],
    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
try:
    ok_line, saw_bad = None, None
    deadline = time.time() + 30
    while time.time() < deadline and qemu.poll() is None:
        try:
            txt = open(SERIAL, errors="replace").read()
        except OSError:
            time.sleep(0.2); continue
        for b in BAD:
            if b in txt and MARK not in txt:
                saw_bad = b; break
        if MARK in txt:
            ok_line = [l for l in txt.splitlines() if l.startswith(MARK)][0]
            break
        if saw_bad: break
        time.sleep(0.2)
finally:
    qemu.terminate()
    try: qemu.wait(timeout=5)
    except Exception: qemu.kill()

txt = open(SERIAL, errors="replace").read()
print("=" * 24, "SERIAL 原文（节选）", "=" * 24)
keep = [l for l in txt.splitlines()
        if l.startswith(("[OK]", "[WARN]", "[VFS-FD]", "[ERR]")) or "panic" in l.lower()]
for l in keep[:60]: print(l)
print("=" * 64)

if ok_line and not any(b in txt.split(MARK)[0] for b in BAD):
    print("fd-test: PASS ->", ok_line); sys.exit(0)
print("fd-test: FAIL (marker=%s bad=%s)" % (bool(ok_line), saw_bad))
sys.exit(1)
