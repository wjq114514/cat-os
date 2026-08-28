#!/bin/bash
set -e
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NGINX="$ROOT/nginx-1.26.2"
cd "$NGINX"

echo "=== Step 1: Configure (host) ==="
rm -rf objs
./configure \
    --without-http_rewrite_module \
    --without-http_gzip_module \
    --without-http_proxy_module \
    --without-http_fastcgi_module \
    --without-http_uwsgi_module \
    --without-http_scgi_module \
    --without-http_grpc_module \
    --without-http_memcached_module \
    --without-http_geo_module \
    --without-http_map_module \
    --without-http_split_clients_module \
    --without-http_referer_module \
    --without-http_limit_conn_module \
    --without-http_limit_req_module \
    --without-http_auth_basic_module \
    --without-http_autoindex_module \
    --without-http_mirror_module \
    --without-http_ssi_module \
    --without-http_charset_module \
    --without-http_userid_module \
    --without-select_module \
    --with-poll_module \
    --prefix=/tmp/nginx \
    --builddir="$NGINX/objs" \
    2>&1 | tail -3

echo "=== Step 1b: Apply Cat-OS configure headers ==="
python3 "$ROOT/patch-auto-headers.py"
python3 "$ROOT/patch-auto-config.py"

echo "=== Step 2: Build with Python ==="
cd "$ROOT"
python3 "$ROOT/build-nginx.py"

echo "=== Step 3: Disable master cycle ==="
python3 - <<'PY'
from pathlib import Path

path = Path("nginx-1.26.2/objs/nginx.elf")
data = bytearray(path.read_bytes())

# The generated main() contains: cmp [ccf->master], 0; jne master_cycle;
# followed immediately by the single-process call sequence. Match that
# instruction context instead of depending on a VMA or a stale ELF offset.
prefix = bytes.fromhex("8338000f85")
suffix = bytes.fromhex("83ec0cffb594feffffe8")
nops = bytes.fromhex("909090909090")
candidates = []
offset = 0
while True:
    offset = data.find(prefix, offset)
    if offset < 0:
        break
    if data[offset + 9:offset + 9 + len(suffix)] == suffix:
        candidates.append(offset + 3)
    offset += 1

if len(candidates) == 1:
    branch = candidates[0]
    data[branch:branch + len(nops)] = nops
    path.write_bytes(data)
    print("patched master-cycle branch at file offset 0x%x" % branch)
else:
    patched = []
    offset = 0
    while True:
        offset = data.find(prefix, offset)
        if offset < 0:
            break
        if data[offset + 3:offset + 9] == nops and \
           data[offset + 9:offset + 9 + len(suffix)] == suffix:
            patched.append(offset + 3)
        offset += 1
    if len(patched) != 1:
        raise SystemExit("expected one master-cycle branch, found %d" % len(candidates))
    print("master-cycle branch already patched at file offset 0x%x" % patched[0])

print("verified single-process branch patch")
PY

echo "=== Step 4: Strip and embed ==="
i686-linux-gnu-strip "$NGINX/objs/nginx" -o "$NGINX/objs/nginx.stripped"
i686-linux-gnu-strip "$NGINX/objs/nginx.elf" -o "$NGINX/objs/nginx.elf.stripped"
python3 - <<'PY'
from pathlib import Path

data = Path("nginx-1.26.2/objs/nginx.elf.stripped").read_bytes()
lines = ["#pragma once", "unsigned char nginx_elf[] = {"]
for i in range(0, len(data), 12):
    lines.append("  " + ", ".join("0x%02x" % b for b in data[i:i + 12]) + ",")
lines.extend(["};", "unsigned int nginx_elf_len = %d;" % len(data), ""])
Path("nginx_bin.h").write_text("\n".join(lines), encoding="ascii")
print("embedded nginx.elf.stripped: %d bytes" % len(data))
PY
ls -la "$NGINX/objs/nginx.stripped" "$NGINX/objs/nginx.elf.stripped" nginx_bin.h

echo "=== Done ==="
