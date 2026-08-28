#!/usr/bin/env python3
"""Patch objs/Makefile for Cat-OS cross-compilation - v4."""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SHIM = str(ROOT / "nginx-shim")
LIBC = str(ROOT)
mf = ROOT / "nginx-1.26.2" / "objs" / "Makefile"

with open(mf) as f:
    content = f.read()

# Replace CC
content = re.sub(r'CC\s*=\s*cc', 'CC =\ti686-linux-gnu-gcc', content)

# Replace CFLAGS
content = re.sub(r'CFLAGS\s*=.*', (
    'CFLAGS =  -pipe  -O2 -W -Wall -Wpointer-arith -Wno-unused-parameter '
    '-Wno-sign-compare -Wno-unused-function -Wno-unused-variable '
    '-Wno-unused-but-set-variable -Wno-missing-field-initializers '
    '-Wno-type-limits -Werror -g '
    '-ffreestanding -nostdlib -nostartfiles -nostdinc -static -m32 '
    f'-I {SHIM} -I /usr/lib/gcc-cross/i686-linux-gnu/13/include -I {LIBC}/libc '
), content, count=1)

# Replace link line
content = content.replace(
    '\t$(LINK) -o objs/nginx \\',
    '\t$(LINK) -o objs/nginx -nostdlib -nostartfiles \\'
)

# Remove -Wl,-E
content = re.sub(r'\t-Wl,-E\n', '', content)

# Fix build target
content = content.replace('build:\tbinary modules manpage', 'build:\tbinary')

# Now remove bpf/epoll: line by line, also removing orphaned recipe fragments
lines = content.split('\n')
out = []
skip_recipe = False
for i, line in enumerate(lines):
    s = line.strip()

    # Remove all bpf/epoll references
    if 'ngx_bpf' in line or 'ngx_epoll_module' in line:
        # If this is a recipe line (starts with \t), set flag to skip orphaned recipe
        if line.startswith('\t'):
            skip_recipe = True
        continue

    # Skip orphaned recipe fragments (lines starting with \t$(CC) that have no corresponding target)
    if skip_recipe:
        if line.startswith('\t') or s == '':
            continue
        else:
            skip_recipe = False

    # Also catch standalone orphaned recipe lines that are just compiler commands with no -o target on same/next line
    if re.match(r'\t\$\(CC\) -c \$\(CFLAGS\)', line):
        # Check if the next line has -o ... target
        if i+1 < len(lines) and '-o ' in lines[i+1]:
            # This is a valid recipe, keep it
            pass
        else:
            # Orphaned fragment, skip
            continue

    out.append(line)

content = '\n'.join(out)

# Clean double blank lines
while '\n\n\n' in content:
    content = content.replace('\n\n\n', '\n\n')

with open(mf, 'w') as f:
    f.write(content)

print("Makefile patched successfully")
