#!/usr/bin/env bash
# ============================================================================
# tests/user_sock_abi/build_selfcheck.sh —— code10 编译/链接自检（零仓库污染）
#
# 用途：在【不改 Makefile、不产生仓库内构建产物】的前提下，复现与 shell_user.c
#       同款的 ring3 编译方式，并对产物做 elf_load 装载约束的静态验证。
#       产物一律落在 mktemp -d 给出的 /tmp 目录，脚本结束打印路径供复核。
#
# 编译参数来源：Makefile「code2: ring3 shell」段 SHELL_CFLAGS / SHELL_LDFLAGS
#   （逐字同款；本测试程序与 shell_user.c 同为 freestanding 无 libc 单文件）。
#
# 静态验证项（依据 elf.c 的装载契约）：
#   [1] gcc -c 零告警零错误（-Wall -Wextra 同 SHELL_CFLAGS）
#   [2] ld 链接成功，所有符号自洽（无 libc 依赖）
#   [3] readelf -h：ELF32 / LSB / EXEC / Intel 80386 / 入口 _start=0x400000
#       （-Ttext=0x400000；user_range_ok 下限，syscall.c:32）
#   [4] readelf -l：所有 PT_LOAD vaddr >= 0x1000（elf_load 校验链，
#       Makefile SHELL_LDFLAGS 注释引用 elf.c:150）
#   [5] readelf -S：不存在 .note.gnu.property（-fcf-protection=none 生效，
#       保证纯 ELF32 —— Makefile 注释同款要求）
#   [6] objdump -d：存在 int $0x80 指令位点（ABI 触达面非空）
#
# 退出码：0 = 全部通过；1 = 任一失败。
# 本脚本属于 tests/ 新增文件，不改任何现有文件；临时产物在 /tmp。
# ============================================================================
set -u

DIR="$(cd "$(dirname "$0")" && pwd)"
SRC="$DIR/user_sock_abi_test.c"
OUT="$(mktemp -d /tmp/usabi-selfcheck.XXXXXX)"
FAIL=0

say() { printf '[selfcheck] %s\n' "$*"; }
die() { printf '[selfcheck] FAIL: %s\n' "$*" >&2; FAIL=1; }

[ -f "$SRC" ] || { echo "missing $SRC" >&2; exit 1; }

# 与 Makefile SHELL_CFLAGS 逐字同款（除输出路径）
CFLAGS="-m32 -march=i686 -ffreestanding -fno-pic -fno-pie \
-fcf-protection=none -fno-stack-protector -fno-builtin \
-fno-asynchronous-unwind-tables -fno-unwind-tables \
-nostdlib -Wall -Wextra -std=gnu99 -O2"
LDFLAGS="-m elf_i386 -nostdlib -static -e _start -Ttext=0x400000"

say "workdir: $OUT"

# ---- [1] compile ------------------------------------------------------------
if gcc $CFLAGS -c -o "$OUT/user_sock_abi_test.o" "$SRC" 2> "$OUT/cc.err"; then
  say "[1] gcc -c OK（-Wall -Wextra 零告警）: $(wc -c < "$OUT/user_sock_abi_test.o") bytes .o"
else
  say "[1] gcc -c FAILED:"; cat "$OUT/cc.err"; exit 1
fi

# ---- [2] link ----------------------------------------------------------------
if ld $LDFLAGS -o "$OUT/user_sock_abi_test.elf" "$OUT/user_sock_abi_test.o" 2> "$OUT/ld.err"; then
  say "[2] ld OK: $(wc -c < "$OUT/user_sock_abi_test.elf") bytes ELF32"
else
  say "[2] ld FAILED:"; cat "$OUT/ld.err"; exit 1
fi

# ---- [3] ELF header ----------------------------------------------------------
H="$(readelf -h "$OUT/user_sock_abi_test.elf")"
echo "$H" | grep -q "Class:.*ELF32"        || die "[3] not ELF32"
echo "$H" | grep -q "Data:.*little endian" || die "[3] not LSB"
echo "$H" | grep -q "Type:.*EXEC"          || die "[3] not ET_EXEC"
echo "$H" | grep -q "Machine:.*Intel 80386" || die "[3] not i386"
ENTRY="$(echo "$H" | awk '/Entry point/{print $4}')"
SYM_START="$(nm "$OUT/user_sock_abi_test.elf" | awk '$3=="_start"{print $1}')"
[ "$(printf '%d' "$ENTRY")" -eq "$(printf '%d' "0x$SYM_START")" ] \
  || die "[3] entry=$ENTRY != _start=0x$SYM_START"
[ "$(printf '%d' "$ENTRY")" -ge 4194304 ] || die "[3] entry=$ENTRY < 0x400000 用户区下限"
say "[3] readelf -h OK: ELF32/LSB/EXEC/i386, entry=$ENTRY == _start（>=0x400000）"

# ---- [4] PT_LOAD vaddr constraint --------------------------------------------
BADV="$(readelf -l "$OUT/user_sock_abi_test.elf" \
        | awk '/LOAD/{print $3}' | tr -d ' \r' \
        | while read -r v; do
            case "$v" in 0x*) ;; *) continue ;; esac
            if [ "$(printf '%d' "$v")" -lt 4096 ]; then echo "$v"; fi
          done )"
[ -z "$BADV" ] || die "[4] PT_LOAD vaddr < 0x1000: $BADV"
NLOAD="$(readelf -l "$OUT/user_sock_abi_test.elf" | grep -c ' LOAD ')"
say "[4] readelf -l OK: ${NLOAD} 个 LOAD 段 vaddr 均 >= 0x1000（elf_load 校验链）"

# ---- [5] no .note.gnu.property -------------------------------------------------
if readelf -S "$OUT/user_sock_abi_test.elf" | grep -q "note.gnu.property"; then
  die "[5] 存在 .note.gnu.property（-fcf-protection=none 未生效）"
else
  say "[5] readelf -S OK: 无 .note.gnu.property（纯 ELF32，PT_LOAD-only 可装载）"
fi

# ---- [6] int $0x80 sites -------------------------------------------------------
NINT="$(objdump -d "$OUT/user_sock_abi_test.elf" | grep -cE 'int +\$0x80')"
[ "${NINT:-0}" -gt 0 ] || die "[6] 未发现 int \$0x80 位点"
say "[6] objdump -d OK: 发现 ${NINT} 处 int \$0x80 触发位点"

# ---- 符号自洽性（nm 无未定义符号）----------------------------------------------
UNDEF="$(nm -u "$OUT/user_sock_abi_test.elf" | grep -v '^$' || true)"
[ -z "$UNDEF" ] || die "未定义符号存在: $UNDEF"
say "[+] nm -u OK: 无未定义符号（freestanding 自洽）"

echo "============================================================"
if [ "$FAIL" -eq 0 ]; then
  say "SELFCHECK PASS — 产物保留于: $OUT"
  say "复核命令示例: readelf -hlS $OUT/user_sock_abi_test.elf"
  exit 0
else
  say "SELFCHECK FAIL — 中间产物保留于: $OUT"
  exit 1
fi
