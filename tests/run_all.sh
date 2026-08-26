#!/usr/bin/env bash
# ============================================================================
# Cat-OS tests/run_all.sh —— 一键编排（code10 正式化入库）
#
# 替代 /tmp/cat-os-tests/run_all.sh（原型保留在 /tmp 供 code4 复用）。
# 与原型的差异：不做 make（构建健康检查归构建侧，避免触碰 Makefile 的双改约束），
# 不编译 ring3 骨架（user_ring3_socktest.c 仍留在 /tmp，接线后由其归属任务回填）。
#
# 阶段:
#   [1/4] 语法自检（bash -n / python3 ast.parse + py_compile）
#   [2/4] blackbox 套件（slirp hostfwd，单次引导跑全部黑盒阶段）
#   [3/4] inject 套件（每用例独立引导一颗新 QEMU；
#         harness 故障 rc∈{3,4,5} 重试≤3 次，断言失败 rc=2 永不重试）
#         例外：dhcp_lease 走 slirp 模式 + LEASE_SCALE 专用 ISO —— 该 ISO
#         由 net_suite.py --build-dhcp-scale-iso 在 /tmp 副本树现编（主仓库
#         零触碰；工具链缺失/构建失败 -> 该用例 NOT_TESTED 不拖垮整轮），
#         已有预构建产物时经 CATOS_DHCP_SCALE_ISO 直接引用跳过构建。
#   [4/4] 结构化汇总（status.txt + 各 JSON 报告）
#
# 退出码: 0 = 全绿；1 = 存在失败。QEMU 缺失时打印 NOT_TESTED 并以 0 退出。
#
# 环境变量:
#   CATOS_REPO(默认 /home/wjqawa/osdev) CATOS_ISO(默认 $REPO/os.iso)
#   CATOS_TEST_OUT(默认 /tmp/catos-tests-run-<时间戳>)
#   CATOS_INJECT_CASES(默认 "sack_t1 sack_t2 sack_t5 sack_t8 rst_l1 tw_recycle backlog_probe l3b_race dhcp_lease")
#   CATOS_DHCP_SCALE(dhcp_lease 租约分母, 默认 21600)
#   CATOS_DHCP_SCALE_ISO(预构建 LEASE_SCALE ISO 路径; 缺省现编到 $OUT/dhcp_scale.iso)
#   其余 qemu_run.sh / net_suite.py 的环境变量均透传生效。
# ============================================================================
set -u

DIR="$(cd "$(dirname "$0")" && pwd)"
REPO="${CATOS_REPO:-/home/wjqawa/osdev}"
ISO="${CATOS_ISO:-$REPO/os.iso}"
OUT="${CATOS_TEST_OUT:-/tmp/catos-tests-run-$(date +%Y%m%d-%H%M%S)}"
FINAL=0
mkdir -p "$OUT"
: > "$OUT/status.txt"

say() { printf '[run_all] %s\n' "$*"; }

# ---- [1/4] 语法门禁 ----------------------------------------------------------
say "[1/4] 语法自检"
SYNTAX_FAIL=0
for sh in "$DIR/qemu_run.sh" "$DIR/run_all.sh"; do
  if bash -n "$sh" 2>"$OUT/syntax_$(basename "$sh").err"; then
    say "  bash -n OK: $(basename "$sh")"
  else
    say "  bash -n FAIL: $sh"; cat "$OUT/syntax_$(basename "$sh").err"; SYNTAX_FAIL=1
  fi
done
for py in "$DIR/wire_lib.py" "$DIR/net_suite.py"; do
  if python3 -c "import ast,sys; ast.parse(open(sys.argv[1],encoding='utf-8').read())" "$py" 2>"$OUT/syntax_$(basename "$py").err"; then
    say "  ast.parse OK: $(basename "$py")"
  else
    say "  ast.parse FAIL: $py"; cat "$OUT/syntax_$(basename "$py").err"; SYNTAX_FAIL=1
  fi
  if python3 -m py_compile "$py" 2>>"$OUT/syntax_$(basename "$py").err"; then
    say "  py_compile OK: $(basename "$py")"
  else
    say "  py_compile FAIL: $py"; SYNTAX_FAIL=1
  fi
done
if [ $SYNTAX_FAIL -ne 0 ]; then say "语法门禁 FAILED"; exit 1; fi

# ---- QEMU 可用性 -------------------------------------------------------------
if ! command -v "${CATOS_QEMU:-qemu-system-i386}" >/dev/null 2>&1; then
  say "qemu-system-i386 不可用 -> [2/4][3/4] NOT_TESTED"
  echo "NOT_TESTED (no qemu)" >> "$OUT/status.txt"
  say "产物目录: $OUT"
  exit 0
fi
[ -f "$ISO" ] || { say "ISO 不存在: $ISO -> NOT_TESTED"; echo "NOT_TESTED (no iso)" >> "$OUT/status.txt"; exit 0; }

# ---- 单用例执行器（harness 重试 / 断言失败直通）------------------------------
run_case() { # $1=label, 其余=命令行
  local label="$1"; shift
  local attempt rc=99
  for attempt in 1 2 3; do
    say "  [$label] attempt=$attempt"
    "$@"
    rc=$?
    case $rc in
      0)
        say "  [$label] PASS (rc=0)"; echo "$label PASS rc=0" >> "$OUT/status.txt"; return 0 ;;
      2)
        say "  [$label] ASSERT FAIL (rc=2, 断言失败不重试)"; echo "$label FAIL rc=2" >> "$OUT/status.txt"; return 2 ;;
      3|4|5)
        say "  [$label] harness/env 故障 (rc=$rc)，重试"; sleep 2 ;;
      *)
        say "  [$label] unexpected rc=$rc"; echo "$label FAIL rc=$rc" >> "$OUT/status.txt"; return "$rc" ;;
    esac
  done
  say "  [$label] 重试耗尽 (最后 rc=$rc)"
  echo "$label HARNESS rc=$rc" >> "$OUT/status.txt"
  return "$rc"
}

# ---- [2/4] blackbox -----------------------------------------------------------
say "[2/4] blackbox 套件 (slirp hostfwd)"
BB_SERIAL="$OUT/blackbox.serial"
BB_JSON="$OUT/blackbox.json"
run_case blackbox \
  "$DIR/qemu_run.sh" --mode slirp --iso "$ISO" --serial "$BB_SERIAL" \
    --boot-timeout "${CATOS_BOOT_TIMEOUT:-150}" -- \
  python3 "$DIR/net_suite.py" --suite blackbox --serial "$BB_SERIAL" --json "$BB_JSON"
RC_BB=$?
[ $RC_BB -ne 0 ] && FINAL=1

# ---- [3/4] inject ---------------------------------------------------------------
say "[3/4] inject 套件 (socket-netdev, 每用例独立引导)"
# shellcheck disable=SC2206
INJECT_CASES_LIST=(${CATOS_INJECT_CASES:-sack_t1 sack_t2 sack_t5 sack_t8 rst_l1 tw_recycle backlog_probe l3b_race dhcp_lease})

# dhcp_lease 前置：LEASE_SCALE 专用 ISO（编译期宏，net_dhcp.c:41-58；
# 普通生产 ISO 租约 86400s 等不到 T1）。构建失败按 NOT_TESTED 处理，
# 不拖垮其余用例（对齐「QEMU 缺失 -> NOT_TESTED 退出 0」的既有口径）。
DHCP_OK=1
DHCP_SCALED_ISO="${CATOS_DHCP_SCALE_ISO:-$OUT/dhcp_scale.iso}"
if printf '%s\n' "${INJECT_CASES_LIST[@]}" | grep -qx "dhcp_lease"; then
  if [ -n "${CATOS_DHCP_SCALE_ISO:-}" ]; then
    if [ -f "$DHCP_SCALED_ISO" ]; then
      say "[3/4] dhcp_lease 使用预构建 scaled-iso: $DHCP_SCALED_ISO"
    else
      say "[3/4] 预构建 scaled-iso 不存在: $DHCP_SCALED_ISO -> inject:dhcp_lease NOT_TESTED"
      echo "inject:dhcp_lease NOT_TESTED (prebuilt scaled-iso missing)" >> "$OUT/status.txt"
      DHCP_OK=0
    fi
  else
    say "[3/4] 构建 LEASE_SCALE 专用 ISO (scale=${CATOS_DHCP_SCALE:-21600}, /tmp 副本树) ..."
    if python3 "$DIR/net_suite.py" \
         --build-dhcp-scale-iso "$REPO" "$DHCP_SCALED_ISO" \
         --scale "${CATOS_DHCP_SCALE:-21600}" \
         >"$OUT/dhcp_scale_build.log" 2>&1; then
      say "  scaled-iso 构建成功: $DHCP_SCALED_ISO"
    else
      say "  scaled-iso 构建失败 ($OUT/dhcp_scale_build.log 尾部) -> inject:dhcp_lease NOT_TESTED"
      tail -8 "$OUT/dhcp_scale_build.log" | sed 's/^/    /'
      echo "inject:dhcp_lease NOT_TESTED (scaled-iso build failed)" >> "$OUT/status.txt"
      DHCP_OK=0
    fi
  fi
fi

for c in "${INJECT_CASES_LIST[@]}"; do
  if [ "$c" = "dhcp_lease" ] && [ $DHCP_OK -ne 1 ]; then continue; fi
  S_SERIAL="$OUT/inject_${c}.serial"
  S_JSON="$OUT/inject_${c}.json"
  if [ "$c" = "dhcp_lease" ]; then
    # slirp 模式（需要 DHCP 服务端）+ scaled-iso。就绪门用串口标记而非
    # guest:80 端口——pristine HEAD 无 ring3 :80 探针（tests/README
    # 「尚未接线」），租约 ACK 才是本用例真正的前置条件。
    CATOS_SLIRP_READY_MARK="[NET] DHCP ACK ip=" \
    run_case "inject:$c" \
      "$DIR/qemu_run.sh" --mode slirp --iso "$DHCP_SCALED_ISO" --serial "$S_SERIAL" \
        --boot-timeout "${CATOS_BOOT_TIMEOUT:-120}" -- \
      python3 "$DIR/net_suite.py" --suite inject --case "$c" \
        --serial "$S_SERIAL" --json "$S_JSON"
    rc=$?
    [ $rc -ne 0 ] && FINAL=1
    continue
  fi
  run_case "inject:$c" \
    "$DIR/qemu_run.sh" --mode socket --iso "$ISO" --serial "$S_SERIAL" \
      --boot-timeout "${CATOS_BOOT_TIMEOUT:-90}" -- \
    python3 "$DIR/net_suite.py" --suite inject --case "$c" \
      --serial "$S_SERIAL" --json "$S_JSON"
  rc=$?
  [ $rc -ne 0 ] && FINAL=1
done

# ---- [4/4] 汇总 -----------------------------------------------------------------
say "[4/4] 汇总"
say "--- status ---"
cat "$OUT/status.txt"
say "--- json 报告摘要 ---"
python3 - "$OUT" <<'PYEOF'
import glob, json, os, sys
out = sys.argv[1]
rows = []
for jp in sorted(glob.glob(os.path.join(out, "*.json"))):
    try:
        d = json.load(open(jp, encoding="utf-8"))
    except Exception as e:
        rows.append((os.path.basename(jp), "JSON_ERROR", repr(e)))
        continue
    for cname, cd in (d.get("cases") or {}).items():
        rows.append((cname,
                     "%s passed / %s failed (exit=%s)"
                     % (cd.get("passed"), cd.get("failed"), cd.get("exit_code")),
                     os.path.basename(jp)))
print("%-28s %-34s %s" % ("CASE", "RESULT", "REPORT"))
for r in rows:
    print("%-28s %-34s %s" % r)
PYEOF

say "产物目录: $OUT （串口原文 *.serial / 结构化 *.json）"
if [ $FINAL -eq 0 ]; then
  say "RUN_ALL: ALL GREEN"
else
  say "RUN_ALL: HAS FAILURES"
fi
exit $FINAL
