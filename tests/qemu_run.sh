#!/usr/bin/env bash
# ============================================================================
# Cat-OS tests/qemu_run.sh —— 统一 QEMU 启动封装（code10 正式化入库）
#
# 来源：/tmp/cat-os-tests/qemu_run.sh（slirp 黑盒）+ /tmp/run_sack_edge.sh 与
# /tmp/ox_run_lifecycle.sh（socket-netdev 注入）。原型保留在 /tmp 供 code4 复用。
#
# 用法:
#   qemu_run.sh [--mode slirp|socket] [--iso PATH] [--serial PATH]
#               [--boot-timeout SEC] [--hold SEC] [--keep] [--qemu-bin BIN]
#               [-- cmd arg...]        # 就绪后执行的命令；SERIAL_LOG 等经环境透传
#
# 行为:
#   启动 QEMU（本 shell 后台子进程 + trap 兜底回收）→ 等待就绪标记 →
#   可选 --hold N 秒 → 执行 cmd（可选，退出码透传）→ 回收。
#   无 cmd 时即冒烟模式：boot + hold 后以 0 退出。
#
# 就绪判定:
#   slirp : hostfwd 端口（默认 18080 -> guest:80）TCP 可连（与原 ext_socktest
#           的 stage_boot 同口径；slirp DHCP 成功不会打印 fallback static）
#   socket: 串口出现 "fallback static"（无 DHCP 服务，内核走静态回退）
#
# 退出码:
#   0 = 成功（含 cmd rc=0）；2 = cmd 断言失败（net_suite.py 语义透传）
#   3 = QEMU 启动失败；4 = 引导超时；64 = 用法错误
#
# 环境变量（均可被 CLI 覆盖）:
#   CATOS_ISO CATOS_SERIAL CATOS_MODE CATOS_BOOT_TIMEOUT CATOS_QEMU
#   CATOS_MEM(默认128M) CATOS_WIRE_PORT(默认12345)
#   hostfwd 端口: P_TCP80(18080) P_TCP81(18081) P_DEAD_TCP(18099)
#                 P_UDP7(17007) P_UDP7000(17000) P_DEAD_UDP(16969)
#
# 本脚本不写仓库内任何现有文件；串口日志默认落在脚本目录或调用方指定路径。
# ============================================================================
set -u

DIR="$(cd "$(dirname "$0")" && pwd)"
MODE="${CATOS_MODE:-slirp}"
ISO="${CATOS_ISO:-/home/wjqawa/osdev/os.iso}"
SERIAL="${CATOS_SERIAL:-$DIR/serial.log}"
BOOT_TIMEOUT="${CATOS_BOOT_TIMEOUT:-120}"
QEMU_BIN="${CATOS_QEMU:-qemu-system-i386}"
MEM="${CATOS_MEM:-128M}"
WIRE_PORT="${CATOS_WIRE_PORT:-12345}"
HOLD=0
KEEP=0
CMD=()

while [ $# -gt 0 ]; do
  case "$1" in
    --mode) MODE="$2"; shift 2 ;;
    --iso) ISO="$2"; shift 2 ;;
    --serial) SERIAL="$2"; shift 2 ;;
    --boot-timeout) BOOT_TIMEOUT="$2"; shift 2 ;;
    --hold) HOLD="$2"; shift 2 ;;
    --keep) KEEP=1; shift ;;
    --qemu-bin) QEMU_BIN="$2"; shift 2 ;;
    --) shift; CMD=("$@"); break ;;
    *) echo "[qemu_run] unknown option: $1" >&2; exit 64 ;;
  esac
done

case "$MODE" in
  slirp|socket) ;;
  *) echo "[qemu_run] bad --mode: $MODE (slirp|socket)" >&2; exit 64 ;;
esac

port_busy() { (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; }

command -v "$QEMU_BIN" >/dev/null 2>&1 || { echo "[qemu_run] $QEMU_BIN not found"; exit 3; }
[ -f "$ISO" ] || { echo "[qemu_run] ISO not found: $ISO"; exit 3; }
mkdir -p "$(dirname "$SERIAL")"
: > "$SERIAL"

# ---- 回收本封装家族的历史残留实例（-name tag 匹配，不误伤其他任务的 QEMU）----
TAG="catos-test-$$"
if pgrep -f "catos-test-" >/dev/null 2>&1; then
  pkill -f "catos-test-" 2>/dev/null || true
  sleep 1
fi
if [ "$MODE" = socket ]; then
  # 等待 wire 端口释放（最多 ~15s），避免 socket listen 冲突
  for _ in $(seq 1 15); do
    if port_busy "$WIRE_PORT"; then sleep 1; else break; fi
  done
fi

# ---- 组装网络参数 -----------------------------------------------------------
NETARGS=()
if [ "$MODE" = slirp ]; then
  P_TCP80="${P_TCP80:-18080}"; P_TCP81="${P_TCP81:-18081}"; P_DEAD_TCP="${P_DEAD_TCP:-18099}"
  P_UDP7="${P_UDP7:-17007}"; P_UDP7000="${P_UDP7000:-17000}"; P_DEAD_UDP="${P_DEAD_UDP:-16969}"
  NETARGS=(-netdev "user,id=net0,hostfwd=tcp:127.0.0.1:${P_TCP80}-:80,hostfwd=tcp:127.0.0.1:${P_TCP81}-:81,hostfwd=tcp:127.0.0.1:${P_DEAD_TCP}-:9999,hostfwd=udp:127.0.0.1:${P_UDP7}-:7,hostfwd=udp:127.0.0.1:${P_UDP7000}-:7000,hostfwd=udp:127.0.0.1:${P_DEAD_UDP}-:16969" -device e1000,netdev=net0)
else
  NETARGS=(-netdev "socket,id=net0,listen=127.0.0.1:${WIRE_PORT}" -device e1000,netdev=net0)
fi

echo "[qemu_run] mode=$MODE iso=$ISO serial=$SERIAL"
"$QEMU_BIN" -m "$MEM" -display none -no-reboot -no-shutdown \
  -serial "file:$SERIAL" -name "$TAG" \
  "${NETARGS[@]}" -cdrom "$ISO" &
QPID=$!

cleanup() {
  [ "$KEEP" = 1 ] && return 0
  kill "$QPID" 2>/dev/null || true
  wait "$QPID" 2>/dev/null || true
}
trap 'cleanup' EXIT
trap 'kill "$QPID" 2>/dev/null; exit 130' INT TERM

# ---- 就绪等待 ----------------------------------------------------------------
DEADLINE=$(( $(date +%s) + BOOT_TIMEOUT ))
if [ "$MODE" = slirp ]; then
  echo "[qemu_run] waiting guest:80 via hostfwd 127.0.0.1:${P_TCP80} (<= ${BOOT_TIMEOUT}s) ..."
  while :; do
    if port_busy "$P_TCP80"; then break; fi
    kill -0 "$QPID" 2>/dev/null || { echo "[qemu_run] QEMU died during boot"; exit 3; }
    if [ "$(date +%s)" -ge "$DEADLINE" ]; then echo "[qemu_run] BOOT TIMEOUT"; exit 4; fi
    sleep 0.5
  done
else
  echo "[qemu_run] waiting 'fallback static' in serial (<= ${BOOT_TIMEOUT}s) ..."
  while :; do
    grep -q "fallback static" "$SERIAL" 2>/dev/null && break
    kill -0 "$QPID" 2>/dev/null || { echo "[qemu_run] QEMU died during boot"; exit 3; }
    if [ "$(date +%s)" -ge "$DEADLINE" ]; then echo "[qemu_run] BOOT TIMEOUT"; exit 4; fi
    sleep 0.5
  done
fi
echo "[qemu_run] guest ready."
sleep 1

# ---- 可选 hold（冒烟观察窗）---------------------------------------------------
if [ "$HOLD" -gt 0 ]; then
  echo "[qemu_run] hold ${HOLD}s ..."
  sleep "$HOLD"
fi

# ---- 可选执行测试命令 ---------------------------------------------------------
RC=0
if [ "${#CMD[@]}" -gt 0 ]; then
  SERIAL_LOG="$SERIAL"
  export SERIAL_LOG
  CATOS_WIRE_PORT="$WIRE_PORT"
  export CATOS_WIRE_PORT
  CATOS_GUEST_IP="10.0.2.15"
  export CATOS_GUEST_IP
  echo "[qemu_run] exec: ${CMD[*]}"
  "${CMD[@]}"
  RC=$?
  echo "[qemu_run] cmd exit=$RC"
fi

echo "QEMU_RUN_RESULT rc=$RC mode=$MODE iso=$ISO serial=$SERIAL"
exit "$RC"
