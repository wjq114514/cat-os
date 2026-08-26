# userland/httpd —— Cat-OS 最小 HTTP 服务端（M0）

ring3 单进程阻塞循环 HTTP/1.0-ish 服务端。设计依据 `docs/MINIMAL_HTTPD_DESIGN.md`
（§6 L0 档：内嵌固定内容，无文件系统）；socket ABI 依据 `docs/SOCKET_API.md`；
syscall 封装范式照抄 `tests/user_sock_abi/user_sock_abi_test.c` 的 `sc5` 内联
`int $0x80`。

## 行为

- 监听 **guest TCP :7000**（回归设计端口，2026-08-26：曾误绑 :80 与 blackbox
  ring3 回显探针冲突——探针同样 bind(:80)，httpd 抢答致 roundtrip 收到 HTTP、
  探针 bind 失败空转致 TCP MULTI 超时）。与 ring3 UDP 回显探针的 UDP:7000
  **不冲突**：内核 UDP/TCP 分表——UDP 槽位 `udp_socks[]`（net.c:342-344，
  查表 `udp_sock_by_port()`），TCP 槽位 `tcp_conns[]`/`tcp_socks[]`
  （net.c:743-745，listen 查表 `tcp_conn_find_listen()`）；bind 系统调用按
  socket 类型分流（net.c:918 SOCK_UDP_UNBOUND 分支只触 udp_socks），
  同端口号跨协议互不可见。
- 只解析请求行；**非 GET → 405**，畸形行/路径非 `/` 开头/含 `..`/长度>256 → 400，
  其余一律 **200 text/plain**，正文固定 `hello from cat-os httpd`。
- 响应恒带 `Content-Length` + `Connection: close`，发完即 nr=28 close。
- 异常路径（recv<=0、EAGAIN 超预算、send<0/超限）：关连接回 accept，主循环永不退出。
- banner 与逐连接访问日志走 `open("/dev/console")`（失败回退 fd=1）→ 串口可观察。

## 使用的 syscall 编号

| nr | 用途 |
|----|------|
| 1  | write（banner/日志 → /dev/console） |
| 5  | open("/dev/console", O_WRONLY=1)；失败返回 -1（非 errno），程序回退 fd=1 |
| 12 | exit（仅 socket/bind/listen 初始化致命失败） |
| 20 | socket(SOCK_STREAM=1) |
| 21 | bind(fd, 7000) |
| 22 | listen(fd, 16) |
| 23 | accept(fd)；空队列 -EAGAIN（忙等软化：每 64 次 EAGAIN 插一段短 spin，Y6' 缺口） |
| 26 | send（收缩式部分写：游标推进 + 返 0 重试上限，宁截断不死循环） |
| 27 | recv（0=EOF；-EAGAIN 预算内重试防慢速客户端占死唯一服务槽） |
| 28 | close（socket 关闭唯一合法编号；绝不用 nr=6/nr=3 关 socket —— L8 别名雷区） |

## 尚未可用的依赖（接线缺口）

1. **exec(nr=11) 加载路径**：当前 sys_exec 嵌入分支仅认 "/bin/shell"，本 ELF 无触发
   路径。接线前本目录 = ABI 规约 + 编译期自检产物，运行时 NOT_TESTED。
2. ring3 无 yield/nanosleep（设计稿缺口 Y6'）：accept 空转为忙等软化实现。
3. house ABI accept 无对端地址出参：访问日志只记 fd/path/status。

## 编译自检（已在副本树验证通过）

```
gcc -m32 -march=i486 -ffreestanding -fno-pic -fsyntax-only \
    -I. -Ilibc/include userland/httpd/httpd.c        # SYNTAX_OK
# 另通过：-Wall -Wextra 零警告；ld -m elf_i386 -nostdlib -static -e _start \
#   -Ttext=0x400000 可产出干净 ELF32（布局契约同 shell_user.elf）
```

## 接线需求清单（给 orchestrator）

1. Makefile 增加 `httpd.o / httpd.elf / httpd.bin / httpd_bin.h` 目标
   （模式照抄 sock_abi 四件套；CFLAGS 同 SOCKABI_CFLAGS 族，LDFLAGS 同 SHELL_LDFLAGS）。
2. 加载路径二选一：
   - kernel.c 内嵌 `elf_load(httpd_elf)` 引导直启（改 kernel.c 内嵌逻辑），或
   - 扩展 syscall.c sys_exec 白名单注册路径（如 "/bin/httpd" → weak 符号 `httpd_elf/_len`）。
3. QEMU 启动参数：curl 验收走 `make run-httpd`（hostfwd tcp:127.0.0.1:18082 ->
   guest:7000）。宿主端口不用 18081——它已被 tests/qemu_run.sh 的
   P_TCP81(18081→guest:81 内核 banner 服务) 占用，blackbox tcp81:* 断言依赖；
   qemu_run.sh 属测试 harness 领地，未加此 forward（后续由 harness owner 补
   `hostfwd=tcp:127.0.0.1:${P_HTTPD:-18082}-:7000` 即可并入统一入口）。

## 验收步骤草案

```bash
# 终端 A：make run-httpd  # 等串口出现 "[HTTPD] listening on port 7000 ..."
# 终端 B：
curl -s http://127.0.0.1:18082/
#   预期输出：hello from cat-os httpd
curl -s -o /dev/null -w '%{http_code}\n' -X POST http://127.0.0.1:18082/
#   预期输出：405
printf 'GARBAGE\r\n\r\n' | nc -q1 127.0.0.1 18082 | head -1
#   预期输出：HTTP/1.0 400 Bad Request
for i in $(seq 1 100); do curl -s http://127.0.0.1:18082/ >/dev/null; done
#   串口无 panic、无 fd 泄漏征兆（EMFILE）
```

串口预期可见 `[HTTPD] cat-os minimal httpd starting ...` banner 与逐连接
`[HTTPD] conn fd=N st=200 path=/ bytes=B` 日志。
