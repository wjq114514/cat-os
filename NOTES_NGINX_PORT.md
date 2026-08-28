# Cat-OS nginx 移植笔记

## 已完成的关键修复

### 1. dup2() 桩修复 (libc/src/posix_stubs.c)
- **问题**: `dup2` 硬编码返回 -1，导致 `ngx_log_redirect_stderr` 失败
- **修复**: 将 `dup2` 改为调用内核 `nr=63` (`vfs_dup2`)
- **验证**: `make libc-test` 通过，fresh QEMU 中 nginx 启动并成功返回 HTTP 200

### 2. master_process off 强制单进程 (二进制补丁)
- **问题**: `ccf->master` 默认为 1，导致进入 `ngx_master_process_cycle` (fork 失败)
- **修复**: `build-nginx.sh` 按唯一指令上下文定位并 NOP 掉 6 字节 `jne` 跳转
- **效果**: 强制走 `ngx_single_process_cycle`

### 3. vfs_fstat 文件大小回退 (fs/vfs.c)
- **修复**: 当 inode size 为 0 时回退到 `fatfh->de.size`

### 4. CATOS_HEAP_POOL_BYTES 增加到 512KB (libc/src/stdlib.c)
- **原值**: 64KB (nginx 启动阶段的配置/模块分配不够)
- **新值**: 512KB (满足 nginx cycle pool 分配)

### 5. nginx accept sockaddr 填充 (kernel/syscall.c + net/net.c)
- **问题**: cat-OS accept 不填充远端地址，导致 `ngx_sock_ntop` 失败
- **修复**:
  - libc `accept` 传递 `addr` 和 `addrlen` 指针到内核
  - 内核 accept 路径填充 `struct sockaddr_in` (peer_ip/peer_port)
  - 新增 `net_socket_peer()` helper

### 6. tcp_close 重置 accepted 标志 (net/net_tcp.c)
- **问题**: close 后 `accepted=true` 导致后续 accept 找不到同一连接
- **修复**: `tcp_close` 中重置 `c->accepted = false`

### 7. nginx_harness.c 固定 FAT16 配置路径
- **改动**: `_start` 调用 `main(3, {"nginx", "-c", "/mnt/fat/CONF/NGINX.CNF"})`
- **原因**: nginx 配置和静态站点由 FAT16 镜像提供，显式路径避免依赖当前工作目录

### 8. poll 模块 index 修复 (nginx-1.26.2/src/event/modules/ngx_poll_module.c)
- **问题**: `ev->index` 初始值为垃圾值 (`-791621424`)，导致 poll 不能正确添加新 fd
- **修复**: 在 `ngx_poll_add_event` 中强制重置 partner 的 invalid index

## 当前状态 (截至 2026-08-28 fresh QEMU r4)

✅ shell 启动内嵌 nginx ELF
✅ FAT16 配置盘挂载并读取 `/mnt/fat/CONF/NGINX.CNF`
✅ nginx 监听 8080 端口并驱动 HTTP 请求
✅ `/` 返回 200 + `Cat-OS nginx works`
✅ `/missing` 返回 404
✅ shell `netstat` 输出网络计数器
✅ shell `ping 10.0.2.2` 收到 reply
✅ 重复执行 `nginx` 返回 `already started`
✅ 串口无 `DBG`、`[SC]`、`[PT]`、`[SC-DUP2]`、`[TRAP]`、`[SMP]` 临时诊断标记

最终 fresh 证据：
- 串口：`/tmp/catos-nginx-rebuild-20260828r4.serial`
- 判定：`/tmp/catos-nginx-rebuild-20260828r4.result`（`OVERALL: PASS`）

## 构建/测试命令

```bash
# 独立重建 libc 并运行宿主断言
make libc-clean && make libc-test
# 构建 nginx、应用 Cat-OS 配置头、NOP 单进程 master 分支并生成 nginx_bin.h
./build-nginx.sh
# 构建内核和 ISO
make clean && make -j2

# 测试
qemu-system-x86_64 -cdrom os.iso -m 128M -display none \
    -serial file:/tmp/catos-nginx-rebuild-20260828r4.serial \
    -no-reboot -no-shutdown \
    -qmp unix:/tmp/catos-nginx-rebuild-20260828r4.qmp,server=on,wait=off \
    -netdev user,id=net0,hostfwd=tcp:127.0.0.1:18098-:8080 \
    -device e1000,netdev=net0 \
    -drive file=/tmp/catos-nginx-config-20260828.img,format=raw,if=ide,index=0,media=disk -boot d
```

## 关键文件清单

- `libc/src/posix_stubs.c` - POSIX/网络包装（含 dup2、accept、poll、writev）
- `libc/src/stdlib.c` - CATOS_HEAP_POOL_BYTES=512KB
- `kernel/syscall.c` - accept 填充 sockaddr
- `net/net_tcp.c` - tcp_close 重置 accepted
- `net/net.c` - net_socket_peer helper
- `nginx-1.26.2/src/event/modules/ngx_poll_module.c` - poll index 修复
- `nginx-epoll-stub.c` - 禁用 epoll 时的链接符号
- `nginx-shim/` - nginx POSIX 头文件兼容层
- `nginx_harness.c` - _start 入口
- `build-nginx.py`、`build-nginx.sh` - nginx 构建、补丁和嵌入脚本
- `Makefile` - ISO 构建

## 当前边界

1. nginx 当前按 `master_process off` 单进程模式运行；master/worker、fork 和信号生命周期不在本次最小闭环内。
2. HTTP 服务启动后需要等待其事件循环完成初始化；最终验收脚本对 guest:8080 使用有界重试。
