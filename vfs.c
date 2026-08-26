#include "vfs.h"
#include "kernel.h"
#include "keyboard.h"
#include "kbdwait.h"
#include "paging.h"
#include <stdint.h>
/* ── L2 fd 分配策略（code7 改动，依据见各函数注释）──────────────────────
 * fds[] 为文件(FILE_VFS)与 socket(FILE_SOCKET) 共享的描述符表，容量
 * VFS_MAX_FD。分配统一走 vfs_fd_alloc()：自 fd=0 起取最低空闲槽位；
 * close 后槽位指针清零即可被后续分配复用（闭包保证）。
 * fd 0/1/2 由 vfs_init 安装 stdin(/dev/kbd)/stdout(/dev/console)/stderr
 * (/dev/console) 占位，保留 POSIX 标准流语义；若未来某 std 未安装，
 * 分配器自动回落到含 0-2 在内的最低空闲槽（不硬性保留）。 */
static file_t *fds[VFS_MAX_FD]; static uint32_t rnd=0x12345678;
static int nullread(struct file*f,void*b,uint32_t n){(void)f;(void)b;(void)n;return 0;} static int nullwrite(struct file*f,const void*b,uint32_t n){(void)f;(void)b;return (int)n;}
static int conwrite(struct file*f,const void*b,uint32_t n){(void)f;const char*p=b;for(uint32_t i=0;i<n;i++){char c=p[i];if(c) {char s[2]={c,0};kputs(s);}}return n;}
/* ── /dev/kbd 多读者策略（2026-08-26 明确化，最小改动=零行为变更）──────────
 * 所有打开的 /dev/kbd fd 共享 keyboard.c 的同一 IRQ1 环形缓冲：
 *   1) 每字节恰交付给一名读者 —— 先轮询到者先得（FCFS），无独占/排队/唤醒
 *      机制（本内核无 sleep/wakeup 原语，见 keyboard.c 读语义注记）；
 *   2) 各读者的 kbdwait 阻塞窗（KBD_BLOCK_TIMEOUT_MS，墙钟 tick 计费）
 *      相互独立，互不占坑：A 读者阻塞不影响 B 读者同刻读到新键；
 *   3) 现网读者面：vfs_init 预装的 stdin(fd0)=shell REPL 常驻轮询 +
 *      enter_usermode() 探针握手期临时第二 fd（读完即 close 收敛为单读者）；
 *      注入键序依赖「探针 kbd 握手先于 shell 独占读」的时序契约。
 * 不选「后开者拒绝」（会杀死探针握手——stdin fd0 先开）与「每读者队列」
 * （需 file_t 侧 per-fd 缓冲 + 派发策略，超出病灶最小集）。 */
static int kread(struct file*f,void*b,uint32_t n){(void)f;uint8_t*p=b;uint32_t i=0;if(!n)return 0;int c=keyboard_getchar_blocking(KBD_BLOCK_TIMEOUT_MS);if(c<0)return 0;p[i++]=(uint8_t)c;while(i<n){c=keyboard_getchar();if(c<0)break;p[i++]=(uint8_t)c;}return (int)i;}
static int zread(struct file*f,void*b,uint32_t n){(void)f;for(uint32_t i=0;i<n;i++)((uint8_t*)b)[i]=0;return n;} static int urread(struct file*f,void*b,uint32_t n){(void)f;for(uint32_t i=0;i<n;i++){rnd=rnd*1664525u+1013904223u;((uint8_t*)b)[i]=(uint8_t)(rnd>>24);}return n;}
static const file_ops_t noops={nullread,nullwrite,0},conops={0,conwrite,0},kop={kread,0,0},zops={zread,0,0},uops={urread,0,0};
static inode_t nodes[]={{VFS_CHR,0,"/dev/null",&noops,0},{VFS_CHR,0,"/dev/console",&conops,0},{VFS_CHR,0,"/dev/kbd",&kop,0},{VFS_CHR,0,"/dev/zero",&zops,0},{VFS_CHR,0,"/dev/urandom",&uops,0}};
/* L2 共享分配器：线性扫描最低空闲槽位并占用。
 * 依据：linux-ref fs/file.c:569 alloc_fd()（start 起 find_next_fd 取最低空闲位）
 *   及 fs/file.c:616 __get_unused_fd_flags()→alloc_fd(0,nofile,flags)——扫描
 *   自 0 开始；POSIX open(2)：成功返回"lowest-numbered unused file descriptor"。
 * 复用闭包：close 路径把 fds[fd] 清零（对照 linux-ref fs/file.c __put_unused_fd
 *   归还位图槽位），本函数下次扫描即可重新命中该槽。
 * 上限安全：越界不可能（循环受 VFS_MAX_FD 约束）；耗尽返回 -1，由调用方翻译为
 *   各自契约错误码（socket 层 -EMFILE/-24，open 层 -1，与改动前一致）。 */
static int vfs_fd_alloc(file_kind_t kind,uint32_t fl,inode_t *ino,void *private){
  static file_t fs[VFS_MAX_FD];
  for(int fd=0;fd<VFS_MAX_FD;fd++)if(!fds[fd]){fs[fd]=(file_t){ino,0,fl,kind,private};fds[fd]=&fs[fd];return fd;}
  return -1;
}
void vfs_init(void){kputs("[OK] VFS mounted /dev (devfs)\n");
  /* L2: 安装标准流占住 fd 0/1/2（stdin/stdout/stderr 语义保留）。
   * 之后动态分配自然从最低空闲槽(=3)起，兼容既有对「首个 open 得 fd 3」的依赖
   * （usermode.c ring3 探针硬编码 fd=3；interrupts.c:31 演示日志）；若某 std 未
   * 装，分配器按最低空闲语义回落到 0-2。 */
  int si=vfs_open("/dev/kbd",O_RDONLY);     /* fd 0 = stdin（可读；阻塞读带超时） */
  int so=vfs_open("/dev/console",O_WRONLY); /* fd 1 = stdout */
  int se=vfs_open("/dev/console",O_WRONLY); /* fd 2 = stderr */
  if(si!=0||so!=1||se!=2)kputs("[WARN] VFS std stream install mismatch\n");
  for(unsigned i=0;i<3;i++){int fd=vfs_open(nodes[i].name,O_RDWR);if(fd>=0){kputs("[OK] VFS dev node open test ");kputs(nodes[i].name);kputs("\n");vfs_close(fd);}}
  /* L2 自检：open/close 反复分配，验证「std 占 0-2 后从最低空闲起 + 释放复用 +
   * kind 隔离 + 边界」。结果经串口 [VFS-FD] 标记输出（工具层断言用）。 */
  {
    int a=vfs_open("/dev/null",O_RDWR);          /* 期望 3（0-2 已被 std 占用） */
    int b=vfs_open("/dev/null",O_RDWR);          /* 期望 4 */
    int c=vfs_open("/dev/null",O_RDWR);          /* 期望 5 */
    int ok=(a==3&&b==4&&c==5);
    ok&=(vfs_close(b)==0);                       /* 归还 4 号槽 */
    int d=vfs_open("/dev/console",O_WRONLY);
    ok&=(d==4);                                  /* 最低空闲复用：新开落回 4 */
    int e=vfs_socket_install((void*)1);          /* socket 与文件共用同一分配器 */
    ok&=(e==6&&vfs_close(e)==-9);                /* kind 隔离：vfs_close 拒收 socket */
    ok&=(vfs_socket_close(e)==0);                /* socket 专属关闭归还槽位 */
    ok&=(vfs_close(a)==0);                       /* 归还 3 号槽 */
    int f=vfs_open("/dev/null",O_RDWR);
    ok&=(f==3);                                  /* 二次复用：新开落回 3 */
    ok&=(vfs_close(c)==0&&vfs_close(d)==0&&vfs_close(f)==0);
    ok&=(vfs_close(-1)==-9&&vfs_close(VFS_MAX_FD)==-9&&vfs_close(f)==-9); /* 边界+双关 */
    kputs(ok?"[VFS-FD] selftest PASS a=3 b=4 c=5 d=4 e=6 f=3\n"
            :"[VFS-FD] selftest FAIL\n");
  }
}
/* L2：分配改经 vfs_fd_alloc（原实现内联 for(fd=3..) 且永久跳过 0-2）。 */
int vfs_open(const char*p,uint32_t fl){for(unsigned i=0;i<sizeof(nodes)/sizeof(nodes[0]);i++){const char*a=p,*b=nodes[i].name;while(*a&&*a==*b){a++;b++;}if(!*a&&!*b)return vfs_fd_alloc(FILE_VFS,fl,&nodes[i],0);}return -1;}
int vfs_read(int fd,void*b,uint32_t n){if(fd<0||fd>=VFS_MAX_FD||!fds[fd]||fds[fd]->kind!=FILE_VFS||!fds[fd]->inode->ops->read)return -9;if(!user_access_ok((uintptr_t)b,n,1))return -14;return fds[fd]->inode->ops->read(fds[fd],b,n);}int vfs_write(int fd,const void*b,uint32_t n){if(!user_access_ok((uintptr_t)b,n,0))return -14;if(fd<0||fd>=VFS_MAX_FD||!fds[fd]||fds[fd]->kind!=FILE_VFS||!fds[fd]->inode->ops->write)return -9;return fds[fd]->inode->ops->write(fds[fd],b,n);}
/* L2：放开 fd<3 拒绝（0-2 现为合法 std 槽位，须可关闭归还）；边界/kind 校验保持：
 * 负值/越界/空槽 → -EBADF(-9)；FILE_SOCKET → -EBADF（socket 只能经 nr==28 或
 * vfs_socket_close 关闭；L8 的 nr==3 close 别名已于 2026-08-26 拆除改挂 read，
 * 见 vfs_syscall 注记）。 */
int vfs_close(int fd){if(fd<0||fd>=VFS_MAX_FD||!fds[fd])return -9;if(fds[fd]->kind!=FILE_VFS)return -9;fds[fd]=0;return 0;}
/* L2：socket 安装走共享分配器（原 for(fd=3..) 内联版）；耗尽契约保持 -EMFILE(-24)。 */
int vfs_socket_install(void *sock){int fd=vfs_fd_alloc(FILE_SOCKET,O_RDWR,0,sock);return fd<0?-24:fd;}
void *vfs_socket_get(int fd){if(fd<0||fd>=VFS_MAX_FD||!fds[fd]||fds[fd]->kind!=FILE_SOCKET)return 0;return fds[fd]->private;}
int vfs_socket_close(int fd){if(!vfs_socket_get(fd))return -9;fds[fd]=0;return 0;}
int vfs_fd_exists(int fd){return fd>=0&&fd<VFS_MAX_FD&&fds[fd]!=0;}
int32_t vfs_syscall(uint32_t nr,const uint32_t*a){
  /* ── L8 别名拆除（2026-08-26，NGINX_GAP_ANALYSIS §5 D4/硬阻塞项落地）──────
   * 历史动机（考古）：L2 之前 fd 分配器内联 for(fd=3..) 永久跳过 0-2，「3 号=
   *   首个可用 fd」时代留下的便捷 close 别名（HEAD=0d4b583 时 nr==6 与 nr==3
   *   分支体逐字等价，构成双重别名）。
   * 本次变更：nr==3 不再走 vfs_close，改挂 read 路径（与 nr==0 同一 vfs_read）。
   *   - 编号对齐依据 linux-ref arch/x86/entry/syscalls/syscall_32.tbl：
   *     Linux x86-32 为 3=read/4=write/5=open/6=close；本内核 VFS ABI 为
   *     0=read/1=write/5=open/6=close —— 5/6 本与 Linux 一致，nr==3 改挂 read 后，
   *     按 Linux ABI 写的 ring3 代码 read(fd=3) 不再静默关 fd（地雷排除）。
   *   - close 语义不变：nr==6 关普通文件；socket 唯一关闭号仍是 nr==28
   *     （CATOS_SYS_CLOSE，socket-aware 路径）；vfs_close 对 FILE_SOCKET 一律
   *     -EBADF 的 kind 隔离保持不变。
   *   - 兼容性核实：全仓 grep 无任何 ring3 调用方使用 nr==3（shell_user.c/
   *     usermode.c/libc/userland/httpd.c 均守 nr==28 或 nr==6），移除零破坏；
   *     sock_abi 套件新增 S7s-S7v 断言锁定新语义（tests/README.md 有变更记录）。 */
  if(nr==5){if(!user_access_ok(a[0],1,0))return -14;uint32_t sl=1;while(sl<256&&user_access_ok(a[0]+sl,1,0)&&((char*)a[0])[sl]!=0)sl++;if(sl>=256)return -14;return vfs_open((const char*)a[0],a[1]);}if(nr==6)return vfs_close(a[0]);if(nr==0||nr==3)return vfs_read(a[0],(void*)a[1],a[2]);if(nr==1)return vfs_write(a[0],(const void*)a[1],a[2]);return -38;}
