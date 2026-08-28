#include "vfs.h"
#include "kernel.h"
#include "keyboard.h"
#include "kbdwait.h"
#include "paging.h"
#include "fat16.h"
/* ── M-B0 领地注记：fat16.c 以 #include 并入本翻译单元 ────────────────────
 * 本轮任务领地仅 ide/vfs/fat16 六文件，Makefile（OBJS 列表）不在其列，
 * 无法追加 fat16.o；故以单翻译单元方式并入（fat16.c 全部内部符号为
 * static，无命名泄漏）。遗留接线项：Makefile OBJS 增加 fat16.o 后删除
 * 本 include 即可还原标准布局。 */
#include "fat16.c"
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
static int kread(struct file*f,void*b,uint32_t n){uint8_t*p=b;uint32_t i=0;if(!n)return 0;int c=(f&&((f->flags&O_NONBLOCK)!=0))?keyboard_getchar():keyboard_getchar_blocking(KBD_BLOCK_TIMEOUT_MS);if(c<0)return 0;p[i++]=(uint8_t)c;while(i<n){c=keyboard_getchar();if(c<0)break;p[i++]=(uint8_t)c;}return (int)i;}
static int zread(struct file*f,void*b,uint32_t n){(void)f;for(uint32_t i=0;i<n;i++)((uint8_t*)b)[i]=0;return n;} static int urread(struct file*f,void*b,uint32_t n){(void)f;for(uint32_t i=0;i<n;i++){rnd=rnd*1664525u+1013904223u;((uint8_t*)b)[i]=(uint8_t)(rnd>>24);}return n;}
static const file_ops_t noops={nullread,nullwrite,0},conops={0,conwrite,0},kop={kread,0,0},zops={zread,0,0},uops={urread,0,0};
static inode_t nodes[]={{VFS_CHR,0,"/dev/null",&noops,0},{VFS_CHR,0,"/dev/console",&conops,0},{VFS_CHR,0,"/dev/kbd",&kop,0},{VFS_CHR,0,"/dev/zero",&zops,0},{VFS_CHR,0,"/dev/urandom",&uops,0}};
/* ── M-B0 块设备注册表（仿 chr 静态节点模式：注册即占一 inode 槽）──────────
 * 与 chr 的差异仅在填充时机 —— chr 编译期静态初始化，blk 由驱动（ide.c
 * mbr_scan）在 vfs_init 之前经 vfs_blk_register 运行期追加。节点 file_ops
 * 用 no-op 占位（read=EOF/write 拒绝）：raw 块 IO 走 blk_ops_t 内核直调，
 * fd 化访问留待 nr=36 接线时再定语义。 */
static const blk_ops_t *g_blks_ops[VFS_BLK_MAX]; static void *g_blks_drv[VFS_BLK_MAX];
static inode_t g_blks_ino[VFS_BLK_MAX]; static int g_blkn;
static int blknop_read(struct file*f,void*b,uint32_t n){(void)f;(void)b;(void)n;return 0;}
static const file_ops_t blknops={blknop_read,0,0};
int vfs_blk_register(const char*name,const blk_ops_t*ops,void*drv){
  if(!name||!ops||g_blkn>=VFS_BLK_MAX)return -1;
  g_blks_ops[g_blkn]=ops;g_blks_drv[g_blkn]=drv;
  g_blks_ino[g_blkn]=(inode_t){VFS_BLK,0,name,&blknops,0};
  return g_blkn++;}
int vfs_blk_count(void){return g_blkn;}
inode_t *vfs_blk_get(int i){return(i>=0&&i<g_blkn)?&g_blks_ino[i]:0;}
void *vfs_blk_drv(int i){return(i>=0&&i<g_blkn)?g_blks_drv[i]:0;}
/* ── M-B0 FAT16 只读挂载：路径决策 = /mnt/fat 前缀路由 ────────────────────
 * 备选两案：「独立目录节点」需为每个 FAT 目录维护动态 inode 树 + 父子
 * 解析，代价远高于「前缀路由」——后者只需在 vfs_open 尾部加一个字符串
 * 前缀分支，fd 层复用既有 FILE_VFS 通道（file_t.pos/private 全部现成）。
 * 故取前缀路由（fs-design 两可方案中实现代价最小者）。语义：
 *   open("/mnt/fat/<8.3 路径>") → fat16_lookup 解析 → 只读 fd；
 *   write 一律拒绝（只读先行）；根目录本身不可 open（无目录 fd 语义）。
 * 单挂载点（首个通过 BPB 校验的块设备），多卷 mount 表留待 VFS 后续。 */
#define FAT_OPEN_MAX 8
typedef struct{int used;fat16_dirent_t de;} fatfh_t;
static fatfh_t fatfh[FAT_OPEN_MAX]; static void *g_fatmnt;
static int fat_read(struct file*f,void*b,uint32_t n){
  fatfh_t*h=f->private;if(!h)return -9;
  int r=fat16_read_file(g_fatmnt,&h->de,f->pos,b,n);
  if(r>0)f->pos+=(uint32_t)r;
  return r;}                                      /* pos 由本 op 自管（chr 族同例） */
static int fat_close(struct file*f){fatfh_t*h=f->private;if(h)h->used=0;return 0;}
static const file_ops_t fatfops={fat_read,0,fat_close};
static inode_t fattpl={VFS_REG,0,"/mnt/fat",&fatfops,0}; /* 模板 inode；真实 size 在 dirent */
/* fs_autoprobe —— 挂载入口。kernel.c 本轮禁改（启动流程不动），故探测
 * 挂在 vfs_init 尾部自动执行：按注册顺序遍历块设备逐个尝试 fat16_mount
 * (ops,0)（分区设备窗口已在 ide.c 绑定故 part_lba=0；整盘设备参与探测
 * 以覆盖 superfloppy），首个通过 BPB 合法性闸门者胜出。
 * 无盘/非 FAT 环境：全部失败 ⇒ 静默返回，零日志不 panic（设计硬要求）。 */
static void fs_selfcheck(void*m);
static void fs_autoprobe(void){
  for(int i=0;i<g_blkn;i++){
    void*h=fat16_mount(g_blks_ops[i],0);
    if(!h)continue;
    g_fatmnt=h;
    kputs("[FS] FAT16 mounted: ");kputs(fat16_label(h));
    kputs(" ");kput_dec(fat16_file_count(h));kputs(" files\n");
    fs_selfcheck(h);
    return;
  }
}
/* ⚠️ TEMP(M-B0 验收自检，临时代码)：内核态读根目录首个文件名/大小并抽读
 * 正文头部；另验一条子目录簇链（SUBDIR/INNER.TXT 为测试镜像固定内容）。
 * 验收后处置建议：整体移除；若需保留能力，应转正为 ring3 shell 的 ls/cat
 * 底座（走 /mnt/fat fd 路径），而非内核态打印。 */
static void fs_selfcheck(void*m){
  fat16_dirent_t d;
  if(fat16_root_enum(m,0,&d))return;
  kputs("[FS][selftest] root[0]=\"");kputs(d.name);
  kputs("\" size=");kput_dec(d.size);kputs("\n");
  uint8_t buf[17]={0};                            /* >16B 聚合初始化可能派发 paging.c memset，链接安全 */
  int r=fat16_read_file(m,&d,0,buf,16);
  if(r>0){for(int i=0;i<r;i++)if(buf[i]<0x20||buf[i]>0x7E)buf[i]='.';
    buf[r]=0;kputs("[FS][selftest] head=\"");kputs((const char*)buf);kputs("\"\n");}
  if(fat16_lookup(m,"SUBDIR/INNER.TXT",&d)==0){
    kputs("[FS][selftest] SUBDIR/INNER.TXT size=");kput_dec(d.size);
    uint8_t nb[9]={0,0,0,0,0,0,0,0,0};
    int rn=fat16_read_file(m,&d,0,nb,8);
    if(rn>0){for(int i=0;i<rn;i++)if(nb[i]<0x20||nb[i]>0x7E)nb[i]='.';
      kputs(" body=\"");kputs((const char*)nb);kputs("\"");}
    kputs("\n");
  }
}
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
  fs_autoprobe();   /* M-B0：FAT16 自动探测挂载（无盘/非 FAT 静默跳过） */
}
/* L2：分配改经 vfs_fd_alloc（原实现内联 for(fd=3..) 且永久跳过 0-2）。
 * M-B0 追加两段解析（顺序：chr 静态节点 → 块设备注册表 → /mnt/fat 前缀）：
 *   1) 块设备名（/dev/hda、/dev/hda1..4）精确命中 → no-op 占位 fd；
 *   2) "/mnt/fat/" 前缀 → fat16_lookup 路径解析，失败按既有契约统一 -1
 *      （open 错误码细分留待 nr=36 ABI 定稿，本层不抢跑）。 */
int vfs_open(const char*p,uint32_t fl){
  for(unsigned i=0;i<sizeof(nodes)/sizeof(nodes[0]);i++){const char*a=p,*b=nodes[i].name;while(*a&&*a==*b){a++;b++;}if(!*a&&!*b)return vfs_fd_alloc(FILE_VFS,fl,&nodes[i],0);}
  for(int i=0;i<g_blkn;i++){const char*a=p,*b=g_blks_ino[i].name;while(*a&&*a==*b){a++;b++;}if(!*a&&!*b)return vfs_fd_alloc(FILE_VFS,fl,&g_blks_ino[i],0);}
  if(g_fatmnt){const char*a=p,*b="/mnt/fat/";while(*a&&*a==*b){a++;b++;}
    if(!*b){
      fatfh_t*h=0;for(int i=0;i<FAT_OPEN_MAX;i++)if(!fatfh[i].used){h=&fatfh[i];break;}
      if(h&&fat16_lookup(g_fatmnt,a,&h->de)==0){
        h->used=1;
        int fd=vfs_fd_alloc(FILE_VFS,fl,&fattpl,h);
        if(fd>=0)return fd;
        h->used=0;return -1;                     /* fd 耗尽 */
      }
      return -1;                                 /* ENOENT / 槽耗尽 */
    }}
  return -1;}
int vfs_read(int fd,void*b,uint32_t n){if(fd<0||fd>=VFS_MAX_FD||!fds[fd]||fds[fd]->kind!=FILE_VFS||!fds[fd]->inode->ops->read)return -9;if(!user_access_ok((uintptr_t)b,n,1))return -14;return fds[fd]->inode->ops->read(fds[fd],b,n);}int vfs_write(int fd,const void*b,uint32_t n){if(!user_access_ok((uintptr_t)b,n,0))return -14;if(fd<0||fd>=VFS_MAX_FD||!fds[fd]||fds[fd]->kind!=FILE_VFS||!fds[fd]->inode->ops->write)return -9;return fds[fd]->inode->ops->write(fds[fd],b,n);}
/* L2：放开 fd<3 拒绝（0-2 现为合法 std 槽位，须可关闭归还）；边界/kind 校验保持：
 * 负值/越界/空槽 → -EBADF(-9)；FILE_SOCKET → -EBADF（socket 只能经 nr==28 或
 * vfs_socket_close 关闭；L8 的 nr==3 close 别名已于 2026-08-26 拆除改挂 read，
 * 见 vfs_syscall 注记）。 */
int vfs_close(int fd){if(fd<0||fd>=VFS_MAX_FD||!fds[fd])return -9;if(fds[fd]->kind!=FILE_VFS)return -9;
  /* M-B0：补发 inode close 钩子（fat 句柄槽释放依赖此；既有 chr 节点
   * close 成员恒为 0，守卫后零行为变更）。 */
  if(fds[fd]->inode->ops&&fds[fd]->inode->ops->close)fds[fd]->inode->ops->close(fds[fd]);
  fds[fd]=0;return 0;}
/* L2：socket 安装走共享分配器（原 for(fd=3..) 内联版）；耗尽契约保持 -EMFILE(-24)。 */
int vfs_socket_install(void *sock){int fd=vfs_fd_alloc(FILE_SOCKET,O_RDWR,0,sock);return fd<0?-24:fd;}
void *vfs_socket_get(int fd){if(fd<0||fd>=VFS_MAX_FD||!fds[fd]||fds[fd]->kind!=FILE_SOCKET)return 0;return fds[fd]->private;}
int vfs_socket_close(int fd){if(!vfs_socket_get(fd))return -9;fds[fd]=0;return 0;}
int vfs_fd_exists(int fd){return fd>=0&&fd<VFS_MAX_FD&&fds[fd]!=0;}

/* ── Wave 1: POSIX syscall 实现 ─────────────────────────────────── */

/* struct catos_stat 内核侧布局（与 user space 一致） */
struct catos_stat {
    uint32_t st_dev, st_ino, st_mode, st_nlink;
    uint32_t st_uid, st_gid, st_rdev;
    uint32_t st_size, st_blksize, st_blocks;
};
#define S_IFCHR  0x2000u
#define S_IFREG  0x8000u
#define S_IFDIR  0x4000u
#define S_IFSOCK 0xC000u

int vfs_fstat(int fd, void *user_stat){
    if(fd<0||fd>=VFS_MAX_FD||!fds[fd])return -9;
    if(!user_access_ok((uintptr_t)user_stat, sizeof(struct catos_stat), 1))return -14;
    struct catos_stat st={0};
    file_t *f=fds[fd];
    if(f->kind==FILE_SOCKET){
        st.st_mode=S_IFSOCK;
    }else if(f->kind==FILE_VFS&&f->inode){
        if(f->inode->type==VFS_CHR) st.st_mode=S_IFCHR;
        else if(f->private&&(((fatfh_t*)f->private)->de.attr&ATTR_DIR))
            st.st_mode=S_IFDIR;
        else st.st_mode=S_IFREG;
        st.st_size=f->inode->size;
        /* FAT 只读挂载：模板 inode(fattpl) size 恒 0，真实大小在 dirent。
         * nginx 配置读取以 fstat.size 做读入门禁（ngx_conf_file.c:535），
         * 传 0 会导致「空配置」假象。private= fatfh 句柄时以 de.size 为准。 */
        if(st.st_size==0u&&f->private)st.st_size=((fatfh_t*)f->private)->de.size;
        st.st_dev=0;
    }
    st.st_nlink=1;
    memcpy(user_stat,&st,sizeof(st));
    return 0;
}

int vfs_lseek(int fd, int32_t offset, int whence){
    if(fd<0||fd>=VFS_MAX_FD||!fds[fd])return -9;
    file_t *f=fds[fd];
    if(f->kind==FILE_SOCKET)return -29; /* ESPIPE */
    if(!f->inode)return -9;
    if(f->inode->type==VFS_CHR){
        /* 设备文件：/dev/null 允许 seek（但无意义），其他设备 -ESPIPE */
        return -29;
    }
    uint32_t newpos;
    switch(whence){
    case 0: /* SEEK_SET */
        newpos=(uint32_t)offset;
        break;
    case 1: /* SEEK_CUR */
        newpos=f->pos+(uint32_t)offset;
        break;
    case 2: /* SEEK_END */
        newpos=f->inode->size+(uint32_t)offset;
        break;
    default:
        return -22; /* EINVAL */
    }
    /* 越界检查：不允许回绕到负数 */
    if(whence!=2&&(int32_t)newpos<0)return -22;
    f->pos=newpos;
    return (int)newpos;
}

int vfs_dup2(int oldfd, int newfd){
    if(oldfd<0||oldfd>=VFS_MAX_FD||!fds[oldfd])return -9;
    if(newfd<0||newfd>=VFS_MAX_FD)return -9;
    if(oldfd==newfd)return newfd;
    /* 关闭 newfd 如果已打开 */
    if(fds[newfd]){
        if(fds[newfd]->kind==FILE_VFS){
            if(fds[newfd]->inode&&fds[newfd]->inode->ops&&fds[newfd]->inode->ops->close)
                fds[newfd]->inode->ops->close(fds[newfd]);
        }
        /* socket 不走 vfs_close（需要 nr=28），此处仅释放 fd 槽位 */
        fds[newfd]=0;
    }
    fds[newfd]=fds[oldfd];
    return newfd;
}

int vfs_fcntl(int fd, int cmd, int arg){
    if(fd<0||fd>=VFS_MAX_FD||!fds[fd])return -9;
    file_t *f=fds[fd];
    switch(cmd){
    case 1: /* F_GETFD */ return 0;
    case 2: /* F_SETFD */ return 0;
    case 3: /* F_GETFL */ return (int)f->flags;
    case 4: /* F_SETFL */ f->flags=(uint32_t)arg; return 0;
    default: return -22; /* EINVAL */
    }
}

int vfs_ioctl(int fd, int cmd, int arg){
    if(fd<0||fd>=VFS_MAX_FD||!fds[fd])return -9;
    switch(cmd){
    case 0x5413: { /* TIOCGWINSZ */
        if(!user_access_ok((uintptr_t)arg, 8, 1))return -14;
        uint16_t *p=(uint16_t*)(uintptr_t)arg;
        p[0]=24; p[1]=80; p[2]=0; p[3]=0;
        return 0;
    }
    case 0x541B: return 0; /* FIONREAD: no buffered data */
    default: return -25; /* ENOTTY */
    }
}

/* iovec entry for writev */
struct catos_iovec { void *iov_base; uint32_t iov_len; };
#define CATOS_UIO_MAXIOV 16

int vfs_writev(int fd, const void *iovec_user, int iovcnt){
    if(fd<0||fd>=VFS_MAX_FD||!fds[fd])return -9;
    if(iovcnt<0||iovcnt>CATOS_UIO_MAXIOV)return -22;
    uint32_t total=0;
    for(int i=0;i<iovcnt;i++){
        struct catos_iovec iov;
        if(!user_access_ok((uintptr_t)iovec_user+i*sizeof(struct catos_iovec), sizeof(struct catos_iovec), 0))
            return -14;
        memcpy(&iov,(const char*)iovec_user+i*sizeof(struct catos_iovec),sizeof(iov));
        if(iov.iov_len==0)continue;
        if(!user_access_ok((uintptr_t)iov.iov_base, iov.iov_len, 0))return -14;
        int r=vfs_write(fd,iov.iov_base,iov.iov_len);
        if(r<0)return r;
        total+=(uint32_t)r;
        if((uint32_t)r<iov.iov_len)break; /* short write */
    }
    return (int)total;
}

int vfs_fd_readable(int fd){
    if(fd<0||fd>=VFS_MAX_FD||!fds[fd])return 0;
    file_t *f=fds[fd];
    if(f->kind!=FILE_VFS)return 0;
    if(f->inode&&f->inode->type==VFS_CHR&&f->inode->ops&&f->inode->ops->read)return 1;
    if(f->inode&&f->inode->type==VFS_REG)return 1;
    return 0;
}

int vfs_fd_writable(int fd){
    if(fd<0||fd>=VFS_MAX_FD||!fds[fd])return 0;
    file_t *f=fds[fd];
    if(f->kind!=FILE_VFS)return 0;
    if(f->inode&&f->inode->type==VFS_CHR&&f->inode->ops&&f->inode->ops->write)return 1;
    if(f->inode&&f->inode->type==VFS_REG)return 1;
    return 0;
}
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
