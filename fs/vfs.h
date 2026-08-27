#ifndef CATOS_VFS_H
#define CATOS_VFS_H
#include <stdint.h>
#define VFS_MAX_FD 32
#define O_RDONLY 0
#define O_WRONLY 1
#define O_RDWR 2
typedef enum { VFS_REG, VFS_CHR, VFS_DIR, VFS_BLK } inode_type_t;
struct inode; struct file;
typedef enum { FILE_VFS, FILE_SOCKET } file_kind_t;
typedef int (*vfs_read_t)(struct file *,void *,uint32_t); typedef int (*vfs_write_t)(struct file *,const void *,uint32_t);
typedef struct file_ops {vfs_read_t read;vfs_write_t write;int (*close)(struct file *);} file_ops_t;
typedef struct inode {inode_type_t type;uint32_t size;const char *name;const file_ops_t *ops;void *private;} inode_t;
typedef struct file {inode_t *inode;uint32_t pos,flags;file_kind_t kind;void *private;} file_t;
/* ── M-B0 块设备层（fs-design 定案：FAT16 只读先行）────────────────────────
 * blk_ops_t 仿 chr 设备的 file_ops 模式：驱动提供三入口，经 vfs_blk_register()
 * 以 devfs 命名（/dev/hda、/dev/hda1..4）挂入 VFS。drv 为驱动私有句柄
 * （ide.c 绑定 g_dsk/g_part 描述符；当前 M-B0 驱动侧为静态单实例绑定，
 * 入参 drv 允许 NULL —— 见 ide.c trampoline 注记）。扇区计数 cnt 不设上限，
 * 驱动内部自行按 ATA 每命令 ≤255 扇区分块。
 * 内核消费者（fat16.c）直接持有 blk_ops_t* 调用，不经 fd 层；
 * /dev/hda* 同时可经 vfs_open 打开（read/write 为 no-op 占位），仅为
 * devfs 命名空间一致性，raw IO 后续随 nr=36 接线再议。 */
typedef struct blk_ops {
  int (*read_sectors)(void *drv,uint32_t lba,uint32_t cnt,void *buf);
  int (*write_sectors)(void *drv,uint32_t lba,uint32_t cnt,const void *buf);
  uint32_t (*capacity)(void *drv);   /* 返回设备总扇区数 */
} blk_ops_t;
#define VFS_BLK_MAX 8           /* 块设备注册表容量（hda+hda1..4 已占 5） */
int vfs_blk_register(const char *name,const blk_ops_t *ops,void *drv);
int vfs_blk_count(void);
inode_t *vfs_blk_get(int i);
void vfs_init(void); int vfs_open(const char *,uint32_t); int vfs_read(int,void *,uint32_t); int vfs_write(int,const void *,uint32_t); int vfs_close(int); int32_t vfs_syscall(uint32_t,const uint32_t *);
int vfs_socket_install(void *sock); void *vfs_socket_get(int fd); int vfs_socket_close(int fd);
int vfs_fd_exists(int fd);
/* Wave 1: POSIX 补全 ───────────────────────────────────────────── */
int vfs_lseek(int fd, int32_t offset, int whence);
int vfs_fstat(int fd, void *user_stat);
int vfs_dup2(int oldfd, int newfd);
int vfs_fcntl(int fd, int cmd, int arg);
int vfs_ioctl(int fd, int cmd, int arg);
int vfs_writev(int fd, const void *iovec_user, int iovcnt);
int vfs_fd_readable(int fd);
int vfs_fd_writable(int fd);
#endif
