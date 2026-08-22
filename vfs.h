#ifndef CATOS_VFS_H
#define CATOS_VFS_H
#include <stdint.h>
#define VFS_MAX_FD 32
#define O_RDONLY 0
#define O_WRONLY 1
#define O_RDWR 2
typedef enum { VFS_REG, VFS_CHR, VFS_DIR } inode_type_t;
struct inode; struct file;
typedef int (*vfs_read_t)(struct file *,void *,uint32_t); typedef int (*vfs_write_t)(struct file *,const void *,uint32_t);
typedef struct file_ops {vfs_read_t read;vfs_write_t write;int (*close)(struct file *);} file_ops_t;
typedef struct inode {inode_type_t type;uint32_t size;const char *name;const file_ops_t *ops;void *private;} inode_t;
typedef struct file {inode_t *inode;uint32_t pos,flags;} file_t;
void vfs_init(void); int vfs_open(const char *,uint32_t); int vfs_read(int,void *,uint32_t); int vfs_write(int,const void *,uint32_t); int vfs_close(int); int32_t vfs_syscall(uint32_t,const uint32_t *);
#endif
