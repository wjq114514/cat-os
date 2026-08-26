#ifndef CATOS_FAT16_H
#define CATOS_FAT16_H
#include "vfs.h"
#include <stdint.h>
/* ── fat16.h — FAT16 只读最小集（M-B0，fs-design 定案）─────────────────────
 * 挂载契约：fat16_mount(blk_ops_t *blk, uint32_t part_lba)
 *   - blk：块设备操作表（ide.c 注册的 /dev/hda 或 /dev/hdaN 均可）；
 *   - part_lba：文件系统起始 LBA（blk 相对）。分区设备传 0（窗口已在
 *     驱动侧绑定）；整盘设备传分区首 LBA（如 63/2048）。
 *   - 成功返回挂载句柄（不透明指针），失败返回 0。当前单挂载点（句柄指向
 *     fat16.c 内静态实例），多卷挂载表留待 VFS mount 层。
 * 范围：BPB 解析、FAT 表 LRU 缓存(≤64 扇区)、根目录/子目录遍历、按簇链
 * 读文件。只读；8.3 短名；LFN 表项跳过；仅支持 512 字节扇区。 */
typedef struct { char name[13]; uint8_t attr; uint32_t size; uint32_t cluster; } fat16_dirent_t;
void *fat16_mount(const blk_ops_t *,uint32_t);      /* →句柄 | 0=非FAT16 */
int fat16_lookup(void *mnt,const char *path,fat16_dirent_t *out); /* '/'起头可省 */
int fat16_read_file(void *mnt,const fat16_dirent_t *,uint32_t off,void *buf,uint32_t len);
int fat16_root_enum(void *mnt,int idx,fat16_dirent_t *out); /* idx=过滤后序号 */
const char *fat16_label(void *mnt);                  /* 卷标(去尾空格) */
uint32_t fat16_file_count(void *mnt);                /* 根目录普通文件数 */
#endif
