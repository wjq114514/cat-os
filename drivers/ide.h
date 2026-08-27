#ifndef CATOS_IDE_H
#define CATOS_IDE_H
#include <stdint.h>
#include "vfs.h"
void ide_init(void); int ide_read_sectors(uint8_t,uint32_t,uint8_t,void*); int ide_write_sectors(uint8_t,uint32_t,uint8_t,const void*);
/* M-B0：主分区枚举 + /dev/hda、/dev/hda1..4 注册（vfs_blk_register）。
 * 读 LBA0 校验 0x55AA 签名后解析 4 个主分区表项；无有效签名/无有效表项时
 * 仅注册整盘并静默返回。当前仅支持 primary master（drive==0）。 */
void mbr_scan(uint8_t drive);
#endif
