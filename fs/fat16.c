/* fat16.c — FAT16 只读最小集（M-B0，fs-design 定案：FAT16 只读先行）
 * 能力面：BPB 解析与合法性校验、FAT 表 LRU 缓存(≤64 扇区项)、根目录/
 * 子目录遍历、8.3 短名解析与大小写不敏感匹配、按簇链读文件。
 * 明确不做（本轮）：写路径、LFN 长名、FAT12/FAT32、非 512 扇区。
 *
 * 关键布局依据（Microsoft EFI FAT32 规范 §5，FAT16 子集）：
 *   引导扇区(BPB)：+11 每扇区字节数 u16；+13 每簇扇区 u8；+14 保留扇区
 *   u16；+16 FAT 数 u8；+17 根目录项数 u16；+19 总扇区16 u16；
 *   +22 每 FAT 扇区16 u16（==0 即 FAT32，拒）；+28 隐藏扇区 u32；
 *   +32 总扇区32 u32（TotSec16==0 时生效）；EBPB 自 +36 起：+36 驱动号、
 *   +38 扩展引导签名、+39 卷序号、+43 卷标 11B（权威源为根目录卷标项，
 *   此处仅兜底）、+54 文件系统类型串。
 *   派生：fat_lba=reserved；root_lba=fat_lba+nfats*fatsz；
 *   root_secs=(rootents*32+511)/512；data_lba=root_lba+root_secs；
 *   nclusters=(totsec-data_lba)/spc。簇号从 2 起，数据区 LBA=
 *   data_lba+(clu-2)*spc。FAT16 表项 u16：≥0xFFF8 EOF，坏簇 0xFFF7。
 *   目录项 32B：+0 首字节(0x00 区段尾/0xE5 已删)；+11 属性(0x0F LFN、
 *   0x08 卷标、0x10 目录)；+26 首簇 u16；+28 大小 u32。
 * 并发注记：缓存/弹跳缓冲为静态单实例 —— M-B0 仅内核态单挂载点串行访问
 * （vfs_init 自检与 ring3 syscall 路径均同步执行），多核/中断下半部并发
 * 接入前需加锁，届时随 VFS mount 表一并处理。 */
#include "fat16.h"
#include "kernel.h"
#include <stdint.h>
/* 局部字节搬运：不用全局 memcpy/memset —— paging.h 的 size_t 版声明与本
 * 文件并入 vfs.c 单翻译单元（Makefile 领地受限，见 vfs.c 注记）时签名
 * 易生冲突，n 量级均 ≤512，手写循环无性能顾虑。 */
static void bcopy(void *d,const void *s,uint32_t n){uint8_t *dd=d;const uint8_t *ss=s;while(n--)*dd++=*ss++;}
static void bzero(void *d,uint32_t n){uint8_t *dd=d;while(n--)*dd++=0;}

#define FAT16_EOD   0x00u
#define FAT16_DEL   0xE5u
#define ATTR_LFN    0x0Fu
#define ATTR_VOLUME 0x08u
#define ATTR_DIR    0x10u
#define FAT_EOF_MIN 0xFFF8u
#define FAT_BAD     0xFFF7u

typedef struct {
  const blk_ops_t *blk;      /* 底层块设备（drv 绑定见 ide.c 注记） */
  uint32_t base;             /* 文件系统起始 LBA（blk 相对） */
  uint16_t bps;              /* 每扇区字节数（仅认 512） */
  uint8_t spc;               /* 每簇扇区数（2 的幂） */
  uint16_t reserved,nfats,fatsz,rootents;
  uint32_t totsec,fat_lba,root_lba,data_lba,nclusters;
  char label[12];            /* 卷标，去尾空格 */
  uint32_t nfiles;           /* 根目录普通文件计数 */
  int has_first;             /* first 是否有效（根目录首个普通文件） */
  fat16_dirent_t first;
} fat16_mnt_t;
static fat16_mnt_t M;        /* 单挂载点实例（句柄=&M），多卷留待 mount 表 */

static uint16_t le16(const uint8_t *p){return (uint16_t)(p[0]|((uint16_t)p[1]<<8));}
static uint32_t le32(const uint8_t *p){return (uint32_t)p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24);}
static int rd_sec(fat16_mnt_t *m,uint32_t lba,void *buf){return m->blk->read_sectors(0,m->base+lba,1,buf);}

/* ── FAT 表 LRU 缓存：全相联 64 项，tick 最老者逐出 ─────────────────────────
 * 键 = FAT 区内相对扇区号（恒取 FAT#0，多 FAT 副本只读场景无需镜像）。
 * 容量依据 fs-design 上限 ≤64 项（64*512B=32KB .bss）。线性扫描 O(64)。 */
#define FC_SLOTS 64
typedef struct { uint32_t sec,tick; uint8_t valid; uint8_t data[512]; } fcent_t;
static fcent_t fcache[FC_SLOTS];
static uint32_t ftick;
static const uint8_t *fat_sector(fat16_mnt_t *m,uint32_t rel){
  fcent_t *victim=0;uint32_t oldest=~0u;
  for(int i=0;i<FC_SLOTS;i++){fcent_t *c=&fcache[i];
    if(c->valid&&c->sec==rel){c->tick=++ftick;return c->data;}
    if(!c->valid){victim=c;break;}                 /* 空槽优先占用 */
    if(c->tick<oldest){oldest=c->tick;victim=c;}}
  if(!victim)victim=&fcache[0];                    /* 不可达：防御 */
  if(m->blk->read_sectors(0,m->base+m->fat_lba+rel,1,victim->data))return 0;
  victim->valid=1;victim->sec=rel;victim->tick=++ftick;return victim->data;
}
static uint16_t fat_next(fat16_mnt_t *m,uint32_t clu){
  if(clu<2||clu==FAT_BAD||clu>=FAT_EOF_MIN)return FAT_EOF_MIN; /* 非法簇号按 EOF 收敛 */
  uint32_t fo=clu*2u,rel=fo>>9,off=fo&511u;
  const uint8_t *s=fat_sector(m,rel);
  return s?le16(s+off):(uint16_t)FAT_EOF_MIN;      /* IO 失败视为链终止 */
}
/* 目录区原始项读取：root 固定区 / 子目录簇链二态。返回 1=取到 0=越界/EOD 前
 * 边界 -1=IO 错。EOD 判定由调用方检查 out[0]==0x00。 */
static int dir_raw(fat16_mnt_t *m,uint32_t dclu,int isroot,uint32_t idx,uint8_t out[32]){
  static uint8_t sec[512];
  uint32_t lba,off;
  if(isroot){
    if(idx>=m->rootents)return 0;
    lba=m->root_lba+idx/16u;off=(idx&15u)*32u;
  }else{
    uint32_t per=m->spc*16u,c=dclu,step=idx/per;
    if(c<2)return 0;
    while(step--){c=fat_next(m,c);if(c<2||c>=FAT_EOF_MIN)return 0;}
    lba=m->data_lba+(c-2)*m->spc+(idx%per)*32u/512u;
    off=(idx%per)*32u&511u;
  }
  if(rd_sec(m,lba,sec))return -1;
  bcopy(out,sec+off,32);
  return 1;
}
/* 8.3 短名格式化："NAME    EXT" → "NAME.EXT"（空扩展省略点号） */
static void fmt83(const uint8_t *r,char out[13]){
  uint32_t j=0;
  for(int i=0;i<8&&r[i]!=' ';i++)out[j++]=(char)r[i];
  if(r[8]!=' '){out[j++]='.';for(int i=8;i<11&&r[i]!=' ';i++)out[j++]=(char)r[i];}
  out[j]=0;
}
static char up(char c){return (c>='a'&&c<='z')?(char)(c-32):c;}
static int nameq(const char *a,const char *b){
  while(*a||*b){if(up(*a)!=up(*b))return 0;a++;b++;}
  return 1;
}
/* 原始项 → dirent；skip 类（删除/LFN/卷标）返回 0 并继续语义交调用方 */
static int de_fill(const uint8_t *r,fat16_dirent_t *de){
  de->attr=r[11];de->size=le32(r+28);de->cluster=le16(r+26);fmt83(r,de->name);
  if(r[0]==FAT16_DEL||de->attr==ATTR_LFN)return 0;
  return 1;
}
void *fat16_mount(const blk_ops_t *blk,uint32_t part_lba){
  if(!blk||!blk->read_sectors)return 0;
  uint8_t bs[512] __attribute__((aligned(2)));
  if(blk->read_sectors(0,part_lba,1,bs))return 0;
  /* 合法性闸门：任一不过即判"非 FAT16"，调用方静默跳过（无盘/异种盘安全） */
  if(bs[510]!=0x55||bs[511]!=0xAA)return 0;
  uint16_t bps=le16(bs+11),reserved=le16(bs+14),rootents=le16(bs+17);
  uint16_t fatsz=le16(bs+22);uint8_t spc=bs[13],nfats=bs[16];
  uint32_t totsec=le16(bs+19)?le16(bs+19):le32(bs+32);   /* TotSec32 在 +32 */
  if(bps!=512)return 0;                            /* 仅 512B 扇区 */
  if(!spc||spc>128||(spc&(spc-1)))return 0;        /* 每簇须 2 的幂 */
  if(reserved<1||nfats<1||nfats>4||fatsz==0)return 0;
  if(rootents==0)return 0;                         /* ==0 即 FAT32，拒 */
  if(totsec==0)return 0;
  uint32_t rootsecs=(rootents*32u+511u)/512u;
  uint32_t data_lba=(uint32_t)reserved+(uint32_t)nfats*fatsz+rootsecs;
  if(totsec<=data_lba)return 0;
  uint32_t nclusters=(totsec-data_lba)/spc;
  if(nclusters<1||nclusters>=65525u)return 0;      /* FAT16 簇号域 */
  M.blk=blk;M.base=part_lba;M.bps=bps;M.spc=spc;M.reserved=reserved;
  M.nfats=nfats;M.fatsz=fatsz;M.rootents=rootents;M.totsec=totsec;
  M.fat_lba=reserved;M.root_lba=reserved+(uint32_t)nfats*fatsz;
  M.data_lba=data_lba;M.nclusters=nclusters;
  M.label[0]=0;M.nfiles=0;M.has_first=0;
  bzero(&fcache,sizeof(fcache));ftick=0;           /* 挂载即冷启动缓存 */
  /* 根目录一次普查：卷标 + 普通文件计数 + 首个普通文件快照。
   * 判序契约：LFN(attr==0x0F 含 0x08 卷标位)必须先于卷标位测试，
   * 否则长名项会被误吞为卷标（MS spec §6.7 同序要求）。IO 错 → 拒载。 */
  for(uint32_t i=0;;i++){
    uint8_t r[32];int rc=dir_raw(&M,0,1,i,r);
    if(rc<0)return 0;                              /* 根区不可读：非可靠卷 */
    if(rc==0||r[0]==FAT16_EOD)break;
    if(r[0]==FAT16_DEL)continue;
    if(r[11]==ATTR_LFN)continue;
    if(r[11]&ATTR_VOLUME){                         /* 卷标项（权威源） */
      uint32_t j=0;for(int k=0;k<11;k++)if(r[k]!=' ')M.label[j++]=(char)r[k];
      M.label[j]=0;continue;
    }
    if(r[11]&ATTR_DIR)continue;                    /* N 只计根目录普通文件 */
    M.nfiles++;
    if(!M.has_first){de_fill(r,&M.first);M.has_first=1;}
  }
  if(!M.label[0]){                                 /* 兜底：BPB 内卷标字段 */
    uint32_t j=0;for(int k=43;k<54;k++)if(bs[k]!=' ')M.label[j++]=(char)bs[k];
    M.label[j]=0;
  }
  return &M;
}
const char *fat16_label(void *mnt){return mnt?((fat16_mnt_t*)mnt)->label:"";}
uint32_t fat16_file_count(void *mnt){return mnt?((fat16_mnt_t*)mnt)->nfiles:0;}
int fat16_root_enum(void *mnt,int idx,fat16_dirent_t *out){
  fat16_mnt_t *m=mnt;if(!m||idx<0||!out)return -1;
  uint32_t want=(uint32_t)idx,hit=0;
  for(uint32_t i=0;;i++){
    uint8_t r[32];int rc=dir_raw(m,0,1,i,r);
    if(rc<0)return -1;
    if(rc==0||r[0]==FAT16_EOD)break;
    fat16_dirent_t d;if(!de_fill(r,&d))continue;
    if(d.attr&ATTR_VOLUME)continue;
    if(d.attr&ATTR_DIR)continue;                   /* 与计数口径一致：仅文件 */
    if(hit++==want){*out=d;return 0;}
  }
  return -2;                                       /* 越界 */
}
/* 路径解析：段间 '/'，支持子目录下钻；返回 0=命中 */
int fat16_lookup(void *mnt,const char *path,fat16_dirent_t *out){
  fat16_mnt_t *m=mnt;if(!m||!path||!out)return -1;
  int isroot=1;uint32_t dclu=0;
  const char *p=path;
  while(*p){
    while(*p=='/')p++;
    if(!*p)break;
    char seg[13];uint32_t sl=0;
    while(*p&&*p!='/'){if(sl>=12)return -4;seg[sl++]=*p++;} /* 无 LFN：>12 拒 */
    seg[sl]=0;
    int found=0;
    for(uint32_t i=0;;i++){
      uint8_t r[32];int rc=isroot?dir_raw(m,0,1,i,r):dir_raw(m,dclu,0,i,r);
      if(rc<0)return -1;
      if(rc==0||r[0]==FAT16_EOD)break;
      fat16_dirent_t d;if(!de_fill(r,&d))continue;
      if(d.attr&ATTR_VOLUME)continue;
      if(nameq(seg,d.name)){
        if(found)return -1;                        /* 不可能：防御 */
        {
          int had_sep=(*p=='/');
          const char *next=p;
          while(*next=='/')next++;
          if(*next){                               /* 还有后续段 */
            if(!(d.attr&ATTR_DIR))return -3;      /* 中间段非目录 */
            isroot=0;dclu=d.cluster;p=next;found=1;break;
          }
          if(had_sep&&!(d.attr&ATTR_DIR))return -3; /* 文件末尾不许 '/' */
        }
        *out=d;return 0;                           /* 末段命中（文件或目录） */
      }
    }
    if(!found)return -2;
  }
  return -2;                                       /* 空路径 */
}
/* 按簇链读文件：off/len 以字节计，越界自动截断到 size。返回实际读到字节数，
 * 负值为错误（链损坏 -1 等）。整扇区对齐走直读快路径，否则 512B 弹跳缓冲。 */
int fat16_read_file(void *mnt,const fat16_dirent_t *de,uint32_t off,void *buf,uint32_t len){
  fat16_mnt_t *m=mnt;
  if(!m||!de||!buf)return -1;
  if(de->attr&ATTR_DIR)return -1;                  /* 目录不提供字节流 */
  if(off>=de->size||len==0)return 0;
  if(len>de->size-off)len=de->size-off;
  static uint8_t bounce[512];                      /* 单线程串行前提，见头注 */
  uint32_t cbytes=m->spc*512u,c=de->cluster,pin=off%cbytes,rem=len;
  uint8_t *dst=buf;
  for(uint32_t s=off/cbytes;s;s--){                /* 跳过偏移所在簇之前者 */
    c=fat_next(m,c);
    if(c<2||c>=FAT_EOF_MIN)return -1;              /* 链短于偏移：坏链 */
  }
  while(rem){
    if(c<2||c>=FAT_EOF_MIN||c==FAT_BAD)return rem<len?-1:(int)(len-rem);
    uint32_t clba=m->data_lba+(c-2)*m->spc;
    while(rem&&pin<cbytes){
      uint32_t sidx=pin>>9,soff=pin&511u,n=512u-soff;
      if(n>rem)n=rem;
      if(soff==0&&n==512u){                        /* 对齐快路径 */
        if(m->blk->read_sectors(0,m->base+clba+sidx,1,dst))return -1;
      }else{
        if(rd_sec(m,clba+sidx,bounce))return -1;
        bcopy(dst,bounce+soff,n);
      }
      dst+=n;rem-=n;pin+=n;
      if(pin>=cbytes)pin=0;
    }
    pin=0;c=fat_next(m,c);
  }
  return (int)len;
}
