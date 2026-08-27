/* ide.c — ATA PIO 驱动 + M-B0 块设备层接入（fs-design：VFS_BLK + mbr_scan）
 * 职责：
 *   1) 既有 ATA 主盘探测/读写（原逻辑逐字保留，含 LBA1 R/W 自检）；
 *   2) mbr_scan()：读 LBA0 校验 0x55AA → 解析 4 个主分区表项（类型/LBA/扇区数）
 *      → 经 vfs_blk_register 注册 /dev/hda 与 /dev/hda1..4（仅有效分区）；
 *      无签名或无有效表项时只注册整盘（ superfloppy 场景），静默不 panic。
 * 驱动绑定注记（与 vfs.h blk_ops_t 契约呼应）：blk_ops_t 三入口首参 drv 为
 * 驱动私有句柄；本驱动为静态单实例绑定 —— 整盘/各分区各用一组 trampoline
 * 函数直接引用 g_dsk/g_part[K] 描述符，故调用方传 drv=NULL 亦语义正确
 * （fat16_mount(blk_ops_t*,part_lba) 两参签名即依赖此约定）。drv 形参保留，
 * 为多盘/热插拔时代的句柄化预留。
 * 时序契约：kernel_main 中 ide_init() 先于 vfs_init()，故注册表在自动挂载
 * 探测（vfs.c fs_autoprobe）之前就绪。 */
#include "ide.h"
#include "vfs.h"
#include "kernel.h"
#include <stdint.h>
static inline void ob(uint16_t p,uint8_t v){__asm__ volatile("outb %0,%1"::"a"(v),"Nd"(p));}static inline uint8_t ib(uint16_t p){uint8_t v;__asm__ volatile("inb %1,%0":"=a"(v):"Nd"(p));return v;}static inline void ins(uint16_t p,void*d){__asm__ volatile("rep insw"::"d"(p),"D"(d),"c"(256):"memory");}static inline void outs(uint16_t p,const void*d){__asm__ volatile("rep outsw"::"d"(p),"S"(d),"c"(256));}
static uint32_t identify28(uint8_t dr){uint16_t b=dr?0x170:0x1f0;uint16_t w[256];ob(b+6,0xA0|((dr&1)<<4));ob(b+7,0xEC);for(volatile int i=0;i<10000;i++);if(!ib(b+7))return 0;ins(b,w);return (uint32_t)w[60]|((uint32_t)w[61]<<16);}
static int rw(uint8_t dr,uint32_t l,uint8_t n,void*b,int wr){
  /* M-B0 加固（QEMU 实测回归：WRITE 后紧邻 READ，新命令首拍状态滞留旧值
   * 0x50[DRDY|DSC 无 DRQ] 而被误判失败；插桩延时即复现消失 —— 典型命令窗
   * 竞态）。三层防御：
   *   1) 命令前等 BSY 清（设备对上一命令的内部收尾可跨越数据阶段完成）；
   *   2) 命令后先垫 ≥4 拍 ALT-Status 读凑满 ATA 400ns 命令窗；
   *   3) 扇区轮询条件改为「BSY 清 且 (DRQ 置 | ERR 置)」带超时 —— 只认
   *      终态，不认过渡态；另保留 ERR 位检查与整命令一次重试。 */
  uint16_t base=dr?0x170:0x1f0;
  int rc=-1;
  for(int t=0;t<2&&rc!=0;t++){
    {uint32_t sp=0;while(ib(base+7)&0x80)if(++sp>10000000u)break;} /* 1) 设备空闲 */
    ob(base+6,0xE0|((dr&1)<<4)|((l>>24)&15));
    ob(base+2,n);ob(base+3,l);ob(base+4,l>>8);ob(base+5,l>>16);
    ob(base+7,wr?0x30:0x20);
    for(volatile int d=0;d<4;d++)(void)ib(base+6);                /* 2) */
    rc=0;
    for(uint8_t s=0;s<n;s++){
      uint8_t st;uint32_t sp=0;
      do{st=ib(base+7);if(++sp>8000000u)break;}                   /* 3) 超时兜底 */
      while(((st&0x80)||!(st&0x08))&&!(st&1));
      if(!(st&8)||(st&1)){rc=-1;break;}
      if(wr)outs(base,b);else ins(base,b);
      b=(uint8_t*)b+512;
    }
  }
  return rc;
}
int ide_read_sectors(uint8_t d,uint32_t l,uint8_t n,void*b){return rw(d,l,n,b,0);}int ide_write_sectors(uint8_t d,uint32_t l,uint8_t n,const void*b){return rw(d,l,n,(void*)b,1);}

/* ── M-B0 块设备绑定 ────────────────────────────────────────────────────── */
typedef struct { uint8_t drive; uint32_t sectors; } ide_disk_t;   /* 整盘 */
typedef struct { uint8_t drive; uint32_t lba0,lba_cnt; } ide_part_t;
static ide_disk_t g_dsk;            /* 仅 primary master（drive 0） */
static ide_part_t g_part[4];
/* ATA 每命令 ≤255 扇区：blk_ops 契约的 cnt 无上限，此处分块转发 */
static int dsk_io(uint32_t l,uint32_t n,void*b,int wr){
  int rc=0;while(n&&!rc){uint32_t c=n>255u?255u:n;
    rc=wr?ide_write_sectors(0,l,(uint8_t)c,b):ide_read_sectors(0,l,(uint8_t)c,b);
    l+=c;b=(uint8_t*)b+c*512u;n-=c;}
  return rc;}
static int part_io(int pi,uint32_t l,uint32_t n,void*b,int wr){
  if(l>=g_part[pi].lba_cnt||n>g_part[pi].lba_cnt-l)return -1; /* 分区越界拒绝 */
  return dsk_io(g_part[pi].lba0+l,n,b,wr);}
/* 整盘 trampoline（drv 忽略，见文件头绑定注记） */
static int h_read(void*d,uint32_t l,uint32_t n,void*b){(void)d;return dsk_io(l,n,b,0);}
static int h_write(void*d,uint32_t l,uint32_t n,const void*b){(void)d;return dsk_io(l,n,(void*)b,1);}
static uint32_t h_cap(void*d){(void)d;return g_dsk.sectors;}
/* 分区 trampoline：每槽位一组具名函数，静态绑死 &g_part[K]（无运行期分派） */
#define PART_TRAMP(K) \
static int p##K##_read(void*d,uint32_t l,uint32_t n,void*b){(void)d;return part_io(K,l,n,b,0);} \
static int p##K##_write(void*d,uint32_t l,uint32_t n,const void*b){(void)d;return part_io(K,l,n,(void*)b,1);} \
static uint32_t p##K##_cap(void*d){(void)d;return g_part[K].lba_cnt;}
PART_TRAMP(0) PART_TRAMP(1) PART_TRAMP(2) PART_TRAMP(3)
static const blk_ops_t HDA_OPS={h_read,h_write,h_cap};
static const blk_ops_t PART_OPS[4]={
  {p0_read,p0_write,p0_cap},{p1_read,p1_write,p1_cap},
  {p2_read,p2_write,p2_cap},{p3_read,p3_write,p3_cap}};
static void phex8(uint8_t v){static const char hx[]="0123456789ABCDEF";
  char s[3]={hx[v>>4],hx[v&15],0};kputs(s);}
/* MBR 主分区表项布局（LBA0）：
 *   +0 状态(0x80 可引导)、+1..3 起 CHS、+4 类型、+5..7 止 CHS、
 *   +8..11 首 LBA(le32)、+12..15 扇区数(le32)。CHS 本内核不消费。 */
void mbr_scan(uint8_t drive){
  if(drive!=0)return;                       /* 当前仅 primary master */
  uint8_t mbr[512] __attribute__((aligned(2)));
  if(ide_read_sectors(0,0,1,mbr))return;    /* 读失败：静默放弃枚举 */
  vfs_blk_register("/dev/hda",&HDA_OPS,&g_dsk);
  if(mbr[510]!=0x55||mbr[511]!=0xAA)return; /* 无签名：仅整盘（superfloppy） */
  for(int i=0;i<4;i++){
    const uint8_t *e=mbr+446+16*i;
    uint8_t type=e[4];
    uint32_t lba=(uint32_t)e[8]|((uint32_t)e[9]<<8)|((uint32_t)e[10]<<16)|((uint32_t)e[11]<<24);
    uint32_t cnt=(uint32_t)e[12]|((uint32_t)e[13]<<8)|((uint32_t)e[14]<<16)|((uint32_t)e[15]<<24);
    if(!type||!cnt)continue;                /* 空表项 */
    if(lba>g_dsk.sectors||cnt>g_dsk.sectors-lba)continue; /* 越出盘容：弃 */
    g_part[i].drive=0;g_part[i].lba0=lba;g_part[i].lba_cnt=cnt;
    char nm[]="/dev/hdaN";nm[8]=(char)('1'+i);
    vfs_blk_register(nm,&PART_OPS[i],&g_part[i]);
    kputs("[MBR] ");kputs(nm);kputs(" type=0x");phex8(type);
    kputs(" lba=");kput_dec(lba);kputs(" sectors=");kput_dec(cnt);kputs("\n");
  }
}
void ide_init(void){uint8_t id[512] __attribute__((aligned(2)));uint32_t sectors=identify28(0);if(ide_read_sectors(0,0,1,id)==0){kputs("[OK] IDE primary master detected sectors=");kput_dec(sectors);kputs(" size=");kput_dec((sectors*512u)/(1024u*1024u));kputs(" MB\n");g_dsk.drive=0;g_dsk.sectors=sectors;mbr_scan(0);uint8_t x[512],y[512];for(int i=0;i<512;i++)x[i]=(uint8_t)(i^0x5a);ide_write_sectors(0,1,1,x);ide_read_sectors(0,1,1,y);int ok=1;for(int i=0;i<512;i++)if(x[i]!=y[i])ok=0;if(ok)kputs("[OK] IDE sector R/W OK\n");}else kputs("[OK] IDE primary master absent\n");}
