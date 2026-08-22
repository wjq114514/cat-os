#ifndef CATOS_IDE_H
#define CATOS_IDE_H
#include <stdint.h>
void ide_init(void); int ide_read_sectors(uint8_t,uint32_t,uint8_t,void*); int ide_write_sectors(uint8_t,uint32_t,uint8_t,const void*);
#endif
