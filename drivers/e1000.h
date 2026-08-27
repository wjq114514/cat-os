#ifndef CATOS_E1000_H
#define CATOS_E1000_H
#include <stdint.h>
void e1000_init(void);
void e1000_poll(void);
void e1000_get_mac(uint8_t out[6]);
/* 供 net 层发包：alloc 返回下一个空闲 TX buffer（含以太头起点），
 * 失败返回 NULL；组好帧后调用 submit(len) 提交并推进 TDT。 */
uint8_t *e1000_tx_alloc(void);
int e1000_tx_submit(uint32_t len);
/* 零拷贝 TX 提交（Wave 2 新增）：直接引用物理地址缓冲区。
 * 物理地址须 16 字节对齐（e1000 描述符硬件要求）。 */
int e1000_tx_submit_buf(uint32_t phys_addr, uint32_t len);
#endif
