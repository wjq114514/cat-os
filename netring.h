#ifndef CATOS_NETRING_H
#define CATOS_NETRING_H
#include <stdint.h>
#define NETRING_SIZE 256
typedef struct {uint32_t addr,len,flags;} net_buf_t;
typedef struct {volatile uint32_t head,tail;net_buf_t desc[NETRING_SIZE];} net_ring_t;
typedef struct {net_ring_t submit,complete;volatile uint32_t doorbell,busy_poll;} net_queue_t;
void netring_init(void);
#endif
