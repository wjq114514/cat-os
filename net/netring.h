#ifndef CATOS_NETRING_H
#define CATOS_NETRING_H
#include <stdint.h>

/* ── NAPI 批量框架 ──────────────────────────────────────────────────── */
#define NETRING_BATCH_BUDGET 32   /* 单次 poll 最大处理包数（参照 Linux NAPI budget） */

void netring_init(void);

/* 吞吐量统计（供 net_stats_snapshot 使用） */
void netring_rx_stat(uint32_t bytes);
void netring_tx_stat(uint32_t bytes);
uint32_t netring_rx_packets(void);
uint32_t netring_tx_packets(void);
uint32_t netring_rx_bytes(void);
uint32_t netring_tx_bytes(void);
#endif
