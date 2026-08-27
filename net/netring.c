/* netring.c — NAPI 批量收发框架（Wave 2 性能优化）
 *
 * 最小实现：为未来零拷贝路径预留 submit/complete 批量接口。
 * 当前实际收发仍走 e1000_poll → net_handle_packet 路径；
 * 本文件提供 batch 统计 + 吞吐量观测，后续对接 page cache。 */
#include "kernel.h"
#include "netring.h"

/* 吞吐量统计（供 net_stats_snapshot 报告） */
static uint32_t nr_rx_packets, nr_tx_packets;
static uint32_t nr_rx_bytes, nr_tx_bytes;

void netring_init(void) {
    nr_rx_packets = nr_tx_packets = 0;
    nr_rx_bytes = nr_tx_bytes = 0;
    kputs("[OK] net ring batch framework initialized (NAPI budget=32)\n");
}

/* 批量统计更新（由 e1000_poll / net_send 调用） */
void netring_rx_stat(uint32_t bytes) { nr_rx_packets++; nr_rx_bytes += bytes; }
void netring_tx_stat(uint32_t bytes) { nr_tx_packets++; nr_tx_bytes += bytes; }

/* 导出给 net_stats_snapshot（net.c 中 nr=32 分发） */
uint32_t netring_rx_packets(void) { return nr_rx_packets; }
uint32_t netring_tx_packets(void) { return nr_tx_packets; }
uint32_t netring_rx_bytes(void) { return nr_rx_bytes; }
uint32_t netring_tx_bytes(void) { return nr_tx_bytes; }
