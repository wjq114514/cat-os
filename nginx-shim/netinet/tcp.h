
#ifndef _SHIM_NETINET_TCP_H
#define _SHIM_NETINET_TCP_H
#define TCP_NODELAY   1
#define TCP_MAXSEG    2
#define TCP_CORK      3
#define TCP_KEEPIDLE  4
#define TCP_KEEPINTVL 5
#define TCP_KEEPCNT   6
#define TCP_DEFER_ACCEPT 9
#define TCP_QUICKACK  12
#define TCP_FASTOPEN  23
#define TCP_INFO      11
struct tcp_info {
    uint8_t tcpi_state; uint8_t tcpi_ca_state; uint8_t tcpi_retransmits;
    uint8_t tcpi_probes; uint8_t tcpi_backoff; uint8_t tcpi_options;
    uint16_t tcpi_snd_wscale; uint16_t tcpi_rcv_wscale;
    uint32_t tcpi_rto; uint32_t tcpi_ato; uint32_t tcpi_snd_mss;
    uint32_t tcpi_rcv_mss; uint32_t tcpi_unacked; uint32_t tcpi_sacked;
    uint32_t tcpi_lost; uint32_t tcpi_retrans; uint32_t tcpi_fackets;
    uint32_t tcpi_last_data_sent; uint32_t tcpi_last_ack_sent;
    uint32_t tcpi_last_data_recv; uint32_t tcpi_last_ack_recv;
    uint32_t tcpi_pmtu; uint32_t tcpi_rcv_ssthresh; uint32_t tcpi_rtt;
    uint32_t tcpi_rttvar; uint32_t tcpi_snd_ssthresh; uint32_t tcpi_snd_cwnd;
    uint32_t tcpi_advmss; uint32_t tcpi_reordering;
    uint32_t tcpi_rcv_space; uint32_t tcpi_total_retrans;
};
#endif
