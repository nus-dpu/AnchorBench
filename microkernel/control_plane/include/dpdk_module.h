#ifndef _LYRA_DPDK_MODULE_H_
#define _LYRA_DPDK_MODULE_H_

#include "init.h"
#include "ipc.h"

extern int dpdk_create_flow(uint16_t port, uint16_t * queues, int nr_queues);

extern uint8_t * dpdk_get_rxpkt(int port_id, int index, uint16_t * pkt_size);
extern uint32_t dpdk_recv_pkts(int port_id);
extern struct rte_mbuf * dpdk_get_txpkt(int port_id, int pkt_size);
extern uint32_t dpdk_send_pkts(int port_id);

extern int __init dpdk_init(void);

#endif  /* _LYRA_DPDK_MODULE_H_ */