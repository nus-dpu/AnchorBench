#ifndef _COMPRESS_PORT_CFG_H_
#define _COMPRESS_PORT_CFG_H_

#include <stdio.h>
#include <string.h>

#include "compress-and-encrypt-constants.h"

struct mbuf_table {
	uint16_t len;
	struct rte_mbuf *m_table[DEFAULT_PKT_BURST];
};

typedef struct port_info_s {
	uint16_t pid;		/**< Port ID value */

	struct q_info {
		rte_atomic32_t flags;		/**< Special send flags for ARP and other */
		struct rte_mempool * rx_mp;	/**< Pool pointer for port RX mbufs */
		uint64_t tx_cnt, rx_cnt;
	} q[NUM_Q];

	struct rte_eth_conf port_conf;		/**< port configuration information */
	struct rte_eth_dev_info dev_info;	/**< PCI info + driver name */
} port_info_t;

extern port_info_t info[RTE_MAX_ETHPORTS];	/**< Port information */

void compress_and_encrypt_cfg_ports(void);

#endif  /* _COMPRESS_PORT_CFG_H_ */