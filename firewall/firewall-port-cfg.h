#ifndef FIREWALL_PORT_CFG_H_
#define FIREWALL_PORT_CFG_H_

#include <stdio.h>
#include <string.h>

#include "firewall-constants.h"

struct mbuf_table {
	uint16_t len;
	struct rte_mbuf *m_table[DEFAULT_PKT_BURST];
};

void firewall_config_ports(int nr_cores, int nr_queues, int nr_hairpin_queues);

#endif  /* FIREWALL_PORT_CFG_H_ */