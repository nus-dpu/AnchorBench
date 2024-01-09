#ifndef FIREWALL_H_
#define FIREWALL_H_

#include <doca_flow.h>
#include "flow_parser.h"

#include <dpdk_utils.h>
#include <utils.h>

#define NR_QUEUES   1
#define MAX_CORES   8

struct app_config {
    int nr_rules;
    int nr_cores;
    int nr_queues;
};

extern struct app_config cfg;

/* Per worker context */
struct worker_ctx {
	uint8_t		queue_id;               /* Queue id */
	uint16_t	ingress_port;           /* Current ingress port */
	uint64_t	dropped_packets;        /* Packets that failed to transmit */
	uint64_t	processed_packets;      /* Packets that were processed by this worker */
	struct rte_mempool *pkt_mempool;    /* DPDK buffer */
};

extern struct worker_ctx ctx[MAX_CORES];

/*
 * Register firewall params into argp
 *
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 *
 * @NOTE: In case of failure, all already allocated resource are freed
 */
doca_error_t register_firewall_params(void);

extern int nr_rules;

int sw_launch_one_lcore(__rte_unused void *dummy);

#endif /* FIREWALL_H_ */
