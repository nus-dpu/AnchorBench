#ifndef _DNS_FILTER_CORE_H_
#define _DNS_FILTER_CORE_H_

#define MAX_FILE_NAME 255		/* Maximal length of file path */
#define MAX_REGEX_RESPONSE_SIZE 256	/* Maximal size of RegEx jobs response */
#define DNS_FILTER_MAX_FLOWS 1024	/* Maximal number of FLOWS in application pipes */

/* Context structure per DPDK thread */
struct dns_worker_ctx {
	int queue_id;								/* Queue ID */
	char **queries;								/* Holds DNS queries */
	struct dns_filter_config *app_cfg;					/* App config struct */
	struct doca_regex_search_result responses[MAX_REGEX_RESPONSE_SIZE];	/* DOCA RegEx jobs responses */
	struct doca_buf *buffers[MAX_REGEX_RESPONSE_SIZE];			/* Buffers in use for job batch */
	struct doca_buf_inventory *buf_inventory;				/* DOCA buffer inventory */
	struct doca_workq *workq;						/* DOCA work queue */
};

int handle_packets_received(struct dns_worker_ctx *worker_ctx, struct rte_mbuf **packets, uint16_t packets_received);

#endif  /* _DNS_FILTER_CORE_H_ */