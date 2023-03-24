#ifndef _DNS_FILTER_CORE_H_
#define _DNS_FILTER_CORE_H_

#include <doca_buf.h>
#include <doca_buf_inventory.h>
#include <doca_ctx.h>
#include <doca_dev.h>
#include <doca_flow.h>
#include <doca_regex.h>

#define MAX_FILE_NAME 255		/* Maximal length of file path */
#define MAX_REGEX_RESPONSE_SIZE 256	/* Maximal size of RegEx jobs response */
#define DNS_FILTER_MAX_FLOWS 1024	/* Maximal number of FLOWS in application pipes */

/* DNS configuration structure */
struct dns_filter_config {
	struct doca_flow_pipe **drop_pipes;		/* Holds ports drop pipes */
	struct application_dpdk_config *dpdk_cfg;	/* App DPDK configuration struct */
	struct doca_pci_bdf pci_address;		/* RegEx PCI address to use */
	char rules_file_path[MAX_FILE_NAME];		/* Path to RegEx rules file */
	struct doca_dev *dev;				/* DOCA device */
	struct doca_regex *doca_reg;			/* DOCA RegEx interface */
};

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