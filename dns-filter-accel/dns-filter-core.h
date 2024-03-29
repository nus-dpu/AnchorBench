#ifndef _DNS_FILTER_CORE_H_
#define _DNS_FILTER_CORE_H_

#include <rte_mbuf.h>

#include <doca_buf.h>
#include <doca_buf_inventory.h>
#include <doca_ctx.h>
#include <doca_dev.h>
#include <doca_flow.h>
#include <doca_regex.h>

#define PACKET_BURST 32			/* The number of packets in the rx queue */
#define DNS_PORT 53				/* DNS packet dst port */
#define UDP_HEADER_SIZE 8			/* UDP header size = 8 bytes (64 bits) */
#define MAX_PORT_STR_LEN 128			/* Maximal length of port name */
#define MAX_DNS_QUERY_LEN 512			/* Maximal length of DNS query */
#define PACKET_MARKER 7				/* Value for marking the matched packets */
#define DNS_PORTS_NUM 2				/* Number of ports that are used by the application */
#define SLEEP_IN_NANOS (1 * 1000)		/* Sample the job every 10 microseconds  */
#define DEFAULT_TIMEOUT_US (10000)		/* Timeout for processing pipe entries */

#define MAX_FILE_NAME 255		/* Maximal length of file path */
#define MAX_REGEX_RESPONSE_SIZE 256	/* Maximal size of RegEx jobs response */
#define DNS_FILTER_MAX_FLOWS 1024	/* Maximal number of FLOWS in application pipes */

/* DNS configuration structure */
struct dns_filter_config {
	struct doca_flow_pipe **drop_pipes;		/* Holds ports drop pipes */
	struct application_dpdk_config *dpdk_cfg;	/* App DPDK configuration struct */
	struct doca_pci_bdf pci_address;		/* RegEx PCI address to use */
	char rules_file_path[MAX_FILE_NAME];		/* Path to RegEx rules file */

	int nr_core;    /* Number of worker cores */
    double rate;    /* Request generation rate */
	int queue_depth;	/* Work queue depth */

	struct doca_dev *dev;				/* DOCA device */
	struct doca_regex *doca_reg;			/* DOCA RegEx interface */
};

/* Context structure per DPDK thread */
struct dns_worker_ctx {
	int queue_id;								/* Queue ID */
	struct dns_filter_config *app_cfg;					/* App config struct */

	struct doca_pci_bdf *pci_address;		/* RegEx PCI address to use */
	struct mempool *buf_mempool;
	struct doca_buf_inventory *buf_inv;				/* DOCA buffer inventory */
	struct doca_mmap *mmap;
	struct doca_workq *workq;						/* DOCA work queue */
};

extern __thread int start_flag;
extern __thread int done_flag;
extern __thread struct timeval start;

extern struct dns_filter_config app_cfg;

#define MAX_NR_LATENCY	(128 * 1024)
extern __thread int nr_latency;
extern __thread uint64_t latency[MAX_NR_LATENCY];

int handle_packets_received(int pid, struct dns_worker_ctx *worker_ctx, struct rte_mbuf **packets, uint16_t packets_received);

#endif  /* _DNS_FILTER_CORE_H_ */