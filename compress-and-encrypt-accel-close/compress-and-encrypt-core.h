#ifndef _COMPRESS_CORE_H_
#define _COMPRESS_CORE_H_

#include <rte_mbuf.h>

#include <doca_buf.h>
#include <doca_buf_inventory.h>
#include <doca_ctx.h>
#include <doca_dev.h>
#include <doca_flow.h>
#include <doca_compress.h>
#include <doca_sha.h>

#define PACKET_BURST 32			/* The number of packets in the rx queue */
#define UDP_PORT 4321				/* DNS packet dst port */
#define UDP_HEADER_SIZE 8			/* UDP header size = 8 bytes (64 bits) */
#define MAX_PORT_STR_LEN 128			/* Maximal length of port name */
#define MAX_DNS_QUERY_LEN 512			/* Maximal length of DNS query */
#define PACKET_MARKER 7				/* Value for marking the matched packets */
#define DNS_PORTS_NUM 2				/* Number of ports that are used by the application */
#define SLEEP_IN_NANOS (1 * 1000)		/* Sample the job every 10 microseconds  */
#define DEFAULT_TIMEOUT_US (10000)		/* Timeout for processing pipe entries */

#define MAX_FILE_NAME 255		/* Maximal length of file path */
#define MAX_REGEX_RESPONSE_SIZE 256	/* Maximal size of RegEx jobs response */
#define COMPRESS_MAX_FLOWS 1024	/* Maximal number of FLOWS in application pipes */

/* IP security configuration structure */
struct compress_and_encrypt_cfg {
	struct application_dpdk_config *dpdk_cfg;	/* App DPDK configuration struct */
	struct doca_pci_bdf pci_address;		/* RegEx PCI address to use */
	char rules_file_path[MAX_FILE_NAME];		/* Path to RegEx rules file */
	struct doca_dev *dev;				/* DOCA device */
	struct doca_compress *doca_compress;			/* DOCA Compress interface */
	struct doca_sha *doca_sha;			/* DOCA SHA interface */
};

/* Context structure per DPDK thread */
struct compress_and_encrypt_ctx {
	int queue_id;								/* Queue ID */
	char **queries;								/* Holds DNS queries */
	struct compress_and_encrypt_cfg *app_cfg;					/* App config struct */
	struct doca_mmap *mmap;
	struct doca_buf_inventory *buf_inventory;				/* DOCA buffer inventory */
	struct doca_workq *workq;						/* DOCA work queue */

	struct timespec ts[PACKET_BURST];
	char *query_buf[PACKET_BURST];
	int query_len[PACKET_BURST];
	char *result_buf[PACKET_BURST];
	struct doca_buf *src_buf[PACKET_BURST];
	struct doca_buf *dst_buf[PACKET_BURST];
};

extern __thread int start_flag;
extern __thread int done_flag;
extern __thread struct timeval start;

#define MAX_NR_LATENCY	(128 * 1024)
extern __thread int nr_latency;
extern __thread uint64_t latency[MAX_NR_LATENCY];

int handle_packets_received(int pid, struct compress_and_encrypt_ctx *worker_ctx, struct rte_mbuf **packets, uint16_t packets_received);
uint32_t dpdk_send_pkts(int pid, int qid);

#endif  /* _COMPRESS_CORE_H_ */