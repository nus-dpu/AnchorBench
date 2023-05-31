#ifndef _REGEX_H_
#define _REGEX_H_

#define _GNU_SOURCE
#define __USE_GNU
#include <sched.h>
#include <pthread.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <math.h>
#include <bsd/string.h>
#include <utils.h>

#include <doca_argp.h>
#include <doca_log.h>
#include <doca_buf.h>
#include <doca_buf_inventory.h>
#include <doca_ctx.h>
#include <doca_dev.h>
#include <doca_error.h>
#include <doca_mmap.h>
#include <doca_regex.h>
#include <doca_regex_mempool.h>

#include <common.h>
#include <mempool.h>

#define WORKQ_DEPTH 128

#define PACKET_BURST	32

#define MAX_NR_CORE 8

#define MAX_FILE_NAME 255			/* Maximal length of file path */
#define MAX_ARG_SIZE 256			/* Maximum size of input argument */

#define M_1				1048576

#define NB_BUF	1024
#define BUF_SIZE	1024

#define MAX_REGEX_RESPONSE_SIZE 256	/* Maximal size of RegEx jobs response */

struct regex_ctx {
	struct doca_pci_bdf *pci_address;		/* RegEx PCI address to use */
	struct mempool *buf_mempool;
	struct doca_buf_inventory *buf_inv;		/* Pool of doca_buf objects */
	struct doca_dev *dev;				/* DOCA device */
	struct doca_mmap *mmap;				/* DOCA Memory orchestration */
	struct doca_regex *doca_regex;			/* DOCA RegEx interface */
	struct doca_workq *workq;			/* DOCA work queue */

	char *query_buf[PACKET_BURST];
	struct doca_buf *buf[PACKET_BURST];
	struct doca_regex_search_result responses[MAX_REGEX_RESPONSE_SIZE];	/* DOCA RegEx jobs responses */
	struct doca_buf *buffers[MAX_REGEX_RESPONSE_SIZE];			/* Buffers in use for job batch */
};

/* Configuration struct */
struct regex_config {
	char *rules_buffer;			/* Buffer holds the RegEx rules */
	size_t rules_buffer_len;		/* Rules buffer size */
	char pci_address[MAX_ARG_SIZE];		/* RegEx PCI address to use */
	char data[MAX_FILE_NAME];		/* Data to scan file path */
    int nr_core;    /* Number of worker cores */
    double rate;    /* Request generation rate */
	int queue_depth;	/* Work queue depth */

	struct doca_dev *dev;				/* DOCA device */
	struct doca_regex *doca_regex;			/* DOCA RegEx interface */
};

extern struct regex_config cfg;

#define MAX_NR_RULE	1000

struct input_info {
	char line[512];
	int len;
};

struct worker {
	uint64_t interval;
	struct timespec last_enq_time;
};

extern void * regex_work_lcore(void * arg);

extern int data_len;
extern pthread_barrier_t barrier;

#endif  /* _REGEX_H_ */
