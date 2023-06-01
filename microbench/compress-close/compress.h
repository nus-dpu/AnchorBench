#ifndef _COMPRESS_H_
#define _COMPRESS_H_

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
#include <doca_compress.h>

#include <common.h>
#include <mempool.h>

#define WORKQ_DEPTH 128

#define MAX_NR_CORE 8

#define MAX_FILE_NAME 255			/* Maximal length of file path */
#define MAX_ARG_SIZE 256			/* Maximum size of input argument */

#define NB_BUF	1024
#define BUF_SIZE	1024

#define SHA_DATA_LEN	1024
#define M_1				1048576

#define PACKET_BURST	32

struct compress_ctx {
	struct doca_pci_bdf *pci_address;		/* Compression PCI address to use */
	struct mempool *buf_mempool;

	struct doca_buf_inventory *buf_inv;		/* Pool of doca_buf objects */
	struct doca_dev *dev;				/* DOCA device */
	struct doca_mmap *mmap;				/* DOCA Memory orchestration */
	struct doca_compress *doca_compress;			/* DOCA Compression interface */
	struct doca_workq *workq;			/* DOCA work queue */

	char **queries;								/* Holds DNS queries */
	struct timespec ts[PACKET_BURST];
	char *query_buf[PACKET_BURST];
	char *result_buf[PACKET_BURST];
	struct doca_buf *src_buf[PACKET_BURST];
	struct doca_buf *dst_buf[PACKET_BURST];
};

/* Configuration struct */
struct compress_config {
	char pci_address[MAX_ARG_SIZE];		/* Compression PCI address to use */
	char data[MAX_FILE_NAME];		/* Data to scan file path */
    int nr_core;    /* Number of worker cores */
    double rate;    /* Request generation rate */
	int queue_depth;	/* Work queue depth */

	struct doca_dev *dev;				/* DOCA device */
	struct doca_compress *doca_compress;			/* DOCA Compress interface */
};

extern struct compress_config cfg;

struct worker {
	uint64_t interval;
	struct timespec last_enq_time;
};

extern void * compress_work_lcore(void * arg);

extern int data_len;
extern pthread_barrier_t barrier;

#endif  /* _SHA_H_ */
