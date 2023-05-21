#ifndef _DMA_H_
#define _DMA_H_

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
#include <doca_dma.h>

#include <common.h>
#include <mempool.h>

#define WORKQ_DEPTH 128

#define MAX_NR_CORE 8

#define MAX_FILE_NAME 255			/* Maximal length of file path */
#define MAX_ARG_SIZE 256			/* Maximum size of input argument */

#define NB_BUF	2048
#define BUF_SIZE	1200

#define M_1				1048576

struct dma_ctx {
	struct doca_pci_bdf *pci_address;		/* DMA PCI address to use */

	struct mempool *src_buf_mempool;
	struct doca_buf_inventory *src_buf_inv;		/* Pool of doca_buf objects */
	struct doca_mmap *remote_mmap;
	char *remote_addr;
	size_t remote_addr_len;

	struct mempool *dst_buf_mempool;
	struct doca_buf_inventory *dst_buf_inv;		/* Pool of doca_buf objects */
	struct doca_mmap *mmap;				/* DOCA Memory orchestration */

	struct doca_dev *dev;				/* DOCA device */
	struct doca_dma *doca_dma;			/* DOCA DMA interface */
	struct doca_workq *workq;			/* DOCA work queue */
};

struct worker {
	uint64_t interval;
	struct timespec last_enq_time;
};

extern void * dma_work_lcore(void * arg);

extern pthread_barrier_t barrier;

#endif  /* _SHA_H_ */
