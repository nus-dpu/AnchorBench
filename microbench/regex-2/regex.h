#ifndef _REGEX_H_
#define _REGEX_H_

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <math.h>

#include <doca_buf.h>
#include <doca_buf_inventory.h>
#include <doca_ctx.h>
#include <doca_dev.h>
#include <doca_error.h>
#include <doca_log.h>
#include <doca_mmap.h>
#include <doca_regex.h>
#include <doca_regex_mempool.h>

#include <common.h>
#include <mempool.h>

#define WORKQ_DEPTH 128
#define MAX_NR_CORE 8
#define MAX_FILE_NAME 255			/* Maximal length of file path */
#define MAX_ARG_SIZE 256			/* Maximum size of input argument */

struct regex_ctx {
	struct doca_pci_bdf *pci_address;		/* RegEx PCI address to use */
	struct mempool *buf_mempool;
	// struct doca_buf *buf[NB_BUF];			/* active job buffer */
	struct doca_buf_inventory *buf_inv;		/* Pool of doca_buf objects */
	struct doca_dev *dev;				/* DOCA device */
	struct doca_mmap *mmap;				/* DOCA Memory orchestration */
	struct doca_regex *doca_regex;			/* DOCA RegEx interface */
	struct doca_workq *workq;			/* DOCA work queue */
	struct doca_regex_search_result *results;	/* Pointer to array of result objects */
};

/* Configuration struct */
struct regex_config {
	char *rules_buffer;			/* Buffer holds the RegEx rules */
	size_t rules_buffer_len;		/* Rules buffer size */
	char pci_address[MAX_ARG_SIZE];		/* RegEx PCI address to use */
	char data[MAX_FILE_NAME];		/* Data to scan file path */
    int nr_core;    /* Number of worker cores */

	struct doca_dev *dev;				/* DOCA device */
	struct doca_regex *doca_regex;			/* DOCA RegEx interface */
};

extern int regex_work_lcore(void * arg);

#endif  /* _REGEX_H_ */