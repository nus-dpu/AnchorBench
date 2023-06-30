#ifndef _SHA_H_
#define _SHA_H_

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
#include <doca_sha.h>
#include <doca_regex.h>

#include <common.h>
#include <regex_mempool.h>
#include <sha_mempool.h>

#define WORKQ_DEPTH 128

#define MAX_NR_CORE 8

#define MAX_FILE_NAME 255			/* Maximal length of file path */
#define MAX_ARG_SIZE 256			/* Maximum size of input argument */

#define NB_BUF			128

/* SHA buffer size */
#define SHA_NB_BUF		256
#define SHA_BUF_SIZE	128

/* SHA buffer size */
#define REGEX_NB_BUF	128
#define REGEX_BUF_SIZE	128

#define K_16			(16 * 1024)
#define M_1				(1024 * 1024)

struct sha_ctx {
	struct sha_mempool *buf_mempool;
	struct doca_buf_inventory *buf_inv;		/* Pool of doca_buf objects */
	struct doca_mmap *mmap;				/* DOCA Memory orchestration */
	struct doca_sha *doca_sha;			/* DOCA SHA interface */
	struct doca_workq *workq;			/* DOCA work queue */

	char * ptr;
	char * input;
	int input_size;
	int len;

	int nb_enqueued;
	int nb_dequeued;
};

struct regex_input {
	char line[256];
	int len;
};

struct regex_ctx {
	struct regex_mempool *buf_mempool;
	struct doca_buf_inventory *buf_inv;		/* Pool of doca_buf objects */
	struct doca_mmap *mmap;				/* DOCA Memory orchestration */
	struct doca_regex *doca_regex;			/* DOCA RegEx interface */

	int index;
	struct regex_input *input;
	int nr_input;

	int nb_enqueued;
	int nb_dequeued;
};

struct app_ctx {
	struct doca_dev *dev;			/* DOCA work queue */
	struct doca_workq *workq;			/* DOCA work queue */

	struct sha_ctx sha_ctx;
	struct regex_ctx regex_ctx;
};

/* Configuration struct */
struct app_config {
	char pci_address[MAX_ARG_SIZE];		/* SHA PCI address to use */
	char config_file[MAX_FILE_NAME];
    int nr_core;    /* Number of worker cores */
    double rate;    /* SHA request generation rate */
	float sha_proportion;
	float regex_proportion;
	int queue_depth;	/* Work queue depth */
	char * rules_buffer;			/* Buffer holds the RegEx rules */
	size_t rules_buffer_len;		/* Rules buffer size */

	struct doca_dev *dev;				/* DOCA device */
	struct doca_sha *doca_sha;			/* DOCA SHA interface */
	struct doca_regex *doca_regex;		/* DOCA RegEx interface */
};

extern struct app_config cfg;

#define MAX_NR_RULE	1000

struct input_info {
	char * line;
	int len;
};

struct worker {
	uint64_t interval;
	struct timespec last_enq_time;
};

extern void * multiaccel_work_lcore(void * arg);

extern int data_len;
extern pthread_barrier_t barrier;

struct lat_info {
	int type;
	uint64_t start;
	uint64_t end;
};

#define REGEX_JOB	1
#define SHA_JOB		2

#define NSEC_PER_SEC    1000000000L
#define TIMESPEC_TO_NSEC(t)	(((t).tv_sec * NSEC_PER_SEC) + ((t).tv_nsec))

#define MAX_NR_LATENCY	(32 * 1024)

extern __thread int nr_latency;
extern __thread bool start_record;
extern __thread struct lat_info * latency;

int sha_enq_job(struct sha_ctx * ctx);
int sha_deq_job(struct sha_ctx * ctx, struct doca_event * event, struct timespec * now);
int regex_enq_job(struct regex_ctx * ctx);
int regex_deq_job(struct regex_ctx * ctx, struct doca_event * event, struct timespec * now);

#endif  /* _SHA_H_ */
