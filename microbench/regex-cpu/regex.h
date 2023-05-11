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

#include <common.h>
#include <mempool.h>

#define WORKQ_DEPTH 128

#define MAX_NR_CORE 8

#define MAX_FILE_NAME 255			/* Maximal length of file path */
#define MAX_ARG_SIZE 256			/* Maximum size of input argument */

#define NB_BUF	512
#define BUF_SIZE	128

#define MAX_RULES		16
#define MAX_RULE_LEN	256

struct regex_ctx {
	int nb_regex_rules;
	regex_t regex_rules[MAX_RULES];
};

/* Configuration struct */
struct regex_config {
	char *rules_buffer;			/* Buffer holds the RegEx rules */
	size_t rules_buffer_len;		/* Rules buffer size */
	char rule[MAX_FILE_NAME];		/* Rule path */
	char data[MAX_FILE_NAME];		/* Data to scan file path */
    int nr_core;    /* Number of worker cores */
    double rate;    /* Request generation rate */
};

extern struct regex_config cfg;

#define MAX_NR_RULE	1000

struct input_info {
	char * line;
	int len;
};

struct worker {
	uint64_t interval;
	struct timespec last_enq_time;
};

extern void * regex_work_lcore(void * arg);

extern pthread_barrier_t barrier;

#endif  /* _REGEX_H_ */
