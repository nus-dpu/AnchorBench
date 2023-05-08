/*
 * Copyright (c) 2022 NVIDIA CORPORATION & AFFILIATES, ALL RIGHTS RESERVED.
 *
 * This software product is a proprietary product of NVIDIA CORPORATION &
 * AFFILIATES (the "Company") and all right, title, and interest in and to the
 * software product, including all associated intellectual property rights, are
 * and shall remain exclusively with the Company.
 *
 * This software product is governed by the End User License Agreement
 * provided with the software product.
 *
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

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
#include <chrono>

DOCA_LOG_REGISTER(REGEX_SCAN::SAMPLE);

#define NB_CHUNKS 128				/* Number of chunks to send to RegEx engine */
#define SLEEP_IN_NANOS (10 * 1000)	/* Sample the job every 10 microseconds  */

#define NB_BUF	128
#define BUF_SIZE	128

#define NSEC_PER_SEC    1000000000L

/* Sample context structure */
struct regex_scan_ctx {
	char *data_buffer;				/* Data buffer */
	size_t data_buffer_len;				/* Length of data buffer */
	char *rules_buffer;				/* Rules buffer */
	size_t rules_buffer_len;			/* Length of rules buffer */
	int chunk_len;					/* size of chunk to send to RegEx */
	struct doca_pci_bdf *pci_address;		/* RegEx PCI address to use */
	// char * data_buf[NB_BUF];
	struct mempool *buf_mempool;
	struct doca_buf *buf[NB_BUF];			/* active job buffer */
	struct doca_buf_inventory *buf_inv;		/* Pool of doca_buf objects */
	struct doca_dev *dev;				/* DOCA device */
	struct doca_mmap *mmap;				/* DOCA Memory orchestration */
	struct doca_regex *doca_regex;			/* DOCA RegEx interface */
	struct doca_workq *workq;			/* DOCA work queue */
	struct doca_regex_search_result *results;	/* Pointer to array of result objects */
};

#define MAX_NR_RULE	1000

struct input_info {
	char * line;
	int len;
};

struct input_info input[MAX_NR_RULE];

/*
 * Printing the RegEx results
 *
 * @regex_cfg [in]: sample RegEx configuration struct
 * @event [in]: DOCA event structure
 */
static void
regex_scan_report_results(struct regex_scan_ctx *regex_cfg, struct doca_event *event)
{
	int offset;
	struct mempool_elt * data_element;
	struct doca_regex_match *ptr;
	struct doca_regex_search_result * const result = (struct doca_regex_search_result *)event->result.ptr;

	if (result->num_matches == 0)
		return;
	ptr = result->matches;
	/* Match start is relative to the whole file data and not the current chunk */
	while (ptr != NULL) {
		data_element = (struct mempool_elt *)event->user_data.ptr;
		// regex_cfg->data_buffer[ptr->match_start + offset + ptr->length] = '\0';
		struct doca_regex_match *const to_release_match = ptr;

		ptr = ptr->next;
		doca_regex_mempool_put_obj(result->matches_mempool, to_release_match);
	}
}

/*
 * Initialize DOCA RegEx resources according to the configuration struct fields
 *
 * @regex_cfg [in]: RegEx configuration struct
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
regex_scan_init(struct regex_scan_ctx *regex_cfg)
{
	doca_error_t result = DOCA_SUCCESS;
	const int mempool_size = 8;

	/* Find doca_dev according to the PCI address */
	result = open_doca_device_with_pci(regex_cfg->pci_address, NULL, &regex_cfg->dev);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("No device matching PCI address found.");
		return result;
	}

	/* Create a DOCA RegEx instance */
	result = doca_regex_create(&(regex_cfg->doca_regex));
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to create RegEx device.");
		return result;
	}

	/* Set the RegEx device as the main HW accelerator */
	result = doca_ctx_dev_add(doca_regex_as_ctx(regex_cfg->doca_regex), regex_cfg->dev);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to set RegEx device.Reason: %s", doca_get_error_string(result));
		return result;
	}

	/* Size per workq memory pool */
	result = doca_regex_set_workq_matches_memory_pool_size(regex_cfg->doca_regex, mempool_size);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable set matches mempool size. Reason: %s", doca_get_error_string(result));
		return result;
	}

	/* Load compiled rules into the RegEx */
	result = doca_regex_set_hardware_compiled_rules(
		regex_cfg->doca_regex, regex_cfg->rules_buffer, regex_cfg->rules_buffer_len);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to program rules file. Reason: %s", doca_get_error_string(result));
		return result;
	}

	/* Create and start buffer inventory */
	result = doca_buf_inventory_create(NULL, NB_BUF, DOCA_BUF_EXTENSION_NONE, &regex_cfg->buf_inv);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to create buffer inventory. Reason: %s", doca_get_error_string(result));
		return result;
	}

	result = doca_buf_inventory_start(regex_cfg->buf_inv);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to start buffer inventory. Reason: %s", doca_get_error_string(result));
		return result;
	}

	/* Create and start mmap */
	result = doca_mmap_create(NULL, &regex_cfg->mmap);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to create memory map. Reason: %s", doca_get_error_string(result));
		return result;
	}

	result = doca_mmap_start(regex_cfg->mmap);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to start memory map. Reason: %s", doca_get_error_string(result));
		return result;
	}

	result = doca_mmap_dev_add(regex_cfg->mmap, regex_cfg->dev);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to add device to memory map. Reason: %s", doca_get_error_string(result));
		return result;
	}

	regex_cfg->buf_mempool = mempool_create(NB_BUF, BUF_SIZE);

	// result = doca_mmap_populate(regex_cfg->mmap, regex_cfg->data_buffer, regex_cfg->data_buffer_len, sysconf(_SC_PAGESIZE),
	result = doca_mmap_populate(regex_cfg->mmap, regex_cfg->buf_mempool->addr, regex_cfg->buf_mempool->size, sysconf(_SC_PAGESIZE),
				    NULL, NULL);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to add memory region to memory map. Reason: %s", doca_get_error_string(result));
		return result;
	}

	uint32_t nb_free, nb_total;
	nb_free = nb_total = 0;

	printf(" >> total number of element: %d, free element: %d\n", 
			doca_buf_inventory_get_num_elements(regex_cfg->buf_inv, &nb_total), doca_buf_inventory_get_num_free_elements(regex_cfg->buf_inv, &nb_free));

	// for (int i = 0; i < NB_BUF; i++) {
	// 	/* Create array of pointers (char*) to hold the queries */
	// 	regex_cfg->data_buf[i] = regex_cfg->data_buffer + BUF_SIZE * i;
	// 	if (regex_cfg->data_buf[i] == NULL) {
	// 		DOCA_LOG_ERR("Dynamic allocation failed");
	// 		return DOCA_ERROR_NO_MEMORY;
	// 	}
	// }

	regex_cfg->results = (struct doca_regex_search_result *)calloc(NB_CHUNKS, sizeof(struct doca_regex_search_result));
	if (regex_cfg->results == NULL) {
		DOCA_LOG_ERR("Unable to add allocate results storage");
		return DOCA_ERROR_NO_MEMORY;
	}

	return result;
}

/*
 * Enqueue job to DOCA RegEx qp
 *
 * @regex_cfg [in]: regex_scan_ctx configuration struct
 * @job_request [in]: RegEx job request, already initialized with first chunk.
 * @remaining_bytes [in]: the remaining bytes to send all jobs (chunks).
 * @return: number of the enqueued jobs or -1
 */
static int
regex_scan_enq_job(struct regex_scan_ctx * regex_cfg, char * data, int data_len) {
	doca_error_t result;
	int nb_enqueued = 0;
	uint32_t nb_total = 0;
	uint32_t nb_free = 0;

	doca_buf_inventory_get_num_elements(regex_cfg->buf_inv, &nb_total);
	doca_buf_inventory_get_num_free_elements(regex_cfg->buf_inv, &nb_free);

	if (nb_free != 0) {
		// struct doca_buf *buf;
		struct mempool_elt * buf_element;
		char * data_buf;
		void *mbuf_data;

		/* Get one free element from the mempool */
		mempool_get(regex_cfg->buf_mempool, &buf_element);
		/* Get the memory segment */
		data_buf = buf_element->addr;

		memcpy(data_buf, data, data_len);

		/* Create a DOCA buffer  for this memory region */
		result = doca_buf_inventory_buf_by_addr(regex_cfg->buf_inv, regex_cfg->mmap, data_buf, BUF_SIZE, &buf_element->buf);
		if (result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Failed to allocate DOCA buf");
			return nb_enqueued;
		}

		printf("\t buf element: %p, doca buf: %p\n", buf_element, data_buf);
		doca_buf_get_data(buf_element->buf, &mbuf_data);
		doca_buf_set_data(buf_element->buf, mbuf_data, BUF_SIZE);

		struct doca_regex_job_search const job_request = {
				.base = {
					.type = DOCA_REGEX_JOB_SEARCH,
					.ctx = doca_regex_as_ctx(regex_cfg->doca_regex),
					.user_data = { .ptr = buf_element },
				},
				.buffer = buf_element->buf,
				.rule_group_ids = {1, 0, 0, 0},
				.result = regex_cfg->results + nb_enqueued,
				.allow_batching = false,
		};

		result = doca_workq_submit(regex_cfg->workq, (struct doca_job *)&job_request);
		if (result == DOCA_ERROR_NO_MEMORY) {
			doca_buf_refcount_rm(buf_element->buf, NULL);
			return nb_enqueued; /* qp is full, try to dequeue. */
		}
		if (result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Unable to enqueue job. Reason: %s", doca_get_error_string(result));
			return -1;
		}
		// *remaining_bytes -= job_size; /* Update remaining bytes to scan. */
		nb_enqueued++;
		--nb_free;
	}

	return nb_enqueued;
}

/*
 * Dequeue jobs responses
 *
 * @regex_cfg [in]: regex_scan_ctx configuration struct
 * @chunk_len [in]: job chunk size
 * @return: number of the dequeue jobs or a negative posix status code.
 */
static int
regex_scan_deq_job(struct regex_scan_ctx *regex_cfg, int chunk_len)
{
	doca_error_t result;
	int nb_dequeued = 0;
	struct doca_event event = {0};
	struct timespec ts;
	uint32_t nb_free = 0;
	uint32_t nb_total = 0;
	struct mempool_elt * buf_element;

	do {
		result = doca_workq_progress_retrieve(regex_cfg->workq, &event, DOCA_WORKQ_RETRIEVE_FLAGS_NONE);
		if (result == DOCA_SUCCESS) {
			buf_element = (struct mempool_elt *)event.user_data.ptr;
			/* release the buffer back into the pool so it can be re-used */
			doca_buf_inventory_get_num_elements(regex_cfg->buf_inv, &nb_total);
			doca_buf_inventory_get_num_free_elements(regex_cfg->buf_inv, &nb_free);
			/* Report the scan result of RegEx engine */
			regex_scan_report_results(regex_cfg, &event);
			/* release the buffer back into the pool so it can be re-used */
			doca_buf_refcount_rm(buf_element->buf, NULL);
			/* Put the element back into the mempool */
			mempool_put(regex_cfg->buf_mempool, buf_element);
			++nb_dequeued;
		} else if (result == DOCA_ERROR_AGAIN) {
			/* Wait for the job to complete */
			ts.tv_sec = 0;
			ts.tv_nsec = SLEEP_IN_NANOS;
			nanosleep(&ts, &ts);
		} else {
			DOCA_LOG_ERR("Failed to dequeue results. Reason: %s", doca_get_error_string(result));
			return -1;
		}

	} while (result == DOCA_SUCCESS);

	return nb_dequeued;
}

/*
 * RegEx scan cleanup, destroy all DOCA RegEx resources
 *
 * @regex_cfg [in]: sample RegEx configuration struct
 */
static void
regex_scan_destroy(struct regex_scan_ctx *regex_cfg)
{
	if (regex_cfg->workq != NULL) {
		doca_ctx_workq_rm(doca_regex_as_ctx(regex_cfg->doca_regex), regex_cfg->workq);
		doca_workq_destroy(regex_cfg->workq);
	}

	doca_ctx_stop(doca_regex_as_ctx(regex_cfg->doca_regex));
	doca_regex_destroy(regex_cfg->doca_regex);
	regex_cfg->doca_regex = NULL;

	if (regex_cfg->results != NULL) {
		free(regex_cfg->results);
		regex_cfg->results = NULL;
	}

	if (regex_cfg->mmap != NULL) {
		doca_mmap_dev_rm(regex_cfg->mmap, regex_cfg->dev);
		doca_mmap_stop(regex_cfg->mmap);
		doca_mmap_destroy(regex_cfg->mmap);
		regex_cfg->mmap = NULL;
	}

	if (regex_cfg->buf_inv != NULL) {
		doca_buf_inventory_stop(regex_cfg->buf_inv);
		doca_buf_inventory_destroy(regex_cfg->buf_inv);
		regex_cfg->buf_inv = NULL;
	}

	if (regex_cfg->dev != NULL) {
		doca_dev_close(regex_cfg->dev);
		regex_cfg->dev = NULL;
	}
}

static inline uint64_t CurrentTime_nanoseconds() {
    return std::chrono::duration_cast<std::chrono::nanoseconds>
              (std::chrono::high_resolution_clock::now().time_since_epoch()).count();
}

/*
 * Run DOCA RegEx sample
 *
 * @data_buffer [in]: User data used to find the matches
 * @data_buffer_len [in]: data_buffer length
 * @pci_addr [in]: pci address for HW RegEx device
 * @rules_buffer [in]: Rules data (compiled rules(rof2.binary))
 * @rules_buffer_len [in]: rules_buffer length
 * @return: 0 on success and negative value otherwise.
 */
int
regex_scan(char *data_buffer, size_t data_buffer_len, struct doca_pci_bdf *pci_addr, char *rules_buffer,
	size_t rules_buffer_len)
{
	if (pci_addr == NULL || rules_buffer == NULL || rules_buffer_len == 0)
		return DOCA_ERROR_INVALID_VALUE;

	doca_error_t result;
	uint32_t remaining_bytes, nb_dequeued = 0, nb_enqueued = 0;
	const int nb_chunks = NB_CHUNKS;
	struct regex_scan_ctx rgx_cfg = {0};
	int ret;

	FILE * fp;
    char * line = NULL;
    size_t len = 0;
    ssize_t read;
	int nr_rule = 0;
	int nr_core = 1;
	double rate = 1.0;
    Generator<uint64_t> * arrival = new ExponentialGenerator(nr_core * 1.0e6 / rate);
	uint64_t start, last_enq_time;
	uint64_t current_time, interval = 0;

	start = last_enq_time = CurrentTime_nanoseconds();

	/* Set DOCA RegEx configuration fields in regex_cfg according to our sample */
	rgx_cfg.data_buffer = data_buffer;
	rgx_cfg.data_buffer_len = data_buffer_len;
	rgx_cfg.pci_address = pci_addr;
	rgx_cfg.rules_buffer = rules_buffer;
	rgx_cfg.rules_buffer_len = rules_buffer_len;
	rgx_cfg.chunk_len = (rgx_cfg.data_buffer_len < nb_chunks) ? rgx_cfg.data_buffer_len
								  : 1 + (rgx_cfg.data_buffer_len / nb_chunks);

	/* Init DOCA RegEx */
	if (regex_scan_init(&rgx_cfg) != DOCA_SUCCESS)
		return -1;

	/* Start DOCA RegEx */
	result = doca_ctx_start(doca_regex_as_ctx(rgx_cfg.doca_regex));
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to start DOCA RegEx. [%s]", doca_get_error_string(result));
		regex_scan_destroy(&rgx_cfg);
		return result;
	}

	result = doca_workq_create(NB_CHUNKS, &(rgx_cfg.workq));
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to create work queue. Reason: %s", doca_get_error_string(result));
		regex_scan_destroy(&rgx_cfg);
		return result;
	}

	result = doca_ctx_workq_add(doca_regex_as_ctx(rgx_cfg.doca_regex), rgx_cfg.workq);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to attach work queue to RegEx. Reason: %s", doca_get_error_string(result));
		regex_scan_destroy(&rgx_cfg);
		return result;
	}

	fp = fopen("../dns.txt", "r");
    if (fp == NULL) {
        return -1;
	}
#if 0
	/* The main loop, enqueues jobs (chunks) and dequeues for results. */
	while ((read = getline(&line, &len, fp)) != -1) {
		// printf("Retrieved line of length %zu:\n", read);
		// printf("%s", line);
		/* Enqueue jobs */
		ret = regex_scan_enq_job(&rgx_cfg, line, read);
		if (ret < 0) {
			DOCA_LOG_ERR("Failed to enqueue jobs");
			regex_scan_destroy(&rgx_cfg);
			return ret;
		}

		nb_enqueued += ret;

		/* Dequeue responses */
		ret = regex_scan_deq_job(&rgx_cfg, rgx_cfg.chunk_len);
		if (ret < 0) {
			DOCA_LOG_ERR("Failed to dequeue jobs responses");
			regex_scan_destroy(&rgx_cfg);
			return ret;
		}
		nb_dequeued += ret;
	}
#endif
	while ((read = getline(&line, &len, fp)) != -1) {
		info[nr_rule].line = line;
		info[nr_rule].len = len;
		nr_rule++;
	}

	while (1) {
		current_time = CurrentTime_nanoseconds();
		if (current - start > 10 * NSEC_PER_SEC) {
			printf("Enqueue: %u, %6.2f(RPS)\n", nb_enqueued, nb_enqueued * 1000000000 / (current - start));
			printf("Dequeue: %u, %6.2f(RPS)\n", nb_dequeued, nb_dequeued * 1000000000 / (current - start));
			break;
		}

		if (current_time - last_enq_time > interval) {
			ret = regex_scan_enq_job(&rgx_cfg, line, read);
			if (ret < 0) {
				DOCA_LOG_ERR("Failed to enqueue jobs");
				continue;
			} else {
				nb_enqueued++;
				interval = arrival->Next();
				last_enq_time = current_time;
			}
		}

		ret = regex_scan_deq_job(&rgx_cfg, rgx_cfg.chunk_len);
		if (ret < 0) {
			DOCA_LOG_ERR("Failed to dequeue jobs responses");
			continue;
		} else {
			nb_dequeued++;
		}
	}

	/* RegEx scan recognition cleanup */
	regex_scan_destroy(&rgx_cfg);
	return 0;
}
