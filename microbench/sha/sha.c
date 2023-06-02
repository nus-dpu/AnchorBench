#include "sha.h"

#include <assert.h>
#include <rte_cycles.h>

DOCA_LOG_REGISTER(SHA::CORE);

#define NSEC_PER_SEC    1000000000L

#define TIMESPEC_TO_NSEC(t)	((t.tv_sec * NSEC_PER_SEC) + (t.tv_nsec))

#define MAX_NR_LATENCY	(128 * 1024)

__thread struct input_info input[MAX_NR_RULE];

__thread int nr_latency = 0;
__thread uint64_t latency[MAX_NR_LATENCY];

__thread unsigned int seed;
__thread struct drand48_data drand_buf;

uint64_t diff_timespec(struct timespec * t1, struct timespec * t2) {
	struct timespec diff = {.tv_sec = t2->tv_sec - t1->tv_sec, .tv_nsec = t2->tv_nsec - t1->tv_nsec};
	if (diff.tv_nsec < 0) {
		diff.tv_nsec += NSEC_PER_SEC;
		diff.tv_sec--;
	}
	return TIMESPEC_TO_NSEC(diff);
}

double ran_expo(double mean) {
    double u, x;
    drand48_r(&drand_buf, &x);
    // u = x / RAND_MAX;
    return -log(1 - x) * mean;
#if 0
    double u;
    u = (double) rand_r(&seed) / RAND_MAX;
    return -log(1- u) * mean;
#endif
}

/*
 * Enqueue job to DOCA SHA qp
 *
 * @sha_ctx [in]: sha_ctx configuration struct
 * @job_request [in]: SHA job request, already initialized with first chunk.
 * @remaining_bytes [in]: the remaining bytes to send all jobs (chunks).
 * @return: number of the enqueued jobs or -1
 */
static int sha_enq_job(struct sha_ctx * ctx, char * data, int data_len) {
	doca_error_t result;
	int nb_enqueued = 0;
	// uint32_t nb_total = 0;
	// uint32_t nb_free = 0;

	// doca_buf_inventory_get_num_elements(ctx->buf_inv, &nb_total);
	// doca_buf_inventory_get_num_free_elements(ctx->buf_inv, &nb_free);

	if (is_mempool_empty(ctx->buf_mempool)) {
		return 0;
	}

	// if (nb_free != 0) {
		struct mempool_elt * src_buf, * dst_buf;
		char * src_data_buf, * dst_data_buf;
		void *mbuf_data;

		/* Get one free element from the mempool */
		mempool_get(ctx->buf_mempool, &src_buf);
		assert(src_buf != NULL);
		mempool_get(ctx->buf_mempool, &dst_buf);
		assert(dst_buf != NULL);
		/* Get the memory segment */
		src_data_buf = src_buf->addr;
		dst_data_buf = dst_buf->addr;

		memset(src_data_buf, 0, BUF_SIZE);
		memcpy(src_data_buf, data, data_len);

		// /* Create a DOCA buffer for this memory region */
		// result = doca_buf_inventory_buf_by_addr(ctx->buf_inv, ctx->mmap, src_data_buf, BUF_SIZE, &src_buf->buf);
		// if (result != DOCA_SUCCESS) {
		// 	DOCA_LOG_ERR("Failed to allocate DOCA buf");
		// 	return nb_enqueued;
		// }

		// /* Create a DOCA buffer for this memory region */
		// result = doca_buf_inventory_buf_by_addr(ctx->buf_inv, ctx->mmap, dst_data_buf, BUF_SIZE, &dst_buf->buf);
		// if (result != DOCA_SUCCESS) {
		// 	DOCA_LOG_ERR("Failed to allocate DOCA buf");
		// 	return nb_enqueued;
		// }

		doca_buf_get_data(src_buf->buf, &mbuf_data);
		doca_buf_set_data(src_buf->buf, mbuf_data, data_len);

		src_buf->response = dst_buf;

	    clock_gettime(CLOCK_MONOTONIC, &src_buf->ts);

		struct doca_sha_job const sha_job = {
			.base = (struct doca_job) {
				.type = DOCA_SHA_JOB_SHA256,
				.flags = DOCA_JOB_FLAGS_NONE,
				.ctx = doca_sha_as_ctx(ctx->doca_sha),
				.user_data = { .ptr = src_buf },
			},
			.resp_buf = dst_buf->buf,
			.req_buf = src_buf->buf,
			.flags = DOCA_SHA_JOB_FLAGS_SHA_PARTIAL_FINAL,
		};

		result = doca_workq_submit(ctx->workq, (struct doca_job *)&sha_job);
		if (result == DOCA_ERROR_NO_MEMORY) {
			// doca_buf_refcount_rm(src_buf->buf, NULL);
			// doca_buf_refcount_rm(dst_buf->buf, NULL);
			mempool_put(ctx->buf_mempool, src_buf);
			mempool_put(ctx->buf_mempool, dst_buf);
			return nb_enqueued; /* qp is full, try to dequeue. */
		}
		if (result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Unable to enqueue job. Reason: %s", doca_get_error_string(result));
			exit(1);
			return -1;
		}
		// *remaining_bytes -= job_size; /* Update remaining bytes to scan. */
		nb_enqueued++;
		// --nb_free;
	// }

	return nb_enqueued;
}

/*
 * Printing the SHA results
 *
 * @sha_ctx [in]: sample SHA configuration struct
 * @event [in]: DOCA event structure
 */
static void sha_report_results(struct doca_buf *buf) {
	uint8_t * resp;
	char sha_output[DOCA_SHA256_BYTE_COUNT * 2 + 1] = {0};
	doca_buf_get_data(buf, (void **)&resp);
	for (int i = 0; i < DOCA_SHA256_BYTE_COUNT; i++)
		sprintf(sha_output + (2 * i), "%02x", resp[i]);
	printf(" result >> %s\n", sha_output);
}

/*
 * Dequeue jobs responses
 *
 * @sha_ctx [in]: sha_ctx configuration struct
 * @chunk_len [in]: job chunk size
 * @return: number of the dequeue jobs or a negative posix status code.
 */
static int sha_deq_job(struct sha_ctx *ctx) {
	doca_error_t result;
	int finished = 0;
	struct doca_event event = {0};
	struct timespec ts;
	uint32_t nb_free = 0;
	uint32_t nb_total = 0;
	struct mempool_elt * src_doca_buf, * dst_doca_buf;
	struct timespec now;

	clock_gettime(CLOCK_MONOTONIC, &now);

	do {
		result = doca_workq_progress_retrieve(ctx->workq, &event, DOCA_WORKQ_RETRIEVE_FLAGS_NONE);
		if (result == DOCA_SUCCESS) {
			src_doca_buf = (struct mempool_elt *)event.user_data.ptr;
			dst_doca_buf = (struct mempool_elt *)src_doca_buf->response;
			if (nr_latency < MAX_NR_LATENCY) {
				latency[nr_latency++] = diff_timespec(&src_doca_buf->ts, &now);
			}
			/* release the buffer back into the pool so it can be re-used */
			// doca_buf_inventory_get_num_elements(ctx->buf_inv, &nb_total);
			// doca_buf_inventory_get_num_free_elements(ctx->buf_inv, &nb_free);
			/* Report the scan result of SHA engine */
			// sha_report_results(dst_doca_buf->buf);
			/* release the buffer back into the pool so it can be re-used */
			// doca_buf_refcount_rm(src_doca_buf->buf, NULL);
			// doca_buf_refcount_rm(dst_doca_buf->buf, NULL);
			/* Put the element back into the mempool */
			mempool_put(ctx->buf_mempool, src_doca_buf);
			mempool_put(ctx->buf_mempool, dst_doca_buf);
			++finished;
		} else if (result == DOCA_ERROR_AGAIN) {
			break;
		} else {
			DOCA_LOG_ERR("Failed to dequeue results. Reason: %s", doca_get_error_string(result));
			return -1;
		}
	} while (result == DOCA_SUCCESS);

	return finished;
}

#define NUM_WORKER	32

void * sha_work_lcore(void * arg) {
    int ret;
	struct sha_ctx * sha_ctx = (struct sha_ctx *)arg;
	uint32_t nb_dequeued = 0, nb_enqueued = 0;
	int cur_ptr = 0;
    FILE * fp;
    char * line = NULL;
    size_t len = 0;
    ssize_t read;
	int nr_rule = 0;
	char * input;
	int input_size;

	double mean = NUM_WORKER * cfg.nr_core * 1.0e6 / cfg.rate;

	struct worker worker[NUM_WORKER];

	double interval;

    struct timespec begin, end, current_time;

    srand48_r(time(NULL), &drand_buf);
    seed = (unsigned int) time(NULL);

	for (int i = 0; i < NUM_WORKER; i++) {
		worker[i].interval = 0;
		clock_gettime(CLOCK_MONOTONIC, &worker[i].last_enq_time);
	}

	input = (char *)calloc(K_16, sizeof(char));

    fp = fopen(cfg.data, "rb");
    if (fp == NULL) {
        return -1;
	}

	/* Seek to the beginning of the file */
	fseek(fp, 0, SEEK_SET);

	/* Read and display data */
	input_size = fread((char **)input, sizeof(char), K_16, fp);

	fclose(fp);

	doca_error_t result;
	struct mempool_elt *elt;
    list_for_each_entry(elt, &sha_ctx->buf_mempool->elt_free_list, list) {
	/* Create a DOCA buffer for this memory region */
		result = doca_buf_inventory_buf_by_addr(sha_ctx->buf_inv, sha_ctx->mmap, elt->addr, BUF_SIZE, &elt->buf);
		if (result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Failed to allocate DOCA buf");
		}
	}

    printf("CPU %02d| Work start!\n", sched_getcpu());

    pthread_barrier_wait(&barrier);

    clock_gettime(CLOCK_MONOTONIC, &begin);

	while (1) {
    	clock_gettime(CLOCK_MONOTONIC, &current_time);
		if (current_time.tv_sec - begin.tv_sec > 10) {
            clock_gettime(CLOCK_MONOTONIC, &end);
			printf("CPU %02d| Enqueue: %u, %6.2lf(RPS), dequeue: %u, %6.2lf(RPS)\n", sched_getcpu(),
                nb_enqueued, nb_enqueued * 1000000000.0 / (double)(TIMESPEC_TO_NSEC(end) - TIMESPEC_TO_NSEC(begin)),
                nb_dequeued, nb_dequeued * 1000000000.0 / (double)(TIMESPEC_TO_NSEC(end) - TIMESPEC_TO_NSEC(begin)));

			FILE * output_fp;
			char name[32];

			sprintf(name, "thp-%d.txt", sched_getcpu());
			output_fp = fopen(name, "w");
			if (!output_fp) {
				printf("Error opening throughput output file!\n");
				return;
			}

			fprintf(output_fp, "%6.2lf\t%6.2lf\n", 
				nb_enqueued * 1000000000.0 / (double)(TIMESPEC_TO_NSEC(end) - TIMESPEC_TO_NSEC(begin)), 
				nb_dequeued * 1000000000.0 / (double)(TIMESPEC_TO_NSEC(end) - TIMESPEC_TO_NSEC(begin)));

			fclose(output_fp);
			break;
		}

		for (int i = 0; i < NUM_WORKER; i++) {
			// if (diff_timespec(&worker[i].last_enq_time, &current_time) > worker[i].interval) {
				if (cur_ptr * data_len >= K_16) {
					cur_ptr = 0;
				}
				ret = sha_enq_job(sha_ctx, input + cur_ptr * data_len, data_len);
				if (ret < 0) {
					DOCA_LOG_ERR("Failed to enqueue jobs");
					continue;
				} else {
					cur_ptr++;
					nb_enqueued++;
					// interval = ran_expo(mean);
					// worker[i].interval = (uint64_t)round(interval);
					// worker[i].last_enq_time = current_time;
				}
			// }
		}

		ret = sha_deq_job(sha_ctx);
		if (ret < 0) {
			DOCA_LOG_ERR("Failed to dequeue jobs responses");
			continue;
		} else {
			nb_dequeued += ret;
		}
	}

    int lat_start = (int)(0.15 * nr_latency);
	FILE * output_fp;
	char name[32];

	sprintf(name, "latency-%d.txt", sched_getcpu());
	output_fp = fopen(name, "w");
	if (!output_fp) {
		printf("Error opening latency output file!\n");
		return NULL;
	}

	for (int i = lat_start; i < nr_latency; i++) {
		fprintf(output_fp, "%lu\n", latency[i]);
	}

	fclose(output_fp);

    return NULL;
}
