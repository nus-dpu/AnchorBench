#include "sha.h"

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
	uint32_t nb_total = 0;
	uint32_t nb_free = 0;

	doca_buf_inventory_get_num_elements(ctx->buf_inv, &nb_total);
	doca_buf_inventory_get_num_free_elements(ctx->buf_inv, &nb_free);

	if (nb_free != 0) {
		struct mempool_elt * buf_element;
		char * data_buf;
		void *mbuf_data;

		/* Get one free element from the mempool */
		mempool_get(ctx->buf_mempool, &buf_element);
		/* Get the memory segment */
		data_buf = buf_element->addr;

		memcpy(data_buf, data, data_len);

		/* Create a DOCA buffer  for this memory region */
		result = doca_buf_inventory_buf_by_addr(ctx->buf_inv, ctx->mmap, data_buf, BUF_SIZE, &buf_element->buf);
		if (result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Failed to allocate DOCA buf");
			return nb_enqueued;
		}

		doca_buf_get_data(buf_element->buf, &mbuf_data);
		doca_buf_set_data(buf_element->buf, mbuf_data, BUF_SIZE);

	    clock_gettime(CLOCK_MONOTONIC, &buf_element->ts);

		struct doca_sha_job const sha_job = {
			.base = (struct doca_job) {
				.type = DOCA_SHA_JOB_SHA256,
				.flags = DOCA_JOB_FLAGS_NONE,
				.ctx = doca_sha_as_ctx(ctx->doca_sha),
				.user_data = { .ptr = buf_element },
			},
			.resp_buf = buf_element->buf,
			.req_buf = buf_element->buf,
			.flags = DOCA_SHA_JOB_FLAGS_NONE,
		};

		result = doca_workq_submit(ctx->workq, (struct doca_job *)&sha_job);
		if (result == DOCA_ERROR_NO_MEMORY) {
			doca_buf_refcount_rm(buf_element->buf, NULL);
			return nb_enqueued; /* qp is full, try to dequeue. */
		}
		if (result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Unable to enqueue job. Reason: %s", doca_get_error_string(result));
			exit(1);
			return -1;
		}
		// *remaining_bytes -= job_size; /* Update remaining bytes to scan. */
		nb_enqueued++;
		--nb_free;
	}

	return nb_enqueued;
}

/*
 * Printing the SHA results
 *
 * @sha_ctx [in]: sample SHA configuration struct
 * @event [in]: DOCA event structure
 */
static void sha_report_results(char *buf) {
	uint8_t * resp;
	doca_buf_get_data(buf, (void **)&resp);
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
	struct mempool_elt * src_doca_buf;
	char * dst_data_buf;
	struct timespec now;

	clock_gettime(CLOCK_MONOTONIC, &now);

	do {
		result = doca_workq_progress_retrieve(ctx->workq, &event, DOCA_WORKQ_RETRIEVE_FLAGS_NONE);
		if (result == DOCA_SUCCESS) {
			src_doca_buf = (struct mempool_elt *)event.user_data.ptr;
			dst_data_buf = (char *)src_doca_buf->response;
			if (nr_latency < MAX_NR_LATENCY) {
				latency[nr_latency++] = diff_timespec(&src_doca_buf->ts, &now);
			}
			/* release the buffer back into the pool so it can be re-used */
			// doca_buf_inventory_get_num_elements(ctx->buf_inv, &nb_total);
			// doca_buf_inventory_get_num_free_elements(ctx->buf_inv, &nb_free);
			/* Report the scan result of SHA engine */
			sha_report_results(dst_data_buf);
			/* release the buffer back into the pool so it can be re-used */
			doca_buf_refcount_rm(src_doca_buf->buf, NULL);
			/* Put the element back into the mempool */
			mempool_put(ctx->buf_mempool, src_doca_buf);
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

/*
 * Run sha_create sample
 *
 * @pci_dev [in]: pci address struct for doca device
 * @src_buffer [in]: source data for the SHA job
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise.
 */
doca_error_t sha_create(struct doca_pci_bdf *pci_dev, char *src_buffer, char *dst_buffer) {
	doca_error_t result;
	// struct timespec ts;
	uint32_t workq_depth = 1;		/* The sample will run 1 sha job */
	uint32_t max_chunks = 2;		/* The sample will use 2 doca buffers */
	size_t pg_sz = sysconf(_SC_PAGESIZE);	/* OS Page Size */

	result = doca_sha_create(&sha_ctx);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to create sha engine: %s", doca_get_error_string(result));
		return result;
	}

	state.ctx = doca_sha_as_ctx(sha_ctx);

	result = open_doca_device_with_pci(pci_dev, NULL, &state.dev);
	if (result != DOCA_SUCCESS) {
		result = doca_sha_destroy(sha_ctx);
		return result;
	}

	result = init_core_objects(&state, DOCA_BUF_EXTENSION_NONE, workq_depth, max_chunks);
	if (result != DOCA_SUCCESS) {
		sha_cleanup(&state, sha_ctx);
		return result;
	}

	if (doca_mmap_populate(state.mmap, dst_buffer, DOCA_SHA256_BYTE_COUNT, pg_sz, NULL, NULL) != DOCA_SUCCESS ||
	    doca_mmap_populate(state.mmap, src_buffer, MAX_DATA_LEN, pg_sz, NULL, NULL) != DOCA_SUCCESS) {
		free(dst_buffer);
		sha_cleanup(&state, sha_ctx);
		return result;
	}

	/* Construct DOCA buffer for each address range */
	result = doca_buf_inventory_buf_by_addr(state.buf_inv, state.mmap, src_buffer, MAX_DATA_LEN, &src_doca_buf);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to acquire DOCA buffer representing source buffer: %s", doca_get_error_string(result));
		sha_cleanup(&state, sha_ctx);
		return result;
	}
	/* Set data address and length in the doca_buf. */
	result = doca_buf_set_data(src_doca_buf, src_buffer, MAX_DATA_LEN);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("doca_buf_set_data() for request doca_buf failure");
		doca_buf_refcount_rm(src_doca_buf, NULL);
		sha_cleanup(&state, sha_ctx);
		return result;
	}

	/* Construct DOCA buffer for each address range */
	result = doca_buf_inventory_buf_by_addr(state.buf_inv, state.mmap, dst_buffer, DOCA_SHA256_BYTE_COUNT, &dst_doca_buf);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to acquire DOCA buffer representing destination buffer: %s", doca_get_error_string(result));
		doca_buf_refcount_rm(src_doca_buf, NULL);
		sha_cleanup(&state, sha_ctx);
		return result;
	}

	return result;
}

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

	double mean = WORKQ_DEPTH * cfg.nr_core * 1.0e6 / cfg.rate;

	struct worker worker[WORKQ_DEPTH];

	double interval;

    struct timespec begin, end, current_time;

    srand48_r(time(NULL), &drand_buf);
    seed = (unsigned int) time(NULL);

	for (int i = 0; i < WORKQ_DEPTH; i++) {
		worker[i].interval = 0;
		clock_gettime(CLOCK_MONOTONIC, &worker[i].last_enq_time);
	}

	input = (char *)calloc(M_1, sizeof(char));

    fp = fopen(cfg.data, "rb");
    if (fp == NULL) {
        return -1;
	}

	/* Seek to the beginning of the file */
	fseek(fp, 0, SEEK_SET);

	/* Read and display data */
	input_size = fread((char **)input, sizeof(char), M_1, fp);

	fclose(fp);

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

		for (int i = 0; i < WORKQ_DEPTH; i++) {
			if (diff_timespec(&worker[i].last_enq_time, &current_time) > worker[i].interval) {
				if (cur_ptr * SHA_DATA_LEN >= M_1) {
					cur_ptr = 0;
				}
				ret = sha_enq_job(sha_ctx, input + cur_ptr * SHA_DATA_LEN, SHA_DATA_LEN);
				if (ret < 0) {
					DOCA_LOG_ERR("Failed to enqueue jobs");
					continue;
				} else {
					cur_ptr += SHA_DATA_LEN;
					nb_enqueued++;
					interval = ran_expo(mean);
					worker[i].interval = (uint64_t)round(interval);
					worker[i].last_enq_time = current_time;
				}
			}
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
