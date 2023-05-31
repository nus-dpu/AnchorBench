#include "regex.h"

#include <rte_cycles.h>

DOCA_LOG_REGISTER(REGEX::CORE);

#define NSEC_PER_SEC    1000000000L

#define TIMESPEC_TO_NSEC(t)	((t.tv_sec * NSEC_PER_SEC) + (t.tv_nsec))

#define MAX_NR_LATENCY	(128 * 1024)

__thread struct input_info input[MAX_NR_RULE];
__thread int index = 0;
__thread int nr_rule = 0;

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
 * Enqueue job to DOCA RegEx qp
 *
 * @regex_cfg [in]: regex_scan_ctx configuration struct
 * @job_request [in]: RegEx job request, already initialized with first chunk.
 * @remaining_bytes [in]: the remaining bytes to send all jobs (chunks).
 * @return: number of the enqueued jobs or -1
 */
static int regex_scan_enq_job(struct regex_ctx * ctx, int i, char * data, int data_len) {
	doca_error_t result;
	int nb_enqueued = 0;

	struct doca_buf *buf = ctx->buf[i];
	void *mbuf_data;
	memcpy(ctx->query_buf[i], data, data_len);

	doca_buf_get_data(buf, &mbuf_data);
	doca_buf_set_data(buf, mbuf_data, data_len);

	// clock_gettime(CLOCK_MONOTONIC, &ctx->ts[i]);

	struct doca_regex_job_search const job_request = {
			.base = {
				.type = DOCA_REGEX_JOB_SEARCH,
				.ctx = doca_regex_as_ctx(ctx->doca_regex),
				.user_data = { .ptr = i },
			},
			.rule_group_ids = {1, 0, 0, 0},
			.buffer = buf,
			.result = ctx->responses + i,
			.allow_batching = i != PACKET_BURST,
	};

	result = doca_workq_submit(ctx->workq, (struct doca_job *)&job_request);
	if (result == DOCA_ERROR_NO_MEMORY) {
		// doca_buf_refcount_rm(buf_element->buf, NULL);
		return nb_enqueued; /* qp is full, try to dequeue. */
	}
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to enqueue job. Reason: %s", doca_get_error_string(result));
		return -1;
	} else {
		ctx->buffers[i] = buf;
	}

	nb_enqueued++;

	return nb_enqueued;
}
#if 0
/*
 * Printing the RegEx results
 *
 * @regex_cfg [in]: sample RegEx configuration struct
 * @event [in]: DOCA event structure
 */
static void regex_scan_report_results(struct regex_ctx *ctx, struct doca_event *event) {
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
#endif
/*
 * Dequeue jobs responses
 *
 * @regex_cfg [in]: regex_scan_ctx configuration struct
 * @chunk_len [in]: job chunk size
 * @return: number of the dequeue jobs or a negative posix status code.
 */
static int regex_scan_deq_job(struct regex_ctx *ctx) {
	doca_error_t result;
	int finished = 0;
	struct doca_event event = {0};
	struct timespec ts;
	uint32_t nb_free = 0;
	uint32_t nb_total = 0;
	int index;
	struct timespec now;

	for (int i = 0; i < PACKET_BURST; i++) {
		result = doca_workq_progress_retrieve(ctx->workq, &event, DOCA_WORKQ_RETRIEVE_FLAGS_NONE);
		if (result == DOCA_SUCCESS) {
			index = event.user_data.u64;
			// clock_gettime(CLOCK_MONOTONIC, &now);
			// if (nr_latency < MAX_NR_LATENCY) {
			// 	latency[nr_latency++] = diff_timespec(&ctx->ts[index], &now);
			// }
			++finished;
		} else if (result == DOCA_ERROR_AGAIN) {
			// break;
		} else {
			DOCA_LOG_ERR("Failed to dequeue results. Reason: %s", doca_get_error_string(result));
			return -1;
		}
	}

	return finished;
}

#define NUM_WORKER	32

int local_regex_processing(struct regex_ctx * worker_ctx) {
	size_t tx_count, rx_count;
	doca_error_t result;
	int ret;

	rx_count = tx_count = 0;

	while (tx_count < PACKET_BURST) {
		for (; tx_count != PACKET_BURST;) {
			struct doca_buf *buf = worker_ctx->buf[tx_count];
			void *mbuf_data;
			char *data_begin = input[index].line;
			size_t data_len = input[index].len;
			memcpy(worker_ctx->query_buf[tx_count], data_begin, data_len);

			doca_buf_get_data(buf, &mbuf_data);
			doca_buf_set_data(buf, mbuf_data, data_len);

			struct doca_regex_job_search const job_request = {
					.base = {
						.type = DOCA_REGEX_JOB_SEARCH,
						.ctx = doca_regex_as_ctx(worker_ctx->doca_regex),
						.user_data = {.u64 = tx_count },
					},
					.rule_group_ids = {1, 0, 0, 0},
					.buffer = buf,
					.result = worker_ctx->responses + tx_count,
					.allow_batching = tx_count != (PACKET_BURST - 1),
			};

			result = doca_workq_submit(worker_ctx->workq, (struct doca_job *)&job_request);
			if (result == DOCA_ERROR_NO_MEMORY) {
				doca_buf_refcount_rm(buf, NULL);
				break;
			}

			if (result == DOCA_SUCCESS) {
				worker_ctx->buffers[tx_count] = buf;
				++tx_count;
				index = (index + 1) % nr_rule;
			} else {
				DOCA_LOG_ERR("Failed to enqueue RegEx job (%s)", doca_get_error_string(result));
				ret = -1;
			}
		}

		for (; rx_count != tx_count;) {
			/* dequeue one */
			struct doca_event event = {0};
			
			result = doca_workq_progress_retrieve(worker_ctx->workq, &event, DOCA_WORKQ_RETRIEVE_FLAGS_NONE);
			if (result == DOCA_SUCCESS) {
				/* Handle the completed jobs */
				++rx_count;
			} else if (result == DOCA_ERROR_AGAIN) {
				/* Wait for the job to complete */
			} else {
				DOCA_LOG_ERR("Failed to dequeue RegEx job response");
				ret = -1;
			}
		}
	}
	return ret;
}

void * regex_work_lcore(void * arg) {
    int ret;
	struct regex_ctx * rgx_ctx = (struct regex_ctx *)arg;
	uint32_t nb_dequeued = 0, nb_enqueued = 0;
    FILE * fp;
    char * line = NULL;
    size_t len = 0;
    ssize_t read;
	doca_error_t result;

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

    fp = fopen(cfg.data, "rb");
	while ((read = getline(&line, &len, fp)) != -1) {
		if (nr_rule >= MAX_NR_RULE) {
			break;
		}
		memcpy(input[nr_rule].line, line, read);
		input[nr_rule].len = read;
		nr_rule++;
	}

	/* Create array of pointers (char*) to hold the queries */
	rgx_ctx->queries = (char **)calloc(PACKET_BURST, sizeof(char *));
	if (rgx_ctx->queries == NULL) {
		DOCA_LOG_ERR("Dynamic allocation failed");
		exit(1);
	}

	for (int i = 0; i < PACKET_BURST; i++) {
		/* Create array of pointers (char*) to hold the queries */
		rgx_ctx->query_buf[i] = (char *)calloc(256, sizeof(char));
		if (rgx_ctx->query_buf[i] == NULL) {
			DOCA_LOG_ERR("Dynamic allocation failed");
			exit(1);
		}

		/* register packet in mmap */
		result = doca_mmap_populate(rgx_ctx->mmap, rgx_ctx->query_buf[i], 256, sysconf(_SC_PAGESIZE), NULL, NULL);
		if (result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Unable to populate memory map (input): %s", doca_get_error_string(result));
			exit(1);
		}

		/* build doca_buf */
		result = doca_buf_inventory_buf_by_addr(rgx_ctx->buf_inv, rgx_ctx->mmap, rgx_ctx->query_buf[i], 256, &rgx_ctx->buf[i]);
		if (result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Unable to acquire DOCA buffer for job data: %s", doca_get_error_string(result));
			exit(1);
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
#if 0
		for (int i = 0; i < PACKET_BURST; i++) {
			// if (diff_timespec(&worker[i].last_enq_time, &current_time) > worker[i].interval) {
				ret = regex_scan_enq_job(rgx_ctx, i, input[index].line, input[index].len);
				if (ret < 0) {
					DOCA_LOG_ERR("Failed to enqueue jobs");
					continue;
				} else {
					index = (index + 1) % nr_rule;
					nb_enqueued++;
					// interval = ran_expo(mean);
					// worker[i].interval = (uint64_t)round(interval);
					// worker[i].last_enq_time = current_time;
				}
			// }
		}

		ret = regex_scan_deq_job(rgx_ctx);
		if (ret < 0) {
			DOCA_LOG_ERR("Failed to dequeue jobs responses");
			continue;
		} else {
			nb_dequeued += ret;
		}
#endif
		local_regex_processing(rgx_ctx);
	}

#if 0
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
#endif
    return NULL;
}
