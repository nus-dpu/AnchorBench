#include "regex.h"

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
    return -log(1 - x) * mean;
}

static int read_file(char const * path, char ** out_bytes, size_t * out_bytes_len) {
	FILE * file;
	char * bytes;

	file = fopen(path, "rb");
	if (file == NULL) {
		return -1;
	}

	if (fseek(file, 0, SEEK_END) != 0) {
		fclose(file);
		return -1;
	}

	long const nb_file_bytes = ftell(file);

	if (nb_file_bytes == -1) {
		fclose(file);
		return -1;
	}

	if (nb_file_bytes == 0) {
		fclose(file);
		return -1;
	}

	bytes = malloc(nb_file_bytes);
	if (bytes == NULL) {
		fclose(file);
		return -1;
	}

	if (fseek(file, 0, SEEK_SET) != 0) {
		free(bytes);
		fclose(file);
		return -1;
	}

	size_t const read_byte_count = fread(bytes, 1, nb_file_bytes, file);

	fclose(file);

	if (read_byte_count != nb_file_bytes) {
		free(bytes);
		return -1;
	}

	*out_bytes = bytes;
	*out_bytes_len = read_byte_count;

	return 0;
}

static void parse_file_by_line(char * content, size_t content_len) {
	char * pos, * check;
	char rule[MAX_RULE_LEN];
	int ret;

	pos = content;
	while (pos < content + content_len) {
		check = strchr(pos, '\n');
		snprintf(rule, check - pos, "%s", pos);
		// regex_rules[nb_regex_rules++] = rule;
		/* Compile RegEx engine */
		ret = regcomp(&regex_rules[nb_regex_rules], rule, 0);
		if (ret != 0) {
			printf("Failed to compile regression engine\n");
		}
		if (!check) {
			break;
		} else {
			pos = check + 1;
			nb_regex_rules++;
		}
	}
}


/*
 * Enqueue job to DOCA RegEx qp
 *
 * @regex_cfg [in]: regex_scan_ctx configuration struct
 * @job_request [in]: RegEx job request, already initialized with first chunk.
 * @remaining_bytes [in]: the remaining bytes to send all jobs (chunks).
 * @return: number of the enqueued jobs or -1
 */
static int regex_scan_enq_job(struct regex_ctx * ctx, char * data, int data_len) {
	doca_error_t result;
	int nb_enqueued = 0;
	uint32_t nb_total = 0;
	uint32_t nb_free = 0;

	doca_buf_inventory_get_num_elements(ctx->buf_inv, &nb_total);
	doca_buf_inventory_get_num_free_elements(ctx->buf_inv, &nb_free);

	if (nb_free != 0) {
		// struct doca_buf *buf;
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

		struct doca_regex_job_search const job_request = {
				.base = {
					.type = DOCA_REGEX_JOB_SEARCH,
					.ctx = doca_regex_as_ctx(ctx->doca_regex),
					.user_data = { .ptr = buf_element },
				},
				.rule_group_ids = {1, 0, 0, 0},
				.buffer = buf_element->buf,
				.result = (struct doca_regex_search_result *)buf_element->response,
				.allow_batching = false,
		};

		result = doca_workq_submit(ctx->workq, (struct doca_job *)&job_request);
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
	struct mempool_elt * buf_element;
	struct timespec now;

	clock_gettime(CLOCK_MONOTONIC, &now);

	do {
		result = doca_workq_progress_retrieve(ctx->workq, &event, DOCA_WORKQ_RETRIEVE_FLAGS_NONE);
		if (result == DOCA_SUCCESS) {
			buf_element = (struct mempool_elt *)event.user_data.ptr;
			if (nr_latency < MAX_NR_LATENCY) {
				latency[nr_latency++] = diff_timespec(&buf_element->ts, &now);
			}
			/* release the buffer back into the pool so it can be re-used */
			doca_buf_inventory_get_num_elements(ctx->buf_inv, &nb_total);
			doca_buf_inventory_get_num_free_elements(ctx->buf_inv, &nb_free);
			/* Report the scan result of RegEx engine */
			regex_scan_report_results(ctx, &event);
			/* release the buffer back into the pool so it can be re-used */
			doca_buf_refcount_rm(buf_element->buf, NULL);
			/* Put the element back into the mempool */
			mempool_put(ctx->buf_mempool, buf_element);
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

void * regex_work_lcore(void * arg) {
    int ret;
	struct regex_ctx * rgx_ctx = (struct regex_ctx *)arg;
	uint32_t nb_dequeued = 0, nb_enqueued = 0;
	int index = 0;

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

    ret = read_file("../regex_rules.txt", &cfg.rules_file_data, &cfg.rules_file_size);
	if (ret == -1) {
		printf("invalid RegEx rules\n");
	}

	parse_file_by_line(cfg.rules_file_data, cfg.rules_file_size);

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
				ret = regex_scan_enq_job(rgx_ctx, input[index].line, input[index].len);
				if (ret < 0) {
					DOCA_LOG_ERR("Failed to enqueue jobs");
					continue;
				} else {
					index = (index + 1) % MAX_NR_RULE;
					nb_enqueued++;
					interval = ran_expo(mean);
					worker[i].interval = (uint64_t)round(interval);
					worker[i].last_enq_time = current_time;
				}
			}
		}

		ret = regex_scan_deq_job(rgx_ctx);
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