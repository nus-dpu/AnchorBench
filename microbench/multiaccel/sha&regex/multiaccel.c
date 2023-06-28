#include <assert.h>
#include <stddef.h>
#include <rte_cycles.h>

#include "multiaccel.h"

DOCA_LOG_REGISTER(MULTIACCEL::CORE);

__thread int nr_latency = 0;
__thread bool start_record = false;
__thread struct lat_info * latency;

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
    double x;
    drand48_r(&drand_buf, &x);
    return -log(1 - x) * mean;
}

int ran_discrete_gen(double ratios[], int size) {
	double x;
	double ratio = 0.0;
    drand48_r(&drand_buf, &x);

	for (int i = 0; i < size; i++) {
		ratio += ratios[i];
		if (x < ratio) {
			return i;
		}
	}

	return -1;
}

int get_next_job(double ratios[], int size) {
	int x = ran_discrete_gen(ratios, size);
	if (x < 0) {
		perror("Discrete generation failed!\n");
	}
	return x + 1;
}

/*
 * Dequeue jobs responses
 *
 * @sha_ctx [in]: sha_ctx configuration struct
 * @chunk_len [in]: job chunk size
 * @return: number of the dequeue jobs or a negative posix status code.
 */
static int deq_job(struct app_ctx * ctx) {
	doca_error_t result;
	struct doca_event event = {0};
	struct timespec now;

	clock_gettime(CLOCK_MONOTONIC, &now);

	do {
		result = doca_workq_progress_retrieve(ctx->workq, &event, DOCA_WORKQ_RETRIEVE_FLAGS_NONE);
		if (result == DOCA_SUCCESS) {
			switch (event.type) {
				case DOCA_SHA_JOB_SHA256:
					sha_deq_job(&ctx->sha_ctx, &event, &now);
					break;
				case DOCA_REGEX_JOB_SEARCH:
					regex_deq_job(&ctx->regex_ctx, &event, &now);
					break;
				default:
					printf("Unknown type of event!\n");
					break;
			}
		} else if (result == DOCA_ERROR_AGAIN) {
			break;
		} else {
			DOCA_LOG_ERR("Failed to dequeue results. Reason: %s", doca_get_error_string(result));
			return -1;
		}
	} while (result == DOCA_SUCCESS);

	return 0;
}

#define NUM_WORKER	32

int load_sha_workload(struct sha_ctx * sha_ctx) {
    FILE * fp;
	char * input;
	int input_size;
  	// std::string input_file_name;
	char * input_file_name;

	/* Init SHA input */
	input = (char *)calloc(K_16, sizeof(char));
	// input_file_name = props.GetProperty(Workload::SHA_INPUT_PROPERTY, Workload::SHA_INPUT_DEFAULT);
	// input_file_name = GetSHAInput();

    fp = fopen("REGEX.txt", "rb");
    if (fp == NULL) {
        return -1;
	}

	/* Seek to the beginning of the file */
	fseek(fp, 0, SEEK_SET);

	/* Read and display data */
	input_size = fread((char **)input, sizeof(char), K_16, fp);

	sha_ctx->ptr = input;
	sha_ctx->input = input;
	sha_ctx->input_size = input_size;
	sha_ctx->len = data_len;
	sha_ctx->nb_enqueued = sha_ctx->nb_dequeued = 0;

	fclose(fp);

	return 0;
}

int load_regex_workload(struct regex_ctx * regex_ctx) {
    FILE * fp;
    char * line = NULL;
    size_t len = 0;
    ssize_t read;
	int nr_input = 0;
	struct regex_input * input;
  	// std::string input_file_name;
  	// char * input_file_name;

	/* Init RegEx input */
	input = (struct regex_input *)calloc(MAX_NR_RULE, sizeof(struct regex_input));
	// input_file_name = props.GetProperty(Workload::REGEX_INPUT_PROPERTY, Workload::REGEX_INPUT_DEFAULT);
	// input_file_name = GetRegExInput();

	fp = fopen("SHA.dat", "rb");
    if (fp == NULL) {
        return -1;
	}

	/* Seek to the beginning of the file */
	fseek(fp, 0, SEEK_SET);

	while ((read = getline(&line, &len, fp)) != -1) {
		if (nr_input >= MAX_NR_RULE) {
			break;
		}
		memcpy(input[nr_input].line, line, read);
		input[nr_input].len = read;
		nr_input++;
	}

	regex_ctx->index = 0;
	regex_ctx->input = input;
	regex_ctx->nr_input = nr_input;
	regex_ctx->nb_enqueued = regex_ctx->nb_dequeued = 0;

	fclose(fp);

	return 0;
}

void * multiaccel_work_lcore(void * arg) {
    int ret;
	struct app_ctx * app_ctx = (struct app_ctx *)arg;
	struct sha_ctx * sha_ctx = &app_ctx->sha_ctx;
	struct regex_ctx * regex_ctx = &app_ctx->regex_ctx;

	double mean;
	struct worker worker[NUM_WORKER];
	double interval;
    struct timespec begin, end, current_time;

	doca_error_t result;
	struct sha_mempool_elt * sha_elt;
	struct regex_mempool_elt * regex_elt;
	struct doca_regex_search_result * res;
	int res_index = 0;

	double job_ratio[2];

	mean = NUM_WORKER * cfg.nr_core * 1.0e6 / cfg.rate;

    srand48_r(time(NULL), &drand_buf);
    seed = (unsigned int) time(NULL);

	job_ratio[0] = cfg.regex_proportion;
	job_ratio[1] = cfg.sha_proportion;

	for (int i = 0; i < NUM_WORKER; i++) {
		worker[i].interval = 0;
		clock_gettime(CLOCK_MONOTONIC, &worker[i].last_enq_time);
	}

	load_sha_workload(sha_ctx);
	load_regex_workload(regex_ctx);

    list_for_each_entry(sha_elt, &sha_ctx->buf_mempool->elt_free_list, list) {
		/* Create a DOCA buffer for this memory region */
		result = doca_buf_inventory_buf_by_addr(sha_ctx->buf_inv, sha_ctx->mmap, sha_elt->src_addr, SHA_BUF_SIZE, &sha_elt->src_buf);
		if (result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Failed to allocate DOCA buf");
		}

		/* Create a DOCA buffer for this memory region */
		result = doca_buf_inventory_buf_by_addr(sha_ctx->buf_inv, sha_ctx->mmap, sha_elt->dst_addr, SHA_BUF_SIZE, &sha_elt->dst_buf);
		if (result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Failed to allocate DOCA buf");
		}
	}

	res = (struct doca_regex_search_result *)calloc(NB_BUF, sizeof(struct doca_regex_search_result));

	list_for_each_entry(regex_elt, &regex_ctx->buf_mempool->elt_free_list, list) {
		regex_elt->response = &res[res_index++];

		/* Create a DOCA buffer for this memory region */
		result = doca_buf_inventory_buf_by_addr(regex_ctx->buf_inv, regex_ctx->mmap, regex_elt->addr, REGEX_BUF_SIZE, &regex_elt->buf);
		if (result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Failed to allocate DOCA buf");
		}
	}

	latency = (struct lat_info *)calloc(MAX_NR_LATENCY, sizeof(struct lat_info));

    printf("CPU %02d| Work start!\n", sched_getcpu());

    pthread_barrier_wait(&barrier);

    clock_gettime(CLOCK_MONOTONIC, &begin);

	while (1) {
    	clock_gettime(CLOCK_MONOTONIC, &current_time);
		if (current_time.tv_sec - begin.tv_sec > 5) {
			start_record = true;
		}

		if (current_time.tv_sec - begin.tv_sec > 10) {
            clock_gettime(CLOCK_MONOTONIC, &end);
			// printf("CPU %02d| Enqueue: %u, %6.2lf(RPS), dequeue: %u, %6.2lf(RPS)\n", sched_getcpu(),
            //     nb_enqueued, nb_enqueued * 1000000000.0 / (double)(TIMESPEC_TO_NSEC(end) - TIMESPEC_TO_NSEC(begin)),
            //     nb_dequeued, nb_dequeued * 1000000000.0 / (double)(TIMESPEC_TO_NSEC(end) - TIMESPEC_TO_NSEC(begin)));

			printf("CPU %02d| SHA enqueue: %u, %6.2lf(RPS), dequeue: %u, %6.2lf(RPS)\n", sched_getcpu(),
                sha_ctx->nb_enqueued, sha_ctx->nb_enqueued * 1000000000.0 / (double)(TIMESPEC_TO_NSEC(end) - TIMESPEC_TO_NSEC(begin)),
                sha_ctx->nb_dequeued, sha_ctx->nb_dequeued * 1000000000.0 / (double)(TIMESPEC_TO_NSEC(end) - TIMESPEC_TO_NSEC(begin)));
			
			printf("CPU %02d| REGEX enqueue: %u, %6.2lf(RPS), dequeue: %u, %6.2lf(RPS)\n", sched_getcpu(),
                regex_ctx->nb_enqueued, regex_ctx->nb_enqueued * 1000000000.0 / (double)(TIMESPEC_TO_NSEC(end) - TIMESPEC_TO_NSEC(begin)),
                regex_ctx->nb_dequeued, regex_ctx->nb_dequeued * 1000000000.0 / (double)(TIMESPEC_TO_NSEC(end) - TIMESPEC_TO_NSEC(begin)));
#if 0
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
#endif
			break;
		}

		for (int i = 0; i < NUM_WORKER; i++) {
			if (diff_timespec(&worker[i].last_enq_time, &current_time) > worker[i].interval) {
				// int next = GetNextJob();
				int next = get_next_job(job_ratio, sizeof(job_ratio) / sizeof(job_ratio[0]));
				switch (next) {
					case SHA_JOB:
						ret = sha_enq_job(sha_ctx);
						break;
					case REGEX_JOB:
						ret = regex_enq_job(regex_ctx);
						break;
				}
				if (ret < 0) {
					DOCA_LOG_ERR("Failed to enqueue jobs");
					continue;
				} else {
					interval = ran_expo(mean);
					worker[i].interval = (uint64_t)round(interval);
					worker[i].last_enq_time = current_time;
				}
			}
		}

		ret = deq_job(app_ctx);
		if (ret < 0) {
			DOCA_LOG_ERR("Failed to dequeue jobs responses");
			continue;
		}
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
		fprintf(output_fp, "%lu\t%lu\t%lu\n", latency[i].start, latency[i].end, latency[i].end - latency[i].start);
	}

	fclose(output_fp);
#endif
    return NULL;
}
