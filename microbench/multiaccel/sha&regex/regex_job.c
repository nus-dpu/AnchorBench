#include "multiaccel.h"

int regex_enq_job(struct regex_ctx * ctx) {
	struct app_ctx * app_ctx = (struct app_ctx *)((char *)ctx - offsetof(struct app_ctx, regex_ctx));
	doca_error_t result;
	char * data = ctx->input[ctx->index].line;
	int data_len = ctx->input[ctx->index].len;
	struct regex_mempool_elt * buf;
	char * data_buf;
	void * mbuf_data;

	if (is_regex_mempool_empty(ctx->buf_mempool)) {
		return 0;
	}

	/* Get one free element from the mempool */
	regex_mempool_get(ctx->buf_mempool, &buf);
	/* Get the memory segment */
	data_buf = buf->addr;

	memcpy(data_buf, data, data_len);

	doca_buf_get_data(buf->buf, &mbuf_data);
	doca_buf_set_data(buf->buf, mbuf_data, data_len);

	clock_gettime(CLOCK_MONOTONIC, &buf->ts);

	struct doca_regex_job_search const job_request = {
			.base = {
				.type = DOCA_REGEX_JOB_SEARCH,
				.ctx = doca_regex_as_ctx(ctx->doca_regex),
				.user_data = { .ptr = buf },
			},
			.rule_group_ids = {1, 0, 0, 0},
			.buffer = buf->buf,
			.result = (struct doca_regex_search_result *)buf->response,
			.allow_batching = false,
	};

	result = doca_workq_submit(app_ctx->workq, (struct doca_job *)&job_request);
	if (result == DOCA_ERROR_NO_MEMORY) {
		regex_mempool_put(ctx->buf_mempool, buf);
		return 0; /* qp is full, try to dequeue. */
	}
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to enqueue job. Reason: %s", doca_get_error_string(result));
		return -1;
	} else {
		ctx->nb_enqueued++;
		ctx->index = (ctx->index + 1) % ctx->nr_input;
	}

	return 0;
}

int regex_deq_job(struct regex_ctx * ctx, struct doca_event * event, struct timespec * now) {
	struct regex_mempool_elt * buf;
	buf = (struct regex_mempool_elt *)event->user_data.ptr;
	if (start_record && nr_latency < MAX_NR_LATENCY) {
		latency[nr_latency].type = REGEX;
		latency[nr_latency].start = TIMESPEC_TO_NSEC(buf->ts);
		latency[nr_latency].end = TIMESPEC_TO_NSEC(*now);
		nr_latency++;
	}
	regex_mempool_put(ctx->buf_mempool, buf);
}