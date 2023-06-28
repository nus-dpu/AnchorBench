#include "multiaccel.h"

/*
 * Enqueue job to DOCA SHA qp
 *
 * @sha_ctx [in]: sha_ctx configuration struct
 * @job_request [in]: SHA job request, already initialized with first chunk.
 * @remaining_bytes [in]: the remaining bytes to send all jobs (chunks).
 * @return: number of the enqueued jobs or -1
 */
int sha_enq_job(struct sha_ctx * ctx) {
	struct app_ctx * app_ctx = (struct app_ctx *)((char *)ctx - offsetof(struct app_ctx, sha_ctx));
	doca_error_t result;
	struct sha_mempool_elt * buf;
	char * src_buf, * dst_buf;
	void * mbuf_data;
	char * data = ctx->ptr;
	int data_len = ctx->len;

	if (is_sha_mempool_empty(ctx->buf_mempool)) {
		return 0;
	}

	/* Get one free element from the mempool */
	sha_mempool_get(ctx->buf_mempool, &buf);
	/* Get the memory segment */
	src_buf = buf->src_addr;
	dst_buf = buf->dst_addr;

	memcpy(src_buf, data, data_len);

	doca_buf_get_data(buf->src_buf, &mbuf_data);
	doca_buf_set_data(buf->src_buf, mbuf_data, data_len);

	clock_gettime(CLOCK_MONOTONIC, &buf->ts);

	struct doca_sha_job const sha_job = {
		.base = (struct doca_job) {
			.type = DOCA_SHA_JOB_SHA256,
			.flags = DOCA_JOB_FLAGS_NONE,
			.ctx = doca_sha_as_ctx(ctx->doca_sha),
			.user_data = { .ptr = buf },
		},
		.resp_buf = buf->dst_buf,
		.req_buf = buf->src_buf,
		.flags = DOCA_SHA_JOB_FLAGS_SHA_PARTIAL_FINAL,
	};

	result = doca_workq_submit(app_ctx->workq, (struct doca_job *)&sha_job);
	if (result == DOCA_ERROR_NO_MEMORY) {
		sha_mempool_put(ctx->buf_mempool, buf);
		return 0; /* qp is full, try to dequeue. */
	}

	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to enqueue job. Reason: %s", doca_get_error_string(result));
		exit(1);
		return -1;
	} else {
		ctx->nb_enqueued++;
		ctx->ptr = ctx->input + (ctx->ptr + data_len - ctx->input) % ctx->input_size;
	}

	return 0;
}

int sha_deq_job(struct sha_ctx * ctx, struct doca_event * event, struct timespec * now) {
	struct sha_mempool_elt * buf;
	buf = (struct sha_mempool_elt *)event->user_data.ptr;
	if (start_record && nr_latency < MAX_NR_LATENCY) {
		latency[nr_latency].type = SHA_JOB;
		latency[nr_latency].start = TIMESPEC_TO_NSEC(buf->ts);
		latency[nr_latency].end = TIMESPEC_TO_NSEC(*now);
		nr_latency++;
	}
	sha_mempool_put(ctx->buf_mempool, buf);
}