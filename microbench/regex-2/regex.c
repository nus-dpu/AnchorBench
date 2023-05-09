#include "regex.h"

DOCA_LOG_REGISTER(REGEX::CORE);

static doca_error_t regex_init_lcore(struct regex_ctx * ctx) {
    doca_error_t result;
    uint32_t nb_free, nb_total;
	nb_free = nb_total = 0;

    result = doca_workq_create(WORKQ_DEPTH, &ctx->workq);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to create work queue. Reason: %s", doca_get_error_string(result));
		// regex_scan_destroy(&rgx_cfg);
		return result;
	}

	result = doca_ctx_workq_add(doca_regex_as_ctx(ctx->doca_regex), ctx->workq);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to attach work queue to RegEx. Reason: %s", doca_get_error_string(result));
		// regex_scan_destroy(&rgx_cfg);
		return result;
	}

    /* Create and start buffer inventory */
	result = doca_buf_inventory_create(NULL, NB_BUF, DOCA_BUF_EXTENSION_NONE, &ctx->buf_inv);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to create buffer inventory. Reason: %s", doca_get_error_string(result));
		return result;
	}

	result = doca_buf_inventory_start(ctx->buf_inv);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to start buffer inventory. Reason: %s", doca_get_error_string(result));
		return result;
	}

	/* Create and start mmap */
	result = doca_mmap_create(NULL, &ctx->mmap);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to create memory map. Reason: %s", doca_get_error_string(result));
		return result;
	}

	result = doca_mmap_start(ctx->mmap);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to start memory map. Reason: %s", doca_get_error_string(result));
		return result;
	}

	result = doca_mmap_dev_add(ctx->mmap, ctx->dev);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to add device to memory map. Reason: %s", doca_get_error_string(result));
		return result;
	}

	ctx->buf_mempool = mempool_create(NB_BUF, BUF_SIZE);

	result = doca_mmap_populate(ctx->mmap, ctx->buf_mempool->addr, ctx->buf_mempool->size, sysconf(_SC_PAGESIZE), NULL, NULL);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to add memory region to memory map. Reason: %s", doca_get_error_string(result));
		return result;
	}

	printf(" >> total number of element: %d, free element: %d\n", 
			doca_buf_inventory_get_num_elements(regex_cfg->buf_inv, &nb_total), doca_buf_inventory_get_num_free_elements(ctx->buf_inv, &nb_free));

	ctx->results = (struct doca_regex_search_result *)calloc(WORKQ_DEPTH, sizeof(struct doca_regex_search_result));
	if (ctx->results == NULL) {
		DOCA_LOG_ERR("Unable to add allocate results storage");
		return DOCA_ERROR_NO_MEMORY;
	}

	return result;
}

int regex_work_lcore(void * arg) {
	doca_error_t result;
	struct regex_ctx rgx_ctx = {0};

    regex_init_lcore(&rgx_cfg);

    printf("CPU %02d| initialization done!\n", sched_getcpu());

    return 0;
}