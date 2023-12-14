/*
 * Copyright (c) 2022-2023 NVIDIA CORPORATION & AFFILIATES, ALL RIGHTS RESERVED.
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

#define _GNU_SOURCE
#define __USE_GNU
#include <sched.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <doca_buf.h>
#include <doca_buf_inventory.h>
#include <doca_log.h>
#include <doca_dma.h>

#include <common.h>

#include "dma_copy_core.h"

#define MAX_NR_CORES	8

struct dma_copy_cfg dma_cfg;

DOCA_LOG_REGISTER(DMA_COPY);

/*
 * Check if DOCA device is DMA capable
 *
 * @devinfo [in]: Device to check
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t check_dev_dma_capable(struct doca_devinfo *devinfo)
{
	return doca_dma_job_get_supported(devinfo, DOCA_DMA_JOB_MEMCPY);
}

static doca_error_t init_dma(struct doca_dev **dev)
{
	doca_error_t result;

	result = open_doca_device_with_capabilities(check_dev_dma_capable, dev);
	if (result != DOCA_SUCCESS)
		DOCA_LOG_ERR("Failed to open DOCA DMA capable device");

	return result;
}

static doca_error_t create_dma_objs(struct core_state * state, enum dma_copy_mode mode) {
	doca_error_t result;
	size_t num_elements = 2;

	result = doca_mmap_create(NULL, &state->mmap);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to create mmap: %s", doca_get_error_string(result));
		return result;
	}

	if (mode == DMA_COPY_MODE_HOST)
		return DOCA_SUCCESS;

	result = doca_buf_inventory_create(NULL, num_elements, DOCA_BUF_EXTENSION_NONE, &state->buf_inv);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to create buffer inventory: %s", doca_get_error_string(result));
		return result;
	}

	result = doca_dma_create(&(state->dma_ctx));
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to create DMA engine: %s", doca_get_error_string(result));
		return result;
	}

	state->ctx = doca_dma_as_ctx(state->dma_ctx);

	result = doca_workq_create(WORKQ_DEPTH, &(state->workq));
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to create work queue: %s", doca_get_error_string(result));
		return result;
	}

	return result;
}

static doca_error_t init_dma_objs(struct core_state * state, enum dma_copy_mode mode) {
	doca_error_t result;

	result = doca_mmap_dev_add(state->mmap, state->dev);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to add device to mmap: %s", doca_get_error_string(result));
		return result;
	}

	if (dma_cfg.mode == DMA_COPY_MODE_HOST)
		return DOCA_SUCCESS;

	result = doca_buf_inventory_start(state->buf_inv);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to start buffer inventory: %s", doca_get_error_string(result));
		return result;
	}

	result = doca_ctx_dev_add(state->ctx, state->dev);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to register device with DMA context: %s", doca_get_error_string(result));
		return result;
	}

	result = doca_ctx_start(state->ctx);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to start DMA context: %s", doca_get_error_string(result));
		return result;
	}

	result = doca_ctx_workq_add(state->ctx, state->workq);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to register work queue with context: %s", doca_get_error_string(result));
		return result;
	}

	return result;
}

void
destroy_objs(struct core_state *state, enum dma_copy_mode mode)
{
	doca_error_t result;

	if (mode == DMA_COPY_MODE_DPU) {
		result = doca_workq_destroy(state->workq);
		if (result != DOCA_SUCCESS)
			DOCA_LOG_ERR("Failed to destroy work queue: %s", doca_get_error_string(result));
		state->workq = NULL;

		result = doca_dma_destroy(state->dma_ctx);
		if (result != DOCA_SUCCESS)
			DOCA_LOG_ERR("Failed to destroy dma: %s", doca_get_error_string(result));
		state->dma_ctx = NULL;
		state->ctx = NULL;

		result = doca_buf_inventory_destroy(state->buf_inv);
		if (result != DOCA_SUCCESS)
			DOCA_LOG_ERR("Failed to destroy buf inventory: %s", doca_get_error_string(result));
		state->buf_inv = NULL;
	}

	result = doca_mmap_destroy(state->mmap);
	if (result != DOCA_SUCCESS)
		DOCA_LOG_ERR("Failed to destroy mmap: %s", doca_get_error_string(result));
	state->mmap = NULL;

	result = doca_dev_close(state->dev);
	if (result != DOCA_SUCCESS)
		DOCA_LOG_ERR("Failed to close device: %s", doca_get_error_string(result));
	state->dev = NULL;
}

/*
 * DMA copy application main function
 *
 * @argc [in]: command line arguments size
 * @argv [in]: array of command line arguments
 * @return: EXIT_SUCCESS on success and EXIT_FAILURE otherwise
 */
int
main(int argc, char **argv)
{
	doca_error_t result;
	struct core_state core_states[MAX_NR_CORES] = {0};
	int exit_status = EXIT_SUCCESS;
	struct doca_dev *dev = NULL;
	struct doca_comm_channel_ep_t *ep = NULL;
	struct doca_dev *cc_dev = NULL;
	struct doca_dev_rep *cc_dev_rep = NULL;
	pthread_t pids[MAX_NR_CORES];
    pthread_attr_t pattr;
    cpu_set_t cpu;
	int ret;

#ifdef DOCA_ARCH_DPU
	dma_cfg.mode = DMA_COPY_MODE_DPU;
#endif

	/* Register a logger backend */
	result = doca_log_create_standard_backend();
	if (result != DOCA_SUCCESS)
		return EXIT_FAILURE;

	result = doca_argp_init("doca_dma_copy", &dma_cfg);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to init ARGP resources: %s", doca_get_error_string(result));
		return EXIT_FAILURE;
	}
	register_dma_copy_params();
	result = doca_argp_start(argc, argv);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to parse application input: %s", doca_get_error_string(result));
		return EXIT_FAILURE;
	}

	/* Init DOCA COMPRESS */
	if (init_dma(&dev) != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to init DOCA DMA: %s", doca_get_error_string(result));
		return EXIT_FAILURE;
	}

	ret = pthread_attr_init(&pattr);
    if (ret != 0) {
        printf("pthread_attr_init failed!(err: %d)\n", errno);
    }

	printf("Spawning DMA copy on %d cores...\n", dma_cfg.nr_cores);

	for (int i = 0; i < dma_cfg.nr_cores; i++) {
		struct core_state * state = &core_states[i];

		CPU_ZERO(&cpu);
        CPU_SET(i, &cpu);

		state->core_id = i;
		state->dev = dev;

		create_dma_objs(state, dma_cfg.mode);
		init_dma_objs(state, dma_cfg.mode);

		result = init_cc(&dma_cfg, &ep, &cc_dev, &cc_dev_rep);
		if (result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Failed to Initiate Comm Channel");
			return EXIT_FAILURE;
		}

		state->ep = ep;
		state->cc_dev = cc_dev;
		state->cc_dev_rep = cc_dev_rep;

		ret = pthread_create(&pids[i], &pattr, &dpu_start_dma_copy, (void *)state);
        if (ret != 0) {
            printf("pthread_create failed!(err: %d)\n", errno);
        }
	}

	/* Destroy core objects */
	for (int i = 0; i < dma_cfg.nr_cores; i++) {
		pthread_join(pids[i], NULL);
	}

	for (int i = 0; i < dma_cfg.nr_cores; i++) {
		struct core_state * state = &core_states[i];
		destroy_objs(state, dma_cfg.mode);
	}

	/* ARGP destroy_resources */
	doca_argp_destroy();

	return exit_status;
}