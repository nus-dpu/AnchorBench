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

#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include <doca_buf.h>
#include <doca_buf_inventory.h>
#include <doca_log.h>

#include "dma_copy_core.h"

#define MAX_NR_CORES	8

DOCA_LOG_REGISTER(DMA_COPY);

struct dma_copy_cfg dma_cfg;

void * 
host_task_main(void * arg) 
{
	doca_error_t result;
	struct doca_dev *cc_dev = NULL;
	struct doca_dev_rep *cc_dev_rep = NULL;
	struct core_state core_state = {0};
	struct doca_comm_channel_ep_t *ep;
	struct doca_comm_channel_addr_t *peer_addr = NULL;
	int exit_status = EXIT_SUCCESS;

	result = init_cc(&dma_cfg, &ep, &cc_dev, &cc_dev_rep);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to Initiate Comm Channel");
		return NULL;
	}

	/* Open DOCA dma device */
	result = open_dma_device(&core_state.dev);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to open DMA device");
		exit_status = EXIT_FAILURE;
		goto destroy_resources;
	}

	/* Create DOCA core objects */
	result = create_core_objs(&core_state, dma_cfg.mode);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create DOCA core structures");
		exit_status = EXIT_FAILURE;
		goto destroy_resources;
	}

	/* Init DOCA core objects */
	result = init_core_objs(&core_state, &dma_cfg);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to initialize DOCA core structures");
		exit_status = EXIT_FAILURE;
		goto destroy_resources;
	}

	result = host_start_dma_copy(&dma_cfg, &core_state, ep, &peer_addr);
	if (result != DOCA_SUCCESS) {
		exit_status = EXIT_FAILURE;
	}

destroy_resources:
	/* Destroy Comm Channel */
	destroy_cc(ep, peer_addr, cc_dev, cc_dev_rep);

	/* Destroy core objects */
	destroy_core_objs(&core_state, &dma_cfg);

	return NULL;
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
	pthread_t pids[MAX_NR_CORES];

#ifdef DOCA_ARCH_DPU
	dma_cfg.mode = DMA_COPY_MODE_DPU;
#endif

	/* Register a logger backend */
	result = doca_log_create_standard_backend();
	if (result != DOCA_SUCCESS) {
		return EXIT_FAILURE;
	}

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

	for (int i = 0; i < dma_cfg.nr_cores; i++) {
		if (pthread_create(&pids[i], NULL, host_task_main, NULL) != 0) {
			perror("pthread_create() error");
			goto destroy_resources;
		}
	}

	for (int i = 0; i < dma_cfg.nr_cores; i++) {
		if (pthread_join(pids[i], NULL) != 0) {
			perror("pthread_join() error");
			goto destroy_resources;
		}
	}

destroy_resources:
	/* ARGP destroy_resources */
	doca_argp_destroy();

	return exit_status;
}
