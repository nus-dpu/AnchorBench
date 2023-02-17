/*
 * Copyright (c) 2021-2022 NVIDIA CORPORATION & AFFILIATES, ALL RIGHTS RESERVED.
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
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_malloc.h>
#include <rte_sft.h>
#include <dpdk_utils.h>

#include <doca_argp.h>
#include <doca_log.h>

#include <dpdk_utils.h>

#include "dns_filter_core.h"

DOCA_LOG_REGISTER(DNS_FILTER);

/*
 * DNS filter application main function
 *
 * @argc [in]: command line arguments size
 * @argv [in]: array of command line arguments
 * @return: EXIT_SUCCESS on success and EXIT_FAILURE otherwise
 */
int
main(int argc, char **argv)
{
	doca_error_t result;
	int exit_status = EXIT_SUCCESS;
	struct dns_filter_config app_cfg = {0};
	struct application_dpdk_config dpdk_config = {
		.port_config.nb_ports = 2,
		.port_config.nb_queues = 2,
		.port_config.nb_hairpin_q = 4,
		.reserve_main_thread = true,
	};

	app_cfg.dpdk_cfg = &dpdk_config;
#ifdef GPU_SUPPORT
	/* Enable calling DPDK-GPU functions */
	dpdk_config.pipe.gpu_support = true;
	/* Enable host pinned mempool */
	dpdk_config.pipe.is_host_mem = true;
#endif
	/* Init ARGP interface and start parsing cmdline/json arguments */
	result = doca_argp_init("dns_filter", &app_cfg);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to init ARGP resources: %s", doca_get_error_string(result));
		return EXIT_FAILURE;
	}
	doca_argp_set_dpdk_program(dpdk_init);
	result = register_dns_filter_params();
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to register application params: %s", doca_get_error_string(result));
		doca_argp_destroy();
		return EXIT_FAILURE;
	}

	result = doca_argp_start(argc, argv);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to parse application input: %s", doca_get_error_string(result));
		doca_argp_destroy();
		return EXIT_FAILURE;
	}

	/* Update queues and ports */
	result = dpdk_queues_and_ports_init(&dpdk_config);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to update application ports and queues: %s", doca_get_error_string(result));
		exit_status = EXIT_FAILURE;
		goto dpdk_destroy;
	}

	/* Init DNS filter */
	// result = dns_filter_init(&app_cfg);
	// if (result != DOCA_SUCCESS) {
	// 	exit_status = EXIT_FAILURE;
	// 	goto dpdk_cleanup;
	// }

	// /* Trigger threads (DNS workers) and start processing packets, one thread per queue */
	// result = dns_worker_lcores_run(&app_cfg);
	// if (result != DOCA_SUCCESS) {
	// 	DOCA_LOG_ERR("Failed to run all dns workers");
	// 	exit_status = EXIT_FAILURE;
	// 	goto dns_filter_cleanup;
	// }

    uint16_t lcore_index = 0;
	int current_lcore = 0, nb_queues = app_cfg.dpdk_cfg->port_config.nb_queues;
	struct dns_worker_ctx *worker_ctx = NULL;

	DOCA_LOG_INFO("%d cores are used as workers", nb_queues);

	/* Init DNS workers to start processing packets */
	while ((current_lcore < RTE_MAX_LCORE) && (lcore_index < nb_queues)) {
		current_lcore = rte_get_next_lcore(current_lcore, true, false);

		/* Create worker context */
		worker_ctx = (struct dns_worker_ctx *)rte_zmalloc(NULL, sizeof(struct dns_worker_ctx), 0);
		if (worker_ctx == NULL) {
			DOCA_LOG_ERR("RTE malloc failed");
			force_quit = true;
			return DOCA_ERROR_NO_MEMORY;
		}
		worker_ctx->app_cfg = app_cfg;
		worker_ctx->queue_id = lcore_index;

		/* Launch the worker to start process packets */
		if (rte_eal_remote_launch((void *)dns_filter_worker, (void *)worker_ctx, current_lcore) != 0) {
			DOCA_LOG_ERR("Remote launch failed");
			result = DOCA_ERROR_DRIVER;
			goto queries_cleanup;
		}

		worker_ctx++;
		lcore_index++;
	}

	/* Wait all threads to be done */
	rte_eal_mp_wait_lcore();

dns_filter_cleanup:
	/* Closing and releasing resources */
	dns_filter_destroy(&app_cfg);

dpdk_cleanup:
	/* DPDK cleanup */
	dpdk_queues_and_ports_fini(&dpdk_config);
dpdk_destroy:
	dpdk_fini();

	/* ARGP cleanup */
	doca_argp_destroy();

	return exit_status;
}
