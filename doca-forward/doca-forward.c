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
#include <doca_argp.h>
#include <doca_log.h>

#include <dpdk_utils.h>

#include "forward.h"

DOCA_LOG_REGISTER(DOCA_FORWARD);

static void
dns_filter_worker(void *args) {
	int ingress_port, nb_ports = worker_ctx->app_cfg->dpdk_cfg->port_config.nb_ports;
	int result;

	DOCA_LOG_DBG("Core %u is receiving packets.", rte_lcore_id());
	while (!force_quit) {

	}
}

doca_error_t
worker_lcores_run(struct dns_filter_config * app_cfg) {
	uint16_t lcore_index = 0;
	int current_lcore = 0, nb_queues = app_cfg->dpdk_cfg->port_config.nb_queues;

	/* Init DNS workers to start processing packets */
	while ((current_lcore < RTE_MAX_LCORE) && (lcore_index < nb_queues)) {
	/* Launch the worker to start process packets */
		if (rte_eal_remote_launch((void *)forward_worker, NULL, current_lcore) != 0) {
			DOCA_LOG_ERR("Remote launch failed");
			result = DOCA_ERROR_DRIVER;
			goto queries_cleanup;
		}
	}
	lcore_index++;
}

/*
 * Forward application main function
 *
 * @argc [in]: command line arguments size
 * @argv [in]: array of command line arguments
 * @return: EXIT_SUCCESS on success and EXIT_FAILURE otherwise
 */
int
main(int argc, char **argv) {
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

	/* Init ARGP interface and start parsing cmdline/json arguments */
	result = doca_argp_init("forward", &app_cfg);
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

	/* Trigger threads (DNS workers) and start processing packets, one thread per queue */
	result = worker_lcores_run(&app_cfg);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to run all dns workers");
		exit_status = EXIT_FAILURE;
		goto dns_filter_cleanup;
	}

	/* Wait all threads to be done */
	rte_eal_mp_wait_lcore();

dpdk_cleanup:
	/* DPDK cleanup */
	dpdk_queues_and_ports_fini(&dpdk_config);
dpdk_destroy:
	dpdk_fini();

	/* ARGP cleanup */
	doca_argp_destroy();

	return exit_status;
}
