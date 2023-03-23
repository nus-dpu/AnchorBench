/*
 * Copyright (c) 2022 NVIDIA CORPORATION & AFFILIATES, ALL RIGHTS RESERVED.
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

#include <doca_argp.h>
#include <doca_flow.h>
#include <doca_log.h>

#include <dpdk_utils.h>

DOCA_LOG_REGISTER(FLOW_HAIRPIN::MAIN);

/* Sample's Logic */
int flow_hairpin(int nb_queues);

/*
 * Sample main function
 *
 * @argc [in]: command line arguments size
 * @argv [in]: array of command line arguments
 * @return: EXIT_SUCCESS on success and EXIT_FAILURE otherwise
 */
int
main(int argc, char **argv)
{
#if 0
	doca_error_t result;
	int ret;
	int exit_status = EXIT_SUCCESS;
	struct application_dpdk_config dpdk_config = {
		.port_config.nb_ports = 2,
		.port_config.nb_queues = 1,
		.port_config.nb_hairpin_q = 2,
		.sft_config = {
			.enable = 1, /* Enable SFT */
			.enable_ct = 0,
			.enable_state_hairpin = 1,
			.enable_state_drop = 0,
		},
	};

	result = doca_argp_init("flow_hairpin", NULL);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to init ARGP resources: %s", doca_get_error_string(result));
		return EXIT_FAILURE;
	}
	doca_argp_set_dpdk_program(dpdk_init);
	result = doca_argp_start(argc, argv);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to parse sample input: %s", doca_get_error_string(result));
		doca_argp_destroy();
		return EXIT_FAILURE;
	}

	/* update queues and ports */
	result = dpdk_queues_and_ports_init(&dpdk_config);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to update ports and queues");
		dpdk_fini(&dpdk_config);
		doca_argp_destroy();
		return EXIT_FAILURE;
	}

	/* run sample */
	ret = flow_hairpin(dpdk_config.port_config.nb_queues);
	if (ret < 0) {
		DOCA_LOG_ERR("flow_hairpin sample encountered errors");
		exit_status = EXIT_FAILURE;
	}

	/* cleanup resources */
	dpdk_queues_and_ports_fini(&dpdk_config);
	dpdk_fini();

	/* ARGP cleanup */
	doca_argp_destroy();
	return exit_status;
#endif
	int ret;
	doca_error_t result;
	int exit_status = EXIT_SUCCESS;
	pthread_t cmdline_thread;
	struct dpi_worker_attr dpi_worker = {0};
	struct application_dpdk_config dpdk_config = {
		.port_config.nb_ports = 2,
		.port_config.nb_queues = 2,
		.port_config.nb_hairpin_q = 4,
		.sft_config = {
			.enable = 1, /* Enable SFT */
			.enable_ct = 1,
			.enable_state_hairpin = 1,
			.enable_state_drop = 1,
		},
		.reserve_main_thread = true,
	};
	struct ar_config ar_config = {.dpdk_config = &dpdk_config};

	/* Parse cmdline/json arguments */
	result = doca_argp_init("application_recognition", &ar_config);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to init ARGP resources: %s", doca_get_error_string(result));
		return EXIT_FAILURE;
	}
	doca_argp_set_dpdk_program(dpdk_init);
	result = register_ar_params();
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to init ARGP resources: %s", doca_get_error_string(result));
		doca_argp_destroy();
		return EXIT_FAILURE;
	}
	result = doca_argp_start(argc, argv);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to parse application input: %s", doca_get_error_string(result));
		doca_argp_destroy();
		return EXIT_FAILURE;
	}

	/* update queues and ports */
	result = dpdk_queues_and_ports_init(&dpdk_config);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to update application ports and queues: %s", doca_get_error_string(result));
		exit_status = EXIT_FAILURE;
		goto dpdk_destroy;
	}
}
