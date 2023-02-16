#include <doca_argp.h>
#include <doca_log.h>

#include <dpdk_utils.h>

#include "security_gateway_core.h"

DOCA_LOG_REGISTER(SECURITY_GATEWAY);

int main(int argc, char **argv) {
	doca_error_t result;
	int ret;
	int nb_ports = 2;
	int exit_status = EXIT_SUCCESS;
	struct security_gateway_ports_map *ports[nb_ports];
	char *eal_param[3] = {"", "-a", "00:00.0"};
	struct security_gateway_config app_cfg = {0};
	struct application_dpdk_config dpdk_config = {
		.port_config.nb_ports = nb_ports,
		.port_config.nb_queues = 7,
		.port_config.nb_hairpin_q = 2,
		.reserve_main_thread = true,
	};
	struct encrypt_rule *encrypt_rules;
	struct decrypt_rule *decrypt_rules;
	int nb_encrypt_rules;
	int nb_decrypt_rules;

    /* Init ARGP interface and start parsing cmdline/json arguments */
	result = doca_argp_init("security_gateway", &app_cfg);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to init ARGP resources: %s", doca_get_error_string(result));
		return EXIT_FAILURE;
	}
	result = register_security_gateway_params();
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

	result = security_gateway_parse_rules(app_cfg.json_path, &nb_encrypt_rules, &encrypt_rules, &nb_decrypt_rules, &decrypt_rules);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to parse application json file: %s", doca_get_error_string(result));
		doca_argp_destroy();
		return EXIT_FAILURE;
	}

    ret = rte_eal_init(3, eal_param);
	if (ret < 0) {
		DOCA_LOG_ERR("EAL initialization failed");
		exit_status = EXIT_FAILURE;
		goto argp_destroy;
	}

	DOCA_LOG_INFO("Init device...");

    result = security_gateway_init_devices(&app_cfg);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to open DOCA devices: %s", doca_get_error_string(result));
		exit_status = EXIT_FAILURE;
		goto argp_destroy;
	}

	DOCA_LOG_INFO("Update queues and ports...");

    /* Update queues and ports */
	result = dpdk_queues_and_ports_init(&dpdk_config);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to update application ports and queues: %s", doca_get_error_string(result));
		exit_status = EXIT_FAILURE;
		goto dpdk_destroy;
	}

    ret = security_gateway_init_doca_flow(&app_cfg, ports);
	if (ret < 0) {
		DOCA_LOG_ERR("Failed to init DOCA Flow");
		exit_status = EXIT_FAILURE;
		goto dpdk_cleanup;
	}

dpdk_cleanup:
	/* DPDK cleanup */
	dpdk_queues_and_ports_fini(&dpdk_config);
dpdk_destroy:
	dpdk_fini();
argp_destroy:
	free(encrypt_rules);
	free(decrypt_rules);
	/* ARGP cleanup */
	doca_argp_destroy();

	return exit_status;
}