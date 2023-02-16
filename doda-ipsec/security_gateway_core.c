#include <json-c/json.h>
#include <signal.h>

#include <rte_ethdev.h>

#include <doca_argp.h>
#include <doca_flow.h>
#include <doca_log.h>
#include <doca_dev.h>
#include <doca_dpdk.h>

#include <dpdk_utils.h>
#include <offload_rules.h>
#include <utils.h>
#include <flow_parser.h>

#include "security_gateway_core.h"

doca_error_t
dpdk_queues_and_ports_init(struct application_dpdk_config *app_dpdk_config)
{
	doca_error_t result;
	int ret = 0;

	/* Check that DPDK enabled the required ports to send/receive on */
	ret = rte_eth_dev_count_avail();
	if (app_dpdk_config->port_config.nb_ports > 0 && ret < app_dpdk_config->port_config.nb_ports) {
		DOCA_LOG_ERR("Application will only function with %u ports, num_of_ports=%d",
			 app_dpdk_config->port_config.nb_ports, ret);
		return DOCA_ERROR_DRIVER;
	}

	/* Check for available logical cores */
	ret = rte_lcore_count();
	if (app_dpdk_config->port_config.nb_queues > 0 && ret < app_dpdk_config->port_config.nb_queues) {
		DOCA_LOG_ERR("At least %u cores are needed for the application to run, available_cores=%d",
			 app_dpdk_config->port_config.nb_queues, ret);
		return DOCA_ERROR_DRIVER;
	}
	app_dpdk_config->port_config.nb_queues = ret;

	if (app_dpdk_config->reserve_main_thread)
		app_dpdk_config->port_config.nb_queues -= 1;
#ifdef GPU_SUPPORT
	/* Enable GPU device and initialization the resources */
	if (app_dpdk_config->pipe.gpu_support) {
		DOCA_LOG_DBG("Enabling GPU support");
		gpu_init(&app_dpdk_config->pipe);
	}
#endif

	if (app_dpdk_config->port_config.nb_ports > 0) {
		result = dpdk_ports_init(app_dpdk_config);
		if (result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Ports allocation failed");
			goto gpu_cleanup;
		}
	}

	/* Enable hairpin queues */
	if (app_dpdk_config->port_config.nb_hairpin_q > 0) {
		result = enable_hairpin_queues(app_dpdk_config->port_config.nb_ports);
		if (result != DOCA_SUCCESS)
			goto ports_cleanup;
	}

	if (app_dpdk_config->sft_config.enable) {
		result = dpdk_sft_init(app_dpdk_config);
		if (result != DOCA_SUCCESS)
			goto hairpin_queues_cleanup;
	}

	return DOCA_SUCCESS;

hairpin_queues_cleanup:
	disable_hairpin_queues(RTE_MAX_ETHPORTS);
ports_cleanup:
	dpdk_ports_fini(app_dpdk_config, RTE_MAX_ETHPORTS);
#ifdef GPU_SUPPORT
	if (app_dpdk_config->pipe.gpu_support)
		dpdk_gpu_unmap(app_dpdk_config);
#endif
gpu_cleanup:
#ifdef GPU_SUPPORT
	if (app_dpdk_config->pipe.gpu_support)
		gpu_fini(&(app_dpdk_config->pipe));
#endif
	return result;
}

doca_error_t
security_gateway_init_devices(struct security_gateway_config * app_cfg) 
{
	doca_error_t result;

	result = open_doca_device_with_pci(&app_cfg->secured_pci_addr, &job_ipsec_create_is_supported, &app_cfg->secured_dev);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to open DOCA device for secured port: %s", doca_get_error_string(result));
		return result;
	}

	result = open_doca_device_with_pci(&app_cfg->unsecured_pci_addr, NULL, &app_cfg->unsecured_dev);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to open DOCA device for unsecured port: %s", doca_get_error_string(result));
		return result;
	}

	/* probe the opened doca devices with 'dv_flow_en=2' for HWS mode */
	result = doca_dpdk_port_probe(app_cfg->secured_dev, "dv_flow_en=2");
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to probe dpdk port for secured port: %s", doca_get_error_string(result));
		return result;
	}

	result = doca_dpdk_port_probe(app_cfg->unsecured_dev, "dv_flow_en=2");
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to probe dpdk port for unsecured port: %s", doca_get_error_string(result));
		return result;
	}

	return DOCA_SUCCESS;
}

doca_error_t
register_security_gateway_params()
{
	doca_error_t result;
	struct doca_argp_param *secured_param, *unsecured_param, *rules_param, *offload_mode;

	/* Create and register ingress pci param */
	result = doca_argp_param_create(&secured_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create ARGP param: %s", doca_get_error_string(result));
		return result;
	}
	doca_argp_param_set_short_name(secured_param, "s");
	doca_argp_param_set_long_name(secured_param, "secured");
	doca_argp_param_set_description(secured_param, "secured port pci-address");
	doca_argp_param_set_callback(secured_param, secured_callback);
	doca_argp_param_set_type(secured_param, DOCA_ARGP_TYPE_STRING);
	doca_argp_param_set_mandatory(secured_param);
	result = doca_argp_register_param(secured_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to register program param: %s", doca_get_error_string(result));
		return result;
	}

	/* Create and register egress pci param */
	result = doca_argp_param_create(&unsecured_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create ARGP param: %s", doca_get_error_string(result));
		return result;
	}
	doca_argp_param_set_short_name(unsecured_param, "u");
	doca_argp_param_set_long_name(unsecured_param, "unsecured");
	doca_argp_param_set_description(unsecured_param, "unsecured port pci-address");
	doca_argp_param_set_callback(unsecured_param, unsecured_callback);
	doca_argp_param_set_type(unsecured_param, DOCA_ARGP_TYPE_STRING);
	doca_argp_param_set_mandatory(unsecured_param);
	result = doca_argp_register_param(unsecured_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to register program param: %s", doca_get_error_string(result));
		return result;
	}

	/* Create and register json rules param */
	result = doca_argp_param_create(&rules_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create ARGP param: %s", doca_get_error_string(result));
		return result;
	}
	doca_argp_param_set_short_name(rules_param, "r");
	doca_argp_param_set_long_name(rules_param, "rules");
	doca_argp_param_set_description(rules_param, "Path to the JSON file with 5-tuple rules");
	doca_argp_param_set_callback(rules_param, rules_callback);
	doca_argp_param_set_type(rules_param, DOCA_ARGP_TYPE_STRING);
	doca_argp_param_set_mandatory(rules_param);
	result = doca_argp_register_param(rules_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to register program param: %s", doca_get_error_string(result));
		return result;
	}

	/* Create and register offload mode param */
	result = doca_argp_param_create(&offload_mode);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create ARGP param: %s", doca_get_error_string(result));
		return result;
	}
	doca_argp_param_set_short_name(offload_mode, "o");
	doca_argp_param_set_long_name(offload_mode, "offload");
	doca_argp_param_set_description(offload_mode, "offload mode - {partial/full}");
	doca_argp_param_set_callback(offload_mode, offload_mode_callback);
	doca_argp_param_set_type(offload_mode, DOCA_ARGP_TYPE_STRING);
	doca_argp_param_set_mandatory(offload_mode);
	result = doca_argp_register_param(offload_mode);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to register program param: %s", doca_get_error_string(result));
		return result;
	}

	/* Register version callback for DOCA SDK & RUNTIME */
	result = doca_argp_register_version_callback(sdk_version_callback);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to register version callback: %s", doca_get_error_string(result));
		return result;
	}

	return result;
}

doca_error_t
security_gateway_parse_rules(char *file_path, int *nb_encrypt_rules, struct encrypt_rule **encrypt_rules,
			int *nb_decrypt_rules, struct decrypt_rule **decrypt_rules)
{
	FILE *json_fp;
	size_t file_length;
	char *json_data = NULL;
	struct json_object *parsed_json;
	struct json_object *json_encrypt_rules;
	struct json_object *json_decrypt_rules;
	doca_error_t result;

	json_fp = fopen(file_path, "r");
	if (json_fp == NULL) {
		DOCA_LOG_ERR("JSON file open failed");
		return DOCA_ERROR_IO_FAILED;
	}

	result = allocate_json_buffer_dynamic(json_fp, &file_length, &json_data);
	if (result != DOCA_SUCCESS) {
		fclose(json_fp);
		DOCA_LOG_ERR("Failed to allocate data buffer for the json file");
		return result;
	}

	if (fread(json_data, file_length, 1, json_fp) < file_length)
		DOCA_LOG_DBG("EOF reached");
	fclose(json_fp);

	parsed_json = json_tokener_parse(json_data);
	if (!json_object_object_get_ex(parsed_json, "encrypt_rules", &json_encrypt_rules)) {
		DOCA_LOG_ERR("missing \"encrypt_rules\" parameter");
		free(json_data);
		return DOCA_ERROR_INVALID_VALUE;
	}

	if (!json_object_object_get_ex(parsed_json, "decrypt_rules", &json_decrypt_rules)) {
		DOCA_LOG_ERR("missing \"decrypt_rules\" parameter");
		free(json_data);
		return DOCA_ERROR_INVALID_VALUE;
	}

	free(json_data);

	result = parse_json_encrypt_rules(json_encrypt_rules, nb_encrypt_rules, encrypt_rules);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to parse encrypt rules");
		return result;
	}
	result = parse_json_decrypt_rules(json_decrypt_rules, nb_decrypt_rules, decrypt_rules);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to parse decrypt rules");
		free(*encrypt_rules);
		return result;
	}
	return DOCA_SUCCESS;
}

doca_error_t
security_gateway_init_devices(struct security_gateway_config *app_cfg)
{
	doca_error_t result;

	result = open_doca_device_with_pci(&app_cfg->secured_pci_addr, &job_ipsec_create_is_supported, &app_cfg->secured_dev);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to open DOCA device for secured port: %s", doca_get_error_string(result));
		return result;
	}

	result = open_doca_device_with_pci(&app_cfg->unsecured_pci_addr, NULL, &app_cfg->unsecured_dev);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to open DOCA device for unsecured port: %s", doca_get_error_string(result));
		return result;
	}

	/* probe the opened doca devices with 'dv_flow_en=2' for HWS mode */
	result = doca_dpdk_port_probe(app_cfg->secured_dev, "dv_flow_en=2");
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to probe dpdk port for secured port: %s", doca_get_error_string(result));
		return result;
	}

	result = doca_dpdk_port_probe(app_cfg->unsecured_dev, "dv_flow_en=2");
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to probe dpdk port for unsecured port: %s", doca_get_error_string(result));
		return result;
	}

	return DOCA_SUCCESS;
}

int
security_gateway_init_doca_flow(struct security_gateway_config *app_cfg, struct security_gateway_ports_map *ports[])
{
	int result;
	int port_id;
	int port_idx = 0;
	int nb_ports = 0;
	struct doca_flow_cfg flow_cfg;
	struct doca_flow_error error;

	memset(&flow_cfg, 0, sizeof(flow_cfg));

	/* init doca flow with crypto shared resources */
	flow_cfg.queues = 8;
	flow_cfg.mode_args = "vnf,hws";
	flow_cfg.cb = check_for_valid_entry;
	flow_cfg.nr_shared_resources[DOCA_FLOW_SHARED_RESOURCE_CRYPTO] = 1024;
	result = doca_flow_init(&flow_cfg, &error);
	if (result < 0) {
		DOCA_LOG_ERR("Failed to init DOCA Flow - %s (%u)", error.message, error.type);
		return -1;
	}

	for (port_id = 0; port_id < RTE_MAX_ETHPORTS; port_id++) {
		/* search for the probed devices */
		if (!rte_eth_dev_is_valid_port(port_id))
			continue;
		if (find_port_action_type(app_cfg, port_id, &port_idx) != DOCA_SUCCESS)
			continue;
		ports[port_idx] = malloc(sizeof(struct security_gateway_ports_map));
		if (ports[port_idx] == NULL) {
			DOCA_LOG_ERR("malloc() failed");
			doca_flow_cleanup(nb_ports, ports);
			return -1;
		}
		result = create_doca_flow_port(port_id, &error, &ports[port_idx]->port);
		if (result < 0) {
			DOCA_LOG_ERR("Failed to init DOCA Flow port - %s (%u)", error.message, error.type);
			free(ports[port_idx]);
			doca_flow_cleanup(nb_ports, ports);
			return -1;
		}
		nb_ports++;
		ports[port_idx]->port_id = port_id;
	}
	if (ports[SECURED_IDX]->port == NULL || ports[UNSECURED_IDX]->port == NULL) {
		DOCA_LOG_ERR("Failed to init two DOCA Flow ports");
		doca_flow_cleanup(nb_ports, ports);
		return -1;
	}
	result = doca_flow_port_pair(ports[SECURED_IDX]->port, ports[UNSECURED_IDX]->port);
	if (result < 0) {
		DOCA_LOG_ERR("Failed to pair ports");
		doca_flow_cleanup(nb_ports, ports);
		return -1;
	}
	return 0;
}