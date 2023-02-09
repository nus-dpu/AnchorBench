#include <stdlib.h>

#include <doca_argp.h>
#include <doca_flow.h>
#include <doca_log.h>
#include <signal.h>
#include <dpdk_utils.h>

#include "subs_template.h"

DOCA_LOG_REGISTER(SUBS_TEMPLATE::MAIN);

bool force_quit;

static void _signal_handler(int signum);
static struct subs_template_cfg* _config_params_and_dpdk(int argc, char **argv);
static doca_error_t _config_doca_flow(struct subs_template_cfg *app_config);
static doca_error_t _destroy_doca_flow(struct subs_template_cfg *app_config);
static doca_error_t _destroy_dpdk(struct subs_template_cfg *app_config);

int main(int argc, char **argv){
	doca_error_t result;
	int exit_status = EXIT_SUCCESS;
	force_quit = false;

	// config params and dpdk for subs_template
    struct subs_template_cfg *app_config = _config_params_and_dpdk(argc, argv);
	if (!app_config || !app_config->dpdk_cfg) {
		exit_status = EXIT_FAILURE;
		goto exit_failed;
	} 

    // config doca flow library for subs_template
	result = _config_doca_flow(app_config);
	if (result != DOCA_SUCCESS) {
		exit_status = EXIT_FAILURE;
		goto dpdk_cleanup;
	}

	// dispatching application logic based on its type
	if (app_config->mode == SUBS_TEMPLATE_MODE_STATIC) {
		// do some static configuration and stuck into idle
		// TODO
		signal(SIGINT, _signal_handler);
		signal(SIGTERM, _signal_handler);
		DOCA_LOG_INFO("Waiting for traffic, press Ctrl+C for termination");
		while (!force_quit)
			sleep(1);
	} else if (app_config->mode == SUBS_TEMPLATE_MODE_INTERACTIVE) {
		// interact with operator using command line during runtime
		result = flow_parser_init("SUBS_TEMPLATE >> ");
		if (result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Failed to init flow parser");
			exit_status = EXIT_FAILURE;
			goto doca_flow_cleanup;
		}
		flow_parser_cleanup();
	} else if (app_config->mode == SUBS_TEMPLATE_MODE_DPDK_WORKER) {
		
	}

doca_flow_cleanup:
	_destroy_doca_flow(app_config);

dpdk_cleanup:
	_destroy_dpdk(app_config);

free_dpdk_config:
	free(app_config->dpdk_cfg);

free_app_config:
	free(app_config);

exit_failed:
	return exit_status;
}

static struct subs_template_cfg* _config_params_and_dpdk(int argc, char **argv){
	doca_error_t result;

	struct subs_template_cfg *subs_template_cfg 
		= (struct subs_template_cfg*)malloc(sizeof(struct subs_template_cfg));
	memset(subs_template_cfg, 0, sizeof(struct subs_template_cfg));
	if(!subs_template_cfg){
		DOCA_LOG_ERR("Failed to allocate memory for subs_template_cfg");
		goto exit_failed;
	}

	// init command line parser interface
    result = doca_argp_init("subs_template", subs_template_cfg);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to init ARGP resources: %s", doca_get_error_string(result));
		goto free_subs_template_cfg;
	}

	// set dpdk_init as the callback that the parser uses
    doca_argp_set_dpdk_program(dpdk_init);

	// register parameters for subs_template
	result = register_subs_template_params();
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to register application params: %s", doca_get_error_string(result));
		goto destroy_doca_argp;
	}

	struct application_dpdk_config *dpdk_config 
		= (struct application_dpdk_config*)malloc(sizeof(struct application_dpdk_config));
	memset(dpdk_config, 0, sizeof(struct application_dpdk_config));
	if(!subs_template_cfg){
		DOCA_LOG_ERR("Failed to allocate memory for dpdk_config");
		goto destroy_doca_argp;
	}
	subs_template_cfg->dpdk_cfg = dpdk_config;

	// parse the command line arguments
    result = doca_argp_start(argc, argv);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to parse sample input: %s", doca_get_error_string(result));
		goto free_dpdk_config;
	}

	// detect dpdk ports
	fill_application_dpdk_config(dpdk_config);
	if(dpdk_config->port_config.nb_ports == 0){
		DOCA_LOG_ERR("No dpdk port detected");
		goto destroy_dpdk;
	}

    // update dpdk queues and ports
	result = dpdk_queues_and_ports_init(&dpdk_config);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to update ports and queues");
		goto destroy_dpdk;
	}

exit_success:
	return subs_template_cfg;

destroy_dpdk:
	dpdk_fini(&dpdk_config);

free_dpdk_config:
	free(dpdk_config);

destroy_doca_argp:
	doca_argp_destroy();

free_subs_template_cfg:
	free(subs_template_cfg);

exit_failed:
	return NULL;
}

static doca_error_t _config_doca_flow(struct subs_template_cfg *app_config){
	return applictaion_doca_flow_init(app_config);
}

static doca_error_t _destroy_doca_flow(struct subs_template_cfg *app_config){
	application_doca_flow_distroy();
}

static doca_error_t _destroy_dpdk(struct subs_template_cfg *app_config){
	dpdk_queues_and_ports_fini(app_config->dpdk_cfg);
	dpdk_fini();
}

static void _signal_handler(int signum){
	if (signum == SIGINT || signum == SIGTERM) {
		DOCA_LOG_INFO("Signal %d received, preparing to exit...", signum);
		force_quit = true;
	}
}