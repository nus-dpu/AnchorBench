#include <stdlib.h>

#include <doca_argp.h>
#include <doca_flow.h>
#include <doca_log.h>

#include <dpdk_utils.h>

#include "subs_template.h"

DOCA_LOG_REGISTER(SUBS_TEMPLATE::PARAMS);

/*
 * ARGP Callback - Handle running mode parameter
 *
 * @param [in]: Input parameter
 * @config [in/out]: Program configuration context
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t _mode_callback(void *param, void *config) {
    struct subs_template_cfg *subs_template_cfg = (struct subs_template_cfg *)config;
    const char *mode = (char *)param;

    if (strcmp(mode, "static") == 0)
		subs_template_cfg->mode = SUBS_TEMPLATE_MODE_STATIC;
	else if (strcmp(mode, "interactive") == 0)
		subs_template_cfg->mode = SUBS_TEMPLATE_MODE_INTERACTIVE;
    else if (strcmp(mode, "dpdk") == 0)
		subs_template_cfg->mode = SUBS_TEMPLATE_MODE_DPDK_WORKER;
	else {
		DOCA_LOG_ERR("Illegal running mode = [%s]", mode);
		return DOCA_ERROR_INVALID_VALUE;
	}

	return DOCA_SUCCESS;
}

/*
 * Register startup parameters for subs_template application
 *
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
doca_error_t register_subs_template_params() {
	doca_error_t result;
	struct doca_argp_param *mode_param;

	result = doca_argp_param_create(&mode_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create ARGP param: %s", doca_get_error_string(result));
		return result;
	}

	doca_argp_param_set_short_name(mode_param, "m");
	doca_argp_param_set_long_name(mode_param, "mode");
	doca_argp_param_set_description(mode_param, "Set running mode {static, interactive, dpdk}");
	doca_argp_param_set_callback(mode_param, _mode_callback);
	doca_argp_param_set_type(mode_param, DOCA_ARGP_TYPE_STRING);
	doca_argp_param_set_mandatory(mode_param);
	result = doca_argp_register_param(mode_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to register program param: %s", doca_get_error_string(result));
		return result;
	}
}

