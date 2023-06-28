#include <iostream>

#include "props.h"
#include "multiaccel.h"

DOCA_LOG_REGISTER(MULTIACCEL::MAIN);

struct app_config cfg;
pthread_barrier_t barrier;

int data_len = 64;

/*
 * ARGP Callback - Handle SHA PCI address parameter
 *
 * @param [in]: Input parameter
 * @config [in/out]: Program configuration context
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t pci_address_callback(void *param, void *config) {
	struct app_config *app_cfg = (struct app_config *)config;
	char *pci_address = (char *)param;
	int len;

	len = strnlen(pci_address, MAX_ARG_SIZE);
	if (len == MAX_ARG_SIZE) {
		DOCA_LOG_ERR("PCI address is too long max %d", MAX_ARG_SIZE - 1);
		return DOCA_ERROR_INVALID_VALUE;
	}
	strlcpy(app_cfg->pci_address, pci_address, MAX_ARG_SIZE);
	return DOCA_SUCCESS;
}

/*
 * ARGP Callback - Handle config file parameter
 *
 * @param [in]: Input parameter
 * @config [in/out]: Program configuration context
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t config_callback(void *param, void *config) {
	struct app_config *cfg = (struct app_config *)config;
	char *data_path = (char *)param;
	int len;

	len = strnlen(data_path, MAX_FILE_NAME);
	if (len == MAX_FILE_NAME) {
		DOCA_LOG_ERR("Data path is too long max %d", MAX_FILE_NAME - 1);
		return DOCA_ERROR_INVALID_VALUE;
	}
	strlcpy(cfg->config_file, data_path, MAX_FILE_NAME);
	return DOCA_SUCCESS;
}

/*
 * ARGP Callback - Handle data to scan path parameter
 *
 * @param [in]: Input parameter
 * @config [in/out]: Program configuration context
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t nr_core_callback(void *param, void *config) {
	struct app_config *app_cfg = (struct app_config *)config;
	char *nr_core_str = (char *)param;
    char *ptr;
	app_cfg->nr_core = strtol(nr_core_str, &ptr, 10);
	return DOCA_SUCCESS;
}

/*
 * ARGP Callback - Handle data to scan path parameter
 *
 * @param [in]: Input parameter
 * @config [in/out]: Program configuration context
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t rate_callback(void *param, void *config) {
	struct app_config *app_cfg = (struct app_config *)config;
	char *nr_core_str = (char *)param;
    char *ptr;
	app_cfg->rate = strtod(nr_core_str, &ptr);
	return DOCA_SUCCESS;
}

/*
 * ARGP Callback - Handle data to scan path parameter
 *
 * @param [in]: Input parameter
 * @config [in/out]: Program configuration context
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t len_callback(void *param, void *config) {
	char *len = (char *)param;
	char *ptr;

	data_len = strtol(len, &ptr, 10);
	return DOCA_SUCCESS;
}

/*
 * ARGP Callback - Handle RegEx rules path parameter
 *
 * @param [in]: Input parameter
 * @config [in/out]: Program configuration context
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t rules_callback(void *param, void *config) {
	struct app_config *app_cfg = (struct app_config *)config;
	char *rules_path = (char *)param;

	/* Read rules file into the rules buffer */
	return read_file(rules_path, &app_cfg->rules_buffer, &app_cfg->rules_buffer_len);
}

/*
 * ARGP Callback - Handle data to scan path parameter
 *
 * @param [in]: Input parameter
 * @config [in/out]: Program configuration context
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t queuedepth_callback(void *param, void *config) {
	struct app_config *app_cfg = (struct app_config *)config;
	char *queue_depth = (char *)param;
    char *ptr;
	app_cfg->queue_depth = strtol(queue_depth, &ptr, 10);
	return DOCA_SUCCESS;
}

/*
 * Register the command line parameters for the sample.
 *
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t register_sha_params() {
	doca_error_t result = DOCA_SUCCESS;
	struct doca_argp_param *pci_param, *rules_param, *config_param, *nr_core_param, *rate_param, *len_param, *queuedepth_param;

	/* Create and register PCI address of SHA device param */
	result = doca_argp_param_create(&pci_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create ARGP param: %s", doca_get_error_string(result));
		return result;
	}
	doca_argp_param_set_short_name(pci_param, "p");
	doca_argp_param_set_long_name(pci_param, "pci-addr");
	doca_argp_param_set_arguments(pci_param, "<PCI-ADDRESS>");
	doca_argp_param_set_description(pci_param, "SHA device PCI address");
	doca_argp_param_set_callback(pci_param, pci_address_callback);
	doca_argp_param_set_type(pci_param, DOCA_ARGP_TYPE_STRING);
	result = doca_argp_register_param(pci_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to register program param: %s", doca_get_error_string(result));
		return result;
	}

	/* Create and register RegEx rules param */
	result = doca_argp_param_create(&rules_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create ARGP param: %s", doca_get_error_string(result));
		return result;
	}
	doca_argp_param_set_short_name(rules_param, "r");
	doca_argp_param_set_long_name(rules_param, "rules");
	doca_argp_param_set_arguments(rules_param, "<path>");
	doca_argp_param_set_description(rules_param, "Path to compiled rules file (rof2.binary)");
	doca_argp_param_set_callback(rules_param, rules_callback);
	doca_argp_param_set_type(rules_param, DOCA_ARGP_TYPE_STRING);
	doca_argp_param_set_mandatory(rules_param);
	result = doca_argp_register_param(rules_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to register program param: %s", doca_get_error_string(result));
		return result;
	}

	/* Create and register configuration file param */
	result = doca_argp_param_create(&config_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create ARGP param: %s", doca_get_error_string(result));
		return result;
	}
	doca_argp_param_set_short_name(config_param, "f");
	doca_argp_param_set_long_name(config_param, "file");
	doca_argp_param_set_arguments(config_param, "<file>");
	doca_argp_param_set_description(config_param, "Path to config file");
	doca_argp_param_set_callback(config_param, config_callback);
	doca_argp_param_set_type(config_param, DOCA_ARGP_TYPE_STRING);
	result = doca_argp_register_param(config_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to register program param: %s", doca_get_error_string(result));
		return result;
	}

    /* Create and register number of cores param */
	result = doca_argp_param_create(&nr_core_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create ARGP param: %s", doca_get_error_string(result));
		return result;
	}
	doca_argp_param_set_short_name(nr_core_param, "c");
	doca_argp_param_set_long_name(nr_core_param, "core");
	doca_argp_param_set_arguments(nr_core_param, "<nr_core>");
	doca_argp_param_set_description(nr_core_param, "Number of worker cores");
	doca_argp_param_set_callback(nr_core_param, nr_core_callback);
	doca_argp_param_set_type(nr_core_param, DOCA_ARGP_TYPE_STRING);
	result = doca_argp_register_param(nr_core_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to register program param: %s", doca_get_error_string(result));
		return result;
	}

	/* Create and register rate param*/
	result = doca_argp_param_create(&rate_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create ARGP param: %s", doca_get_error_string(result));
		return result;
	}
	doca_argp_param_set_short_name(rate_param, "s");
	doca_argp_param_set_long_name(rate_param, "speed");
	doca_argp_param_set_arguments(rate_param, "<rate>");
	doca_argp_param_set_description(rate_param, "Request generation rate");
	doca_argp_param_set_callback(rate_param, rate_callback);
	doca_argp_param_set_type(rate_param, DOCA_ARGP_TYPE_STRING);
	result = doca_argp_register_param(rate_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to register program param: %s", doca_get_error_string(result));
		return result;
	}

	/* Create and register len param*/
	result = doca_argp_param_create(&len_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create ARGP param: %s", doca_get_error_string(result));
		return result;
	}
	doca_argp_param_set_short_name(len_param, "b");
	doca_argp_param_set_long_name(len_param, "block_size");
	doca_argp_param_set_arguments(len_param, "<block data size>");
	doca_argp_param_set_description(len_param, "Set data length");
	doca_argp_param_set_callback(len_param, len_callback);
	doca_argp_param_set_type(len_param, DOCA_ARGP_TYPE_STRING);
	result = doca_argp_register_param(len_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to register program param: %s", doca_get_error_string(result));
		return result;
	}

	/* Create and register rate param */
	result = doca_argp_param_create(&queuedepth_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create ARGP param: %s", doca_get_error_string(result));
		return result;
	}
	doca_argp_param_set_short_name(queuedepth_param, "q");
	doca_argp_param_set_long_name(queuedepth_param, "queue");
	doca_argp_param_set_arguments(queuedepth_param, "<queue depth>");
	doca_argp_param_set_description(queuedepth_param, "Work queue depth");
	doca_argp_param_set_callback(queuedepth_param, queuedepth_callback);
	doca_argp_param_set_type(queuedepth_param, DOCA_ARGP_TYPE_STRING);
	result = doca_argp_register_param(queuedepth_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to register program param: %s", doca_get_error_string(result));
		return result;
	}

	return result;
}

/*
 * Multiapp context initialization
 *
 * @app_cfg [in/out]: application configuration structure
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t multiaccel_init(struct app_config *app_cfg) {
    doca_error_t result = DOCA_SUCCESS;
	const int mempool_size = 32;
	struct doca_pci_bdf pcie_dev = {0};

    result = parse_pci_addr(app_cfg->pci_address, &pcie_dev);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to parse PCI address: %s", doca_get_error_string(result));
		return DOCA_ERROR_INVALID_VALUE;
	}

	/* Find doca_dev according to the PCI address */
	result = open_doca_device_with_pci(&pcie_dev, NULL, &app_cfg->dev);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("No device matching PCI address found.");
		return result;
	}

	/* Create a DOCA SHA instance */
	result = doca_sha_create(&(app_cfg->doca_sha));
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to create SHA device.");
		return result;
	}

	/* Set the SHA device as the main HW accelerator */
	result = doca_ctx_dev_add(doca_sha_as_ctx(app_cfg->doca_sha), app_cfg->dev);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to set SHA device.Reason: %s", doca_get_error_string(result));
		return result;
	}

    /* Start DOCA SHA */
	result = doca_ctx_start(doca_sha_as_ctx(app_cfg->doca_sha));
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to start DOCA SHA. [%s]", doca_get_error_string(result));
		return result;
	}

	/* Create a DOCA RegEx instance */
	result = doca_regex_create(&(app_cfg->doca_regex));
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to create RegEx device.");
		return result;
	}

	/* Set the RegEx device as the main HW accelerator */
	result = doca_ctx_dev_add(doca_regex_as_ctx(app_cfg->doca_regex), app_cfg->dev);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to set RegEx device.Reason: %s", doca_get_error_string(result));
		return result;
	}

	/* Size per workq memory pool */
	result = doca_regex_set_workq_matches_memory_pool_size(app_cfg->doca_regex, mempool_size);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable set matches mempool size. Reason: %s", doca_get_error_string(result));
		return result;
	}

	/* Load compiled rules into the RegEx */
	result = doca_regex_set_hardware_compiled_rules(
		app_cfg->doca_regex, app_cfg->rules_buffer, app_cfg->rules_buffer_len);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to program rules file. Reason: %s", doca_get_error_string(result));
		return result;
	}

    /* Start DOCA RegEx */
	result = doca_ctx_start(doca_regex_as_ctx(app_cfg->doca_regex));
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to start DOCA RegEx. [%s]", doca_get_error_string(result));
		// regex_scan_destroy(&regex_cfg);
		return result;
	}

	return result;
}

static doca_error_t multiaccel_init_lcore(struct app_ctx *ctx) {
	struct sha_ctx * sha_ctx = &ctx->sha_ctx;
	struct regex_ctx * regex_ctx = &ctx->regex_ctx;
    doca_error_t result;

    result = doca_workq_create(WORKQ_DEPTH, &ctx->workq);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to create work queue. Reason: %s", doca_get_error_string(result));
		return result;
	}

	/* Add workq to SHA */
	result = doca_ctx_workq_add(doca_sha_as_ctx(sha_ctx->doca_sha), ctx->workq);
	if (result != DOCA_SUCCESS) {
		printf("Unable to attach work queue to SHA. Reason: %s", doca_get_error_string(result));
		return result;
	}

	/* Add workq to RegEx */
	result = doca_ctx_workq_add(doca_regex_as_ctx(regex_ctx->doca_regex), ctx->workq);
	if (result != DOCA_SUCCESS) {
		printf("Unable to attach work queue to REGEX. Reason: %s", doca_get_error_string(result));
		return result;
	}

    /* Create and start buffer inventory for SHA context */
	result = doca_buf_inventory_create(NULL, NB_BUF, DOCA_BUF_EXTENSION_NONE, &sha_ctx->buf_inv);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to create buffer inventory. Reason: %s", doca_get_error_string(result));
		return result;
	}

	result = doca_buf_inventory_start(sha_ctx->buf_inv);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to start buffer inventory. Reason: %s", doca_get_error_string(result));
		return result;
	}

	/* Create and start mmap */
	result = doca_mmap_create(NULL, &sha_ctx->mmap);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to create memory map. Reason: %s", doca_get_error_string(result));
		return result;
	}

	result = doca_mmap_set_max_num_chunks(sha_ctx->mmap, NB_BUF);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to set memory map number of regions: %s", doca_get_error_string(result));
		return result;
	}

	result = doca_mmap_start(sha_ctx->mmap);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to start memory map. Reason: %s", doca_get_error_string(result));
		return result;
	}

	result = doca_mmap_dev_add(sha_ctx->mmap, ctx->dev);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to add device to memory map. Reason: %s", doca_get_error_string(result));
		return result;
	}

	sha_ctx->buf_mempool = sha_mempool_create(NB_BUF, SHA_BUF_SIZE);

	result = doca_mmap_populate(sha_ctx->mmap, sha_ctx->buf_mempool->addr, sha_ctx->buf_mempool->size, sysconf(_SC_PAGESIZE), NULL, NULL);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to add memory region to memory map. Reason: %s", doca_get_error_string(result));
		return result;
	}

    /* Create and start buffer inventory for RegEx context */
	result = doca_buf_inventory_create(NULL, NB_BUF, DOCA_BUF_EXTENSION_NONE, &regex_ctx->buf_inv);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to create buffer inventory. Reason: %s", doca_get_error_string(result));
		return result;
	}

	result = doca_buf_inventory_start(regex_ctx->buf_inv);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to start buffer inventory. Reason: %s", doca_get_error_string(result));
		return result;
	}

	/* Create and start mmap */
	result = doca_mmap_create(NULL, &regex_ctx->mmap);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to create memory map. Reason: %s", doca_get_error_string(result));
		return result;
	}

	result = doca_mmap_set_max_num_chunks(regex_ctx->mmap, NB_BUF);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to set memory map number of regions: %s", doca_get_error_string(result));
		return result;
	}

	result = doca_mmap_start(regex_ctx->mmap);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to start memory map. Reason: %s", doca_get_error_string(result));
		return result;
	}

	result = doca_mmap_dev_add(regex_ctx->mmap, ctx->dev);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to add device to memory map. Reason: %s", doca_get_error_string(result));
		return result;
	}

	regex_ctx->buf_mempool = regex_mempool_create(NB_BUF, REGEX_BUF_SIZE);

	result = doca_mmap_populate(regex_ctx->mmap, regex_ctx->buf_mempool->addr, regex_ctx->buf_mempool->size, sysconf(_SC_PAGESIZE), NULL, NULL);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to add memory region to memory map. Reason: %s", doca_get_error_string(result));
		return result;
	}

	return result;
}

int main(int argc, char **argv) {
	int ret;
	doca_error_t result;
    pthread_t pids[MAX_NR_CORE];
    pthread_attr_t pattr;
    cpu_set_t cpu;
	struct app_ctx *app_ctx = NULL;

	/* Parse cmdline/json arguments */
	result = doca_argp_init("multiaccel", &cfg);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to init ARGP resources: %s", doca_get_error_string(result));
		return EXIT_FAILURE;
	}

	/* Register Multiapp params */
	result = register_sha_params();
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to register sample parameters: %s", doca_get_error_string(result));
		doca_argp_destroy();
		return EXIT_FAILURE;
	}

	/* Start parsing sample arguments */
	result = doca_argp_start(argc, argv);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to parse sample input: %s", doca_get_error_string(result));
		doca_argp_destroy();
		return EXIT_FAILURE;
	}

    /* Init DOCA SHA */
	if (multiaccel_init(&cfg) != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to init DOCA SHA: %s", doca_get_error_string(result));
		return EXIT_FAILURE;
	}

    ret = pthread_attr_init(&pattr);
    if (ret != 0) {
        printf("pthread_attr_init failed!(err: %d)\n", errno);
    }

	pthread_barrier_init(&barrier, NULL, cfg.nr_core);

	InitProps(cfg.config_file);
	
	for (int i = 0; i < cfg.nr_core; i++) {
        CPU_ZERO(&cpu);
        CPU_SET(i, &cpu);

		app_ctx = (struct app_ctx *)calloc(1, sizeof(struct app_ctx));

        app_ctx->dev = cfg.dev;
        app_ctx->sha_ctx.doca_sha = cfg.doca_sha;
        app_ctx->regex_ctx.doca_regex = cfg.doca_regex;

        multiaccel_init_lcore(app_ctx);

        /* The pthread_create() call stores the thread ID into
            corresponding element of tinfo[]. */

        ret = pthread_attr_setaffinity_np(&pattr, sizeof(cpu_set_t), &cpu);
        if (ret != 0) {
            printf("pthread_attr_setaffinity_np failed!(err: %d)\n", errno);
        }

        ret = pthread_create(&pids[i], &pattr, &multiaccel_work_lcore, (void *)app_ctx);
        if (ret != 0) {
            printf("pthread_create failed!(err: %d)\n", errno);
        }
    }

	for (int i = 0; i < cfg.nr_core; i++) {
		ret = pthread_join(pids[i], NULL);
        if (ret != 0) {
            printf("pthread_join failed!(err: %d)\n", errno);
        }
	}

    pthread_barrier_destroy(&barrier);

	/* ARGP cleanup */
	doca_argp_destroy();

	return EXIT_SUCCESS;
}