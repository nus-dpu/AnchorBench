#include "sha.h"

DOCA_LOG_REGISTER(SHA::MAIN);

struct sha_config cfg;
pthread_barrier_t barrier;

/*
 * ARGP Callback - Handle SHA PCI address parameter
 *
 * @param [in]: Input parameter
 * @config [in/out]: Program configuration context
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t pci_address_callback(void *param, void *config) {
	struct sha_config *sha_cfg = (struct sha_config *)config;
	char *pci_address = (char *)param;
	int len;

	len = strnlen(pci_address, MAX_ARG_SIZE);
	if (len == MAX_ARG_SIZE) {
		DOCA_LOG_ERR("PCI address is too long max %d", MAX_ARG_SIZE - 1);
		return DOCA_ERROR_INVALID_VALUE;
	}
	strlcpy(sha_cfg->pci_address, pci_address, MAX_ARG_SIZE);
	return DOCA_SUCCESS;
}

/*
 * ARGP Callback - Handle data to scan path parameter
 *
 * @param [in]: Input parameter
 * @config [in/out]: Program configuration context
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t data_callback(void *param, void *config) {
	struct sha_config *sha_cfg = (struct sha_config *)config;
	char *data_path = (char *)param;
	int len;

	len = strnlen(data_path, MAX_FILE_NAME);
	if (len == MAX_FILE_NAME) {
		DOCA_LOG_ERR("Data path is too long max %d", MAX_FILE_NAME - 1);
		return DOCA_ERROR_INVALID_VALUE;
	}
	strlcpy(sha_cfg->data, data_path, MAX_FILE_NAME);
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
	struct sha_config *sha_cfg = (struct sha_config *)config;
	char *nr_core_str = (char *)param;
    char *ptr;
	sha_cfg->nr_core = strtol(nr_core_str, &ptr, 10);
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
	struct sha_config *sha_cfg = (struct sha_config *)config;
	char *nr_core_str = (char *)param;
    char *ptr;
	sha_cfg->rate = strtod(nr_core_str, &ptr);
	return DOCA_SUCCESS;
}

/*
 * Register the command line parameters for the sample.
 *
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t register_sha_params() {
	doca_error_t result = DOCA_SUCCESS;
	struct doca_argp_param *pci_param, *rules_param, *data_param, *nr_core_param, *rate_param;

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

	/* Create and register data to scan param*/
	result = doca_argp_param_create(&data_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create ARGP param: %s", doca_get_error_string(result));
		return result;
	}
	doca_argp_param_set_short_name(data_param, "d");
	doca_argp_param_set_long_name(data_param, "data");
	doca_argp_param_set_arguments(data_param, "<path>");
	doca_argp_param_set_description(data_param, "Path to data file");
	doca_argp_param_set_callback(data_param, data_callback);
	doca_argp_param_set_type(data_param, DOCA_ARGP_TYPE_STRING);
	result = doca_argp_register_param(data_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to register program param: %s", doca_get_error_string(result));
		return result;
	}

    /* Create and register number of cores param*/
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

	return result;
}

/*
 * SHA context initialization
 *
 * @app_cfg [in/out]: application configuration structure
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t sha_init(struct sha_config *sha_cfg) {
    doca_error_t result = DOCA_SUCCESS;
	const int mempool_size = 8;
	struct doca_pci_bdf pcie_dev = {0};

    result = parse_pci_addr(sha_cfg->pci_address, &pcie_dev);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to parse PCI address: %s", doca_get_error_string(result));
		return EXIT_FAILURE;
	}

	/* Find doca_dev according to the PCI address */
	result = open_doca_device_with_pci(&pcie_dev, NULL, &sha_cfg->dev);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("No device matching PCI address found.");
		return result;
	}

	/* Create a DOCA SHA instance */
	result = doca_sha_create(&(sha_cfg->doca_sha));
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to create SHA device.");
		return result;
	}

	/* Set the SHA device as the main HW accelerator */
	result = doca_ctx_dev_add(doca_sha_as_ctx(sha_cfg->doca_sha), sha_cfg->dev);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to set SHA device.Reason: %s", doca_get_error_string(result));
		return result;
	}

	/* Size per workq memory pool */
	result = doca_sha_set_workq_matches_memory_pool_size(sha_cfg->doca_sha, mempool_size);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable set matches mempool size. Reason: %s", doca_get_error_string(result));
		return result;
	}

    /* Start DOCA SHA */
	result = doca_ctx_start(doca_sha_as_ctx(sha_cfg->doca_sha));
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to start DOCA SHA. [%s]", doca_get_error_string(result));
		return result;
	}

	return result;
}

static doca_error_t sha_init_lcore(struct sha_ctx * ctx) {
    doca_error_t result;
    uint32_t nb_free, nb_total;
	nb_free = nb_total = 0;

    result = doca_workq_create(WORKQ_DEPTH, &ctx->workq);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to create work queue. Reason: %s", doca_get_error_string(result));
		return result;
	}

	result = doca_ctx_workq_add(doca_sha_as_ctx(ctx->doca_sha), ctx->workq);
	if (result != DOCA_SUCCESS) {
		printf("Unable to attach work queue to SHA. Reason: %s", doca_get_error_string(result));
		return result;
	}

    /* Create and start buffer inventory */
	result = doca_buf_inventory_create(NULL, NB_BUF, DOCA_BUF_EXTENSION_NONE, &ctx->buf_inv);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to create buffer inventory. Reason: %s", doca_get_error_string(result));
		return result;
	}

	result = doca_buf_inventory_start(ctx->buf_inv);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to start buffer inventory. Reason: %s", doca_get_error_string(result));
		return result;
	}

	/* Create and start mmap */
	result = doca_mmap_create(NULL, &ctx->mmap);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to create memory map. Reason: %s", doca_get_error_string(result));
		return result;
	}

	result = doca_mmap_start(ctx->mmap);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to start memory map. Reason: %s", doca_get_error_string(result));
		return result;
	}

	result = doca_mmap_dev_add(ctx->mmap, ctx->dev);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to add device to memory map. Reason: %s", doca_get_error_string(result));
		return result;
	}

	ctx->buf_mempool = mempool_create(NB_BUF, BUF_SIZE);

	result = doca_mmap_populate(ctx->mmap, ctx->buf_mempool->addr, ctx->buf_mempool->size, sysconf(_SC_PAGESIZE), NULL, NULL);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to add memory region to memory map. Reason: %s", doca_get_error_string(result));
		return result;
	}

	printf(" >> total number of element: %d, free element: %d\n", 
		doca_buf_inventory_get_num_elements(ctx->buf_inv, &nb_total), doca_buf_inventory_get_num_free_elements(ctx->buf_inv, &nb_free));

	return result;
}

int main(int argc, char **argv) {
	int ret;
	doca_error_t result;
    pthread_t pids[MAX_NR_CORE];
    pthread_attr_t pattr;
    cpu_set_t cpu;
	struct sha_ctx *sha_ctx = NULL;

	/* Parse cmdline/json arguments */
	result = doca_argp_init("sha", &cfg);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to init ARGP resources: %s", doca_get_error_string(result));
		return EXIT_FAILURE;
	}

	/* Register SHA params */
	result = register_sha_scan_params();
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to register sample parameters: %s", doca_get_error_string(result));
		doca_argp_destroy();
		return EXIT_FAILURE;
	}

	/* Start parsing sample arguments */
	result = doca_argp_start(argc, argv);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to parse sample input: %s", doca_get_error_string(result));
		if (cfg.rules_buffer != NULL)
			free(cfg.rules_buffer);
		doca_argp_destroy();
		return EXIT_FAILURE;
	}

    /* Init DOCA SHA */
	if (sha_init(&cfg) != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to init DOCA SHA: %s", doca_get_error_string(result));
		return EXIT_FAILURE;
	}

    ret = pthread_attr_init(&pattr);
    if (ret != 0) {
        printf("pthread_attr_init failed!(err: %d)\n", errno);
    }

	pthread_barrier_init(&barrier, NULL, cfg.nr_core);

    for (int i = 0; i < cfg.nr_core; i++) {
        CPU_ZERO(&cpu);
        CPU_SET(i, &cpu);

		rgx_ctx = (struct sha_ctx *)calloc(1, sizeof(struct sha_ctx));

        rgx_ctx->dev = cfg.dev;
        rgx_ctx->doca_sha = cfg.doca_sha;

        sha_init_lcore(rgx_ctx);

        /* The pthread_create() call stores the thread ID into
            corresponding element of tinfo[]. */

        ret = pthread_attr_setaffinity_np(&pattr, sizeof(cpu_set_t), &cpu);
        if (ret != 0) {
            printf("pthread_attr_setaffinity_np failed!(err: %d)\n", errno);
        }

        ret = pthread_create(&pids[i], &pattr, &sha_work_lcore, (void *)rgx_ctx);
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

    /* Cleanup */
	if (cfg.rules_buffer != NULL)
		free(cfg.rules_buffer);

	/* ARGP cleanup */
	doca_argp_destroy();

	return EXIT_SUCCESS;
}