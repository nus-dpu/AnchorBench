#include "dma_dpu.h"

DOCA_LOG_REGISTER(DMA::MAIN);

#define MAX_DMA_BUF_SIZE (1024 * 1024)	/* DMA buffer maximum size */

struct dma_config cfg;
pthread_barrier_t barrier;

/*
 * DMA context initialization
 *
 * @app_cfg [in/out]: application configuration structure
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t dma_init(struct dma_config *dma_cfg) {
    doca_error_t result = DOCA_SUCCESS;
	const int mempool_size = 8;
	struct doca_pci_bdf pcie_dev = {0};

    result = parse_pci_addr(dma_cfg->pci_address, &pcie_dev);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to parse PCI address: %s", doca_get_error_string(result));
		return EXIT_FAILURE;
	}

	/* Find doca_dev according to the PCI address */
	result = open_doca_device_with_pci(&pcie_dev, NULL, &dma_cfg->dev);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("No device matching PCI address found.");
		return result;
	}

	/* Create a DOCA DMA instance */
	result = doca_dma_create(&(dma_cfg->doca_dma));
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to create DMA device.");
		return result;
	}

	/* Set the DMA device as the main HW accelerator */
	result = doca_ctx_dev_add(doca_dma_as_ctx(dma_cfg->doca_dma), dma_cfg->dev);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to set DMA device.Reason: %s", doca_get_error_string(result));
		return result;
	}

    /* Start DOCA DMA */
	result = doca_ctx_start(doca_dma_as_ctx(dma_cfg->doca_dma));
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to start DOCA DMA. [%s]", doca_get_error_string(result));
		return result;
	}

	return result;
}


/*
 * Saves export descriptor and buffer information content into memory buffers
 *
 * @export_desc_file_path [in]: Export descriptor file path
 * @buffer_info_file_path [in]: Buffer information file path
 * @export_desc [in]: Export descriptor buffer
 * @export_desc_len [in]: Export descriptor buffer length
 * @remote_addr [in]: Remote buffer address
 * @remote_addr_len [in]: Remote buffer total length
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
save_config_info_to_buffers(const char *export_desc_file_path, const char *buffer_info_file_path, char *export_desc,
			    size_t *export_desc_len, char **remote_addr, size_t *remote_addr_len)
{
	FILE *fp;
	long file_size;
	char buffer[RECV_BUF_SIZE];

	fp = fopen(export_desc_file_path, "r");
	if (fp == NULL) {
		DOCA_LOG_ERR("Failed to open %s", export_desc_file_path);
		return DOCA_ERROR_IO_FAILED;
	}

	if (fseek(fp, 0, SEEK_END) != 0) {
		DOCA_LOG_ERR("Failed to calculate file size");
		fclose(fp);
		return DOCA_ERROR_IO_FAILED;
	}

	file_size = ftell(fp);
	if (file_size == -1) {
		DOCA_LOG_ERR("Failed to calculate file size");
		fclose(fp);
		return DOCA_ERROR_IO_FAILED;
	}

	if (file_size > MAX_DMA_BUF_SIZE)
		file_size = MAX_DMA_BUF_SIZE;

	*export_desc_len = file_size;

	if (fseek(fp, 0L, SEEK_SET) != 0) {
		DOCA_LOG_ERR("Failed to calculate file size");
		fclose(fp);
		return DOCA_ERROR_IO_FAILED;
	}

	if (fread(export_desc, 1, file_size, fp) != file_size) {
		DOCA_LOG_ERR("Failed to allocate memory for source buffer");
		fclose(fp);
		return DOCA_ERROR_IO_FAILED;
	}

	fclose(fp);

	/* Read source buffer information from file */
	fp = fopen(buffer_info_file_path, "r");
	if (fp == NULL) {
		DOCA_LOG_ERR("Failed to open %s", buffer_info_file_path);
		return DOCA_ERROR_IO_FAILED;
	}

	/* Get source buffer address */
	if (fgets(buffer, RECV_BUF_SIZE, fp) == NULL) {
		DOCA_LOG_ERR("Failed to read the source (host) buffer address");
		fclose(fp);
		return DOCA_ERROR_IO_FAILED;
	}
	*remote_addr = (char *)strtoull(buffer, NULL, 0);

	memset(buffer, 0, RECV_BUF_SIZE);

	/* Get source buffer length */
	if (fgets(buffer, RECV_BUF_SIZE, fp) == NULL) {
		DOCA_LOG_ERR("Failed to read the source (host) buffer length");
		fclose(fp);
		return DOCA_ERROR_IO_FAILED;
	}
	*remote_addr_len = strtoull(buffer, NULL, 0);

	fclose(fp);

	return DOCA_SUCCESS;
}

static doca_error_t dma_init_lcore(struct dma_ctx * ctx) {
    doca_error_t result;
    uint32_t nb_free, nb_total;
	nb_free = nb_total = 0;
	char export_desc[1024] = {0};
	size_t export_desc_len = 0;

    result = doca_workq_create(WORKQ_DEPTH, &ctx->workq);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to create work queue. Reason: %s", doca_get_error_string(result));
		return result;
	}

	result = doca_ctx_workq_add(doca_dma_as_ctx(ctx->doca_dma), ctx->workq);
	if (result != DOCA_SUCCESS) {
		printf("Unable to attach work queue to DMA. Reason: %s", doca_get_error_string(result));
		return result;
	}

    /* Create and start buffer inventory */
	result = doca_buf_inventory_create(NULL, NB_BUF, DOCA_BUF_EXTENSION_NONE, &ctx->src_buf_inv);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to create buffer inventory. Reason: %s", doca_get_error_string(result));
		return result;
	}

	result = doca_buf_inventory_start(ctx->src_buf_inv);
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

	ctx->src_buf_mempool = mempool_create(NB_BUF, BUF_SIZE);

	result = doca_mmap_populate(ctx->mmap, ctx->src_buf_mempool->addr, ctx->src_buf_mempool->size, sysconf(_SC_PAGESIZE), NULL, NULL);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to add memory region to memory map. Reason: %s", doca_get_error_string(result));
		return result;
	}

	/* Copy all relevant information into local buffers */
	save_config_info_to_buffers(cfg.export_desc_file_path, cfg.buffer_info_file_path, export_desc, &export_desc_len,
				    &ctx->remote_addr, &ctx->remote_addr_len);

	ctx->dst_buf_mempool = mempool_create(NB_BUF, BUF_SIZE);

	result = doca_mmap_populate(ctx->mmap, ctx->src_buf_mempool->addr, ctx->src_buf_mempool->size, sysconf(_SC_PAGESIZE), NULL, NULL);
	if (result != DOCA_SUCCESS) {
		return result;
	}

	/* Create a local DOCA mmap from exported data */
	result = doca_mmap_create_from_export(NULL, (const void *)export_desc, export_desc_len, ctx->dev, &ctx->remote_mmap);
	if (result != DOCA_SUCCESS) {
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
	struct dma_ctx *dma_ctx = NULL;

	/* Parse cmdline/json arguments */
	result = doca_argp_init("dma", &cfg);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to init ARGP resources: %s", doca_get_error_string(result));
		return EXIT_FAILURE;
	}

	/* Register DMA params */
	result = register_dma_params();
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

    /* Init DOCA DMA */
	if (dma_init(&cfg) != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to init DOCA DMA: %s", doca_get_error_string(result));
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

		dma_ctx = (struct dma_ctx *)calloc(1, sizeof(struct dma_ctx));

        dma_ctx->dev = cfg.dev;
        dma_ctx->doca_dma = cfg.doca_dma;

        dma_init_lcore(dma_ctx);

        /* The pthread_create() call stores the thread ID into
            corresponding element of tinfo[]. */

        ret = pthread_attr_setaffinity_np(&pattr, sizeof(cpu_set_t), &cpu);
        if (ret != 0) {
            printf("pthread_attr_setaffinity_np failed!(err: %d)\n", errno);
        }

        ret = pthread_create(&pids[i], &pattr, &dma_work_lcore, (void *)dma_ctx);
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