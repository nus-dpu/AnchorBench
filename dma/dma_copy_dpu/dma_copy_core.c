/*
 * Copyright (c) 2022-2023 NVIDIA CORPORATION & AFFILIATES, ALL RIGHTS RESERVED.
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

#include <stdint.h>
#include <string.h>
#include <time.h>
#include <netinet/in.h>
#include <errno.h>
#include <sys/epoll.h>
#include <unistd.h>
#include <math.h>

#include <doca_buf.h>
#include <doca_buf_inventory.h>
#include <doca_ctx.h>
#include <doca_dev.h>
#include <doca_dma.h>
#include <doca_mmap.h>

#include <common.h>

#include "pack.h"
#include "utils.h"

#include "dma_copy.h"
#include "dma_copy_core.h"

DOCA_LOG_REGISTER(DMA_COPY_CORE);

#define NSEC_PER_SEC    1000000000L

#define TIMESPEC_TO_NSEC(t)	((t.tv_sec * NSEC_PER_SEC) + (t.tv_nsec))

#define MAX_NR_LATENCY	(32 * 1024)

struct lat_info {
	uint64_t start;
	uint64_t end;
};

__thread int nr_latency = 0;
__thread bool start_record = false;
__thread struct lat_info * latency;

__thread unsigned int seed;
__thread struct drand48_data drand_buf;

#define NSEC_PER_SEC    1000000000L
#define TIMESPEC_TO_NSEC(t)	((t.tv_sec * NSEC_PER_SEC) + (t.tv_nsec))

uint64_t diff_timespec(struct timespec * t1, struct timespec * t2) {
	struct timespec diff = {.tv_sec = t2->tv_sec - t1->tv_sec, .tv_nsec = t2->tv_nsec - t1->tv_nsec};
	if (diff.tv_nsec < 0) {
		diff.tv_nsec += NSEC_PER_SEC;
		diff.tv_sec--;
	}
	return TIMESPEC_TO_NSEC(diff);
}

/*
 * Validate file size
 *
 * @file_path [in]: File to validate
 * @file_size [out]: File size
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
validate_file_size(const char *file_path, uint32_t *file_size)
{
	FILE *fp;
	long size;

	fp = fopen(file_path, "r");
	if (fp == NULL) {
		DOCA_LOG_ERR("Failed to open %s", file_path);
		return DOCA_ERROR_IO_FAILED;
	}

	if (fseek(fp, 0, SEEK_END) != 0) {
		DOCA_LOG_ERR("Failed to calculate file size");
		fclose(fp);
		return DOCA_ERROR_IO_FAILED;
	}

	size = ftell(fp);
	if (size == -1) {
		DOCA_LOG_ERR("Failed to calculate file size");
		fclose(fp);
		return DOCA_ERROR_IO_FAILED;
	}

	fclose(fp);

	if (size > MAX_DMA_BUF_SIZE) {
		DOCA_LOG_ERR("File size of %ld is larger than DMA buffer maximum size of %d", size, MAX_DMA_BUF_SIZE);
		return DOCA_ERROR_INVALID_VALUE;
	}

	DOCA_LOG_INFO("The file size is %ld", size);

	*file_size = size;

	return DOCA_SUCCESS;
}

/*
 * ARGP validation Callback - check if input file exists
 *
 * @config [in]: Program configuration context
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
args_validation_callback(void *config)
{
	struct dma_copy_cfg *cfg = (struct dma_copy_cfg *)config;

	if (access(cfg->file_path, F_OK | R_OK) == 0) {
		cfg->is_file_found_locally = true;
		return validate_file_size(cfg->file_path, &cfg->file_size);
	}

	return DOCA_SUCCESS;
}

/*
 * ARGP Callback - Handle Comm Channel DOCA device PCI address parameter
 *
 * @param [in]: Input parameter
 * @config [in/out]: Program configuration context
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
dev_pci_addr_callback(void *param, void *config)
{
	struct dma_copy_cfg *cfg = (struct dma_copy_cfg *)config;
	const char *dev_pci_addr = (char *)param;

	if (strnlen(dev_pci_addr, DOCA_DEVINFO_PCI_ADDR_SIZE) == DOCA_DEVINFO_PCI_ADDR_SIZE) {
		DOCA_LOG_ERR("Entered device PCI address exceeding the maximum size of %d", DOCA_DEVINFO_PCI_ADDR_SIZE - 1);
		return DOCA_ERROR_INVALID_VALUE;
	}

	strlcpy(cfg->cc_dev_pci_addr, dev_pci_addr, DOCA_DEVINFO_PCI_ADDR_SIZE);

	return DOCA_SUCCESS;
}

/*
 * ARGP Callback - Handle nr cores parameter
 *
 * @param [in]: Input parameter
 * @config [in/out]: Program configuration context
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
nr_cores_callback(void *param, void *config)
{
	struct dma_copy_cfg *cfg = (struct dma_copy_cfg *)config;
	cfg->nr_cores = *(int *)param;

	return DOCA_SUCCESS;
}

/*
 * ARGP Callback - Handle file parameter
 *
 * @param [in]: Input parameter
 * @config [in/out]: Program configuration context
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
file_path_callback(void *param, void *config)
{
	struct dma_copy_cfg *cfg = (struct dma_copy_cfg *)config;
	char *file_path = (char *)param;
	int file_path_len = strnlen(file_path, MAX_ARG_SIZE);

	if (file_path_len == MAX_ARG_SIZE) {
		DOCA_LOG_ERR("Entered file path exceeded buffer size - MAX=%d", MAX_ARG_SIZE - 1);
		return DOCA_ERROR_INVALID_VALUE;
	}

	strlcpy(cfg->file_path, file_path, MAX_ARG_SIZE);

	return DOCA_SUCCESS;
}

/*
 * ARGP Callback - Handle Comm Channel DOCA device representor PCI address parameter
 *
 * @param [in]: Input parameter
 * @config [in/out]: Program configuration context
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
rep_pci_addr_callback(void *param, void *config)
{
	struct dma_copy_cfg *cfg = (struct dma_copy_cfg *)config;
	const char *rep_pci_addr = (char *)param;

	if (cfg->mode == DMA_COPY_MODE_DPU) {
		if (strnlen(rep_pci_addr, DOCA_DEVINFO_REP_PCI_ADDR_SIZE) == DOCA_DEVINFO_REP_PCI_ADDR_SIZE) {
			DOCA_LOG_ERR("Entered device representor PCI address exceeding the maximum size of %d",
				     DOCA_DEVINFO_REP_PCI_ADDR_SIZE - 1);
			return DOCA_ERROR_INVALID_VALUE;
		}

		strlcpy(cfg->cc_dev_rep_pci_addr, rep_pci_addr, DOCA_DEVINFO_REP_PCI_ADDR_SIZE);
	}

	return DOCA_SUCCESS;
}

/*
 * ARGP Callback - Handle nr cores parameter
 *
 * @param [in]: Input parameter
 * @config [in/out]: Program configuration context
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
rate_callback(void *param, void *config)
{
	struct dma_copy_cfg *cfg = (struct dma_copy_cfg *)config;
	char *rate_str = (char *)param;
    char *ptr;

	cfg->rate = strtod(rate_str, &ptr);

	return DOCA_SUCCESS;
}

/*
 * Wait for status message
 *
 * @ep [in]: Comm Channel endpoint
 * @peer_addr [in]: Comm Channel peer address
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
wait_for_successful_status_msg(struct doca_comm_channel_ep_t *ep, struct doca_comm_channel_addr_t **peer_addr)
{
	struct cc_msg_dma_status msg_status;
	doca_error_t result;
	size_t msg_len, status_msg_len = sizeof(struct cc_msg_dma_status);
	struct timespec ts = {
		.tv_nsec = SLEEP_IN_NANOS,
	};

	msg_len = status_msg_len;
	while ((result = doca_comm_channel_ep_recvfrom(ep, (void *)&msg_status, &msg_len, DOCA_CC_MSG_FLAG_NONE,
						       peer_addr)) == DOCA_ERROR_AGAIN) {
		nanosleep(&ts, &ts);
		msg_len = status_msg_len;
	}
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Status message was not received: %s", doca_get_error_string(result));
		return result;
	}

	if (!msg_status.is_success) {
		DOCA_LOG_ERR("Failure status received");
		return DOCA_ERROR_INVALID_VALUE;
	}

	return DOCA_SUCCESS;
}

/*
 * Send status message
 *
 * @ep [in]: Comm Channel endpoint
 * @peer_addr [in]: Comm Channel peer address
 * @status [in]: Status to send
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
send_status_msg(struct doca_comm_channel_ep_t *ep, struct doca_comm_channel_addr_t **peer_addr, bool status)
{
	struct cc_msg_dma_status status_msg;
	doca_error_t result;
	struct timespec ts = {
		.tv_nsec = SLEEP_IN_NANOS,
	};

	status_msg.is_success = status;

	while ((result = doca_comm_channel_ep_sendto(ep, &status_msg, sizeof(struct cc_msg_dma_status),
						     DOCA_CC_MSG_FLAG_NONE, *peer_addr)) == DOCA_ERROR_AGAIN)
		nanosleep(&ts, &ts);

	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to send status message: %s", doca_get_error_string(result));
		return result;
	}

	return DOCA_SUCCESS;
}

/*
 * Save remote buffer information into a file
 *
 * @cfg [in]: Application configuration
 * @buffer [in]: Buffer to read information from
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
save_buffer_into_a_file(struct dma_copy_cfg *cfg, const char *buffer)
{
	FILE *fp;

	fp = fopen(cfg->file_path, "w");
	if (fp == NULL) {
		DOCA_LOG_ERR("Failed to create the DMA copy file");
		return DOCA_ERROR_IO_FAILED;
	}

	if (fwrite(buffer, 1, cfg->file_size, fp) != cfg->file_size) {
		DOCA_LOG_ERR("Failed to write full content into the output file");
		fclose(fp);
		return DOCA_ERROR_IO_FAILED;
	}

	fclose(fp);

	return DOCA_SUCCESS;
}

/*
 * Fill local buffer with file content
 *
 * @cfg [in]: Application configuration
 * @buffer [out]: Buffer to save information into
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
fill_buffer_with_file_content(struct dma_copy_cfg *cfg, char *buffer)
{
	FILE *fp;

	fp = fopen(cfg->file_path, "r");
	if (fp == NULL) {
		DOCA_LOG_ERR("Failed to open %s", cfg->file_path);
		return DOCA_ERROR_IO_FAILED;
	}

	/* Read file content and store it in the local buffer which will be exported */
	if (fread(buffer, 1, cfg->file_size, fp) != cfg->file_size) {
		DOCA_LOG_ERR("Failed to read content from file: %s", cfg->file_path);
		fclose(fp);
		return DOCA_ERROR_IO_FAILED;
	}
	fclose(fp);

	return DOCA_SUCCESS;
}

/*
 * Allocate memory and populate it into the memory map
 *
 * @core_state [in]: DOCA core structure
 * @nb_buffer [in]: Number of buffer
 * @buffer_len [in]: Allocated buffer length
 * @access_flags [in]: The access permissions of the mmap
 * @mp [out]: Mempool
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
memory_alloc_and_populate(struct core_state *core_state, int nb_buffer, size_t buffer_len, uint32_t access_flags, struct mempool ** mp)
{	
	doca_error_t result;

	*mp = mempool_create(nb_buffer, buffer_len);
	if (*mp == NULL) {
		return DOCA_ERROR_NO_MEMORY;
	}

	result = doca_mmap_set_permissions(core_state->mmap, access_flags);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to set access permissions of memory map: %s", doca_get_error_string(result));
		return result;
	}

	result = doca_mmap_set_memrange(core_state->mmap, *mp, sizeof(struct mempool) + (*mp)->total_size);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to set memrange of memory map: %s", doca_get_error_string(result));
		return result;
	}

	/* Populate local buffer into memory map to allow access from DPU side after exporting */
	result = doca_mmap_start(core_state->mmap);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to populate memory map: %s", doca_get_error_string(result));
	}

	return result;
}

static doca_error_t
mempool_buf_inventory(struct core_state *core_state, struct mempool * mp, char * export_desc_buf, size_t export_desc_len, char * host_dma_addr, size_t host_dma_offset)
{
	struct doca_mmap *remote_mmap;
	struct doca_buf *remote_doca_buf;
	struct doca_buf *local_doca_buf;
	doca_error_t result;

	printf("Core %02d| Create a local DOCA mmap from export descriptor...\n", core_state->core_id);

	/* Create a local DOCA mmap from export descriptor */
	result = doca_mmap_create_from_export(NULL, (const void *)export_desc_buf, export_desc_len,
						core_state->dev, &remote_mmap);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create memory map from export descriptor");
		return result;
	}

	for (int i = 0; i < mp->nb_elt; i++) {
		struct mempool_elt * elt = (struct mempool_elt *)(mp->elts + i * mp->elt_size);

		/* Construct DOCA buffer for remote (Host) address range */
		result = doca_buf_inventory_buf_by_addr(core_state->buf_inv, remote_mmap, host_dma_addr, host_dma_offset,
							&remote_doca_buf);
		if (result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Unable to acquire DOCA remote buffer: %s", doca_get_error_string(result));
			doca_mmap_destroy(remote_mmap);
			return result;
		}

		/* Construct DOCA buffer for local (DPU) address range */
		result = doca_buf_inventory_buf_by_addr(core_state->buf_inv, core_state->mmap, elt->addr, host_dma_offset,
							&local_doca_buf);
		if (result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Unable to acquire DOCA local buffer: %s", doca_get_error_string(result));
			doca_buf_refcount_rm(remote_doca_buf, NULL);
			doca_mmap_destroy(remote_mmap);
			return result;
		}

		elt->buf1 = local_doca_buf;
		elt->buf2 = remote_doca_buf;
	}

	return DOCA_SUCCESS;
}

/*
 * DPU side function for file size and location negotiation
 *
 * @cfg [in]: Application configuration
 * @ep [in]: Comm Channel endpoint
 * @peer_addr [in]: Comm Channel peer address
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
dpu_negotiate_dma_direction_and_size(struct dma_copy_cfg *cfg, int core_id, struct doca_comm_channel_ep_t *ep,
				     struct doca_comm_channel_addr_t **peer_addr)
{
	struct cc_msg_dma_direction host_dma_direction = {0};
	struct cc_msg_dma_direction dpu_dma_direction = {0};
	struct timespec ts = {
		.tv_nsec = SLEEP_IN_NANOS,
	};
	doca_error_t result;
	size_t msg_len;
	char name[32] = {0};

	if (cfg->is_file_found_locally) {
		DOCA_LOG_INFO("Core %02d| File was found locally, it will be DMA copied to the Host", core_id);
		dpu_dma_direction.file_in_host = false;
		dpu_dma_direction.file_size = htonl(cfg->file_size);
	} else {
		DOCA_LOG_INFO("Core %02d| File was not found locally, it will be DMA copied from the Host", core_id);
		dpu_dma_direction.file_in_host = true;
	}
	
	sprintf(name, SERVER_NAME " %d", core_id);

	result = doca_comm_channel_ep_listen(ep, name);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Comm Channel endpoint couldn't start listening: %s", doca_get_error_string(result));
		return result;
	}

	DOCA_LOG_INFO("Core %02d| Waiting for Host to send negotiation message", core_id);

	/* Wait until Host negotiation message will arrive */
	msg_len = sizeof(struct cc_msg_dma_direction);
	while ((result = doca_comm_channel_ep_recvfrom(ep, (void *)&host_dma_direction, &msg_len,
						       DOCA_CC_MSG_FLAG_NONE, peer_addr)) == DOCA_ERROR_AGAIN) {
		nanosleep(&ts, &ts);
		msg_len = sizeof(struct cc_msg_dma_direction);
	}
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Response message was not received: %s", doca_get_error_string(result));
		send_status_msg(ep, peer_addr, STATUS_FAILURE);
		return result;
	}

	if (msg_len != sizeof(struct cc_msg_dma_direction)) {
		DOCA_LOG_ERR("Response negotiation message was not received correctly");
		send_status_msg(ep, peer_addr, STATUS_FAILURE);
		return DOCA_ERROR_INVALID_VALUE;
	}

	/* Make sure file is located only on one side */
	if (cfg->is_file_found_locally && host_dma_direction.file_in_host == true) {
		DOCA_LOG_ERR("Error - File was found on both Host and DPU");
		send_status_msg(ep, peer_addr, STATUS_FAILURE);
		return DOCA_ERROR_INVALID_VALUE;

	} else if (!cfg->is_file_found_locally) {
		if (!host_dma_direction.file_in_host) {
			DOCA_LOG_ERR("Error - File was not found on both Host and DPU");
			send_status_msg(ep, peer_addr, STATUS_FAILURE);
			return DOCA_ERROR_INVALID_VALUE;
		}
		cfg->file_size = ntohl(host_dma_direction.file_size);
	}

	/* Send direction message to Host */
	while ((result = doca_comm_channel_ep_sendto(ep, &dpu_dma_direction, sizeof(struct cc_msg_dma_direction),
						     DOCA_CC_MSG_FLAG_NONE, *peer_addr)) == DOCA_ERROR_AGAIN)
		nanosleep(&ts, &ts);

	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to send negotiation buffer to DPU: %s", doca_get_error_string(result));
		return result;
	}

	return DOCA_SUCCESS;
}

/*
 * DPU side function for clean DOCA core objects
 *
 * @state [in]: DOCA core structure
 */
static void
dpu_cleanup_core_objs(struct core_state *state)
{
	doca_error_t result;

	result = doca_ctx_workq_rm(state->ctx, state->workq);
	if (result != DOCA_SUCCESS)
		DOCA_LOG_ERR("Failed to remove work queue from ctx: %s", doca_get_error_string(result));

	result = doca_ctx_stop(state->ctx);
	if (result != DOCA_SUCCESS)
		DOCA_LOG_ERR("Unable to stop DMA context: %s", doca_get_error_string(result));

	result = doca_ctx_dev_rm(state->ctx, state->dev);
	if (result != DOCA_SUCCESS)
		DOCA_LOG_ERR("Failed to remove device from DMA ctx: %s", doca_get_error_string(result));
}

/*
 * DPU side function for receiving export descriptor on Comm Channel
 *
 * @ep [in]: Comm Channel endpoint
 * @peer_addr [in]: Comm Channel peer address
 * @export_desc_buffer [out]: Buffer to save the export descriptor
 * @export_desc_len [out]: Export descriptor length
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
dpu_receive_export_desc(struct doca_comm_channel_ep_t *ep, struct doca_comm_channel_addr_t **peer_addr,
			char *export_desc_buffer, size_t *export_desc_len)
{
	size_t msg_len;
	doca_error_t result;
	struct timespec ts = {
		.tv_nsec = SLEEP_IN_NANOS,
	};

	DOCA_LOG_INFO("Waiting for Host to send export descriptor");

	/* Receive exported descriptor from Host */
	msg_len = CC_MAX_MSG_SIZE;
	while ((result = doca_comm_channel_ep_recvfrom(ep, (void *)export_desc_buffer, &msg_len,
						       DOCA_CC_MSG_FLAG_NONE, peer_addr)) == DOCA_ERROR_AGAIN) {
		nanosleep(&ts, &ts);
		msg_len = CC_MAX_MSG_SIZE;
	}
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to receive export descriptor from Host: %s", doca_get_error_string(result));
		send_status_msg(ep, peer_addr, STATUS_FAILURE);
		return result;
	}

	*export_desc_len = msg_len;
	DOCA_DLOG_INFO("Export descriptor received successfully from Host");

	result = send_status_msg(ep, peer_addr, STATUS_SUCCESS);
	if (result != DOCA_SUCCESS)
		return result;

	return result;
}

/*
 * DPU side function for receiving remote buffer address and offset on Comm Channel
 *
 * @ep [in]: Comm Channel endpoint
 * @peer_addr [in]: Comm Channel peer address
 * @host_addr [out]: Remote buffer address
 * @host_offset [out]: Remote buffer offset
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
dpu_receive_addr_and_offset(struct doca_comm_channel_ep_t *ep, struct doca_comm_channel_addr_t **peer_addr,
			    char **host_addr, size_t *host_offset)
{
	doca_error_t result;
	uint64_t received_addr, received_addr_len;
	size_t msg_len;
	struct timespec ts = {
		.tv_nsec = SLEEP_IN_NANOS,
	};

	DOCA_LOG_INFO("Waiting for Host to send address and offset");

	/* Receive remote source buffer address */
	msg_len = sizeof(received_addr);
	while ((result = doca_comm_channel_ep_recvfrom(ep, (void *)&received_addr, &msg_len, DOCA_CC_MSG_FLAG_NONE,
						       peer_addr)) == DOCA_ERROR_AGAIN) {
		nanosleep(&ts, &ts);
		msg_len = sizeof(received_addr);
	}
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to receive remote address from Host: %s", doca_get_error_string(result));
		send_status_msg(ep, peer_addr, STATUS_FAILURE);
		return result;
	}

	received_addr = ntohq(received_addr);
	if (received_addr > SIZE_MAX) {
		DOCA_LOG_ERR("Address size exceeds pointer size in this device");
		send_status_msg(ep, peer_addr, STATUS_FAILURE);
		return DOCA_ERROR_INVALID_VALUE;
	}
	*host_addr = (char *)received_addr;

	DOCA_DLOG_INFO("Remote address received successfully from Host: %" PRIu64 "", received_addr);

	result = send_status_msg(ep, peer_addr, STATUS_SUCCESS);
	if (result != DOCA_SUCCESS)
		return result;

	/* Receive remote source buffer length */
	msg_len = sizeof(received_addr_len);
	while ((result = doca_comm_channel_ep_recvfrom(ep, (void *)&received_addr_len, &msg_len,
						       DOCA_CC_MSG_FLAG_NONE, peer_addr)) == DOCA_ERROR_AGAIN) {
		nanosleep(&ts, &ts);
		msg_len = sizeof(received_addr_len);
	}
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to receive remote address offset from Host: %s", doca_get_error_string(result));
		send_status_msg(ep, peer_addr, STATUS_FAILURE);
		return result;
	}

	received_addr_len = ntohq(received_addr_len);
	if (received_addr_len > SIZE_MAX) {
		DOCA_LOG_ERR("Offset exceeds SIZE_MAX in this device");
		send_status_msg(ep, peer_addr, STATUS_FAILURE);
		return DOCA_ERROR_INVALID_VALUE;
	}
	*host_offset = (size_t)received_addr_len;

	DOCA_DLOG_INFO("Address offset received successfully from Host: %" PRIu64 "", received_addr_len);

	result = send_status_msg(ep, peer_addr, STATUS_SUCCESS);
	if (result != DOCA_SUCCESS)
		return result;

	return result;
}

/*
 * DPU side function for submitting DMA job into the work queue and save into a file if needed
 *
 * @cfg [in]: Application configuration
 * @core_state [in]: DOCA core structure
 * @bytes_to_copy [in]: Number of bytes to DMA copy
 * @buffer [in]: local DMA buffer
 * @local_doca_buf [in]: local DOCA buffer
 * @remote_doca_buf [in]: remote DOCA buffer
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
dpu_submit_dma_job(struct dma_copy_cfg *cfg, struct core_state *core_state, size_t bytes_to_copy, char *buffer,
		   struct doca_buf *local_doca_buf, struct doca_buf *remote_doca_buf)
{
	struct doca_event event = {0};
	struct doca_dma_job_memcpy dma_job = {0};
	doca_error_t result;
	void *data;
	struct doca_buf *src_buf;
	struct doca_buf *dst_buf;
	struct timespec ts = {
		.tv_sec = 0,
		.tv_nsec = SLEEP_IN_NANOS,
	};

	/* Construct DMA job */
	dma_job.base.type = DOCA_DMA_JOB_MEMCPY;
	dma_job.base.flags = DOCA_JOB_FLAGS_NONE;
	dma_job.base.ctx = core_state->ctx;

	/* Determine DMA copy direction */
	if (cfg->is_file_found_locally) {
		src_buf = local_doca_buf;
		dst_buf = remote_doca_buf;
	} else {
		src_buf = remote_doca_buf;
		dst_buf = local_doca_buf;
	}

	/* Set data position in src_buf */
	result = doca_buf_get_data(src_buf, &data);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to get data address from DOCA buffer: %s", doca_get_error_string(result));
		return result;
	}
	result = doca_buf_set_data(src_buf, data, bytes_to_copy);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to set data for DOCA buffer: %s", doca_get_error_string(result));
		return result;
	}

	dma_job.src_buff = src_buf;
	dma_job.dst_buff = dst_buf;

	/* Enqueue DMA job */
	result = doca_workq_submit(core_state->workq, &dma_job.base);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to submit DMA job: %s", doca_get_error_string(result));
		return result;
	}

	/* Wait for job completion */
	while ((result = doca_workq_progress_retrieve(core_state->workq, &event, DOCA_WORKQ_RETRIEVE_FLAGS_NONE)) ==
	       DOCA_ERROR_AGAIN) {
		nanosleep(&ts, &ts);
	}

	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to retrieve DMA job: %s", doca_get_error_string(result));
		return result;
	}

	/* event result is valid */
	result = (doca_error_t)event.result.u64;
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("DMA job event returned unsuccessfully: %s", doca_get_error_string(result));
		return result;
	}

	DOCA_LOG_INFO("DMA copy was done Successfully");

	doca_buf_reset_data_len(local_doca_buf);
	doca_buf_reset_data_len(remote_doca_buf);

	/* If the buffer was copied into to DPU, save it as a file */
	if (!cfg->is_file_found_locally) {
		DOCA_LOG_INFO("Writing DMA buffer into a file on %s", cfg->file_path);
		result = save_buffer_into_a_file(cfg, buffer);
		if (result != DOCA_SUCCESS)
			return result;
	}

	return result;
}

static int
dma_enq_job(struct dma_copy_cfg *cfg, struct core_state *core_state, size_t bytes_to_copy) {
	struct mempool_elt * mbuf;
	struct doca_event event = {0};
	struct doca_dma_job_memcpy dma_job = {0};
	doca_error_t result;
	void *data;
	struct doca_buf *src_buf;
	struct doca_buf *dst_buf;

	mempool_get(core_state->mp, &mbuf);
	if (!mbuf) {
		return -1;
	}

	/* Construct DMA job */
	dma_job.base.type = DOCA_DMA_JOB_MEMCPY;
	dma_job.base.flags = DOCA_JOB_FLAGS_NONE;
	dma_job.base.ctx = core_state->ctx;
	dma_job.base.user_data.ptr = (void *)mbuf;

	/* Determine DMA copy direction */
	if (cfg->is_file_found_locally) {
		// src_buf = local_doca_buf;
		// dst_buf = remote_doca_buf;
		src_buf = mbuf->buf1;
		dst_buf = mbuf->buf2;
	} else {
		// src_buf = remote_doca_buf;
		// dst_buf = local_doca_buf;
		src_buf = mbuf->buf2;
		dst_buf = mbuf->buf1;
	}

	clock_gettime(CLOCK_MONOTONIC, &mbuf->ts);

	/* Set data position in src_buf */
	result = doca_buf_get_data(src_buf, &data);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to get data address from DOCA buffer: %s", doca_get_error_string(result));
		return result;
	}
	result = doca_buf_set_data(src_buf, data, bytes_to_copy);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to set data for DOCA buffer: %s", doca_get_error_string(result));
		return result;
	}

	dma_job.src_buff = src_buf;
	dma_job.dst_buff = dst_buf;

	/* Enqueue DMA job */
	result = doca_workq_submit(core_state->workq, &dma_job.base);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to submit DMA job: %s", doca_get_error_string(result));
		return result;
	}

	return result;
}

static int
dma_deq_job(struct dma_copy_cfg *cfg, struct core_state *core_state) {
	struct mempool_elt * mbuf;
	struct doca_event event = {0};
	doca_error_t result, dma_job_result;
	int nb_dequeue = 0;
	struct timespec now;

	clock_gettime(CLOCK_MONOTONIC, &now);

	do {
		result = doca_workq_progress_retrieve(core_state->workq, &event, DOCA_WORKQ_RETRIEVE_FLAGS_NONE);
		if (result == DOCA_SUCCESS) {
			mbuf = (struct mempool_elt *)event.user_data.ptr;
			doca_buf_reset_data_len(mbuf->buf1);
			doca_buf_reset_data_len(mbuf->buf2);
			mempool_put(core_state->mp, mbuf);
			/* event result is valid */
			dma_job_result = (doca_error_t)event.result.u64;
			if (dma_job_result != DOCA_SUCCESS) {
				DOCA_LOG_ERR("DMA job event returned unsuccessfully: %s", doca_get_error_string(result));
				return dma_job_result;
			} else {
				if (start_record && nr_latency < MAX_NR_LATENCY) {
					latency[nr_latency].start = TIMESPEC_TO_NSEC(mbuf->ts);
					latency[nr_latency].end = TIMESPEC_TO_NSEC(now);
					nr_latency++;
				}

				nb_dequeue++;
			}
		} else if (result == DOCA_ERROR_AGAIN) {
			break;
		} else {
			DOCA_LOG_ERR("Failed to dequeue results. Reason: %s", doca_get_error_string(result));
			return -1;
		}
	} while (result == DOCA_SUCCESS);

	return nb_dequeue;
}


/*
 * Set Comm Channel properties
 *
 * @mode [in]: Running mode
 * @ep [in]: DOCA comm_channel endpoint
 * @dev [in]: DOCA device object to use
 * @dev_rep [in]: DOCA device representor object to use
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
set_cc_properties(enum dma_copy_mode mode, struct doca_comm_channel_ep_t *ep, struct doca_dev *dev, struct doca_dev_rep *dev_rep)
{
	doca_error_t result;

	result = doca_comm_channel_ep_set_device(ep, dev);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to set DOCA device property");
		return result;
	}

	result = doca_comm_channel_ep_set_max_msg_size(ep, CC_MAX_MSG_SIZE);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to set max_msg_size property");
		return result;
	}

	result = doca_comm_channel_ep_set_send_queue_size(ep, CC_MAX_QUEUE_SIZE);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to set snd_queue_size property");
		return result;
	}

	result = doca_comm_channel_ep_set_recv_queue_size(ep, CC_MAX_QUEUE_SIZE);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to set rcv_queue_size property");
		return result;
	}

	if (mode == DMA_COPY_MODE_DPU) {
		result = doca_comm_channel_ep_set_device_rep(ep, dev_rep);
		if (result != DOCA_SUCCESS)
			DOCA_LOG_ERR("Failed to set DOCA device representor property");
	}

	return result;
}

void
destroy_cc(struct doca_comm_channel_ep_t *ep, struct doca_comm_channel_addr_t *peer,
	   struct doca_dev *dev, struct doca_dev_rep *dev_rep)
{
	doca_error_t result;

	if (peer != NULL) {
		result = doca_comm_channel_ep_disconnect(ep, peer);
		if (result != DOCA_SUCCESS)
			DOCA_LOG_ERR("Failed to disconnect from Comm Channel peer address: %s",
				     doca_get_error_string(result));
	}

	result = doca_comm_channel_ep_destroy(ep);
	if (result != DOCA_SUCCESS)
		DOCA_LOG_ERR("Failed to destroy Comm Channel endpoint: %s", doca_get_error_string(result));

	if (dev_rep != NULL) {
		result = doca_dev_rep_close(dev_rep);
		if (result != DOCA_SUCCESS)
			DOCA_LOG_ERR("Failed to close Comm Channel DOCA device representor: %s",
				     doca_get_error_string(result));
	}

	result = doca_dev_close(dev);
	if (result != DOCA_SUCCESS)
		DOCA_LOG_ERR("Failed to close Comm Channel DOCA device: %s", doca_get_error_string(result));
}

doca_error_t
init_cc(struct dma_copy_cfg *cfg, struct doca_comm_channel_ep_t **ep, struct doca_dev **dev, struct doca_dev_rep **dev_rep)
{
	doca_error_t result;

	result = doca_comm_channel_ep_create(ep);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create Comm Channel endpoint: %s", doca_get_error_string(result));
		return result;
	}

	result = open_doca_device_with_pci(cfg->cc_dev_pci_addr, NULL, dev);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to open Comm Channel DOCA device based on PCI address");
		doca_comm_channel_ep_destroy(*ep);
		return result;
	}

	/* Open DOCA device representor on DPU side */
	if (cfg->mode == DMA_COPY_MODE_DPU) {
		result = open_doca_device_rep_with_pci(*dev, DOCA_DEV_REP_FILTER_NET, cfg->cc_dev_rep_pci_addr, dev_rep);
		if (result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Failed to open Comm Channel DOCA device representor based on PCI address");
			doca_comm_channel_ep_destroy(*ep);
			doca_dev_close(*dev);
			return result;
		}
	}

	result = set_cc_properties(cfg->mode, *ep, *dev, *dev_rep);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to set Comm Channel properties");
		doca_comm_channel_ep_destroy(*ep);
		if (cfg->mode == DMA_COPY_MODE_DPU)
			doca_dev_rep_close(*dev_rep);
		doca_dev_close(*dev);
	}

	return result;
}

doca_error_t
register_dma_copy_params(void)
{
	doca_error_t result;
	struct doca_argp_param *nr_cores_param, *file_path_param, *dev_pci_addr_param, *rep_pci_addr_param, *rate_param;

    /* Number of worker cores callback */
	result = doca_argp_param_create(&nr_cores_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create ARGP param: %s", doca_get_error_string(result));
		return result;
	}
	doca_argp_param_set_short_name(nr_cores_param, "c");
	doca_argp_param_set_long_name(nr_cores_param, "core");
	doca_argp_param_set_description(nr_cores_param,
					"Number of cores submitting DMA jobs");
	doca_argp_param_set_callback(nr_cores_param, nr_cores_callback);
	doca_argp_param_set_type(nr_cores_param, DOCA_ARGP_TYPE_INT);
	doca_argp_param_set_mandatory(nr_cores_param);
	result = doca_argp_register_param(nr_cores_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to register program param: %s", doca_get_error_string(result));
		return result;
	}

	/* Create and register string to dma copy param */
	result = doca_argp_param_create(&file_path_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create ARGP param: %s", doca_get_error_string(result));
		return result;
	}
	doca_argp_param_set_short_name(file_path_param, "f");
	doca_argp_param_set_long_name(file_path_param, "file");
	doca_argp_param_set_description(file_path_param,
					"Full path to file to be copied/created after a successful DMA copy");
	doca_argp_param_set_callback(file_path_param, file_path_callback);
	doca_argp_param_set_type(file_path_param, DOCA_ARGP_TYPE_STRING);
	doca_argp_param_set_mandatory(file_path_param);
	result = doca_argp_register_param(file_path_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to register program param: %s", doca_get_error_string(result));
		return result;
	}

	/* Create and register Comm Channel DOCA device PCI address */
	result = doca_argp_param_create(&dev_pci_addr_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create ARGP param: %s", doca_get_error_string(result));
		return result;
	}
	doca_argp_param_set_short_name(dev_pci_addr_param, "p");
	doca_argp_param_set_long_name(dev_pci_addr_param, "pci-addr");
	doca_argp_param_set_description(dev_pci_addr_param,
					"DOCA Comm Channel device PCI address");
	doca_argp_param_set_callback(dev_pci_addr_param, dev_pci_addr_callback);
	doca_argp_param_set_type(dev_pci_addr_param, DOCA_ARGP_TYPE_STRING);
	doca_argp_param_set_mandatory(dev_pci_addr_param);
	result = doca_argp_register_param(dev_pci_addr_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to register program param: %s", doca_get_error_string(result));
		return result;
	}

	/* Create and register Comm Channel DOCA device representor PCI address */
	result = doca_argp_param_create(&rep_pci_addr_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create ARGP param: %s", doca_get_error_string(result));
		return result;
	}
	doca_argp_param_set_short_name(rep_pci_addr_param, "r");
	doca_argp_param_set_long_name(rep_pci_addr_param, "rep-pci");
	doca_argp_param_set_description(rep_pci_addr_param,
					"DOCA Comm Channel device representor PCI address (needed only on DPU)");
	doca_argp_param_set_callback(rep_pci_addr_param, rep_pci_addr_callback);
	doca_argp_param_set_type(rep_pci_addr_param, DOCA_ARGP_TYPE_STRING);
	result = doca_argp_register_param(rep_pci_addr_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to register program param: %s", doca_get_error_string(result));
		return result;
	}

	/* Create and register Comm Channel DOCA device representor PCI address */
	result = doca_argp_param_create(&rate_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create ARGP param: %s", doca_get_error_string(result));
		return result;
	}
	doca_argp_param_set_short_name(rate_param, "s");
	doca_argp_param_set_long_name(rate_param, "submit rate");
	doca_argp_param_set_description(rate_param, "Job submission rate");
	doca_argp_param_set_callback(rate_param, rate_callback);
	doca_argp_param_set_type(rate_param, DOCA_ARGP_TYPE_STRING);
	result = doca_argp_register_param(rate_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to register program param: %s", doca_get_error_string(result));
		return result;
	}

	/* Register validation callback */
	result = doca_argp_register_validation_callback(args_validation_callback);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to register program validation callback: %s", doca_get_error_string(result));
		return result;
	}

	return DOCA_SUCCESS;
}

#define NUM_WORKER	16

double ran_expo(double mean) {
    double u, x;
    drand48_r(&drand_buf, &x);
    return -log(1 - x) * mean;
}

void * dpu_start_dma_copy(void * arg) {
	struct core_state * state = (struct core_state *)arg;
	char *buffer;
	char *host_dma_addr = NULL;
	char export_desc_buf[CC_MAX_MSG_SIZE];
    struct doca_comm_channel_ep_t *ep = state->ep;
    struct doca_comm_channel_addr_t *peer_addr;
	struct doca_buf *remote_doca_buf;
	struct doca_buf *local_doca_buf;
	struct doca_mmap *remote_mmap;
	size_t host_dma_offset, export_desc_len;
	doca_error_t result;
	struct worker worker[NUM_WORKER];
    struct timespec begin, end, current_time;

	double interval;
	double mean = NUM_WORKER * dma_cfg.nr_cores * 1.0e6 / dma_cfg.rate;
	int ret;

	printf("Core %02d| Negotiate DMA copy direction with Host...\n", state->core_id);

	/* Negotiate DMA copy direction with Host */
	result = dpu_negotiate_dma_direction_and_size(&dma_cfg, state->core_id, ep, &peer_addr);
	if (result != DOCA_SUCCESS) {
		dpu_cleanup_core_objs(state);
		return NULL;
	}

	printf("Core %02d| Allocate memory...\n", state->core_id);

	latency = (struct lat_info *)calloc(MAX_NR_LATENCY, sizeof(struct lat_info));

	/* Allocate memory to be used for read operation in case file is found locally, otherwise grant write access */
	uint32_t access = dma_cfg.is_file_found_locally ? DOCA_ACCESS_LOCAL_READ_ONLY : DOCA_ACCESS_LOCAL_READ_WRITE;

	result = memory_alloc_and_populate(state, 128, dma_cfg.file_size, access, &(state->mp));
	if (result != DOCA_SUCCESS) {
		dpu_cleanup_core_objs(state);
		return NULL;
	}

	printf("Core %02d| Receive export descriptor from Host...\n", state->core_id);

	/* Receive export descriptor from Host */
	result = dpu_receive_export_desc(ep, &peer_addr, export_desc_buf, &export_desc_len);
	if (result != DOCA_SUCCESS) {
		dpu_cleanup_core_objs(state);
		return NULL;
	}

	printf("Core %02d| Receive remote address and offset from Host...\n", state->core_id);

	/* Receive remote address and offset from Host */
	result = dpu_receive_addr_and_offset(ep, &peer_addr, &host_dma_addr, &host_dma_offset);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create memory map from export");
		dpu_cleanup_core_objs(state);
		return NULL;
	}

	printf("Core %02d| Construct DOCA buffer for remote (Host) address range...\n", state->core_id);

	mempool_buf_inventory(state, state->mp, export_desc_buf, export_desc_len, host_dma_addr, host_dma_offset);

	printf("Core %02d| Fill buffer in file content if relevant...\n", state->core_id);

	/* Fill buffer in file content if relevant */
	if (dma_cfg.is_file_found_locally) {
		buffer = (char *)malloc(dma_cfg.file_size);
		result = fill_buffer_with_file_content(&dma_cfg, buffer);
		if (result != DOCA_SUCCESS) {
			send_status_msg(ep, &peer_addr, STATUS_FAILURE);
			doca_buf_refcount_rm(local_doca_buf, NULL);
			doca_buf_refcount_rm(remote_doca_buf, NULL);
			doca_mmap_destroy(remote_mmap);
			dpu_cleanup_core_objs(state);
			return NULL;
		}

		for (int i = 0; i < state->mp->nb_elt; i++) {
			struct mempool_elt * elt = (struct mempool_elt *)(state->mp->elts + i * state->mp->elt_size);
	        memcpy(&elt->addr, buffer, dma_cfg.file_size);
		}
	}

	printf("Core %02d| Initialize workers...\n", state->core_id);

	for (int i = 0; i < NUM_WORKER; i++) {
		worker[i].interval = 0;
		clock_gettime(CLOCK_MONOTONIC, &worker[i].last_enq_time);
	}

	// int i = 0;
	// struct mempool_elt * elt;
    // list_for_each_entry(elt, &state->mp->elt_free_list, list) {
    //     printf("%02d > elt(%p) buf1: %p, buf2: %p\n", i++, elt, elt->buf1, elt->buf2);
    // }

	printf("Core %02d| Submit DMA job into the queue and wait until job completion...\n", state->core_id);

	/* Submit DMA job into the queue and wait until job completion */
	// for (int i = 0; i < 10; i++) {
	// 	result = dpu_submit_dma_job(&dma_cfg, state, host_dma_offset, buffer, local_doca_buf, remote_doca_buf);
	// 	if (result != DOCA_SUCCESS) {
	// 		send_status_msg(ep, &peer_addr, STATUS_FAILURE);
	// 		doca_buf_refcount_rm(local_doca_buf, NULL);
	// 		doca_buf_refcount_rm(remote_doca_buf, NULL);
	// 		doca_mmap_destroy(remote_mmap);
	// 		dpu_cleanup_core_objs(state);
	// 		free(buffer);
	// 		return NULL;
	// 	}
	// }

	clock_gettime(CLOCK_MONOTONIC, &begin);

	while (1) {
    	clock_gettime(CLOCK_MONOTONIC, &current_time);
		if (current_time.tv_sec - begin.tv_sec > 5) {
			start_record = true;
		}

		if (current_time.tv_sec - begin.tv_sec > 10) {
            clock_gettime(CLOCK_MONOTONIC, &end);
			// FILE * output_fp;
			// char name[32];

			// sprintf(name, "thp-%d.txt", sched_getcpu());
			// output_fp = fopen(name, "w");
			// if (!output_fp) {
			// 	printf("Error opening throughput output file!\n");
			// 	return;
			// }

			// fprintf(output_fp, "%6.2lf\t%6.2lf\n", 
			// 	nb_enqueued * 1000000000.0 / (double)(TIMESPEC_TO_NSEC(end) - TIMESPEC_TO_NSEC(begin)), 
			// 	nb_dequeued * 1000000000.0 / (double)(TIMESPEC_TO_NSEC(end) - TIMESPEC_TO_NSEC(begin)));

			// fclose(output_fp);
			break;
		}

		for (int i = 0; i < NUM_WORKER; i++) {
			if (diff_timespec(&worker[i].last_enq_time, &current_time) > worker[i].interval) {
				ret = dma_enq_job(&dma_cfg, state, host_dma_offset);
				if (ret < 0) {
					continue;
				} else {
					state->nb_enqueued++;
					interval = ran_expo(mean);
					worker[i].interval = (uint64_t)round(interval);
					worker[i].last_enq_time = current_time;
				}
			}
		}

		ret = dma_deq_job(&dma_cfg, state);
		if (ret < 0) {
			DOCA_LOG_ERR("Failed to dequeue jobs responses");
			continue;
		} else {
			state->nb_dequeued += ret;
		}
	}

	send_status_msg(ep, &peer_addr, STATUS_SUCCESS);

	int lat_start = (int)(0.15 * nr_latency);
	FILE * latency_fp, * thp_fp;
	char name[32];

	sprintf(name, "latency-%d.txt", sched_getcpu());
	latency_fp = fopen(name, "w");
	if (!latency_fp) {
		printf("Error opening latency output file!\n");
		return NULL;
	}

	for (int i = lat_start; i < nr_latency; i++) {
		fprintf(latency_fp, "%lu\t%lu\t%lu\n", latency[i].start, latency[i].end, latency[i].end - latency[i].start);
	}

	fclose(latency_fp);

	sprintf(name, "thp-%d.txt", sched_getcpu());
	thp_fp = fopen(name, "w");
	if (!thp_fp) {
		printf("Error opening latency output file!\n");
		return NULL;
	}

	double enqueue_rate, dequeue_rate;
	enqueue_rate = state->nb_enqueued * 1000000000.0 / (double)(TIMESPEC_TO_NSEC(end) - TIMESPEC_TO_NSEC(begin));
	dequeue_rate = state->nb_dequeued * 1000000000.0 / (double)(TIMESPEC_TO_NSEC(end) - TIMESPEC_TO_NSEC(begin));
	
	printf("Enqueue: %u, %6.2lf(RPS), dequeue: %u, %6.2lf(RPS)\n", 
			state->nb_enqueued, enqueue_rate, state->nb_dequeued, dequeue_rate);

	fprintf(thp_fp, "%.2lf\t%.2lf\n", enqueue_rate, dequeue_rate);

	fclose(thp_fp);

	printf("Core %02d| Destroy Comm Channel...\n", state->core_id);

	/* Destroy Comm Channel */
	destroy_cc(ep, peer_addr, state->cc_dev, state->cc_dev_rep);

	// doca_buf_refcount_rm(remote_doca_buf, NULL);
	// doca_buf_refcount_rm(local_doca_buf, NULL);
	doca_mmap_destroy(remote_mmap);
	dpu_cleanup_core_objs(state);
	return NULL;
}
