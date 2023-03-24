#include <stdint.h>
#include <termios.h>
#include <stdio.h>
#include <execinfo.h>
#include <signal.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/time.h>

#include "dns-filter-core.h"

/*
 * In this function happened the inspection of DNS packets and classify if the query fit the listing type
 * The inspection includes extracting DNS query and set it to RegEx engine to check a match
 *
 * @worker_ctx [in]: a pointer to DNS worker configuration struct
 * @packets_received [in]: size of mbufs array
 * @packets [in]: mbufs array
 * @return: 0 on success and negative value otherwise
 */
static int
regex_processing(struct dns_worker_ctx *worker_ctx, uint16_t packets_received, struct rte_mbuf **packets)
{
	size_t tx_count, rx_count, ii;
	doca_error_t result;
	int ret = 0;
	struct doca_mmap *mmap;
	uint32_t const num_mem_regions = packets_received;

	/* Start DNS workload */
	ret = cpu_workload_run(packets, packets_received, worker_ctx->queries);
	if (ret < 0)
		return ret;

	/* Setup memory map
	 *
	 * Really what we want is the DOCA DPDK packet pool bridge which will make mkey management for packets buffers
	 * very efficient. Right now we do not have this so we have to create a map each burst of packets and then tear
	 * it down at the end of the burst
	 */
	result = doca_mmap_create(NULL, &mmap);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to create mmap");
		return -1;
	}

	result = doca_mmap_set_max_num_chunks(mmap, num_mem_regions);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to set memory map number of regions: %s", doca_get_error_string(result));
		doca_mmap_destroy(mmap);
		return -1;
	}

	result = doca_mmap_start(mmap);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to start memory map: %s", doca_get_error_string(result));
		doca_mmap_destroy(mmap);
		return -1;
	}

	result = doca_mmap_dev_add(mmap, worker_ctx->app_cfg->dev);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to add device to mmap: %s", doca_get_error_string(result));
		doca_mmap_stop(mmap);
		doca_mmap_destroy(mmap);
		return -1;
	}

	/* Enqueue jobs to DOCA RegEx*/
	rx_count = tx_count = 0;
	while (tx_count < packets_received) {
		for (; tx_count != packets_received;) {
			struct doca_buf *buf;
			void *data_begin = (void *)worker_ctx->queries[tx_count];
			size_t data_len = strlen(worker_ctx->queries[tx_count]);
			void *mbuf_data;

			/* register packet in mmap */
			result = doca_mmap_populate(mmap, data_begin, data_len, sysconf(_SC_PAGESIZE), NULL, NULL);
			if (result != DOCA_SUCCESS) {
				DOCA_LOG_ERR("Unable to populate memory map (input): %s", doca_get_error_string(result));
				ret = -1;
				goto doca_buf_cleanup;
			}

			/* build doca_buf */
			result = doca_buf_inventory_buf_by_addr(worker_ctx->buf_inventory, mmap, data_begin, data_len,
								&buf);
			if (result != DOCA_SUCCESS) {
				DOCA_LOG_ERR("Unable to acquire DOCA buffer for job data: %s",
						doca_get_error_string(result));
				ret = -1;
				goto doca_buf_cleanup;
			}
			doca_buf_get_data(buf, &mbuf_data);
			doca_buf_set_data(buf, mbuf_data, data_len);

			struct doca_regex_job_search const job_request = {
					.base = {
						.type = DOCA_REGEX_JOB_SEARCH,
						.ctx = doca_regex_as_ctx(worker_ctx->app_cfg->doca_reg),
						.user_data = {.u64 = tx_count },
					},
					.rule_group_ids = {1, 0, 0, 0},
					.buffer = buf,
					.result = worker_ctx->responses + tx_count,
					.allow_batching = tx_count != (packets_received - 1),
			};

			result = doca_workq_submit(worker_ctx->workq, (struct doca_job *)&job_request);
			if (result == DOCA_ERROR_NO_MEMORY) {
				doca_buf_refcount_rm(buf, NULL);
				break;
			}

			if (result == DOCA_SUCCESS) {
				worker_ctx->buffers[tx_count] = buf;
				++tx_count;
			} else {
				DOCA_LOG_ERR("Failed to enqueue RegEx job");
				ret = -1;
				goto doca_buf_cleanup;
			}
		}

		for (; rx_count != tx_count;) {
			/* dequeue one */
			struct timespec ts;
			struct doca_event event = {0};

			result = doca_workq_progress_retrieve(worker_ctx->workq, &event, DOCA_WORKQ_RETRIEVE_FLAGS_NONE);
			if (result == DOCA_SUCCESS) {
				/* Handle the completed jobs */
				++rx_count;
			} else if (result == DOCA_ERROR_AGAIN) {

				/* Wait for the job to complete */
				ts.tv_sec = 0;
				ts.tv_nsec = SLEEP_IN_NANOS;
				nanosleep(&ts, &ts);
			} else {
				DOCA_LOG_ERR("Failed to dequeue RegEx job response");
				ret = -1;
				goto doca_buf_cleanup;
			}
		}
	}

doca_buf_cleanup:
	for (ii = 0; ii != tx_count; ++ii)
		doca_buf_refcount_rm(worker_ctx->buffers[ii], NULL);

	doca_mmap_dev_rm(mmap, worker_ctx->app_cfg->dev);
	doca_mmap_stop(mmap);
	doca_mmap_destroy(mmap);
	return ret;
}

/*
 * The main function for handling the new received packets
 *
 * @worker_ctx [in]: a pointer to DNS worker configuration struct
 * @packets_received [in]: size of mbufs array
 * @packets [in]: array of packets
 * @return: 0 on success and negative value otherwise
 */
int
handle_packets_received(struct dns_worker_ctx *worker_ctx, struct rte_mbuf **packets, uint16_t packets_received)
{
	int packets_count, ret;
	uint8_t ingress_port;
	uint32_t current_packet;
	struct rte_mbuf *packets_to_send[PACKET_BURST] = {0};
	char *valid_queries[PACKET_BURST] = {0};

	/* Start RegEx jobs */
	ret = regex_processing(worker_ctx, packets_received, packets);
	if (ret < 0) {
		return ret;
    }

	/* filter DNS packets depending to DOCA RegEx responses */
	packets_count = filter_listing_packets(worker_ctx, packets_received, packets, valid_queries, packets_to_send);
	if (packets_count < 0) {
		return -1;
    }

	if (packets_count > 0) {
		/* Packet sent to port 0 or 1 */
		ingress_port = packets_to_send[0]->port ^ 1;
		ret = rte_eth_tx_burst(ingress_port, worker_ctx->queue_id, packets_to_send, packets_count);
		transmitted += ret;
	}

	return 0;
}