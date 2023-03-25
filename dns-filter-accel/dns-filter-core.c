#include <stdint.h>
#include <termios.h>
#include <stdio.h>
#include <execinfo.h>
#include <signal.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/time.h>
#include <resolv.h>
#include <netinet/udp.h>

#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_malloc.h>
#include <rte_sft.h>

#include <doca_argp.h>
#include <doca_flow.h>
#include <doca_log.h>
#include <doca_mmap.h>
#include <doca_regex_mempool.h>

#include "dns-filter-core.h"

DOCA_LOG_REGISTER(DNS_FILTER::Core);

#define ETH_HEADER_SIZE 14			/* ETH header size = 14 bytes (112 bits) */
#define IP_HEADER_SIZE 	20			/* IP header size = 20 bytes (160 bits) */
#define UDP_HEADER_SIZE 8			/* UDP header size = 8 bytes (64 bits) */
#define DNS_HEADER_SIZE 12			/* DNS header size = 12 bytes (72 bits) */

static void
check_packets_marking(struct rte_mbuf **packets, uint16_t *packets_received)
{
	char * p;
	struct udphdr * u;
	struct rte_mbuf *packet;
	uint32_t current_packet, index = 0;

	for (current_packet = 0; current_packet < *packets_received; current_packet++) {
		packet = packets[current_packet];
		p = rte_pktmbuf_mtod(packet, char *);
		/* Skip UDP and DNS header to get DNS (query) start */
		p += ETH_HEADER_SIZE;
		p += IP_HEADER_SIZE;
		u = (struct udphdr *)p;

		if (ntohs(u->dest) == DNS_PORT) {
			/* Packet matched by one of pipe entries(rules) */
			packets[index] = packets[current_packet];
			index++;
			continue;
		}
		/* Packet didn't match by one of pipe entries(rules), packet received before rules offload */
		DOCA_DLOG_WARN("Packet received before rules offload");
	}
	/* Packets array will contain marked packets in places < index */
	*packets_received = index;
}

/*
 * Helper function to extract DNS query per packet
 *
 * @pkt [in]: packet to extract
 * @query [out]: a place where to store the pointer of DNS query
 * @return: 0 on success and negative value otherwise
 */
static int
extract_dns_query(struct rte_mbuf *pkt, char **query)
{
	int len, result;
	ns_msg handle; /* nameserver struct for DNS packet */
	struct rte_mbuf mbuf = *pkt;
	struct rte_sft_error error;
	struct rte_sft_mbuf_info mbuf_info;
	uint32_t payload_offset = 0;
	const unsigned char *data;

	/* Parse mbuf, and extract the query */
	result = rte_sft_parse_mbuf(&mbuf, &mbuf_info, NULL, &error);
	if (result) {
		DOCA_LOG_ERR("rte_sft_parse_mbuf error: %s", error.message);
		return result;
	}

	/* Calculate the offset of UDP header start */
	payload_offset += ((mbuf_info.l4_hdr - (void *)mbuf_info.eth_hdr));

	/* Skip UDP header to get DNS (query) start */
	payload_offset += UDP_HEADER_SIZE;

	/* Get a pointer to start of packet payload */
	data = (const unsigned char *)rte_pktmbuf_adj(&mbuf, payload_offset);
	if (data == NULL) {
		DOCA_LOG_ERR("Error in pkt mbuf adj");
		return -1;
	}
	len = rte_pktmbuf_data_len(&mbuf);

	/* Parse DNS packet information and fill them into handle fields */
	/* Ignore the timestamp field*/
	if (ns_initparse(data, len - sizeof(uint64_t), &handle) < 0) {
		DOCA_LOG_ERR("Fail to parse domain DNS packet");
		return -1;
	}

	/* Get DNS query start from handle field */
	*query = (char *)handle._sections[ns_s_qd];

	return 0;
}

/*
 * The main function for CPU workload, iterate on array of packets to extract the DNS queries
 *
 * @packets [in]: array of packets, metadata for bursting packets
 * @nb_packets [in]: packets array size
 * @queries [out]: array of strings holding the pointers to the DNS queries
 * @return: 0 on success and negative value otherwise
 */
static int
cpu_workload_run(struct rte_mbuf **packets, int nb_packets, char **queries)
{
	int i, result;

	for (i = 0; i < nb_packets; i++) {
		result = extract_dns_query(packets[i], &queries[i]);
		if (result < 0)
			return result;
	}
	return 0;
}

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
	uint64_t start, round_start, round_end, end;
	uint64_t ts1, ts2, ts3, ts4, submit;

	ts1 = ts2 = ts3 = ts4 = submit = 0;

	/* Start DNS workload */
	ret = cpu_workload_run(packets, packets_received, worker_ctx->queries);
	if (ret < 0)
		return ret;

	start = rte_rdtsc();
	/* Enqueue jobs to DOCA RegEx*/
	rx_count = tx_count = 0;
	while (tx_count < packets_received) {
		round_start = rte_rdtsc();
		for (; tx_count != packets_received;) {
			// printf("Process %ld packet(query: %p, query buf: %p, buf: %p)\n", 
			// 		tx_count, worker_ctx->queries[tx_count], worker_ctx->query_buf[tx_count], worker_ctx->buf[tx_count]);
			struct doca_buf *buf;
			void *mbuf_data;
			void *data_begin = (void *)worker_ctx->queries[tx_count];
			size_t data_len = strlen(data_begin);
#if 0
			buf = worker_ctx->buf[tx_count];
			memcpy(worker_ctx->query_buf[tx_count], data_begin, data_len);
			doca_buf_get_data(buf, &mbuf_data);
			doca_buf_set_data(buf, mbuf_data, data_len);
#endif

			ts1 = rte_rdtsc();
			/* Setup memory map
			*
			* Really what we want is the DOCA DPDK packet pool bridge which will make mkey management for packets buffers
			* very efficient. Right now we do not have this so we have to create a map each burst of packets and then tear
			* it down at the end of the burst
			*/
			result = doca_mmap_create(NULL, &worker_ctx->mmap);
			if (result != DOCA_SUCCESS) {
				DOCA_LOG_ERR("Unable to create mmap");
				return -1;
			}

			result = doca_mmap_set_max_num_chunks(worker_ctx->mmap, PACKET_BURST);
			if (result != DOCA_SUCCESS) {
				DOCA_LOG_ERR("Unable to set memory map number of regions: %s", doca_get_error_string(result));
				doca_mmap_destroy(worker_ctx->mmap);
				return -1;
			}

			result = doca_mmap_start(worker_ctx->mmap);
			if (result != DOCA_SUCCESS) {
				DOCA_LOG_ERR("Unable to start memory map: %s", doca_get_error_string(result));
				doca_mmap_destroy(worker_ctx->mmap);
				return -1;
			}

			result = doca_mmap_dev_add(worker_ctx->mmap, worker_ctx->app_cfg->dev);
			if (result != DOCA_SUCCESS) {
				DOCA_LOG_ERR("Unable to add device to mmap: %s", doca_get_error_string(result));
				doca_mmap_stop(worker_ctx->mmap);
				doca_mmap_destroy(worker_ctx->mmap);
				return -1;
			}

			ts2 = rte_rdtsc();
			/* register packet in mmap */
			result = doca_mmap_populate(worker_ctx->mmap, data_begin, data_len, sysconf(_SC_PAGESIZE), NULL, NULL);
			if (result != DOCA_SUCCESS) {
				DOCA_LOG_ERR("Unable to populate memory map (input): %s", doca_get_error_string(result));
				ret = -1;
				goto doca_buf_cleanup;
			}

			/* build doca_buf */
			result = doca_buf_inventory_buf_by_addr(worker_ctx->buf_inventory, worker_ctx->mmap, data_begin, data_len, &buf);
			if (result != DOCA_SUCCESS) {
				DOCA_LOG_ERR("Unable to acquire DOCA buffer for job data: %s",
						doca_get_error_string(result));
				ret = -1;
				goto doca_buf_cleanup;
			}
			ts3 = rte_rdtsc();

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
				DOCA_LOG_ERR("Failed to enqueue RegEx job (%s)", doca_get_error_string(result));
				printf("buf: %p\n", buf);
				ret = -1;
				goto doca_buf_cleanup;
			}
			ts4 = rte_rdtsc();
			printf("t1 -> t2: %lu, t2 -> t3: %lu, ts4 -> ts3: %lu\n", ts2 - ts1, ts3 - ts2, ts4 - ts3);
		}

		submit = rte_rdtsc();

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
		round_end = rte_rdtsc();
		printf("round start -> submit: %lu, submit -> round end: %lu\n", submit - round_start, round_end - submit);
	}

	end = rte_rdtsc();
	printf("start -> end: %lu\n", end - start);

doca_buf_cleanup:
	for (ii = 0; ii != tx_count; ++ii)
		doca_buf_refcount_rm(worker_ctx->buffers[ii], NULL);

	doca_mmap_dev_rm(worker_ctx->mmap, worker_ctx->app_cfg->dev);
	doca_mmap_stop(worker_ctx->mmap);
	doca_mmap_destroy(worker_ctx->mmap);
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
handle_packets_received(int pid, struct dns_worker_ctx *worker_ctx, struct rte_mbuf **packets, uint16_t packets_received)
{
	int ret;
	// uint8_t egress_port;

	/* Check packets marking */
	check_packets_marking(packets, &packets_received);
	if (packets_received == 0) {
		return packets_received;
	}

	printf("Receive %d packets\n", packets_received);

	/* Start RegEx jobs */
	ret = regex_processing(worker_ctx, packets_received, packets);
	if (ret < 0) {
		return ret;
    }

	return packets_received;
}