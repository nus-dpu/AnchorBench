/*
 * Copyright (c) 2021-2022 NVIDIA CORPORATION & AFFILIATES, ALL RIGHTS RESERVED.
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
#include <arpa/nameser.h>
#include <bsd/string.h>
#include <getopt.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <resolv.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>

#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_malloc.h>
#include <rte_sft.h>

#include <doca_argp.h>
#include <doca_flow.h>
#include <doca_log.h>
#include <doca_mmap.h>
#include <doca_regex_mempool.h>

#include <common.h>

#include <dpdk_utils.h>
#include <offload_rules.h>
#include <utils.h>

#include "dns_filter_core.h"

DOCA_LOG_REGISTER(DNS_FILTER::Core);

#define PACKET_BURST 32			/* The number of packets in the rx queue */
#define DNS_PORT 53				/* DNS packet dst port */
#define UDP_HEADER_SIZE 8			/* UDP header size = 8 bytes (64 bits) */
#define MAX_PORT_STR_LEN 128			/* Maximal length of port name */
#define MAX_DNS_QUERY_LEN 512			/* Maximal length of DNS query */
#define PACKET_MARKER 7				/* Value for marking the matched packets */
#define DNS_PORTS_NUM 2				/* Number of ports that are used by the application */
#define SLEEP_IN_NANOS (10 * 1000)		/* Sample the job every 10 microseconds  */
#define DEFAULT_TIMEOUT_US (10000)		/* Timeout for processing pipe entries */

static bool force_quit;					/* Shared variable to communicate between DPDK threads */
struct doca_flow_port *ports[DNS_PORTS_NUM];		/* Holds DOCA flow ports instances */

/*
 * Signals handler function
 * Once a signal is received by the APP proccess, update the shared variable between the APP threads and quit
 *
 * @signum [in]: signal number
 */
static void
signal_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM) {
		DOCA_LOG_INFO("Signal %d received, preparing to exit...", signum);
		force_quit = true;
	}
}

/*
 * RegEx context initialization
 *
 * @app_cfg [in/out]: application configuration structure
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
regex_init(struct dns_filter_config *app_cfg)
{
	doca_error_t result;
	char *rules_file_data;
	size_t rules_file_size;

	result = open_doca_device_with_pci(&app_cfg->pci_address, NULL, &app_cfg->dev);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("No device matching PCI address found. Reason: %s", doca_get_error_string(result));
		return result;
	}

	/* Create a DOCA RegEx instance */
	result = doca_regex_create(&(app_cfg->doca_reg));
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("DOCA RegEx creation Failed. Reason: %s", doca_get_error_string(result));
		doca_dev_close(app_cfg->dev);
		return DOCA_ERROR_INITIALIZATION;
	}

	/* Set hw RegEx device to DOCA RegEx */
	result = doca_ctx_dev_add(doca_regex_as_ctx(app_cfg->doca_reg), app_cfg->dev);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to install RegEx device. Reason: %s", doca_get_error_string(result));
		result = DOCA_ERROR_INITIALIZATION;
		goto regex_cleanup;
	}
	/* Set matches memory pool to 0 because the app needs to check if there are matches and don't need the matches details  */
	result = doca_regex_set_workq_matches_memory_pool_size(app_cfg->doca_reg, 0);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to create match memory pools. Reason: %s", doca_get_error_string(result));
		goto regex_cleanup;
	}

	/* Attach rules file to DOCA RegEx */
	result = read_file(app_cfg->rules_file_path, &rules_file_data, &rules_file_size);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to load rules file content. Reason: %s", doca_get_error_string(result));
		goto regex_cleanup;
	}

	result = doca_regex_set_hardware_compiled_rules(app_cfg->doca_reg, rules_file_data, rules_file_size);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to program rules. Reason: %s", doca_get_error_string(result));
		free(rules_file_data);
		goto regex_cleanup;
	}
	free(rules_file_data);

	/* Start DOCA RegEx */
	result = doca_ctx_start(doca_regex_as_ctx(app_cfg->doca_reg));
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to start DOCA RegEx");
		result = DOCA_ERROR_INITIALIZATION;
		goto regex_cleanup;
	}
	return DOCA_SUCCESS;

regex_cleanup:
	doca_dev_close(app_cfg->dev);
	doca_regex_destroy(app_cfg->doca_reg);
	return result;
}

/*
 * Update DOCA flow entry with 5-tuple of current packet
 *
 * @mbuf [in]: packet mbuf
 * @match [out]: holds matcher information according to packet mbuf fields
 */
static void
update_packet_match(struct rte_mbuf *mbuf, struct doca_flow_match *match)
{
	struct rte_ipv4_hdr *ipv4_hdr_outer_l3 =
		rte_pktmbuf_mtod_offset(mbuf, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
	uint8_t *ipv4_hdr = ((uint8_t *)ipv4_hdr_outer_l3 + rte_ipv4_hdr_len(ipv4_hdr_outer_l3));
	struct rte_udp_hdr *udp_hdr_outer_l4 = (typeof(udp_hdr_outer_l4))ipv4_hdr;

	/* Update the match field with packet 5-tuple */
	match->out_dst_ip.ipv4_addr = ipv4_hdr_outer_l3->dst_addr;
	match->out_src_ip.ipv4_addr = ipv4_hdr_outer_l3->src_addr;
	match->out_src_port = udp_hdr_outer_l4->src_port;
}

/*
 * Add entry with DROP action to block the incoming packets with the same 5-tuple
 *
 * @app_cfg [in]: application configuration structure
 * @queue_id [in]: ID of queue to insert the entry to it
 * @mbuf [in]: packet mbuf
 * @return: 0 on success and negative value otherwise
 */
static int
restrict_packet(struct dns_filter_config *app_cfg, int queue_id, struct rte_mbuf *mbuf)
{
	struct doca_flow_match match = {0};
	struct doca_flow_actions action = {0};
	struct doca_flow_error error = {0};
	struct doca_flow_pipe *pipe = app_cfg->drop_pipes[mbuf->port];
	struct doca_flow_pipe_entry *entry;
	int processed, num_of_entries = 1;

	/* Add hw entry to DNS drop pipe which presents current packet 5-tuple */
	DOCA_DLOG_DBG("restricting packet:");
	update_packet_match(mbuf, &match);
	entry = doca_flow_pipe_add_entry(queue_id, pipe, &match, &action, NULL, NULL, DOCA_FLOW_NO_WAIT, NULL, &error);
	if (entry == NULL) {
		DOCA_LOG_ERR("entry creation FAILED: %s", error.message);
		return -1;
	}

	processed = doca_flow_entries_process(ports[mbuf->port], queue_id, DEFAULT_TIMEOUT_US, num_of_entries);
	if (processed != num_of_entries || doca_flow_pipe_entry_get_status(entry) != DOCA_FLOW_ENTRY_STATUS_SUCCESS) {
		DOCA_LOG_ERR("entry creation FAILED");
		return -1;
	}
	return 0;
}

#ifdef GPU_SUPPORT
/*
 * The main function for GPU workload(extracting DNS queries in parallel),
 * it prepares the relevant input to start a CUDA kernel
 *
 * @packets [in]: array of packets
 * @nb_packets [in]: packets array size
 * @worker_ctx [in/out]: a data structure holding worker ctx details
 * @return: 0 on success and negative value otherwise
 *
 * @NOTE: the array allocated in CPU memory and registered to GPU device to allow the access to it)
 */
static int
gpu_workload_run(struct rte_mbuf **packets, uint16_t nb_packets, struct dns_worker_ctx *worker_ctx)
{
	int result;
	char **queries = worker_ctx->queries;
	enum rte_gpu_comm_list_status status;
	struct gpu_pipeline *pipe = &worker_ctx->app_cfg->dpdk_cfg->pipe;

	/* Comm_list is an array of communication objects, associating one object per DNS worker to avoid Race Condition */
	if (worker_ctx->queue_id >= COMM_LIST_LEN) {
		DOCA_LOG_ERR("DNS worker id greater than the maximum -[%d]", COMM_LIST_LEN-1);
		return -1;
	}

	/* Update the communication list with informations from the list of mbufs (packet address, number of packets...) */
	result = rte_gpu_comm_populate_list_pkts(&pipe->comm_list[worker_ctx->queue_id], packets, nb_packets);
	if (result != 0) {
		DOCA_LOG_ERR("rte_gpu_comm_populate_list_pkts returned error %d", result);
		return result;
	}

	/* Wrapper function, create a CUDA kernal to start GPU workload */
	workload_launch_gpu_processing(&pipe->comm_list[worker_ctx->queue_id], pipe->c_stream, queries);

	/* Waiting until GPU workload is done, comm_list.status will be updated once GPU done */
	do {
		/* Get the workload status using atomic function */
		result = rte_gpu_comm_get_status(&pipe->comm_list[worker_ctx->queue_id], &status);
		if (result < 0) {
			DOCA_LOG_ERR("rte_gpu_comm_get_status error, killing the app.");
			return result;
		}
	} while (!force_quit && status != RTE_GPU_COMM_LIST_DONE);

	/* Check if happened any error in GPU side */
	CUDA_ERROR_CHECK(cudaGetLastError());

	return 0;
}
#else
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
#endif

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
#ifdef GPU_SUPPORT
	ret = gpu_workload_run(packets, packets_received, worker_ctx);
#else
	ret = cpu_workload_run(packets, packets_received, worker_ctx->queries);
#endif
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

#define ETH_HEADER_SIZE 14			/* ETH header size = 14 bytes (112 bits) */
#define IP_HEADER_SIZE 	20			/* IP header size = 20 bytes (160 bits) */

/*
 * This function filters the received packets according to RegEx results to send them back to their destination
 *
 * @worker_ctx [in]: a pointer to DNS worker configuration struct
 * @packets_received [in]: size of mbufs array
 * @packets [in]: packets burst
 * @valid_queries [out]: holds the queries of filtered packets
 * @packets_to_send [out]: holds mbufs of filtered packets to send them back by calling rte_eth_tx_burst()
 * @return: 0 on success and negative value otherwise
 */
static int
filter_listing_packets(struct dns_worker_ctx *worker_ctx, uint16_t packets_received, struct rte_mbuf **packets,
	char **valid_queries, struct rte_mbuf **packets_to_send)
{
	char *query, *p;
	bool to_restrict;
	int packets_count = 0;
	uint32_t current_packet;
	struct rte_mbuf *packet;
	int result;

	for (current_packet = 0; current_packet < packets_received; current_packet++) {
		packet = packets[current_packet];
		query = (char *)worker_ctx->queries[current_packet];
		switch (worker_ctx->app_cfg->listing_type) {
		case DNS_ALLOW_LISTING:
			/* Filtering as allowlist option */
			if (worker_ctx->responses[current_packet].detected_matches != 0)
				to_restrict = false;
			else
				to_restrict = true;
			break;
		case DNS_DENY_LISTING:
			/* Filtering as denylist option */
			if (worker_ctx->responses[current_packet].detected_matches == 0)
				to_restrict = false;
			else
				to_restrict = true;
			break;
		default:
			DOCA_LOG_ERR("Invalid listing type");
			return -1;
		}
		if (to_restrict) {
			/* Blocking current packet */
			result = restrict_packet(worker_ctx->app_cfg, worker_ctx->queue_id, packet);
			if (result < 0)
				return result;
			DOCA_DLOG_DBG("DNS query:  %s", query);
		} else {
			/* Hold packet and forward to the ingress port */
			packets_to_send[packets_count] = packet;
			valid_queries[packets_count++] = query;
		}
	}
	return packets_count;
}

/*
 * Filtering the received packets before APP rules offload
 * While application uploading and before adding offload rules for DNS packets,
 * non-DNS packets may be received to RX queues and the application will read them when calling (rte_eth_rx_burst ())
 * Marking mode for matched packets is enabled in order to classify if the received packets were already
 * in the Rx queues before adding the rules
 *
 * @packets [in]: array of bursted packets
 * @packets_received [out]: stores the fixing size of packets array
 *
 * @NOTE: this function filters packets array to include only the marked packets (matched by one of the rules)
 */
static void
check_packets_marking(struct rte_mbuf **packets, uint16_t *packets_received)
{
	struct rte_mbuf *packet;
	uint32_t current_packet, index = 0;

	for (current_packet = 0; current_packet < *packets_received; current_packet++) {
		packet = packets[current_packet];
		if (packet->hash.fdir.hi == PACKET_MARKER) {
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

__thread int start_flag = 0;
__thread int done_flag = 0;
__thread struct timeval start;
__thread uint64_t received = 0;
__thread uint64_t transmitted = 0;

#define MSEC_PER_SEC    1000L
#define USEC_PER_MSEC   1000L
#define TIMEVAL_TO_MSEC(t)  ((t.tv_sec * MSEC_PER_SEC) + (t.tv_usec / USEC_PER_MSEC))

/*
 * The main function for handling the new received packets
 *
 * @worker_ctx [in]: a pointer to DNS worker configuration struct
 * @packets_received [in]: size of mbufs array
 * @packets [in]: array of packets
 * @return: 0 on success and negative value otherwise
 */
static int
handle_packets_received(struct dns_worker_ctx *worker_ctx, uint16_t packets_received, struct rte_mbuf **packets)
{
	int packets_count, ret;
	uint8_t ingress_port;
	uint32_t current_packet;
	struct rte_mbuf *packets_to_send[PACKET_BURST] = {0};
	char *valid_queries[PACKET_BURST] = {0};

	struct rte_mbuf *packet;
	struct udphdr * u;

	for (int i = 0; i < packets_received; i++) {
		packet = packets[i];
		p = rte_pktmbuf_mtod(packet, char *);
		/* Skip UDP and DNS header to get DNS (query) start */
		p += ETH_HEADER_SIZE;
		p += IP_HEADER_SIZE;
		u = (struct udphdr *)p;
		printf("UDP src: %u, UDP dst: %u\n", ntohs(u->source), ntohs(u->dest));
	}

	/* Check packets marking */
	check_packets_marking(packets, &packets_received);
	if (packets_received == 0)
		return packets_received;

	/* Start RegEx jobs */
	ret = regex_processing(worker_ctx, packets_received, packets);
	if (ret < 0)
		return ret;

	/* filter DNS packets depending to DOCA RegEx responses */
	packets_count = filter_listing_packets(worker_ctx, packets_received, packets, valid_queries, packets_to_send);
	if (packets_count < 0)
		return -1;

	/* Deciding the port to send the packet to */
	for (current_packet = 0; current_packet < packets_count; current_packet++)
		/* Print DNS packet info */
		DOCA_DLOG_DBG("DNS query:  %s", valid_queries[current_packet]);

	if (packets_count > 0) {
		/* Packet sent to port 0 or 1 */
		ingress_port = packets_to_send[0]->port ^ 1;
		ret = rte_eth_tx_burst(ingress_port, worker_ctx->queue_id, packets_to_send, packets_count);
		transmitted += ret;
	}

	return 0;
}

/*
 * Dequeue packets from DPDK queue, queue id equals to worker_ctx->queue_id, and send them for APP processing
 *
 * @worker_ctx [in]: a pointer to DNS worker configuration struct
 * @ingress_port [in]: port id for dequeue packets
 * @return: 0 on success and negative value otherwise
 */
static int
process_packets(struct dns_worker_ctx *worker_ctx, int ingress_port)
{
	struct rte_mbuf *packets[PACKET_BURST];
	int nb_packets = rte_eth_rx_burst(ingress_port, worker_ctx->queue_id, packets, PACKET_BURST);
	int result;

	/* Handle the received packets from a queue with id = worker_ctx->queue_id */
	if (nb_packets) {
		if (!start_flag) {
			start_flag = 1;
			gettimeofday(&start, NULL);
		}
		DOCA_DLOG_DBG("Received %d packets from port 0x%x using core %u", nb_packets, ingress_port, rte_lcore_id());
		result = handle_packets_received(worker_ctx, nb_packets, packets);
		if (result < 0)
			return result;
		received += nb_packets;
	}
	return 0;
}

/*
 * Worker main function, run in busy wait for reading packets until receiving quit signal or until an error is encountered
 *
 * @args [in]: a generic pointer to DNS worker configuration struct, one context per thread(worker)
 */
static void
dns_filter_worker(void *args)
{
	struct dns_worker_ctx *worker_ctx = (struct dns_worker_ctx *)args;
	int ingress_port, nb_ports = worker_ctx->app_cfg->dpdk_cfg->port_config.nb_ports;
	int result;
	float tot_recv_rate, tot_send_rate;
	struct timeval curr;

	DOCA_LOG_DBG("Core %u is receiving packets.", rte_lcore_id());
	while (!force_quit) {
		for (ingress_port = 0; ingress_port < nb_ports; ingress_port++) {
			result = process_packets(worker_ctx, ingress_port);
			if (result < 0) {
				force_quit = true;
				break;
			}
		}
		gettimeofday(&curr, NULL);
		if (start_flag && !done_flag) {
			if (curr.tv_sec - start.tv_sec >= 20) {
				tot_recv_rate = (float)received / (TIMEVAL_TO_MSEC(curr) - TIMEVAL_TO_MSEC(start));
				tot_send_rate = (float)transmitted / (TIMEVAL_TO_MSEC(curr) - TIMEVAL_TO_MSEC(start));
				printf("CORE %d ==> RX: %8.2f (KPS), TX: %8.2f (KPS)\n", rte_lcore_id(), tot_recv_rate , tot_send_rate);
				done_flag = 1;
			}
		}
	}

#ifdef GPU_SUPPORT
	/* Unregister the array of queries */
	int ret = rte_gpu_mem_unregister(worker_ctx->app_cfg->dpdk_cfg->pipe.gpu_id, worker_ctx->queries);

	if (ret < 0)
		DOCA_LOG_ERR("GPU MEM unregistration failed with error [%d]", ret);
#endif
	doca_ctx_workq_rm(doca_regex_as_ctx(worker_ctx->app_cfg->doca_reg), worker_ctx->workq);
	doca_workq_destroy(worker_ctx->workq);
	doca_buf_inventory_stop(worker_ctx->buf_inventory);
	doca_buf_inventory_destroy(worker_ctx->buf_inventory);
	rte_free(worker_ctx->queries);
	rte_free(worker_ctx);
}

/*
 * create DNS drop pipe for blocking packets per APP port
 *
 * @port [in]: pointer to DOCA flow port
 * @dns_pipe [in]: DNS FW pipe, it is the next pipe of the DROP pipe
 * @return: pipe handler on success and NULL otherwise
 */
static struct doca_flow_pipe *
build_drop_pipe(struct doca_flow_port *port, struct doca_flow_pipe *dns_pipe)
{
	struct doca_flow_pipe *drop_pipe;
	struct doca_flow_error err = {0};
	struct doca_flow_pipe_cfg drop_pipe_cfg = {0};
	struct doca_flow_match drop_match;
	struct doca_flow_actions actions;
	struct doca_flow_actions *actions_array[1];
	struct doca_flow_fwd drop_fw;
	struct doca_flow_fwd drop_miss_fw;

	/* Allocate DNS drop pipe fields */
	memset(&actions, 0, sizeof(actions));
	memset(&drop_fw, 0, sizeof(drop_fw));
	memset(&drop_miss_fw, 0, sizeof(drop_miss_fw));
	memset(&drop_match, 0, sizeof(drop_match));
	memset(&drop_pipe_cfg, 0, sizeof(drop_pipe_cfg));

	drop_pipe_cfg.attr.name = "DNS_DROP_PIPE";
	drop_pipe_cfg.attr.type = DOCA_FLOW_PIPE_BASIC;
	drop_pipe_cfg.match = &drop_match;
	actions_array[0] = &actions;
	drop_pipe_cfg.actions = actions_array;
	drop_pipe_cfg.attr.nb_actions = 1;
	drop_pipe_cfg.port = port;
	drop_pipe_cfg.attr.is_root = true;

	drop_match.out_dst_ip.ipv4_addr = 0xffffffff;
	drop_match.out_src_ip.ipv4_addr = 0xffffffff;
	drop_match.out_dst_ip.type = DOCA_FLOW_IP4_ADDR;
	drop_match.out_src_ip.type = DOCA_FLOW_IP4_ADDR;
	drop_match.out_l4_type = DOCA_PROTO_UDP;
	drop_match.out_dst_port = rte_cpu_to_be_16(DNS_PORT);
	drop_match.out_src_port = 0xffff;

	drop_fw.type = DOCA_FLOW_FWD_DROP;

	drop_miss_fw.type = DOCA_FLOW_FWD_PIPE;
	drop_miss_fw.next_pipe = dns_pipe;

	/* Create DNS drop pipe */
	drop_pipe = doca_flow_pipe_create(&drop_pipe_cfg, &drop_fw, &drop_miss_fw, &err);
	if (drop_pipe == NULL) {
		DOCA_LOG_ERR("DNS pipe creation FAILED: %s", err.message);
		return NULL;
	}
	return drop_pipe;
}

/*
 * create DNS forward pipe per APP port
 *
 * @app_cfg [in]: application configuration structure
 * @port [in]: pointer to DOCA flow port
 * @hairpin_pipe [in]: DNS hairpin pipe, it is the next pipe of the forward pipe
 * @return: pipe handler on success and NULL otherwise
 */
static struct doca_flow_pipe *
build_dns_pipe(struct dns_filter_config *app_cfg, struct doca_flow_port *port, struct doca_flow_pipe *hairpin_pipe)
{
	int queue_index, nb_queues = app_cfg->dpdk_cfg->port_config.nb_queues;
	struct doca_flow_match dns_match;
	struct doca_flow_fwd dns_fw, dns_miss_fw;
	struct doca_flow_actions actions;
	struct doca_flow_actions *actions_array[1];
	struct doca_flow_pipe_cfg dns_pipe_cfg = {0};
	struct doca_flow_pipe *dns_pipe;
	struct doca_flow_error err = {0};
	uint16_t rss_queues[nb_queues];
	struct doca_flow_pipe_entry *entry;
	int processed, num_of_entries = 1;

	/* Allocate DNS pipe fields */
	memset(&actions, 0, sizeof(actions));
	memset(&dns_fw, 0, sizeof(dns_fw));
	memset(&dns_miss_fw, 0, sizeof(dns_miss_fw));
	memset(&dns_match, 0, sizeof(dns_match));
	memset(&dns_pipe_cfg, 0, sizeof(dns_pipe_cfg));

	actions.meta.mark = PACKET_MARKER;
	dns_pipe_cfg.attr.name = "DNS_FW_PIPE";
	dns_pipe_cfg.attr.type = DOCA_FLOW_PIPE_BASIC;
	dns_pipe_cfg.match = &dns_match;
	dns_pipe_cfg.port = port;
	actions_array[0] = &actions;
	dns_pipe_cfg.actions = actions_array;
	dns_pipe_cfg.attr.nb_actions = 1;

	dns_match.out_dst_ip.type = DOCA_FLOW_IP4_ADDR;
	dns_match.out_l4_type = IPPROTO_UDP;
	dns_match.out_dst_port = rte_cpu_to_be_16(DNS_PORT);

	/* Configure queues for rss fw */
	for (queue_index = 0; queue_index < nb_queues; queue_index++)
		rss_queues[queue_index] = queue_index;

	dns_fw.type = DOCA_FLOW_FWD_RSS;
	dns_fw.rss_queues = rss_queues;
	dns_fw.rss_flags = DOCA_FLOW_RSS_UDP;
	dns_fw.num_of_queues = nb_queues;

	/* Configure miss fwd for non DNS packets */
	dns_miss_fw.type = DOCA_FLOW_FWD_PIPE;
	dns_miss_fw.next_pipe = hairpin_pipe;
	dns_pipe = doca_flow_pipe_create(&dns_pipe_cfg, &dns_fw, &dns_miss_fw, &err);
	if (dns_pipe == NULL) {
		DOCA_LOG_ERR("DNS pipe creation FAILED: %s", err.message);
		return NULL;
	}

	/* Add HW offload DNS rule */
	entry = doca_flow_pipe_add_entry(0, dns_pipe, &dns_match, &actions, NULL, NULL, DOCA_FLOW_NO_WAIT, NULL, &err);
	if (entry == NULL) {
		DOCA_LOG_ERR("entry creation FAILED: %s", err.message);
		return NULL;
	}

	processed = doca_flow_entries_process(port, 0, DEFAULT_TIMEOUT_US, num_of_entries);
	if (processed != num_of_entries || doca_flow_pipe_entry_get_status(entry) != DOCA_FLOW_ENTRY_STATUS_SUCCESS) {
		DOCA_LOG_ERR("entry creation FAILED");
		return NULL;
	}

	return dns_pipe;
}

/*
 * create DNS hairpin pipe per APP port
 *
 * @port [in]: pointer to DOCA flow port
 * @port_id [in]: port ID
 * @return: pipe handler on success and NULL otherwise
 */
static struct doca_flow_pipe *
hairpin_non_dns_packets(struct doca_flow_port *port, uint16_t port_id)
{
	struct doca_flow_match non_dns_match;
	struct doca_flow_fwd non_dns_fw;
	struct doca_flow_actions actions;
	struct doca_flow_actions *actions_array[1];
	struct doca_flow_pipe_cfg non_dns_pipe_cfg = {0};
	struct doca_flow_pipe *non_dns_pipe;
	struct doca_flow_error err = {0};
	struct doca_flow_pipe_entry *entry;
	int processed, num_of_entries = 1;

	/* Zeroed fields are ignored , no changeable fields */
	memset(&non_dns_match, 0, sizeof(non_dns_match));
	memset(&actions, 0, sizeof(actions));
	memset(&non_dns_fw, 0, sizeof(non_dns_fw));
	memset(&non_dns_pipe_cfg, 0, sizeof(non_dns_pipe_cfg));
	non_dns_pipe_cfg.attr.name = "HAIRPIN_NON_DNS_PIPE";
	non_dns_pipe_cfg.attr.type = DOCA_FLOW_PIPE_BASIC;
	non_dns_pipe_cfg.match = &non_dns_match;

	/* Configure the port id "owner" of pipe */
	non_dns_pipe_cfg.port = port;
	actions_array[0] = &actions;
	non_dns_pipe_cfg.actions = actions_array;
	non_dns_pipe_cfg.attr.nb_actions = 1;
	non_dns_fw.type = DOCA_FLOW_FWD_PORT;
	non_dns_fw.port_id = port_id ^ 1;

	non_dns_pipe = doca_flow_pipe_create(&non_dns_pipe_cfg, &non_dns_fw, NULL, &err);
	if (non_dns_pipe == NULL) {
		DOCA_LOG_ERR("failed to create non-DNS pipe: %s", err.message);
		return NULL;
	}
	entry = doca_flow_pipe_add_entry(0, non_dns_pipe, &non_dns_match, &actions, NULL, NULL, DOCA_FLOW_NO_WAIT, NULL, &err);
	if (entry == NULL) {
		DOCA_LOG_ERR("entry creation FAILED: %s", err.message);
		return NULL;
	}

	processed = doca_flow_entries_process(port, 0, DEFAULT_TIMEOUT_US, num_of_entries);
	if (processed != num_of_entries || doca_flow_pipe_entry_get_status(entry) != DOCA_FLOW_ENTRY_STATUS_SUCCESS) {
		DOCA_LOG_ERR("entry creation FAILED");
		return NULL;
	}

	return non_dns_pipe;
}

/*
 * Create DOCA flow ports
 *
 * @portid [in]: port ID
 * @return: port handler on success and NULL otherwise
 */
static struct doca_flow_port *
dns_filter_port_create(uint8_t portid)
{
	char port_id_str[MAX_PORT_STR_LEN];
	struct doca_flow_error err = {0};
	struct doca_flow_port *port;
	struct doca_flow_port_cfg port_cfg = {0};

	port_cfg.port_id = portid;
	port_cfg.type = DOCA_FLOW_PORT_DPDK_BY_ID;
	snprintf(port_id_str, MAX_PORT_STR_LEN, "%d", port_cfg.port_id);
	port_cfg.devargs = port_id_str;
	port = doca_flow_port_start(&port_cfg, &err);
	if (port == NULL) {
		DOCA_LOG_ERR("failed to initialize DOCA flow port: %s", err.message);
		return NULL;
	}
	return port;
}

/*
 * Destroy DOCA flow ports
 *
 * @nb_ports [in]: number of APP ports
 */
static void
dns_filter_destroy_ports(int nb_ports)
{
	int portid;

	for (portid = 0; portid < nb_ports; portid++) {
		if (ports[portid])
			doca_flow_port_destroy(ports[portid]);
	}
}

/*
 * Initialize DOCA flow ports
 *
 * @nb_ports [in]: number of APP ports
 * @return: 0 on success and negative value otherwise
 */
static int
dns_filter_init_ports(int nb_ports)
{
	int portid, result;

	for (portid = 0; portid < nb_ports; portid++) {
		/* Create DOCA flow port */
		ports[portid] = dns_filter_port_create(portid);
		if (ports[portid] == NULL) {
			dns_filter_destroy_ports(portid);
			return -1;
		}
		/* Pair ports should same as DPDK hairpin binding order */
		if (!portid || !(portid % 2))
			continue;
		result = doca_flow_port_pair(ports[portid], ports[portid ^ 1]);
		if (result < 0) {
			DOCA_LOG_ERR("pair port %u %u fail", portid, portid ^ 1);
			dns_filter_destroy_ports(portid + 1);
			return result;
		}
	}
	return 0;
}

/*
 * ARGP Callback - Handle DNS listing type parameter
 *
 * @param [in]: Input parameter
 * @config [in/out]: Program configuration context
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
type_callback(void *param, void *config)
{
	struct dns_filter_config *dns_cfg = (struct dns_filter_config *)config;
	const char *type = (char *)param;

	if (strcmp(type, "allow") == 0)
		dns_cfg->listing_type = DNS_ALLOW_LISTING;
	else if (strcmp(type, "deny") == 0)
		dns_cfg->listing_type = DNS_DENY_LISTING;
	else {
		DOCA_LOG_ERR("Illegal listing type = [%s]", type);
		return DOCA_ERROR_INVALID_VALUE;
	}

	return DOCA_SUCCESS;
}

/*
 * ARGP Callback - Handle RegEx rules parameter
 *
 * @param [in]: Input parameter
 * @config [in/out]: Program configuration context
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
rules_callback(void *param, void *config)
{
	struct dns_filter_config *dns_cfg = (struct dns_filter_config *)config;
	const char *rules_path = (char *)param;

	if (strnlen(rules_path, MAX_FILE_NAME) == MAX_FILE_NAME) {
		DOCA_LOG_ERR("Denylist rules file name too long max %d", MAX_FILE_NAME - 1);
		return DOCA_ERROR_INVALID_VALUE;
	}
	strlcpy(dns_cfg->rules_file_path, rules_path, MAX_FILE_NAME);
	return DOCA_SUCCESS;
}


/*
 * ARGP Callback - Handle RegEx PCI address parameter
 *
 * @param [in]: Input parameter
 * @config [in/out]: Program configuration context
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
pci_address_callback(void *param, void *config)
{
	struct dns_filter_config *dns_cfg = (struct dns_filter_config *)config;
	const char *pci_address = (char *)param;

	if (parse_pci_addr(pci_address, &dns_cfg->pci_address) != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Invalid PCI address: \"%s\"", pci_address);
		return DOCA_ERROR_INVALID_VALUE;
	}
	return DOCA_SUCCESS;
}

/*
 * Register the command line parameters for the application
 *
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
doca_error_t
register_dns_filter_params(void)
{
	doca_error_t result;
	struct doca_argp_param *type_param, *rules_param, *pci_address_param;

	/* Create and register listing type param */
	result = doca_argp_param_create(&type_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create ARGP param: %s", doca_get_error_string(result));
		return result;
	}
	doca_argp_param_set_short_name(type_param, "t");
	doca_argp_param_set_long_name(type_param, "type");
	doca_argp_param_set_description(type_param, "Set DNS listing type {allow, deny}");
	doca_argp_param_set_callback(type_param, type_callback);
	doca_argp_param_set_type(type_param, DOCA_ARGP_TYPE_STRING);
	doca_argp_param_set_mandatory(type_param);
	result = doca_argp_register_param(type_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to register program param: %s", doca_get_error_string(result));
		return result;
	}

	/* Create and register rules param */
	result = doca_argp_param_create(&rules_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create ARGP param: %s", doca_get_error_string(result));
		return result;
	}
	doca_argp_param_set_short_name(rules_param, "r");
	doca_argp_param_set_long_name(rules_param, "rules");
	doca_argp_param_set_arguments(rules_param, "<path>");
	doca_argp_param_set_description(rules_param, "Path to rules file (rof2.binary)");
	doca_argp_param_set_callback(rules_param, rules_callback);
	doca_argp_param_set_type(rules_param, DOCA_ARGP_TYPE_STRING);
	doca_argp_param_set_mandatory(rules_param);
	result = doca_argp_register_param(rules_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to register program param: %s", doca_get_error_string(result));
		return result;
	}

	/* Create and register RegEx pci address param */
	result = doca_argp_param_create(&pci_address_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create ARGP param: %s", doca_get_error_string(result));
		return result;
	}
	doca_argp_param_set_short_name(pci_address_param, "p");
	doca_argp_param_set_long_name(pci_address_param, "pci-addr");
	doca_argp_param_set_arguments(pci_address_param, "<address>");
	doca_argp_param_set_description(pci_address_param, "Set PCI address of the RXP engine to use");
	doca_argp_param_set_callback(pci_address_param, pci_address_callback);
	doca_argp_param_set_type(pci_address_param, DOCA_ARGP_TYPE_STRING);
	doca_argp_param_set_mandatory(pci_address_param);
	result = doca_argp_register_param(pci_address_param);
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
dns_worker_lcores_run(struct dns_filter_config *app_cfg)
{

	uint16_t lcore_index = 0;
	int current_lcore = 0, nb_queues = app_cfg->dpdk_cfg->port_config.nb_queues;
	struct dns_worker_ctx *worker_ctx = NULL;
	doca_error_t result;

	DOCA_LOG_INFO("%d cores are used as workers", nb_queues);

	/* Init DNS workers to start processing packets */
	while ((current_lcore < RTE_MAX_LCORE) && (lcore_index < nb_queues)) {
		current_lcore = rte_get_next_lcore(current_lcore, true, false);

		/* Create worker context */
		worker_ctx = (struct dns_worker_ctx *)rte_zmalloc(NULL, sizeof(struct dns_worker_ctx), 0);
		if (worker_ctx == NULL) {
			DOCA_LOG_ERR("RTE malloc failed");
			force_quit = true;
			return DOCA_ERROR_NO_MEMORY;
		}
		worker_ctx->app_cfg = app_cfg;
		worker_ctx->queue_id = lcore_index;

		/* initialise doca_buf_inventory */
		result = doca_buf_inventory_create(NULL, MAX_REGEX_RESPONSE_SIZE, DOCA_BUF_EXTENSION_NONE, &worker_ctx->buf_inventory);
		if (result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Unable to allocate buffer inventory: %s", doca_get_error_string(result));
			rte_free(worker_ctx);
			force_quit = true;
			return result;
		}
		result = doca_buf_inventory_start(worker_ctx->buf_inventory);
		if (result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Unable to start buffer inventory: %s", doca_get_error_string(result));
			doca_buf_inventory_destroy(worker_ctx->buf_inventory);
			rte_free(worker_ctx);
			force_quit = true;
			return result;
		}

		/* initialise doca_buf_inventory */
		result = doca_workq_create(PACKET_BURST, &worker_ctx->workq);
		if (result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Unable to create work queue: %s", doca_get_error_string(result));
			goto destroy_buf_inventory;
		}
		result = doca_ctx_workq_add(doca_regex_as_ctx(app_cfg->doca_reg), worker_ctx->workq);
		if (result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Unable to attach workq to regex: %s", doca_get_error_string(result));
			goto destroy_workq;
		}

		/* Create array of pointers (char*) to hold the queries */
		worker_ctx->queries = rte_zmalloc(NULL, PACKET_BURST * sizeof(char *), 0);
		if (worker_ctx->queries == NULL) {
			DOCA_LOG_ERR("Dynamic allocation failed");
			result = DOCA_ERROR_NO_MEMORY;
			goto worker_cleanup;
		}
#ifdef GPU_SUPPORT
		/* Register external memory to GPU device, allow the access it */
		int ret = rte_gpu_mem_register(app_cfg->dpdk_cfg->pipe.gpu_id, PACKET_BURST, worker_ctx->queries);

		if (ret < 0) {
			DOCA_LOG_ERR("GPU MEM registration failed with error [%d]", ret);
			result = DOCA_ERROR_DRIVER;
			goto queries_cleanup;
		}
#endif

		/* Launch the worker to start process packets */
		if (rte_eal_remote_launch((void *)dns_filter_worker, (void *)worker_ctx, current_lcore) != 0) {
			DOCA_LOG_ERR("Remote launch failed");
			result = DOCA_ERROR_DRIVER;
			goto queries_cleanup;
		}

		worker_ctx++;
		lcore_index++;
	}
	return DOCA_SUCCESS;

queries_cleanup:
	rte_free(worker_ctx->queries);
worker_cleanup:
	doca_ctx_workq_rm(doca_regex_as_ctx(app_cfg->doca_reg), worker_ctx->workq);
destroy_workq:
	doca_workq_destroy(worker_ctx->workq);
destroy_buf_inventory:
	doca_buf_inventory_stop(worker_ctx->buf_inventory);
	doca_buf_inventory_destroy(worker_ctx->buf_inventory);
	rte_free(worker_ctx);
	force_quit = true;
	return result;
}

doca_error_t
dns_filter_init(struct dns_filter_config *app_cfg)
{
	uint16_t portid, nb_ports;
	struct doca_flow_error err = {0};
	struct doca_flow_cfg dns_flow_cfg = {0};
	struct doca_flow_pipe *hairpin_pipe;
	struct doca_flow_pipe *dns_pipe;
	struct application_dpdk_config *dpdk_config = app_cfg->dpdk_cfg;
	doca_error_t result;

	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	/* Initialize DOCA framework */
	dns_flow_cfg.queues = dpdk_config->port_config.nb_queues;
	dns_flow_cfg.mode_args = "vnf,hws";
	nb_ports = dpdk_config->port_config.nb_ports;

	/* Create array to hold drop pipe per port */
	app_cfg->drop_pipes = malloc(sizeof(struct doca_flow_pipe *) * nb_ports);
	if (app_cfg->drop_pipes == NULL) {
		DOCA_LOG_ERR("Failed to allocate memory for DNS drop pipes");
		return DOCA_ERROR_NO_MEMORY;
	}

	if (doca_flow_init(&dns_flow_cfg, &err) < 0) {
		free(app_cfg->drop_pipes);
		DOCA_LOG_ERR("failed to init DOCA: %s", err.message);
		return DOCA_ERROR_INITIALIZATION;
	}

	if (dns_filter_init_ports(nb_ports) < 0) {
		free(app_cfg->drop_pipes);
		doca_flow_destroy();
		DOCA_LOG_ERR("failed to init ports");
		return DOCA_ERROR_INITIALIZATION;
	}

	for (portid = 0; portid < nb_ports; portid++) {
		/* Hairpin pipes for non-DNS packets */
		hairpin_pipe = hairpin_non_dns_packets(ports[portid], portid);
		if (hairpin_pipe == NULL) {
			result = DOCA_ERROR_INITIALIZATION;
			goto doca_flow_cleanup;
		}

		/* DNS flow pipe */
		dns_pipe = build_dns_pipe(app_cfg, ports[portid], hairpin_pipe);
		if (dns_pipe == NULL) {
			result = DOCA_ERROR_INITIALIZATION;
			goto doca_flow_cleanup;
		}
#if 0
		/* DNS drop pipe */
		app_cfg->drop_pipes[portid] = build_drop_pipe(ports[portid], dns_pipe);
		if (app_cfg->drop_pipes[portid] == NULL) {
			result = DOCA_ERROR_INITIALIZATION;
			goto doca_flow_cleanup;
		}
#endif
	}
	/* DOCA RegEx initialization */
	result = regex_init(app_cfg);
	if (result != DOCA_SUCCESS)
		goto doca_flow_cleanup;

	DOCA_LOG_DBG("Application configuration and rules offload done");
	return result;

doca_flow_cleanup:
	dns_filter_destroy_ports(app_cfg->dpdk_cfg->port_config.nb_ports);
	doca_flow_destroy();
	if (app_cfg->drop_pipes != NULL)
		free(app_cfg->drop_pipes);

	return result;
}

void
dns_filter_destroy(struct dns_filter_config *app_cfg)
{
	/* Cleanup DOCA RegEx resources */
	doca_ctx_stop(doca_regex_as_ctx(app_cfg->doca_reg));
	doca_regex_destroy(app_cfg->doca_reg);

	if (app_cfg->dev != NULL) {
		doca_dev_close(app_cfg->dev);
		app_cfg->dev = NULL;
	}

	app_cfg->doca_reg = NULL;
	dns_filter_destroy_ports(app_cfg->dpdk_cfg->port_config.nb_ports);
	doca_flow_destroy();
	if (app_cfg->drop_pipes != NULL)
		free(app_cfg->drop_pipes);
}
