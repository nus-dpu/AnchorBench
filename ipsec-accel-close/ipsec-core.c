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
#include <doca_sha.h>

#include "ipsec-core.h"

DOCA_LOG_REGISTER(IPSEC::Core);

__thread int nr_latency = 0;
__thread uint64_t latency[MAX_NR_LATENCY];

#define ETH_HEADER_SIZE 14			/* ETH header size = 14 bytes (112 bits) */
#define IP_HEADER_SIZE 	20			/* IP header size = 20 bytes (160 bits) */
#define UDP_HEADER_SIZE 8			/* UDP header size = 8 bytes (64 bits) */
#define DNS_HEADER_SIZE 12			/* DNS header size = 12 bytes (72 bits) */

#define USEC_PER_SEC   	1000000L
#define TIMEVAL_TO_USEC(t)  ((t.tv_sec * USEC_PER_SEC) + t.tv_usec)

/*
 * Helper function to extract payload of a packet
 *
 * @pkt [in]: packet to extract
 * @query [out]: a place where to store the pointer of payload data
 * @return: 0 on success and negative value otherwise
 */
static int
extract_payload(struct rte_mbuf *pkt, char **query, int *len)
{
	int data_len, result;
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
	data_len = rte_pktmbuf_data_len(&mbuf);

	*query = data;
	*len = data_len;

	return 0;
}

#define NSEC_PER_SEC    1000000000L

#define TIMESPEC_TO_NSEC(t)	((t.tv_sec * NSEC_PER_SEC) + (t.tv_nsec))

static uint64_t diff_timespec(struct timespec * t1, struct timespec * t2) {
	struct timespec diff = {.tv_sec = t2->tv_sec - t1->tv_sec, .tv_nsec = t2->tv_nsec - t1->tv_nsec};
	if (diff.tv_nsec < 0) {
		diff.tv_nsec += NSEC_PER_SEC;
		diff.tv_sec--;
	}
	return TIMESPEC_TO_NSEC(diff);
}

static int
extract_sha_payload(struct rte_mbuf *pkt, char **sha_data, int *sha_data_len)
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

	/* Get DNS query start from handle field */
	*sha_data = (char *)(data + sizeof(uint64_t));
	sha_data_len = len - sizeof(uint64_t));

	return 0;
}

static void
check_packets_marking(struct ipsec_ctx *worker_ctx, struct rte_mbuf **packets, uint16_t *packets_received)
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

		if (ntohs(u->dest) == 1234) {
			if (!start_flag) {
				start_flag = 1;
				gettimeofday(&start, NULL);
			}

			extract_sha_payload(packets[current_packet], &worker_ctx->query_buf[index], &worker_ctx->query_len[index]);

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

static void
update_packet_payload(struct rte_mbuf * packet, char * result) {
	char * p;
	p = rte_pktmbuf_mtod(packet, char *);
	p += (ETH_HEADER_SIZE + IP_HEADER_SIZE + UDP_HEADER_SIZE + sizeof(uint64_t));
	packet->pkt_len = packet->data_len = ETH_HEADER_SIZE + IP_HEADER_SIZE + UDP_HEADER_SIZE + sizeof(uint64_t) + DOCA_SHA256_BYTE_COUNT;
	memcpy(p, result, DOCA_SHA256_BYTE_COUNT);
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
sha_processing(struct ipsec_ctx *worker_ctx, uint16_t packets_received, struct rte_mbuf **packets)
{
	size_t tx_count, rx_count;
	doca_error_t result;
	int ret = 0;

	/* Enqueue jobs to DOCA RegEx*/
	rx_count = tx_count = 0;

	while (tx_count < packets_received) {
		struct timespec enq_start, enq_end, deq_end;
		clock_gettime(CLOCK_MONOTONIC, &enq_start);
		for (; tx_count != packets_received;) {
			struct doca_buf *src_buf = worker_ctx->src_buf[tx_count];
			struct doca_buf *dst_buf = worker_ctx->dst_buf[tx_count];
			void *mbuf_data;
			void *data_begin = (void *)worker_ctx->query_buf[tx_count];
			size_t data_len = worker_ctx->query_len[tx_count];

			doca_buf_get_data(src_buf, &mbuf_data);
			doca_buf_set_data(src_buf, mbuf_data, data_len);

			clock_gettime(CLOCK_MONOTONIC, &worker_ctx->ts[tx_count]);

			struct doca_sha_job const sha_job = {
				.base = (struct doca_job) {
					.type = DOCA_SHA_JOB_SHA256,
					.flags = DOCA_JOB_FLAGS_NONE,
					.ctx = doca_sha_as_ctx(worker_ctx->app_cfg->doca_sha),
					.user_data = {.u64 = tx_count },
				},
				.resp_buf = dst_buf,
				.req_buf = src_buf,
				.flags = DOCA_SHA_JOB_FLAGS_SHA_PARTIAL_FINAL,
			};

			result = doca_workq_submit(worker_ctx->workq, (struct doca_job *)&sha_job);
			if (result == DOCA_ERROR_NO_MEMORY) {
				break;
			}

			if (result == DOCA_SUCCESS) {
				++tx_count;
			} else {
				DOCA_LOG_ERR("Failed to enqueue RegEx job (%s)", doca_get_error_string(result));
				ret = -1;
				goto doca_buf_cleanup;
			}
		}

		for (; rx_count != tx_count;) {
			/* dequeue one */
			struct doca_event event = {0};
			struct timespec now;
			int index;
			uint8_t * resp;
			struct doca_buf *dst_buf;
			
			result = doca_workq_progress_retrieve(worker_ctx->workq, &event, DOCA_WORKQ_RETRIEVE_FLAGS_NONE);
			if (result == DOCA_SUCCESS) {
				/* Handle the completed jobs */
				index = event.user_data.u64;
				clock_gettime(CLOCK_MONOTONIC, &now);
				if (nr_latency < MAX_NR_LATENCY) {
					latency[nr_latency++] = diff_timespec(&worker_ctx->ts[index], &now);
				}
				dst_buf = worker_ctx->dst_buf[index];
				doca_buf_get_data(dst_buf, (void **)&resp);
				update_packet_payload(packets[index], resp);
				++rx_count;
			} else if (result == DOCA_ERROR_AGAIN) {
				/* Wait for the job to complete */
				// printf("Wait for job to complete\n");
				// ts.tv_sec = 0;
				// ts.tv_nsec = 20;
				// nanosleep(&ts, &ts);
			} else {
				DOCA_LOG_ERR("Failed to dequeue RegEx job response");
				ret = -1;
				goto doca_buf_cleanup;
			}
		}
	}
	
doca_buf_cleanup:
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
handle_packets_received(int pid, struct ipsec_ctx *worker_ctx, struct rte_mbuf **packets, uint16_t packets_received)
{
	int ret;

	check_packets_marking(worker_ctx, packets, &packets_received);
	if (packets_received == 0) {
		return packets_received;
	}

	/* Start SHA jobs */
	ret = sha_processing(worker_ctx, packets_received, packets);
	if (ret < 0) {
		return ret;
    }

	return packets_received;
}