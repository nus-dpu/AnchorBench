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

#include "dns-filter-port-cfg.h"
#include "dns-filter-constants.h"
#include "dns-filter-core.h"
#include "dns-filter.h"

#include "mempool.h"

DOCA_LOG_REGISTER(DNS_FILTER::Core);

#define ETH_HEADER_SIZE 14			/* ETH header size = 14 bytes (112 bits) */
#define IP_HEADER_SIZE 	20			/* IP header size = 20 bytes (160 bits) */
#define UDP_HEADER_SIZE 8			/* UDP header size = 8 bytes (64 bits) */
#define DNS_HEADER_SIZE 12			/* DNS header size = 12 bytes (72 bits) */

__thread struct mbuf_table tx_mbufs[RTE_MAX_ETHPORTS];

#define NSEC_PER_SEC    1000000000L

#define TIMESPEC_TO_NSEC(t)	((t.tv_sec * NSEC_PER_SEC) + (t.tv_nsec))

#define USEC_PER_SEC   	1000000L
#define TIMEVAL_TO_USEC(t)  ((t.tv_sec * USEC_PER_SEC) + t.tv_usec)

__thread int nr_latency = 0;
__thread uint64_t latency[MAX_NR_LATENCY];

static uint64_t diff_timespec(struct timespec * t1, struct timespec * t2) {
	struct timespec diff = {.tv_sec = t2->tv_sec - t1->tv_sec, .tv_nsec = t2->tv_nsec - t1->tv_nsec};
	if (diff.tv_nsec < 0) {
		diff.tv_nsec += NSEC_PER_SEC;
		diff.tv_sec--;
	}
	return TIMESPEC_TO_NSEC(diff);
}

int dpdk_tx_mbuf_init(void) {
	int pid = 1;
	for (int i = 0; i < PACKET_BURST; i++) {
		/* Allocate new buffer for sended packets */
		tx_mbufs[pid].m_table[i] = rte_pktmbuf_alloc(pkt_mempools[rte_lcore_id()]);
		if (unlikely(tx_mbufs[pid].m_table[i] == NULL)) {
			rte_exit(EXIT_FAILURE, "Failed to allocate %d:wmbuf[%d] on device %d!\n", rte_lcore_id(), i, pid);
		}
	}
}

uint32_t dpdk_send_pkts(int pid, int qid) {
    int total_pkt, pkt_cnt;
    total_pkt = pkt_cnt = tx_mbufs[pid].len;

    struct rte_mbuf ** pkts = tx_mbufs[pid].m_table;

    if (pkt_cnt > 0) {
        int ret;
        do {
            /* Send packets until there is none in TX queue */
            ret = rte_eth_tx_burst(pid, qid, pkts, pkt_cnt);
            pkts += ret;
            pkt_cnt -= ret;
        } while (pkt_cnt > 0);

        /* Allocate new packet memory buffer for TX queue (WHY NEED NEW BUFFER??) */
#if MALLOC_PACKET
        for (int i = 0; i < tx_mbufs[pid].len; i++) {
            /* Allocate new buffer for sended packets */
            tx_mbufs[pid].m_table[i] = rte_pktmbuf_alloc(pkt_mempools[rte_lcore_id()]);
            if (unlikely(tx_mbufs[pid].m_table[i] == NULL)) {
                rte_exit(EXIT_FAILURE, "Failed to allocate %d:wmbuf[%d] on device %d!\n", rte_lcore_id(), i, pid);
            }
        }
#endif

        tx_mbufs[pid].len = 0;
    }

    return total_pkt;
}

struct rte_mbuf * dpdk_get_txpkt(int port_id, int pkt_size) {
    if (unlikely(tx_mbufs[port_id].len == DEFAULT_PKT_BURST)) {
        return NULL;
    }

    int next_pkt = tx_mbufs[port_id].len;
    struct rte_mbuf * tx_pkt = tx_mbufs[port_id].m_table[next_pkt];

    tx_pkt->pkt_len = tx_pkt->data_len = pkt_size;
    tx_pkt->nb_segs = 1;
    tx_pkt->next = NULL;
    
    tx_mbufs[port_id].len++;

    return tx_pkt;
}

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
	if (ns_initparse(data, len - 2 * sizeof(uint64_t), &handle) < 0) {
		DOCA_LOG_ERR("Fail to parse domain DNS packet");
		return -1;
	}

	/* Get DNS query start from handle field */
	*query = (char *)handle._sections[ns_s_qd];

	return 0;
}

static void
stamp_dns_ts(struct rte_mbuf *pkt, uint64_t latency)
{
	int len, result;
	struct rte_mbuf mbuf = *pkt;
	struct rte_sft_error error;
	struct rte_sft_mbuf_info mbuf_info;
	uint32_t payload_offset = 0;
	const unsigned char *data;
	uint64_t * ptr;

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

	data += (len - sizeof(uint64_t));

	ptr = (uint64_t *)data;
	*ptr = latency;
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
#if 0
static int
regex_processing(struct dns_worker_ctx *worker_ctx, uint16_t packets_received, struct rte_mbuf **packets)
{
	size_t tx_count, rx_count;
	doca_error_t result;
	int ret = 0;
	uint64_t elapse[DEFAULT_PKT_BURST];

	/* Start DNS workload */
	ret = cpu_workload_run(packets, packets_received, worker_ctx->queries);
	if (ret < 0)
		return ret;

	/* Enqueue jobs to DOCA RegEx*/
	rx_count = tx_count = 0;

	while (tx_count < packets_received) {
		for (; tx_count != packets_received;) {
			struct doca_buf *buf = worker_ctx->buf[tx_count];
			void *mbuf_data;
			void *data_begin = (void *)worker_ctx->queries[tx_count];
			size_t data_len = strlen(data_begin);
			memcpy(worker_ctx->query_buf[tx_count], data_begin, data_len);

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
				elapse[tx_count] = rte_rdtsc();
				++tx_count;
			} else {
				DOCA_LOG_ERR("Failed to enqueue RegEx job (%s)", doca_get_error_string(result));
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
				elapse[rx_count] = rte_rdtsc() - elapse[rx_count];
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
#endif

/*
 * Enqueue job to DOCA RegEx qp
 *
 * @regex_cfg [in]: regex_scan_ctx configuration struct
 * @job_request [in]: RegEx job request, already initialized with first chunk.
 * @remaining_bytes [in]: the remaining bytes to send all jobs (chunks).
 * @return: number of the enqueued jobs or -1
 */
static int regex_scan_enq_job(struct dns_worker_ctx * ctx, bool flush, struct rte_mbuf * mbuf, char * pkt, int len, char * data, int data_len) {
	doca_error_t result;
	uint32_t nb_total = 0;
	uint32_t nb_free = 0;
	size_t tx_count = 0;

	struct mempool_elt * buf_element;
	char * data_buf;
	void *mbuf_data;

	if (is_mempool_empty(ctx->buf_mempool)) {
        rte_pktmbuf_free(mbuf);
		return 0;
	}

	/* Get one free element from the mempool */
	mempool_get(ctx->buf_mempool, &buf_element);
	/* Get the memory segment */
	data_buf = buf_element->addr;

#if MALLOC_PACKET
	buf_element->packet = (char *)malloc(len);
	memcpy(buf_element->packet, pkt, len);
	buf_element->packet_size = len;
#else
	buf_element->packet = mbuf;
	buf_element->packet_size = len;
#endif

	memcpy(data_buf, data, data_len);

	doca_buf_get_data(buf_element->buf, &mbuf_data);
	doca_buf_set_data(buf_element->buf, mbuf_data, data_len);

	clock_gettime(CLOCK_MONOTONIC, &buf_element->ts);

	struct doca_regex_job_search const job_request = {
			.base = {
				.type = DOCA_REGEX_JOB_SEARCH,
				.ctx = doca_regex_as_ctx(ctx->app_cfg->doca_reg),
				.user_data = { .ptr = buf_element },
			},
			.rule_group_ids = {1, 0, 0, 0},
			.buffer = buf_element->buf,
			.result = (struct doca_regex_search_result *)buf_element->response,
			.allow_batching = flush,
	};

	result = doca_workq_submit(ctx->workq, (struct doca_job *)&job_request);
	
	if (result == DOCA_ERROR_NO_MEMORY) {
		// doca_buf_refcount_rm(buf_element->buf, NULL);
		mempool_put(ctx->buf_mempool, buf_element);
		return 0; /* qp is full, try to dequeue. */
	}
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to enqueue job. Reason: %s", doca_get_error_string(result));
		return -1;
	}

	nb_enqueued++;

	return 0;
}

/*
 * Dequeue jobs responses
 *
 * @regex_cfg [in]: regex_scan_ctx configuration struct
 * @chunk_len [in]: job chunk size
 * @return: number of the dequeue jobs or a negative posix status code.
 */
int regex_scan_deq_job(int pid, struct dns_worker_ctx *ctx) {
	doca_error_t result;
	int finished = 0;
	struct doca_event event = {0};
	struct timespec ts;
	uint32_t nb_free = 0;
	uint32_t nb_total = 0;
	struct mempool_elt * buf_element;
	struct timespec now;
	char * query;

	clock_gettime(CLOCK_MONOTONIC, &now);

	do {
		result = doca_workq_progress_retrieve(ctx->workq, &event, DOCA_WORKQ_RETRIEVE_FLAGS_NONE);
		if (result == DOCA_SUCCESS) {
			buf_element = (struct mempool_elt *)event.user_data.ptr;
			nb_dequeued++;
			// if (nr_latency < MAX_NR_LATENCY) {
			// 	latency[nr_latency++] = diff_timespec(&buf_element->ts, &now);
			// }
#if MALLOC_PACKET
			struct rte_mbuf * mbuf = (struct rte_mbuf *)dpdk_get_txpkt(pid, buf_element->packet_size);
    		if (mbuf != NULL) {
				char * data = rte_pktmbuf_mtod(mbuf, uint8_t *);
				memcpy(data, buf_element->packet, buf_element->packet_size);
				free(buf_element->packet);
			}
#else
			struct rte_mbuf * mbuf = (struct rte_mbuf *)buf_element->packet;
			if (likely(tx_mbufs[pid].len < DEFAULT_PKT_BURST)) {
				stamp_dns_ts(mbuf, diff_timespec(&buf_element->ts, &now));
				int next_pkt = tx_mbufs[pid].len;
				struct rte_mbuf * tx_pkt = tx_mbufs[pid].m_table[next_pkt] = mbuf;

				tx_pkt->pkt_len = tx_pkt->data_len = buf_element->packet_size;
				tx_pkt->nb_segs = 1;
				tx_pkt->next = NULL;

				tx_mbufs[pid].len++;
			} else {
				rte_pktmbuf_free(mbuf);
			}
#endif
			// extract_dns_query(buf_element->packet, &query);
			// fprintf(stderr, "Result: %s, ts: %lu\n", query, extract_dns_ts(buf_element->packet));

			/* Report the scan result of RegEx engine */
			// regex_scan_report_results(ctx, &event);
			/* release the buffer back into the pool so it can be re-used */
			// doca_buf_refcount_rm(buf_element->buf, NULL);
			/* Put the element back into the mempool */
			mempool_put(ctx->buf_mempool, buf_element);
			++finished;
			// if (nr_latency < MAX_NR_LATENCY) {
			// 	clock_gettime(CLOCK_MONOTONIC, &now);
			// 	latency[nr_latency++] = diff_timespec(&buf_element->ts, &now);
			// }

		} else if (result == DOCA_ERROR_AGAIN) {
			break;
		} else {
			DOCA_LOG_ERR("Failed to dequeue results. Reason: %s", doca_get_error_string(result));
			// return -1;
			break;
		}
	} while (result == DOCA_SUCCESS);

	return finished;
}

static int
dns_processing(int pid, struct dns_worker_ctx *worker_ctx, uint16_t packets_received, struct rte_mbuf **packets)
{
	for (int i = 0; i < packets_received; i++) {
		struct rte_mbuf * mbuf = packets[i];
		char * pkt = rte_pktmbuf_mtod(mbuf, char *);
		int len = rte_pktmbuf_data_len(mbuf);

		struct udphdr * u;
		char * query;

		u = (struct udphdr *)(pkt + ETH_HEADER_SIZE + IP_HEADER_SIZE);
		if (ntohs(u->dest) != DNS_PORT) {
			continue;
		} else {
			if (!start_flag) {
				start_flag = 1;
				gettimeofday(&start, NULL);
			}
		}
	
		extract_dns_query(mbuf, &query);

		regex_scan_enq_job(worker_ctx, (i == (packets_received - 1))? false : true, mbuf, pkt, len, query, strlen(query));
	}
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
	// check_packets_marking(packets, &packets_received);
	// if (packets_received == 0) {
	// 	return packets_received;
	// }

	/* Start RegEx jobs */
	// ret = regex_processing(worker_ctx, packets_received, packets);
	ret = dns_processing(pid, worker_ctx, packets_received, packets);
	if (ret < 0) {
		return ret;
    }

	return packets_received;
}