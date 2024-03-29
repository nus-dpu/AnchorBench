#include <stdint.h>
#include <termios.h>
#include <stdio.h>
#include <execinfo.h>
#include <signal.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/time.h>

#include <doca_argp.h>
#include <doca_log.h>

#include "common.h"
#include "utils.h"
#include "dns-filter.h"
#include "dns-filter-core.h"
#include "dns-filter-l2p.h"
#include "dns-filter-constants.h"
#include "dns-filter-port-cfg.h"

DOCA_LOG_REGISTER(DNS_FILTER);

#define BURST_TX_RETRIES 	16

#define MSEC_PER_SEC    1000L
#define USEC_PER_MSEC   1000L
#define TIMEVAL_TO_MSEC(t)  ((t.tv_sec * MSEC_PER_SEC) + (t.tv_usec / USEC_PER_MSEC))

int delay_cycles = 0;

__thread struct timeval last_log;
__thread int start_flag = 0;
__thread struct timeval start;
__thread uint64_t nr_recv;
__thread uint64_t nr_send;
__thread int nb_enqueued = 0;
__thread int nb_dequeued = 0;

#define MAX_RULES		16
#define MAX_RULE_LEN	64

enum layer_name {
	L2,
	L3,
	L4,
	END
};

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

static void pkt_burst_forward(struct dns_worker_ctx *worker_ctx, int pid, int qid) {
	struct rte_mbuf * pkts_burst[DEFAULT_PKT_BURST];
	uint16_t nb_rx, nb_tx = 0, to_send = 0;
	uint32_t retry;

	/*
	 * Receive a burst of packets and forward them.
	 */
	nb_rx = rte_eth_rx_burst(pid, qid, pkts_burst, DEFAULT_PKT_BURST);
	if (unlikely(nb_rx == 0)) {
		return;
	}

	nr_recv += nb_rx;

	to_send = handle_packets_received(pid, worker_ctx, pkts_burst, nb_rx);
	if (to_send > 0) {
		nb_tx = rte_eth_tx_burst(pid ^ 1, qid, pkts_burst, to_send);
		if (unlikely(nb_tx < nb_rx)) {
			retry = 0;
			while (nb_tx < nb_rx && retry++ < BURST_TX_RETRIES) {
				nb_tx += rte_eth_tx_burst(pid ^ 1, qid, &pkts_burst[nb_tx], nb_rx - nb_tx);
			}
		}
		nr_send += nb_tx;
	}

	if (unlikely(nb_tx < nb_rx)) {
		do {
			rte_pktmbuf_free(pkts_burst[nb_tx]);
		} while (++nb_tx < nb_rx);
	}

	return;
}

static void pg_lcore_get_rxbuf(uint8_t lid, port_info_t ** infos, uint8_t rxcnt) {
    for (int idx = 0; idx < rxcnt; idx++) {
        uint16_t pid = infos[idx]->pid;
        uint8_t qid = get_rxque(&l2p, lid, pid);
        printf("Core %d getting QUEUE %d RX buffer from PORT %d\n", lid, qid, pid);
    }
}

static void port_map_info(uint8_t lid, port_info_t **infos, uint8_t *qids, uint8_t *txcnt, uint8_t *rxcnt, const char *msg) {
    uint8_t idx, pid, cnt = 0;
    uint8_t rx, tx;
    char buf[256];

    rx = get_lcore_rxcnt(&l2p, lid);
    tx = get_lcore_txcnt(&l2p, lid);

    if (txcnt && rxcnt) {
        *rxcnt = rx;
        *txcnt = tx;
        cnt    = tx;
    } else if (rxcnt) {
        *rxcnt = rx;
        cnt    = rx;
    } else if (txcnt) {
        *txcnt = tx;
        cnt    = tx;
    }

    snprintf(buf, sizeof(buf), "  %s processing lcore: %3d rx: %2d tx: %2d", msg, lid, rx, tx);

    for (idx = 0; idx < cnt; idx++) {
        if (rxcnt) {
            pid = get_rx_pid(&l2p, lid, idx);
        } else {
            pid = get_tx_pid(&l2p, lid, idx);
        }

        if ((infos[idx] = (port_info_t *)get_port_private(&l2p, pid)) == NULL)
            rte_panic("Config error: No port %d found on lcore %d\n", pid, lid);

        if (qids) {
			qids[idx] = get_rxque(&l2p, lid, pid);
			printf("lcore %d has RX queue %d on port %d\n", lid, qids[idx], pid);
        }
    }

    printf("%s\n", buf);
}

#define MAX_PATTERN_NUM		4
#define MAX_ACTION_NUM		2

int dns_filter_setup_flow(uint32_t pid, uint8_t qid, uint16_t src_port) {
	struct rte_flow_error error;
	struct rte_flow_attr attr;
	struct rte_flow_item pattern[MAX_PATTERN_NUM];
	struct rte_flow_action action[MAX_ACTION_NUM];
	struct rte_flow * flow = NULL;
	struct rte_flow_action_queue queue = { .index = qid };
	struct rte_flow_item_ipv4 ip_spec;
	struct rte_flow_item_ipv4 ip_mask;
	struct rte_flow_item_udp udp_spec;
	struct rte_flow_item_udp udp_mask;
	int res;

	memset(pattern, 0, sizeof(pattern));
	memset(action, 0, sizeof(action));

	/*
	* set the rule attribute.
	* in this case only ingress packets will be checked.
	*/
	memset(&attr, 0, sizeof(struct rte_flow_attr));
	attr.ingress = 1;

	/*
	* create the action sequence.
	* one action only,  move packet to queue
	*/
	action[0].type = RTE_FLOW_ACTION_TYPE_QUEUE;
	action[0].conf = &queue;
	action[1].type = RTE_FLOW_ACTION_TYPE_END;

	/*
	* set the first level of the pattern (ETH).
	*/
	pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;

	/*
	* setting the second level of the pattern (IP).
	*/
	memset(&ip_spec, 0, sizeof(struct rte_flow_item_ipv4));
	memset(&ip_mask, 0, sizeof(struct rte_flow_item_ipv4));
	pattern[1].type = RTE_FLOW_ITEM_TYPE_IPV4;
	pattern[1].spec = &ip_spec;
	pattern[1].mask = &ip_mask;

	/*
	* setting the third level of the pattern (UDP).
	*/
	memset(&udp_spec, 0, sizeof(struct rte_flow_item_udp));
	memset(&udp_mask, 0, sizeof(struct rte_flow_item_udp));
	udp_spec.hdr.src_port = htons(src_port);
	udp_mask.hdr.src_port = htons(0xff00);
	pattern[2].type = RTE_FLOW_ITEM_TYPE_UDP;
	pattern[2].spec = &udp_spec;
	pattern[2].mask = &udp_mask;

	/* the final level must be always type end */
	pattern[3].type = RTE_FLOW_ITEM_TYPE_END;

	res = rte_flow_validate(pid, &attr, pattern, action, &error);
	if (!res) {
		flow = rte_flow_create(pid, &attr, pattern, action, &error);
		if (!flow) {
			rte_flow_flush(pid, &error);
		}
	}
}

int dns_filter_worker(void *arg) {
	struct dns_worker_ctx *worker_ctx = (struct dns_worker_ctx *)arg;
    uint8_t lid = rte_lcore_id();
    port_info_t *infos[RTE_MAX_ETHPORTS];
    uint8_t qids[RTE_MAX_ETHPORTS];
    uint8_t idx, txcnt, rxcnt;
	struct timeval curr;
	float tot_recv_rate, tot_send_rate;
	float tot_enqueue_rate, tot_dequeue_rate;
	unsigned long tot_recv, tot_send;
	float sec_recv, sec_send;
	float max_recv, max_send;
	uint16_t src_port;

	tot_recv = tot_send = 0;
	max_recv = max_send = 0.0;

	memset(infos, '\0', sizeof(infos));
    memset(qids, '\0', sizeof(qids));

	port_map_info(lid, infos, qids, &txcnt, &rxcnt, "RX/TX");

    pg_lcore_get_rxbuf(lid, infos, rxcnt);
#if 0
	for (idx = 0; idx < rxcnt; idx++) {
		for (int i = 17; i < 29; i++) {
			if (i % 6 + 1 == lid) {
				src_port = (i << 8);
				printf("Direct flow with src port %x to core %d\n", src_port, qids[idx]);
				dns_filter_setup_flow(infos[idx]->pid, qids[idx], src_port);
			}
		}
	}
#endif
	gettimeofday(&start, NULL);
	gettimeofday(&last_log, NULL);

    while (true) {
		gettimeofday(&curr, NULL);
		if (curr.tv_sec - last_log.tv_sec >= 1) {
			sec_recv = (float)nr_recv / (TIMEVAL_TO_MSEC(curr) - TIMEVAL_TO_MSEC(last_log));
			sec_send = (float)nr_send / (TIMEVAL_TO_MSEC(curr) - TIMEVAL_TO_MSEC(last_log));
			printf("CORE %d ==> RX: %8.2f (KPS), TX: %8.2f (KPS) / Max RX: %8.2f (KPS), Max TX: %8.2f (KPS)\n", 
					lid, sec_recv, sec_send, max_recv, max_send);
			if (sec_recv > max_recv) {
				max_recv = sec_recv;
			}
			if (sec_send > max_send) {
				max_send = sec_send;
			}
			tot_recv += nr_recv;
			tot_send += nr_send;
			nr_recv = nr_send = 0;
			last_log = curr;
		}
		if (start_flag & (curr.tv_sec - start.tv_sec > 20)) {
			break;
		}
		for (idx = 0; idx < rxcnt; idx++) {
            pkt_burst_forward(worker_ctx, infos[idx]->pid, qids[idx]);
        }
	}

	tot_recv_rate = (float)tot_recv / (TIMEVAL_TO_MSEC(curr) - TIMEVAL_TO_MSEC(start));
	tot_send_rate = (float)tot_send / (TIMEVAL_TO_MSEC(curr) - TIMEVAL_TO_MSEC(start));

	// printf("CORE %d ==> RX: %8.2f (KPS), TX: %8.2f (KPS)\n", lid, tot_recv_rate , tot_send_rate);

	FILE * output_fp;
	char name[32];

	sprintf(name, "network-thp-%d.txt", sched_getcpu());
	output_fp = fopen(name, "w");
	if (!output_fp) {
		printf("Error opening throughput output file!\n");
		return;
	}

	fprintf(output_fp, "%6.2lf\t%6.2lf\n", tot_recv_rate, tot_send_rate);

	fclose(output_fp);

	sprintf(name, "thp-%d.txt", sched_getcpu());
	output_fp = fopen(name, "w");
	if (!output_fp) {
		printf("Error opening throughput output file!\n");
		return;
	}

	tot_enqueue_rate = (float)nb_enqueued / (TIMEVAL_TO_MSEC(curr) - TIMEVAL_TO_MSEC(start));
	tot_dequeue_rate = (float)nb_dequeued / (TIMEVAL_TO_MSEC(curr) - TIMEVAL_TO_MSEC(start));

	fprintf(output_fp, "%6.2lf\t%6.2lf\n", tot_enqueue_rate, tot_dequeue_rate);

	fclose(output_fp);

	int lat_start = (int)(0.15 * nr_latency);

	sprintf(name, "latency-%d.txt", sched_getcpu());
	output_fp = fopen(name, "w");
	if (!output_fp) {
		printf("Error opening latency output file!\n");
		return NULL;
	}

	for (int i = lat_start; i < nr_latency; i++) {
		fprintf(output_fp, "%lu\n", latency[i]);
	}

	fclose(output_fp);

	return 0;
}

static int dns_filter_parse_args(int argc, char ** argv) {
	int opt, option_index;
	int offset;
	static struct option lgopts[] = {
		{"crc-strip", 0, 0, 0},
		{NULL, 0, 0, 0}
	};

	while ((opt = getopt_long(argc, argv, "m:r:d:h", lgopts, &option_index)) != EOF)
		switch (opt) {
		case 'm':	/* Matrix for port mapping. */
			if (pg_parse_matrix(&l2p, optarg) == -1) {
				printf("invalid matrix string (%s)\n", optarg);
				// pktgen_usage(prgname);
				return -1;
			}
			break;

		case 'd':	/* Delay cycles */
			delay_cycles = strtol(optarg, NULL, 10);
			break;

		case 'h':	/* print out the help message */
			// pktgen_usage(prgname);
			return -1;

		case 0:	/* crc-strip for all ports */
			break;
		default:
			return -1;
		}

	for (int i = 0; i < argc; i++) {
		if (strcmp(argv[i], "--") == 0) {
			offset = i;
			break;
		}
	}

    return offset;
}

doca_error_t
dns_worker_lcores_run(struct dns_filter_config *app_cfg)
{
	uint16_t lcore_index = 0;
	struct dns_worker_ctx *worker_ctx = NULL;
	doca_error_t result;
	int lcore_id;

	/* Init DNS workers to start processing packets */
	RTE_LCORE_FOREACH_WORKER(lcore_id) {
		/* Create worker context */
		worker_ctx = (struct dns_worker_ctx *)rte_zmalloc(NULL, sizeof(struct dns_worker_ctx), 0);
		if (worker_ctx == NULL) {
			DOCA_LOG_ERR("RTE malloc failed");
			return DOCA_ERROR_NO_MEMORY;
		}
		worker_ctx->app_cfg = app_cfg;
		worker_ctx->queue_id = lcore_index;

		/* initialise doca_buf_inventory */
		result = doca_buf_inventory_create(NULL, MAX_REGEX_RESPONSE_SIZE, DOCA_BUF_EXTENSION_NONE, &worker_ctx->buf_inventory);
		if (result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Unable to allocate buffer inventory: %s", doca_get_error_string(result));
			rte_free(worker_ctx);
			return result;
		}
		result = doca_buf_inventory_start(worker_ctx->buf_inventory);
		if (result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Unable to start buffer inventory: %s", doca_get_error_string(result));
			doca_buf_inventory_destroy(worker_ctx->buf_inventory);
			rte_free(worker_ctx);
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

		for (int i = 0; i < PACKET_BURST; i++) {
			/* Create array of pointers (char*) to hold the queries */
			worker_ctx->query_buf[i] = rte_zmalloc(NULL, 256, 0);
			if (worker_ctx->query_buf[i] == NULL) {
				DOCA_LOG_ERR("Dynamic allocation failed");
				result = DOCA_ERROR_NO_MEMORY;
				goto worker_cleanup;
			}

			/* register packet in mmap */
			result = doca_mmap_populate(worker_ctx->mmap, worker_ctx->query_buf[i], 256, sysconf(_SC_PAGESIZE), NULL, NULL);
			if (result != DOCA_SUCCESS) {
				DOCA_LOG_ERR("Unable to populate memory map (input): %s", doca_get_error_string(result));
				goto queries_cleanup;
			}

			/* build doca_buf */
			result = doca_buf_inventory_buf_by_addr(worker_ctx->buf_inventory, worker_ctx->mmap, worker_ctx->query_buf[i], 256, &worker_ctx->buf[i]);
			if (result != DOCA_SUCCESS) {
				DOCA_LOG_ERR("Unable to acquire DOCA buffer for job data: %s", doca_get_error_string(result));
				goto queries_cleanup;
			}
		}

		/* Launch the worker to start process packets */
		if (rte_eal_remote_launch((void *)dns_filter_worker, (void *)worker_ctx, lcore_id) != 0) {
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
	return result;
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
	struct doca_argp_param *rules_param, *pci_address_param;

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

int dpdk_setup_rss(int nr_queues) {
	struct rte_flow *flow;
	struct rte_flow_error error;
	struct rte_flow_attr attr = { /* Holds the flow attributes. */
				.group = 0, /* set the rule on the main group. */
				.ingress = 1,/* Rx flow. */
				.priority = 0, }; /* add priority to rule
				to give the Decap rule higher priority since
				it is more specific than RSS */
	/* create flow on first port and first hairpin queue. */
	uint16_t port_id = rte_eth_find_next_owned_by(0, RTE_ETH_DEV_NO_OWNER);
	RTE_ASSERT(port_id != RTE_MAX_ETHPORTS);
	struct rte_eth_dev_info dev_info;
	int ret = rte_eth_dev_info_get(port_id, &dev_info);
	if (ret) {
		rte_exit(EXIT_FAILURE, "Cannot get device info");
	}

	static struct rte_flow_item pattern[] = {
		[L2] = { /* ETH type is set since we always start from ETH. */
			.type = RTE_FLOW_ITEM_TYPE_ETH,
			.spec = NULL,
			.mask = NULL,
			.last = NULL },
		[L3] = { /* ETH type is set since we always start from ETH. */
			.type = RTE_FLOW_ITEM_TYPE_ETH,
			.spec = NULL,
			.mask = NULL,
			.last = NULL },
		[L4] = { /* ETH type is set since we always start from ETH. */
			.type = RTE_FLOW_ITEM_TYPE_ETH,
			.spec = NULL,
			.mask = NULL,
			.last = NULL },
		[END] = {
			.type = RTE_FLOW_ITEM_TYPE_END,
			.spec = NULL,
			.mask = NULL,
			.last = NULL },
	};

	uint16_t queues[16];
	for (int i = 0; i < nr_queues; i++) {
		queues[i] = i;
	}

	struct rte_flow_action_rss rss = {
			.level = 0, /* RSS should be done on inner header. */
			.queue = queues, /* Set the selected target queues. */
			.queue_num = nr_queues, /* The number of queues. */
			.types = ETH_RSS_IP | ETH_RSS_UDP
	};

	struct rte_flow_action actions[] = {
		[0] = {
			.type = RTE_FLOW_ACTION_TYPE_RSS,
			.conf = &rss,
		},
		[1] = {
			.type = RTE_FLOW_ACTION_TYPE_END,
		},
	};

	struct rte_flow_item_udp udp_spec = {
		.hdr = {
		.dst_port = RTE_BE16(DNS_PORT)}
	};
	struct rte_flow_item_udp udp_mask = {
		.hdr = {
		.dst_port = RTE_BE16(0xFFFF)}
	};

	pattern[L2].type = RTE_FLOW_ITEM_TYPE_ETH;
	pattern[L2].spec = NULL;

	pattern[L2].type = RTE_FLOW_ITEM_TYPE_IPV4;
	pattern[L3].spec = NULL;
	pattern[L3].mask = NULL;

	pattern[L4].type = RTE_FLOW_ITEM_TYPE_UDP;
	pattern[L4].spec = &udp_spec;
	pattern[L4].mask = &udp_mask;

	pattern[END].type = RTE_FLOW_ITEM_TYPE_END;

	flow = rte_flow_create(port_id, &attr, pattern, actions, &error);
	if (!flow) {
		printf("Can't create hairpin flows on port: %u\n", port_id);
	}
}

int main(int argc, char **argv) {
	uint32_t i;
	int32_t ret;
	doca_error_t result;
	struct dns_filter_config app_cfg = {0};
	int lcore_id, nr_cores = 0;

	/* initialize EAL */
	ret = rte_eal_init(argc, argv);
	if (ret < 0) {
		return -1;
    }

	argc -= ret;
	argv += ret;

	ret = dns_filter_parse_args(argc, argv);
	if (ret < 0) {
		return -1;
    }

	argc -= ret;
	argv += ret;

	/* Init ARGP interface and start parsing cmdline/json arguments */
	result = doca_argp_init("dns_filter", &app_cfg);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to init ARGP resources: %s", doca_get_error_string(result));
		return EXIT_FAILURE;
	}

	printf(">>> Packet Burst %d, RX Desc %d, TX Desc %d, mbufs/port %d, mbuf cache %d\n",
			DEFAULT_PKT_BURST, DEFAULT_RX_DESC, DEFAULT_TX_DESC, MAX_MBUFS_PER_PORT, MBUF_CACHE_SIZE);

	/* Configure and initialize the ports */
	dns_filter_config_ports();

	result = register_dns_filter_params();
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to register application params: %s", doca_get_error_string(result));
		doca_argp_destroy();
		return EXIT_FAILURE;
	}

	result = doca_argp_start(argc, argv);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to parse application input: %s", doca_get_error_string(result));
		doca_argp_destroy();
		return EXIT_FAILURE;
	}

	/* DOCA RegEx initialization */
	result = regex_init(&app_cfg);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_INFO("Failed to init DOCA RegEx");
		return result;
	}

	/* Init DNS workers to start processing packets */
	RTE_LCORE_FOREACH_WORKER(lcore_id) {
		nr_cores++;
	}

	dpdk_setup_rss(nr_cores);

	result = dns_worker_lcores_run(&app_cfg);

	rte_delay_ms(250);	/* Wait for the lcores to start up. */

	/* Wait for all of the cores to stop running and exit. */
	rte_eal_mp_wait_lcore();

	RTE_ETH_FOREACH_DEV(i) {
		rte_eth_dev_stop(i);
		rte_delay_ms(100);
	}

	return 0;
}
