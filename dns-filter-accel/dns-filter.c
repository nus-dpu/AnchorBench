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

#include "mempool.h"

DOCA_LOG_REGISTER(DNS_FILTER);

#define BURST_TX_RETRIES 	16

#define MSEC_PER_SEC    1000L
#define USEC_PER_MSEC   1000L
#define USEC_PER_SEC   	1000000L
#define TIMEVAL_TO_USEC(t)  ((t.tv_sec * USEC_PER_SEC) + t.tv_usec)
#define TIMEVAL_TO_MSEC(t)  ((t.tv_sec * MSEC_PER_SEC) + (t.tv_usec / USEC_PER_MSEC))

int delay_cycles = 0;

__thread struct timeval last_log;
__thread int start_flag = 0;
__thread struct timeval start;
__thread uint64_t nr_recv;
__thread uint64_t nr_send;

struct dns_filter_config app_cfg;

#define MAX_RULES		16
#define MAX_RULE_LEN	64

#define MEMPOOL_CACHE_SIZE  256
#define N_MBUF              8192
#define BUF_SIZE            2048
#define MBUF_SIZE           (BUF_SIZE + sizeof(struct rte_mbuf) + RTE_PKTMBUF_HEADROOM)

// __thread struct mbuf_table tx_mbufs[RTE_MAX_ETHPORTS];

struct rte_mempool * pkt_mempools[NR_CPUS];

/*
 * RegEx context initialization
 *
 * @app_cfg [in/out]: application configuration structure
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
dns_filter_init(struct dns_filter_config *app_cfg)
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

static int pkt_burst_forward(struct dns_worker_ctx *worker_ctx, int pid, int qid) {
	struct rte_mbuf * pkts_burst[DEFAULT_PKT_BURST];
	uint16_t nb_rx, nb_tx = 0, to_send = 0;
	uint32_t retry;

	/*
	 * Receive a burst of packets and forward them.
	 */
	nb_rx = rte_eth_rx_burst(pid, qid, pkts_burst, DEFAULT_PKT_BURST);
	if (unlikely(nb_rx == 0)) {
		return nb_rx;
	}

	nr_recv += nb_rx;

	handle_packets_received(pid, worker_ctx, pkts_burst, nb_rx);

	// for (int nb_tx = 0; nb_tx != nb_rx;) {
	// 	nb_tx += regex_scan_deq_job(pid ^ 1, worker_ctx);
	// }

	// for (int i = 0; i < nb_rx; i++) {
    //     rte_pktmbuf_free(pkts_burst[i]);
    //     RTE_MBUF_PREFETCH_TO_FREE(pkts_burst[i + 1]);
    // }

	// if (to_send > 0) {
		// nb_tx = rte_eth_tx_burst(pid ^ 1, qid, pkts_burst, nb_rx);
		// if (unlikely(nb_tx < nb_rx)) {
		// 	retry = 0;
		// 	while (nb_tx < nb_rx && retry++ < BURST_TX_RETRIES) {
		// 		nb_tx += rte_eth_tx_burst(pid ^ 1, qid, &pkts_burst[nb_tx], nb_rx - nb_tx);
		// 	}
		// }
		// nr_send += nb_tx;
	// }
	// if (unlikely(nb_tx < nb_rx)) {
	// 	do {
	// 		rte_pktmbuf_free(pkts_burst[nb_tx]);
	// 	} while (++nb_tx < nb_rx);
	// }

	return nb_rx;
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

int dns_filter_worker(void *arg) {
	struct dns_worker_ctx *worker_ctx = (struct dns_worker_ctx *)arg;
    uint8_t lid = rte_lcore_id();
    port_info_t *infos[RTE_MAX_ETHPORTS];
    uint8_t qids[RTE_MAX_ETHPORTS];
    uint8_t idx, txcnt, rxcnt;
	struct timeval curr;
	float tot_recv_rate, tot_send_rate;
	unsigned long tot_recv, tot_send;
	float sec_recv, sec_send;
	float max_recv, max_send;

	tot_recv = tot_send = 0;
	max_recv = max_send = 0.0;

	memset(infos, '\0', sizeof(infos));
    memset(qids, '\0', sizeof(qids));

	port_map_info(lid, infos, qids, &txcnt, &rxcnt, "RX/TX");

    pg_lcore_get_rxbuf(lid, infos, rxcnt);

	// dpdk_tx_mbuf_init();

	doca_error_t result;
	struct mempool_elt *elt;
    list_for_each_entry(elt, &worker_ctx->buf_mempool->elt_free_list, list) {
		/* Create a DOCA buffer  for this memory region */
		result = doca_buf_inventory_buf_by_addr(worker_ctx->buf_inv, worker_ctx->mmap, elt->addr, MEMPOOL_BUF_SIZE, &elt->buf);
		if (result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Failed to allocate DOCA buf");
		}
	}

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
			regex_scan_deq_job(infos[idx]->pid  ^ 1, worker_ctx);
			nr_send += dpdk_send_pkts(infos[idx]->pid ^ 1, qids[idx]);
        }
	}

	tot_recv_rate = (float)tot_recv / (TIMEVAL_TO_MSEC(curr) - TIMEVAL_TO_MSEC(start));
	tot_send_rate = (float)tot_send / (TIMEVAL_TO_MSEC(curr) - TIMEVAL_TO_MSEC(start));

	FILE * output_fp;
	char name[32];

	sprintf(name, "thp-%d.txt", sched_getcpu());
	output_fp = fopen(name, "w");
	if (!output_fp) {
		printf("Error opening throughput output file!\n");
		return;
	}

	fprintf(output_fp, "%6.2lf\t%6.2lf\n", tot_recv_rate, tot_send_rate);

	fclose(output_fp);

	// int lat_start = (int)(0.15 * nr_latency);

	// sprintf(name, "latency-%d.txt", sched_getcpu());
	// output_fp = fopen(name, "w");
	// if (!output_fp) {
	// 	printf("Error opening latency output file!\n");
	// 	return NULL;
	// }

	// for (int i = lat_start; i < nr_latency; i++) {
	// 	fprintf(output_fp, "%lu\n", latency[i]);
	// }

	// fclose(output_fp);
	
	return 0;
}

static int dns_filter_parse_args(int argc, char ** argv) {
	int opt, option_index;
	int offset;
	static struct option lgopts[] = {
		{"crc-strip", 0, 0, 0},
		{NULL, 0, 0, 0}
	};

	while ((opt = getopt_long(argc, argv, "q:m:r:d:h", lgopts, &option_index)) != EOF)
		switch (opt) {
		case 'q':
			app_cfg.queue_depth = strtol(optarg, NULL, 10);
			break;

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

static doca_error_t dns_filter_init_lcore(struct dns_worker_ctx * ctx) {
    doca_error_t result;
    uint32_t nb_free, nb_total;
	nb_free = nb_total = 0;

    result = doca_workq_create(app_cfg.queue_depth, &ctx->workq);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to create work queue. Reason: %s", doca_get_error_string(result));
		// regex_scan_destroy(&rgx_cfg);
		return result;
	}

	result = doca_ctx_workq_add(doca_regex_as_ctx(ctx->app_cfg->doca_reg), ctx->workq);
	if (result != DOCA_SUCCESS) {
		printf("Unable to attach work queue to RegEx. Reason: %s", doca_get_error_string(result));
		// regex_scan_destroy(&rgx_cfg);
		return result;
	}

    /* Create and start buffer inventory */
	result = doca_buf_inventory_create(NULL, MEMPOOL_NR_BUF, DOCA_BUF_EXTENSION_NONE, &ctx->buf_inv);
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

	result = doca_mmap_set_max_num_chunks(ctx->mmap, PACKET_BURST);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to set memory map number of regions: %s", doca_get_error_string(result));
		return result;
	}

	result = doca_mmap_start(ctx->mmap);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to start memory map. Reason: %s", doca_get_error_string(result));
		return result;
	}

	result = doca_mmap_dev_add(ctx->mmap, ctx->app_cfg->dev);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to add device to memory map. Reason: %s", doca_get_error_string(result));
		return result;
	}

	ctx->buf_mempool = mempool_create(MEMPOOL_NR_BUF, MEMPOOL_BUF_SIZE);

	result = doca_mmap_populate(ctx->mmap, ctx->buf_mempool->addr, ctx->buf_mempool->size, sysconf(_SC_PAGESIZE), NULL, NULL);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to add memory region to memory map. Reason: %s", doca_get_error_string(result));
		return result;
	}

	/* Segment the region into pieces */
	struct mempool_elt *elt;
    list_for_each_entry(elt, &ctx->buf_mempool->elt_free_list, list) {
		elt->response = (void *)calloc(1, sizeof(struct doca_regex_search_result));
		elt->packet = (char *)calloc(256, sizeof(char));
	}

	return result;
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

		dns_filter_init_lcore(worker_ctx);

		/* Launch the worker to start process packets */
		if (rte_eal_remote_launch((void *)dns_filter_worker, (void *)worker_ctx, lcore_id) != 0) {
			DOCA_LOG_ERR("Remote launch failed");
			result = DOCA_ERROR_DRIVER;
			goto worker_cleanup;
		}

		worker_ctx++;
		lcore_index++;
	}
	return DOCA_SUCCESS;

worker_cleanup:
	doca_ctx_workq_rm(doca_regex_as_ctx(app_cfg->doca_reg), worker_ctx->workq);
destroy_workq:
	doca_workq_destroy(worker_ctx->workq);
destroy_buf_inventory:
	doca_buf_inventory_stop(worker_ctx->buf_inv);
	doca_buf_inventory_destroy(worker_ctx->buf_inv);
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

int dpdk_mempool_init(struct dns_filter_config * app_cfg) {
	char name[RTE_MEMPOOL_NAMESIZE];
	for (int i = 0; i < NR_CPUS; i++) {
        sprintf(name, "pkt_mempool_%d", i);
        pkt_mempools[i] = rte_mempool_create(name, N_MBUF,
                            MBUF_SIZE, MEMPOOL_CACHE_SIZE,
                            sizeof(struct rte_pktmbuf_pool_private),
                            rte_pktmbuf_pool_init, NULL,
                            rte_pktmbuf_init, NULL,
                            rte_socket_id(), MEMPOOL_F_SP_PUT | MEMPOOL_F_SC_GET);
        assert(pkt_mempools[i] != NULL);
    }
}

int main(int argc, char **argv) {
	uint32_t i;
	int32_t ret;
	doca_error_t result;

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
	result = dns_filter_init(&app_cfg);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_INFO("Failed to init DOCA RegEx");
		return result;
	}

	dpdk_mempool_init(&app_cfg);

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
