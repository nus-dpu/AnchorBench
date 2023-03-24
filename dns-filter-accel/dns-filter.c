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

#define MAX_RULES		16
#define MAX_RULE_LEN	64

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

	if (!start_flag) {
		start_flag = 1;
		gettimeofday(&start, NULL);
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

	gettimeofday(&start, NULL);
	gettimeofday(&last_log, NULL);

    while (true) {
		gettimeofday(&curr, NULL);
		if (curr.tv_sec - last_log.tv_sec > 1) {
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

	printf("CORE %d ==> RX: %8.2f (KPS), TX: %8.2f (KPS)\n", lid, tot_recv_rate , tot_send_rate);

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
			doca_mmap_destroy(mmap);
			return -1;
		}

		result = doca_mmap_start(worker_ctx->mmap);
		if (result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Unable to start memory map: %s", doca_get_error_string(result));
			doca_mmap_destroy(mmap);
			return -1;
		}

		result = doca_mmap_dev_add(worker_ctx->mmap, worker_ctx->app_cfg->dev);
		if (result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Unable to add device to mmap: %s", doca_get_error_string(result));
			doca_mmap_stop(mmap);
			doca_mmap_destroy(mmap);
			return -1;
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

int main(int argc, char **argv) {
	uint32_t i;
	int32_t ret;
	doca_error_t result;
	struct dns_filter_config app_cfg = {0};

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
