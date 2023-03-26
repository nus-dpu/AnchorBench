#include <stdint.h>
#include <termios.h>
#include <stdio.h>
#include <execinfo.h>
#include <signal.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/time.h>

#include "testpmd.h"
#include "testpmd-l2p.h"
#include "testpmd-constants.h"
#include "testpmd-port-cfg.h"

#define BURST_TX_RETRIES 16

#define MSEC_PER_SEC    1000L
#define USEC_PER_MSEC   1000L
#define TIMEVAL_TO_MSEC(t)  ((t.tv_sec * MSEC_PER_SEC) + (t.tv_usec / USEC_PER_MSEC))

int delay_cycles = 0;

__thread struct timeval last_log;
__thread int start_flag = 0;
__thread struct timeval start;
__thread uint64_t nr_recv;
__thread uint64_t nr_send;

static void pkt_burst_forward(int pid, int qid) {
	struct rte_mbuf * pkts_burst[DEFAULT_PKT_BURST];
	uint16_t nb_rx;
	uint16_t nb_tx;
	uint32_t retry;
	uint64_t start_tsc, cur_tsc;

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

	for (int i = 0; i < nb_rx; i++) {
		start_tsc = rte_rdtsc();
		do {
			cur_tsc = rte_rdtsc();
		} while (cur_tsc - start_tsc < delay_cycles);
	}

	nb_tx = rte_eth_tx_burst(pid, qid, pkts_burst, nb_rx);
	if (unlikely(nb_tx < nb_rx)) {
		retry = 0;
		while (nb_tx < nb_rx && retry++ < BURST_TX_RETRIES) {
			nb_tx += rte_eth_tx_burst(pid, qid, &pkts_burst[nb_tx], nb_rx - nb_tx);
		}
	}
	nr_send += nb_tx;
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

int testpmd_setup_flow(uint32_t pid, uint8_t qid, uint16_t dst_port) {
	struct rte_flow_error error;
	struct rte_flow_attr attr;
	struct rte_flow_item pattern[MAX_PATTERN_NUM];
	struct rte_flow_action action[MAX_ACTION_NUM];
	struct rte_flow * flow = NULL;
	struct rte_flow_action_queue queue = { .queue = qid };
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
	udp_spec.hdr.dst_port = htons(dst_port);
	udp_mask.hdr.dst_port = htons(0xff00);
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

int testpmd_launch_one_lcore(void *arg __rte_unused) {
    uint8_t lid = rte_lcore_id();
    port_info_t *infos[RTE_MAX_ETHPORTS];
    uint8_t qids[RTE_MAX_ETHPORTS];
    uint32_t pid;
    uint8_t idx, txcnt, rxcnt;
	struct timeval curr;
	float tot_recv_rate, tot_send_rate;
	unsigned long tot_recv, tot_send;
	float sec_recv, sec_send;
	float max_recv, max_send;
	uint16_t dst_port = lid << 8;

	tot_recv = tot_send = 0;
	max_recv = max_send = 0.0;

	memset(infos, '\0', sizeof(infos));
    memset(qids, '\0', sizeof(qids));

	port_map_info(lid, infos, qids, &txcnt, &rxcnt, "RX/TX");

    pg_lcore_get_rxbuf(lid, infos, rxcnt);

	for (idx = 0; idx < rxcnt; idx++) {
		testpmd_setup_flow(infos[idx]->pid, qids[idx], dst_port);
	}

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
		if (curr.tv_sec - start.tv_sec > 20) {
			break;
		}
		for (idx = 0; idx < rxcnt; idx++) {
            pkt_burst_forward(infos[idx]->pid, qids[idx]);
        }
	}

	tot_recv_rate = (float)tot_recv / (TIMEVAL_TO_MSEC(curr) - TIMEVAL_TO_MSEC(start));
	tot_send_rate = (float)tot_send / (TIMEVAL_TO_MSEC(curr) - TIMEVAL_TO_MSEC(start));

	printf("CORE %d ==> RX: %8.2f (KPS), TX: %8.2f (KPS)\n", lid, tot_recv_rate , tot_send_rate);
}

static int testpmd_parse_args(int argc, char ** argv) {
	int opt, num_cores, num_flows;
	int option_index;
	double rate;
	static struct option lgopts[] = {
		{"crc-strip", 0, 0, 0},
		{NULL, 0, 0, 0}
	};

	while ((opt = getopt_long(argc, argv, "m:d:h", lgopts, &option_index)) != EOF)
		switch (opt) {
		case 'm':	/* Matrix for port mapping. */
			if (pg_parse_matrix(&l2p, optarg) == -1) {
				printf("invalid matrix string (%s)", optarg);
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
    return 0;
}

int main(int argc, char **argv) {
	uint32_t i;
	int32_t ret;

	/* initialize EAL */
	ret = rte_eal_init(argc, argv);
	if (ret < 0) {
		return -1;
    }

	argc -= ret;
	argv += ret;

	ret = testpmd_parse_args(argc, argv);

	printf(">>> Packet Burst %d, RX Desc %d, TX Desc %d, mbufs/port %d, mbuf cache %d\n",
			DEFAULT_PKT_BURST, DEFAULT_RX_DESC, DEFAULT_TX_DESC, MAX_MBUFS_PER_PORT, MBUF_CACHE_SIZE);

	/* Configure and initialize the ports */
	testpmd_config_ports();

	/* launch per-lcore init on every lcore except initial and initial + 1 lcores */
	ret = rte_eal_mp_remote_launch(testpmd_launch_one_lcore, NULL, SKIP_MAIN);
	if (ret != 0) {
		printf("Failed to start lcore %d, return %d\n", i, ret);
	}

	rte_delay_ms(250);	/* Wait for the lcores to start up. */

	/* Wait for all of the cores to stop running and exit. */
	rte_eal_mp_wait_lcore();

	RTE_ETH_FOREACH_DEV(i) {
		rte_eth_dev_stop(i);
		rte_delay_ms(100);
	}

	return 0;
}
