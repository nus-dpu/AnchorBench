#include <stdint.h>
#include <termios.h>
#include <stdio.h>
#include <execinfo.h>
#include <signal.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/time.h>
#include <regex.h>

#include "dns-filter.h"
#include "dns-filter-l2p.h"
#include "dns-filter-constants.h"
#include "dns-filter-port-cfg.h"

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

#define MAX_RULES		16
#define MAX_RULE_LEN	64

__thread int nb_regex_rules = 0;
__thread regex_t regex_rules[MAX_RULES];

#define ETH_HEADER_SIZE 14			/* ETH header size = 14 bytes (112 bits) */
#define IP_HEADER_SIZE 	20			/* IP header size = 20 bytes (160 bits) */
#define UDP_HEADER_SIZE 8			/* UDP header size = 8 bytes (64 bits) */
#define DNS_HEADER_SIZE 12			/* DNS header size = 12 bytes (72 bits) */

static int read_file(char const * path, char ** out_bytes, size_t * out_bytes_len) {
	FILE * file;
	char * bytes;

	file = fopen(path, "rb");
	if (file == NULL) {
		return -1;
	}

	if (fseek(file, 0, SEEK_END) != 0) {
		fclose(file);
		return -1;
	}

	long const nb_file_bytes = ftell(file);

	if (nb_file_bytes == -1) {
		fclose(file);
		return -1;
	}

	if (nb_file_bytes == 0) {
		fclose(file);
		return -1;
	}

	bytes = malloc(nb_file_bytes);
	if (bytes == NULL) {
		fclose(file);
		return -1;
	}

	if (fseek(file, 0, SEEK_SET) != 0) {
		free(bytes);
		fclose(file);
		return -1;
	}

	size_t const read_byte_count = fread(bytes, 1, nb_file_bytes, file);

	fclose(file);

	if (read_byte_count != nb_file_bytes) {
		free(bytes);
		return -1;
	}

	*out_bytes = bytes;
	*out_bytes_len = read_byte_count;

	return 0;
}

static void parse_file_by_line(char * content, size_t content_len) {
	char * pos, * check;
	char rule[MAX_RULE_LEN];
	int ret;

	pos = content;
	while (pos < content + content_len) {
		check = strchr(pos, '\n');
		snprintf(rule, check - pos, "%s", pos);
		// regex_rules[nb_regex_rules++] = rule;
		/* Compile RegEx engine */
		ret = regcomp(&regex_rules[nb_regex_rules], rule, 0);
		if (ret != 0) {
			printf("Failed to compile regression engine\n");
		}
		if (!check) {
			break;
		} else {
			pos = check + 1;
			nb_regex_rules++;
		}
	}
}

static int extract_dns_query(struct rte_mbuf *pkt) {
	int result, len, query_len;
	uint32_t payload_offset = 0;
    char * p, * parse, * dst;
	char name[32];

	dst = name;

	p = rte_pktmbuf_mtod(pkt, char *);

	/* Skip UDP and DNS header to get DNS (query) start */
    p += ETH_HEADER_SIZE;
    p += IP_HEADER_SIZE;
	p += UDP_HEADER_SIZE;
	p += DNS_HEADER_SIZE;

	query_len = (int)strlen(p);

	for(int i = 0 ; i < query_len;)  {
		len = p[i++];
		for (int j = 0; j < len; j++) {
			*dst++ = p[i++];
		}
		if (i != query_len) {
			*dst++ = '.';
		}
	}

	for (int i = 0; i < nb_regex_rules; i++) {
		result = regexec(&regex_rules[i], name, 0, NULL, 0);
		if (result == 0) {
			return 1;
		}
	}

	return 0;
}

static int handle_packets_received(struct rte_mbuf **packets, uint16_t packets_received) {
	int ret;

	for (int i = 0; i < packets_received; i++) {
		ret = extract_dns_query(packets[i]);
		if (ret < 0)
			return ret;
	}
	return 0;
}

static void pkt_burst_forward(int pid, int qid) {
	struct rte_mbuf * pkts_burst[DEFAULT_PKT_BURST];
	uint16_t nb_rx;
	uint16_t nb_tx;
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

	handle_packets_received(pkts_burst, nb_rx);

	nb_tx = rte_eth_tx_burst(pid, qid, pkts_burst, nb_rx);
	if (unlikely(nb_tx < nb_rx)) {
		retry = 0;
		while (nb_tx < nb_rx && retry++ < BURST_TX_RETRIES) {
			nb_tx += rte_eth_tx_burst(pid ^ 1, qid, &pkts_burst[nb_tx], nb_rx - nb_tx);
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

int dns_filter_launch_one_lcore(void *arg __rte_unused) {
    uint8_t lid = rte_lcore_id();
    port_info_t *infos[RTE_MAX_ETHPORTS];
    uint8_t qids[RTE_MAX_ETHPORTS];
    uint8_t idx, txcnt, rxcnt;
	struct timeval curr;
	float tot_recv_rate, tot_send_rate;
	unsigned long tot_recv, tot_send;
	float sec_recv, sec_send;
	float max_recv, max_send;
	int ret;
	char * rules_file_data;
	size_t rules_file_size;

	tot_recv = tot_send = 0;
	max_recv = max_send = 0.0;

	memset(infos, '\0', sizeof(infos));
    memset(qids, '\0', sizeof(qids));

	port_map_info(lid, infos, qids, &txcnt, &rxcnt, "RX/TX");

    pg_lcore_get_rxbuf(lid, infos, rxcnt);

	ret = read_file("../regex_rules.txt", &rules_file_data, &rules_file_size);
	if (ret == -1) {
		printf("invalid RegEx rules\n");
	}
	parse_file_by_line(rules_file_data, rules_file_size);

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
		if (start_flag & curr.tv_sec - start.tv_sec > 20) {
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

static int dns_filter_parse_args(int argc, char ** argv) {
	int opt, option_index, ret;
	double rate;
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

		case 'r':	/* RegEx rultes */
			// ret = read_file(optarg, &rules_file_data, &rules_file_size);
			// if (ret == -1) {
			// 	printf("invalid RegEx rules\n");
			// }
			// parse_file_by_line(rules_file_data, rules_file_size);
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

	ret = dns_filter_parse_args(argc, argv);

	printf(">>> Packet Burst %d, RX Desc %d, TX Desc %d, mbufs/port %d, mbuf cache %d\n",
			DEFAULT_PKT_BURST, DEFAULT_RX_DESC, DEFAULT_TX_DESC, MAX_MBUFS_PER_PORT, MBUF_CACHE_SIZE);

	/* Configure and initialize the ports */
	dns_filter_config_ports();

	/* launch per-lcore init on every lcore except initial and initial + 1 lcores */
	ret = rte_eal_mp_remote_launch(dns_filter_launch_one_lcore, NULL, SKIP_MAIN);
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
