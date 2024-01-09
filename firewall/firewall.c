/*
 * Copyright (c) 2022 NVIDIA CORPORATION & AFFILIATES, ALL RIGHTS RESERVED.
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

#include <string.h>
#include <unistd.h>

#include <rte_ethdev.h>
#include <rte_byteorder.h>
#include <linux/if_ether.h>
#include <linux/udp.h>
#include <rte_ip.h>
#include <rte_udp.h>

#include <doca_log.h>
#include <doca_flow.h>
#include <doca_argp.h>

#include "firewall.h"

#define MAX_PKT_BURST	(32)

#include "flow_common.h"

DOCA_LOG_REGISTER(FIREWALL);

struct app_config cfg;

__thread uint64_t sec_nb_rx;
__thread uint64_t sec_nb_tx;

#define USEC_PER_SEC		1000000L
#define TIMEVAL_TO_USEC(t)  ((t.tv_sec * USEC_PER_SEC) + (t.tv_usec))

/*
 * ARGP Callback - Handle the size of vector for the allreduce parameter
 *
 * @param [in]: Input parameter
 * @config [in/out]: Program configuration context
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
set_nr_rules_param(void *param, void *config)
{
	cfg.nr_rules = *(int *) param;
	return DOCA_SUCCESS;
}

/*
 * ARGP Callback - Handle the size of vector for the allreduce parameter
 *
 * @param [in]: Input parameter
 * @config [in/out]: Program configuration context
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
set_nr_cores_param(void *param, void *config)
{
	cfg.nr_cores = *(int *) param;
	return DOCA_SUCCESS;
}

/*
 * ARGP Callback - Handle the size of vector for the allreduce parameter
 *
 * @param [in]: Input parameter
 * @config [in/out]: Program configuration context
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
set_nr_queues_param(void *param, void *config)
{
	cfg.nr_queues = *(int *) param;
	return DOCA_SUCCESS;
}

doca_error_t
register_firewall_params(void)
{
	doca_error_t result;
	struct doca_argp_param *nr_rules_param, *nr_cores_param, *nr_queues_param;

	/* Create and register vector size param */
	result = doca_argp_param_create(&nr_rules_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create ARGP param: %s", doca_get_error_string(result));
		return result;
	}
	doca_argp_param_set_short_name(nr_rules_param, "r");
	doca_argp_param_set_long_name(nr_rules_param, "rule");
	doca_argp_param_set_arguments(nr_rules_param, "<rule>");
	doca_argp_param_set_description(nr_rules_param, "Number of hardware offload rules");
	doca_argp_param_set_callback(nr_rules_param, set_nr_rules_param);
	doca_argp_param_set_type(nr_rules_param, DOCA_ARGP_TYPE_INT);
	result = doca_argp_register_param(nr_rules_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to register program param: %s", doca_get_error_string(result));
		return result;
	}

	/* Create and register vector size param */
	result = doca_argp_param_create(&nr_cores_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create ARGP param: %s", doca_get_error_string(result));
		return result;
	}
	doca_argp_param_set_short_name(nr_cores_param, "c");
	doca_argp_param_set_long_name(nr_cores_param, "core");
	doca_argp_param_set_arguments(nr_cores_param, "<core>");
	doca_argp_param_set_description(nr_cores_param, "Number of cores");
	doca_argp_param_set_callback(nr_cores_param, set_nr_cores_param);
	doca_argp_param_set_type(nr_cores_param, DOCA_ARGP_TYPE_INT);
	result = doca_argp_register_param(nr_cores_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to register program param: %s", doca_get_error_string(result));
		return result;
	}

	/* Create and register vector size param */
	result = doca_argp_param_create(&nr_queues_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create ARGP param: %s", doca_get_error_string(result));
		return result;
	}
	doca_argp_param_set_short_name(nr_queues_param, "q");
	doca_argp_param_set_long_name(nr_queues_param, "queue");
	doca_argp_param_set_arguments(nr_queues_param, "<queue>");
	doca_argp_param_set_description(nr_queues_param, "Number of queues");
	doca_argp_param_set_callback(nr_queues_param, set_nr_queues_param);
	doca_argp_param_set_type(nr_queues_param, DOCA_ARGP_TYPE_INT);
	result = doca_argp_register_param(nr_queues_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to register program param: %s", doca_get_error_string(result));
		return result;
	}

	return DOCA_SUCCESS;
}

/*
 * Create DOCA Flow pipe with 5 tuple match that forwards the matched traffic to the other port
 *
 * @port [in]: port of the pipe
 * @port_id [in]: port ID of the pipe
 * @pipe [out]: created pipe pointer
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise.
 */
static doca_error_t
create_hairpin_pipe(struct doca_flow_port *port, int port_id, struct doca_flow_pipe **pipe, struct doca_flow_pipe *rss_pipe)
{
	int nb_queues = 1;
	int queue_index;
	uint16_t rss_queues[nb_queues];
	struct doca_flow_match match;
	struct doca_flow_actions actions, *actions_arr[NB_ACTIONS_ARR];
	struct doca_flow_fwd fwd;
	// struct doca_flow_fwd fwd_miss;
	struct doca_flow_pipe_cfg pipe_cfg;
	doca_error_t result;

	memset(&match, 0, sizeof(match));
	memset(&actions, 0, sizeof(actions));
	memset(&fwd, 0, sizeof(fwd));
	memset(&pipe_cfg, 0, sizeof(pipe_cfg));

	pipe_cfg.attr.name = "HAIRPIN_PIPE";
	pipe_cfg.attr.type = DOCA_FLOW_PIPE_BASIC;
	pipe_cfg.match = &match;
	actions_arr[0] = &actions;
	pipe_cfg.actions = actions_arr;
	pipe_cfg.attr.is_root = true;
	pipe_cfg.attr.nb_actions = NB_ACTIONS_ARR;
	pipe_cfg.port = port;

	/* 5 tuple match */
	match.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;
	match.outer.l4_type_ext = DOCA_FLOW_L4_TYPE_EXT_UDP;
	match.outer.ip4.dst_ip = 0xffffffff;
	match.outer.ip4.src_ip = 0xffffffff;
	match.outer.udp.l4_port.dst_port = 0xffff;
	match.outer.udp.l4_port.src_port = 0xffff;

	/* forwarding traffic to other port */
	// fwd.type = DOCA_FLOW_FWD_PORT;
	// fwd.port_id = port_id ^ 1;
	// fwd.type = DOCA_FLOW_FWD_DROP;

	fwd.type = DOCA_FLOW_FWD_PORT;
	fwd.port_id = port_id ^ 1;

	// fwd_miss.type = DOCA_FLOW_FWD_PIPE;
	// fwd_miss.next_pipe = rss_pipe;

	// result = doca_flow_pipe_create(&pipe_cfg, &fwd, &fwd_miss, pipe);
	result = doca_flow_pipe_create(&pipe_cfg, &fwd, NULL, pipe);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Hairpin pipe creation FAILED: %s", doca_get_error_string(result));
		return result;
	}

	return DOCA_SUCCESS;
}

/*
 * Add DOCA Flow pipe entry to the hairpin pipe
 *
 * @pipe [in]: pipe of the entry
 * @status [in]: user context for adding entry
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise.
 */
static doca_error_t
add_hairpin_pipe_entry(struct doca_flow_pipe *pipe, struct entries_status *status, uint16_t sport)
{
	struct doca_flow_match match;
	struct doca_flow_actions actions;
	struct doca_flow_pipe_entry *entry;
	doca_error_t result;

	/* example 5-tuple to forward */
	doca_be32_t dst_ip_addr = BE_IPV4_ADDR(10, 0, 0, 1);
	doca_be32_t src_ip_addr = BE_IPV4_ADDR(10, 0, 0, 3);
	doca_be16_t dst_port = rte_cpu_to_be_16(53);
	// doca_be16_t src_port = rte_cpu_to_be_16(0x1101);
	doca_be16_t src_port = rte_cpu_to_be_16(sport);

	memset(&match, 0, sizeof(match));
	memset(&actions, 0, sizeof(actions));

	match.outer.ip4.dst_ip = dst_ip_addr;
	match.outer.ip4.src_ip = src_ip_addr;
	match.outer.udp.l4_port.dst_port = dst_port;
	match.outer.udp.l4_port.src_port = src_port;

	result = doca_flow_pipe_add_entry(0, pipe, &match, &actions, NULL, NULL, 0, status, &entry);
	if (result != DOCA_SUCCESS)
		return result;

	return DOCA_SUCCESS;
}

doca_error_t
create_rss_pipe(struct doca_flow_port *port, int port_id, int nb_queues, struct doca_flow_pipe **pipe)
{
	int queue_index;
	uint16_t rss_queues[nb_queues];
	struct doca_flow_match match = {0};
	struct doca_flow_match match_mask = {0};
	struct doca_flow_fwd fwd = {0};
	struct doca_flow_pipe_cfg pipe_cfg = {0};
	struct entries_status status = {0};
	doca_error_t result;

	memset(&match, 0, sizeof(match));
	memset(&match_mask, 0, sizeof(match_mask));
	memset(&fwd, 0, sizeof(fwd));
	memset(&status, 0, sizeof(status));
	memset(&pipe_cfg, 0, sizeof(pipe_cfg));

	match.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;
	match.outer.ip4.dst_ip = 0xffffffff;
	match.outer.ip4.src_ip = 0xffffffff;

	pipe_cfg.attr.name = "RSS_PIPE";
	pipe_cfg.attr.type = DOCA_FLOW_PIPE_BASIC;
	pipe_cfg.attr.nb_actions = 1;
	pipe_cfg.match = &match;
	pipe_cfg.match_mask = &match_mask;
	pipe_cfg.attr.is_root = false;
	pipe_cfg.port = port;

	/* Configure queues for rss fw */
	for (queue_index = 0; queue_index < nb_queues; queue_index++) {
		rss_queues[queue_index] = queue_index;
	}

	fwd.type = DOCA_FLOW_FWD_RSS;
	fwd.rss_queues = rss_queues;
	fwd.num_of_queues = nb_queues;

	result = doca_flow_pipe_create(&pipe_cfg, &fwd, NULL, pipe);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("RSS pipe creation FAILED: %s", doca_get_error_string(result));
		return result;
	}

	return DOCA_SUCCESS;
}

/*
 * Add DOCA Flow pipe entry to the hairpin pipe
 *
 * @pipe [in]: pipe of the entry
 * @status [in]: user context for adding entry
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise.
 */
static doca_error_t
add_rss_pipe_entry(struct doca_flow_pipe *pipe, struct entries_status *status)
{
	struct doca_flow_match match;
	struct doca_flow_actions actions;
	struct doca_flow_pipe_entry *entry;
	doca_error_t result;

	/* example 5-tuple to forward */
	doca_be32_t dst_ip_addr = BE_IPV4_ADDR(10, 0, 0, 1);
	doca_be32_t src_ip_addr = BE_IPV4_ADDR(10, 0, 0, 3);
	// doca_be16_t dst_port = rte_cpu_to_be_16(53);
	// doca_be16_t src_port = rte_cpu_to_be_16(1234);

	memset(&match, 0, sizeof(match));
	memset(&actions, 0, sizeof(actions));

	match.outer.ip4.dst_ip = dst_ip_addr;
	match.outer.ip4.src_ip = src_ip_addr;
	// match.outer.udp.l4_port.dst_port = dst_port;
	// match.outer.udp.l4_port.src_port = src_port;

	result = doca_flow_pipe_add_entry(0, pipe, &match, &actions, NULL, NULL, 0, status, &entry);
	if (result != DOCA_SUCCESS)
		return result;

	return DOCA_SUCCESS;
}

int
sw_launch_one_lcore(__rte_unused void *dummy)
{
	uint16_t port_id;
	struct rte_mbuf * pkts_burst[MAX_PKT_BURST] = { NULL };
	int nb_rx, nb_tx;
	char * p;
    struct udphdr * udp;
	struct timeval current, last_log;
	double elapsed;
	uint16_t qid = sched_getcpu();

	gettimeofday(&last_log, NULL);
	while (1) {
		nb_rx = nb_tx = 0;
		gettimeofday(&current, NULL);
		if (current.tv_sec - last_log.tv_sec >= 1) {
			elapsed = TIMEVAL_TO_USEC(current) - TIMEVAL_TO_USEC(last_log);
			printf("CPU %02d | RX: %.2f (MPS), TX: %.2f (MPS)\n", sched_getcpu(), sec_nb_rx / elapsed, sec_nb_tx / elapsed);
			sec_nb_rx = sec_nb_tx = 0;
			gettimeofday(&last_log, NULL);
		}
		RTE_ETH_FOREACH_DEV(port_id) {
			nb_rx = rte_eth_rx_burst(port_id, qid, pkts_burst, MAX_PKT_BURST);
			if (unlikely(nb_rx == 0)) {
				continue;
			}
			sec_nb_rx += nb_rx;

			// for (int i = 0; i < nb_rx; i++) {
			//     p = rte_pktmbuf_mtod(pkts_burst[i], char *);
			//     udp = (struct udphdr *)(p + ETH_HLEN + sizeof(struct iphdr));
			// 	printf("Src port: %x, dst port: %x\n", ntohs(udp->source), ntohs(udp->dest));
			// }

			nb_tx += rte_eth_tx_burst(port_id ^ 1, qid, &pkts_burst[nb_tx], nb_rx - nb_tx);
			sec_nb_tx += nb_tx;

			if (unlikely(nb_tx < nb_rx)) {
				do {
					rte_pktmbuf_free(pkts_burst[nb_tx]);
				} while (++nb_tx < nb_rx);
			}
		}
	}

	return 0;
}

/*
 * Run flow_hairpin_vnf sample
 *
 * @nb_queues [in]: number of queues the sample will use
 * @nr_rules [in]: number of rules to be offloaded to hardware
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise.
 */
doca_error_t
flow_hairpin_vnf(int nb_ports, struct doca_flow_port *ports[], int nb_queues, int nr_rules)
{
	struct doca_flow_resources resource = {0};
	uint32_t nr_shared_resources[DOCA_FLOW_SHARED_RESOURCE_MAX] = {0};
	struct doca_flow_pipe *hairpin_pipe;
	struct doca_flow_pipe *rss_pipe;
	struct entries_status status;
	int num_of_entries;
	doca_error_t result;
	unsigned int lcore_id;
	int port_id;
	uint16_t sport;

	result = init_doca_flow(nb_queues, "vnf,hws", resource, nr_shared_resources);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to init DOCA Flow: %s", doca_get_error_string(result));
		return result;
	}

	result = init_doca_flow_ports(nb_ports, ports, true);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to init DOCA ports: %s", doca_get_error_string(result));
		doca_flow_destroy();
		return result;
	}

	for (port_id = 0; port_id < nb_ports; port_id++) {
		num_of_entries = 0;

		memset(&status, 0, sizeof(status));
#if 0
		result = create_rss_pipe(ports[port_id], port_id, nb_queues, &rss_pipe);
		if (result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Failed to create pipe: %s", doca_get_error_string(result));
			stop_doca_flow_ports(nb_ports, ports);
			doca_flow_destroy();
			return result;
		}

		result = add_rss_pipe_entry(rss_pipe, &status);
		if (result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Failed to add entry: %s", doca_get_error_string(result));
			stop_doca_flow_ports(nb_ports, ports);
			doca_flow_destroy();
			return result;
		}
		num_of_entries++;
#endif
		result = create_hairpin_pipe(ports[port_id], port_id, &hairpin_pipe, NULL);
		if (result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Failed to create pipe: %s", doca_get_error_string(result));
			stop_doca_flow_ports(nb_ports, ports);
			doca_flow_destroy();
			return result;
		}

		for (int i = 0; i < nr_rules; i++) {
			/* PktGen: core 17-31 */
			for (int j = 17; j < 32; j++) {
				sport = (j << 8) | (i + 1);
				result = add_hairpin_pipe_entry(hairpin_pipe, &status, sport);
				if (result != DOCA_SUCCESS) {
					DOCA_LOG_ERR("Failed to add entry: %s", doca_get_error_string(result));
					stop_doca_flow_ports(nb_ports, ports);
					doca_flow_destroy();
					return result;
				}
				num_of_entries++;
			}
		}

		result = doca_flow_entries_process(ports[port_id], 0, DEFAULT_TIMEOUT_US, num_of_entries);
		if (result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Failed to process entries: %s", doca_get_error_string(result));
			stop_doca_flow_ports(nb_ports, ports);
			doca_flow_destroy();
			return result;
		}

		if (status.nb_processed != num_of_entries || status.failure) {
			DOCA_LOG_ERR("Failed to process entries");
			stop_doca_flow_ports(nb_ports, ports);
			doca_flow_destroy();
			return DOCA_ERROR_BAD_STATE;
		}

		DOCA_LOG_INFO("Offload %d rules on port %d", status.nb_processed, port_id);
	}

	return DOCA_SUCCESS;
}
