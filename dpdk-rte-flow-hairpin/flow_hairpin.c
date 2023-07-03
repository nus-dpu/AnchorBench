#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdarg.h>
#include <errno.h>
#include <getopt.h>
#include <stdbool.h>
#include <sys/time.h>
#include <signal.h>
#include <unistd.h>

#include <rte_malloc.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_ethdev.h>
#include <rte_flow.h>

#include "config.h"
#include "flow.h"

#define MAX_ITERATIONS             100
#define DEFAULT_RULES_COUNT    4000000
#define DEFAULT_RULES_BATCH     100000
#define DEFAULT_GROUP                0

struct rte_flow *flow;
static uint8_t flow_group;

static uint64_t encap_data;
static uint64_t decap_data;

static uint64_t flow_items[MAX_ITEMS_NUM];
static uint64_t flow_actions[MAX_ACTIONS_NUM];
static uint64_t flow_attrs[MAX_ATTRS_NUM];
static uint8_t items_idx, actions_idx, attrs_idx;

static uint64_t ports_mask;
static volatile bool force_quit;
static bool dump_iterations;
static bool delete_flag;
static bool dump_socket_mem_flag;
static bool enable_fwd;

static struct rte_mempool *mbuf_mp;
static uint32_t nb_lcores;
static uint32_t rules_count;
static uint32_t rules_batch;
static uint32_t hairpin_queues_num; /* total hairpin q number - default: 0 */
static uint32_t nb_lcores;

#define MAX_PKT_BURST    32
#define LCORE_MODE_PKT    1
#define LCORE_MODE_STATS  2
#define MAX_STREAMS      64
#define MAX_LCORES       64

static void
usage(char *progname)
{
	printf("\nusage: %s\n", progname);
	printf("\nControl configurations:\n");
	printf("  --rules-count=N: to set the number of needed"
		" rules to insert, default is %d\n", DEFAULT_RULES_COUNT);
	printf("  --rules-batch=N: set number of batched rules,"
		" default is %d\n", DEFAULT_RULES_BATCH);
	printf("  --dump-iterations: To print rates for each"
		" iteration\n");
	printf("  --deletion-rate: Enable deletion rate"
		" calculations\n");
	printf("  --dump-socket-mem: To dump all socket memory\n");
	printf("  --enable-fwd: To enable packets forwarding"
		" after insertion\n");
	printf("  --portmask=N: hexadecimal bitmask of ports used\n");

	printf("To set flow attributes:\n");
	printf("  --ingress: set ingress attribute in flows\n");
	printf("  --egress: set egress attribute in flows\n");
	printf("  --transfer: set transfer attribute in flows\n");
	printf("  --group=N: set group for all flows,"
		" default is %d\n", DEFAULT_GROUP);

	printf("To set flow items:\n");
	printf("  --ether: add ether layer in flow items\n");
	printf("  --vlan: add vlan layer in flow items\n");
	printf("  --ipv4: add ipv4 layer in flow items\n");
	printf("  --ipv6: add ipv6 layer in flow items\n");
	printf("  --tcp: add tcp layer in flow items\n");
	printf("  --udp: add udp layer in flow items\n");
	printf("  --vxlan: add vxlan layer in flow items\n");
	printf("  --vxlan-gpe: add vxlan-gpe layer in flow items\n");
	printf("  --gre: add gre layer in flow items\n");
	printf("  --geneve: add geneve layer in flow items\n");
	printf("  --gtp: add gtp layer in flow items\n");
	printf("  --meta: add meta layer in flow items\n");
	printf("  --tag: add tag layer in flow items\n");
	printf("  --icmpv4: add icmpv4 layer in flow items\n");
	printf("  --icmpv6: add icmpv6 layer in flow items\n");

	printf("To set flow actions:\n");
	printf("  --port-id: add port-id action in flow actions\n");
	printf("  --rss: add rss action in flow actions\n");
	printf("  --queue: add queue action in flow actions\n");
	printf("  --jump: add jump action in flow actions\n");
	printf("  --mark: add mark action in flow actions\n");
	printf("  --count: add count action in flow actions\n");
	printf("  --set-meta: add set meta action in flow actions\n");
	printf("  --set-tag: add set tag action in flow actions\n");
	printf("  --drop: add drop action in flow actions\n");
	printf("  --hairpin-queue=N: add hairpin-queue action in flow actions\n");
	printf("  --hairpin-rss=N: add hairpin-rss action in flow actions\n");
	printf("  --set-src-mac: add set src mac action to flow actions\n"
		"Src mac to be set is random each flow\n");
	printf("  --set-dst-mac: add set dst mac action to flow actions\n"
		 "Dst mac to be set is random each flow\n");
	printf("  --set-src-ipv4: add set src ipv4 action to flow actions\n"
		"Src ipv4 to be set is random each flow\n");
	printf("  --set-dst-ipv4 add set dst ipv4 action to flow actions\n"
		"Dst ipv4 to be set is random each flow\n");
	printf("  --set-src-ipv6: add set src ipv6 action to flow actions\n"
		"Src ipv6 to be set is random each flow\n");
	printf("  --set-dst-ipv6: add set dst ipv6 action to flow actions\n"
		"Dst ipv6 to be set is random each flow\n");
	printf("  --set-src-tp: add set src tp action to flow actions\n"
		"Src tp to be set is random each flow\n");
	printf("  --set-dst-tp: add set dst tp action to flow actions\n"
		"Dst tp to be set is random each flow\n");
	printf("  --inc-tcp-ack: add inc tcp ack action to flow actions\n"
		"tcp ack will be increments by 1\n");
	printf("  --dec-tcp-ack: add dec tcp ack action to flow actions\n"
		"tcp ack will be decrements by 1\n");
	printf("  --inc-tcp-seq: add inc tcp seq action to flow actions\n"
		"tcp seq will be increments by 1\n");
	printf("  --dec-tcp-seq: add dec tcp seq action to flow actions\n"
		"tcp seq will be decrements by 1\n");
	printf("  --set-ttl: add set ttl action to flow actions\n"
		"L3 ttl to be set is random each flow\n");
	printf("  --dec-ttl: add dec ttl action to flow actions\n"
		"L3 ttl will be decrements by 1\n");
	printf("  --set-ipv4-dscp: add set ipv4 dscp action to flow actions\n"
		"ipv4 dscp value to be set is random each flow\n");
	printf("  --set-ipv6-dscp: add set ipv6 dscp action to flow actions\n"
		"ipv6 dscp value to be set is random each flow\n");
	printf("  --flag: add flag action to flow actions\n");
	printf("  --raw-encap=<data>: add raw encap action to flow actions\n"
		"Data is the data needed to be encaped\n"
		"Example: raw-encap=ether,ipv4,udp,vxlan\n");
	printf("  --raw-decap=<data>: add raw decap action to flow actions\n"
		"Data is the data needed to be decaped\n"
		"Example: raw-decap=ether,ipv4,udp,vxlan\n");
	printf("  --vxlan-encap: add vxlan-encap action to flow actions\n"
		"Encapped data is fixed with pattern: ether,ipv4,udp,vxlan\n"
		"With fixed values\n");
	printf("  --vxlan-decap: add vxlan_decap action to flow actions\n");
}

enum layer_name {
	L2,
	L3,
	L4,
	TUNNEL,
	L2_INNER,
	L3_INNER,
	L4_INNER,
	END
};

static struct rte_flow_item pattern[] = {
	[L2] = { /* ETH type is set since we always start from ETH. */
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

struct rte_flow *
hairpin_one_port_flows_create(void)
{
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
	if (ret)
		rte_exit(EXIT_FAILURE, "Cannot get device info");
	uint16_t qi;
	for (qi = 0; qi < dev_info.nb_rx_queues; qi++) {
		struct rte_eth_dev *dev = &rte_eth_devices[port_id];
		if (rte_eth_dev_is_rx_hairpin_queue(dev, qi))
			break;
	}
	struct rte_flow_action_queue queue;
	struct rte_flow_action actions[] = {
		[0] = {
			.type = RTE_FLOW_ACTION_TYPE_QUEUE,
			.conf = &queue,
		},
		[1] = {
			.type = RTE_FLOW_ACTION_TYPE_END,
		},
	};
	pattern[L2].type = RTE_FLOW_ITEM_TYPE_ETH;
	pattern[L2].spec = NULL;
	queue.index = qi; /* rx hairpin queue index. */
	flow = rte_flow_create(port_id, &attr, pattern, actions, &error);
	if (!flow)
		printf("Can't create hairpin flows on port: %u\n", port_id);
	return flow;
}

static int
setup_hairpin_queues(uint16_t port_id, uint16_t prev_port_id,
		uint16_t port_num, uint64_t nr_hairpin_queues)
{
	/*
	 * Configure hairpin queue with so called port pair mode,
	 * which pair two consequece port together:
	 * P0 <-> P1, P2 <-> P3, etc
	 */
	uint16_t peer_port_id = RTE_MAX_ETHPORTS;
	uint32_t hairpin_queue, peer_hairpin_queue, nr_queues = 0;
	int ret = 0;
	struct rte_eth_hairpin_conf hairpin_conf = {
		.peer_count = 1,
		.manual_bind = 1,
		.tx_explicit = 1,
	};
	struct rte_eth_dev_info dev_info = { 0 };
	struct rte_eth_dev_info peer_dev_info = { 0 };
	struct rte_eth_rxq_info rxq_info = { 0 };
	struct rte_eth_txq_info txq_info = { 0 };
	uint16_t nr_std_rxq, nr_std_txq, peer_nr_std_rxq, peer_nr_std_txq;

	ret = rte_eth_dev_info_get(port_id, &dev_info);
	if (ret)
		rte_exit(EXIT_FAILURE, "Error: can't get device info, port id:"
				" %u\n", port_id);
	nr_std_rxq = dev_info.nb_rx_queues - nr_hairpin_queues;
	nr_std_txq = dev_info.nb_tx_queues - nr_hairpin_queues;
	nr_queues = dev_info.nb_rx_queues;
	/* only get first q info. */
	rte_eth_rx_queue_info_get(port_id, 0, &rxq_info);
	rte_eth_tx_queue_info_get(port_id, 0, &txq_info);
	if (port_num & 0x1) {
		peer_port_id = prev_port_id;
	}
	else {
		peer_port_id = rte_eth_find_next_owned_by(port_id + 1,
				RTE_ETH_DEV_NO_OWNER);
		if (peer_port_id >= RTE_MAX_ETHPORTS)
			peer_port_id = port_id;
	}
	ret = rte_eth_dev_info_get(peer_port_id, &peer_dev_info);
	if (ret)
		rte_exit(EXIT_FAILURE, "Error: can't get peer device info, "
				"peer port id: %u", peer_port_id);
	peer_nr_std_rxq = peer_dev_info.nb_rx_queues - nr_hairpin_queues;
	peer_nr_std_txq = peer_dev_info.nb_tx_queues - nr_hairpin_queues;
	for (hairpin_queue = nr_std_rxq, peer_hairpin_queue = peer_nr_std_txq;
			hairpin_queue < nr_queues;
			hairpin_queue++, peer_hairpin_queue++) {
		hairpin_conf.peers[0].port = peer_port_id;
		hairpin_conf.peers[0].queue = peer_hairpin_queue;
		ret = rte_eth_rx_hairpin_queue_setup(
				port_id, hairpin_queue,
				rxq_info.nb_desc, &hairpin_conf);
		if (ret != 0)
			return ret;
	}
	for (hairpin_queue = nr_std_txq, peer_hairpin_queue = peer_nr_std_rxq;
			hairpin_queue < nr_queues;
			hairpin_queue++, peer_hairpin_queue++) {
		hairpin_conf.peers[0].port = peer_port_id;
		hairpin_conf.peers[0].queue = peer_hairpin_queue;
		ret = rte_eth_tx_hairpin_queue_setup(
				port_id, hairpin_queue,
				txq_info.nb_desc, &hairpin_conf);
		if (ret != 0)
			return ret;
	}
	return ret;
}

int
hairpin_two_ports_setup(uint64_t nr_hairpin_queue)
{
	uint16_t port_id, prev_port_id = RTE_MAX_ETHPORTS;
	uint16_t port_num = 0;
	int ret = 0;

	RTE_ETH_FOREACH_DEV(port_id) {
		ret = setup_hairpin_queues(port_id, prev_port_id,
				port_num, nr_hairpin_queue);
		if (ret)
			rte_exit(EXIT_FAILURE, "Error to setup hairpin queues"
					" on port: %u", port_id);
		port_num++;
		prev_port_id = port_id;
	}
	return 0;
}

struct rte_flow *
hairpin_two_ports_flows_create(void)
{
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
	uint16_t qi;
	for (qi = 0; qi < dev_info.nb_rx_queues; qi++) {
		struct rte_eth_dev *dev = &rte_eth_devices[port_id];
		if (rte_eth_dev_is_rx_hairpin_queue(dev, qi)) {
			break;
		}
	}
	struct rte_flow_action_queue queue;
	struct rte_flow_action actions[] = {
		[0] = {
			.type = RTE_FLOW_ACTION_TYPE_QUEUE,
			.conf = &queue,
		},
		[1] = {
			.type = RTE_FLOW_ACTION_TYPE_END,
		},
	};
	queue.index = qi; /* rx hairpin queue index. */

	flow = rte_flow_create(port_id, &attr, pattern, actions, &error);
	if (!flow) {
		printf("Can't create hairpin flows on port: %u\n", port_id);
	} else {
		printf("Direct flows to hairpin queue: %u on port: %u\n", qi, port_id);
	}

	/* get peer port id. */
	uint16_t pair_port_list[RTE_MAX_ETHPORTS];
	int pair_port_num = rte_eth_hairpin_get_peer_ports(port_id,
			pair_port_list, RTE_MAX_ETHPORTS, 0);
	if (pair_port_num < 0)
		rte_exit(EXIT_FAILURE, "Can't get pair port !");
	RTE_ASSERT(pair_port_num == 1);
	/* create pattern to match hairpin flow from hairpin RX queue. */
	pattern[L2].type = RTE_FLOW_ITEM_TYPE_ETH;
	pattern[L2].spec = NULL;
	pattern[END].type = RTE_FLOW_ITEM_TYPE_END;
	/* create actions. */
	actions[0].type = RTE_FLOW_ACTION_TYPE_END;
	attr.egress = 1;
	attr.ingress = 0;
	flow = rte_flow_create(pair_port_list[0], &attr, pattern, actions,
			&error);
	if (!flow) {
		printf("Can't create hairpin flows on pair port: %u, "
			"error: %s\n", pair_port_list[0], error.message);
	}
	return flow;
}

static void
init_port(void)
{
	int ret;
	uint16_t std_queue;
	uint16_t hairpin_queue;
	uint16_t port_id;
	uint16_t nr_ports;
	uint16_t nr_queues;
	struct rte_eth_hairpin_conf hairpin_conf = {
		.peer_count = 1,
	};
	struct rte_eth_conf port_conf = {
		.rx_adv_conf = {
			.rss_conf.rss_hf =
				GET_RSS_HF(),
		}
	};
	struct rte_eth_txconf txq_conf;
	struct rte_eth_rxconf rxq_conf;
	struct rte_eth_dev_info dev_info;

	nr_queues = RXQ_NUM;
	if (hairpin_queues_num != 0)
		nr_queues = RXQ_NUM + hairpin_queues_num;

	nr_ports = rte_eth_dev_count_avail();
	if (nr_ports == 0)
		rte_exit(EXIT_FAILURE, "Error: no port detected\n");

	mbuf_mp = rte_pktmbuf_pool_create("mbuf_pool",
					TOTAL_MBUF_NUM, MBUF_CACHE_SIZE,
					0, MBUF_SIZE,
					rte_socket_id());
	if (mbuf_mp == NULL)
		rte_exit(EXIT_FAILURE, "Error: can't init mbuf pool\n");

	for (port_id = 0; port_id < nr_ports; port_id++) {
		ret = rte_eth_dev_info_get(port_id, &dev_info);
		if (ret != 0)
			rte_exit(EXIT_FAILURE,
				"Error during getting device"
				" (port %u) info: %s\n",
				port_id, strerror(-ret));

		port_conf.txmode.offloads &= dev_info.tx_offload_capa;
		port_conf.rxmode.offloads &= dev_info.rx_offload_capa;

		printf(":: initializing port: %d\n", port_id);

		ret = rte_eth_dev_configure(port_id, nr_queues,
				nr_queues, &port_conf);
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
				":: cannot configure device: err=%d, port=%u\n",
				ret, port_id);

		rxq_conf = dev_info.default_rxconf;
		for (std_queue = 0; std_queue < RXQ_NUM; std_queue++) {
			ret = rte_eth_rx_queue_setup(port_id, std_queue, NR_RXD,
					rte_eth_dev_socket_id(port_id),
					&rxq_conf,
					mbuf_mp);
			if (ret < 0)
				rte_exit(EXIT_FAILURE,
					":: Rx queue setup failed: err=%d, port=%u\n",
					ret, port_id);
		}

		txq_conf = dev_info.default_txconf;
		for (std_queue = 0; std_queue < TXQ_NUM; std_queue++) {
			ret = rte_eth_tx_queue_setup(port_id, std_queue, NR_TXD,
					rte_eth_dev_socket_id(port_id),
					&txq_conf);
			if (ret < 0)
				rte_exit(EXIT_FAILURE,
					":: Tx queue setup failed: err=%d, port=%u\n",
					ret, port_id);
		}

		/* Catch all packets from traffic generator. */
		ret = rte_eth_promiscuous_enable(port_id);
		if (ret != 0)
			rte_exit(EXIT_FAILURE,
				":: promiscuous mode enable failed: err=%s, port=%u\n",
				rte_strerror(-ret), port_id);

		ret = rte_eth_dev_start(port_id);
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
				"rte_eth_dev_start:err=%d, port=%u\n",
				ret, port_id);

		printf(":: initializing port: %d done\n", port_id);
	}

	if (hairpin_queues_num != 0) {
		hairpin_two_ports_setup(hairpin_queues_num);
		hairpin_two_ports_flows_create();
	}
}

static void
args_parse(int argc, char **argv)
{
	uint64_t pm;
	char **argvopt;
	char *token;
	char *end;
	int n, opt;
	int opt_idx;
	size_t i;

	static const struct option_dict {
		const char *str;
		const uint64_t mask;
		uint64_t *map;
		uint8_t *map_idx;

	} flow_options[] = {
		{
			.str = "ether",
			.mask = FLOW_ITEM_MASK(RTE_FLOW_ITEM_TYPE_ETH),
			.map = &flow_items[0],
			.map_idx = &items_idx
		},
		{
			.str = "ipv4",
			.mask = FLOW_ITEM_MASK(RTE_FLOW_ITEM_TYPE_IPV4),
			.map = &flow_items[0],
			.map_idx = &items_idx
		},
		{
			.str = "ipv6",
			.mask = FLOW_ITEM_MASK(RTE_FLOW_ITEM_TYPE_IPV6),
			.map = &flow_items[0],
			.map_idx = &items_idx
		},
		{
			.str = "vlan",
			.mask = FLOW_ITEM_MASK(RTE_FLOW_ITEM_TYPE_VLAN),
			.map = &flow_items[0],
			.map_idx = &items_idx
		},
		{
			.str = "tcp",
			.mask = FLOW_ITEM_MASK(RTE_FLOW_ITEM_TYPE_TCP),
			.map = &flow_items[0],
			.map_idx = &items_idx
		},
		{
			.str = "udp",
			.mask = FLOW_ITEM_MASK(RTE_FLOW_ITEM_TYPE_UDP),
			.map = &flow_items[0],
			.map_idx = &items_idx
		},
		{
			.str = "vxlan",
			.mask = FLOW_ITEM_MASK(RTE_FLOW_ITEM_TYPE_VXLAN),
			.map = &flow_items[0],
			.map_idx = &items_idx
		},
		{
			.str = "vxlan-gpe",
			.mask = FLOW_ITEM_MASK(RTE_FLOW_ITEM_TYPE_VXLAN_GPE),
			.map = &flow_items[0],
			.map_idx = &items_idx
		},
		{
			.str = "gre",
			.mask = FLOW_ITEM_MASK(RTE_FLOW_ITEM_TYPE_GRE),
			.map = &flow_items[0],
			.map_idx = &items_idx
		},
		{
			.str = "geneve",
			.mask = FLOW_ITEM_MASK(RTE_FLOW_ITEM_TYPE_GENEVE),
			.map = &flow_items[0],
			.map_idx = &items_idx
		},
		{
			.str = "gtp",
			.mask = FLOW_ITEM_MASK(RTE_FLOW_ITEM_TYPE_GTP),
			.map = &flow_items[0],
			.map_idx = &items_idx
		},
		{
			.str = "meta",
			.mask = FLOW_ITEM_MASK(RTE_FLOW_ITEM_TYPE_META),
			.map = &flow_items[0],
			.map_idx = &items_idx
		},
		{
			.str = "tag",
			.mask = FLOW_ITEM_MASK(RTE_FLOW_ITEM_TYPE_TAG),
			.map = &flow_items[0],
			.map_idx = &items_idx
		},
		{
			.str = "icmpv4",
			.mask = FLOW_ITEM_MASK(RTE_FLOW_ITEM_TYPE_ICMP),
			.map = &flow_items[0],
			.map_idx = &items_idx
		},
		{
			.str = "icmpv6",
			.mask = FLOW_ITEM_MASK(RTE_FLOW_ITEM_TYPE_ICMP6),
			.map = &flow_items[0],
			.map_idx = &items_idx
		},
		{
			.str = "ingress",
			.mask = INGRESS,
			.map = &flow_attrs[0],
			.map_idx = &attrs_idx
		},
		{
			.str = "egress",
			.mask = EGRESS,
			.map = &flow_attrs[0],
			.map_idx = &attrs_idx
		},
		{
			.str = "transfer",
			.mask = TRANSFER,
			.map = &flow_attrs[0],
			.map_idx = &attrs_idx
		},
		{
			.str = "port-id",
			.mask = FLOW_ACTION_MASK(RTE_FLOW_ACTION_TYPE_PORT_ID),
			.map = &flow_actions[0],
			.map_idx = &actions_idx
		},
		{
			.str = "rss",
			.mask = FLOW_ACTION_MASK(RTE_FLOW_ACTION_TYPE_RSS),
			.map = &flow_actions[0],
			.map_idx = &actions_idx
		},
		{
			.str = "queue",
			.mask = FLOW_ACTION_MASK(RTE_FLOW_ACTION_TYPE_QUEUE),
			.map = &flow_actions[0],
			.map_idx = &actions_idx
		},
		{
			.str = "jump",
			.mask = FLOW_ACTION_MASK(RTE_FLOW_ACTION_TYPE_JUMP),
			.map = &flow_actions[0],
			.map_idx = &actions_idx
		},
		{
			.str = "mark",
			.mask = FLOW_ACTION_MASK(RTE_FLOW_ACTION_TYPE_MARK),
			.map = &flow_actions[0],
			.map_idx = &actions_idx
		},
		{
			.str = "count",
			.mask = FLOW_ACTION_MASK(RTE_FLOW_ACTION_TYPE_COUNT),
			.map = &flow_actions[0],
			.map_idx = &actions_idx
		},
		{
			.str = "set-meta",
			.mask = FLOW_ACTION_MASK(RTE_FLOW_ACTION_TYPE_SET_META),
			.map = &flow_actions[0],
			.map_idx = &actions_idx
		},
		{
			.str = "set-tag",
			.mask = FLOW_ACTION_MASK(RTE_FLOW_ACTION_TYPE_SET_TAG),
			.map = &flow_actions[0],
			.map_idx = &actions_idx
		},
		{
			.str = "drop",
			.mask = FLOW_ACTION_MASK(RTE_FLOW_ACTION_TYPE_DROP),
			.map = &flow_actions[0],
			.map_idx = &actions_idx
		},
		{
			.str = "set-src-mac",
			.mask = FLOW_ACTION_MASK(
				RTE_FLOW_ACTION_TYPE_SET_MAC_SRC
			),
			.map = &flow_actions[0],
			.map_idx = &actions_idx
		},
		{
			.str = "set-dst-mac",
			.mask = FLOW_ACTION_MASK(
				RTE_FLOW_ACTION_TYPE_SET_MAC_DST
			),
			.map = &flow_actions[0],
			.map_idx = &actions_idx
		},
		{
			.str = "set-src-ipv4",
			.mask = FLOW_ACTION_MASK(
				RTE_FLOW_ACTION_TYPE_SET_IPV4_SRC
			),
			.map = &flow_actions[0],
			.map_idx = &actions_idx
		},
		{
			.str = "set-dst-ipv4",
			.mask = FLOW_ACTION_MASK(
				RTE_FLOW_ACTION_TYPE_SET_IPV4_DST
			),
			.map = &flow_actions[0],
			.map_idx = &actions_idx
		},
		{
			.str = "set-src-ipv6",
			.mask = FLOW_ACTION_MASK(
				RTE_FLOW_ACTION_TYPE_SET_IPV6_SRC
			),
			.map = &flow_actions[0],
			.map_idx = &actions_idx
		},
		{
			.str = "set-dst-ipv6",
			.mask = FLOW_ACTION_MASK(
				RTE_FLOW_ACTION_TYPE_SET_IPV6_DST
			),
			.map = &flow_actions[0],
			.map_idx = &actions_idx
		},
		{
			.str = "set-src-tp",
			.mask = FLOW_ACTION_MASK(
				RTE_FLOW_ACTION_TYPE_SET_TP_SRC
			),
			.map = &flow_actions[0],
			.map_idx = &actions_idx
		},
		{
			.str = "set-dst-tp",
			.mask = FLOW_ACTION_MASK(
				RTE_FLOW_ACTION_TYPE_SET_TP_DST
			),
			.map = &flow_actions[0],
			.map_idx = &actions_idx
		},
		{
			.str = "inc-tcp-ack",
			.mask = FLOW_ACTION_MASK(
				RTE_FLOW_ACTION_TYPE_INC_TCP_ACK
			),
			.map = &flow_actions[0],
			.map_idx = &actions_idx
		},
		{
			.str = "dec-tcp-ack",
			.mask = FLOW_ACTION_MASK(
				RTE_FLOW_ACTION_TYPE_DEC_TCP_ACK
			),
			.map = &flow_actions[0],
			.map_idx = &actions_idx
		},
		{
			.str = "inc-tcp-seq",
			.mask = FLOW_ACTION_MASK(
				RTE_FLOW_ACTION_TYPE_INC_TCP_SEQ
			),
			.map = &flow_actions[0],
			.map_idx = &actions_idx
		},
		{
			.str = "dec-tcp-seq",
			.mask = FLOW_ACTION_MASK(
				RTE_FLOW_ACTION_TYPE_DEC_TCP_SEQ
			),
			.map = &flow_actions[0],
			.map_idx = &actions_idx
		},
		{
			.str = "set-ttl",
			.mask = FLOW_ACTION_MASK(
				RTE_FLOW_ACTION_TYPE_SET_TTL
			),
			.map = &flow_actions[0],
			.map_idx = &actions_idx
		},
		{
			.str = "dec-ttl",
			.mask = FLOW_ACTION_MASK(
				RTE_FLOW_ACTION_TYPE_DEC_TTL
			),
			.map = &flow_actions[0],
			.map_idx = &actions_idx
		},
		{
			.str = "set-ipv4-dscp",
			.mask = FLOW_ACTION_MASK(
				RTE_FLOW_ACTION_TYPE_SET_IPV4_DSCP
			),
			.map = &flow_actions[0],
			.map_idx = &actions_idx
		},
		{
			.str = "set-ipv6-dscp",
			.mask = FLOW_ACTION_MASK(
				RTE_FLOW_ACTION_TYPE_SET_IPV6_DSCP
			),
			.map = &flow_actions[0],
			.map_idx = &actions_idx
		},
		{
			.str = "flag",
			.mask = FLOW_ACTION_MASK(
				RTE_FLOW_ACTION_TYPE_FLAG
			),
			.map = &flow_actions[0],
			.map_idx = &actions_idx
		},
		{
			.str = "vxlan-encap",
			.mask = FLOW_ACTION_MASK(
				RTE_FLOW_ACTION_TYPE_VXLAN_ENCAP
			),
			.map = &flow_actions[0],
			.map_idx = &actions_idx
		},
		{
			.str = "vxlan-decap",
			.mask = FLOW_ACTION_MASK(
				RTE_FLOW_ACTION_TYPE_VXLAN_DECAP
			),
			.map = &flow_actions[0],
			.map_idx = &actions_idx
		},
	};

	static const struct option lgopts[] = {
		/* Control */
		{ "help",                       0, 0, 0 },
		{ "rules-count",                1, 0, 0 },
		{ "rules-batch",                1, 0, 0 },
		{ "dump-iterations",            0, 0, 0 },
		{ "deletion-rate",              0, 0, 0 },
		{ "dump-socket-mem",            0, 0, 0 },
		{ "enable-fwd",                 0, 0, 0 },
		{ "portmask",                   1, 0, 0 },
		/* Attributes */
		{ "ingress",                    0, 0, 0 },
		{ "egress",                     0, 0, 0 },
		{ "transfer",                   0, 0, 0 },
		{ "group",                      1, 0, 0 },
		/* Items */
		{ "ether",                      0, 0, 0 },
		{ "vlan",                       0, 0, 0 },
		{ "ipv4",                       0, 0, 0 },
		{ "ipv6",                       0, 0, 0 },
		{ "tcp",                        0, 0, 0 },
		{ "udp",                        0, 0, 0 },
		{ "vxlan",                      0, 0, 0 },
		{ "vxlan-gpe",                  0, 0, 0 },
		{ "gre",                        0, 0, 0 },
		{ "geneve",                     0, 0, 0 },
		{ "gtp",                        0, 0, 0 },
		{ "meta",                       0, 0, 0 },
		{ "tag",                        0, 0, 0 },
		{ "icmpv4",                     0, 0, 0 },
		{ "icmpv6",                     0, 0, 0 },
		/* Actions */
		{ "port-id",                    0, 0, 0 },
		{ "rss",                        0, 0, 0 },
		{ "queue",                      0, 0, 0 },
		{ "jump",                       0, 0, 0 },
		{ "mark",                       0, 0, 0 },
		{ "count",                      0, 0, 0 },
		{ "set-meta",                   0, 0, 0 },
		{ "set-tag",                    0, 0, 0 },
		{ "drop",                       0, 0, 0 },
		{ "hairpin-queue",              1, 0, 0 },
		{ "hairpin-rss",                1, 0, 0 },
		{ "set-src-mac",                0, 0, 0 },
		{ "set-dst-mac",                0, 0, 0 },
		{ "set-src-ipv4",               0, 0, 0 },
		{ "set-dst-ipv4",               0, 0, 0 },
		{ "set-src-ipv6",               0, 0, 0 },
		{ "set-dst-ipv6",               0, 0, 0 },
		{ "set-src-tp",                 0, 0, 0 },
		{ "set-dst-tp",                 0, 0, 0 },
		{ "inc-tcp-ack",                0, 0, 0 },
		{ "dec-tcp-ack",                0, 0, 0 },
		{ "inc-tcp-seq",                0, 0, 0 },
		{ "dec-tcp-seq",                0, 0, 0 },
		{ "set-ttl",                    0, 0, 0 },
		{ "dec-ttl",                    0, 0, 0 },
		{ "set-ipv4-dscp",              0, 0, 0 },
		{ "set-ipv6-dscp",              0, 0, 0 },
		{ "flag",                       0, 0, 0 },
		{ "raw-encap",                  1, 0, 0 },
		{ "raw-decap",                  1, 0, 0 },
		{ "vxlan-encap",                0, 0, 0 },
		{ "vxlan-decap",                0, 0, 0 },
	};

	hairpin_queues_num = 0;
	argvopt = argv;

	printf(":: Flow -> ");
	while ((opt = getopt_long(argc, argvopt, "",
				lgopts, &opt_idx)) != EOF) {
		switch (opt) {
		case 0:
			if (strcmp(lgopts[opt_idx].name, "help") == 0) {
				usage(argv[0]);
				rte_exit(EXIT_SUCCESS, "Displayed help\n");
			}

			if (strcmp(lgopts[opt_idx].name, "group") == 0) {
				n = atoi(optarg);
				if (n >= 0)
					flow_group = n;
				else
					rte_exit(EXIT_SUCCESS,
						"flow group should be >= 0\n");
				printf("group %d / ", flow_group);
			}

			for (i = 0; i < RTE_DIM(flow_options); i++)
				if (strcmp(lgopts[opt_idx].name,
						flow_options[i].str) == 0) {
					flow_options[i].map[
					(*flow_options[i].map_idx)++] =
						flow_options[i].mask;
					printf("%s / ", flow_options[i].str);
				}

			if (strcmp(lgopts[opt_idx].name,
					"hairpin-rss") == 0) {
				n = atoi(optarg);
				if (n > 0)
					hairpin_queues_num = n;
				else
					rte_exit(EXIT_SUCCESS,
						"Hairpin queues should be > 0\n");

				flow_actions[actions_idx++] =
					HAIRPIN_RSS_ACTION;
				printf("hairpin-rss / ");
			}
			if (strcmp(lgopts[opt_idx].name,
					"hairpin-queue") == 0) {
				n = atoi(optarg);
				if (n > 0)
					hairpin_queues_num = n;
				else
					rte_exit(EXIT_SUCCESS,
						"Hairpin queues should be > 0\n");

				flow_actions[actions_idx++] =
					HAIRPIN_QUEUE_ACTION;
				printf("hairpin-queue / ");
			}

			if (strcmp(lgopts[opt_idx].name, "raw-encap") == 0) {
				printf("raw-encap ");
				flow_actions[actions_idx++] =
					FLOW_ITEM_MASK(
						RTE_FLOW_ACTION_TYPE_RAW_ENCAP
					);

				token = strtok(optarg, ",");
				while (token != NULL) {
					for (i = 0; i < RTE_DIM(flow_options); i++) {
						if (strcmp(flow_options[i].str, token) == 0) {
							printf("%s,", token);
							encap_data |= flow_options[i].mask;
							break;
						}
						/* Reached last item with no match */
						if (i == (RTE_DIM(flow_options) - 1)) {
							fprintf(stderr, "Invalid encap item: %s\n", token);
							usage(argv[0]);
							rte_exit(EXIT_SUCCESS, "Invalid encap item\n");
						}
					}
					token = strtok(NULL, ",");
				}
				printf(" / ");
			}
			if (strcmp(lgopts[opt_idx].name, "raw-decap") == 0) {
				printf("raw-decap ");
				flow_actions[actions_idx++] =
					FLOW_ITEM_MASK(
						RTE_FLOW_ACTION_TYPE_RAW_DECAP
					);

				token = strtok(optarg, ",");
				while (token != NULL) {
					for (i = 0; i < RTE_DIM(flow_options); i++) {
						if (strcmp(flow_options[i].str, token) == 0) {
							printf("%s,", token);
							encap_data |= flow_options[i].mask;
							break;
						}
						/* Reached last item with no match */
						if (i == (RTE_DIM(flow_options) - 1)) {
							fprintf(stderr, "Invalid decap item: %s\n", token);
							usage(argv[0]);
							rte_exit(EXIT_SUCCESS, "Invalid decap item\n");
						}
					}
					token = strtok(NULL, ",");
				}
				printf(" / ");
			}
			/* Control */
			if (strcmp(lgopts[opt_idx].name,
					"rules-batch") == 0) {
				n = atoi(optarg);
				if (n >= DEFAULT_RULES_BATCH)
					rules_batch = n;
				else {
					printf("\n\nrules_batch should be >= %d\n",
						DEFAULT_RULES_BATCH);
					rte_exit(EXIT_SUCCESS, " ");
				}
			}
			if (strcmp(lgopts[opt_idx].name,
					"rules-count") == 0) {
				n = atoi(optarg);
				if (n >= (int) rules_batch)
					rules_count = n;
				else {
					printf("\n\nrules_count should be >= %d\n",
						rules_batch);
				}
			}
			if (strcmp(lgopts[opt_idx].name,
					"dump-iterations") == 0)
				dump_iterations = true;
			if (strcmp(lgopts[opt_idx].name,
					"deletion-rate") == 0)
				delete_flag = true;
			if (strcmp(lgopts[opt_idx].name,
					"dump-socket-mem") == 0)
				dump_socket_mem_flag = true;
			if (strcmp(lgopts[opt_idx].name,
					"enable-fwd") == 0)
				enable_fwd = true;
			if (strcmp(lgopts[opt_idx].name,
					"portmask") == 0) {
				/* parse hexadecimal string */
				end = NULL;
				pm = strtoull(optarg, &end, 16);
				if ((optarg[0] == '\0') || (end == NULL) || (*end != '\0'))
					rte_exit(EXIT_FAILURE, "Invalid fwd port mask\n");
				ports_mask = pm;
			}
			break;
		default:
			fprintf(stderr, "Invalid option: %s\n", argv[optind]);
			usage(argv[0]);
			rte_exit(EXIT_SUCCESS, "Invalid option\n");
			break;
		}
	}
	printf("end_flow\n");
}

int
main(int argc, char **argv)
{
	int ret;
	uint16_t port;
	struct rte_flow_error error;
	int64_t alloc, last_alloc;

	ret = rte_eal_init(argc, argv);
	if (ret < 0) {
		rte_exit(EXIT_FAILURE, "EAL init failed\n");
	}

	argc -= ret;
	argv += ret;
	if (argc > 1) {
		args_parse(argc, argv);
	}

	init_port();

	sleep(20);

	// init_lcore_info();
	// rte_eal_mp_remote_launch(start_forwarding, NULL, CALL_MAIN);

	// RTE_ETH_FOREACH_DEV(port) {
	// 	rte_flow_flush(port, &error);
	// 	if (rte_eth_dev_stop(port) != 0)
	// 		printf("Failed to stop device on port %u\n", port);
	// 	rte_eth_dev_close(port);
	// }
	return 0;
}

