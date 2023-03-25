#include <rte_common.h>
#include <rte_eal.h>
#include <rte_flow.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>

#define MAX_PATTERN_NUM		4
#define MAX_ACTION_NUM		2

/* Configure the Rx and Tx hairpin queues for the selected port. */
static int
setup_hairpin_queues(uint16_t pi) {
	uint16_t qi;
	struct rte_eth_hairpin_conf hairpin_conf = {
		.peer_count = 1,
	};
	int i;
	int diag;
	struct rte_port *port = &ports[pi];

	for (qi = nb_txq, i = 0; qi < nb_hairpinq + nb_txq; qi++) {
		hairpin_conf.peers[0].port = pi;
		hairpin_conf.peers[0].queue = i + nb_rxq;
		diag = rte_eth_tx_hairpin_queue_setup
			(pi, qi, nb_txd, &hairpin_conf);
		i++;
		if (diag == 0)
			continue;

		/* Fail to setup rx queue, return */
		if (rte_atomic16_cmpset(&(port->port_status),
					RTE_PORT_HANDLING,
					RTE_PORT_STOPPED) == 0)
			printf("Port %d can not be set back "
					"to stopped\n", pi);
		printf("Fail to configure port %d hairpin "
				"queues\n", pi);
		/* try to reconfigure queues next time */
		port->need_reconfig_queues = 1;
		return -1;
	}
	for (qi = nb_rxq, i = 0; qi < nb_hairpinq + nb_rxq; qi++) {
		hairpin_conf.peers[0].port = pi;
		hairpin_conf.peers[0].queue = i + nb_txq;
		diag = rte_eth_rx_hairpin_queue_setup
			(pi, qi, nb_rxd, &hairpin_conf);
		i++;
		if (diag == 0)
			continue;

		/* Fail to setup rx queue, return */
		if (rte_atomic16_cmpset(&(port->port_status),
					RTE_PORT_HANDLING,
					RTE_PORT_STOPPED) == 0)
			printf("Port %d can not be set back "
					"to stopped\n", pi);
		printf("Fail to configure port %d hairpin "
				"queues\n", pi);
		/* try to reconfigure queues next time */
		port->need_reconfig_queues = 1;
		return -1;
	}
	return 0;
}

int main(int argc, char **argv) {
	uint32_t i;
	int32_t ret;
	int port_id;

	/* initialize EAL */
	ret = rte_eal_init(argc, argv);
	if (ret < 0) {
		return -1;
    }

	argc -= ret;
	argv += ret;

    RTE_ETH_FOREACH_DEV(port_id) {
        if (setup_hairpin_queues(port_id) != 0) {
				return -1;
        }

        struct rte_flow_error error;
        struct rte_flow_attr attr;
        struct rte_flow_item pattern[MAX_PATTERN_NUM];
        struct rte_flow_action action[MAX_ACTION_NUM];
        struct rte_flow * flow = NULL;
        struct rte_flow_action_queue_id port = { .queue = port_id ^ 1 };
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
        action[0].type = RTE_FLOW_ACTION_TYPE_QUEUE_ID;
        action[0].conf = &port;
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
        pattern[2].type = RTE_FLOW_ITEM_TYPE_UDP;
        pattern[2].spec = &udp_spec;
        pattern[2].mask = &udp_mask;

        /* the final level must be always type end */
        pattern[3].type = RTE_FLOW_ITEM_TYPE_END;

        res = rte_flow_validate(port_id, &attr, pattern, action, &error);
        if (!res) {
            flow = rte_flow_create(port_id, &attr, pattern, action, &error);
            if (!flow) {
                rte_flow_flush(port_id, &error);
            }
        }
    }

	while(true);

	/* Wait for all of the cores to stop running and exit. */
	rte_eal_mp_wait_lcore();

	RTE_ETH_FOREACH_DEV(i) {
		rte_eth_dev_stop(i);
		rte_delay_ms(100);
	}

	return 0;
}
