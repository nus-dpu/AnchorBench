#include <fcntl.h>
#include <ifaddrs.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <netdb.h>
#include <net/if.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>

#include <rte_common.h>
#include <rte_eal.h>
#include <rte_flow.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>

#include "testpmd-port-cfg.h"
#include "testpmd-l2p.h"

#define SG_MEMPOOL

int port_cnt = 0;
port_info_t info[RTE_MAX_ETHPORTS];	/**< Port information */
l2p_t l2p;

/* RX queue configuration */
static struct rte_eth_rxconf rx_conf = {
    .rx_thresh = {
        .pthresh = 8,
        .hthresh = 8,
        .wthresh = 4,
    },
    .rx_free_thresh = 32,
};

/* TX queue configuration */
static struct rte_eth_txconf tx_conf = {
    .tx_thresh = {
        .pthresh = 36,
        .hthresh = 0,
        .wthresh = 0,
    },
    .tx_free_thresh = 0,
};

/* Port configuration */
struct rte_eth_conf port_conf = {
    .rxmode = {
        .mq_mode = ETH_MQ_RX_NONE,
    },
    .txmode = {
        .mq_mode = ETH_MQ_TX_NONE,
        .offloads = (DEV_TX_OFFLOAD_IPV4_CKSUM |
                DEV_TX_OFFLOAD_UDP_CKSUM |
                DEV_TX_OFFLOAD_TCP_CKSUM),
    },
};

#include "testpmd-constants.h"
#include "testpmd-port-cfg.h"

static struct rte_mempool * testpmd_mempool_create(const char *type, uint8_t pid, uint8_t queue_id,
			uint32_t nb_mbufs, int socket_id, int cache_size){
	struct rte_mempool * mp;
	char name[RTE_MEMZONE_NAMESIZE];

	snprintf(name, sizeof(name), "%-12s%u:%u", type, pid, queue_id);
	printf("    Create: %-*s - Memory used (MBUFs %5u x (size %u + Hdr %lu)) + %lu = %6lu KB headroom %d %d\n",
		16,
		name,
		nb_mbufs,
		MBUF_SIZE,
		sizeof(struct rte_mbuf),
		sizeof(struct rte_mempool),
		(((nb_mbufs * (MBUF_SIZE + sizeof(struct rte_mbuf)) +
		   sizeof(struct rte_mempool))) + 1023) / 1024,
		RTE_PKTMBUF_HEADROOM,
		RTE_MBUF_DEFAULT_BUF_SIZE);

	/* create the mbuf pool */
	mp = rte_mempool_create(name, nb_mbufs, MBUF_SIZE, cache_size,
							sizeof(struct rte_pktmbuf_pool_private), 
							rte_pktmbuf_pool_init, NULL,
                            rte_pktmbuf_init, NULL,
							socket_id, MEMPOOL_F_SP_PUT | MEMPOOL_F_SC_GET);
	if (mp == NULL) {
		printf("Cannot create mbuf pool (%s) port %d, queue %d, nb_mbufs %d, socket_id %d: %s\n",
			name, pid, queue_id, nb_mbufs, socket_id, rte_strerror(errno));
    }

	return mp;
}

#define FULL_IP_MASK   0xffffffff /* full mask */
#define EMPTY_IP_MASK  0x0 /* empty mask */

#define FULL_PORT_MASK   0xffff /* full mask */
#define PART_PORT_MASK   0xff00 /* partial mask */
#define EMPTY_PORT_MASK  0x0 /* empty mask */

#define MAX_PATTERN_NUM		4
#define MAX_ACTION_NUM		2

void testpmd_create_flow(int pid, uint16_t sport, uint16_t queueid) {
    uint16_t dst_port;
	struct rte_flow_error error;
	struct rte_flow_attr attr;
	struct rte_flow_item pattern[MAX_PATTERN_NUM];
	struct rte_flow_action action[MAX_ACTION_NUM];
	struct rte_flow * flow = NULL;
	struct rte_flow_action_queue queue = { .index = queueid };
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
    attr.priority = 0;

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
    udp_spec.hdr.dst_port = htons(sport);
    udp_mask.hdr.dst_port = htons(PART_PORT_MASK);
    pattern[2].type = RTE_FLOW_ITEM_TYPE_UDP;
    pattern[2].spec = &udp_spec;
    pattern[2].mask = &udp_mask;

    /* the final level must be always type end */
    pattern[3].type = RTE_FLOW_ITEM_TYPE_END;

    printf("Direct flow to port %x via queue %d\n", dst_port & PART_PORT_MASK, queueid);

    res = rte_flow_validate(pid, &attr, pattern, action, &error);
    if (!res) {
retry:
        flow = rte_flow_create(pid, &attr, pattern, action, &error);
        if (!flow) {
            rte_flow_flush(pid, &error);
            goto retry;
        }
    } else {
        printf("control: invalid flow rule! msg: %s\n", error.message);
    }
}

void testpmd_config_ports() {
    struct rte_eth_conf conf = {0};
    uint32_t lid, pid, q;
    rxtx_t rt;
    uint16_t nb_ports;
	int32_t ret, cache_size;
#ifdef SG_MEMPOOL
    struct rte_mempool * mp;
#endif
    cache_size = RTE_MEMPOOL_CACHE_MAX_SIZE;

	/* Find out the total number of ports in the system. */
	/* We have already blacklisted the ones we needed to in main routine. */
	nb_ports = rte_eth_dev_count_total();
	if (nb_ports > RTE_MAX_ETHPORTS) {
		nb_ports = RTE_MAX_ETHPORTS;
    }

	if (nb_ports == 0) {
		perror("*** Did not find any ports to use ***");
    }

	printf("Configuring %d ports, MBUF Size %d, MBUF Cache Size %d\n",
		    nb_ports, MBUF_SIZE, MBUF_CACHE_SIZE);

    /* For each lcore setup each port that is handled by that lcore. */
    for (lid = 0; lid < RTE_MAX_LCORE; lid++) {
        if (get_map(&l2p, RTE_MAX_ETHPORTS, lid) == 0) {
            continue;
        }

        /* For each port attached or handled by the lcore */
        RTE_ETH_FOREACH_DEV(pid) {
            /* If non-zero then this port is handled by this lcore. */
            if (get_map(&l2p, pid, lid) == 0) {
                continue;
            }

            pg_set_port_private(&l2p, pid, &info[pid]);
            info[pid].pid = pid;
        }
    }

    pg_dump_l2p(&l2p);

#ifdef SG_MEMPOOL
    mp = rte_pktmbuf_pool_create("MBUF_POOL", MAX_MBUFS_PER_PORT * 2, 
                        cache_size, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	if (mp == NULL) {
        printf("Cannot allocate RX mbufs\n", pid);
	}
    printf("Shared RX mbuf: %p\n", mp);
#endif

    RTE_ETH_FOREACH_DEV(pid) {
		/* Skip if we do not have any lcores attached to a port. */
        if ((rt.rxtx = get_map(&l2p, pid, RTE_MAX_LCORE)) == 0) {
            continue;
		}

        port_cnt++;
        printf("Initialize Port %u -- TxQ %u, RxQ %u\n", pid, rt.tx, rt.rx);

    	/* Get Ethernet device info */
        ret = rte_eth_dev_info_get(pid, &info[pid].dev_info);
	    if (ret < 0) {
            printf("Error during getting device (port %u) info: %s\n", pid, strerror(-ret));
        }

        /* Get a clean copy of the configuration structure */
        rte_memcpy(&conf, &port_conf, sizeof(struct rte_eth_conf));

        /* Configure # of RX and TX queue for port */
        ret = rte_eth_dev_configure(pid, rt.rx, rt.tx, &conf);
    	if (ret < 0) {
	    	printf("Cannot configure device: err=%d, port=%u\n", ret, pid);
	    }

        for (q = 0; q < rt.rx; q++) {
#ifdef SG_MEMPOOL
			printf("\tLink PORT %d QUEUE %d to mempool %p\n", pid, q, mp);
			ret = rte_eth_rx_queue_setup(pid, q, DEFAULT_RX_DESC, SOCKET_ID_ANY, &rx_conf, mp);
			if (ret < 0) {
				printf("rte_eth_rx_queue_setup: err=%d, port=%d, %s\n", ret, pid, rte_strerror(-ret));
            }
#else
            /* Create and initialize the default Receive buffers. */
			info[pid].q[q].rx_mp = testpmd_mempool_create("Default RX", pid, q,
								   MAX_MBUFS_PER_PORT, SOCKET_ID_ANY, cache_size);
			if (info[pid].q[q].rx_mp == NULL) {
				printf("Cannot init port %d for Default RX mbufs\n", pid);
            }

            printf("\tLink PORT %d QUEUE %d to mempool %p\n", pid, q, info[pid].q[q].rx_mp);
			ret = rte_eth_rx_queue_setup(pid, q, DEFAULT_RX_DESC, SOCKET_ID_ANY, &rx_conf, info[pid].q[q].rx_mp);
			if (ret < 0) {
				printf("rte_eth_rx_queue_setup: err=%d, port=%d, %s\n", ret, pid, rte_strerror(-ret));
            }
#endif
		}

        for (q = 0; q < rt.tx; q++) {
			ret = rte_eth_tx_queue_setup(pid, q, DEFAULT_TX_DESC, SOCKET_ID_ANY, &tx_conf);
			if (ret < 0) {
				printf("rte_eth_tx_queue_setup: err=%d, port=%d, %s\n", ret, pid, rte_strerror(-ret));
            }
		}

        for (q = 0; q < rt.rx; q++) {
            testpmd_create_flow(pid, q << 8, q);
        }
    }

    RTE_ETH_FOREACH_DEV(pid) {
        ret = rte_eth_promiscuous_enable(pid);
        if (ret != 0) {
            printf("rte_eth_promiscuous_enable:err = %d, port = %u\n", ret, (unsigned)pid);
        }

        /* Start device */
        ret = rte_eth_dev_start(pid);
		if (ret != 0) {
            printf("rte_eth_dev_start: port=%d, %s\n", pid, rte_strerror(-ret));
        }
    }
}
