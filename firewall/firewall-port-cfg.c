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

#include "firewall.h"

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
        .mq_mode = RTE_ETH_MQ_RX_NONE,
    },
    .txmode = {
        .mq_mode = RTE_ETH_MQ_TX_NONE,
        .offloads = (RTE_ETH_TX_OFFLOAD_IPV4_CKSUM |
                RTE_ETH_TX_OFFLOAD_UDP_CKSUM |
                RTE_ETH_TX_OFFLOAD_TCP_CKSUM),
    },
    .rx_adv_conf = {
        .rss_conf = {
            .rss_key = NULL,
            .rss_hf =
                RTE_ETH_RSS_IP | RTE_ETH_RSS_TCP | RTE_ETH_RSS_UDP,
        },
    },
};

#include "firewall-constants.h"
#include "firewall-port-cfg.h"

void firewall_config_ports(int nr_cores, int nr_queues, int nr_hairpin_queues) {
    struct rte_eth_conf conf = {0};
    uint32_t pid;
    uint16_t nb_ports;
	int32_t ret;
	struct rte_eth_dev_info dev_info;
    char name[RTE_MEMPOOL_NAMESIZE];

	/* Find out the total number of ports in the system. */
	/* We have already blacklisted the ones we needed to in main routine. */
	nb_ports = rte_eth_dev_count_total();
	if (nb_ports > RTE_MAX_ETHPORTS) {
		nb_ports = RTE_MAX_ETHPORTS;
    }

	if (nb_ports == 0) {
		perror("*** Did not find any ports to use ***");
    }

	printf("Configuring %d ports, MBUF Size %d, MBUF Cache Size %d\n", nb_ports, MBUF_SIZE, MBUF_CACHE_SIZE);

    for (int i = 0; i < nr_cores; i++) {
        sprintf(name, "pkt_mempool_%d", i);
        /* Create and initialize the default Receive buffers. */
        ctx[i].pkt_mempool = rte_mempool_create(name, MAX_MBUFS_PER_PORT,
                        MBUF_SIZE, RTE_MEMPOOL_CACHE_MAX_SIZE,
                        sizeof(struct rte_pktmbuf_pool_private),
                        rte_pktmbuf_pool_init, NULL,
                        rte_pktmbuf_init, NULL,
                        rte_socket_id(), MEMPOOL_F_SP_PUT | MEMPOOL_F_SC_GET);
        if (ctx[i].pkt_mempool == NULL) {
            printf("Cannot init Default RX mbufs for core %d\n", i);
        }
    }

    RTE_ETH_FOREACH_DEV(pid) {
        printf("Initialize Port %u -- TxQ %u, RxQ %u\n", pid, nr_queues, nr_queues);

    	/* Get Ethernet device info */
        ret = rte_eth_dev_info_get(pid, &dev_info);
	    if (ret < 0) {
            printf("Error during getting device (port %u) info: %s\n", pid, strerror(-ret));
        }

        /* Get a clean copy of the configuration structure */
        rte_memcpy(&conf, &port_conf, sizeof(struct rte_eth_conf));

        if (nr_queues > 1) {
            conf.rx_adv_conf.rss_conf.rss_key = NULL;
            conf.rx_adv_conf.rss_conf.rss_hf &= dev_info.flow_type_rss_offloads;
        } else {
            conf.rx_adv_conf.rss_conf.rss_key = NULL;
            conf.rx_adv_conf.rss_conf.rss_hf  = 0;
        }

        if (conf.rx_adv_conf.rss_conf.rss_hf != 0) {
            conf.rxmode.mq_mode = RTE_ETH_MQ_RX_RSS;
        } else {
            conf.rxmode.mq_mode = RTE_ETH_MQ_RX_NONE;
        }

        /* Configure # of RX and TX queue for port */
        ret = rte_eth_dev_configure(pid, nr_queues, nr_queues, &conf);
    	if (ret < 0) {
	    	printf("Cannot configure device: err=%d, port=%u\n", ret, pid);
	    }

        for (int i = 0; i < nr_cores; i++) {
            ret = rte_eth_rx_queue_setup(pid, i, DEFAULT_RX_DESC, SOCKET_ID_ANY, &rx_conf, ctx[i].pkt_mempool);
			if (ret < 0) {
				printf("rte_eth_rx_queue_setup: err=%d, port=%d, %s\n", ret, pid, rte_strerror(-ret));
            }
		}

        for (int i = 0; i < nr_cores; i++) {
			ret = rte_eth_tx_queue_setup(pid, i, DEFAULT_TX_DESC, SOCKET_ID_ANY, &tx_conf);
			if (ret < 0) {
				printf("rte_eth_tx_queue_setup: err=%d, port=%d, %s\n", ret, pid, rte_strerror(-ret));
            }
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
