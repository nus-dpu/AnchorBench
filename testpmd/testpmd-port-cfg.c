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
    .rx_adv_conf = {
        .rss_conf = {
            .rss_key = NULL,
            .rss_hf =
                RTE_ETH_RSS_IP | RTE_ETH_RSS_TCP | ETH_RSS_UDP,
        },
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
	mp = rte_mempool_create(name, nb_mbufs, MBUF_SIZE, 256,
							sizeof(struct rte_pktmbuf_pool_private), 
							rte_pktmbuf_pool_init, NULL,
                            rte_pktmbuf_init, NULL,
							socket_id, 0);
	if (mp == NULL) {
		printf("Cannot create mbuf pool (%s) port %d, queue %d, nb_mbufs %d, socket_id %d: %s\n",
			name, pid, queue_id, nb_mbufs, socket_id, rte_strerror(errno));
    }

	return mp;
}

void testpmd_config_ports() {
    struct rte_eth_conf conf = {0};
    uint32_t lid, pid, q;
    rxtx_t rt;
    uint16_t nb_ports;
	int32_t ret, cache_size;
    cache_size = MAX_MBUFS_PER_PORT;

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

        if (rt.rx > 1) {
            conf.rx_adv_conf.rss_conf.rss_key = NULL;
            conf.rx_adv_conf.rss_conf.rss_hf &= info[pid].dev_info.flow_type_rss_offloads;
        } else {
            conf.rx_adv_conf.rss_conf.rss_key = NULL;
            conf.rx_adv_conf.rss_conf.rss_hf  = 0;
        }

        if (conf.rx_adv_conf.rss_conf.rss_hf != 0) {
            conf.rxmode.mq_mode = ETH_MQ_RX_RSS;
        } else {
            conf.rxmode.mq_mode = ETH_MQ_RX_NONE;
        }

        /* Configure # of RX and TX queue for port */
        ret = rte_eth_dev_configure(pid, rt.rx, rt.tx, &conf);
    	if (ret < 0) {
	    	printf("Cannot configure device: err=%d, port=%u\n", ret, pid);
	    }

        for (q = 0; q < rt.rx; q++) {
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
		}

        for (q = 0; q < rt.tx; q++) {
			ret = rte_eth_tx_queue_setup(pid, q, DEFAULT_TX_DESC, SOCKET_ID_ANY, &tx_conf);
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
