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

#include "core.h"
#include "ipc.h"
#include "eth.h"
#include "etharp.h"
#include "netfmt.h"
#include "printk.h"
#include "netif.h"
#include "list.h"

/* Maximum number of packets to be retrieved via burst */
#define MAX_PKT_BURST   512

#define MEMPOOL_CACHE_SIZE  256
#define N_MBUF              8192
#define BUF_SIZE            2048
#define MBUF_SIZE           (BUF_SIZE + sizeof(struct rte_mbuf) + RTE_PKTMBUF_HEADROOM)

#define RTE_TEST_RX_DESC_DEFAULT    4096
#define RTE_TEST_TX_DESC_DEFAULT    4096

/* -------------------------------------------------------------------------- */
/* RX queue configuration */
static struct rte_eth_rxconf rx_conf = {
    .rx_thresh = {
        .pthresh = 8,
        .hthresh = 8,
        .wthresh = 4,
    },
    .rx_free_thresh = 32,
    .rx_deferred_start = 1,
};

/* TX queue configuration */
static struct rte_eth_txconf tx_conf = {
    .tx_thresh = {
        .pthresh = 36,
        .hthresh = 0,
        .wthresh = 0,
    },
    .tx_free_thresh = 0,
    .tx_deferred_start = 1,
};

/* Port configuration */
struct rte_eth_conf port_conf = {
    .rxmode = {
        .mq_mode        = ETH_MQ_RX_NONE,
        .split_hdr_size = 0,
    },
    .txmode = {
        .mq_mode = ETH_MQ_TX_NONE,
        .offloads = (DEV_TX_OFFLOAD_IPV4_CKSUM |
                DEV_TX_OFFLOAD_UDP_CKSUM |
                DEV_TX_OFFLOAD_TCP_CKSUM),
    },
};

/* -------------------------------------------------------------------------- */
struct mbuf_table {
    int len;
    struct rte_mbuf * mtable[MAX_PKT_BURST];
} __rte_cache_aligned;

/* Packet mempool for each core */
struct rte_mempool * pkt_mempools[NR_CPUS];
/* RX mbuf and TX mbuf */
struct mbuf_table rx_mbufs[RTE_MAX_ETHPORTS];
struct mbuf_table tx_mbufs[RTE_MAX_ETHPORTS];

/* -------------------------------------------------------------------------- */
/* Interface in use */
struct list_head in_use_iface_list;

/* -------------------------------------------------------------------------- */
/**
 * print_iface_info - print out interface information
 * * Can be used to print out all probed ifaces or in used ones
 */
static void print_iface_info(struct list_head * list) {
    struct netif * netif;
    list_for_each_entry(netif, list, list) {
        pr_info("\t%8s\t%8s\t%8s\t%15s\t%15s\n \
                \t%8s\t%8s\t%8d\t" ETHER_STRING "\t" IP_STRING "\n", \
                "Interface", "PCI", "Port", "MAC Address", "IP Address",   \
                netif->name, netif->pci_addr, netif->port_id, ETHER_FMT(netif->hwaddr.ether_addr_octet), NET_IP_FMT(netif->ip_addr));
    }
}

static void probe_all_ifaces(void) {
    int port_id;
    struct list_head probed_iface_list;

    init_list_head(&probed_iface_list);

    RTE_ETH_FOREACH_DEV(port_id) {
        struct netif * netif = (struct netif *)malloc(sizeof(struct netif));

        netif->port_id = port_id;

        struct rte_ether_addr eth_addr;
        rte_eth_macaddr_get(port_id, &eth_addr);

        memcpy(&netif->hwaddr, eth_addr.addr_bytes, RTE_ETHER_ADDR_LEN);

        list_add_tail(&netif->list, &probed_iface_list);
    }

    struct ifaddrs * addrs;
    getifaddrs(&addrs);
    for (struct ifaddrs * addr = addrs; addr != NULL; addr = addr->ifa_next) {
        if (addr->ifa_addr && addr->ifa_addr->sa_family == AF_PACKET) {
            struct ifreq if_req;
            strcpy(if_req.ifr_name, addr->ifa_name);

            /* Create Socket */
            int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
            if(sock == -1) {
                pr_err(" socket allocation failed!");
            }

            char eth_addr[ETH_ALEN];
            memset(eth_addr, 0, ETH_ALEN);

            if(ioctl(sock, SIOCGIFHWADDR, &if_req) == 0) {
                /* Get MAC address */
                memcpy(eth_addr, if_req.ifr_addr.sa_data, ETH_ALEN);
            }

            close(sock);

            struct netif * iface, * in_use_iface;
            list_for_each_entry(iface, &probed_iface_list, list) {
                if (!memcmp(&iface->hwaddr, eth_addr, ETH_ALEN)) {
                    /* Found one iface for DPDK device */
                    strcpy(iface->name, addr->ifa_name);
                    /* Check if we are using this device */
                    list_for_each_entry(in_use_iface, &in_use_iface_list, list) {
                        if (!strcmp(in_use_iface->name, iface->name)) {
                            memcpy(&in_use_iface->hwaddr.ether_addr_octet, eth_addr, ETH_ALEN);
                        }
                    }
                }
            }
        }
    }
}

static int parse_nic_config(int rte_argc, char ** rte_argv) {
    FILE * fp;

    /* Init iface in use list */
    init_list_head(&in_use_iface_list);

    fp = fopen("nic.conf", "r");
    if(!fp) {
        pr_err("Failed to open NIC configuration file!\n");
        return -1;
    }

    char fbuff[128];

    char name[16], pci_addr[16], ip_addr[16], ip_mask[16];

    while(1){
        if (fgets(fbuff, 128, fp) == NULL) {
            break;
        }

        if ((strcmp(fbuff, "\n") == 0) || (strncmp(fbuff, "#", 1) == 0)) {
            continue;
        } else if (sscanf(fbuff, "%s\t%s\t%s\t%s\n", name, pci_addr, ip_addr, ip_mask)) {
            struct netif * netif = (struct netif *)calloc(1, sizeof(struct netif));
            memcpy(netif->name, name, strlen(name));
            memcpy(netif->pci_addr, pci_addr, 16);
            netif->ip_addr.addr = inet_addr((const char *)ip_addr);
            netif->netmask.addr = inet_addr((const char *)ip_mask);
            netif->input = ethernet_input;
            netif->output = etharp_output;
            netif->linkoutput = netif_tx_func;
            list_add_tail(&netif->list, &in_use_iface_list);
            rte_argv[rte_argc++] = "-a";
            rte_argv[rte_argc++] = netif->pci_addr;
        }
    }

    print_iface_info(&in_use_iface_list);

    return rte_argc;
}

/**
 * probe_avail_ifaces - probe all available interfaces and append them to list
 */
static void probe_avail_ifaces(void) {
    probe_all_ifaces();
    print_iface_info(&in_use_iface_list);
    return;
}

enum layer_name {
	L2,
	L3,
	L4,
	END
};

int dpdk_create_flow(struct flow * fl, uint16_t port, uint16_t * queues, int nr_queues) {
    int port_id;
    struct rte_flow_error error;
	struct rte_flow_attr attr = { /* Holds the flow attributes. */
				.group = 0, /* set the rule on the main group. */
				.ingress = 1,/* Rx flow. */
				.priority = 0, }; /* add priority to rule
				to give the Decap rule higher priority since
				it is more specific than RSS */

    struct rte_flow_item pattern[] = {
        [L2] = { /* ETH type is set since we always start from ETH. */
            .type = RTE_FLOW_ITEM_TYPE_ETH,
            .spec = NULL,
            .mask = NULL,
            .last = NULL },
        [L3] = { /* ETH type is set since we always start from ETH. */
            .type = RTE_FLOW_ITEM_TYPE_ETH,
            .spec = NULL,
            .mask = NULL,
            .last = NULL },
        [L4] = { /* ETH type is set since we always start from ETH. */
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

    struct rte_flow_action_rss rss = {
        .level = 0, /* RSS should be done on inner header. */
        .queue = queues, /* Set the selected target queues. */
        .queue_num = nr_queues, /* The number of queues. */
        .types = ETH_RSS_IP | ETH_RSS_UDP
    };

    struct rte_flow_action actions[] = {
        [0] = {
            .type = RTE_FLOW_ACTION_TYPE_RSS,
            .conf = &rss,
        },
        [1] = {
            .type = RTE_FLOW_ACTION_TYPE_END,
        },
    };

    struct rte_flow * flow = NULL;

    struct rte_flow_item_udp udp_spec = {
        .hdr = {
        .dst_port = RTE_BE16(port)}
    };
    struct rte_flow_item_udp udp_mask = {
        .hdr = {
        .dst_port = RTE_BE16(0xFFFF)}
    };

    pattern[L2].type = RTE_FLOW_ITEM_TYPE_ETH;
	pattern[L2].spec = NULL;

	pattern[L2].type = RTE_FLOW_ITEM_TYPE_IPV4;
	pattern[L3].spec = NULL;
	pattern[L3].mask = NULL;

	pattern[L4].type = RTE_FLOW_ITEM_TYPE_UDP;
	pattern[L4].spec = &udp_spec;
	pattern[L4].mask = &udp_mask;

	pattern[END].type = RTE_FLOW_ITEM_TYPE_END;
    RTE_ETH_FOREACH_DEV(port_id) {
        flow = rte_flow_create(port_id, &attr, pattern, actions, &error);
        if (!flow) {
            printf("Can't create hairpin flows on port: %u\n", port_id);
        }
    }

	return 0;
}

/**
 * mempool_init - init packet mempool on each port for RX/TX queue
 */
static int mempool_init(void) {
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

    /* Associate the first RX/TX to the first packet mempool (both used by control plane) */
    uint16_t port_id = 0;
    RTE_ETH_FOREACH_DEV(port_id) {
        for (int i = 0; i < MAX_PKT_BURST; i++) {
            /* Allocate RX packet buffer in DPDK context memory pool */
            rx_mbufs[port_id].mtable[i] = rte_pktmbuf_alloc(pkt_mempools[0]);
            assert(rx_mbufs[port_id].mtable[i] != NULL);
        }

        rx_mbufs[port_id].len = 0;

        for (int i = 0; i < MAX_PKT_BURST; i++) {
            /* Allocate TX packet buffer in DPDK context memory pool */
            tx_mbufs[port_id].mtable[i] = rte_pktmbuf_alloc(pkt_mempools[0]);
            assert(tx_mbufs[port_id].mtable[i] != NULL);
        }

        tx_mbufs[port_id].len = 0;
    }

    return 0;
}

/**
 * queue_init - init RX/TX queue for each interface
 */
static int queue_init(void) {
    int ret;

    struct netif * netif;
    list_for_each_entry(netif, &in_use_iface_list, list) {
        int port_id = netif->port_id;

        /* Get Ethernet device info */
        struct rte_eth_dev_info dev_info;
        ret = rte_eth_dev_info_get(port_id, &dev_info);
	    if (ret != 0) {
            pr_emerg("Error during getting device (port %u) info: %s\n", port_id, strerror(-ret));
        }

        int nb_rx_queue, nb_tx_queue;
        nb_rx_queue = nb_tx_queue = NR_CPUS;

        /* Configure # of RX and TX queue for port */
        ret = rte_eth_dev_configure(port_id, nb_rx_queue, nb_tx_queue, &port_conf);
    	if (ret < 0) {
	    	pr_emerg("cannot configure device: err=%d, port=%u\n", ret, port_id);
	    }

        /* Set up rx queue with pakcet mempool */
        for (int i = 0; i < nb_rx_queue; i++) {
	    	ret = rte_eth_rx_queue_setup(port_id, i, RTE_TEST_RX_DESC_DEFAULT,
                        rte_eth_dev_socket_id(port_id),
                        &rx_conf,
                        pkt_mempools[i]);
    		if (ret < 0) {
	    		pr_emerg("Rx queue setup failed: err=%d, port=%u\n", ret, port_id);
		    }
	    }

        /* Set up tx queue with pakcet mempool */
    	for (int i = 0;i < nb_tx_queue;i++) {
	    	ret = rte_eth_tx_queue_setup(port_id, i, RTE_TEST_TX_DESC_DEFAULT,
		    		rte_eth_dev_socket_id(port_id),
			    	&tx_conf);
    		if (ret < 0) {
	    		pr_emerg("Tx queue setup failed: err=%d, port=%u\n", ret, port_id);
		    }
	    }

        pr_info("Port %d has %d RX queue and %d TX queue\n", port_id, nb_rx_queue, nb_tx_queue);

        ret = rte_eth_promiscuous_enable(port_id);
        if (ret != 0) {
            pr_emerg("rte_eth_promiscuous_enable:err = %d, port = %u\n", ret, (unsigned) port_id);
        }

        /* Start Ethernet device */
        ret = rte_eth_dev_start(port_id);
        if (ret < 0) {
            pr_emerg("rte_eth_dev_start:err = %d, port = %u\n", ret, (unsigned) port_id);
        }
    }

    return 0;
}


static void free_pkts(struct rte_mbuf ** pkts, int pkt_cnt) {
    for (int i = 0; i < pkt_cnt; i++) {
        rte_pktmbuf_free(pkts[i]);
        RTE_MBUF_PREFETCH_TO_FREE(pkts[i+1]);
    }
}

uint8_t * dpdk_get_rxpkt(int port_id, int index, uint16_t * pkt_size) {
    struct rte_mbuf * rx_pkt = rx_mbufs[port_id].mtable[index];
    *pkt_size = rx_pkt->pkt_len;
    return rte_pktmbuf_mtod(rx_pkt, uint8_t *);
}

uint32_t dpdk_recv_pkts(int port_id) {
    if (rx_mbufs[port_id].len != 0) {
        free_pkts(rx_mbufs[port_id].mtable, rx_mbufs[port_id].len);
        rx_mbufs[port_id].len = 0;
    }

    int ret = rte_eth_rx_burst((uint8_t)port_id, cpu_id, rx_mbufs[port_id].mtable, MAX_PKT_BURST);
    rx_mbufs[port_id].len = ret;

    return ret;
}

struct rte_mbuf * dpdk_get_txpkt(int port_id, int pkt_size) {
    if (unlikely(tx_mbufs[port_id].len == MAX_PKT_BURST)) {
        return NULL;
    }

    int next_pkt = tx_mbufs[port_id].len;
    struct rte_mbuf * tx_pkt = tx_mbufs[port_id].mtable[next_pkt];

    tx_pkt->pkt_len = tx_pkt->data_len = pkt_size;
    tx_pkt->nb_segs = 1;
    tx_pkt->next = NULL;
    
    tx_mbufs[port_id].len++;

    return tx_pkt;
}

uint32_t dpdk_send_pkts(int port_id) {
    int total_pkt, pkt_cnt;
    total_pkt = pkt_cnt = tx_mbufs[port_id].len;

    struct rte_mbuf ** pkts = tx_mbufs[port_id].mtable;

    if (pkt_cnt > 0) {
        int ret;
        do {
            /* Send packets until there is none in TX queue */
            ret = rte_eth_tx_burst(port_id, cpu_id, pkts, pkt_cnt);
            pkts += ret;
            pkt_cnt -= ret;
        } while (pkt_cnt > 0);

        /* Allocate new packet memory buffer for TX queue (WHY NEED NEW BUFFER??) */
        for (int i = 0; i < tx_mbufs[port_id].len; i++) {
            /* Allocate new buffer for sended packets */
            tx_mbufs[port_id].mtable[i] = rte_pktmbuf_alloc(pkt_mempools[cpu_id]);
            if (unlikely(tx_mbufs[port_id].mtable[i] == NULL)) {
                rte_exit(EXIT_FAILURE, "Failed to allocate %d:wmbuf[%d] on device %d!\n", cpu_id, i, port_id);
            }
        }

        tx_mbufs[port_id].len = 0;
    }

    return total_pkt;
}

int __init dpdk_init(void) {
    int ret;
    int argc = 6;
    char * argv[16] = { "",
                        "-c", "0x1",
                        "-n", "4",
                        "--proc-type=auto"};

    /* Parse NIC configuration file */
    argc = parse_nic_config(argc, argv);

    if (argc < 0) {
        pr_emerg("failed to parse NIC configuration file!\n");
        return -1;
    }

    if ((ret = rte_eal_init(argc, argv)) < 0) {
        pr_emerg("rte_eal_init() failed! ret: %d\n", ret);
        return -1;
    }

    /* Probe available iface and get iface info */
    probe_avail_ifaces();

    /* Init packet mempool and mbuf for each core */
    mempool_init();

    /* Init queue for each core */
    queue_init();

    return 0;
}