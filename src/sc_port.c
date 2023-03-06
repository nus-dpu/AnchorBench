#include "sc_global.h"
#include "sc_utils.h"
#include "sc_port.h"

int _init_single_port(uint16_t port_index, struct sc_config *sc_config);
static bool _is_port_choosed(uint16_t port_index, struct sc_config *sc_config);
static void _print_port_info(uint16_t port_index);
static void _show_offloads(uint64_t offloads, const char *(show_offload)(uint64_t));

/*!
 * \brief dpdk ethernet port configuration
 */
static struct rte_eth_conf port_conf_default = {
    #if RTE_VERSION >= RTE_VERSION_NUM(20, 11, 255, 255)
        .rxmode = {
            .mq_mode = RTE_ETH_MQ_RX_RSS,
        },
        .txmode = {
            .mq_mode = RTE_ETH_MQ_TX_NONE,
        },
    #else
        .rxmode = {
            .mq_mode = ETH_MQ_RX_RSS,
        },
        .txmode = {
            .mq_mode = ETH_MQ_TX_NONE,
        },
    #endif
};

/*!
 * \brief   initialize all available dpdk port
 * \param   sc_config   the global configuration
 * \return  zero for successfully initialization
 */
int init_ports(struct sc_config *sc_config){
    uint16_t i, port_index, nb_ports;
    
    /* check available ports */
    nb_ports = rte_eth_dev_count_avail();
    if(nb_ports == 0)
        rte_exit(EXIT_FAILURE, "No Ethernet ports\n");
    
    for(i=0, port_index=0; port_index<nb_ports; port_index++){
        /* skip the port if it's unused */
        if (!rte_eth_dev_is_valid_port(port_index)){
            printf("port %d is not valid\n", port_index);
            continue;
        }

        /* skip the port if not specified in the configuratio file */
        if(!_is_port_choosed(port_index, sc_config))
            continue;

        /* print detail info of the port */
        _print_port_info(port_index);

        /* initialize the current port */
        if(_init_single_port(port_index, sc_config) != SC_SUCCESS){
            printf("failed to initailize port %d\n", port_index);
            return SC_ERROR_INTERNAL;
        }

        sc_config->port_ids[i] = port_index; 
        i++;
    }

    sc_config->nb_used_ports = i;
    return SC_SUCCESS;
}

/*!
 * \brief   initialize a specified port
 * \param   port_index  the index of the init port
 * \param   sc_config   the global configuration
 * \return  zero for successfully initialization
 */
int _init_single_port(uint16_t port_index, struct sc_config *sc_config){
    int ret;
    uint16_t i;
    struct rte_eth_conf port_conf = port_conf_default;
	struct rte_ether_addr eth_addr;

    /* obtain mac address of the port */
    ret = rte_eth_macaddr_get(port_index, &eth_addr);
    if (ret < 0) {
        printf("failed to obtain mac address of port %d: %s\n", 
            port_index, rte_strerror(-ret));
        return SC_ERROR_INTERNAL;
    }

    /* configure the port */
    ret = rte_eth_dev_configure(
        port_index, sc_config->nb_rx_rings_per_port, 
        sc_config->nb_tx_rings_per_port, &port_conf);
	if (ret != 0) {
        printf("failed to configure port %d: %s\n",
            port_index, rte_strerror(-ret));
        return SC_ERROR_INTERNAL;
    }

    /* allocate rx_rings */
    for (i = 0; i < sc_config->nb_rx_rings_per_port; i++) {
        ret = rte_eth_rx_queue_setup(
            port_index, i, RTE_TEST_RX_DESC_DEFAULT,
			rte_eth_dev_socket_id(port_index), NULL, 
            sc_config->pktmbuf_pool);
		if (ret < 0) {
            printf("failed to setup rx_ring %d for port %d: %s\n", 
                i, port_index, rte_strerror(-ret));
            return SC_ERROR_INTERNAL;
        }
    }

    /* allocate tx_rings */
    for (i = 0; i < sc_config->nb_tx_rings_per_port; i++) {
        ret = rte_eth_tx_queue_setup(
            port_index, i, RTE_TEST_TX_DESC_DEFAULT,
			rte_eth_dev_socket_id(port_index), NULL);
		if (ret < 0) {
            printf("failed to setup tx_ring %d for port %d: %s\n", 
                i, port_index, rte_strerror(-ret));
            return SC_ERROR_INTERNAL;
        }
    }

    /* start the port */
    ret = rte_eth_dev_start(port_index);
	if (ret < 0) {
        printf("failed to start port %d: %s\n", 
            port_index, rte_strerror(-ret));
        return SC_ERROR_INTERNAL;
    }

    /* set as promiscuous mode (if enabled) */
    if(sc_config->enable_promiscuous){
		ret = rte_eth_promiscuous_enable(port_index);
		if (ret != 0) {
            printf("failed to set port %d as promiscuous mode: %s\n", 
                port_index, rte_strerror(-ret));
            return SC_ERROR_INTERNAL;
        }
	}

    /* print finish message */
    #if RTE_VERSION >= RTE_VERSION_NUM(20, 11, 255, 255)
        printf("finish init port %u, MAC address: " RTE_ETHER_ADDR_PRT_FMT "\n\n",
            port_index,
            RTE_ETHER_ADDR_BYTES(&eth_addr));
    #else
        printf("finish init port %u\n\n", port_index);
    #endif // RTE_VERSION >= RTE_VERSION_NUM(20, 11, 255, 255)
        
    return SC_SUCCESS;
}

/*!
 * \brief   check whether the port is going to be used 
 *          (defined in the configuration file)
 * \param   port_index  the index of the checked port
 * \param   sc_config   the global configuration
 * \return  whether the port is used
 */
static bool _is_port_choosed(uint16_t port_index, struct sc_config *sc_config){
    int i, ret;
    struct rte_ether_addr mac;
    char ebuf[RTE_ETHER_ADDR_FMT_SIZE];

    ret = rte_eth_macaddr_get(port_index, &mac);
    if (ret == 0)
        rte_ether_format_addr(ebuf, sizeof(ebuf), &mac);
    else
        return false;

    for(i=0; i<sc_config->nb_conf_ports; i++){
        if(sc_config->port_mac[i] == NULL) continue;
        if(!strcmp(ebuf, sc_config->port_mac[i])) return true;
    }

    return false;
}

/*!
 * \brief print detail port information based on given port index
 * \param port_index    index of the specified port
 */
static void _print_port_info(uint16_t port_index){
    int k, ret;
    uint16_t queue_index, mtu;
    uint32_t used_desp;
    struct rte_eth_link link;
    struct rte_eth_dev_info dev_info;
    struct rte_eth_rxq_info rx_queue_info;
    struct rte_eth_txq_info tx_queue_info;
    struct rte_eth_dev_owner owner;
    struct rte_ether_addr mac;
    struct rte_eth_rss_conf rss_conf;
    char link_status_text[RTE_ETH_LINK_MAX_STR_LEN];

    #if RTE_VERSION >= RTE_VERSION_NUM(20, 11, 255, 255)
        struct rte_eth_fc_conf fc_conf;
    #endif // RTE_VERSION >= RTE_VERSION_NUM(20, 11, 255, 255)

    printf("\nUSED PORTs:\n");
    
    /* get device info */
    ret = rte_eth_dev_info_get(port_index, &dev_info);
    if (ret != 0) {
        printf("Error during getting device info: %s\n", 
            strerror(-ret));
        return;
    }

    /* print dev_info */
    printf("\t  -- driver %s device %s socket %d\n",
            dev_info.driver_name, dev_info.device->name,
            rte_eth_dev_socket_id(port_index));

    /* print dev_owner */
    ret = rte_eth_dev_owner_get(port_index, &owner);
    if (ret == 0 && owner.id != RTE_ETH_DEV_NO_OWNER)
        printf("\t --  owner %#"PRIx64":%s\n",
                owner.id, owner.name);

    /* print link */
    ret = rte_eth_link_get(port_index, &link);
    if (ret < 0) {
        printf("Link get failed (port %u): %s\n",
                port_index, rte_strerror(-ret));
    } else {
        rte_eth_link_to_str(link_status_text,
                sizeof(link_status_text),
                &link);
        printf("\t%s\n", link_status_text);
    }

    /* print flow control */
    #if RTE_VERSION >= RTE_VERSION_NUM(20, 11, 255, 255)
        ret = rte_eth_dev_flow_ctrl_get(port_index, &fc_conf);
        if (ret == 0 && fc_conf.mode != RTE_ETH_FC_NONE)  {
            printf("\t  -- flow control mode %s%s high %u low %u pause %u%s%s\n",
                fc_conf.mode == RTE_ETH_FC_RX_PAUSE ? "rx " :
                fc_conf.mode == RTE_ETH_FC_TX_PAUSE ? "tx " :
                fc_conf.mode == RTE_ETH_FC_FULL ? "full" : "???",
                fc_conf.autoneg ? " auto" : "",
                fc_conf.high_water,
                fc_conf.low_water,
                fc_conf.pause_time,
                fc_conf.send_xon ? " xon" : "",
                fc_conf.mac_ctrl_frame_fwd ? " mac_ctrl" : "");
        }
    #endif // RTE_VERSION >= RTE_VERSION_NUM(20, 11, 255, 255)

    /* print mac address */
    ret = rte_eth_macaddr_get(port_index, &mac);
    if (ret == 0) {
        char ebuf[RTE_ETHER_ADDR_FMT_SIZE];

        rte_ether_format_addr(ebuf, sizeof(ebuf), &mac);
        printf("\t  -- mac %s\n", ebuf);
    }

    /* print whether the port is set as promiscuous mode */
    ret = rte_eth_promiscuous_get(port_index);
    if (ret >= 0)
        printf("\t  -- promiscuous mode %s\n",
                ret > 0 ? "enabled" : "disabled");

    /* print whether the port is set as multicast mode */
    ret = rte_eth_allmulticast_get(port_index);
    if (ret >= 0)
        printf("\t  -- all multicast mode %s\n",
                ret > 0 ? "enabled" : "disabled");

    /* print mtu */
    ret = rte_eth_dev_get_mtu(port_index, &mtu);
		if (ret == 0)
			printf("\t  -- mtu (%d)\n", mtu);

    /* print rx_queue info */
    for (queue_index = 0; queue_index < dev_info.nb_rx_queues; queue_index++) {
        ret = rte_eth_rx_queue_info_get(port_index, queue_index, &rx_queue_info);
        if (ret != 0)
            break;

        if (queue_index == 0)
            printf("  - rx queue\n");

        printf("\t  -- %d descriptors ", queue_index);
        used_desp = rte_eth_rx_queue_count(port_index, queue_index);
        if (used_desp >= 0)
            printf("%d/", used_desp);
        printf("%u", rx_queue_info.nb_desc);

        if (rx_queue_info.scattered_rx)
            printf(" scattered");

        if (rx_queue_info.conf.rx_drop_en)
            printf(" drop_en");

        if (rx_queue_info.conf.rx_deferred_start)
            printf(" deferred_start");

        if (rx_queue_info.rx_buf_size != 0)
            printf(" rx buffer size %u",
                    rx_queue_info.rx_buf_size);

        printf(" mempool %s socket %d",
                rx_queue_info.mp->name,
                rx_queue_info.mp->socket_id);

        if (rx_queue_info.conf.offloads != 0)
            _show_offloads(rx_queue_info.conf.offloads, rte_eth_dev_rx_offload_name);

        printf("\n");
    }

    /* print tx_queue info */
    for (queue_index = 0; queue_index < dev_info.nb_tx_queues; queue_index++) {
        ret = rte_eth_tx_queue_info_get(port_index, queue_index, &tx_queue_info);
        if (ret != 0)
            break;
        if (queue_index == 0)
            printf("  - tx queue\n");

        printf("\t  -- %d descriptors %d",
                queue_index, tx_queue_info.nb_desc);

        printf(" thresh %u/%u",
                tx_queue_info.conf.tx_rs_thresh,
                tx_queue_info.conf.tx_free_thresh);

        if (tx_queue_info.conf.tx_deferred_start)
            printf(" deferred_start");

        if (tx_queue_info.conf.offloads != 0)
            _show_offloads(tx_queue_info.conf.offloads, rte_eth_dev_tx_offload_name);
        printf("\n");
    }

    /* print rss info */
    ret = rte_eth_dev_rss_hash_conf_get(port_index, &rss_conf);
    if (ret == 0) {
        if (rss_conf.rss_key) {
            printf("\t  -- RSS len %u key (hex):",
                    rss_conf.rss_key_len);
            for (k = 0; k < rss_conf.rss_key_len; k++)
                printf(" %x", rss_conf.rss_key[k]);
            printf("\t  -- hf 0x%"PRIx64"\n",
                    rss_conf.rss_hf);
        }
    }

    printf("\n");
}

/*!
 * \brief parse and print all offloading flags
 * \param offloads      offloading flag
 * \param show_offload  callback function for printing the meaning of offloading flags
 */
static void _show_offloads(uint64_t offloads, const char *(show_offload)(uint64_t)){
	printf(" offloads :");
	while (offloads != 0) {
		uint64_t offload_flag = 1ULL << __builtin_ctzll(offloads);
		printf(" %s", show_offload(offload_flag));
		offloads &= ~offload_flag;
	}
}