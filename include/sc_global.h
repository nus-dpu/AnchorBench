#ifndef _SC_GLOBAL_H_
#define _SC_GLOBAL_H_

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <pthread.h>

#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_version.h>

/* maximum number of parameters to init rte eal */
#define SC_RTE_ARGC_MAX (RTE_MAX_ETHPORTS << 1) + 7

/* maximum number of ports to used */
#define SC_MAX_NB_PORTS RTE_MAX_ETHPORTS

/* maximum number of queues per port */
#define SC_MAX_NB_QUEUE_PER_PORT RTE_MAX_QUEUES_PER_PORT

/* maximum number of lcores to used */
#define SC_MAX_NB_CORES RTE_MAX_LCORE

struct app_config;
struct doca_config;

/* global configuration of SoConnect */
struct sc_config {
    /* dpdk lcore */
    uint32_t core_ids[SC_MAX_NB_CORES];
    uint32_t nb_used_cores;

    /* logging */
    uint32_t log_core_id;
    pthread_t *logging_thread;
    pthread_mutex_t *timer_mutex;

    /* dpdk port */
    char* port_mac[SC_MAX_NB_PORTS];
    uint16_t port_ids[SC_MAX_NB_PORTS];
    uint16_t nb_used_ports;
    uint16_t nb_rx_rings_per_port;
    uint16_t nb_tx_rings_per_port;
    bool enable_promiscuous;

    /* dpdk memory */
    struct rte_mempool *pktmbuf_pool;
    uint16_t nb_memory_channels_per_socket;

    /* app */
    struct app_config *app_config;

    /* per-core metadata */
    void *per_core_meta;

    /* doca specific configurations */
    #if defined(HAS_DOCA)
        void *doca_config;
    #endif
};

/* application specific configuration */
struct app_config {
    /* callback function: operations while entering the worker loop */
    int (*process_enter)(struct sc_config *sc_config);
    /* callback function: processing single received packet (server mode) */
    int (*process_pkt)(struct rte_mbuf *pkt, struct sc_config *sc_config);
    /* callback function: client logic (client mode) */
    int (*process_client)(struct sc_config *sc_config, bool *ready_to_exit);
    /* callback function: operations while exiting the worker loop */
    int (*process_exit)(struct sc_config *sc_config);

    /* internal configuration of the application */
    void *internal_config;
};

#endif // _SC_GLOBAL_H_