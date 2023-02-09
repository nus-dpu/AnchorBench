#ifndef _CM_SKETCH_H_
#define _CM_SKETCH_H_

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

#ifdef GPU_SUPPORT
#include <cuda_runtime.h>
#endif

#include <doca_buf.h>
#include <doca_buf_inventory.h>
#include <doca_ctx.h>
#include <doca_dev.h>
#include <doca_flow.h>
#include <doca_regex.h>

#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_tcp.h>
#include <rte_spinlock.h>

#include <offload_rules.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NB_ROWS 64
#define NB_COUNTER 8196

/* cm_sketch running mode */
enum cm_sketch_running_mode {
    /* Invalid mode */
	CM_SKETCH_MODE_INVALID = 0,
    /* Static running mode, need to provide the app a rules file */
	CM_SKETCH_MODE_STATIC,
    /* Interactive running mode, adding rules in runtime from the command line */	
	CM_SKETCH_MODE_INTERACTIVE,
    /* Running dpdk worker threads */
	CM_SKETCH_MODE_DPDK_WORKER,
};

struct pairwise_hash{
    uint64_t a;
    uint64_t b;
};

struct cm_sketch_cfg {
    /* Application running mode */
    enum cm_sketch_running_mode mode;
    /* App DPDK configuration struct */
    struct application_dpdk_config *dpdk_cfg;
    /* DOCA ports */
    struct doca_flow_port **ports;
    /* Count-min sketch structure */
    uint64_t **cm_sketch;
    /* Spin lock of the count-min sketch structure */
    rte_spinlock_t cm_sketch_lock;
    /* Pair-wise hash function family */
    struct pairwise_hash **pairwise_hash_family;
    /* The prime used by the pairwise hash family */
    uint64_t prime;
};

struct cm_sketch_worker_ctx {
    /* DPDK Queue ID */
    int queue_id;
    /* App config struct */              
    struct cm_sketch_cfg *app_cfg;
    /* DOCA work queue */
    struct doca_workq *workq;						
};

doca_error_t register_cm_sketch_params();

uint64_t rand64(void);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif