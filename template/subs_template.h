#ifndef _SUBS_TEMPLATE_H_
#define _SUBS_TEMPLATE_H_

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

#include <offload_rules.h>

#ifdef __cplusplus
extern "C" {
#endif

/* subs_template running mode */
enum subs_template_running_mode {
    /* Invalid mode */
	SUBS_TEMPLATE_MODE_INVALID = 0,
    /* Static running mode, need to provide the app a rules file */
	SUBS_TEMPLATE_MODE_STATIC,
    /* Interactive running mode, adding rules in runtime from the command line */	
	SUBS_TEMPLATE_MODE_INTERACTIVE,
    /* Running dpdk worker threads */
	SUBS_TEMPLATE_MODE_DPDK_WORKER,
};

struct subs_template_cfg {
    /* Application running mode */
    enum subs_template_running_mode mode;
    /* App DPDK configuration struct */
    struct application_dpdk_config *dpdk_cfg;
    /* RegEx PCI address to use */
    struct doca_pci_bdf pci_address;
    /* DOCA device */
    struct doca_dev *dev;
    /* DOCA RegEx interface */
	struct doca_regex *doca_reg;
};

struct subs_template_worker_ctx {
    /* DPDK Queue ID */
    int queue_id;
    /* App config struct */              
    struct subs_template_cfg *app_cfg;
    /* DOCA work queue */
    struct doca_workq *workq;						
};

doca_error_t register_subs_template_params();

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif