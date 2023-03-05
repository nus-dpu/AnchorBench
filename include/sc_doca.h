#ifndef _SC_DOCA_H_
#define _SC_DOCA_H_

#include "sc_global.h"
#include "sc_doca_utils.h"

#if defined(SC_HAS_DOCA)

/* macro to compute a version number usable for comparisons */
#define SC_DOCA_VERSION_NUM(a,b) ((a) << 8 | (b))
#define SC_DOCA_VERSION \
    SC_DOCA_VERSION_NUM(SC_DOCA_MAIN_VERSION, SC_DOCA_SUB_VERSION)

#include <doca_argp.h>
#include <doca_error.h>
#include <doca_dev.h>
#include <doca_sha.h>
#include <doca_log.h>
#include <doca_buf.h>

#include "sc_global.h"
#include "sc_utils.h"
#include "sc_log.h"

/* 
 * doca specific configuration 
 * NOTE: we seperete doca_config apart from sc_config to make
 *       the integration of future version of DOCA easier
 */
struct doca_config {
    /* scalable functions */
    char* scalable_functions[SC_MAX_NB_PORTS];
    uint16_t nb_used_sfs;

    /* sha configurations */
    #if defined(SC_NEED_DOCA_SHA)
        struct doca_pci_bdf sha_pci_bdf;        /* pci bus-device-function index of sha engine */
        struct doca_mmap *sha_mmap;             /* memory map for sha engine */
        struct doca_dev *sha_dev;		        /* doca device of sha engine */
        struct doca_buf_inventory *sha_buf_inv; /* buffer inventory for sha engine */
        struct doca_ctx *sha_ctx;			    /* doca context for sha engine */
        struct doca_workq *sha_workq;           /* work queue for sha engine */
    #endif // SC_HAS_DOCA && SC_NEED_DOCA_SHA
};
#define DOCA_CONF(scc) ((struct doca_config*)scc->doca_config)

int init_doca(struct sc_config *sc_config, const char *doca_conf_path);

#endif // SC_HAS_DOCA


#endif