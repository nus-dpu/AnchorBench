#ifndef _SC_DOCA_H_
#define _SC_DOCA_H_

#if defined(HAS_DOCA)

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
    /* doca core objects */
    struct doca_dev *doca_dev;			        /* doca device */
    struct doca_mmap *doca_mmap;			    /* doca mmap */
    struct doca_buf_inventory *doca_buf_inv;	/* doca buffer inventory */
    struct doca_ctx *doca_ctx;			        /* doca context */
    struct doca_workq *doca_workq;		        /* doca work queue */

    /* sha configurations */
    #if defined(HAS_DOCA) && defined(NEED_DOCA_SHA)
        char *doca_sha_pci_address;
    #endif // HAS_DOCA && NEED_DOCA_SHA
};
#define DOCA_CONF(scc) ((struct doca_config*)scc->doca_config)

int init_doca(struct sc_config *sc_config, const char *doca_conf_path);

#endif // HAS_DOCA


#endif