#ifndef _SC_COMPILE_DEBUG_H_
#define _SC_COMPILE_DEBUG_H_

#include <rte_version.h>

#include "sc_utils.h"

/* print dpdk version while compiling */
#pragma message "DPDK Version: " \
    XSTR(RTE_VER_YEAR) "." XSTR(RTE_VER_MONTH) "." XSTR(RTE_VER_MINOR) "." XSTR(RTE_VER_RELEASE)

#if defined(SC_HAS_DOCA)
    /* print doca version while compiling */
    #pragma message "DOCA Version: " \
        XSTR(SC_DOCA_MAIN_VERSION) "." XSTR(SC_DOCA_SUB_VERSION)
#endif

#endif
