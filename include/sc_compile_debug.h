#ifndef _SC_COMPILE_DEBUG_H_
#define _SC_COMPILE_DEBUG_H_

#include <rte_version.h>

#include "sc_utils.h"

/* print rte version while compiling */
#pragma message "RTE Version: " \
    XSTR(RTE_VER_YEAR) "." XSTR(RTE_VER_MONTH) "." XSTR(RTE_VER_MINOR) "." XSTR(RTE_VER_RELEASE)

#endif
