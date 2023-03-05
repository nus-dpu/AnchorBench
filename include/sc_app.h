#ifndef _SC_APP_H_
#define _SC_APP_H_

#include "sc_global.h"

#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_tcp.h>

/* include header file of the application x from apps/sc_x/x.h */
#include APP_HEADER_FILE_PATH

int init_app(struct sc_config *sc_config, const char *app_conf_path);

#endif