#ifndef _SC_WORKER_H_
#define _SC_WORKER_H_

#include <unistd.h>

#include <rte_launch.h>
#include <rte_mbuf.h>
#include <rte_ethdev.h>

#define SC_MAX_PKT_BURST 512

int init_worker_threads(struct sc_config *sc_config);
int launch_worker_threads(struct sc_config *sc_config);
int launch_worker_threads_async(struct sc_config *sc_config);

#endif