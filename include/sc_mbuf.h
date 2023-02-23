#ifndef _SC_MBUF_H_
#define _SC_MBUF_H_

#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_mbuf_core.h>

#define NUM_MBUFS 8191
#define MEMPOOL_CACHE_SIZE 256

int init_memory(struct sc_config *sc_config);

#endif