#ifndef _DNS_FILTER_H_
#define _DNS_FILTER_H_

#include <rte_version.h>
#include <rte_config.h>

#include <rte_errno.h>
#include <rte_log.h>
#include <rte_tailq.h>
#include <rte_common.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_memzone.h>
#include <rte_malloc.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_pci.h>
#include <rte_random.h>
#include <rte_timer.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_tcp.h>

extern __thread int nb_enqueued;
extern __thread int nb_dequeued;

#define NR_CPUS	8
extern struct rte_mempool * pkt_mempools[NR_CPUS];

struct rte_mbuf * dpdk_get_txpkt(int port_id, int pkt_size);

#endif  /* _DNS_FILTER_H_*/