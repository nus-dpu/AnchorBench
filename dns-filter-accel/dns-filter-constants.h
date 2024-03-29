#ifndef _DNS_FILTER_CONSTANTS_H_
#define _DNS_FILTER_CONSTANTS_H_

#include <rte_mbuf.h>
#include <rte_mempool.h>

enum {
	DEFAULT_RX_PKT_BURST	= 32,	/* Increasing this number consumes memory very fast */
	DEFAULT_PKT_BURST		= 64,	/* Increasing this number consumes memory very fast */
	DEFAULT_RX_DESC         = (DEFAULT_PKT_BURST * 8 * 2),
	DEFAULT_TX_DESC         = DEFAULT_RX_DESC * 2,

	MAX_MBUFS_PER_PORT      = (DEFAULT_TX_DESC * 8),/* number of buffers to support per port */
	MAX_SPECIAL_MBUFS       = 64,
	MBUF_CACHE_SIZE         = (MAX_MBUFS_PER_PORT / 8),

	DEFAULT_PRIV_SIZE       = 0,
	MBUF_SIZE		= RTE_MBUF_DEFAULT_BUF_SIZE + DEFAULT_PRIV_SIZE, /* See: http://dpdk.org/dev/patchwork/patch/4479/ */

	NUM_Q                   = 16,
	MEMPOOL_NR_BUF			= 128,
 	MEMPOOL_BUF_SIZE		= 256,
};

#endif  /* _DNS_FILTER_CONSTANTS_H_ */