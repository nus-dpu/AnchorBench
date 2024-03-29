/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020 Mellanox Technologies, Ltd
 */
#ifndef CONFIG_H
#define CONFIG_H

#define FLOW_ITEM_MASK(_x) (UINT64_C(1) << _x)
#define FLOW_ACTION_MASK(_x) (UINT64_C(1) << _x)
#define FLOW_ATTR_MASK(_x) (UINT64_C(1) << _x)
#define GET_RSS_HF() (ETH_RSS_IP | ETH_RSS_UDP)

/* Configuration */
#define RXQ_NUM 8
#define TXQ_NUM 8
#define TOTAL_MBUF_NUM 4096
#define DEFAULT_PRIV_SIZE   0
#define MBUF_SIZE (RTE_MBUF_DEFAULT_BUF_SIZE + DEFAULT_PRIV_SIZE)
#define MBUF_CACHE_SIZE 512
#define NR_RXD  256
#define NR_TXD  512

/* This is used for encap/decap & header modify actions.
 * When it's 1: it means all actions have fixed values.
 * When it's 0: it means all actions will have different values.
 */
#define FIXED_VALUES 1

/* Items/Actions parameters */
#define JUMP_ACTION_TABLE 2
#define VLAN_VALUE 1
#define VNI_VALUE 1
#define META_DATA 1
#define TAG_INDEX 0
#define PORT_ID_DST 1
#define TEID_VALUE 1

/* Flow items/acctions max size */
#define MAX_ITEMS_NUM 32
#define MAX_ACTIONS_NUM 32
#define MAX_ATTRS_NUM 16

/* Storage for struct rte_flow_action_rss including external data. */
struct action_rss_data {
	struct rte_flow_action_rss conf;
	uint8_t key[40];
	uint16_t queue[128];
};

#endif  /* CONFIG_H */