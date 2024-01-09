/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020 Mellanox Technologies, Ltd
 *
 * This file contains the items, actions and attributes
 * definition. And the methods to prepare and fill items,
 * actions and attributes to generate rte_flow rule.
 */

#ifndef FLOW_H
#define FLOW_H

#include <stdint.h>
#include <rte_flow.h>

#include "config.h"

/* Actions */
#define HAIRPIN_QUEUE_ACTION FLOW_ACTION_MASK(0)
#define HAIRPIN_RSS_ACTION   FLOW_ACTION_MASK(1)

/* Attributes */
#define INGRESS              FLOW_ATTR_MASK(0)
#define EGRESS               FLOW_ATTR_MASK(1)
#define TRANSFER             FLOW_ATTR_MASK(2)

#endif /* FLOW_H */
