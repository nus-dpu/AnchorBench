#ifndef _SC_PORT_H_
#define _SC_PORT_H_

#include <stdlib.h>

#include <rte_ethdev.h>
#include <rte_version.h>

/*!
 * \brief configurable number of RX/TX ring descriptors
 */
#define RTE_TEST_RX_DESC_DEFAULT 512
#define RTE_TEST_TX_DESC_DEFAULT 512

int init_ports(struct sc_config *sc_config);

#endif