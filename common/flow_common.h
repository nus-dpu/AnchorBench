/*
 * Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES, ALL RIGHTS RESERVED.
 *
 * This software product is a proprietary product of NVIDIA CORPORATION &
 * AFFILIATES (the "Company") and all right, title, and interest in and to the
 * software product, including all associated intellectual property rights, are
 * and shall remain exclusively with the Company.
 *
 * This software product is governed by the End User License Agreement
 * provided with the software product.
 *
 */

#ifndef FLOW_COMMON_H_
#define FLOW_COMMON_H_

#include <arpa/inet.h>

#include <doca_flow.h>

#ifdef __cplusplus
extern "C" {
#endif

#define QUEUE_DEPTH (512)	   /* DOCA Flow queue depth */
#define SECURED_IDX (0)		   /* Index for secured network port in ports array */
#define UNSECURED_IDX (1)	   /* Index for unsecured network port in ports array */
#define DEFAULT_TIMEOUT_US (10000) /* default timeout for processing entries */
#define SET_L4_PORT(layer, port, value) \
	do { \
		if (match.layer.l4_type_ext == DOCA_FLOW_L4_TYPE_EXT_TCP) \
			match.layer.tcp.l4_port.port = (value); \
		else if (match.layer.l4_type_ext == DOCA_FLOW_L4_TYPE_EXT_UDP) \
			match.layer.udp.l4_port.port = (value); \
	} while (0) /* Set match l4 port */

#define SET_IP6_ADDR(addr, a, b, c, d) \
	do { \
		addr[0] = a; \
		addr[1] = b; \
		addr[2] = c; \
		addr[3] = d; \
	} while (0)

/* user context struct that will be used in entries process callback */
struct entries_status {
	bool failure;	      /* will be set to true if some entry status will not be success */
	int nb_processed;     /* number of entries that was already processed */
	int entries_in_queue; /* number of entries in queue that is waiting to process */
};

/*
 * Process the added entries and check the status
 *
 * @port [in]: DOCA Flow port
 * @status [in]: the entries status struct that monitor the entries in this specific port
 * @timeout [in]: timeout for process entries
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
doca_error_t process_entries(struct doca_flow_port *port, struct entries_status *status, int timeout);

/*
 * Create empty pipe in order the packets will get to rss pipe
 *
 * @pipe [out]: the created pipe
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
doca_error_t create_empty_pipe(struct doca_flow_pipe **pipe);

/*
 * Remove trailing zeros from ipv4/ipv6 payload.
 * Trailing zeros are added to ipv4/ipv6 payload so that it's larger than the minimal ethernet frame size.
 *
 * @m [in]: the mbuf to update
 */
void remove_trailing_zeros(struct rte_mbuf **m);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* FLOW_COMMON_H_ */