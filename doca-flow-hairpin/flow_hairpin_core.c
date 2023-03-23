/*
 * Copyright (c) 2022 NVIDIA CORPORATION & AFFILIATES, ALL RIGHTS RESERVED.
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

#include <string.h>
#include <unistd.h>

#include <rte_byteorder.h>

#include <doca_log.h>
#include <doca_flow.h>

#include "flow_common.h"

DOCA_LOG_REGISTER(FLOW_HAIRPIN);

/*
 * Create DOCA Flow pipe with 5 tuple match that forwards the matched traffic to the other port
 *
 * @port [in]: port of the pipe
 * @port_id [in]: port ID of the pipe
 * @pipe [out]: created pipe pointer
 * @error [out]: output error
 * @return: 0 on success, negative value otherwise and error is set.
 */
int
create_hairpin_pipe(struct doca_flow_port *port, int port_id, struct doca_flow_pipe **pipe, struct doca_flow_error *error)
{
	struct doca_flow_match match;
	struct doca_flow_actions actions, *actions_arr[NB_ACTIONS_ARR];
	struct doca_flow_fwd fwd;
	struct doca_flow_pipe_cfg pipe_cfg = {0};

	memset(&match, 0, sizeof(match));
	memset(&actions, 0, sizeof(actions));
	memset(&fwd, 0, sizeof(fwd));
	memset(&pipe_cfg, 0, sizeof(pipe_cfg));

	pipe_cfg.attr.name = "HAIRPIN_PIPE";
	pipe_cfg.attr.type = DOCA_FLOW_PIPE_BASIC;
	pipe_cfg.match = &match;
	actions_arr[0] = &actions;
	pipe_cfg.actions = actions_arr;
	pipe_cfg.attr.is_root = true;
	pipe_cfg.attr.nb_actions = NB_ACTIONS_ARR;
	pipe_cfg.port = port;

	/* 5 tuple match */
	// match.out_l4_type = DOCA_PROTO_TCP;
	// match.out_src_ip.type = DOCA_FLOW_IP4_ADDR;
	// match.out_src_ip.ipv4_addr = 0xffffffff;
	// match.out_dst_ip.type = DOCA_FLOW_IP4_ADDR;
	// match.out_dst_ip.ipv4_addr = 0xffffffff;
	// match.out_src_port = 0xffff;
	// match.out_dst_port = 0xffff;

	/* forwarding traffic to other port */
	fwd.type = DOCA_FLOW_FWD_PORT;
	fwd.port_id = port_id ^ 1;

	*pipe = doca_flow_pipe_create(&pipe_cfg, &fwd, NULL, error);
	if (*pipe == NULL)
		return -1;
	return 0;
}

/*
 * Add DOCA Flow pipe entry to the hairpin pipe
 *
 * @pipe [in]: pipe of the entry
 * @port [in]: port of the entry
 * @error [out]: output error
 * @return: 0 on success, negative value otherwise and error is set.
 */
int
add_hairpin_pipe_entry(struct doca_flow_pipe *pipe, struct doca_flow_port *port, struct doca_flow_error *error)
{
	struct doca_flow_match match;
	struct doca_flow_actions actions;
	struct doca_flow_pipe_entry *entry;
	int result;
	int num_of_entries = 1;

	memset(&match, 0, sizeof(match));
	memset(&actions, 0, sizeof(actions));

	entry = doca_flow_pipe_add_entry(0, pipe, &match, &actions, NULL, NULL, 0, NULL, error);
	result = doca_flow_entries_process(port, 0, DEFAULT_TIMEOUT_US, num_of_entries);
	if (result != num_of_entries || doca_flow_pipe_entry_get_status(entry) != DOCA_FLOW_ENTRY_STATUS_SUCCESS)
		return -1;

	return 0;
}

/*
 * Run flow_hairpin sample
 *
 * @nb_queues [in]: number of queues the sample will use
 * @return: 0 on success and negative value otherwise.
 */
int
flow_hairpin(int nb_queues)
{
	int nb_ports = 2;
	struct doca_flow_resources resource = {0};
	uint32_t nr_shared_resources[DOCA_FLOW_SHARED_RESOURCE_MAX] = {0};
	struct doca_flow_port *ports[nb_ports];
	struct doca_flow_pipe *pipe;
	struct doca_flow_error error;
	int port_id;
	int result;

	if (init_doca_flow(nb_queues, "vnf,hws", resource, nr_shared_resources, &error) < 0) {
		DOCA_LOG_ERR("Failed to init DOCA Flow - %s (%u)", error.message, error.type);
		return -1;
	}

	if (init_doca_flow_ports(nb_ports, ports, true)) {
		DOCA_LOG_ERR("Failed to init DOCA ports");
		doca_flow_destroy();
		return -1;
	}

	for (port_id = 0; port_id < nb_ports; port_id++) {
		result = create_hairpin_pipe(ports[port_id], port_id, &pipe, &error);
		if (result < 0) {
			DOCA_LOG_ERR("Failed to create pipe - %s (%u)", error.message, error.type);
			destroy_doca_flow_ports(nb_ports, ports);
			doca_flow_destroy();
			return -1;
		}

		result = add_hairpin_pipe_entry(pipe, ports[port_id], &error);
		if (result < 0) {
			DOCA_LOG_ERR("Failed to add entry - %s (%u)", error.message, error.type);
			destroy_doca_flow_ports(nb_ports, ports);
			doca_flow_destroy();
			return -1;
		}
	}

	DOCA_LOG_INFO("Wait few seconds for packets to arrive");
	while (true);

	destroy_doca_flow_ports(nb_ports, ports);
	doca_flow_destroy();
	return 0;
}
