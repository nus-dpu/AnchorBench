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

/* user context struct that will be used in entries process callback */
struct entries_status {
	bool failure;	      /* will be set to true if some entry status will not be success */
	int nb_processed;     /* number of entries that was already processed */
	int entries_in_queue; /* number of entries in queue that is waiting to process */
};

DOCA_LOG_REGISTER(FLOW_HAIRPIN);

/*
 * Create DOCA Flow pipe with 5 tuple match that forwards the matched traffic to the other port
 *
 * @port [in]: port of the pipe
 * @port_id [in]: port ID of the pipe
 * @pipe [out]: created pipe pointer
 * @return: 0 on success, negative value otherwise and error is set.
 */
doca_error_t
create_hairpin_pipe(struct doca_flow_port *port, int port_id, struct doca_flow_pipe **pipe)
{
	struct doca_flow_match match;
	struct doca_flow_actions actions, *actions_arr[NB_ACTIONS_ARR];
	struct doca_flow_fwd fwd;
	struct doca_flow_pipe_cfg pipe_cfg = {0};
	doca_error_t result;

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

	/* forwarding traffic to other port */
	fwd.type = DOCA_FLOW_FWD_PORT;
	fwd.port_id = port_id ^ 1;

	result = doca_flow_pipe_create(&pipe_cfg, &fwd, NULL, pipe);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create pipe: %s", doca_get_error_string(result));
		return result;
	}

	return DOCA_SUCCESS;
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
add_hairpin_pipe_entry(struct doca_flow_pipe *pipe, struct doca_flow_port *port)
{
	struct doca_flow_match match;
	struct doca_flow_actions actions;
	struct doca_flow_pipe_entry *entry;
	struct entries_status status = {0};
	doca_error_t result;
	int num_of_entries = 1;

	memset(&match, 0, sizeof(match));
	memset(&actions, 0, sizeof(actions));

	result = doca_flow_pipe_add_entry(0, pipe, &match, &actions, NULL, NULL, DOCA_FLOW_NO_WAIT, &status, &entry);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to add entry in pipe: %s", doca_get_error_string(result));
		return result;
	}

	result = doca_flow_entries_process(port, 0, DEFAULT_TIMEOUT_US, num_of_entries);
	if (result != num_of_entries || doca_flow_pipe_entry_get_status(entry) != DOCA_FLOW_ENTRY_STATUS_SUCCESS) {
		DOCA_LOG_ERR("Failed to add entry in pipe");
		return result;
	}

	return DOCA_SUCCESS;
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
	int port_id;
	doca_error_t result;

	result = init_doca_flow(nb_queues, "vnf,hws", resource, nr_shared_resources);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to init DOCA Flow: %s", doca_get_error_string(result));
		return -1;
	}

	result = init_doca_flow_ports(nb_ports, ports, true);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to init DOCA ports: %s", doca_get_error_string(result));
		doca_flow_destroy();
		return -1;
	}

	for (port_id = 0; port_id < nb_ports; port_id++) {
		result = create_hairpin_pipe(ports[port_id], port_id, &pipe);
		if (result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Failed to create hairpin pipe: %s", doca_get_error_string(result));
			destroy_doca_flow_ports(nb_ports, ports);
			doca_flow_destroy();
			return -1;
		}

		result = add_hairpin_pipe_entry(pipe, ports[port_id]);
		if (result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Failed to add entry to hairpin pipe: %s", doca_get_error_string(result));
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
