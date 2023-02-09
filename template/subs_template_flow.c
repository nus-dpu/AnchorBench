#include <rte_ethdev.h>

#include <doca_log.h>

#include "flow_pipes_manager.h"
#include "offload_rules.h"

#include "subs_template.h"

DOCA_LOG_REGISTER(SUBS_TEMPLATE::FLOW);

#define MAX_PORT_STR_LEN 128	   	/* Maximal length of doca port name */
#define DEFAULT_TIMEOUT_US (10000) 	/* Timeout for processing pipe entries */

static struct flow_pipes_manager *pipes_manager;

/*
 * Create DOCA Flow pipe
 *
 * @cfg [in]: DOCA Flow pipe configuration
 * @port_id [in]: Not being used
 * @fwd [in]: DOCA Flow forward
 * @fw_pipe_id [in]: Pipe ID to forward
 * @fwd_miss [in]: DOCA Flow forward miss
 * @fw_miss_pipe_id [in]: Pipe ID to forward miss
 */
static void pipe_create(struct doca_flow_pipe_cfg *cfg, uint16_t port_id, struct doca_flow_fwd *fwd, 
		uint64_t fw_pipe_id, struct doca_flow_fwd *fwd_miss, uint64_t fw_miss_pipe_id){
	// TODO
}

/*
 * Add DOCA Flow entry
 *
 * @pipe_queue [in]: Queue identifier
 * @pipe_id [in]: Pipe ID
 * @match [in]: DOCA Flow match
 * @actions [in]: Pipe ID to actions
 * @monitor [in]: DOCA Flow monitor
 * @fwd [in]: DOCA Flow forward
 * @fw_pipe_id [in]: Pipe ID to forward
 * @flags [in]: Add entry flags
 */
static void pipe_add_entry(uint16_t pipe_queue, uint64_t pipe_id, struct doca_flow_match *match, 
		struct doca_flow_actions *actions, struct doca_flow_monitor *monitor, 
		struct doca_flow_fwd *fwd, uint64_t fw_pipe_id, uint32_t flags){
	// TODO
}


/*
 * Add DOCA Flow control pipe entry
 *
 * @pipe_queue [in]: Queue identifier
 * @priority [in]: Entry priority
 * @pipe_id [in]: Pipe ID
 * @match [in]: DOCA Flow match
 * @match_mask [in]: DOCA Flow match mask
 * @fwd [in]: DOCA Flow forward
 * @fw_pipe_id [in]: Pipe ID to forward
 */
static void pipe_control_add_entry(uint16_t pipe_queue, uint8_t priority, uint64_t pipe_id, 
		struct doca_flow_match *match, struct doca_flow_match *match_mask, 
		struct doca_flow_fwd *fwd, uint64_t fw_pipe_id){
	// TODO
}

/*
 * Destroy DOCA Flow pipe
 *
 * @pipe_id [in]: Pipe ID to destroy
 */
static void pipe_destroy(uint64_t pipe_id){
	// TODO
}

/*
 * Remove DOCA Flow entry
 *
 * @pipe_queue [in]: Queue identifier
 * @entry_id [in]: Entry ID to remove
 */
static void pipe_rm_entry(uint16_t pipe_queue, uint64_t entry_id){
	// TODO
}

/*
 * DOCA Flow port pipes flush
 *
 * @port_id [in]: Port ID to flush
 */
static void port_pipes_flush(uint16_t port_id){
	// TODO
}

/*
 * DOCA Flow query
 *
 * @entry_id [in]: Entry to query
 * @stats [in]: Query statistics
 */
static void flow_query(uint64_t entry_id, struct doca_flow_query *stats){
	// TODO
}

/*
 * DOCA Flow port pipes dump
 *
 * @port_id [in]: Port ID to dump
 * @fd [in]: File to dump information into
 */
static void port_pipes_dump(uint16_t port_id, FILE *fd){
	// TODO
}

/*
 * Register pipe operation functions to doca flow framework
 */
static void register_actions_on_flow_parser(){
	set_pipe_create(pipe_create);
	set_pipe_add_entry(pipe_add_entry);
	set_pipe_control_add_entry(pipe_control_add_entry);
	set_pipe_destroy(pipe_destroy);
	set_pipe_rm_entry(pipe_rm_entry);
	set_port_pipes_flush(port_pipes_flush);
	set_query(flow_query);
	set_port_pipes_dump(port_pipes_dump);
}

/*
 * Create application port
 *
 * @portid [in]: Port ID
 * @return: DOCA Flow port structure
 */
static struct doca_flow_port* port_create(uint8_t portid){
	char port_id_str[MAX_PORT_STR_LEN];
	struct doca_flow_error err = {0};
	struct doca_flow_port *port;
	struct doca_flow_port_cfg port_cfg = {0};

	port_cfg.port_id = portid;
	port_cfg.type = DOCA_FLOW_PORT_DPDK_BY_ID;
	snprintf(port_id_str, MAX_PORT_STR_LEN, "%d", port_cfg.port_id);
	port_cfg.devargs = port_id_str;
	port = doca_flow_port_start(&port_cfg, &err);
	if (port == NULL) {
		DOCA_LOG_ERR("Failed to initialize doca flow port: %s", err.message);
		return NULL;
	}
	return port;
}

/*
 * Destroy application's ports
 *
 * @nb_ports [in]: Number of ports to destroy
 * @ports [in]: Port array
 */
static void ports_destroy(int nb_ports, struct doca_flow_port **ports){
	int portid;
	struct doca_flow_port *port;

	for (portid = 0; portid < nb_ports; portid++) {
		port = ports[portid];
		if (port != NULL)
			doca_flow_port_destroy(port);
	}
}

/*
 * Initialize application's ports
 *
 * @nb_ports [in]: Number of ports to init
 * @return: Zero on success and negative value otherwise
 */
static int init_ports(int nb_ports){
	int portid;
	struct doca_flow_port *ports[nb_ports];

	for (portid = 0; portid < nb_ports; portid++) {
		ports[portid] = port_create(portid);
		if (ports[portid] == NULL) return -1;
	}
}

/*
 * Warpper of initialization process of doca flow
 *
 * @app_config [in]: configuration of subs_template
 * @return: Zero on success and other value otherwise
 */
doca_error_t applictaion_doca_flow_init(struct subs_template_cfg *app_config){
	struct doca_flow_error err = {0};
	struct doca_flow_cfg flow_cfg = {0};
	doca_error_t result;

	// init doca flow framework
	flow_cfg.queues = app_config->dpdk_cfg->port_config.nb_queues;
	flow_cfg.mode_args = "vnf"; 	// change the port mode here
	if (doca_flow_init(&flow_cfg, &err) < 0) {
		DOCA_LOG_ERR("Failed to init doca: %s", err.message);
		goto exit_failure;
	}

	// init doca ports
	if (init_ports(app_config->dpdk_cfg->port_config.nb_ports) < 0) {
		DOCA_LOG_ERR("Failed to init ports");
		goto destory_doca_flow;
	}

	// create pipe manager
	result = create_pipes_manager(&pipes_manager);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create pipes manager");
		goto destory_doca_flow;
	}

	register_actions_on_flow_parser();
	return DOCA_SUCCESS;

destory_doca_flow:
	doca_flow_destroy();

exit_failure:
    return DOCA_ERROR_INITIALIZATION;
}

/*
 * Realease the resources use within doca flow framework
 */
void application_doca_flow_distroy(){
	destroy_pipes_manager(pipes_manager);
}