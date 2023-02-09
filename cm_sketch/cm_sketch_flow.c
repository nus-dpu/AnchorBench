#include <rte_ethdev.h>

#include <doca_log.h>

#include "flow_pipes_manager.h"
#include "offload_rules.h"

#include "cm_sketch.h"

DOCA_LOG_REGISTER(CM_SKETCH::FLOW);

#define MAX_PORT_STR_LEN 128	   	/* Maximal length of doca port name */
#define DEFAULT_TIMEOUT_US (10000) 	/* Timeout for processing pipe entries */

static struct flow_pipes_manager *pipes_manager;

/*
 * Handler - Create DOCA Flow pipe under interactive mode
 *
 * @cfg [in]: DOCA Flow pipe configuration
 * @port_id [in]: Not being used
 * @fwd [in]: DOCA Flow forward
 * @fw_pipe_id [in]: Pipe ID to forward
 * @fwd_miss [in]: DOCA Flow forward miss
 * @fw_miss_pipe_id [in]: Pipe ID to forward miss
 */
static void _cb_pipe_create(struct doca_flow_pipe_cfg *cfg, uint16_t port_id, struct doca_flow_fwd *fwd, 
		uint64_t fw_pipe_id, struct doca_flow_fwd *fwd_miss, uint64_t fw_miss_pipe_id){
	// TODO
}

/*
 * Handler - Add DOCA Flow entry under interactive mode
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
static void _cb_pipe_add_entry(uint16_t pipe_queue, uint64_t pipe_id, struct doca_flow_match *match, 
		struct doca_flow_actions *actions, struct doca_flow_monitor *monitor, 
		struct doca_flow_fwd *fwd, uint64_t fw_pipe_id, uint32_t flags){
	// TODO
}


/*
 * Handler - Add DOCA Flow control pipe entry under interactive mode
 *
 * @pipe_queue [in]: Queue identifier
 * @priority [in]: Entry priority
 * @pipe_id [in]: Pipe ID
 * @match [in]: DOCA Flow match
 * @match_mask [in]: DOCA Flow match mask
 * @fwd [in]: DOCA Flow forward
 * @fw_pipe_id [in]: Pipe ID to forward
 */
static void _cb_pipe_control_add_entry(uint16_t pipe_queue, uint8_t priority, uint64_t pipe_id, 
		struct doca_flow_match *match, struct doca_flow_match *match_mask, 
		struct doca_flow_fwd *fwd, uint64_t fw_pipe_id){
	// TODO
}

/*
 * Handler - Destroy DOCA Flow pipe under interactive mode
 *
 * @pipe_id [in]: Pipe ID to destroy
 */
static void _cb_pipe_destroy(uint64_t pipe_id){
	// TODO
}

/*
 * Handler - Remove DOCA Flow entry under interactive mode
 *
 * @pipe_queue [in]: Queue identifier
 * @entry_id [in]: Entry ID to remove
 */
static void _cb_pipe_rm_entry(uint16_t pipe_queue, uint64_t entry_id){
	// TODO
}

/*
 * Handler - DOCA Flow port pipes flush under interactive mode
 *
 * @port_id [in]: Port ID to flush
 */
static void _cb_port_pipes_flush(uint16_t port_id){
	// TODO
}

/*
 * Handler - DOCA Flow query under interactive mode
 *
 * @entry_id [in]: Entry to query
 * @stats [in]: Query statistics
 */
static void _cb_flow_query(uint64_t entry_id, struct doca_flow_query *stats){
	// TODO
}

/*
 * Handler - DOCA Flow port pipes dump under interactive mode
 *
 * @port_id [in]: Port ID to dump
 * @fd [in]: File to dump information into
 */
static void _cb_port_pipes_dump(uint16_t port_id, FILE *fd){
	// TODO
}

/*
 * Register pipe operation functions to doca flow framework
 */
static void register_actions_on_flow_parser(){
	set_pipe_create(_cb_pipe_create);
	set_pipe_add_entry(_cb_pipe_add_entry);
	set_pipe_control_add_entry(_cb_pipe_control_add_entry);
	set_pipe_destroy(_cb_pipe_destroy);
	set_pipe_rm_entry(_cb_pipe_rm_entry);
	set_port_pipes_flush(_cb_port_pipes_flush);
	set_query(_cb_flow_query);
	set_port_pipes_dump(_cb_port_pipes_dump);
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
 * Initialize application's ports
 *
 * @app_config [in]: configuration of cm_sketch
 * @return: Zero on success and negative value otherwise
 */
static int init_ports(struct cm_sketch_cfg *app_config){
	int portid, destory_portid;

	struct doca_flow_port **ports = (struct doca_flow_port**)malloc(
		sizeof(struct doca_flow_port*) * app_config->dpdk_cfg->port_config.nb_ports);
	if(!ports){
		DOCA_LOG_ERR("failed to allocate doca port array");
		goto exit_failure;
	}
	app_config->ports = ports;

	for (portid = 0; portid < app_config->dpdk_cfg->port_config.nb_ports; portid++) {
		ports[portid] = port_create(portid);
		if (ports[portid] == NULL){
			DOCA_LOG_ERR("failed to create port %d", portid);
			goto destory_ports;
		}
	}

destory_ports:
	for(destory_portid = 0; destory_portid < portid; destory_portid++) {
		doca_flow_port_destroy(ports[destory_portid]);
	}

destory_ports_array:
	free(ports);

exit_failure:
	return -1;
}

/*
 * Destroy application's ports
 *
 * @app_config [in]: configuration of cm_sketch
 */ 
static void destroy_ports(struct cm_sketch_cfg *app_config){
	int portid;
	struct doca_flow_port *port;

	for (portid = 0; portid < app_config->dpdk_cfg->port_config.nb_ports; portid++) {
		port = app_config->ports[portid];
		if (port != NULL)
			doca_flow_port_destroy(port);
	}
}

/*
 * Initialize pipes
 *
 * @app_config [in]: configuration of cm_sketch
 * @return: Zero on success and negative value otherwise
 */
static int init_pipes(struct cm_sketch_cfg *app_config){
	uint16_t portid;
	for (portid = 0; portid < app_config->dpdk_cfg->port_config.nb_ports; portid++) {
		// TODO: add your building pipe logic here
	}
}

/*
 * Warpper of initialization process of doca flow
 *
 * @app_config [in]: configuration of cm_sketch
 * @return: Zero on success and other value otherwise
 */
doca_error_t applictaion_doca_flow_init(struct cm_sketch_cfg *app_config){
	struct doca_flow_error err = {0};
	struct doca_flow_cfg flow_cfg = {0};
	doca_error_t result;

	// init doca flow framework
	flow_cfg.queues = app_config->dpdk_cfg->port_config.nb_queues;
	flow_cfg.mode_args = "vnf,hws"; 	// change the port mode here
	if (doca_flow_init(&flow_cfg, &err) < 0) {
		DOCA_LOG_ERR("Failed to init doca: %s", err.message);
		goto exit_failure;
	}

	// init doca ports
	if (init_ports(app_config) < 0) {
		DOCA_LOG_ERR("Failed to init ports");
		goto destory_doca_flow;
	}

	// init doca pipes
	if (init_pipes(app_config->dpdk_cfg->port_config.nb_ports) < 0) {
		DOCA_LOG_ERR("Failed to init pipes");
		goto destory_doca_ports;
	}

	// create pipe manager under interactive mode
	if(app_config->mode == CM_SKETCH_MODE_INTERACTIVE){
		result = create_pipes_manager(&pipes_manager);
		if (result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Failed to create pipes manager");
			goto destory_doca_ports;
		}
		register_actions_on_flow_parser();
	}
	
	return DOCA_SUCCESS;

destory_doca_ports:
	destroy_ports(app_config);

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