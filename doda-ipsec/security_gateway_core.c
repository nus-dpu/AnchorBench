#include <json-c/json.h>
#include <signal.h>

#include <rte_ethdev.h>

#include <doca_argp.h>
#include <doca_flow.h>
#include <doca_log.h>
#include <doca_dev.h>
#include <doca_dpdk.h>

#include <dpdk_utils.h>
#include <offload_rules.h>
#include <utils.h>
#include <flow_parser.h>

#include "security_gateway_core.h"

DOCA_LOG_REGISTER(SECURITY_GATEWAY::Core);

#define PACKET_BURST 128		/* The number of packets in the rx queue */
#define SLEEP_IN_NANOS (10 * 1000)	/* Sample the job every 10 microseconds  */
#define ENCAP_DST_IP_IDX 30		/* index in encap raw data for destination IP */
#define ENCAP_ESP_SPI_IDX 34		/* index in encap raw data for esp SPI */

static bool force_quit;			/* Set when signal is received */

/*
 * Signals handler function to handle SIGINT and SIGTERM signals
 *
 * @signum [in]: signal number
 */
static void
signal_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM) {
		DOCA_LOG_INFO("Signal %d received, preparing to exit", signum);
		force_quit = true;
	}
}

/*
 * Get dpdk port ID and check if its encryption port or decryption, based on
 * user PCI input and DOCA device devinfo
 *
 * @app_cfg [in]: application configuration structure
 * @port_id [in]: port ID
 * @idx [out]: index for ports array - 0 for secured network index and 1 for unsecured
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
find_port_action_type(struct security_gateway_config *app_cfg, int port_id, int *idx)
{
	struct doca_dev *dev;
	struct doca_devinfo *dev_info;
	struct doca_pci_bdf pci_addr;
	doca_error_t result;

	result = doca_dpdk_port_as_dev(port_id, &dev);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to find DOCA device associated with port ID %d: %s", port_id, doca_get_error_string(result));
		return result;
	}
	dev_info = doca_dev_as_devinfo(dev);
	if (dev_info == NULL) {
		DOCA_LOG_ERR("Failed to find DOCA device associated with port ID %d", port_id);
		return result;
	}
	result = doca_devinfo_get_pci_addr(dev_info, &pci_addr);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to get device PCI address: %s", doca_get_error_string(result));
		return result;
	}

	if (pci_addr.raw == app_cfg->unsecured_pci_addr.raw) {
		*idx = UNSECURED_IDX;
		return DOCA_SUCCESS;
	} else if (pci_addr.raw == app_cfg->secured_pci_addr.raw) {
		*idx = SECURED_IDX;
		return DOCA_SUCCESS;
	}
	return DOCA_ERROR_INVALID_VALUE;
}

void
doca_flow_cleanup(int nb_ports, struct security_gateway_ports_map *ports[])
{
	int port_id;

	for (port_id = 0; port_id < nb_ports; port_id++) {
		if (ports[port_id] != NULL) {
			doca_flow_port_stop(ports[port_id]->port);
			doca_flow_port_destroy(ports[port_id]->port);
			free(ports[port_id]);
		}
	}

	doca_flow_destroy();
}

/*
 * Create DOCA Flow port by port id
 *
 * @port_id [in]: port ID
 * @error [out]: output error
 * @port [out]: pointer to port handler
 * @return: 0 on success and negative value otherwise
 */
static int
create_doca_flow_port(int port_id, struct doca_flow_error *error, struct doca_flow_port **port)
{
	int max_port_str_len = 128;
	struct doca_flow_port_cfg port_cfg;
	char port_id_str[max_port_str_len];

	memset(&port_cfg, 0, sizeof(port_cfg));

	port_cfg.port_id = port_id;
	port_cfg.type = DOCA_FLOW_PORT_DPDK_BY_ID;
	snprintf(port_id_str, max_port_str_len, "%d", port_cfg.port_id);
	port_cfg.devargs = port_id_str;
	DOCA_LOG_INFO("start doca flow for port %d...", port_id);
	*port = doca_flow_port_start(&port_cfg, error);
	if (*port == NULL)
		return -1;
	return 0;
}

/*
 * Entry processing callback
 *
 * @entry [in]: entry pointer
 * @status [in]: doca flow entry status
 * @op [in]: doca flow entry operation
 * @user_ctx [out]: user context
 */
static void
check_for_valid_entry(struct doca_flow_pipe_entry *entry, enum doca_flow_entry_status status,
		      enum doca_flow_entry_op op, void *user_ctx)
{
	DOCA_LOG_INFO("check for valid entry callback...");
	if (status != DOCA_FLOW_ENTRY_STATUS_SUCCESS) {
		DOCA_LOG_ERR("Failed to add entry");
		if (user_ctx != NULL)
			*(bool *)user_ctx = true; /* set is_failure to true if processing failed */
	}

}

int
security_gateway_init_doca_flow(struct security_gateway_config *app_cfg, struct security_gateway_ports_map *ports[])
{
	int result;
	int port_id;
	int port_idx = 0;
	int nb_ports = 0;
	struct doca_flow_cfg flow_cfg;
	struct doca_flow_error error;

	memset(&flow_cfg, 0, sizeof(flow_cfg));

	/* init doca flow with crypto shared resources */
	flow_cfg.queues = 8;
	flow_cfg.mode_args = "vnf";
	flow_cfg.cb = check_for_valid_entry;
	flow_cfg.nr_shared_resources[DOCA_FLOW_SHARED_RESOURCE_CRYPTO] = 1024;
	result = doca_flow_init(&flow_cfg, &error);
	if (result < 0) {
		DOCA_LOG_ERR("Failed to init DOCA Flow - %s (%u)", error.message, error.type);
		return -1;
	}

	for (port_id = 0; port_id < RTE_MAX_ETHPORTS; port_id++) {
		DOCA_LOG_INFO("search for the probed devices...");
		/* search for the probed devices */
		if (!rte_eth_dev_is_valid_port(port_id))
			continue;
		if (find_port_action_type(app_cfg, port_id, &port_idx) != DOCA_SUCCESS)
			continue;
		ports[port_idx] = malloc(sizeof(struct security_gateway_ports_map));
		if (ports[port_idx] == NULL) {
			DOCA_LOG_ERR("malloc() failed");
			doca_flow_cleanup(nb_ports, ports);
			return -1;
		}
		DOCA_LOG_INFO("create doca flow for port %d...", port_id);
		result = create_doca_flow_port(port_id, &error, &ports[port_idx]->port);
		if (result < 0) {
			DOCA_LOG_ERR("Failed to init DOCA Flow port - %s (%u)", error.message, error.type);
			free(ports[port_idx]);
			doca_flow_cleanup(nb_ports, ports);
			return -1;
		}
		nb_ports++;
		ports[port_idx]->port_id = port_id;
	}
	if (ports[SECURED_IDX]->port == NULL || ports[UNSECURED_IDX]->port == NULL) {
		DOCA_LOG_ERR("Failed to init two DOCA Flow ports");
		doca_flow_cleanup(nb_ports, ports);
		return -1;
	}
	result = doca_flow_port_pair(ports[SECURED_IDX]->port, ports[UNSECURED_IDX]->port);
	if (result < 0) {
		DOCA_LOG_ERR("Failed to pair ports");
		doca_flow_cleanup(nb_ports, ports);
		return -1;
	}
	return 0;
}

/*
 * Initialized DOCA workq with ipsec context
 *
 * @dev [in]: doca device to connect to context
 * @ctx [in]: ipsec context
 * @workq [out]: created workq
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
security_gateway_init_workq(struct doca_dev *dev, struct doca_ctx *ctx, struct doca_workq **workq)
{
	doca_error_t result;

	result = doca_ctx_dev_add(ctx, dev);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to register device with lib context: %s", doca_get_error_string(result));
		return result;
	}

	result = doca_ctx_start(ctx);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to start lib context: %s", doca_get_error_string(result));
		doca_ctx_dev_rm(ctx, dev);
		return result;
	}

	result = doca_workq_create(1, workq);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to create work queue: %s", doca_get_error_string(result));
		doca_ctx_stop(ctx);
		doca_ctx_dev_rm(ctx, dev);
		return result;
	}

	result = doca_ctx_workq_add(ctx, *workq);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to register work queue with context: %s", doca_get_error_string(result));
		doca_workq_destroy(*workq);
		doca_ctx_stop(ctx);
		doca_ctx_dev_rm(ctx, dev);
		return result;
	}
	return DOCA_SUCCESS;
}

/*
 * Destroy DOCA workq and stop doca context
 *
 * @dev [in]: doca device to connect to context
 * @ctx [in]: ipsec context
 * @workq [in]: doca workq
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
security_gateway_destroy_workq(struct doca_dev *dev, struct doca_ctx *ctx, struct doca_workq *workq)
{
	doca_error_t tmp_result, result = DOCA_SUCCESS;

	tmp_result = doca_ctx_workq_rm(ctx, workq);
	if (tmp_result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to remove work queue from ctx: %s", doca_get_error_string(tmp_result));
		DOCA_ERROR_PROPAGATE(result, tmp_result);
	}

	tmp_result = doca_workq_destroy(workq);
	if (tmp_result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to destroy work queue: %s", doca_get_error_string(tmp_result));
		DOCA_ERROR_PROPAGATE(result, tmp_result);
	}

	tmp_result = doca_ctx_stop(ctx);
	if (tmp_result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to stop context: %s", doca_get_error_string(tmp_result));
		DOCA_ERROR_PROPAGATE(result, tmp_result);
	}

	tmp_result = doca_ctx_dev_rm(ctx, dev);
	if (tmp_result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to remove device from ctx: %s", doca_get_error_string(tmp_result));
		DOCA_ERROR_PROPAGATE(result, tmp_result);
	}

	return result;
}

doca_error_t
security_gateway_create_ipsec_sa(struct security_gateway_config *app_cfg, enum doca_ipsec_direction direction,
				 struct doca_ipsec_sa **sa)
{
	struct doca_workq *doca_workq;
	struct doca_ctx *doca_ctx;
	struct doca_ipsec *ipsec_ctx;
	struct doca_ipsec_sa_attrs sa_attrs;
	struct doca_event event = {0};
	struct timespec ts;
	uint8_t raw_key[16] = "RAW_KEY_128";
	doca_error_t result;

	memset(&sa_attrs, 0, sizeof(sa_attrs));

	result = doca_ipsec_create(&ipsec_ctx);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to create IPSEC context: %s", doca_get_error_string(result));
		return result;
	}

	doca_ctx = doca_ipsec_as_ctx(ipsec_ctx);

	result = security_gateway_init_workq(app_cfg->secured_dev, doca_ctx, &doca_workq);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to initialize DOCA workq: %s", doca_get_error_string(result));
		doca_ipsec_destroy(ipsec_ctx);
		return result;
	}

	sa_attrs.mode = DOCA_IPSEC_SA_MODE_TUNNEL;
	sa_attrs.offload = DOCA_IPSEC_SA_OFFLOAD_CRYPTO;
	sa_attrs.protocol = DOCA_IPSEC_SA_PROTO_ESP;
	sa_attrs.icv_length = DOCA_IPSEC_ICV_LENGTH_16;
	sa_attrs.key.type = DOCA_ENCRYPTION_KEY_AESGCM_128;
	sa_attrs.key.aes_gcm.implicit_iv = 0;
	sa_attrs.key.aes_gcm.salt = 6;
	sa_attrs.key.aes_gcm.raw_key = (void *)&raw_key;
	sa_attrs.direction = direction;

	const struct doca_ipsec_sa_create_job sa_create = {
		.base = (struct doca_job) {
			.type = DOCA_IPSEC_JOB_SA_CREATE,
			.flags = DOCA_JOB_FLAGS_NONE,
			.ctx = doca_ctx,
			.user_data.u64 = DOCA_IPSEC_JOB_SA_CREATE,
		},
		.sa_attrs = sa_attrs,
	};

	/* Enqueue sha job */
	result = doca_workq_submit(doca_workq, &sa_create.base);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to submit ipsec job: %s", doca_get_error_string(result));
		security_gateway_destroy_workq(app_cfg->secured_dev, doca_ctx, doca_workq);
		doca_ipsec_destroy(ipsec_ctx);
		return result;
	}

	/* Wait for job completion */
	while ((result = doca_workq_progress_retrieve(doca_workq, &event, DOCA_WORKQ_RETRIEVE_FLAGS_NONE)) ==
	       DOCA_ERROR_AGAIN) {
		/* Wait for the job to complete */
		ts.tv_sec = 0;
		ts.tv_nsec = SLEEP_IN_NANOS;
		nanosleep(&ts, &ts);
	}

	if (result != DOCA_SUCCESS)
		DOCA_LOG_ERR("Failed to retrieve job: %s", doca_get_error_string(result));

	/* if job succeed event.result.ptr will point to the new created sa object */
	*sa = event.result.ptr;
	security_gateway_destroy_workq(app_cfg->secured_dev, doca_ctx, doca_workq);
	doca_ipsec_destroy(ipsec_ctx);
	return result;
}

/**
 * Check if given device is capable of executing a DOCA_IPSEC_JOB_SA_CREATE job.
 *
 * @devinfo [in]: The DOCA device information
 * @return: DOCA_SUCCESS if the device supports DOCA_IPSEC_JOB_SA_CREATE and DOCA_ERROR otherwise.
 */
static doca_error_t
job_ipsec_create_is_supported(struct doca_devinfo *devinfo)
{
	doca_error_t result;

	result = doca_ipsec_job_get_supported(devinfo, DOCA_IPSEC_JOB_SA_CREATE);
	if (result != DOCA_SUCCESS)
		return result;
	return doca_ipsec_is_offload_supported(devinfo, DOCA_IPSEC_SA_OFFLOAD_CRYPTO);
}

doca_error_t
security_gateway_init_devices(struct security_gateway_config *app_cfg)
{
	doca_error_t result;

	result = open_doca_device_with_pci(&app_cfg->secured_pci_addr, &job_ipsec_create_is_supported, &app_cfg->secured_dev);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to open DOCA device for secured port: %s", doca_get_error_string(result));
		return result;
	}

	result = open_doca_device_with_pci(&app_cfg->unsecured_pci_addr, NULL, &app_cfg->unsecured_dev);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to open DOCA device for unsecured port: %s", doca_get_error_string(result));
		return result;
	}

	/* probe the opened doca devices with 'dv_flow_en=2' for HWS mode */
	result = doca_dpdk_port_probe(app_cfg->secured_dev, "dv_flow_en=2");
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to probe dpdk port for secured port: %s", doca_get_error_string(result));
		return result;
	}

	result = doca_dpdk_port_probe(app_cfg->unsecured_dev, "dv_flow_en=2");
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to probe dpdk port for unsecured port: %s", doca_get_error_string(result));
		return result;
	}

	return DOCA_SUCCESS;
}

/*
 * Handling the new received packets - print packet source IP and send them to tx queues of second port
 *
 * @packets_received [in]: size of mbufs array
 * @packets [in]: array of packets
 * @queue_id [in]: TX queue ID to send the packets to
 */
static void
handle_packets_received(uint16_t packets_received, struct rte_mbuf **packets, uint16_t queue_id)
{
	uint32_t current_packet;
	uint8_t fwd_port = packets[0]->port ^ 1;

	/* Deciding the port to send the packet to */
	for (current_packet = 0; current_packet < packets_received; current_packet++) {
		/* Enter your logic here */
#ifdef DOCA_LOGGING_ALLOW_DLOG
		struct rte_ether_hdr *eth;
		struct rte_ipv4_hdr *ipv4;
		/* Print packet info */
		eth = rte_pktmbuf_mtod(packets[current_packet], typeof(eth));
		ipv4 = (void *)(eth + 1);
		DOCA_DLOG_DBG("packet source IP: %d.%d.%d.%d", (ipv4->src_addr >> 0) & 0xff,
								(ipv4->src_addr >> 8) & 0xff,
								(ipv4->src_addr >> 16) & 0xff,
								(ipv4->src_addr >> 24) & 0xff);
#endif
	}

	rte_eth_tx_burst(fwd_port, queue_id, packets, packets_received);
}

/*
 * Receive the income packets from the RX queue and send it to the TX queue in the second port
 *
 * @args [in]: generic pointer to core context struct
 */
static void
process_queue_packets(void *args)
{
	uint16_t port_id;
	int nb_packets;
	struct rte_mbuf *packets[PACKET_BURST];
	struct security_gateway_core_ctx *ctx = (struct security_gateway_core_ctx *)args;

	DOCA_LOG_DBG("Core %u is receiving packets.", rte_lcore_id());
	while (!force_quit) {
		for (port_id = 0; port_id < ctx->nb_ports; port_id++) {
			nb_packets = rte_eth_rx_burst(port_id, ctx->queue_id, packets, PACKET_BURST);
			if (nb_packets) {
				DOCA_DLOG_DBG("Received %d packets from port 0x%x using core %u", nb_packets, port_id, rte_lcore_id());
				handle_packets_received(nb_packets, packets, ctx->queue_id);
			}
		}
	}
	free(ctx);
}

/*
 * Run on each lcore process_queue_packets() to receive and send packets in a loop
 *
 * @nb_queues [in]: number of queues
 * @nb_ports [in]: number of ports
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
security_gateway_process_packets(uint16_t nb_queues, uint8_t nb_ports)
{
	uint16_t lcore_index = 0;
	int current_lcore = 0;
	struct security_gateway_core_ctx *ctx;

	while ((current_lcore < RTE_MAX_LCORE) && (lcore_index < nb_queues)) {
		current_lcore = rte_get_next_lcore(current_lcore, true, false);
		ctx = (struct security_gateway_core_ctx *)malloc(sizeof(struct security_gateway_core_ctx));
		if (ctx == NULL) {
			DOCA_LOG_ERR("malloc() failed");
			force_quit = true;
			return DOCA_ERROR_NO_MEMORY;
		}
		ctx->nb_ports = nb_ports;
		ctx->queue_id = lcore_index;

		/* Launch the worker to start process packets */
		if (rte_eal_remote_launch((void *)process_queue_packets, (void *)ctx, current_lcore) != 0) {
			DOCA_LOG_ERR("Remote launch failed");
			free(ctx);
			force_quit = true;
			return DOCA_ERROR_DRIVER;
		}
		lcore_index++;
	}

	return DOCA_SUCCESS;
}

doca_error_t
security_gateway_wait_for_traffic(struct security_gateway_config *app_cfg, struct application_dpdk_config *dpdk_config)
{
	doca_error_t result;

	force_quit = false;

	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);
	DOCA_LOG_INFO("Waiting for traffic, press Ctrl+C for termination");
	/* Wait in a loop for packets */
	if (app_cfg->mode == SECURITY_GATEWAY_FULL_OFFLOAD) {
		while (!force_quit)
			sleep(1);
	} else {
		result = security_gateway_process_packets(dpdk_config->port_config.nb_queues, dpdk_config->port_config.nb_ports);
		if (result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Failed to process packets on all lcores");
			return result;
		}
		/* Wait all threads to be done */
		rte_eal_mp_wait_lcore();
	}
	return DOCA_SUCCESS;
}

/*
 * Create ipsec encrypt pipe changeable meta data match and changeable shared IPSEC encryption object
 *
 * @port [in]: port of the pipe
 * @pipe [out]: the created pipe
 * @return: 0 on success and negative value otherwise
 */
static int
create_ipsec_encrypt_pipe(struct doca_flow_port *port, struct doca_flow_pipe **pipe)
{
	int nb_actions = 1;
	struct doca_flow_match match;
	struct doca_flow_actions actions, *actions_arr[nb_actions];
	struct doca_flow_pipe_cfg pipe_cfg;
	struct doca_flow_error error;

	memset(&match, 0, sizeof(match));
	memset(&actions, 0, sizeof(actions));
	memset(&pipe_cfg, 0, sizeof(pipe_cfg));

	pipe_cfg.attr.name = "ENCRYPT_PIPE";
	pipe_cfg.attr.type = DOCA_FLOW_PIPE_BASIC;
	pipe_cfg.match = &match;
	pipe_cfg.match_mask = &match;
	actions_arr[0] = &actions;
	pipe_cfg.actions = actions_arr;
	pipe_cfg.attr.nb_actions = nb_actions;
	pipe_cfg.port = port;

	match.meta.pkt_meta = 0xffffffff;

	actions.security.proto_type = DOCA_FLOW_CRYPTO_PROTOCOL_ESP_ENCRYPT;
	actions.security.crypto_id = 0xffffffff;

	*pipe = doca_flow_pipe_create(&pipe_cfg, NULL, NULL, &error);
	if (*pipe == NULL) {
		DOCA_LOG_ERR("Failed to create encrypt pipe - %s (%u)", error.message, error.type);
		return -1;
	}

	return 0;
}

/*
 * Create pipe with 5 tuple match, changeable set meta, and fwd that depends on user mode:
 * - in full offload fwd to second port
 * - in partial offload fwd the matched packets to the application
 *
 * @port [in]: port of the pipe
 * @port_id [in]: port ID of the pipe
 * @protocol_type [in]: DOCA_PROTO_TCP / DOCA_PROTO_UDP
 * @mode [in]: application running mode - full offload / partial offload
 * @nb_queues [in]: number of doca flow queues for RSS
 * @pipe [out]: the created pipe
 * @return: 0 on success and negative value otherwise
 */
static int
create_ipsec_hairpin_pipe(struct doca_flow_port *port, int port_id, uint8_t protocol_type,
			  enum security_gateway_offload_mode mode, int nb_queues, struct doca_flow_pipe **pipe)
{
	int nb_actions = 1;
	uint16_t rss_queues[nb_queues];
	struct doca_flow_match match;
	struct doca_flow_fwd fwd;
	struct doca_flow_actions actions, *actions_arr[nb_actions];
	struct doca_flow_pipe_cfg pipe_cfg;
	struct doca_flow_error error;
	int i;

	memset(&match, 0, sizeof(match));
	memset(&fwd, 0, sizeof(fwd));
	memset(&actions, 0, sizeof(actions));
	memset(&pipe_cfg, 0, sizeof(pipe_cfg));

	pipe_cfg.attr.name = "HAIRPIN_PIPE";
	pipe_cfg.attr.type = DOCA_FLOW_PIPE_BASIC;
	pipe_cfg.match = &match;
	actions_arr[0] = &actions;
	pipe_cfg.actions = actions_arr;
	pipe_cfg.attr.nb_actions = nb_actions;
	pipe_cfg.attr.is_root = false;
	pipe_cfg.port = port;

	match.out_l4_type = protocol_type;
	match.out_dst_ip.ipv4_addr = 0xffffffff;
	match.out_src_ip.ipv4_addr = 0xffffffff;
	match.out_dst_ip.type = DOCA_FLOW_IP4_ADDR;
	match.out_src_ip.type = DOCA_FLOW_IP4_ADDR;
	match.out_dst_port = 0xffff;
	match.out_src_port = 0xffff;

	if (mode == SECURITY_GATEWAY_FULL_OFFLOAD) {
		fwd.type = DOCA_FLOW_FWD_PORT;
		fwd.port_id = port_id ^ 1;
	} else {
		/* for partial offload the packets will be send to the app before getting to the second port */
		for (i = 0; i < nb_queues; i++)
			rss_queues[i] = i;
		fwd.type = DOCA_FLOW_FWD_RSS;
		fwd.rss_queues = rss_queues;
		fwd.num_of_queues = nb_queues;
	}

	actions.meta.pkt_meta = 0xffffffff;

	*pipe = doca_flow_pipe_create(&pipe_cfg, &fwd, NULL, &error);
	if (*pipe == NULL) {
		DOCA_LOG_ERR("Failed to create encrypt pipe - %s (%u)", error.message, error.type);
		return -1;
	}

	return 0;
}

/*
 * Create ipsec decrypt pipe with ESP header match and changeable shared IPSEC decryption object
 *
 * @port [in]: port of the pipe
 * @pipe [out]: the created pipe
 * @return: 0 on success and negative value otherwise
 */
static int
create_ipsec_decrypt_pipe(struct doca_flow_port *port, struct doca_flow_pipe **pipe)
{
	int nb_actions = 1;
	struct doca_flow_match match;
	struct doca_flow_actions actions, *actions_arr[nb_actions];
	struct doca_flow_fwd fwd_miss;
	struct doca_flow_pipe_cfg pipe_cfg;
	struct doca_flow_error error;

	memset(&match, 0, sizeof(match));
	memset(&actions, 0, sizeof(actions));
	memset(&fwd_miss, 0, sizeof(fwd_miss));
	memset(&pipe_cfg, 0, sizeof(pipe_cfg));

	pipe_cfg.attr.name = "DECRYPT_PIPE";
	pipe_cfg.match = &match;
	actions_arr[0] = &actions;
	pipe_cfg.actions = actions_arr;
	pipe_cfg.attr.nb_actions = nb_actions;
	pipe_cfg.attr.is_root = true;
	pipe_cfg.port = port;

	match.out_dst_ip.type = DOCA_FLOW_IP4_ADDR;
	match.out_dst_ip.ipv4_addr = 0xffffffff;
	match.tun.type = DOCA_FLOW_TUN_ESP;
	match.tun.esp_spi = 0xffffffff;

	actions.security.proto_type = DOCA_FLOW_CRYPTO_PROTOCOL_ESP_DECRYPT;
	actions.security.crypto_id = 0xffffffff;

	fwd_miss.type = DOCA_FLOW_FWD_DROP;

	*pipe = doca_flow_pipe_create(&pipe_cfg, NULL, &fwd_miss, &error);
	if (*pipe == NULL) {
		DOCA_LOG_ERR("Failed to create decrypt pipe - %s (%u)", error.message, error.type);
		return -1;
	}

	return 0;
}

/*
 * Create pipe for decryption syndrome and add entry to it.
 * If syndrome is 0 forwarding the packets, else drop them.
 *
 * @port [in]: port of the pipe
 * @port_id [in]: port ID of the pipe
 * @mode [in]: application running mode - full offload / partial offload
 * @nb_queues [in]: number of doca flow queues for RSS
 * @pipe [out]: the created pipe
 * @return: 0 on success and negative value otherwise
 */
static int
create_ipsec_syndrome_pipe(struct doca_flow_port *port, int port_id, enum security_gateway_offload_mode mode,
			   int nb_queues, struct doca_flow_pipe **pipe)
{
	int nb_actions = 1;
	uint16_t rss_queues[nb_queues];
	struct doca_flow_match match;
	struct doca_flow_match match_mask;
	struct doca_flow_actions actions, *actions_arr[nb_actions];
	struct doca_flow_pipe_cfg pipe_cfg;
	struct doca_flow_fwd fwd;
	struct doca_flow_fwd fwd_miss;
	struct doca_flow_pipe_entry *entry;
	struct doca_flow_error error;
	int num_of_entries = 1;
	int i;
	int result;

	memset(&match, 0, sizeof(match));
	memset(&match_mask, 0, sizeof(match_mask));
	memset(&actions, 0, sizeof(actions));
	memset(&pipe_cfg, 0, sizeof(pipe_cfg));

	pipe_cfg.attr.name = "DECRYPT_SYNDROME_PIPE";
	pipe_cfg.match = &match;
	pipe_cfg.match_mask = &match_mask;
	actions_arr[0] = &actions;
	pipe_cfg.actions = actions_arr;
	pipe_cfg.attr.nb_actions = nb_actions;
	pipe_cfg.attr.is_root = false;
	pipe_cfg.port = port;

	match_mask.meta.ipsec_syndrome = 0xff;
	match.meta.ipsec_syndrome = 0xff;

	if (mode == SECURITY_GATEWAY_FULL_OFFLOAD) {
		fwd.type = DOCA_FLOW_FWD_PORT; /* fwd decrypted packets with syndrome 0 to second port */
		fwd.port_id = port_id ^ 1;
	} else {
		for (i = 0; i < nb_queues; i++)
			rss_queues[i] = i;
		fwd.type = DOCA_FLOW_FWD_RSS;  /* fwd decrypted packets with syndrome 0 to the application */
		fwd.rss_queues = rss_queues;
		fwd.num_of_queues = nb_queues;
	}

	fwd_miss.type = DOCA_FLOW_FWD_DROP;

	*pipe = doca_flow_pipe_create(&pipe_cfg, &fwd, &fwd_miss, &error);
	if (*pipe == NULL) {
		DOCA_LOG_ERR("Failed to create syndrome pipe - %s (%u)", error.message, error.type);
		return -1;
	}

	memset(&match, 0, sizeof(match));
	match.meta.ipsec_syndrome = 0;

	entry = doca_flow_pipe_add_entry(0, *pipe, &match, &actions, NULL, NULL, DOCA_FLOW_NO_WAIT, NULL, &error);
	result = doca_flow_entries_process(port, 0, DEFAULT_TIMEOUT_US, num_of_entries);
	if (result != num_of_entries || doca_flow_pipe_entry_get_status(entry) != DOCA_FLOW_ENTRY_STATUS_SUCCESS)
		return -1;
	return 0;
}

/*
 * Create control pipe for unsecured port
 *
 * @port [in]: port of the pipe
 * @pipe [out]: the created pipe
 * @return: 0 on success and negative value otherwise
 */
static int
create_control_pipe(struct doca_flow_port *port, struct doca_flow_pipe **pipe)
{
	struct doca_flow_pipe_cfg pipe_cfg;
	struct doca_flow_error error;

	memset(&pipe_cfg, 0, sizeof(pipe_cfg));

	pipe_cfg.attr.name = "CONTROL_PIPE";
	pipe_cfg.attr.type = DOCA_FLOW_PIPE_CONTROL;
	pipe_cfg.attr.is_root = true;
	pipe_cfg.port = port;

	*pipe = doca_flow_pipe_create(&pipe_cfg, NULL, NULL, &error);
	if (*pipe == NULL) {
		DOCA_LOG_ERR("Failed to create control pipe - %s (%u)", error.message, error.type);
		return -1;
	}
	return 0;
}

/*
 * Add control pipe entries - one entry that forwards TCP traffic to TCP pipe,
 * and one entry that forwards UDP traffic to UDP pipe
 *
 * @control_pipe [in]: control pipe pointer
 * @tcp_pipe [in]: TCP pipe pointer to forward TCP traffic
 * @udp_pipe [in]: UDP pipe pointer to forward UDP traffic
 * @return: 0 on success and negative value otherwise
 */
static int
add_control_pipe_entries(struct doca_flow_pipe *control_pipe, struct doca_flow_pipe *tcp_pipe,
			 struct doca_flow_pipe *udp_pipe)
{
	struct doca_flow_pipe_entry *entry;
	struct doca_flow_match match;
	struct doca_flow_fwd fwd;
	struct doca_flow_error error;

	memset(&match, 0, sizeof(match));
	memset(&fwd, 0, sizeof(fwd));

	fwd.type = DOCA_FLOW_FWD_DROP;

	entry = doca_flow_pipe_control_add_entry(0, 1, control_pipe, &match, NULL, NULL, NULL, NULL, &fwd, &error);
	if (entry == NULL) {
		DOCA_LOG_ERR("Failed to add UDP entry - %s (%u)", error.message, error.type);
		return -1;
	}

	match.out_dst_ip.type = DOCA_FLOW_IP4_ADDR;
	match.out_l4_type = DOCA_PROTO_TCP;

	fwd.type = DOCA_FLOW_FWD_PIPE;
	fwd.next_pipe = tcp_pipe;
	entry = doca_flow_pipe_control_add_entry(0, 0, control_pipe, &match, NULL, NULL, NULL, NULL, &fwd, &error);
	if (entry == NULL) {
		DOCA_LOG_ERR("Failed to add TCP entry - %s (%u)", error.message, error.type);
		return -1;
	}

	match.out_dst_ip.type = DOCA_FLOW_IP4_ADDR;
	match.out_l4_type = DOCA_PROTO_UDP;

	fwd.type = DOCA_FLOW_FWD_PIPE;
	fwd.next_pipe = udp_pipe;
	entry = doca_flow_pipe_control_add_entry(0, 0, control_pipe, &match, NULL, NULL, NULL, NULL, &fwd, &error);
	if (entry == NULL) {
		DOCA_LOG_ERR("Failed to add UDP entry - %s (%u)", error.message, error.type);
		return -1;
	}

	return 0;
}

/*
 * Config and bind shared IPSEC object for encryption
 *
 * @port [in]: port to bind the shared object to
 * @sa [in]: crypto object handle (IPsec offload object)
 * @ipsec_id [in]: shared object ID
 * @rule [in]: encrypt rule
 * @return: 0 on success and negative value otherwise
 */
static int
create_ipsec_encrypt_shared_object(struct doca_flow_port *port, void *sa,
				   uint32_t ipsec_id, struct encrypt_rule rule)
{
	struct doca_flow_shared_resource_cfg cfg;
	struct doca_flow_resource_crypto_cfg crypto_cfg;
	struct doca_flow_error error;
	uint8_t reformat_encap_data[50] = {
		0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,	/* mac_dst */
		0x11, 0x22, 0x33, 0x44, 0x55, 0x66,	/* mac_src */
		0x08, 0x00,				/* mac_type */
		0x45, 0x00, 0x00, 0x00,	0x00, 0x00,	/* IP v4 */
		0x00, 0x00, 0x00, 0x32, 0x00, 0x00,
		0x02, 0x02, 0x02, 0x02,			/* IP src */
		0x00, 0x00, 0x00, 0x00,			/* IP dst */
		0x00, 0x00, 0x00, 0x00,			/* SPI */
		0x00, 0x00, 0x00, 0x00,			/* ESN */
		0x00, 0x00, 0x00, 0x00,			/* IV */
		0x00, 0x00, 0x00, 0x00,
	};

	int result;

	memset(&crypto_cfg, 0, sizeof(crypto_cfg));
	memset(&cfg, 0, sizeof(cfg));

	/* dst IP was already converted to big endian */
	reformat_encap_data[ENCAP_DST_IP_IDX] = GET_BYTE(rule.encap_dst_ip, 0);
	reformat_encap_data[ENCAP_DST_IP_IDX + 1] = GET_BYTE(rule.encap_dst_ip, 1);
	reformat_encap_data[ENCAP_DST_IP_IDX + 2] = GET_BYTE(rule.encap_dst_ip, 2);
	reformat_encap_data[ENCAP_DST_IP_IDX + 3] = GET_BYTE(rule.encap_dst_ip, 3);

	reformat_encap_data[ENCAP_ESP_SPI_IDX] = GET_BYTE(rule.esp_spi, 3);
	reformat_encap_data[ENCAP_ESP_SPI_IDX + 1] = GET_BYTE(rule.esp_spi, 2);
	reformat_encap_data[ENCAP_ESP_SPI_IDX + 2] = GET_BYTE(rule.esp_spi, 1);
	reformat_encap_data[ENCAP_ESP_SPI_IDX + 3] = GET_BYTE(rule.esp_spi, 0);

	crypto_cfg.proto_type = DOCA_FLOW_CRYPTO_PROTOCOL_ESP_ENCRYPT;
	crypto_cfg.action_type = DOCA_FLOW_CRYPTO_ACTION_ENCRYPT;
	crypto_cfg.reformat_type = DOCA_FLOW_CRYPTO_REFORMAT_ENCAP;
	crypto_cfg.net_type = DOCA_FLOW_CRYPTO_NET_TUNNEL;
	crypto_cfg.header_type = DOCA_FLOW_CRYPTO_HEADER_NONE;
	crypto_cfg.security_ctx = sa;
	crypto_cfg.fwd.type = DOCA_FLOW_FWD_NONE; /* fwd encrypted packets to the wire */
	memcpy(crypto_cfg.reformat_data, reformat_encap_data, sizeof(reformat_encap_data));
	crypto_cfg.reformat_data_sz = sizeof(reformat_encap_data);

	cfg.crypto_cfg = crypto_cfg;

	/* config ipsec object */
	result = doca_flow_shared_resource_cfg(DOCA_FLOW_SHARED_RESOURCE_CRYPTO, ipsec_id, &cfg, &error);
	if (result != 0) {
		DOCA_LOG_ERR("Failed to cfg shared ipsec object - %s (%u)", error.message, error.type);
		return -1;
	}
	/* bind shared ipsec encrypt object to port */
	result = doca_flow_shared_resources_bind(DOCA_FLOW_SHARED_RESOURCE_CRYPTO, &ipsec_id, 1, port, &error);
	if (result != 0) {
		DOCA_LOG_ERR("Failed to bind shared ipsec object to port - %s (%u)", error.message, error.type);
		return -1;
	}
	return 0;
}

/*
 * Config and bind shared IPSEC object for decryption
 *
 * @port [in]: port to bind the shared object to
 * @sa [in]: crypto object handle (IPsec offload object)
 * @ipsec_id [in]: shared object ID
 * @syndrome_pipe [in]: next pipe to forward the decrypted packets to
 * @return: 0 on success and negative value otherwise
 */
static int
create_ipsec_decrypt_shared_object(struct doca_flow_port *port, void *sa, uint32_t ipsec_id,
				   struct doca_flow_pipe *syndrome_pipe)
{
	struct doca_flow_shared_resource_cfg cfg;
	struct doca_flow_resource_crypto_cfg crypto_cfg;
	struct doca_flow_error error;
	uint8_t reformat_decap_data[14] = {
		0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,	/* mac_dst */
		0x11, 0x22, 0x33, 0x44, 0x55, 0x66,	/* mac_src */
		0x08, 0x00				/* mac_type */
	};
	int result;

	memset(&crypto_cfg, 0, sizeof(crypto_cfg));
	memset(&cfg, 0, sizeof(cfg));

	crypto_cfg.proto_type = DOCA_FLOW_CRYPTO_PROTOCOL_ESP_DECRYPT;
	crypto_cfg.action_type = DOCA_FLOW_CRYPTO_ACTION_DECRYPT;
	crypto_cfg.reformat_type = DOCA_FLOW_CRYPTO_REFORMAT_DECAP;
	crypto_cfg.net_type = DOCA_FLOW_CRYPTO_NET_TUNNEL;
	crypto_cfg.header_type = DOCA_FLOW_CRYPTO_HEADER_NONE;
	crypto_cfg.security_ctx = sa;
	crypto_cfg.fwd.type = DOCA_FLOW_FWD_PIPE; /* fwd decrypted packets to check the syndrome */
	crypto_cfg.fwd.next_pipe = syndrome_pipe;
	memcpy(crypto_cfg.reformat_data, reformat_decap_data, sizeof(reformat_decap_data));
	crypto_cfg.reformat_data_sz = sizeof(reformat_decap_data);

	cfg.crypto_cfg = crypto_cfg;

	/* config ipsec object */
	result = doca_flow_shared_resource_cfg(DOCA_FLOW_SHARED_RESOURCE_CRYPTO, ipsec_id, &cfg, &error);
	if (result != 0) {
		DOCA_LOG_ERR("Failed to cfg shared ipsec object - %s (%u)", error.message, error.type);
		return -1;
	}
	/* bind shared ipsec decrypt object to port */
	result = doca_flow_shared_resources_bind(DOCA_FLOW_SHARED_RESOURCE_CRYPTO, &ipsec_id, 1, port, &error);
	if (result != 0) {
		DOCA_LOG_ERR("Failed to bind shared ipsec object to port - %s (%u)", error.message, error.type);
		return -1;
	}
	return 0;
}

/*
 * Add encryption entries to the encrypt pipes:
 * - 5 tuple rule in the TCP / UDP pipe with specific set meta data value (shared obj ID)
 * - specific meta data match on encryption pipe (shared obj ID) with shared object ID in actions
 *
 * @rules [in]: array of rules to insert for encryption
 * @nb_rules [in]: number of rules
 * @encryption_pipe [in]: encryption pipe to add the entries to
 * @tcp_pipe [in]: TCP pipe to add the entries to
 * @udp_pipe [in]: UDP pipe to add the entries to
 * @ports [in]: array of ports
 * @sa [in]: crypto object handle (IPsec offload object)
 * @return: 0 on success and negative value otherwise
 */
static int
add_encrypt_entries(struct encrypt_rule *rules, int nb_rules, struct doca_flow_pipe *encryption_pipe,
		    struct doca_flow_pipe *tcp_pipe, struct doca_flow_pipe *udp_pipe,
		    struct security_gateway_ports_map **ports, void *sa)
{
	struct doca_flow_match match;
	struct doca_flow_actions actions;
	struct doca_flow_pipe *pipe;
	struct doca_flow_pipe_entry *entry;
	struct doca_flow_error error;
	bool is_failure = false;
	int nb_entries;
	int i;
	int result;

	memset(&match, 0, sizeof(match));
	memset(&actions, 0, sizeof(actions));

	match.out_dst_ip.type = DOCA_FLOW_IP4_ADDR;
	match.out_src_ip.type = DOCA_FLOW_IP4_ADDR;

	for (i = 0; i < nb_rules; i++) {
		/* build 5-tuple rule match */
		if (rules[i].protocol == IPPROTO_TCP)
			pipe = tcp_pipe;
		else
			pipe = udp_pipe;
		match.out_l4_type = rules[i].protocol;
		match.out_dst_ip.ipv4_addr = rules[i].dst_ip;
		match.out_src_ip.ipv4_addr = rules[i].src_ip;
		match.out_dst_port = rte_cpu_to_be_16(rules[i].dst_port);
		match.out_src_port = rte_cpu_to_be_16(rules[i].src_port);

		/* set meta value */
		actions.meta.pkt_meta = i;
		actions.action_idx = 0;

		/* add entry to hairpin pipe*/
		entry = doca_flow_pipe_add_entry(0, pipe, &match, &actions, NULL, NULL, DOCA_FLOW_NO_WAIT, (void *)&is_failure, &error);
		if (entry == NULL) {
			DOCA_LOG_ERR("Failed to add pipe entry - %s (%u)", error.message, error.type);
			return -1;
		}

		/* create ipsec shared object */
		result = create_ipsec_encrypt_shared_object(ports[SECURED_IDX]->port, sa, i, rules[i]);
		if (result < 0)
			return result;

		memset(&match, 0, sizeof(match));

		match.meta.pkt_meta = i;

		actions.action_idx = 0;
		actions.security.crypto_id = i;
		/* add entry to encrypt pipe*/
		entry = doca_flow_pipe_add_entry(0, encryption_pipe, &match, &actions, NULL, NULL, DOCA_FLOW_NO_WAIT, (void *)&is_failure, &error);
		if (entry == NULL) {
			DOCA_LOG_ERR("Failed to add pipe entry - %s (%u)", error.message, error.type);
			return -1;
		}
	}
	/* process the entries in the encryption pipe*/
	nb_entries = nb_rules;
	do {
		result = doca_flow_entries_process(ports[SECURED_IDX]->port, 0, DEFAULT_TIMEOUT_US, nb_entries);
		if (result < 0 || is_failure) {
			DOCA_LOG_ERR("Failed to process entries");
			return -1;
		}
		nb_entries -= result;
	} while (nb_entries > 0);

	/* process the entries in TCP and UDP pipes */
	nb_entries = nb_rules;
	do {
		result = doca_flow_entries_process(ports[UNSECURED_IDX]->port, 0, DEFAULT_TIMEOUT_US, nb_entries);
		if (result < 0 || is_failure) {
			DOCA_LOG_ERR("Failed to process entries");
			return -1;
		}
		nb_entries -= result;
	} while (nb_entries > 0);
	return 0;
}

/*
 * Add decryption entries to the decrypt pipe
 *
 * @rules [in]: array of rules to insert for decryption
 * @nb_rules [in]: number of rules in array
 * @pipe [in]: decryption pipe to add the entries to
 * @nb_encrypt_rules [in]: number of initalized shared ipsec objects
 * @port [in]: port of the entries
 * @sa [in]: crypto object handle (IPsec offload object)
 * @syndrome_pipe [in]: next pipe to forward the decrypted packets to
 * @return: 0 on success and negative value otherwise
 */
static int
add_decrypt_entries(struct decrypt_rule *rules, int nb_rules, struct doca_flow_pipe *pipe, int nb_encrypt_rules,
		    struct doca_flow_port *port, void *sa, struct doca_flow_pipe *syndrome_pipe)
{
	struct doca_flow_match match;
	struct doca_flow_actions actions;
	struct doca_flow_pipe_entry *entry;
	struct doca_flow_error error;
	bool is_failure = false;
	int nb_entries;
	int i;
	int result;

	memset(&match, 0, sizeof(match));
	memset(&actions, 0, sizeof(actions));

	match.out_dst_ip.type = DOCA_FLOW_IP4_ADDR;
	match.tun.type = DOCA_FLOW_TUN_ESP;

	/* create ipsec shared object */
	result = create_ipsec_decrypt_shared_object(port, sa, nb_encrypt_rules, syndrome_pipe);
	if (result < 0)
		return result;

	for (i = 0; i < nb_rules; i++) {

		/* build rule match with specific destination IP and ESP SPI */
		match.out_dst_ip.ipv4_addr = rules[i].dst_ip;
		match.tun.esp_spi = RTE_BE32(rules[i].esp_spi);

		/* decryption crypto IDs will start in nb_encrypt_rules */
		actions.action_idx = 0;
		actions.security.crypto_id = nb_encrypt_rules;

		entry = doca_flow_pipe_add_entry(0, pipe, &match, &actions, NULL, NULL, DOCA_FLOW_NO_WAIT, NULL, &error);
		if (entry == NULL) {
			DOCA_LOG_ERR("Failed to add pipe entry - %s (%u)", error.message, error.type);
			return -1;
		}
	}

	/* process the entries in the decryption pipe*/
	nb_entries = nb_rules;
	do {
		result = doca_flow_entries_process(port, 0, DEFAULT_TIMEOUT_US, nb_entries);
		if (result < 0 || is_failure) {
			DOCA_LOG_ERR("Failed to process entries");
			return -1;
		}
		nb_entries -= result;
	} while (nb_entries > 0);
	return 0;
}

int
security_gateway_insert_encrypt_rules(struct security_gateway_ports_map *ports[], struct encrypt_rule *rules,
				      int nb_rules, struct doca_ipsec_sa *sa, enum security_gateway_offload_mode mode, int nb_queues)
{
	struct doca_flow_pipe *encryption_pipe;
	struct doca_flow_pipe *tcp_pipe;
	struct doca_flow_pipe *udp_pipe;
	struct doca_flow_pipe *control_pipe;
	int result;


	result = create_ipsec_encrypt_pipe(ports[SECURED_IDX]->port, &encryption_pipe);
	if (result < 0)
		return result;

	result = create_ipsec_hairpin_pipe(ports[UNSECURED_IDX]->port, ports[UNSECURED_IDX]->port_id, DOCA_PROTO_TCP, mode, nb_queues, &tcp_pipe);
	if (result < 0) {
		DOCA_LOG_ERR("Failed create TCP hairpin pipe");
		return result;
	}

	result = create_ipsec_hairpin_pipe(ports[UNSECURED_IDX]->port, ports[UNSECURED_IDX]->port_id, DOCA_PROTO_UDP, mode, nb_queues, &udp_pipe);
	if (result < 0) {
		DOCA_LOG_ERR("Failed create UDP hairpin pipe");
		return result;
	}

	result = create_control_pipe(ports[UNSECURED_IDX]->port, &control_pipe);
	if (result < 0)
		return result;

	result = add_control_pipe_entries(control_pipe, tcp_pipe, udp_pipe);
	if (result < 0)
		return result;

	result = add_encrypt_entries(rules, nb_rules, encryption_pipe, tcp_pipe, udp_pipe, ports, (void *)sa);
	if (result < 0)
		return result;

	return 0;
}

int
security_gateway_insert_decrypt_rules(struct security_gateway_ports_map *port, struct decrypt_rule *rules,
					int nb_rules, int nb_encrypt_rules, struct doca_ipsec_sa *sa,
					enum security_gateway_offload_mode mode, int nb_queues)
{
	struct doca_flow_pipe *syndrome_pipe;
	struct doca_flow_pipe *decrypt_pipe;
	int result;

	result = create_ipsec_syndrome_pipe(port->port, port->port_id, mode, nb_queues, &syndrome_pipe);
	if (result < 0)
		return result;

	result = create_ipsec_decrypt_pipe(port->port, &decrypt_pipe);
	if (result < 0)
		return result;

	result = add_decrypt_entries(rules, nb_rules, decrypt_pipe, nb_encrypt_rules, port->port, (void *)sa, syndrome_pipe);
	if (result < 0)
		return result;

	return 0;
}

/*
 * Parse protocol type from json object rule
 *
 * @cur_rule [in]: json object of the current rule to parse
 * @protocol [out]: the parsed protocol value
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
create_protocol(struct json_object *cur_rule, uint8_t *protocol)
{
	doca_error_t result;
	struct json_object *json_protocol;
	const char *protocol_str;

	if (!json_object_object_get_ex(cur_rule, "protocol", &json_protocol)) {
		DOCA_LOG_ERR("Missing protocol type");
		return DOCA_ERROR_INVALID_VALUE;
	}
	if (json_object_get_type(json_protocol) != json_type_string) {
		DOCA_LOG_ERR("Expecting a string value for \"protocol\"");
		return DOCA_ERROR_INVALID_VALUE;
	}

	protocol_str = json_object_get_string(json_protocol);
	result = parse_protocol_string(protocol_str, protocol);
	if (result != DOCA_SUCCESS)
		return result;
	return DOCA_SUCCESS;
}

/*
 * Parse IP from json object rule
 *
 * @cur_rule [in]: json object of the current rule to parse
 * @ip_type [in]: src-ip/dst-ip/encap-dst-ip
 * @ip [out]: the parsed dst_ip value
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
create_ip(struct json_object *cur_rule, char *ip_type, doca_be32_t *ip)
{
	doca_error_t result;
	struct json_object *json_ip;

	if (!json_object_object_get_ex(cur_rule, ip_type, &json_ip)) {
		DOCA_LOG_ERR("Missing %s", ip_type);
		return DOCA_ERROR_INVALID_VALUE;
	}
	if (json_object_get_type(json_ip) != json_type_string) {
		DOCA_LOG_ERR("Expecting a string value for \"%s\"", ip_type);
		return DOCA_ERROR_INVALID_VALUE;
	}

	result = parse_ipv4_str(json_object_get_string(json_ip), ip);
	if (result != DOCA_SUCCESS)
		return result;
	return DOCA_SUCCESS;
}

/*
 * Parse port from json object rule
 *
 * @cur_rule [in]: json object of the current rule to parse
 * @port_type [in]: src-port/dst-port
 * @port [out]: the parsed src_port value
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
create_port(struct json_object *cur_rule, char *port_type, int *port)
{
	struct json_object *json_port;

	if (!json_object_object_get_ex(cur_rule, port_type, &json_port)) {
		DOCA_LOG_ERR("Missing %s", port_type);
		return DOCA_ERROR_INVALID_VALUE;
	}
	if (json_object_get_type(json_port) != json_type_int) {
		DOCA_LOG_ERR("Expecting a int value for \"%s\"", port_type);
		return DOCA_ERROR_INVALID_VALUE;
	}

	*port = json_object_get_int(json_port);
	return DOCA_SUCCESS;
}

/*
 * Parse SPI from json object rule
 *
 * @cur_rule [in]: json object of the current rule to parse
 * @esp_spi [out]: the parsed esp_spi value
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
create_spi(struct json_object *cur_rule, doca_be32_t *esp_spi)
{
	struct json_object *json_spi;

	if (!json_object_object_get_ex(cur_rule, "spi", &json_spi)) {
		DOCA_LOG_ERR("Missing spi");
		return DOCA_ERROR_INVALID_VALUE;
	}
	if (json_object_get_type(json_spi) != json_type_int) {
		DOCA_LOG_ERR("Expecting a int value for \"spi\"");
		return DOCA_ERROR_INVALID_VALUE;
	}

	*esp_spi = json_object_get_int(json_spi);
	return DOCA_SUCCESS;
}

/*
 * Parse json object of the decryption rules and set it in decrypt_rules array
 *
 * @json_rules [in]: json object of the rules to parse
 * @nb_decrypt_rules [out]: number of parsed rules
 * @decrypt_rules [out]: parsed rules in array
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
parse_json_decrypt_rules(struct json_object *json_rules, int *nb_decrypt_rules, struct decrypt_rule **decrypt_rules)
{
	int i;
	doca_error_t result;
	struct json_object *cur_rule;
	struct decrypt_rule *rules_arr = NULL;

	*nb_decrypt_rules = json_object_array_length(json_rules);

	DOCA_LOG_DBG("num of rules in input file: %d", *nb_decrypt_rules);

	rules_arr = (struct decrypt_rule *)calloc(*nb_decrypt_rules, sizeof(struct decrypt_rule));
	if (rules_arr == NULL) {
		DOCA_LOG_ERR("calloc() function failed");
		return DOCA_ERROR_NO_MEMORY;
	}

	for (i = 0; i < *nb_decrypt_rules; i++) {
		cur_rule = json_object_array_get_idx(json_rules, i);
		result = create_ip(cur_rule, "dst-ip", &rules_arr[i].dst_ip);
		if (result != DOCA_SUCCESS) {
			free(rules_arr);
			return result;
		}
		result = create_spi(cur_rule, &rules_arr[i].esp_spi);
		if (result != DOCA_SUCCESS) {
			free(rules_arr);
			return result;
		}
	}
	*decrypt_rules = rules_arr;
	return DOCA_SUCCESS;
}

/*
 * Parse json object of the encryption rules and set it in encrypt_rules array
 *
 * @json_rules [in]: json object of the rules to parse
 * @nb_encrypt_rules [out]: number of parsed rules
 * @encrypt_rules [out]: parsed rules in array
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
parse_json_encrypt_rules(struct json_object *json_rules, int *nb_encrypt_rules, struct encrypt_rule **encrypt_rules)
{
	int i;
	doca_error_t result;
	struct json_object *cur_rule;
	struct encrypt_rule *rules_arr = NULL;

	*nb_encrypt_rules = json_object_array_length(json_rules);

	DOCA_LOG_DBG("num of rules in input file: %d", *nb_encrypt_rules);

	rules_arr = (struct encrypt_rule *)calloc(*nb_encrypt_rules, sizeof(struct encrypt_rule));
	if (rules_arr == NULL) {
		DOCA_LOG_ERR("calloc() function failed");
		return DOCA_ERROR_NO_MEMORY;
	}

	for (i = 0; i < *nb_encrypt_rules; i++) {
		cur_rule = json_object_array_get_idx(json_rules, i);
		result = create_protocol(cur_rule, &rules_arr[i].protocol);
		if (result != DOCA_SUCCESS) {
			free(rules_arr);
			return result;
		}
		result = create_ip(cur_rule, "src-ip", &rules_arr[i].src_ip);
		if (result != DOCA_SUCCESS) {
			free(rules_arr);
			return result;
		}
		result = create_ip(cur_rule, "dst-ip", &rules_arr[i].dst_ip);
		if (result != DOCA_SUCCESS) {
			free(rules_arr);
			return result;
		}
		result = create_port(cur_rule, "src-port", &rules_arr[i].src_port);
		if (result != DOCA_SUCCESS) {
			free(rules_arr);
			return result;
		}
		result = create_port(cur_rule, "dst-port", &rules_arr[i].dst_port);
		if (result != DOCA_SUCCESS) {
			free(rules_arr);
			return result;
		}
		result = create_ip(cur_rule, "encap-dst-ip", &rules_arr[i].encap_dst_ip);
		if (result != DOCA_SUCCESS) {
			free(rules_arr);
			return result;
		}
		result = create_spi(cur_rule, &rules_arr[i].esp_spi);
		if (result != DOCA_SUCCESS) {
			free(rules_arr);
			return result;
		}
	}
	*encrypt_rules = rules_arr;
	return DOCA_SUCCESS;
}

/*
 * Check the input file size and allocate a buffer to read it
 *
 * @fp [in]: file pointer to the input rules file
 * @file_length [out]: total bytes in file
 * @json_data [out]: allocated buffer
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
allocate_json_buffer_dynamic(FILE *fp, size_t *file_length, char **json_data)
{
	ssize_t buf_len = 0;

	/* use fseek to put file counter to the end, and calculate file length */
	if (fseek(fp, 0L, SEEK_END) == 0) {
		buf_len = ftell(fp);
		if (buf_len < 0) {
			DOCA_LOG_ERR("ftell() function failed");
			return DOCA_ERROR_IO_FAILED;
		}

		/* dynamic allocation */
		*json_data = (char *)malloc(buf_len + 1);
		if (*json_data == NULL) {
			DOCA_LOG_ERR("malloc() function failed");
			return DOCA_ERROR_NO_MEMORY;
		}

		/* return file counter to the beginning */
		if (fseek(fp, 0L, SEEK_SET) != 0) {
			free(*json_data);
			*json_data = NULL;
			DOCA_LOG_ERR("fseek() function failed");
			return DOCA_ERROR_IO_FAILED;
		}
	}
	*file_length = buf_len;
	return DOCA_SUCCESS;
}

doca_error_t
security_gateway_parse_rules(char *file_path, int *nb_encrypt_rules, struct encrypt_rule **encrypt_rules,
			int *nb_decrypt_rules, struct decrypt_rule **decrypt_rules)
{
	FILE *json_fp;
	size_t file_length;
	char *json_data = NULL;
	struct json_object *parsed_json;
	struct json_object *json_encrypt_rules;
	struct json_object *json_decrypt_rules;
	doca_error_t result;

	json_fp = fopen(file_path, "r");
	if (json_fp == NULL) {
		DOCA_LOG_ERR("JSON file open failed");
		return DOCA_ERROR_IO_FAILED;
	}

	result = allocate_json_buffer_dynamic(json_fp, &file_length, &json_data);
	if (result != DOCA_SUCCESS) {
		fclose(json_fp);
		DOCA_LOG_ERR("Failed to allocate data buffer for the json file");
		return result;
	}

	if (fread(json_data, file_length, 1, json_fp) < file_length)
		DOCA_LOG_DBG("EOF reached");
	fclose(json_fp);

	parsed_json = json_tokener_parse(json_data);
	if (!json_object_object_get_ex(parsed_json, "encrypt_rules", &json_encrypt_rules)) {
		DOCA_LOG_ERR("missing \"encrypt_rules\" parameter");
		free(json_data);
		return DOCA_ERROR_INVALID_VALUE;
	}

	if (!json_object_object_get_ex(parsed_json, "decrypt_rules", &json_decrypt_rules)) {
		DOCA_LOG_ERR("missing \"decrypt_rules\" parameter");
		free(json_data);
		return DOCA_ERROR_INVALID_VALUE;
	}

	free(json_data);

	result = parse_json_encrypt_rules(json_encrypt_rules, nb_encrypt_rules, encrypt_rules);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to parse encrypt rules");
		return result;
	}
	result = parse_json_decrypt_rules(json_decrypt_rules, nb_decrypt_rules, decrypt_rules);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to parse decrypt rules");
		free(*encrypt_rules);
		return result;
	}
	return DOCA_SUCCESS;
}

/*
 * ARGP Callback - Handle DOCA device PCI address parameter for secured port
 *
 * @param [in]: Input parameter
 * @config [in/out]: Program configuration context
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
secured_callback(void *param, void *config)
{
	doca_error_t result;
	struct security_gateway_config *app_cfg = (struct security_gateway_config *)config;
	char *pci_addr = (char *)param;

	result = parse_pci_addr(pci_addr, &app_cfg->secured_pci_addr);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Invalid PCI address: %s", doca_get_error_string(result));
		return result;
	}
	return DOCA_SUCCESS;
}

/*
 * ARGP Callback - Handle DOCA device PCI address parameter for unsecured port
 *
 * @param [in]: Input parameter
 * @config [in/out]: Program configuration context
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
unsecured_callback(void *param, void *config)
{
	struct security_gateway_config *app_cfg = (struct security_gateway_config *)config;
	char *pci_addr = (char *)param;
	doca_error_t result;

	result = parse_pci_addr(pci_addr, &app_cfg->unsecured_pci_addr);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Invalid PCI address: %s", doca_get_error_string(result));
		return result;
	}
	return DOCA_SUCCESS;
}

/*
 * ARGP Callback - Handle rules file parameter
 *
 * @param [in]: Input parameter
 * @config [in/out]: Program configuration context
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
rules_callback(void *param, void *config)
{
	struct security_gateway_config *app_cfg = (struct security_gateway_config *)config;
	const char *json_path = (char *)param;

	if (strnlen(json_path, MAX_FILE_NAME) == MAX_FILE_NAME) {
		DOCA_LOG_ERR("JSON file name is too long - MAX=%d", MAX_FILE_NAME - 1);
		return DOCA_ERROR_INVALID_VALUE;
	}
	if (access(json_path, F_OK) == -1) {
		DOCA_LOG_ERR("JSON file was not found %s", json_path);
		return DOCA_ERROR_NOT_FOUND;
	}
	strlcpy(app_cfg->json_path, json_path, MAX_FILE_NAME);
	return DOCA_SUCCESS;
}

/*
 * ARGP Callback - Handle application offload mode
 *
 * @param [in]: Input parameter
 * @config [in/out]: Program configuration context
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
offload_mode_callback(void *param, void *config)
{
	struct security_gateway_config *app_cfg = (struct security_gateway_config *)config;
	const char *mode = (char *)param;

	if (strcmp(mode, "full") == 0)
		app_cfg->mode = SECURITY_GATEWAY_FULL_OFFLOAD;
	else if (strcmp(mode, "partial") == 0)
		app_cfg->mode = SECURITY_GATEWAY_PARTIAL_OFFLOAD;
	else {
		DOCA_LOG_ERR("Illegal running mode = [%s]", mode);
		return DOCA_ERROR_INVALID_VALUE;
	}

	return DOCA_SUCCESS;
}

doca_error_t
register_security_gateway_params()
{
	doca_error_t result;
	struct doca_argp_param *secured_param, *unsecured_param, *rules_param, *offload_mode;

	/* Create and register ingress pci param */
	result = doca_argp_param_create(&secured_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create ARGP param: %s", doca_get_error_string(result));
		return result;
	}
	doca_argp_param_set_short_name(secured_param, "s");
	doca_argp_param_set_long_name(secured_param, "secured");
	doca_argp_param_set_description(secured_param, "secured port pci-address");
	doca_argp_param_set_callback(secured_param, secured_callback);
	doca_argp_param_set_type(secured_param, DOCA_ARGP_TYPE_STRING);
	doca_argp_param_set_mandatory(secured_param);
	result = doca_argp_register_param(secured_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to register program param: %s", doca_get_error_string(result));
		return result;
	}

	/* Create and register egress pci param */
	result = doca_argp_param_create(&unsecured_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create ARGP param: %s", doca_get_error_string(result));
		return result;
	}
	doca_argp_param_set_short_name(unsecured_param, "u");
	doca_argp_param_set_long_name(unsecured_param, "unsecured");
	doca_argp_param_set_description(unsecured_param, "unsecured port pci-address");
	doca_argp_param_set_callback(unsecured_param, unsecured_callback);
	doca_argp_param_set_type(unsecured_param, DOCA_ARGP_TYPE_STRING);
	doca_argp_param_set_mandatory(unsecured_param);
	result = doca_argp_register_param(unsecured_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to register program param: %s", doca_get_error_string(result));
		return result;
	}

	/* Create and register json rules param */
	result = doca_argp_param_create(&rules_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create ARGP param: %s", doca_get_error_string(result));
		return result;
	}
	doca_argp_param_set_short_name(rules_param, "r");
	doca_argp_param_set_long_name(rules_param, "rules");
	doca_argp_param_set_description(rules_param, "Path to the JSON file with 5-tuple rules");
	doca_argp_param_set_callback(rules_param, rules_callback);
	doca_argp_param_set_type(rules_param, DOCA_ARGP_TYPE_STRING);
	doca_argp_param_set_mandatory(rules_param);
	result = doca_argp_register_param(rules_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to register program param: %s", doca_get_error_string(result));
		return result;
	}

	/* Create and register offload mode param */
	result = doca_argp_param_create(&offload_mode);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create ARGP param: %s", doca_get_error_string(result));
		return result;
	}
	doca_argp_param_set_short_name(offload_mode, "o");
	doca_argp_param_set_long_name(offload_mode, "offload");
	doca_argp_param_set_description(offload_mode, "offload mode - {partial/full}");
	doca_argp_param_set_callback(offload_mode, offload_mode_callback);
	doca_argp_param_set_type(offload_mode, DOCA_ARGP_TYPE_STRING);
	doca_argp_param_set_mandatory(offload_mode);
	result = doca_argp_register_param(offload_mode);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to register program param: %s", doca_get_error_string(result));
		return result;
	}

	/* Register version callback for DOCA SDK & RUNTIME */
	result = doca_argp_register_version_callback(sdk_version_callback);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to register version callback: %s", doca_get_error_string(result));
		return result;
	}

	return result;
}
