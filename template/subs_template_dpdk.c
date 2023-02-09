#include <rte_ethdev.h>

#include <doca_log.h>

#include "flow_pipes_manager.h"
#include "offload_rules.h"

#include "subs_template.h"

DOCA_LOG_REGISTER(SUBS_TEMPLATE::Utils);

#define PACKET_BURST 128			/* The number of packets in the rx queue */
#define MAX_PORT_STR_LEN 128	   /* Maximal length of port name */
#define DEFAULT_TIMEOUT_US (10000) /* Timeout for processing pipe entries */

static struct flow_pipes_manager *pipes_manager;
extern bool force_quit;

/*
 * The main function for handling the new received packets
 *
 * @worker_ctx [in]: a pointer to DNS worker configuration struct
 * @packets_received [in]: size of mbufs array
 * @packets [in]: array of packets
 * @return: 0 on success and negative value otherwise
 */
static int _handle_packets_received(struct subs_template_worker_ctx *worker_ctx, uint16_t packets_received, struct rte_mbuf **packets){
	// TODO: add your packet processing logic here
	return 0;
}

void fill_application_dpdk_config(struct application_dpdk_config *dpdk_cfg){
	dpdk_cfg->port_config.nb_ports = 2;
	dpdk_cfg->port_config.nb_queues = 2;
	dpdk_cfg->port_config.nb_hairpin_q = 4;
	dpdk_cfg->reserve_main_thread = true;
	DOCA_LOG_DBG("dpdk config with %d ports", dpdk_cfg->port_config.nb_ports);
	DOCA_LOG_DBG("dpdk config with %d queues", dpdk_cfg->port_config.nb_queues);
	DOCA_LOG_DBG("dpdk config with %d hairpin queues", dpdk_cfg->port_config.nb_hairpin_q);
	if(dpdk_cfg->reserve_main_thread)
		DOCA_LOG_DBG("dpdk config with reserve_main_thread");
}

/*
 * Dequeue packets from DPDK queue, queue id equals to worker_ctx->queue_id, and send them for APP processing
 *
 * @worker_ctx [in]: a pointer to DNS worker configuration struct
 * @ingress_port [in]: port id for dequeue packets
 * @return: 0 on success and negative value otherwise
 */
static int _process_packets(struct subs_template_worker_ctx *worker_ctx, int ingress_port){
	struct rte_mbuf *packets[PACKET_BURST];
	int nb_packets = rte_eth_rx_burst(ingress_port, worker_ctx->queue_id, packets, PACKET_BURST);
	int result;
	
	/* Handle the received packets from a queue with id = worker_ctx->queue_id */
	if (nb_packets) {
		DOCA_DLOG_DBG("Received %d packets from port 0x%x using core %u", nb_packets, ingress_port, rte_lcore_id());
		result = _handle_packets_received(worker_ctx, nb_packets, packets);
		if (result < 0)
			return result;
	}
	return 0;
}

static void subs_template_worker(void *args){
	struct subs_template_worker_ctx *worker_ctx = (struct subs_template_worker_ctx *)args;
	int ingress_port, nb_ports = worker_ctx->app_cfg->dpdk_cfg->port_config.nb_ports;
	int result;

	DOCA_LOG_DBG("Core %u is receiving packets.", rte_lcore_id());

	while (!force_quit) {
		for (ingress_port = 0; ingress_port < nb_ports; ingress_port++) {
			result = _process_packets(worker_ctx, ingress_port);
			if (result < 0) {
				force_quit = true;
				break;
			}
		}
	}

	rte_free(worker_ctx);
}

doca_error_t subs_template_lcores_run(struct subs_template_cfg *app_cfg){
	uint16_t lcore_index = 0;
	int current_lcore = 0, nb_queues = app_cfg->dpdk_cfg->port_config.nb_queues;
	struct subs_template_worker_ctx *worker_ctx = NULL;
	doca_error_t result;

	DOCA_LOG_INFO("%d cores are used as workers", nb_queues);

	/* Init subs_template workers to start processing packets */
	while ((current_lcore < RTE_MAX_LCORE) && (lcore_index < nb_queues)) {
		current_lcore = rte_get_next_lcore(current_lcore, true, false);

		worker_ctx = (struct subs_template_worker_ctx*)rte_zmalloc(
			NULL, sizeof(struct subs_template_worker_ctx), 0);
		if (worker_ctx == NULL) {
			DOCA_LOG_ERR("RTE malloc failed");
			force_quit = true;
			return DOCA_ERROR_NO_MEMORY;
		}
		worker_ctx->app_cfg = app_cfg;
		worker_ctx->queue_id = lcore_index;

		if (rte_eal_remote_launch((void *)subs_template_worker, (void *)worker_ctx, current_lcore) != 0) {
			DOCA_LOG_ERR("Remote launch failed");
			result = DOCA_ERROR_DRIVER;
			goto destroy_worker_ctx;	// May need to be modified
		}

		worker_ctx++;
		lcore_index++;
	}

	return DOCA_SUCCESS;

destroy_worker_ctx:
	rte_free(worker_ctx);
	force_quit = true;
	return result;
}