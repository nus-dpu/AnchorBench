#include <rte_ethdev.h>
#include <rte_spinlock.h>

#include <doca_log.h>

#include "flow_pipes_manager.h"
#include "offload_rules.h"

#include "cm_sketch.h"

DOCA_LOG_REGISTER(CM_SKETCH::Utils);

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
static int _handle_packets_received(struct cm_sketch_worker_ctx *worker_ctx, uint16_t packets_received, struct rte_mbuf **packets){
	uint8_t i = 0;
	uint32_t pkt_index = 0;
	uint8_t merged_smac = 0, merged_dmac = 0, merged_sip = 0, merged_dip = 0; 
	uint32_t ip_mask = 0x11111111;
	uint64_t hash_src = 0, hash_result = 0;
	uint64_t a, b, prime;
	uint64_t counter_value = 0;
	uint64_t row_index = 0;

	for(pkt_index=0; pkt_index<packets_received; pkt_index += 1){
		/* extract fields */
		struct rte_ether_hdr* eth_addr 
			= rte_pktmbuf_mtod_offset(packets[pkt_index], struct rte_ether_hdr*, 0);
		struct rte_ipv4_hdr* ipv4_addr 
			= rte_pktmbuf_mtod_offset(packets[pkt_index], struct rte_ipv4_hdr*, RTE_ETHER_HDR_LEN);
		struct rte_udp_hdr* udp_addr 
			= rte_pktmbuf_mtod_offset(
				packets[pkt_index], struct rte_udp_hdr*, RTE_ETHER_HDR_LEN+rte_ipv4_hdr_len(ipv4_addr));

		/* merge mac address */
		for(i=0; i<RTE_ETHER_ADDR_LEN; i++) {
			merged_smac ^= eth_addr->s_addr.addr_bytes[i];
			merged_dmac ^= eth_addr->d_addr.addr_bytes[i];
		}

		/* merge ipv4 address */
		for(i=0; i<4; i++) {
			merged_sip ^= (ipv4_addr->src_addr & ip_mask);
			merged_dip ^= (ipv4_addr->dst_addr & ip_mask);
			ip_mask = ip_mask << 8;
		}
		
		/* calculate hash source */
		hash_src = merged_smac + merged_dmac + merged_sip + merged_dip + udp_addr->src_port + udp_addr->dst_port;
		prime = worker_ctx->app_cfg->prime;
		if(hash_src >= prime){
			DOCA_LOG_DBG("hash source is larger than the selected prime, abandon updating");
			continue;
		}

		/* calculate hash result */
		for(row_index=0; row_index<NB_ROWS; row_index++){
			a = worker_ctx->app_cfg->pairwise_hash_family[row_index]->a;
			b = worker_ctx->app_cfg->pairwise_hash_family[row_index]->b;
			hash_result = ((a*hash_src+b) % prime) % NB_COUNTER;

			/* update counter */
			rte_spinlock_lock(&worker_ctx->app_cfg->cm_sketch_lock);
			counter_value = worker_ctx->app_cfg->cm_sketch[row_index][hash_result];
			if(counter_value == (1<<64)){
				DOCA_LOG_DBG("counter locate at [%ld][%ld] is overflowed, abandon updating", row_index, hash_result);
				rte_spinlock_unlock(&worker_ctx->app_cfg->cm_sketch_lock);
				continue;
			} else {
				worker_ctx->app_cfg->cm_sketch[row_index][hash_result] = counter_value + 1;
			}
			rte_spinlock_unlock(&worker_ctx->app_cfg->cm_sketch_lock);
		}

	}

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
static int _process_packets(struct cm_sketch_worker_ctx *worker_ctx, int ingress_port){
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

static void cm_sketch_worker(void *args){
	struct cm_sketch_worker_ctx *worker_ctx = (struct cm_sketch_worker_ctx *)args;
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

doca_error_t cm_sketch_lcores_run(struct cm_sketch_cfg *app_cfg){
	doca_error_t result = DOCA_SUCCESS;
	uint16_t lcore_index = 0;
	uint64_t cm_sketch_row_index = 0, temp_row_index = 0;
	int current_lcore = 0, nb_queues = app_cfg->dpdk_cfg->port_config.nb_queues;
	struct cm_sketch_worker_ctx *worker_ctx = NULL;
	uint64_t **cm_sketch, *cm_sketch_row;
	struct pairwise_hash **pairwise_hash_family, *pairwise_hash;
	uint64_t cm_sketch_hash_index = 0;

	DOCA_LOG_INFO("%d cores are used as workers", nb_queues);

	/* Allocate Count-min structure */
	cm_sketch = (uint64_t**)rte_zmalloc(NULL, sizeof(uint64_t*)*NB_ROWS, 0);
	if (cm_sketch == NULL) {
		DOCA_LOG_ERR("RTE malloc failed");
		result = DOCA_ERROR_NO_MEMORY;
		goto exit;
	}
	for(cm_sketch_row_index=0; cm_sketch_row_index<NB_ROWS; cm_sketch_row_index++){
		cm_sketch_row = (uint64_t*)rte_zmalloc(NULL, sizeof(uint64_t)*NB_COUNTER, 0);
		if (cm_sketch_row == NULL) {
			DOCA_LOG_ERR("RTE malloc failed");
			result = DOCA_ERROR_NO_MEMORY;
			goto destroy_cm_sketch_rows;
		}
		cm_sketch[cm_sketch_row_index] = cm_sketch_row;
	}
	app_cfg->cm_sketch = cm_sketch;

	/* Init pairwise hash function family */
	app_cfg->prime = (1<<61)-1;
	pairwise_hash_family = (struct pairwise_hash**)rte_zmalloc(NULL, sizeof(struct pairwise_hash*)*NB_ROWS, 0);
	if (pairwise_hash_family == NULL) {
		DOCA_LOG_ERR("RTE malloc failed");
		result = DOCA_ERROR_NO_MEMORY;
		goto destroy_cm_sketch_rows;
	}
	for(cm_sketch_hash_index=0; cm_sketch_hash_index<NB_ROWS; cm_sketch_hash_index++){
		pairwise_hash = (struct pairwise_hash*)rte_zmalloc(NULL, sizeof(struct pairwise_hash), 0);
		if (pairwise_hash == NULL) {
			DOCA_LOG_ERR("RTE malloc failed");
			result = DOCA_ERROR_NO_MEMORY;
			goto destory_cm_sketch_hash;
		}
		pairwise_hash_family[cm_sketch_hash_index] = pairwise_hash;
		pairwise_hash->a = app_cfg->prime;
		pairwise_hash->b = app_cfg->prime;
		while(pairwise_hash->a >= 1 && pairwise_hash->a <= app_cfg->prime-1)
			pairwise_hash->a = rand64();
		while(pairwise_hash->a >= 0 && pairwise_hash->a <= app_cfg->prime-1)
			pairwise_hash->b = rand64();
	}

	/* Init the spin lock for count-min sketch */
	rte_spinlock_init(&app_cfg->cm_sketch_lock);

	/* Init cm_sketch workers to start processing packets */
	while ((current_lcore < RTE_MAX_LCORE) && (lcore_index < nb_queues)) {
		current_lcore = rte_get_next_lcore(current_lcore, true, false);

		worker_ctx = (struct cm_sketch_worker_ctx*)rte_zmalloc(
			NULL, sizeof(struct cm_sketch_worker_ctx), 0);
		if (worker_ctx == NULL) {
			DOCA_LOG_ERR("RTE malloc failed");
			force_quit = true;
			result = DOCA_ERROR_NO_MEMORY;
			goto destroy_cm_sketch_rows;
		}
		worker_ctx->app_cfg = app_cfg;
		worker_ctx->queue_id = lcore_index;

		if (rte_eal_remote_launch((void *)cm_sketch_worker, (void *)worker_ctx, current_lcore) != 0) {
			DOCA_LOG_ERR("Remote launch failed");
			result = DOCA_ERROR_DRIVER;
			goto destroy_worker_ctx;
		}

		worker_ctx++;
		lcore_index++;
	}

	goto exit;

destroy_worker_ctx:
	rte_free(worker_ctx);
	force_quit = true;
	return result;

destory_cm_sketch_hash:
	for(temp_row_index=0; temp_row_index<cm_sketch_hash_index; temp_row_index++){
		rte_free(pairwise_hash_family[temp_row_index]);
	}

destroy_cm_sketch_hash_family:
	rte_free(pairwise_hash_family);

destroy_cm_sketch_rows:
	for(temp_row_index=0; temp_row_index<cm_sketch_row_index; temp_row_index++){
		rte_free(cm_sketch[temp_row_index]);
	}

destroy_cm_sketch:
	rte_free(cm_sketch);

exit:
	return result;
}