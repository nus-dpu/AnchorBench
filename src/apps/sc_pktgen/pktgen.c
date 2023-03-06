#include "sc_global.h"
#include "sc_pktgen/pktgen.h"
#include "sc_utils/pktgen.h"
#include "sc_utils.h"
#include "sc_log.h"

/*!
 * \brief   initialize application (internal)
 * \param   sc_config   the global configuration
 * \return  zero for successfully initialization
 */
int _init_app(struct sc_config *sc_config){
    
    return SC_SUCCESS;
}

/*!
 * \brief   parse application-specific key-value configuration pair
 * \param   key         the key of the config pair
 * \param   value       the value of the config pair
 * \param   sc_config   the global configuration
 * \return  zero for successfully parsing
 */
int _parse_app_kv_pair(char* key, char *value, struct sc_config* sc_config){
    int result = SC_SUCCESS;
    return result;
}

/*!
 * \brief   callback while entering application
 * \param   sc_config   the global configuration
 * \return  zero for successfully executing
 */
int _process_enter(struct sc_config *sc_config){
    return SC_SUCCESS;
}

/*!
 * \brief   callback for processing packet
 * \param   pkt             the received packet
 * \param   sc_config       the global configuration
 * \param   fwd_port_id     specified the forward port index if need to forward packet
 * \param   need_forward    indicate whether need to forward packet, default to be false
 * \return  zero for successfully processing
 */
int _process_pkt(struct rte_mbuf *pkt, struct sc_config *sc_config, uint16_t *fwd_port_id, bool *need_forward){
    SC_WARNING_DETAILS("_process_pkt not implemented");
    return SC_ERROR_NOT_IMPLEMENTED;
}

/*!
 * \brief   callback for client logic
 * \param   sc_config       the global configuration
 * \param   queue_id        the index of the queue for current core to tx/rx packet
 * \param   ready_to_exit   indicator for exiting worker loop
 * \return  zero for successfully executing
 */
int _process_client(struct sc_config *sc_config, uint16_t queue_id, bool *ready_to_exit){
    int i, result = SC_SUCCESS;
    struct rte_mbuf *send_pkt_bufs[32]; /* static max nb of pkt with a brust: 32 */

    struct rte_ether_hdr pkt_eth_hdr;
    struct rte_ipv4_hdr pkt_ipv4_hdr;
    struct rte_udp_hdr pkt_udp_hdr;

    uint32_t src_ipv4_addr, dst_ipv4_addr;
    char src_ether_addr[6], dst_ether_addr[6];

    uint16_t src_port, dst_port;

    uint16_t pkt_len = 0;

    /* assemble ethernet header */
    if(SC_SUCCESS != sc_util_generate_random_ether_addr(src_ether_addr)){
        SC_THREAD_ERROR("failed to generate random source mac address");
        result = SC_ERROR_INTERNAL;
        goto process_client_ready_to_exit;
    }
    if(SC_SUCCESS != sc_util_generate_random_ether_addr(dst_ether_addr)){
        SC_THREAD_ERROR("failed to generate random destination mac address");
        result = SC_ERROR_INTERNAL;
        goto process_client_ready_to_exit;
    }
    if(SC_SUCCESS != sc_util_initialize_eth_header(&pkt_eth_hdr, 
        (struct rte_ether_addr *)src_ether_addr, 
        (struct rte_ether_addr *)dst_ether_addr,
        RTE_ETHER_TYPE_IPV4, 0, 0, &pkt_len
    )){
        SC_THREAD_ERROR("failed to assemble ethernet header");
        result = SC_ERROR_INTERNAL;
        goto process_client_ready_to_exit;
    }
    
    /* assemble ipv4 header */
    if(SC_SUCCESS != sc_util_generate_random_ipv4_addr(&src_ipv4_addr)){
        SC_THREAD_ERROR("failed to generate random source ipv4 address");
        result = SC_ERROR_INTERNAL;
        goto process_client_ready_to_exit;
    }
    if(SC_SUCCESS != sc_util_generate_random_ipv4_addr(&dst_ipv4_addr)){
        SC_THREAD_ERROR("failed to generate random destination ipv4 address");
        result = SC_ERROR_INTERNAL;
        goto process_client_ready_to_exit;
    }
    if(SC_SUCCESS != sc_util_initialize_ipv4_header_proto(&pkt_ipv4_hdr, src_ipv4_addr, dst_ipv4_addr, pkt_len, IPPROTO_UDP, &pkt_len)){
        SC_THREAD_ERROR("failed to assemble ipv4 header");
        result = SC_ERROR_INTERNAL;
        goto process_client_ready_to_exit;
    }

    /* assemble udp header */
    src_port = sc_util_random_unsigned_int16();
    dst_port = sc_util_random_unsigned_int16();
    if(SC_SUCCESS != sc_util_initialize_udp_header(&pkt_udp_hdr, src_port, dst_port, pkt_len, &pkt_len)){
        SC_THREAD_ERROR("failed to assemble udp header");
        result = SC_ERROR_INTERNAL;
        goto process_client_ready_to_exit;
    }

    /* assembly fininal pkt brust */
    // 1 segment per packet
    // packet length: 60 = eth(18) + ipv4(20) + udp(8) + data(14)
    if(SC_SUCCESS != sc_util_generate_packet_burst_proto(
            sc_config->pktmbuf_pool, send_pkt_bufs, &pkt_eth_hdr, 0, &pkt_ipv4_hdr, 1, IPPROTO_UDP, &pkt_udp_hdr, 32, 60, 1)){
        SC_THREAD_ERROR("failed to assemble final packet");
        result = SC_ERROR_INTERNAL;
        goto process_client_ready_to_exit;
    }

    // free for debug
    for(i=0; i<32; i++){
        rte_pktmbuf_free(send_pkt_bufs[i]);
    }

    goto process_client_exit;

process_client_ready_to_exit:
    *ready_to_exit = true;

process_client_exit:
    return result;
}

/*!
 * \brief   callback while exiting application
 * \param   sc_config   the global configuration
 * \return  zero for successfully executing
 */
int _process_exit(struct sc_config *sc_config){
    return SC_SUCCESS;
}