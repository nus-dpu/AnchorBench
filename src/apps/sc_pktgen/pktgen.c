#include "sc_global.h"
#include "sc_app.h"
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

    /* meter value */
    if(!strcmp(key, "meter")){
        value = sc_util_del_both_trim(value);
        sc_util_del_change_line(value);
        uint32_t meter;
        if(sc_util_atoui_32(value, &meter) != SC_SUCCESS) {
            result = SC_ERROR_INVALID_VALUE;
            goto invalid_meter;
        }
        INTERNAL_CONF(sc_config)->meter = meter;
        goto _parse_app_kv_pair_exit;

invalid_meter:
        SC_ERROR_DETAILS("invalid configuration meter\n");
    }

    /* packet length value */
    if(!strcmp(key, "pkt_len")){
        value = sc_util_del_both_trim(value);
        sc_util_del_change_line(value);
        uint32_t pkt_len;
        if(sc_util_atoui_32(value, &pkt_len) != SC_SUCCESS) {
            result = SC_ERROR_INVALID_VALUE;
            goto invalid_pkt_len;
        }
        INTERNAL_CONF(sc_config)->pkt_len = pkt_len;
        goto _parse_app_kv_pair_exit;

invalid_pkt_len:
        SC_ERROR_DETAILS("invalid configuration pkt_len\n");
    }

    /* number of packet per burst */
    if(!strcmp(key, "nb_pkt_per_burst")){
        value = sc_util_del_both_trim(value);
        sc_util_del_change_line(value);
        uint32_t nb_pkt_per_burst;
        if(sc_util_atoui_32(value, &nb_pkt_per_burst) != SC_SUCCESS) {
            result = SC_ERROR_INVALID_VALUE;
            goto invalid_nb_pkt_per_burst;
        }
        INTERNAL_CONF(sc_config)->nb_pkt_per_burst = nb_pkt_per_burst;
        goto _parse_app_kv_pair_exit;

invalid_nb_pkt_per_burst:
        SC_ERROR_DETAILS("invalid configuration nb_pkt_per_burst\n");
    }

_parse_app_kv_pair_exit:
    return result;
}

/*!
 * \brief   callback while entering application
 * \param   sc_config   the global configuration
 * \return  zero for successfully executing
 */
int _process_enter(struct sc_config *sc_config){
    /* calculate per-core meter value */
    PER_CORE_META(sc_config).per_core_meter = 
        (float)INTERNAL_CONF(sc_config)->meter / (float)sc_config->nb_used_cores;
    SC_THREAD_LOG("per core meter is %f Gbps", PER_CORE_META(sc_config).per_core_meter);

    /* initialize the last_send_time */
    if(unlikely(-1 == gettimeofday(&PER_CORE_META(sc_config).last_send_time, NULL))){
        SC_THREAD_ERROR_DETAILS("failed to obtain current time");
        return SC_ERROR_INTERNAL;
    }

    /* initialize the start_time */
    if(unlikely(-1 == gettimeofday(&PER_CORE_META(sc_config).start_time, NULL))){
        SC_THREAD_ERROR_DETAILS("failed to obtain current time");
        return SC_ERROR_INTERNAL;
    }

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
    int i, nb_tx, result = SC_SUCCESS;
    struct rte_mbuf **send_pkt_bufs = NULL;
    struct rte_ether_hdr pkt_eth_hdr;
    struct rte_ipv4_hdr pkt_ipv4_hdr;
    struct rte_udp_hdr pkt_udp_hdr;

    uint32_t src_ipv4_addr, dst_ipv4_addr;
    char src_ether_addr[6], dst_ether_addr[6];

    uint16_t src_port, dst_port;

    uint16_t pkt_len = INTERNAL_CONF(sc_config)->pkt_len - 18 - 20 - 8;

    struct timeval current_time;
    long interval_sec;
    long interval_usec;

    /* calculate time intervals */
    if(unlikely(-1 == gettimeofday(&current_time, NULL))){
        SC_THREAD_ERROR_DETAILS("failed to obtain current time");
        result = SC_ERROR_INTERNAL;
        goto process_client_ready_to_exit;
    }
    interval_sec = current_time.tv_sec - PER_CORE_META(sc_config).last_send_time.tv_sec;
    interval_usec = current_time.tv_usec - PER_CORE_META(sc_config).last_send_time.tv_usec;
    interval_usec += 1000000 * interval_sec;    /* duration since last send (us) */

    /* meter check */
    if( INTERNAL_CONF(sc_config)->pkt_len
        * PER_CORE_META(sc_config).nb_send_pkt_interval
        * 8 > PER_CORE_META(sc_config).per_core_meter * 1000000000
    ){
        goto process_client_exit;
    }

    /* allocate array for pointers to pkt_bufs */
    send_pkt_bufs = (struct rte_mbuf **)rte_malloc(NULL, 
        sizeof(struct rte_mbuf*)*INTERNAL_CONF(sc_config)->nb_pkt_per_burst, 0);
    if(unlikely(!send_pkt_bufs)){
        SC_THREAD_ERROR_DETAILS("failed to allocate memory for send_pkt_bufs");
        result = SC_ERROR_INTERNAL;
        goto process_client_ready_to_exit;
    }
    
    /* refresh last send time */
    if(unlikely(-1 == gettimeofday(&PER_CORE_META(sc_config).last_send_time, NULL))){
        SC_THREAD_ERROR_DETAILS("failed to obtain current time");
        result = SC_ERROR_INTERNAL;
        goto process_client_ready_to_exit;
    }

    /* refresh number of sent packet within the interval */
    PER_CORE_META(sc_config).nb_send_pkt_interval = 0;

    /* assemble udp header */
    src_port = sc_util_random_unsigned_int16();
    dst_port = sc_util_random_unsigned_int16();
    if(SC_SUCCESS != sc_util_initialize_udp_header(&pkt_udp_hdr, src_port, dst_port, pkt_len, &pkt_len)){
        SC_THREAD_ERROR("failed to assemble udp header");
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
    if(SC_SUCCESS != sc_util_initialize_ipv4_header_proto(
            &pkt_ipv4_hdr, src_ipv4_addr, dst_ipv4_addr, pkt_len, IPPROTO_UDP, &pkt_len)){
        SC_THREAD_ERROR("failed to assemble ipv4 header");
        result = SC_ERROR_INTERNAL;
        goto process_client_ready_to_exit;
    }

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
    
    /* assembly fininal pkt brust */
    // 1 segment per packet
    // packet length: 60 = eth(18) + ipv4(20) + udp(8) + data(14)
    if(SC_SUCCESS != sc_util_generate_packet_burst_proto(
            sc_config->pktmbuf_pool, send_pkt_bufs, &pkt_eth_hdr, 0, &pkt_ipv4_hdr, 1, IPPROTO_UDP, &pkt_udp_hdr, INTERNAL_CONF(sc_config)->nb_pkt_per_burst, INTERNAL_CONF(sc_config)->pkt_len, 1)){
        SC_THREAD_ERROR("failed to assemble final packet");
        result = SC_ERROR_INTERNAL;
        goto process_client_ready_to_exit;
    }

    nb_tx = 0;
    for(i=0; i<sc_config->nb_used_ports; i++){
        nb_tx += rte_eth_tx_burst(sc_config->port_ids[i], queue_id, send_pkt_bufs, INTERNAL_CONF(sc_config)->nb_pkt_per_burst);
    }
    PER_CORE_META(sc_config).nb_send_pkt += nb_tx;
    PER_CORE_META(sc_config).nb_send_pkt_interval += nb_tx;
    
    goto process_client_exit;

process_client_ready_to_exit:
    *ready_to_exit = true;

process_client_exit:
    if(send_pkt_bufs)
        rte_free(send_pkt_bufs);
    return result;
}

/*!
 * \brief   callback while exiting application
 * \param   sc_config   the global configuration
 * \return  zero for successfully executing
 */
int _process_exit(struct sc_config *sc_config){
    long interval_sec;
    long interval_usec;

    /* initialize the end_time */
    if(unlikely(-1 == gettimeofday(&PER_CORE_META(sc_config).end_time, NULL))){
        SC_THREAD_ERROR_DETAILS("failed to obtain current time");
        return SC_ERROR_INTERNAL;
    }

    interval_sec 
        = PER_CORE_META(sc_config).end_time.tv_sec - PER_CORE_META(sc_config).start_time.tv_sec;
    interval_usec 
        = PER_CORE_META(sc_config).end_time.tv_usec - PER_CORE_META(sc_config).start_time.tv_usec;
    interval_usec += 1000 * 1000 * interval_sec;    /* duration since last send (us) */

    SC_THREAD_LOG("send %d packets in total, throughput: %f Gbps",
        PER_CORE_META(sc_config).nb_send_pkt,
        (float)(PER_CORE_META(sc_config).nb_send_pkt * INTERNAL_CONF(sc_config)->pkt_len * 8) 
        / (float)(interval_usec * 1000)
    );
    return SC_SUCCESS;
}