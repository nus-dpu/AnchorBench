#ifndef _SC_PKTGEN_H_
#define _SC_PKTGEN_H_

#include <sys/time.h>
#include <rte_ether.h>
#include <rte_malloc.h>

struct _per_core_meta {
    float per_core_meter;

    uint64_t nb_send_pkt;
    struct timeval last_send_time;
    uint64_t nb_send_pkt_interval;

    struct timeval start_time;
    struct timeval end_time;
};

/* definition of internal config */
struct _internal_config {
    uint32_t meter;             /* unit: Gbps */
    uint32_t pkt_len;          /* unit: bytes */
    uint32_t nb_pkt_per_burst; 
};

int _init_app(struct sc_config *sc_config);
int _parse_app_kv_pair(char* key, char *value, struct sc_config* sc_config);
int _process_enter(struct sc_config *sc_config);
int _process_pkt(struct rte_mbuf *pkt, struct sc_config *sc_config, uint16_t *fwd_port_id, bool *need_forward);
int _process_client(struct sc_config *sc_config, uint16_t queue_id, bool *ready_to_exit);
int _process_exit(struct sc_config *sc_config);

#endif