#ifndef _SC_TEMPLATE_H_
#define _SC_TEMPLATE_H_

struct _per_core_meta {
    int something;
};

/* definition of internal config */
struct _internal_config {
    int something;
};

int _init_app(struct sc_config *sc_config);
int _parse_app_kv_pair(char* key, char *value, struct sc_config* sc_config);
int _process_enter(struct sc_config *sc_config);
int _process_pkt(struct rte_mbuf *pkt, struct sc_config *sc_config, uint16_t *fwd_port_id, bool *need_forward);
int _process_client(struct sc_config *sc_config, uint16_t queue_id, bool *ready_to_exit);
int _process_exit(struct sc_config *sc_config);

#endif