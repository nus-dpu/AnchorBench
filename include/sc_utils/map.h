#ifndef _SC_MAP_H_
#define _SC_MAP_H_

#include <errno.h>
#include <stdint.h>

#include <rte_malloc.h>

#include "sc_global.h"
#include "sc_utils.h"
#include "sc_log.h"

typedef struct kv_entry {
    void *key;
    uint64_t key_len;
    void *value;
    uint64_t value_len;
    struct kv_entry *next;
} sc_kv_entry_t;

typedef struct kv_map {
    sc_kv_entry_t *head;
    uint64_t length;
} sc_kv_map_t;

int new_kv_map(sc_kv_map_t **p);
int insert_kv_map(sc_kv_map_t *p, void *key, uint64_t key_len, void *value, uint64_t value_len);
int delete_kv_map(sc_kv_map_t *p, void *key, uint64_t key_len);
int update_kv_map(sc_kv_map_t *p, void *key, uint64_t key_len, void *value, uint64_t value_len);
int query_kv_map(sc_kv_map_t *p, void *key, uint64_t key_len, void **value, uint64_t *value_len);
int get_kv_entry_by_index(sc_kv_map_t *p, uint64_t id, sc_kv_entry_t **e);

#endif