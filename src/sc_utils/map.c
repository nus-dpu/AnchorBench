#include "sc_utils/map.h"

/*!
 * \brief   create a new key-value map
 * \param   p   pointer to the pointer of created key-value map
 * \return  zero for successfully creating
 */
int new_kv_map(sc_kv_map_t **p){
    *p = (sc_kv_map_t*)rte_malloc(NULL, sizeof(sc_kv_map_t), 0);
    if(!(*p)){
        SC_ERROR_DETAILS("failed to allocate memory for sc_kv_map_t: %s", strerror(errno));
        return SC_ERROR_MEMORY;
    }
    memset((*p), 0, sizeof(sc_kv_map_t));
    (*p)->length = 0;
    return SC_SUCCESS;
}

/*!
 * \brief   insert a key-value entry to the specified key-value map
 * \param   p           pointer to the key-value map
 * \param   key         pointer to the key
 * \param   key_len     length of the given key
 * \param   value       pointer to the value
 * \param   value_len   length of the given value
 * \return  zero for successfully inserting
 */
int insert_kv_map(sc_kv_map_t *p, void *key, uint64_t key_len, void *value, uint64_t value_len){
    int i, result = SC_SUCCESS;
    sc_kv_entry_t *pointer, *last_pointer;

    sc_kv_entry_t *entry = (sc_kv_entry_t*)rte_malloc(NULL, sizeof(sc_kv_entry_t), 0);
    if(!entry){
        SC_ERROR_DETAILS("failed to allocate memory for sc_kv_entry_t: %s", strerror(errno));
        result = SC_ERROR_MEMORY;
        goto insert_kv_map_exit;
    }
    
    void *_key = (void*)rte_malloc(NULL, key_len, 0);
    if(!_key){
        SC_ERROR_DETAILS("failed to allocate memory for key: %s", strerror(errno));
        result = SC_ERROR_MEMORY;
        goto free_sc_kv_entry_t;
    }
    memcpy(_key, key, key_len);

    void *_value = (void*)rte_malloc(NULL, value_len, 0);
    if(!_value){
        SC_ERROR_DETAILS("failed to allocate memory for value: %s", strerror(errno));
        result = SC_ERROR_MEMORY;
        goto free_key;
    }
    memcpy(_value, value, value_len);

    entry->key = (void*)_key;
    entry->value = (void*)_value;
    entry->key_len = key_len;
    entry->value_len = value_len;

    if(p->length == 0){
        p->head = entry;
    } else {
        pointer = p->head;
        for(i=0; i<p->length; i++){
            last_pointer = pointer;
            pointer = pointer->next;
            if(unlikely(pointer == NULL && i != p->length-1)){
                SC_ERROR_DETAILS("unexpected empty pointer within sc_map link list");
                result = SC_ERROR_INTERNAL;
                goto free_value;
            }
        }
        last_pointer->next = entry;
    }
    p->length += 1;

    goto insert_kv_map_exit;

free_value:
    rte_free(_value);

free_key:
    rte_free(_key);

free_sc_kv_entry_t:
    rte_free(entry);

insert_kv_map_exit:
    return result;
}

/*!
 * \brief   delete a key-value entry from the specified key-value map
 * \param   p           pointer to the key-value map
 * \param   key         pointer to the key
 * \param   key_len     length of the given key
 * \return  zero for successfully deleting
 */
int delete_kv_map(sc_kv_map_t *p, void *key, uint64_t key_len){
    sc_kv_entry_t *pointer = p->head, *last_pointer;
    
    while(pointer){
        if(pointer->key_len != key_len){ 
            last_pointer = pointer;
            pointer = pointer->next;
            continue;
        }
        if(!memcmp(pointer->key, key, key_len)){
            if(pointer == p->head){
                p->head = pointer->next;
                rte_free(pointer);
                p->length -= 1;
                return SC_SUCCESS;
            } else {
                last_pointer->next = pointer->next;
                rte_free(pointer);
                p->length -= 1;
                return SC_SUCCESS;
            }
        } else {
            last_pointer = pointer;
            pointer = pointer->next;
        }
    }

    return SC_ERROR_NOT_EXIST;
}

/*!
 * \brief   update the specified key-value entry by the given key
 * \param   p           pointer to the key-value map
 * \param   key         pointer to the given key
 * \param   key_len     length of the given key
 * \param   value       the update value
 * \param   value_len   the length of the update value
 * \return  zero for successfully updating  
 */
int update_kv_map(sc_kv_map_t *p, void *key, uint64_t key_len, void *value, uint64_t value_len){
    unsigned char *new_value;
    sc_kv_entry_t *pointer = p->head;

    /* query*/
    while(pointer){
        if(pointer->key_len != key_len){ 
            pointer = pointer->next;
            continue;
        }
        if(!memcmp(pointer->key, key, key_len)){ break; } 
        else { pointer = pointer->next; }
    }
    if(!pointer){ return SC_ERROR_NOT_EXIST; }

    /* update */
    new_value = (unsigned char*)rte_malloc(NULL, sizeof(unsigned char) * value_len, 0);
    if(!new_value){
        SC_ERROR_DETAILS("failed to allocate memory for value: %s", strerror(errno));
        return SC_ERROR_MEMORY;
    }
    memcpy(new_value, value, value_len);
    rte_free(pointer->value);
    pointer->value = new_value;
    pointer->value_len = value_len;
    
    return SC_SUCCESS;
}

/*!
 * \brief   query the specified key-value map by the given key
 * \param   p           pointer to the key-value map
 * \param   key         pointer to the key
 * \param   key_len     length of the given key
 * \param   value       the query result value
 * \param   value_len   the length of the query result
 * \return  zero for successfully deleting
 */
int query_kv_map(sc_kv_map_t *p, void *key, uint64_t key_len, void **value, uint64_t *value_len){
    sc_kv_entry_t *pointer = p->head;

    while(pointer){
        if(pointer->key_len != key_len){
            pointer = pointer->next;
            continue;
        }
        if(!memcmp(pointer->key, key, key_len)){
            (*value) = pointer->value;
            if(value_len != NULL) *value_len = pointer->value_len;
            return SC_SUCCESS;
        } else {
            pointer = pointer->next;
        }
    }

    return SC_ERROR_NOT_EXIST;
}

int get_kv_entry_by_index(sc_kv_map_t *p, uint64_t id, sc_kv_entry_t **e){
    uint64_t i;
    sc_kv_entry_t *pointer = p->head;

    if(id >= p->length){ return SC_ERROR_NOT_EXIST; }
    for(i=0; i<id; i++){
        pointer = pointer->next;
        if(unlikely(pointer == NULL && i != id-1)){
            SC_ERROR_DETAILS("unexpected empty pointer within sc_map link list");
            return SC_ERROR_INTERNAL;
        }
    }

    (*e) = pointer;

    return SC_SUCCESS;
}