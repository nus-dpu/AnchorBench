#include "sc_global.h"
#include "sc_utils.h"
#include "sc_log.h"
#include "sc_sketch/sketch.h"
#include "sc_sketch/cm_sketch.h"
#include "sc_sketch/spooky-c.h"

/*!
 * \brief   udpate the sketch structre using a specific key
 * \param   key         the hash key for the processed packet
 * \param   sc_config   the global configuration
 * \return  zero for successfully updating
 */
int __cm_update(const char* key, struct sc_config *sc_config){
    int i;
    uint32_t hash_result;
    uint32_t cm_nb_rows = INTERNAL_CONF(sc_config)->cm_nb_rows;
    uint32_t cm_nb_counters_per_row = INTERNAL_CONF(sc_config)->cm_nb_counters_per_row;
    rte_spinlock_t *lock = &(INTERNAL_CONF(sc_config)->cm_sketch->lock);
    counter_t *counters = INTERNAL_CONF(sc_config)->cm_sketch->counters;

    #if defined(MODE_LATENCY)
        struct timeval hash_start, hash_end;
        struct timeval update_start, update_end;
        struct timeval lock_start, lock_end;
    #endif // MODE_LATENCY

    for(i=0; i<cm_nb_rows; i++){
        /* step 1: hashing */
        #if defined(MODE_LATENCY)
            gettimeofday(&hash_start, NULL);
        #endif
        hash_result = spooky_hash32(key, TUPLE_KEY_LENGTH, INTERNAL_CONF(sc_config)->cm_sketch->hash_seeds[i]);
        hash_result %= cm_nb_counters_per_row;
        #if defined(MODE_LATENCY)
            gettimeofday(&hash_end, NULL);
            PER_CORE_META(sc_config).overall_hash.tv_usec
                += (hash_end.tv_sec - hash_start.tv_sec) * 1000000 
                    + (hash_end.tv_usec - hash_start.tv_usec);
        #endif // MODE_LATENCY
        // SC_THREAD_LOG("hash result: %u", hash_result);
    
        /* step 2: require spin lock */
        #if defined(MODE_LATENCY)
            gettimeofday(&lock_start, NULL);
        #endif // MODE_LATENCY
        rte_spinlock_lock(lock);
        #if defined(MODE_LATENCY)
            gettimeofday(&lock_end, NULL);
            PER_CORE_META(sc_config).overall_lock.tv_usec
                += (lock_end.tv_sec - lock_start.tv_sec) * 1000000 
                    + (lock_end.tv_usec - lock_start.tv_usec);
        #endif // MODE_LATENCY

        /* step 3: update counter */
        #if defined(MODE_LATENCY)
            gettimeofday(&update_start, NULL);
        #endif // MODE_LATENCY
        counters[i*cm_nb_counters_per_row + hash_result] += 1;
        #if defined(MODE_LATENCY)
            gettimeofday(&update_end, NULL);
            PER_CORE_META(sc_config).overall_update.tv_usec
                += (update_end.tv_sec - update_start.tv_sec) * 1000000 
                    + (update_end.tv_usec - update_start.tv_usec);
        #endif // MODE_LATENCY

        /* step 4: expire spin lock */
        #if defined(MODE_LATENCY)
            gettimeofday(&lock_start, NULL);
        #endif // MODE_LATENCY
        rte_spinlock_unlock(lock);
        #if defined(MODE_LATENCY)
            gettimeofday(&lock_end, NULL);
            PER_CORE_META(sc_config).overall_lock.tv_usec
                += (lock_end.tv_sec - lock_start.tv_sec) * 1000000 
                    + (lock_end.tv_usec - lock_start.tv_usec);
        #endif // MODE_LATENCY
    }

    return SC_SUCCESS;
}

/*!
 * \brief   query the sketch structre using a specific key
 * \param   key         the hash key for the processed packet
 * \param   result      query result 
 * \param   sc_config   the global configuration
 * \return  zero for successfully querying
 */
int __cm_query(const char* key, void *result, struct sc_config *sc_config){
    int i;
    counter_t c, smallest_c = 0;
    uint32_t hash_result;
    uint32_t cm_nb_rows = INTERNAL_CONF(sc_config)->cm_nb_rows;
    uint32_t cm_nb_counters_per_row = INTERNAL_CONF(sc_config)->cm_nb_counters_per_row;
    rte_spinlock_t *lock = &(INTERNAL_CONF(sc_config)->cm_sketch->lock);
    counter_t *counters = INTERNAL_CONF(sc_config)->cm_sketch->counters;

    for(i=0; i<cm_nb_rows; i++){
        /* step 1: hashing */
        hash_result = spooky_hash32(key, TUPLE_KEY_LENGTH, INTERNAL_CONF(sc_config)->cm_sketch->hash_seeds[i]);
        hash_result %= cm_nb_counters_per_row;

        /* step 2: require spin lock */
        rte_spinlock_lock(lock);

        /* step 3: read counter */
        c = counters[i*cm_nb_counters_per_row + hash_result];
        if(i == 0) {
            smallest_c = c;
        } else {
            if(c < smallest_c){ smallest_c = c; }
        }
        *((counter_t*)result) = smallest_c;

        /* step 4: expire spin lock */
        rte_spinlock_unlock(lock);

        return SC_SUCCESS;
    }

    return SC_ERROR_NOT_IMPLEMENTED;
}

/*!
 * \brief   clean the sketch structre
 * \return  zero for successfully querying
 */
int __cm_clean(struct sc_config *sc_config){
    int i;
    rte_spinlock_t *lock = &(INTERNAL_CONF(sc_config)->cm_sketch->lock);
    counter_t *counters = INTERNAL_CONF(sc_config)->cm_sketch->counters;
    uint32_t cm_nb_rows = INTERNAL_CONF(sc_config)->cm_nb_rows;
    uint32_t cm_nb_counters_per_row = INTERNAL_CONF(sc_config)->cm_nb_counters_per_row;

    rte_spinlock_lock(lock);
    for(i=0; i<cm_nb_rows*cm_nb_counters_per_row; i++){ counters[i] = 0; }
    rte_spinlock_unlock(lock);
    
    return SC_SUCCESS;
}

/*!
 * \brief   record the actual value for a specific key
 * \return  zero for successfully recording
 */
int __cm_record(const char* key, struct sc_config *sc_config){
    #if defined(MODE_ACCURACY)
        int ret;
        uint64_t *queried_flow_count;
        uint64_t flow_count;
        
        /* query the key-value map */
        ret = query_kv_map(PER_CORE_META(sc_config).kv_map, key, TUPLE_KEY_LENGTH, &queried_flow_count, NULL);
        if(ret != SC_SUCCESS && ret != SC_ERROR_NOT_EXIST){
            SC_ERROR("error occured during query key-value map");
        }

        if(ret == SC_ERROR_NOT_EXIST){  /* no entry found, create a new entry for the flow */
            SC_THREAD_LOG("key %s not found, insert", (const char*)key);
            flow_count = 1;
            if( SC_SUCCESS != insert_kv_map(PER_CORE_META(sc_config).kv_map, 
                                    key, TUPLE_KEY_LENGTH, &flow_count, sizeof(flow_count))
            ){
                SC_ERROR("failed to insert key %s to key-value map", key);
                return SC_ERROR_INTERNAL;
            }
        } else {    /* update the old entry */
            flow_count = *queried_flow_count + 1;
            SC_THREAD_LOG("key %s found, value %ld", (const char*)key, flow_count);
            if(SC_SUCCESS != update_kv_map(PER_CORE_META(sc_config).kv_map, 
                                    key, TUPLE_KEY_LENGTH, &flow_count, sizeof(flow_count))
            ){
                SC_ERROR("failed to updating key %s to key-value map, flow count: %ld", key, flow_count);
                return SC_ERROR_INTERNAL;
            }
        }
    #endif // MODE_ACCURACY
    return SC_SUCCESS;
}

/*!
 * \brief   evaluate cm sketch result
 * \return  evaluate the throughput/latency/accuracy of the sketch
 */
int __cm_evaluate(struct sc_config *sc_config){
    SC_THREAD_LOG_LOCK();

    /* output accuracy log */
    #if defined(MODE_ACCURACY)
        uint64_t i;
        sc_kv_entry_t *entry;
        counter_t cm_result;

        for(i=0; i<PER_CORE_META(sc_config).kv_map->length; i++){
            /* obtain actual result */
            if(SC_SUCCESS != get_kv_entry_by_index(PER_CORE_META(sc_config).kv_map, i, &entry)){
                SC_THREAD_ERROR(
                    "failed to get key-value entry from key-value map with index %ld, something is wrong", i);
                continue;
            }

            /* obtain cm_sketch result */
            if(SC_SUCCESS != __cm_query((const char*)(entry->key), &cm_result, sc_config)){
                SC_THREAD_ERROR(
                    "failed to query sketch result of key %s, something is wrong", (const char*)(entry->key));
                continue;
            }

            /* check whether the cm result is valid */
            if(cm_result < (*((uint64_t*)(entry->value)))){
                SC_THREAD_WARNING(
                    "cm sketch result (%ld) is less than actual value (%ld) for flow %s, something is wrong",
                    cm_result, (*((uint64_t*)(entry->value))), (const char*)(entry->key)
                )
                continue;
            }

            SC_THREAD_LOG(
                "key %s with value %ld, cm value %ld", 
                (const char*)(entry->key), *((uint64_t*)(entry->value)), cm_result
            );
        }
    #endif // MODE_ACCURACY

    /* output latency log */
    #if defined(MODE_LATENCY)
        /* number of processed packet/bytes */
        SC_THREAD_LOG("number of processed pkt: %ld",
            PER_CORE_META(sc_config).nb_pkts);
        SC_THREAD_LOG("number of processed bytes: %ld",
            PER_CORE_META(sc_config).nb_bytes);

        /* packet process */
        SC_THREAD_LOG("overall pkt process latency: %ld us",
            PER_CORE_META(sc_config).overall_pkt_process.tv_usec);
        if(PER_CORE_META(sc_config).nb_pkts > 0){
            SC_THREAD_LOG("average pkt process latency: %f us/pkt",
                (float)PER_CORE_META(sc_config).overall_pkt_process.tv_usec / (float)PER_CORE_META(sc_config).nb_pkts);
        }
        /* hash */
        SC_THREAD_LOG("overall hash latency: %ld us",
            PER_CORE_META(sc_config).overall_hash.tv_usec);
        if(PER_CORE_META(sc_config).nb_pkts > 0){
            SC_THREAD_LOG("average hash latency: %f us/pkt",
                (float)PER_CORE_META(sc_config).overall_hash.tv_usec / (float)PER_CORE_META(sc_config).nb_pkts);
        }
        /* lock */
        SC_THREAD_LOG("overall lock latency: %ld us",
            PER_CORE_META(sc_config).overall_lock.tv_usec);
        if(PER_CORE_META(sc_config).nb_pkts > 0){
            SC_THREAD_LOG("average lock latency: %f us/pkt",
                (float)PER_CORE_META(sc_config).overall_lock.tv_usec / (float)PER_CORE_META(sc_config).nb_pkts);
        }
        /* update */
        SC_THREAD_LOG("overall update latency: %ld us",
            PER_CORE_META(sc_config).overall_update.tv_usec);
        if(PER_CORE_META(sc_config).nb_pkts > 0){
            SC_THREAD_LOG("average update latency: %f us/pkt",
                (float)PER_CORE_META(sc_config).overall_update.tv_usec / (float)PER_CORE_META(sc_config).nb_pkts);
        }
    #endif // MODE_LATENCY

    /* output throughput log */
    #if defined(MODE_THROUGHPUT)
        SC_THREAD_LOG("thread execute duration: %ld us", 
            PER_CORE_META(sc_config).thread_end_time.tv_sec * 1000000 
            + PER_CORE_META(sc_config).thread_end_time.tv_usec 
            - PER_CORE_META(sc_config).thread_start_time.tv_sec * 1000000   
            - PER_CORE_META(sc_config).thread_start_time.tv_usec 
        );
    #endif // MODE_THROUGHPUT

    SC_THREAD_LOG_UNLOCK();
    return SC_SUCCESS;
}