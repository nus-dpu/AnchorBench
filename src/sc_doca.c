#include "sc_doca.h"

#if defined(SC_HAS_DOCA)

DOCA_LOG_REGISTER(SC::DOCA);

static int _parse_doca_kv_pair(char* key, char *value, struct sc_config* sc_config);

/*!
 * \brief   initialize doca and corresponding resources
 * \param   sc_config       the global configuration
 * \param   doca_conf_path  path to the configuration for doca
 * \return  zero for successfully initialization
 */
int init_doca(struct sc_config *sc_config, const char *doca_conf_path){   
    int result = SC_SUCCESS;
    doca_error_t doca_result;
    FILE* fp = NULL;
    
    /* open doca configuration file */
    fp = fopen(doca_conf_path, "r");
    if(!fp){
        SC_ERROR("failed to open the base configuration file: %s\n", strerror(errno));
        result = SC_ERROR_INTERNAL;
        goto init_doca_exit;
    }

    /* parse doca configuration file */
    if(sc_util_parse_config(fp, sc_config, _parse_doca_kv_pair) != SC_SUCCESS){
        SC_ERROR("failed to parse the doca configuration file, exit\n");
        result = SC_ERROR_INTERNAL;
        goto init_doca_exit;
    }

    /* initialize sha engine if the application need it */
    #if defined(SC_NEED_DOCA_SHA)
        /* create doca context */
        struct doca_sha *sha_ctx;
        uint32_t workq_depth = 1;		/* The sha engine will run 1 sha job */
        uint32_t max_chunks = 2;		/* The sha engine will use 2 doca buffers */

        doca_result = doca_sha_create(&sha_ctx);
        if (doca_result != DOCA_SUCCESS) {
            SC_ERROR_DETAILS("unable to create sha engine: %s", doca_get_error_string(result));
            result = SC_ERROR_INTERNAL;
            goto sha_init_failed;
        }
        DOCA_CONF(sc_config)->sha_ctx = doca_sha_as_ctx(sha_ctx);

        /* open doca sha device */
        result = sc_doca_util_open_doca_device_with_pci(
            &(DOCA_CONF(sc_config)->sha_pci_bdf), NULL,
            &(DOCA_CONF(sc_config)->sha_dev)
        );
        if (result != SC_SUCCESS) {
            SC_ERROR("failed to open pci device of sha engine");
            result = SC_ERROR_INTERNAL;
            goto sha_destory_ctx;
        }

        /* initialize doca core object for sha engine */
        result = sc_doca_util_init_core_objects(
            &(DOCA_CONF(sc_config)->sha_mmap),
            DOCA_CONF(sc_config)->sha_dev,
            &(DOCA_CONF(sc_config)->sha_buf_inv),
            DOCA_CONF(sc_config)->sha_ctx,
            &(DOCA_CONF(sc_config)->sha_workq),
            DOCA_BUF_EXTENSION_NONE,
            workq_depth, max_chunks
        );
        if(result != SC_SUCCESS){
            SC_ERROR("failed to initialize core objects for sha engine");
            result = SC_ERROR_INTERNAL;
            goto sha_destory_ctx;
        }

        goto sha_init_successed;

sha_destory_core_objects:
        sc_doca_util_destory_core_objects(
            &(DOCA_CONF(sc_config)->sha_mmap),
            &(DOCA_CONF(sc_config)->sha_dev),
            &(DOCA_CONF(sc_config)->sha_buf_inv),
            DOCA_CONF(sc_config)->sha_ctx,
            &(DOCA_CONF(sc_config)->sha_workq)
        );

sha_destory_ctx:
        doca_result = doca_sha_destroy(sha_ctx);
        if(doca_result != DOCA_SUCCESS){
            SC_ERROR_DETAILS("failed to destroy sha: %s",
                doca_get_error_string(doca_result));
            result = SC_ERROR_INTERNAL;
        }

sha_init_failed:
        goto init_doca_exit;

sha_init_successed:
    #endif // SC_NEED_DOCA_SHA

init_doca_exit:
    return result;
}

/*!
 * \brief   parse key-value pair of doca config
 * \param   key         the key of the config pair
 * \param   value       the value of the config pair
 * \param   sc_config   the global configuration
 * \return  zero for successfully parsing
 */
static int _parse_doca_kv_pair(char* key, char *value, struct sc_config* sc_config){
    int result = SC_SUCCESS;

    #if defined(SC_NEED_DOCA_SHA)
        /* config: PCI address of SHA engine */
        if(!strcmp(key, "sha_pci_address")){
            value = sc_util_del_both_trim(value);
            sc_util_del_change_line(value);
            if(SC_SUCCESS != sc_doca_util_parse_pci_addr(
                    value, &(DOCA_CONF(sc_config)->sha_pci_bdf))){
                SC_ERROR("failed to parse pci address for doca sha engine");
                result = SC_ERROR_INVALID_VALUE;
            }
            goto parse_doca_kv_pair_exit;
        }
    #endif

parse_doca_kv_pair_exit:
    return result;
}



#endif // SC_HAS_DOCA