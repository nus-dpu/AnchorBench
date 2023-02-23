#include "sc_doca.h"

#if defined(HAS_DOCA)

DOCA_LOG_REGISTER(SC::DOCA);

static int _parse_doca_kv_pair(char* key, char *value, struct sc_config* sc_config);

/*!
 * \brief   initialize doca and corresponding resources
 * \param   sc_config       the global configuration
 * \param   doca_conf_path  path to the configuration for doca
 * \return  zero for successfully initialization
 */
int init_doca(struct sc_config *sc_config, const char *doca_conf_path){
    return SC_SUCCESS;
    
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
    if(parse_config(fp, sc_config, _parse_doca_kv_pair) != SC_SUCCESS){
        SC_ERROR("failed to parse the doca configuration file, exit\n");
        result = SC_ERROR_INTERNAL;
        goto init_doca_exit;
    }

    /* initialize sha engine if the application need it */
    #if defined(NEED_DOCA_SHA)
        /* create doca context */
        struct doca_sha *sha_ctx;
        doca_result = doca_sha_create(&sha_ctx);
        if (doca_result != DOCA_SUCCESS) {
            DOCA_LOG_ERR("Unable to create sha engine: %s", doca_get_error_string(result));
            result = SC_ERROR_INTERNAL;
            goto init_doca_exit;
        }
        DOCA_CONF(sc_config)->doca_ctx = doca_sha_as_ctx(sha_ctx);
    #endif // NEED_DOCA_SHA

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

    #if defined(NEED_DOCA_SHA)
        /* config: PCI address of SHA engine */
        if(!strcmp(key, "sha_pci_address")){
            char *pci_address_str;

            value = del_both_trim(value);
            del_change_line(value);

            pci_address_str = (char*)malloc(strlen(value)+1);
            if(unlikely(!pci_address_str)){
                SC_ERROR_DETAILS("Failed to allocate memory for pci_address_str\n");
                result = SC_ERROR_MEMORY;
            } else {
                DOCA_CONF(sc_config)->doca_sha_pci_address = pci_address_str;
            }

            goto parse_doca_kv_pair_exit;
        }
    #endif

parse_doca_kv_pair_exit:
    return result;
}



#endif // HAS_DOCA