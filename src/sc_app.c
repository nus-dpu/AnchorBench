#include "sc_global.h"
#include "sc_utils.h"
#include "sc_app.h"
#include "sc_log.h"

#if defined(APP_SKETCH)
#include "sc_sketch/sketch.h"
#endif // APP_SKETCH

/*!
 * \brief   initialize application
 * \param   sc_config       the global configuration
 * \param   app_conf_path   path to the configuration file of currernt application
 * \return  zero for successfully initialization
 */
int init_app(struct sc_config *sc_config, const char *app_conf_path){
    FILE* fp = NULL;

    /* allocate internal config */
    struct _internal_config *_internal_config = (struct _internal_config*)malloc(sizeof(struct _internal_config));
    if(unlikely(!_internal_config)){
        SC_ERROR_DETAILS("failed to allocate memory for internal_config");
        return SC_ERROR_MEMORY;
    }
    sc_config->app_config->internal_config = _internal_config;

    /* specify pkt entering callback function */
    sc_config->app_config->process_enter = _process_enter;

    /* specify pkt processing callback function (server mode) */
    sc_config->app_config->process_pkt = _process_pkt;

    /* specify client callback function (client mode) */
    sc_config->app_config->process_client = _process_client;

    /* specify pkt exiting callback function */
    sc_config->app_config->process_exit = _process_exit;

    /* open application configuration file */
    fp = fopen(app_conf_path, "r");
    if(!fp){
        SC_ERROR("failed to open the application configuration file: %s\n", strerror(errno));
        return SC_ERROR_NOT_EXIST;
    }

    /* parse configuration file */
    if(parse_config(fp, sc_config, _parse_app_kv_pair) != SC_SUCCESS){
        SC_ERROR("failed to parse the application configuration file, exit\n");
        return SC_ERROR_INPUT;
    }
    
    /* initialize application (internal) */
    return _init_app(sc_config);
}