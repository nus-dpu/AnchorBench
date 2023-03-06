#include <errno.h>
#include <string.h>
#include <signal.h>

#include <rte_eal.h>
#include <rte_common.h>

#include <gmp.h>

#include "sc_compile_debug.h"
#include "sc_global.h"
#include "sc_port.h"
#include "sc_mbuf.h"
#include "sc_utils.h"
#include "sc_worker.h"
#include "sc_app.h"
#include "sc_log.h"
#if defined(SC_HAS_DOCA)
  #include "sc_doca.h"
#endif

/* indicator to force shutdown all threads (e.g. worker threads, logging thread, etc.) */
volatile bool sc_force_quit;

/* path to the dpdk configuration file */
const char* dpdk_conf_path = "../conf/dpdk.conf";

/* path to the doca configuration file */
#if defined(SC_HAS_DOCA)
  const char* doca_conf_path = "../conf/doca.conf";
#endif

static int _init_env(struct sc_config *sc_config, int argc, char **argv);
static int _check_configuration(struct sc_config *sc_config, int argc, char **argv);
static int _parse_dpdk_kv_pair(char* key, char *value, struct sc_config* sc_config);
static void _signal_handler(int signum);

int main(int argc, char **argv){
  int result = EXIT_SUCCESS;
  FILE* fp = NULL;

  /* allocate memory space for storing configuration */
  struct app_config *app_config = (struct app_config*)malloc(sizeof(struct app_config));
  if(unlikely(!app_config)){
    SC_ERROR_DETAILS("failed to allocate memory for app_config: %s\n", strerror(errno));
    result = EXIT_FAILURE;
    goto sc_exit;
  }
  memset(app_config, 0, sizeof(struct app_config));
  
  #if defined(SC_HAS_DOCA)
    struct doca_config *doca_config = (struct doca_config*)malloc(sizeof(struct doca_config));
    if(unlikely(!doca_config)){
      SC_ERROR_DETAILS("failed to allocate memory for doca_config: %s\n", strerror(errno));
      result = EXIT_FAILURE;
      goto sc_exit;
    }
    memset(doca_config, 0, sizeof(struct doca_config));
  #endif // SC_HAS_DOCA

  struct sc_config *sc_config = (struct sc_config*)malloc(sizeof(struct sc_config));
  if(unlikely(!sc_config)){
    SC_ERROR_DETAILS("failed to allocate memory for sc_config: %s\n", strerror(errno));
    result = EXIT_FAILURE;
    goto sc_exit;
  }
  memset(sc_config, 0, sizeof(struct sc_config));
  sc_config->app_config = app_config;
  #if defined(SC_HAS_DOCA)
    sc_config->doca_config = (void*)doca_config;
  #endif // SC_HAS_DOCA

  /* open dpdk configuration file */
  fp = fopen(dpdk_conf_path, "r");
  if(!fp){
    SC_ERROR("failed to open the base configuration file: %s\n", strerror(errno));
    result = EXIT_FAILURE;
    goto sc_exit;
  }
  SC_LOG("open dpdk configuration file from %s", dpdk_conf_path);

  /* parse dpdk configuration file */
  if(sc_util_parse_config(fp, sc_config, _parse_dpdk_kv_pair) != SC_SUCCESS){
    SC_ERROR("failed to parse the base configuration file, exit\n");
    result = EXIT_FAILURE;
    goto sc_exit;
  }
  SC_LOG("parsed configuration file");

  /* check configurations */
  if(_check_configuration(sc_config, argc, argv) != SC_SUCCESS){
    SC_ERROR("configurations check failed\n");
    result = EXIT_FAILURE;
    goto sc_exit;
  }
  SC_LOG("checked configuration file");

  /* init environment */
  if(_init_env(sc_config, argc, argv) != SC_SUCCESS){
    SC_ERROR("failed to initialize environment, exit\n");
    result = EXIT_FAILURE;
    goto sc_exit;
  }
  SC_LOG("initialized dpdk environment");

  /* initailize memory */
  if(init_memory(sc_config) != SC_SUCCESS){
    SC_ERROR("failed to initialize memory, exit\n");
    result = EXIT_FAILURE;
    goto sc_exit;
  }
  SC_LOG("initialized rte memory");

  /* initailize ports */
  if(init_ports(sc_config) != SC_SUCCESS){
    SC_ERROR("failed to initialize dpdk ports, exit\n");
    result = EXIT_FAILURE;
    goto sc_exit;
  }
  SC_LOG("initialized rte ports");

  /* initailize doca (if necessary) */
  #if defined(SC_HAS_DOCA)
    if(init_doca(sc_config, doca_conf_path) != SC_SUCCESS){
      SC_ERROR("failed to initialize doca, exit\n");
      result = EXIT_FAILURE;
      goto sc_exit;
    }
    SC_LOG("initialized doca");
  #endif

  /* initailize application */
  if(init_app(sc_config, APP_CONF_PATH) != SC_SUCCESS){
    SC_ERROR("failed to config application\n");
    result = EXIT_FAILURE;
    goto sc_exit;
  }
  SC_LOG("initialized application");

  /* initailize lcore threads */
  if(init_worker_threads(sc_config) != SC_SUCCESS){
    SC_ERROR("failed to initialize worker threads\n");
    result = EXIT_FAILURE;
    goto sc_exit;
  }
  SC_LOG("initialized worker threads");

  /* initailize logging thread */
  if(init_logging_thread(sc_config) != SC_SUCCESS){
    SC_ERROR("failed to initialize logging thread\n");
    result = EXIT_FAILURE;
    goto sc_exit;
  }
  SC_LOG("initialized logging threads");

  /* launch logging thread */
  if(launch_logging_thread_async(sc_config) != SC_SUCCESS){
    SC_ERROR("failed to launch logging thread\n");
    result = EXIT_FAILURE;
    goto sc_exit;
  }
  SC_LOG("launch logging threads");

  /* (sync/async) launch worker threads */
  if(launch_worker_threads(sc_config) != SC_SUCCESS){
    SC_ERROR("failed to launch worker threads\n");
    result = EXIT_FAILURE;
    goto sc_exit;
  }

sc_exit:
  rte_exit(result, "exit\n");
  return 0;
}

/*!
 * \brief   initialize environment, including rte eal
 * \param   sc_config   the global configuration
 * \param   argc        number of command line parameters
 * \param   argv        command line parameters
 * \return  zero for successfully initialization
 */
static int _init_env(struct sc_config *sc_config, int argc, char **argv){
  int i, ret, rte_argc = 0;
  char *rte_argv[SC_RTE_ARGC_MAX];
  char rte_init_str[256] = {0};
  mpz_t cpu_mask;
  char cpu_mask_buf[SC_MAX_NB_PORTS] = {0};
  char mem_channels_buf[8] = "";
  
  /* reset the random seed */
  srand((unsigned)time(NULL));

  /* config cpu mask */
  mpz_init(cpu_mask);
  for(i=0; i<sc_config->nb_used_cores; i++){
    mpz_setbit(cpu_mask, sc_config->core_ids[i]);
  }
  gmp_sprintf(cpu_mask_buf, "%ZX", cpu_mask);
  mpz_clear(cpu_mask);
  for(i=0; i<sc_config->nb_used_cores; i++){
    if(i == 0) printf("\nUSED CORES:\n");
    printf("%u ", sc_config->core_ids[i]);
    if(i == sc_config->nb_used_cores-1) printf("\n\n");
  }

  /* config memory channel */
  sprintf(mem_channels_buf, "%u", sc_config->nb_memory_channels_per_socket);

  /* prepare command line options for initailizing rte eal */
  rte_argc = 5;
  rte_argv[0] = "";
  rte_argv[1] = "-c";
  rte_argv[2] = cpu_mask_buf;
  rte_argv[3] = "-n";
  rte_argv[4] = mem_channels_buf;
  
  #if defined(SC_HAS_DOCA)
    /* 
     * specified used scalable functions, check more details:
     * [1] DOCA doc: https://docs.nvidia.com/networking/m/view-rendered-page.action?abstractPageId=71013008
     * [2] DPDK doc: https://doc.dpdk.org/guides/platform/mlx5.html#linux-environment
     */
    char **sf_eal_confs = (char**)malloc(sizeof(char*)*DOCA_CONF(sc_config)->nb_used_sfs);
    if(unlikely(!sf_eal_confs)){
      SC_ERROR_DETAILS("Failed to allocate memory for sf_eal_confs");
      return SC_ERROR_MEMORY;
    }
    for(i=0; i<DOCA_CONF(sc_config)->nb_used_sfs; i++){
      #define SF_EAL_CONF_STRLEN 128
        sf_eal_confs[i] = (char*)malloc(sizeof(char)*SF_EAL_CONF_STRLEN);
        if(unlikely(!sf_eal_confs[i])){
          SC_ERROR_DETAILS("Failed to allocate memory for sf_eal_confs[%d]", i);
          return SC_ERROR_MEMORY;
        }
        memset(sf_eal_confs[i], 0, SF_EAL_CONF_STRLEN);
        sprintf(sf_eal_confs[i], "auxiliary:%s,dv_flow_en=2", 
          DOCA_CONF(sc_config)->scalable_functions[i]);
      #undef SF_EAL_CONF_STRLEN

      rte_argv[rte_argc] = "-a";
      rte_argv[rte_argc+1] = sf_eal_confs[i];
      rte_argc += 2;
    }
  #endif // SC_HAS_DOCA

  for(i=0; i<rte_argc; i++){
    if(i!=0){
      sprintf(rte_init_str, "%s %s", rte_init_str, rte_argv[i]);
    } else {
      sprintf(rte_init_str, "%s", rte_argv[i]);
    }
  }
  SC_LOG("EAL initialize parameters:\n\t%s", rte_init_str);

  /* initialize rte eal */
  ret = rte_eal_init(rte_argc, rte_argv);
  if (ret < 0){
    printf("failed to init rte eal: %s\n", rte_strerror(-ret));
    return SC_ERROR_INTERNAL;
  }
  
  #if defined(SC_HAS_DOCA)
    /* free parameter string buffer */
    for(i=0; i<DOCA_CONF(sc_config)->nb_used_sfs; i++){ free(sf_eal_confs[i]); }
    free(sf_eal_confs);
  #endif

  /* register signal handler */
  signal(SIGINT, _signal_handler);
	signal(SIGTERM, _signal_handler);

  return SC_SUCCESS;
}

/*!
 * \brief   check whether configurations are valid
 * \param   sc_config   the global configuration
 * \param   argc        number of command line parameters
 * \param   argv        command line parameters
 * \return  zero for valid configuration
 */
static int _check_configuration(struct sc_config *sc_config, int argc, char **argv){
  uint32_t i;
  unsigned int socket_id;
  
  /* 
   * 1. check whether the specified lcores are located in the same NUMA socket,
   *    could be manually check through "numactl -H"
   * 2. check whether the specified lcores exceed the physical range
   */
  for(i=0; i<sc_config->nb_used_cores; i++){
    // TODO: rte_lcore_to_socket_id always return 0, is that a bug?
    if (i == 0) {
      socket_id = rte_lcore_to_socket_id(sc_config->core_ids[i]);
    } else {
      if (rte_lcore_to_socket_id(sc_config->core_ids[i]) != socket_id) {
        SC_ERROR_DETAILS("specified lcores aren't locate at the same NUMA socket");
        return SC_ERROR_INVALID_VALUE;
      }
    }

    if(sc_util_check_core_id(sc_config->core_ids[i]) != SC_SUCCESS){
      return SC_ERROR_INVALID_VALUE;
    }
  }

  /* check whether the number of queues per core is equal to the number of lcores */
  if(sc_config->nb_rx_rings_per_port != sc_config->nb_used_cores ||
     sc_config->nb_tx_rings_per_port != sc_config->nb_used_cores){
      SC_ERROR_DETAILS("the number of queues per core (rx: %u, tx: %u) isn't equal to the number of lcores (%u)",
        sc_config->nb_rx_rings_per_port,
        sc_config->nb_tx_rings_per_port,
        sc_config->nb_used_cores
      );
      return SC_ERROR_INVALID_VALUE;
  }

  /* check whether the core for logging is conflict with other worker cores */
  for(i=0; i<sc_config->nb_used_cores; i++){
    if(sc_config->core_ids[i] == sc_config->log_core_id){
      SC_ERROR_DETAILS("the core for logging is conflict with other worker cores");
      return SC_ERROR_INVALID_VALUE;
    }
  }

  #if defined(SC_HAS_DOCA)
    /* check whether number of scalable functions is valid */
    if(DOCA_CONF(sc_config)->nb_used_sfs == 0){
      SC_ERROR_DETAILS("no scalable functions is specified, unbale to initialize rte eal on Bluefield");
      return SC_ERROR_INVALID_VALUE;
    }
  #endif

  return SC_SUCCESS;
}

/*!
 * \brief   signal handler for stoping executing
 * \param   signum    index of the received signal
 */
static void _signal_handler(int signum) {
	if (signum == SIGINT || signum == SIGTERM) {
		SC_WARNING("signal %d received, preparing to exit...\n", signum);
		sc_force_quit = true;
	}
}


/*!
 * \brief   parse key-value pair of DPDK config
 * \param   key         the key of the config pair
 * \param   value       the value of the config pair
 * \param   sc_config   the global configuration
 * \return  zero for successfully parsing
 */
static int _parse_dpdk_kv_pair(char* key, char *value, struct sc_config* sc_config){
    int i, result = SC_SUCCESS;
    uint16_t nb_ports = 0;
    
    /* config: used device */
    if(!strcmp(key, "port_mac")){
        char *delim = ",";
        char *p, *port_mac;

        for(;;){
            if(nb_ports == 0)
                p = strtok(value, delim);
            else
                p = strtok(NULL, delim);
            
            if (!p) break;

            p = sc_util_del_both_trim(p);
            sc_util_del_change_line(p);

            port_mac = (char*)malloc(strlen(p)+1);
            if(unlikely(!port_mac)){
                SC_ERROR_DETAILS("Failed to allocate memory for port_mac");
                result = SC_ERROR_MEMORY;
                goto free_dev_src;
            }
            memset(port_mac, 0, strlen(p)+1);

            strcpy(port_mac, p);
            sc_config->port_mac[nb_ports] = port_mac;
            nb_ports += 1;
            printf("conf port mac: %s\n", port_mac);
        }

        sc_config->nb_conf_ports = nb_ports;
        printf("nb of conf port mac: %d\n", nb_ports);

        goto exit;

free_dev_src:
        for(i=0; i<nb_ports; i++) free(sc_config->port_mac[i]);
    }

    /* config: number of RX rings per port */
    if(!strcmp(key, "nb_rx_rings_per_port")){
        uint16_t nb_rings;
        value = sc_util_del_both_trim(value);
        sc_util_del_change_line(value);
        if(sc_util_atoui_16(value, &nb_rings) != SC_SUCCESS) {
            result = SC_ERROR_INVALID_VALUE;
            goto invalid_nb_rx_rings_per_port;
        }
            
        if(nb_rings <= 0 || nb_rings > SC_MAX_NB_QUEUE_PER_PORT) {
            result = SC_ERROR_INVALID_VALUE;
            goto invalid_nb_rx_rings_per_port;
        }

        sc_config->nb_rx_rings_per_port = nb_rings;
        goto exit;

invalid_nb_rx_rings_per_port:
        SC_ERROR_DETAILS("invalid configuration nb_rx_rings_per_port\n");
    }

    /* config: number of TX rings per port */
    if(!strcmp(key, "nb_tx_rings_per_port")){
        uint16_t nb_rings;
        value = sc_util_del_both_trim(value);
        sc_util_del_change_line(value);
        if (sc_util_atoui_16(value, &nb_rings) != SC_SUCCESS) {
            result = SC_ERROR_INVALID_VALUE;
            goto invalid_nb_tx_rings_per_port;
        }
            
        if(nb_rings == 0 || nb_rings > SC_MAX_NB_QUEUE_PER_PORT) {
            result = SC_ERROR_INVALID_VALUE;
            goto invalid_nb_tx_rings_per_port;
        }

        sc_config->nb_tx_rings_per_port = nb_rings;
        goto exit;

invalid_nb_tx_rings_per_port:
        SC_ERROR_DETAILS("invalid configuration nb_tx_rings_per_port\n");
    }

    /* config: whether to enable promiscuous mode */
    if(!strcmp(key, "enable_promiscuous")){
        value = sc_util_del_both_trim(value);
        sc_util_del_change_line(value);
        if (!strcmp(value, "true")){
            sc_config->enable_promiscuous = true;
        } else if (!strcmp(value, "false")){
            sc_config->enable_promiscuous = false;
        } else {
            result = SC_ERROR_INVALID_VALUE;
            goto invalid_enable_promiscuous;
        }

        goto exit;

invalid_enable_promiscuous:
        SC_ERROR_DETAILS("invalid configuration enable_promiscuous\n");
    }

    /* config: number of cores to used */
    if(!strcmp(key, "used_core_ids")){
        uint16_t nb_used_cores = 0;
        uint32_t core_id = 0;
        char *delim = ",";
        char *core_id_str;

        value = sc_util_del_both_trim(value);
        sc_util_del_change_line(value);
        
        for(;;){
            if(nb_used_cores == 0)
                core_id_str = strtok(value, delim);
            else
                core_id_str = strtok(NULL, delim);
            
            if (!core_id_str) break;

            core_id_str = sc_util_del_both_trim(core_id_str);
            sc_util_del_change_line(core_id_str);

            if (sc_util_atoui_32(core_id_str, &core_id) != SC_SUCCESS) {
                result = SC_ERROR_INVALID_VALUE;
                goto invalid_used_cores;
            }

            if (core_id > SC_MAX_NB_CORES) {
                result = SC_ERROR_INVALID_VALUE;
                goto invalid_used_cores;
            }

            sc_config->core_ids[nb_used_cores] = core_id;
            nb_used_cores += 1;
        }

        sc_config->nb_used_cores = nb_used_cores;
        goto exit;

invalid_used_cores:
        SC_ERROR_DETAILS("invalid configuration used_cores\n");
    }

    /* config: number of memory channels per socket */
    if(!strcmp(key, "nb_memory_channels_per_socket")){
        uint16_t nb_memory_channels_per_socket;
        value = sc_util_del_both_trim(value);
        sc_util_del_change_line(value);
        if (sc_util_atoui_16(value, &nb_memory_channels_per_socket) != SC_SUCCESS) {
            result = SC_ERROR_INVALID_VALUE;
            goto invalid_nb_memory_channels_per_socket;
        }

        sc_config->nb_memory_channels_per_socket = nb_memory_channels_per_socket;
        goto exit;

invalid_nb_memory_channels_per_socket:
        SC_ERROR_DETAILS("invalid configuration nb_memory_channels_per_socket\n");
    }

    /* config: the core for logging */
    if(!strcmp(key, "log_core_id")){
        uint32_t log_core_id;
        value = sc_util_del_both_trim(value);
        sc_util_del_change_line(value);
        if (sc_util_atoui_32(value, &log_core_id) != SC_SUCCESS) {
            result = SC_ERROR_INVALID_VALUE;
            goto invalid_log_core_id;
        }

        sc_config->log_core_id = log_core_id;
        goto exit;

invalid_log_core_id:
        SC_ERROR_DETAILS("invalid configuration log_core_id\n");
    }

    /* DOCA-specific configurations for DPDK */
    #if defined(SC_HAS_DOCA)
      uint16_t nb_sfs = 0;

      /* config: used scalable functions */
      if(!strcmp(key, "bf_scalable_functions")){
        char *delim = ",";
        char *p, *bf_sf;

        for(;;){
            if(nb_sfs == 0)
                p = strtok(value, delim);
            else
                p = strtok(NULL, delim);
            if (!p) break;

            p = sc_util_del_both_trim(p);
            sc_util_del_change_line(p);

            bf_sf = (char*)malloc(strlen(p)+1);
            if(unlikely(!bf_sf)){
                SC_ERROR_DETAILS("Failed to allocate memory for bf_sf\n");
                result = SC_ERROR_MEMORY;
                goto free_sfs;
            }
            memset(bf_sf, 0, strlen(p)+1);

            strcpy(bf_sf, p);
            DOCA_CONF(sc_config)->scalable_functions[nb_sfs] = bf_sf;
            nb_sfs += 1;
        }

        DOCA_CONF(sc_config)->nb_used_sfs = nb_sfs;

        goto exit;

free_sfs:
        for(i=0; i<nb_sfs; i++) free(DOCA_CONF(sc_config)->scalable_functions[i]);
        DOCA_CONF(sc_config)->nb_used_sfs = 0;
      }
    #endif // SC_HAS_DOCA

exit:
    return result;
}