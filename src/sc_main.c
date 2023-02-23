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
#if defined(HAS_DOCA)
  #include "sc_doca.h"
#endif

/* indicator to force shutdown all threads (e.g. worker threads, logging thread, etc.) */
volatile bool sc_force_quit;

/* path to the base configuration file */
const char* base_conf_path = "../conf/base.conf";

/* path to the application configuration file */
#if defined(APP_SKETCH)
  const char* app_conf_path = "../conf/sketch.conf";
#else
  const char* app_conf_path = "";
#endif // APP_*

/* path to the doca configuration file */
#if defined(HAS_DOCA)
  const char* doca_conf_path = "../conf/doca.conf";
#endif

static int _init_env(struct sc_config *sc_config, int argc, char **argv);
static int _check_configuration(struct sc_config *sc_config, int argc, char **argv);
static int _parse_base_kv_pair(char* key, char *value, struct sc_config* sc_config);
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
  
  #if defined(HAS_DOCA)
    struct doca_config *doca_config = (struct doca_config*)malloc(sizeof(struct doca_config));
    if(unlikely(!doca_config)){
      SC_ERROR_DETAILS("failed to allocate memory for doca_config: %s\n", strerror(errno));
      result = EXIT_FAILURE;
      goto sc_exit;
    }
    memset(doca_config, 0, sizeof(struct doca_config));
  #endif // HAS_DOCA

  struct sc_config *sc_config = (struct sc_config*)malloc(sizeof(struct sc_config));
  if(unlikely(!sc_config)){
    SC_ERROR_DETAILS("failed to allocate memory for sc_config: %s\n", strerror(errno));
    result = EXIT_FAILURE;
    goto sc_exit;
  }
  memset(sc_config, 0, sizeof(struct sc_config));
  sc_config->app_config = app_config;
  #if defined(HAS_DOCA)
    sc_config->doca_config = (void*)doca_config;
  #endif // HAS_DOCA

  /* open configuration file */
  fp = fopen(base_conf_path, "r");
  if(!fp){
    SC_ERROR("failed to open the base configuration file: %s\n", strerror(errno));
    result = EXIT_FAILURE;
    goto sc_exit;
  }

  /* parse configuration file */
  if(parse_config(fp, sc_config, _parse_base_kv_pair) != SC_SUCCESS){
    SC_ERROR("failed to parse the base configuration file, exit\n");
    result = EXIT_FAILURE;
    goto sc_exit;
  }

  /* check configurations */
  if(_check_configuration(sc_config, argc, argv) != SC_SUCCESS){
    SC_ERROR("configurations check failed\n");
    result = EXIT_FAILURE;
    goto sc_exit;
  }

  /* init environment */
  if(_init_env(sc_config, argc, argv) != SC_SUCCESS){
    SC_ERROR("failed to initialize environment, exit\n");
    result = EXIT_FAILURE;
    goto sc_exit;
  }

  /* initailize memory */
  if(init_memory(sc_config) != SC_SUCCESS){
    SC_ERROR("failed to initialize memory, exit\n");
    result = EXIT_FAILURE;
    goto sc_exit;
  }

  /* initailize ports */
  if(init_ports(sc_config) != SC_SUCCESS){
    SC_ERROR("failed to initialize dpdk ports, exit\n");
    result = EXIT_FAILURE;
    goto sc_exit;
  }

  /* initailize doca (if necessary) */
  #if defined(HAS_DOCA)
    if(init_doca(sc_config, doca_conf_path) != SC_SUCCESS){
      SC_ERROR("failed to initialize doca, exit\n");
      result = EXIT_FAILURE;
      goto sc_exit;
    }
  #endif

  /* initailize application */
  if(init_app(sc_config, app_conf_path) != SC_SUCCESS){
    SC_ERROR("failed to config application\n");
    result = EXIT_FAILURE;
    goto sc_exit;
  }

  /* initailize lcore threads */
  if(init_worker_threads(sc_config) != SC_SUCCESS){
    SC_ERROR("failed to initialize worker threads\n");
    result = EXIT_FAILURE;
    goto sc_exit;
  }

  /* initailize logging thread */
  if(init_logging_thread(sc_config) != SC_SUCCESS){
    SC_ERROR("failed to initialize logging thread\n");
    result = EXIT_FAILURE;
    goto sc_exit;
  }

  /* launch logging thread */
  if(launch_logging_thread_async(sc_config) != SC_SUCCESS){
    SC_ERROR("failed to launch logging thread\n");
    result = EXIT_FAILURE;
    goto sc_exit;
  }

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
  mpz_t cpu_mask;
  char cpu_mask_buf[SC_MAX_NB_PORTS] = {0};
  char mem_channels_buf[8] = "";
  
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

  /* initialize rte eal */
  ret = rte_eal_init(rte_argc, rte_argv);
  if (ret < 0){
    printf("failed to init rte eal: %s\n", rte_strerror(-ret));
    return SC_ERROR_INTERNAL;
  }
  
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
        SC_ERROR_DETAILS("specified lcores aren't locate at the same NUMA socket\n");
        return SC_ERROR_INPUT;
      }
    }

    if(check_core_id(sc_config->core_ids[i]) != SC_SUCCESS){
      return SC_ERROR_INPUT;
    }
  }

  /* check whether the number of queues per core is equal to the number of lcores */
  if(sc_config->nb_rx_rings_per_port != sc_config->nb_used_cores ||
     sc_config->nb_tx_rings_per_port != sc_config->nb_used_cores){
      SC_ERROR_DETAILS("the number of queues per core (rx: %u, tx: %u) isn't equal to the number of lcores (%u) \n",
        sc_config->nb_rx_rings_per_port,
        sc_config->nb_tx_rings_per_port,
        sc_config->nb_used_cores
      );
      return SC_ERROR_INPUT;
  }

  /* check whether the core for logging is conflict with other worker cores */
  for(i=0; i<sc_config->nb_used_cores; i++){
    if(sc_config->core_ids[i] == sc_config->log_core_id){
      SC_ERROR_DETAILS("the core for logging is conflict with other worker cores");
      return SC_ERROR_INPUT;
    }
  }

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
 * \brief   parse key-value pair of base config
 * \param   key         the key of the config pair
 * \param   value       the value of the config pair
 * \param   sc_config   the global configuration
 * \return  zero for successfully parsing
 */
static int _parse_base_kv_pair(char* key, char *value, struct sc_config* sc_config){
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

            p = del_both_trim(p);
            del_change_line(p);

            port_mac = (char*)malloc(strlen(p)+1);
            if(unlikely(!port_mac)){
                SC_ERROR_DETAILS("Failed to allocate memory for port_mac\n");
                result = SC_ERROR_MEMORY;
                goto free_dev_src;
            }
            memset(port_mac, 0, strlen(p)+1);

            strcpy(port_mac, p);
            sc_config->port_mac[nb_ports] = port_mac;
            nb_ports += 1;
        }

        goto exit;

free_dev_src:
        for(i=0; i<nb_ports; i++) free(sc_config->port_mac[i]);
    }

    /* config: number of RX rings per port */
    if(!strcmp(key, "nb_rx_rings_per_port")){
        uint16_t nb_rings;
        value = del_both_trim(value);
        del_change_line(value);
        if(atoui_16(value, &nb_rings) != SC_SUCCESS) {
            result = SC_ERROR_INPUT;
            goto invalid_nb_rx_rings_per_port;
        }
            
        if(nb_rings <= 0 || nb_rings > SC_MAX_NB_QUEUE_PER_PORT) {
            result = SC_ERROR_INPUT;
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
        value = del_both_trim(value);
        del_change_line(value);
        if (atoui_16(value, &nb_rings) != SC_SUCCESS) {
            result = SC_ERROR_INPUT;
            goto invalid_nb_tx_rings_per_port;
        }
            
        if(nb_rings == 0 || nb_rings > SC_MAX_NB_QUEUE_PER_PORT) {
            result = SC_ERROR_INPUT;
            goto invalid_nb_tx_rings_per_port;
        }

        sc_config->nb_tx_rings_per_port = nb_rings;
        goto exit;

invalid_nb_tx_rings_per_port:
        SC_ERROR_DETAILS("invalid configuration nb_tx_rings_per_port\n");
    }

    /* config: whether to enable promiscuous mode */
    if(!strcmp(key, "enable_promiscuous")){
        value = del_both_trim(value);
        del_change_line(value);
        if (!strcmp(value, "true")){
            sc_config->enable_promiscuous = true;
        } else if (!strcmp(value, "false")){
            sc_config->enable_promiscuous = false;
        } else {
            result = SC_ERROR_INPUT;
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

        value = del_both_trim(value);
        del_change_line(value);
        
        for(;;){
            if(nb_used_cores == 0)
                core_id_str = strtok(value, delim);
            else
                core_id_str = strtok(NULL, delim);
            
            if (!core_id_str) break;

            core_id_str = del_both_trim(core_id_str);
            del_change_line(core_id_str);

            if (atoui_32(core_id_str, &core_id) != SC_SUCCESS) {
                result = SC_ERROR_INPUT;
                goto invalid_used_cores;
            }

            if (core_id > SC_MAX_NB_CORES) {
                result = SC_ERROR_INPUT;
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
        value = del_both_trim(value);
        del_change_line(value);
        if (atoui_16(value, &nb_memory_channels_per_socket) != SC_SUCCESS) {
            result = SC_ERROR_INPUT;
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
        value = del_both_trim(value);
        del_change_line(value);
        if (atoui_32(value, &log_core_id) != SC_SUCCESS) {
            result = SC_ERROR_INPUT;
            goto invalid_log_core_id;
        }

        sc_config->log_core_id = log_core_id;
        goto exit;

invalid_log_core_id:
        SC_ERROR_DETAILS("invalid configuration log_core_id\n");
    }

exit:
    return result;
}