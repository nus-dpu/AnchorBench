#include "sc_global.h"
#include "sc_log.h"
#include "sc_utils.h"

char current_time_str[128] = "UNKNOWN TIME";
pthread_mutex_t thread_log_mutex;
pthread_mutex_t timer_mutex;
extern volatile bool sc_force_quit;

/*!
 * \brief   function that execute on the logging thread
 * \param   args   (sc_config) the global configuration
 */
void* _log_loop(void *args){
    time_t time_ptr;
    struct tm *tmp_ptr = NULL;
    struct sc_config *sc_config = (struct sc_config*)args;

    /* stick this thread to specified logging core */
    sc_util_stick_this_thread_to_core(sc_config->log_core_id);

    while(!sc_force_quit){
        /* timer */
        pthread_mutex_lock(&timer_mutex);
        time(&time_ptr);
        tmp_ptr = localtime(&time_ptr);
        memset(current_time_str, 0, sizeof(current_time_str));
        sprintf(current_time_str, "%d-%d-%d %d:%d:%d",
            tmp_ptr->tm_year + 1900,
            tmp_ptr->tm_mon + 1,
            tmp_ptr->tm_mday,
            tmp_ptr->tm_hour,
            tmp_ptr->tm_min,
            tmp_ptr->tm_sec
        );
        pthread_mutex_unlock(&timer_mutex);
    }

    SC_WARNING("logging thread exit\n");
    return NULL;
}

/*!
 * \brief   initialzie logging thread
 * \param   sc_config   the global configuration
 * \return  zero for successfully initialization
 */
int init_logging_thread(struct sc_config *sc_config){
    /* create logging thread handler */
    pthread_t *logging_thread = (pthread_t*)malloc(sizeof(pthread_t));
    if(unlikely(!logging_thread)){
        SC_ERROR_DETAILS("failed to allocate memory for logging thread hanlder");
        return SC_ERROR_MEMORY;
    }
    sc_config->logging_thread = logging_thread;

    /* initialize mutex lock for timer */
    if(pthread_mutex_init(&timer_mutex, NULL) != 0){
        SC_ERROR_DETAILS("failed to initialize timer mutex");
        return SC_ERROR_INTERNAL;
    }

    /* initialize log lock for each thread */
    if(pthread_mutex_init(&thread_log_mutex, NULL) != 0){
        SC_ERROR_DETAILS("failed to initialize per-thread log mutex");
        return SC_ERROR_INTERNAL;
    }

    return SC_SUCCESS;
}

/*!
 * \brief   launch logging thread
 * \param   sc_config   the global configuration
 * \return  zero for successfully launch
 */
int launch_logging_thread_async(struct sc_config *sc_config){
    if(pthread_create(sc_config->logging_thread, NULL, _log_loop, sc_config) != 0){
        SC_ERROR_DETAILS("failed to launch logger thread");
        return SC_ERROR_INTERNAL;
    }
    return SC_SUCCESS;
}

/*!
 * \brief   wait logging thread to finish
 * \param   sc_config   the global configuration
 * \return  zero for successfully launch
 */
int join_logging_thread(struct sc_config *sc_config){
    pthread_join(*(sc_config->logging_thread), NULL);
    pthread_mutex_destroy(&timer_mutex);
    return SC_SUCCESS;
}