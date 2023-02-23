#ifndef _SC_LOG_H_
#define _SC_LOG_H_

#include <time.h>
#include <pthread.h>

#include <rte_lcore.h>

extern char current_time_str[128];
extern pthread_mutex_t timer_mutex;
extern pthread_mutex_t thread_log_mutex;

int init_logging_thread(struct sc_config *sc_config);
int launch_logging_thread_async(struct sc_config *sc_config);
int join_logging_thread(struct sc_config *sc_config);

#define SC_LOG_ENABLE true

#define SC_THREAD_LOG_LOCK() pthread_mutex_lock(&thread_log_mutex);
#define SC_THREAD_LOG_UNLOCK() pthread_mutex_unlock(&thread_log_mutex);

#define SC_ERROR(...) \
{\
pthread_mutex_lock(&timer_mutex);\
fprintf(stderr, "\033[31m%s\033[0m \033[101m\033[97m Error \033[0m ", current_time_str);\
pthread_mutex_unlock(&timer_mutex);\
fprintf(stderr, __VA_ARGS__);\
fprintf(stderr, "\n");\
fflush(stderr);\
}

#define SC_ERROR_DETAILS(...) \
{\
SC_ERROR(__VA_ARGS__)\
fprintf(stderr, "\
  \033[33mfile:\033[0m       %s;\n\
  \033[33mfunction:\033[0m   %s;\n\
  \033[33mline:\033[0m       %d;\n", __FILE__, __func__, __LINE__);\
fflush(stderr);\
}

#define SC_THREAD_ERROR(...) \
{\
pthread_mutex_lock(&timer_mutex);\
fprintf(stderr, "\033[31m%s\033[0m \033[101m\033[97m lcore %u Error \033[0m ", current_time_str, rte_lcore_id());\
pthread_mutex_unlock(&timer_mutex);\
fprintf(stderr, __VA_ARGS__);\
fprintf(stderr, "\n");\
fflush(stderr);\
}

#define SC_THREAD_ERROR_DETAILS(...) \
{\
SC_ERROR(__VA_ARGS__)\
fprintf(stderr, "\
  \033[33mlcore:\033[0m      %u;\n\
  \033[33mfile:\033[0m       %s;\n\
  \033[33mfunction:\033[0m   %s;\n\
  \033[33mline:\033[0m       %d;\n", rte_lcore_id(), __FILE__, __func__, __LINE__);\
fflush(stderr);\
}

#define SC_WARNING(...) \
{\
pthread_mutex_lock(&timer_mutex);\
fprintf(stdout, "\033[31m%s\033[0m \033[103m\033[97m Warning \033[0m ", current_time_str);\
pthread_mutex_unlock(&timer_mutex);\
fprintf(stdout, __VA_ARGS__);\
fprintf(stdout, "\n");\
fflush(stdout);\
}

#define SC_WARNING_DETAILS(...) \
{\
SC_WARNING(__VA_ARGS__)\
fprintf(stdout, "\
  \033[33mfile:\033[0m       %s;\n\
  \033[33mfunction:\033[0m   %s;\n\
  \033[33mline:\033[0m       %d;\n", __FILE__, __func__, __LINE__);\
fflush(stdout);\
}

#define SC_THREAD_WARNING(...) \
{\
pthread_mutex_lock(&timer_mutex);\
fprintf(stdout, "\033[31m%s\033[0m \033[103m\033[97m lcore %u Warning \033[0m ", current_time_str, rte_lcore_id());\
pthread_mutex_unlock(&timer_mutex);\
fprintf(stdout, __VA_ARGS__);\
fprintf(stdout, "\n");\
fflush(stdout);\
}

#define SC_THREAD_WARNING_DETAILS(...) \
{\
SC_WARNING(__VA_ARGS__)\
fprintf(stdout, "\
  \033[33mlcore:\033[0m      %u;\n\
  \033[33mfile:\033[0m       %s;\n\
  \033[33mfunction:\033[0m   %s;\n\
  \033[33mline:\033[0m       %d;\n", rte_lcore_id(), __FILE__, __func__, __LINE__);\
fflush(stdout);\
}

#if SC_LOG_ENABLE

#define SC_LOG(...) \
{\
pthread_mutex_lock(&timer_mutex);\
fprintf(stdout, "\033[31m%s\033[0m \033[104m\033[97m Debug \033[0m ", current_time_str);\
pthread_mutex_unlock(&timer_mutex);\
fprintf(stdout, __VA_ARGS__);\
fprintf(stdout, "\n");\
fflush(stdout);\
}

#define SC_LOG_DETAILS(...) \
{\
SC_LOG(__VA_ARGS__)\
fprintf(stdout, "\
  \033[33mfile:\033[0m       %s;\n\
  \033[33mfunction:\033[0m   %s;\n\
  \033[33mline:\033[0m       %d;\n", __FILE__, __func__, __LINE__);\
fflush(stdout);\
}

#define SC_THREAD_LOG(...) \
{\
pthread_mutex_lock(&timer_mutex);\
fprintf(stdout, "\033[31m%s\033[0m \033[104m\033[97m lcore %u Debug \033[0m ", current_time_str, rte_lcore_id());\
pthread_mutex_unlock(&timer_mutex);\
fprintf(stdout, __VA_ARGS__);\
fprintf(stdout, "\n");\
fflush(stdout);\
}

#define SC_THREAD_LOG_DETAILS(...) \
{\
SC_LOG(__VA_ARGS__)\
fprintf(stdout, "\
  \033[33mlcore:\033[0m      %u;\n\
  \033[33mfile:\033[0m       %s;\n\
  \033[33mfunction:\033[0m   %s;\n\
  \033[33mline:\033[0m       %d;\n", rte_lcore_id(), __FILE__, __func__, __LINE__);\
fflush(stdout);\
}
#else
#define SC_LOG(...)
#define SC_LOG_DETAILS(...)
#define SC_THREAD_LOG(...)
#define SC_THREAD_LOG_DETAILS(...)
#endif

#endif