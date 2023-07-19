#ifndef _LYRA_SCHED_H_
#define _LYRA_SCHED_H_

#include <stdbool.h>

#include "init.h"

#ifndef CONFIG_NR_CPUS
#define CONFIG_NR_CPUS  1
#endif

#define NR_CPUS CONFIG_NR_CPUS

struct core_info {
    int sockfd;
    bool occupied;
};

extern struct core_info core_infos[NR_CPUS];

extern unsigned int cpu_id;

extern bool try_get_core(int sockfd, int core);
extern uint64_t get_avail_core(int sockfd, int nr_cores);

extern int __init sched_init(void);

#endif  /* _LYRA_SCHED_H_ */