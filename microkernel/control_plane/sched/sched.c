#define _GNU_SOURCE
#include <sched.h>
#include <string.h>

#include "bitops.h"
#include "core.h"

struct core_info core_infos[NR_CPUS];
unsigned int cpu_id;

bool try_get_core(int sockfd, int core) {
    if (core_infos[core].occupied) {
        return false;
    }

    core_infos[core].sockfd = sockfd;
    core_infos[core].occupied = true;

    return true;
}

uint64_t get_avail_core(int sockfd, int nr_cores) {
    uint64_t cpumask = 0x0;
    int nr_allocated = 0;

    for (int i = 0; i < NR_CPUS && nr_allocated < nr_cores; i++) {
        if (try_get_core(sockfd, i)) {
            set_bit(i, (void *)&cpumask);
            nr_allocated++;
        }
    }

    return cpumask;
}

int __init sched_init(void) {
    /* Clear all cpu infos */
    memset(core_infos, 0, NR_CPUS * sizeof(struct core_info));

    /* First core is always allocated to control plane */
    core_infos[0].occupied = true;

    cpu_id = sched_getcpu();

    return 0;
}