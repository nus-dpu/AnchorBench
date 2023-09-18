#include "worker.h"

__thread double mean;
__thread unsigned int seed;
__thread struct drand48_data drand_buf;
__thread struct worker worker[NR_WORKER];
