#include "worker.h"

__thread unsigned int seed;
__thread struct drand48_data drand_buf;

