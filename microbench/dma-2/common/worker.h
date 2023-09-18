#ifndef _WORKER_H_
#define _WORKER_H_

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <math.h>
#include <time.h>

#define NR_WORKER   1

#ifndef NSEC_PER_SEC
#define NSEC_PER_SEC        1000000000L
#endif  /* NSEC_PER_SEC */

#ifndef TIMESPEC_TO_NSEC
#define TIMESPEC_TO_NSEC(t)	(((t).tv_sec * NSEC_PER_SEC) + ((t).tv_nsec))
#endif  /* TIMESPEC_TO_NSEC */

struct worker {
	uint64_t interval;
	struct timespec last_submit;
};

extern __thread double mean;
extern __thread unsigned int seed;
extern __thread struct drand48_data drand_buf;
extern __thread struct worker worker[NR_WORKER];

static inline void init_worker(int nr_core, double rate) {
    for (int i = 0; i < NR_WORKER; i++) {
		worker[i].interval = 0;
		clock_gettime(CLOCK_MONOTONIC, &worker[i].last_submit);
	}

    mean = NR_WORKER * nr_core * 1.0e6 / rate;

	srand48_r(time(NULL), &drand_buf);
    seed = (unsigned int) time(NULL);
}

static inline bool if_time_to_submit(struct timespec * last_submit, struct timespec * now, uint64_t interval) {
    struct timespec diff = {.tv_sec = now->tv_sec - last_submit->tv_sec, .tv_nsec = now->tv_nsec - last_submit->tv_nsec};
	if (diff.tv_nsec < 0) {
		diff.tv_nsec += NSEC_PER_SEC;
		diff.tv_sec--;
	}
	return TIMESPEC_TO_NSEC(diff) > interval;
}

static inline double ran_expo(double mean) {
    double x;
    drand48_r(&drand_buf, &x);
    return -log(1 - x) * mean;
}

static inline void update_worker_timestamp(struct worker * worker, struct timespec * now) {
    worker->last_submit = *now;
    worker->interval = (uint64_t)round(ran_expo(mean));
    worker->last_submit = *now;
}

#endif  /* _WORKER_H_ */