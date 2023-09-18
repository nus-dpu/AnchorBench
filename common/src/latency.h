#ifndef _LATENCY_H_
#define _LATENCY_H_

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <time.h>

#define DISCARD_RATE    0.15

#define LAGGY_TIME_SEC  5
#define MAX_NR_LATENCY	20000

#ifndef NSEC_PER_SEC
#define NSEC_PER_SEC        1000000000L
#endif  /* NSEC_PER_SEC */

#ifndef TIMESPEC_TO_NSEC
#define TIMESPEC_TO_NSEC(t)	(((t).tv_sec * NSEC_PER_SEC) + ((t).tv_nsec))
#endif  /* TIMESPEC_TO_NSEC */

struct lat_info {
	uint64_t start;
	uint64_t end;
};

extern __thread int nr_latency;
extern __thread bool start_lat_record;
extern __thread struct lat_info * latency;

static inline void init_latency_array(void) {
    latency = (struct lat_info *)calloc(MAX_NR_LATENCY, sizeof(struct lat_info));
}

static inline void if_laggy_record_start(struct timespec * start, struct timespec * now) {
    if (now->tv_sec - start->tv_sec >= LAGGY_TIME_SEC) {
        start_lat_record = true;
    }
}

static inline void record_latency(struct timespec * ts1, struct timespec * ts2) {
    if (start_lat_record && latency && nr_latency < MAX_NR_LATENCY) {
        latency[nr_latency].start = TIMESPEC_TO_NSEC(*ts1);
        latency[nr_latency].end = TIMESPEC_TO_NSEC(*ts2);
        nr_latency++;
    }
}

void output_latency(char * name);

#endif  /* _LATENCY_H_ */