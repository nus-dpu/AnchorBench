#ifndef DMA_COPY_H_
#define DMA_COPY_H_

#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

struct worker {
	uint64_t interval;
	struct timespec last_enq_time;
};

#endif	/* DMA_COPY_H_ */