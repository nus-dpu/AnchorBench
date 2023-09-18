#ifndef _WORKER_H_
#define _WORKER_H_

extern __thread unsigned int seed;
extern __thread struct drand48_data drand_buf;

#endif  /* _WORKER_H_ */