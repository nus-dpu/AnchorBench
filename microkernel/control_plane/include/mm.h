#ifndef _LYRA_MM_H_
#define _LYRA_MM_H_

#include "bitops.h"
#include "init.h"

#define NR_FD_BLOCK 32
#define NR_MAX_FILE (NR_FD_BLOCK * BITS_PER_TYPE(unsigned long))

struct file {
    const struct file_operations * f_op;
    union {
        int fd;
        void * ptr;
    } f_priv_data;
    char            f_path[64];
	unsigned int    f_flags;
    unsigned int    f_count;
} __attribute__((aligned(64)));

extern int __init mm_init(void);

#endif  /* _LYRA_MM_H_ */

