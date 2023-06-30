#ifndef _SHA_MEMPOOL_H_
#define _SHA_MEMPOOL_H_

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <unistd.h>

#include <doca_buf.h>

#include "list.h"

#define CACHE_LINE_SIZE     64

/** 
 * Align a value to a given power of two (get round)
 * @result
 *      Aligned value that is no bigger than value
 */
#define ALIGN_ROUND(val, align) \
    (typeof(val))((val) & (~((typeof(val))((align) - 1))))

/**
 * Align a value to a given power of two (get ceiling)
 * @result
 *      Aligned value that is no smaller than value
 */
#define ALIGN_CEIL(val, align) \
    ALIGN_ROUND(val + (typeof(val))((align) - 1), align)

/** 
 * Force alignment
 */
#define __aligned(a)        __attribute__((__aligned__(a)))

/* Mempool element structure */
struct sha_mempool_elt {
    /* Entry for element list */
    struct list_head    list;
    /* Mempool this element belongs to */
    struct sha_mempool      * mp;
    /* Timestamp */
    struct timespec     ts;
    /* DOCA buf that holds the element data */
    struct doca_buf     * src_buf;
    char                * src_addr;
    /* DOCA buf that holds the element data */
    struct doca_buf     * dst_buf;
    char                * dst_addr;
};

/* Mempool structure */
struct sha_mempool {
    /* Size of an element */
    uint32_t            elt_size;

    /* Address of memory pool */     
    char                * addr;
    /* Size of memory pool */
    size_t              size;

    /* List of free objects */
    struct list_head    elt_free_list;
    /* List of used objects */
    struct list_head    elt_used_list;
};

extern int is_sha_mempool_empty(struct sha_mempool * mp);
extern struct sha_mempool * sha_mempool_create(int num_elt, size_t elt_size);
extern void sha_mempool_free(struct sha_mempool * mp);
extern int sha_mempool_get(struct sha_mempool * mp, struct sha_mempool_elt ** obj);
extern void sha_mempool_put(struct sha_mempool * mp, struct sha_mempool_elt * addr);

#endif  /* _SHA_MEMPOOL_H_ */