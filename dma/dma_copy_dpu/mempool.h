#ifndef _MEMPOOL_H_
#define _MEMPOOL_H_

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

/* ====================================================================== */
/* Mempool element structure with single DOCA buf */
struct mempool_elt {
    /* Entry for element list */
    struct list_head    list;
    /* Mempool this element belongs to */
    struct mempool      * mp;
    /* DOCA buf that holds the element data */
    struct doca_buf     * buf1; /* malloc */
    struct doca_buf     * buf2; /* mmap */
    /* Timestamp */
    struct timespec     ts;
    void                * response;
    char                addr[0];
};

/* Mempool structure */
struct mempool {
    int                 nb_elt;
    /* Size of one element (start from addr) */
    uint32_t            elt_size;
    /* Size of memory pool */
    size_t              total_size;

    /* List of free objects */
    struct list_head    elt_free_list;
    /* List of used objects */
    struct list_head    elt_used_list;

    /* Address of memory pool */
    char                elts[0];
};

extern int is_mempool_empty(struct mempool * mp);
extern struct mempool * mempool_create(int num_elt, size_t elt_size);
extern void mempool_free(struct mempool * mp);
extern int mempool_get(struct mempool * mp, struct mempool_elt ** obj);
extern void mempool_put(struct mempool * mp, struct mempool_elt * addr);

#endif  /* _MEMPOOL_H_ */