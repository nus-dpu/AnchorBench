#ifndef _REGEX_MEMPOOL_H_
#define _REGEX_MEMPOOL_H_

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
struct regex_mempool_elt {
    /* Entry for element list */
    struct list_head    list;
    /* Mempool this element belongs to */
    struct regex_mempool    * mp;
    /* DOCA buf that holds the element data */
    struct doca_buf     * buf;
    /* Timestamp */
    struct timespec     ts;
    void                * response;
    void                * packet;
    int                 packet_size;
    char                * addr;
};

/* Mempool structure */
struct regex_mempool {
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

extern int is_regex_mempool_empty(struct regex_mempool * mp);
extern struct regex_mempool * regex_mempool_create(int num_elt, size_t elt_size);
extern void regex_mempool_free(struct regex_mempool * mp);
extern int regex_mempool_get(struct regex_mempool * mp, struct regex_mempool_elt ** obj);
extern void regex_mempool_put(struct regex_mempool * mp, struct regex_mempool_elt * addr);

#endif  /* _REGEX_MEMPOOL_H_ */