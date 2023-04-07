#ifndef _COMMON_MEMPOOL_H_
#define _COMMON_MEMPOOL_H_

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <unistd.h>

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
struct mempool_elt {
    /* Entry for element list */
    struct list_head    list;
    /* Mempool this element belongs to */
    struct mempool      * mp;
    /* Mempool element size */
    int                 size;
    /* Element address */
    char                * addr;
};

/* Mempool structure */
struct mempool {
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

extern struct mempool * mempool_create(char * name, int num_elt, size_t elt_size);
extern void mempool_free(struct mempool * mp);
extern int mempool_get(struct mempool * mp, void ** obj);
extern void mempool_put(struct mempool * mp, void * addr);

#endif  /* _COMMON_MEMPOOL_H_ */