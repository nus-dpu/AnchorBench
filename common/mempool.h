#ifndef _COMMON_MEMPOOL_H_
#define _COMMON_MEMPOOL_H_

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
struct sgl_mempool_elt {
    /* Entry for element list */
    struct list_head    list;
    /* Mempool this element belongs to */
    struct sgl_mempool  * mp;
    /* DOCA buf that holds the element data */
    struct doca_buf     * buf;
    /* Timestamp */
    struct timespec     ts;
    void                * response;
    char                addr[0];
};

/* Mempool structure */
struct sgl_mempool {
    /* Size of one element (start from addr) */
    uint32_t            elt_size;
    /* Size of memory pool */
    size_t              total_size;

    /* List of free objects */
    struct list_head    elt_free_list;
    /* List of used objects */
    struct list_head    elt_used_list;

    /* Address of memory pool */
    struct sgl_mempool_elt  elts[0];
};

extern int is_sgl_mempool_empty(struct sgl_mempool * mp);
extern struct sgl_mempool * sgl_mempool_create(int num_elt, size_t elt_size);
extern void sgl_mempool_free(struct sgl_mempool * mp);
extern int sgl_mempool_get(struct sgl_mempool * mp, struct sgl_mempool_elt ** obj);
extern void sgl_mempool_put(struct sgl_mempool * mp, struct sgl_mempool_elt * addr);

/* ====================================================================== */
/* Mempool element structure with single DOCA buf */
struct dbl_mempool_elt {
    /* Entry for element list */
    struct list_head    list;
    /* Mempool this element belongs to */
    struct sgl_mempool  * mp;
    /* DOCA buf that holds the element data */
    struct doca_buf     * buf1;
    struct doca_buf     * buf2;
    /* Timestamp */
    struct timespec     ts;
    void                * response;
    char                addr[0];
};

/* Mempool structure */
struct dbl_mempool {
    /* Size of one element (start from addr) */
    uint32_t            elt_size;
    /* Size of memory pool */
    size_t              total_size;

    /* List of free objects */
    struct list_head    elt_free_list;
    /* List of used objects */
    struct list_head    elt_used_list;

    /* Address of memory pool */
    struct dbl_mempool_elt  elts[0];
};

extern int is_dbl_mempool_empty(struct dbl_mempool * mp);
extern struct dbl_mempool * dbl_mempool_create(int num_elt, size_t elt_size);
extern void dbl_mempool_free(struct dbl_mempool * mp);
extern int dbl_mempool_get(struct dbl_mempool * mp, struct dbl_mempool_elt ** obj);
extern void dbl_mempool_put(struct dbl_mempool * mp, struct dbl_mempool_elt * addr);

#endif  /* _COMMON_MEMPOOL_H_ */