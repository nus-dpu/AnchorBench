#include "mempool.h"

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

int is_mempool_empty(struct mempool * mp) {
    if (list_empty(&mp->elt_free_list)) {
        return 1;
    }

    return 0;
}

/*----------------------------------------------------------------------------*/
int mempool_create(struct mempool * mp, int num_elt, size_t elt_size) {
    size_t round_size = ALIGN_CEIL(elt_size, 64);
    size_t total_size = num_elt * round_size;

    /* Allocate a continuous memory region */
    mp->addr = (char *)calloc(num_elt, round_size);
    if (!mp->addr) {
        goto free_mp;
    }

    mp->elt_size = round_size;
    mp->size = total_size;

    init_list_head(&mp->elt_free_list);
    init_list_head(&mp->elt_used_list);

    struct mempool_elt * elts = (struct mempool_elt *)calloc(num_elt, sizeof(struct mempool_elt));

    /* Segment the region into pieces */
    for (int i = 0; i < num_elt; i++) {
        struct mempool_elt * elt = (struct mempool_elt *)&elts[i];
        elt->mp = mp;
        elt->addr = mp->addr + i * round_size;
        list_add_tail(&elt->list, &mp->elt_free_list);
    }

    return 0;

free_mp:
    free(mp);
    return -1;
}

/*----------------------------------------------------------------------------*/
void mempool_free(struct mempool * mp) {
    struct mempool_elt * elt, * temp;
    list_for_each_entry_safe(elt, temp, &mp->elt_free_list, list) {
        free(elt);
    }

    list_for_each_entry_safe(elt, temp, &mp->elt_used_list, list) {
        free(elt);
    }

    free(mp->addr);
    free(mp);
    
    return;
}

/*----------------------------------------------------------------------------*/
int mempool_get(struct mempool * mp, struct mempool_elt ** obj) {
    struct mempool_elt * elt = list_first_entry_or_null(&mp->elt_free_list, struct mempool_elt, list);

    if (!elt) {
        *obj = NULL;
        return -ENOENT;
    }
    
    list_del_init(&elt->list);
    // list_add_tail(&elt->list, &mp->elt_used_list);

    // *obj = elt->addr;
    *obj = elt;

    return 0;
}

/*----------------------------------------------------------------------------*/
void mempool_put(struct mempool * mp, struct mempool_elt * elt) {
    // list_del_init(&elt->list);
    // memset(elt->addr, 0, mp->elt_size);
    list_add_tail(&elt->list, &mp->elt_free_list);
}