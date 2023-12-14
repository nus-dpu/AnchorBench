#include "mempool.h"

int is_mempool_empty(struct mempool * mp) {
    if (list_empty(&mp->elt_free_list)) {
        return 1;
    }

    return 0;
}

/*----------------------------------------------------------------------------*/
struct mempool * mempool_create(int n, size_t size) {
    size_t elt_size = size + sizeof(struct mempool_elt);
    size_t total_size = n * elt_size;

    struct mempool * mp = (struct mempool *)malloc(sizeof(struct mempool) + total_size);

    if (!mp) {
        goto failed;
    }

    memset(mp, 0, sizeof(struct mempool) + total_size);

    mp->elt_size = size;
    mp->total_size = total_size;

    init_list_head(&mp->elt_free_list);
    init_list_head(&mp->elt_used_list);

    /* Segment the region into pieces */
    for (int i = 0; i < n; i++) {
        struct mempool_elt * elt = &mp->elts[i];
        elt->mp = mp;
        list_add_tail(&elt->list, &mp->elt_free_list);
    }

    return mp;

failed:
    free(mp);
    return NULL;
}

/*----------------------------------------------------------------------------*/
void mempool_free(struct mempool * mp) {
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
    *obj = elt;

    return 0;
}

/*----------------------------------------------------------------------------*/
void mempool_put(struct mempool * mp, struct mempool_elt * elt) {
    list_add_tail(&elt->list, &mp->elt_free_list);
}