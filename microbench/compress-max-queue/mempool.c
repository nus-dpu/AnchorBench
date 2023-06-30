#include "mempool.h"

int is_mempool_empty(struct mempool * mp) {
    if (list_empty(&mp->elt_free_list)) {
        return 1;
    }

    return 0;
}

/*----------------------------------------------------------------------------*/
struct mempool * mempool_create(int num_elt, size_t elt_size) {
    size_t total_size = num_elt * elt_size;

    struct mempool * mp = (struct mempool *)malloc(sizeof(struct mempool));

    if (!mp) {
        goto failed;
    }
    /* Allocate a continuous memory region */
    mp->addr = (char *)calloc(num_elt, elt_size);
    if (!mp->addr) {
        goto free_mp;
    }

    mp->elt_size = elt_size;
    mp->size = total_size;

    init_list_head(&mp->elt_free_list);
    init_list_head(&mp->elt_used_list);

    struct mempool_elt * elts = (struct mempool_elt *)calloc(num_elt / 2, sizeof(struct mempool_elt));

    /* Segment the region into pieces */
    for (int i = 0; i < num_elt; i += 2) {
        // struct mempool_elt * elt = (struct mempool_elt *)calloc(1, sizeof(struct mempool_elt));
        struct mempool_elt * elt = (struct mempool_elt *)&elts[i / 2];
        elt->mp = mp;
        elt->src_addr = mp->addr + i * elt_size;
        elt->dst_addr = mp->addr + (i + 1) * elt_size;
        list_add_tail(&elt->list, &mp->elt_free_list);
    }

    return mp;

free_mp:
    free(mp);
failed:
    return NULL;
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