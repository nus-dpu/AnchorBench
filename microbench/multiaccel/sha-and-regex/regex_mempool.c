#include "regex_mempool.h"

int is_regex_mempool_empty(struct regex_mempool * mp) {
    if (list_empty(&mp->elt_free_list)) {
        return 1;
    }

    return 0;
}

/*----------------------------------------------------------------------------*/
struct regex_mempool * regex_mempool_create(int num_elt, size_t elt_size) {
    size_t total_size = num_elt * elt_size;

    struct regex_mempool * mp = (struct regex_mempool *)malloc(sizeof(struct regex_mempool));

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

    struct regex_mempool_elt * elts = (struct regex_mempool_elt *)calloc(num_elt, sizeof(struct regex_mempool_elt));

    /* Segment the region into pieces */
    for (int i = 0; i < num_elt; i++) {
        struct regex_mempool_elt * elt = (struct regex_mempool_elt *)&elts[i];
        elt->mp = mp;
        elt->addr = mp->addr + i * elt_size;
        list_add_tail(&elt->list, &mp->elt_free_list);
    }

    return mp;

free_mp:
    free(mp);
failed:
    return NULL;
}

/*----------------------------------------------------------------------------*/
void regex_mempool_free(struct regex_mempool * mp) {
    struct regex_mempool_elt * elt, * temp;
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
int regex_mempool_get(struct regex_mempool * mp, struct regex_mempool_elt ** obj) {
    struct regex_mempool_elt * elt = list_first_entry_or_null(&mp->elt_free_list, struct regex_mempool_elt, list);

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
void regex_mempool_put(struct regex_mempool * mp, struct regex_mempool_elt * elt) {
    list_add_tail(&elt->list, &mp->elt_free_list);
}