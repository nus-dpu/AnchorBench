#include "mempool.h"

/*----------------------------------------------------------------------------*/
struct mempool * mempool_create(char * buf, int num_elt, size_t elt_size) {
    size_t total_size = num_elt * elt_size;

    struct mempool * mp = (struct mempool *)malloc(sizeof(struct mempool));

    if (!mp) {
        goto failed;
    }

    mp->addr = buf;
    if (!mp->addr) {
        goto free_mp;
    }

    mp->elt_size = elt_size;
    mp->size = total_size;

    init_list_head(&mp->elt_free_list);
    init_list_head(&mp->elt_used_list);

    for (int i = 0; i < num_elt; i++) {
        struct mempool_elt * elt = (struct mempool_elt *)calloc(1, sizeof(struct mempool_elt));
        elt->mp = mp;
        elt->size = elt_size;
        elt->addr = mp->addr + i * elt_size;
	    printf("\t -> element %d: %p\n", i, elt->addr);
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
int mempool_get(struct mempool * mp, void ** obj) {
    struct mempool_elt * elt = list_first_entry_or_null(&mp->elt_free_list, struct mempool_elt, list);

    if (!elt) {
        *obj = NULL;
        return -ENOENT;
    }
    
    list_del_init(&elt->list);
    list_add_tail(&elt->list, &mp->elt_used_list);

    *obj = elt->addr;

    return 0;
}

/*----------------------------------------------------------------------------*/
void mempool_put(struct mempool * mp, void * addr) {
    struct mempool_elt * elt, * temp;
    list_for_each_entry_safe(elt, temp, &mp->elt_used_list, list) {
        if(elt->addr == addr) {
            list_del_init(&elt->list);
            memset(elt->addr, 0, elt->size);
            list_add_tail(&elt->list, &mp->elt_free_list);
            break;
        }
    }
}