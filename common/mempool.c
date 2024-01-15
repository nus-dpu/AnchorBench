#include "mempool.h"

/* ====================================================================== */
int is_sgl_mempool_empty(struct sgl_mempool * mp) {
    if (list_empty(&mp->elt_free_list)) {
        return 1;
    }

    return 0;
}

/*----------------------------------------------------------------------------*/
struct sgl_mempool * sgl_mempool_create(int n, size_t size) {
    size_t elt_size = size + sizeof(struct sgl_mempool_elt);
    size_t total_size = n * elt_size;

    struct sgl_mempool * mp = (struct sgl_mempool *)malloc(sizeof(struct sgl_mempool) + total_size);

    if (!mp) {
        goto failed;
    }

    memset(mp, 0, sizeof(struct sgl_mempool) + total_size);

    mp->elt_size = size;
    mp->total_size = total_size;

    init_list_head(&mp->elt_free_list);
    init_list_head(&mp->elt_used_list);

    /* Segment the region into pieces */
    for (int i = 0; i < n; i++) {
        struct sgl_mempool_elt * elt = &mp->elts[i];
        elt->mp = mp;
        list_add_tail(&elt->list, &mp->elt_free_list);
    }

    return mp;

failed:
    free(mp);
    return NULL;
}

/*----------------------------------------------------------------------------*/
void sgl_mempool_free(struct sgl_mempool * mp) {
    free(mp);
    return;
}

/*----------------------------------------------------------------------------*/
int sgl_mempool_get(struct sgl_mempool * mp, struct sgl_mempool_elt ** obj) {
    struct sgl_mempool_elt * elt = list_first_entry_or_null(&mp->elt_free_list, struct sgl_mempool_elt, list);

    if (!elt) {
        *obj = NULL;
        return -ENOENT;
    }
    
    list_del_init(&elt->list);
    *obj = elt;

    return 0;
}

/*----------------------------------------------------------------------------*/
void sgl_mempool_put(struct sgl_mempool * mp, struct sgl_mempool_elt * elt) {
    list_add_tail(&elt->list, &mp->elt_free_list);
}

/* ====================================================================== */
int is_dbl_mempool_empty(struct dbl_mempool * mp) {
    if (list_empty(&mp->elt_free_list)) {
        return 1;
    }

    return 0;
}

/*----------------------------------------------------------------------------*/
struct dbl_mempool * dbl_mempool_create(int n, size_t size) {
    size_t elt_size = 2 * size + sizeof(struct dbl_mempool_elt);
    size_t total_size = n * elt_size;

    struct dbl_mempool * mp = (struct dbl_mempool *)malloc(sizeof(struct dbl_mempool) + total_size);

    if (!mp) {
        goto failed;
    }

    memset(mp, 0, sizeof(struct dbl_mempool) + total_size);

    mp->elt_size = size;
    mp->total_size = total_size;

    init_list_head(&mp->elt_free_list);
    init_list_head(&mp->elt_used_list);

    /* Segment the region into pieces */
    for (int i = 0; i < n; i++) {
        struct dbl_mempool_elt * elt = &mp->elts[i];
        elt->mp = mp;
        list_add_tail(&elt->list, &mp->elt_free_list);
    }

    return mp;

failed:
    free(mp);
    return NULL;
}

/*----------------------------------------------------------------------------*/
void dbl_mempool_free(struct dbl_mempool * mp) {
    free(mp);
    return;
}

/*----------------------------------------------------------------------------*/
int dbl_mempool_get(struct dbl_mempool * mp, struct dbl_mempool_elt ** obj) {
    struct dbl_mempool_elt * elt = list_first_entry_or_null(&mp->elt_free_list, struct dbl_mempool_elt, list);

    if (!elt) {
        *obj = NULL;
        return -ENOENT;
    }
    
    list_del_init(&elt->list);
    *obj = elt;

    return 0;
}

/*----------------------------------------------------------------------------*/
void dbl_mempool_put(struct dbl_mempool * mp, struct dbl_mempool_elt * elt) {
    list_add_tail(&elt->list, &mp->elt_free_list);
}