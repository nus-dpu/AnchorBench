#ifndef _LIST_H_
#define _LIST_H_

#include <stdio.h>
#include <stddef.h>

struct list_head {
    struct list_head * next;
    struct list_head * prev;
};

/**
 * list_empty - test whether a list is empty
 * 
 * @param head the list to test
 */
static inline int list_empty(const struct list_head * head) {
    return head->next == head;
}

/**
 * list_is_null - test whether a list is null
 * 
 * * Used by pthread_mutex (PTHREAD_MUTEX_INITIALIZER set list to NULL)
 * @param head the list to test
 */
static inline int list_is_null(const struct list_head * head) {
    return (head->next == NULL) && (head->prev == NULL);
}

#define LIST_HEAD_INIT(name) { &(name), &(name) }

/**
 * init_list_head - initialize a given list
 * 
 * @param list the list to be initialized
 */
static inline void init_list_head(struct list_head * list) {
    list->next = list->prev = list;
}

/**
 * list_is_singular - tests whether a list has just one entry.
 * @head: the list to test.
 */
static inline int list_is_singular(struct list_head *head) {
	return !list_empty(head) && (head->next == head->prev);
}

/**
 * __list_add - insert a new entry between two known consecutive entries
 * 
 * @param entry the new entry to be added
 * @param prev the previous entry
 * @param next the next entry
 */
static inline void __list_add(struct list_head * entry, struct list_head * prev, struct list_head * next) {
    next->prev = entry;
    entry->next = next;
    entry->prev = prev;
    prev->next = entry;
}

/**
 * list_add - add a new list entry
 * 
 * @param entry the new entry to be added
 * @param head list head to add it after
 */
static inline void list_add(struct list_head * entry, struct list_head * head) {
    __list_add(entry, head, head->next);
}

/**
 * list_add_head - add an entry at the head of the list
 * 
 * @param entry the new entry to be added
 * @param head list head to add it
 */
static inline void list_add_head(struct list_head * entry, struct list_head * head) {
    list_add(entry, head);
}

/**
 * list_add_tail - add an entry at the tail of the list
 * 
 * @param entry the new entry to be added
 * @param head list head to add
 */
static inline void list_add_tail(struct list_head * entry, struct list_head * head) {
    list_add(entry, head->prev);
}

/**
 * __list_del - delete a list entry 
 * 
 * @param prev the previous entry of the deleted entry
 * @param next the next entry of the deleted entry
 */
static inline void __list_del(struct list_head * prev, struct list_head * next) {
    next->prev = prev;
    prev->next = next;
}

/**
 * list_del_init - delete an entry from the list and reinitialize it 
 * 
 * @param entry the element to be deleted from the list
 */
static inline void list_del_init(struct list_head * entry) {
    __list_del(entry->prev, entry->next);
    init_list_head(entry);
}

/**
 * list_del - delete an entry from the list and nullify it
 * 
 * @param entry the element to be deleted from the list
 */
static inline void list_del(struct list_head * entry) {
    __list_del(entry->prev, entry->next);
    entry->next = entry->prev = NULL;
}

/**
 * list_entry - get the struct for this entry 
 * 
 * @param ptr the &struct list_head pointer
 * @param type the type of the struct this is embedded in
 * @param member the name of the list_head within the struct
 */
#define list_entry(ptr, type, member)   \
    (type *)((char *)ptr - offsetof(type, member))

/**
 * list_first_entry - get the first element from a list
 * 
 * @param ptr the list head to take the element from
 * @param type the type of the struct this is embedded in
 * @param member the name of the list_head within the struct
 */
#define list_first_entry(ptr, type, member) \
    list_entry((ptr)->next, type, member)

/**
 * list_first_entry_or_null - get the first element from a list
 * * Return NULL if the list is empty
 * 
 * @param ptr the list head to take the element from
 * @param type the type of the struct this is embedded in
 * @param member the name of the list_head within the struct
 * 
 */
#define list_first_entry_or_null(ptr, type, member) ({  \
    struct list_head * head__ = (ptr);  \
    struct list_head * pos__ = head__->next;    \
    pos__ != head__ ? list_entry(pos__, type, member) : NULL; \
})

/**
 * list_last_entry - get the last element from a list
 * 
 * @param ptr the list head to take the element from
 * @param type the type of the struct this is embedded in
 * @param member the name of the list_head within the struct
 */
#define list_last_entry(ptr, type, member) \
    list_entry((ptr)->prev, type, member)

/**
 * list_next_entry - get the next element in list
 * 
 * @param pos the type * to cursor
 * @param member the name of the list_head within the struct
 */
#define list_next_entry(pos, member) \
    list_entry((pos)->member.next, typeof(*(pos)), member)

/**
 * list_prev_entry - get the previous element in list
 * 
 * @param pos the type * to cursor
 * @param member the name of the list_head within the struct
 */
#define list_prev_entry(pos, member) \
    list_entry((pos)->member.prev, typeof(*(pos)), member)

/**
 * list_entry_is_head - test if the entry points to the head of the list
 * @pos:	the type * to cursor
 * @head:	the head for your list.
 * @member:	the name of the list_head within the struct.
 */
#define list_entry_is_head(pos, head, member)				\
	(&pos->member == (head))

/**
 * list_for_each	-	iterate over a list
 * @pos:	the &struct list_head to use as a loop cursor.
 * @head:	the head for your list.
 */
#define list_for_each(pos, head) \
	for (pos = (head)->next; pos != (head); pos = pos->next)

/**
 * list_for_each_entry - iterate over list of given type
 * 
 * @param pos the type * to cursor
 * @param head the head of the list
 * @param member the name of the list_head within the struct
 */
#define list_for_each_entry(pos, head, member)  \
    for (pos = list_first_entry(head, typeof(*pos), member);    \
        &pos->member != (head); \
        pos = list_next_entry(pos, member))

/**
 * list_for_each_entry_safe - iterate over list of given type
 * * Safe against removal of list entry
 * 
 * @param pos the type * to cursor
 * @param n another type * to use as temporary storage
 * @param head the head of the list
 * @param member the name of the list_head within the struct
 */
#define list_for_each_entry_safe(pos, n, head, member)  \
    for (pos = list_first_entry(head, typeof(*pos), member),    \
        n = list_next_entry(pos, member);   \
        &pos->member != (head); \
        pos = n, n = list_next_entry(n, member))

/**
 * list_for_each_entry_safe_reverse - iterate backwards over list safe against removal
 * @pos:	the type * to use as a loop cursor.
 * @n:		another type * to use as temporary storage
 * @head:	the head for your list.
 * @member:	the name of the list_head within the struct.
 *
 * Iterate backwards over list of given type, safe against removal
 * of list entry.
 */
#define list_for_each_entry_safe_reverse(pos, n, head, member)		\
	for (pos = list_last_entry(head, typeof(*pos), member),		\
		n = list_prev_entry(pos, member);			\
        !list_entry_is_head(pos, head, member); 			\
        pos = n, n = list_prev_entry(n, member))

static inline void __list_splice(const struct list_head * list, struct list_head * prev, struct list_head * next) {
	struct list_head *first = list->next;
	struct list_head *last = list->prev;

	first->prev = prev;
	prev->next = first;

	last->next = next;
	next->prev = last;
}

/**
 * list_splice - join two lists, this is designed for stacks
 * @list: the new list to add.
 * @head: the place to add it in the first list.
 */
static inline void list_splice(const struct list_head * list, struct list_head * head) {
	if (!list_empty(list)) {
        __list_splice(list, head, head->next);
    }
}

/**
 * list_splice_init - join two lists and reinitialise the emptied list.
 * @list: the new list to add.
 * @head: the place to add it in the first list.
 *
 * The list at @list is reinitialised
 */
static inline void list_splice_init(struct list_head * list, struct list_head * head) {
	if (!list_empty(list)) {
		__list_splice(list, head, head->next);
		init_list_head(list);
	}
}

/**
 * list_splice_tail_init - join two lists and reinitialise the emptied list
 * @list: the new list to add.
 * @head: the place to add it in the first list.
 *
 * Each of the lists is a queue.
 * The list at @list is reinitialised
 */
static inline void list_splice_tail_init(struct list_head * list, struct list_head * head) {
	if (!list_empty(list)) {
		__list_splice(list, head->prev, head);
		init_list_head(list);
	}
}

#endif  /* _LIST_H_ */