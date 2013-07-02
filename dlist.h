#ifndef _DLIST_H_
#define _DLIST_H_

#include <stddef.h>

struct dlist_node_tag {
	struct dlist_node_tag *next;
	struct dlist_node_tag *prev;
};


struct dlist_tag {
	unsigned int size;
	struct dlist_node_tag dummy;
};


typedef struct dlist_tag dlist_t;
typedef struct dlist_node_tag dlist_node_t;


void dlist_init(dlist_t *list);

void dlist_append(dlist_t *list, dlist_node_t *node);

void dlist_prepend(dlist_t *list, dlist_node_t *node);

dlist_node_t *dlist_remove(dlist_t *list, dlist_node_t *node);

dlist_node_t *dlist_remove_head(dlist_t *list);

dlist_node_t *dlist_remove_rear(dlist_t *list);

unsigned int dlist_size(dlist_t *list);


dlist_node_t *dlist_foreach(dlist_t *list, int (*visitor)(dlist_node_t *));

dlist_node_t *dlist_get_head(dlist_t *list);

dlist_node_t *dlist_get_rear(dlist_t *list);



#define dlist_get_struct_ptr(struct_type_name, field_name, node_address) \
	((struct_type_name*)((char*)node_address - offsetof(struct_type_name, field_name)))


#define dlist_begin_foreach(list, struct_type_name, field_name, var_ptr_name) { \
	dlist_node_t *_p = (list)->dummy.next; \
	for (; _p != &((list)->dummy); _p = _p->next) { \
		struct_type_name *var_ptr_name = \
			((struct_type_name*)((char*)_p - \
				offsetof(struct_type_name, field_name)));

				
#define dlist_end_foreach }}

#endif
