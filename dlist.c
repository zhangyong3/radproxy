#include "dlist.h"
#include <stdio.h>

void dlist_init(dlist_t *list)
{
	list->size = 0;
	list->dummy.next = &list->dummy;
	list->dummy.prev = &list->dummy;
}

void dlist_append(dlist_t *list, dlist_node_t *node)
{
	dlist_node_t *p = &list->dummy;

	node->next = p;
	node->prev = p->prev;
	
	p->prev->next = node;
	p->prev = node;
	list->size+=1;
}

void dlist_prepend(dlist_t *list, dlist_node_t *node)
{
	dlist_node_t *p = &list->dummy;

	node->next = p->next;
	node->prev = p;
	
	p->next->prev = node;
	p->next = node;
	list->size+=1;
}


dlist_node_t *dlist_remove(dlist_t *list, dlist_node_t *node)
{
	dlist_node_t *p = &list->dummy;
	if (node == p)
		return NULL;

	node->prev->next = node->next;
	node->next->prev = node->prev;
	list->size-=1;
	return node;
}

dlist_node_t *dlist_remove_head(dlist_t *list)
{
	dlist_node_t *p = &list->dummy;
	if (p->next == p)
		return NULL;

	return dlist_remove(list, p->next);
}

dlist_node_t *dlist_remove_rear(dlist_t *list)
{
	dlist_node_t *p = &list->dummy;
	if (p->next == p)
		return NULL;

	return dlist_remove(list, p->prev);
}

unsigned int dlist_size(dlist_t *list)
{
	return list->size;
}


dlist_node_t *dlist_foreach(dlist_t *list, int (*visitor)(dlist_node_t *))
{
	dlist_node_t *p = list->dummy.next;
	for (; p != &list->dummy; p = p->next) {
		if (visitor(p)) {
			return p;
		}
	}

	return NULL;
}

dlist_node_t *dlist_get_head(dlist_t *list)
{
	dlist_node_t *p = list->dummy.next;
	if (p != &list->dummy)
		return p;

	return NULL;
}

dlist_node_t *dlist_get_rear(dlist_t *list)
{
	dlist_node_t *p = list->dummy.prev;
	if (p != &list->dummy)
		return p;

	return NULL;
}


#ifdef TEST
#include <stdio.h>
#include <stdlib.h>

/*
gcc -o t -DTEST dlist.c
*/
struct intdata
{
	dlist_node_t node;
	int val;
};


int intvisitor(dlist_node_t *p)
{
	struct intdata *x = dlist_get_struct_ptr(struct intdata, node, p);
	printf("%d\n", x->val);
	return 0;
}

int main()
{
	dlist_t list;
	dlist_init(&list);

	struct intdata *p;
	int i;

	for (i = 0; i < 10; i++) {
		struct intdata *d;
		d = calloc(1, sizeof(*d));
		d->val = i;
		
		if (i == 5)
			p = d;

		dlist_append(&list, &d->node);
	}

	intvisitor(&p->node);

	printf("size of list=%u\n", dlist_size(&list));
	dlist_foreach(&list, intvisitor);

	//printf("\ndelete\n");
	dlist_remove(&list, &p->node);
	dlist_prepend(&list, &p->node);
	printf("size of list=%u\n", dlist_size(&list));
	dlist_foreach(&list, intvisitor);

	printf("\n");
	dlist_node_t *t;
	t = dlist_get_head(&list);
	if (t != NULL)
		intvisitor(t);

	t = dlist_get_rear(&list);
	if (t != NULL)
		intvisitor(t);

	printf("-----------\n");
	dlist_begin_foreach(&list, struct intdata, node, p_node)
	{
		printf(" %d", p_node->val);
	}
	dlist_end_foreach();
	
	printf("\n");

	return 0;
}


#endif
