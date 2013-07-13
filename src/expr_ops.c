#include <string.h>
#include <linux_list.h>

#include "expr_ops.h"

static LIST_HEAD(expr_ops_list);

void nft_expr_ops_register(struct expr_ops *ops)
{
	list_add_tail(&ops->head, &expr_ops_list);
}

struct expr_ops *nft_expr_ops_lookup(const char *name)
{
	struct expr_ops *ops;

	list_for_each_entry(ops, &expr_ops_list, head) {
		if (strcmp(ops->name, name) == 0)
			return ops;
	}

	return NULL;
}
