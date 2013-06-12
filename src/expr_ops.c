#include <string.h>

#include "expr_ops.h"

extern struct expr_ops expr_ops_bitwise;
extern struct expr_ops expr_ops_byteorder;
extern struct expr_ops expr_ops_cmp;
extern struct expr_ops expr_ops_counter;
extern struct expr_ops expr_ops_ct;
extern struct expr_ops expr_ops_exthdr;
extern struct expr_ops expr_ops_immediate;
extern struct expr_ops expr_ops_log;
extern struct expr_ops expr_ops_lookup;
extern struct expr_ops expr_ops_match;
extern struct expr_ops expr_ops_meta;
extern struct expr_ops expr_ops_nat;
extern struct expr_ops expr_ops_payload;
extern struct expr_ops expr_ops_target;

struct expr_ops *expr_ops[] = {
	&expr_ops_bitwise,
	&expr_ops_byteorder,
	&expr_ops_cmp,
	&expr_ops_counter,
	&expr_ops_ct,
	&expr_ops_exthdr,
	&expr_ops_immediate,
	&expr_ops_match,
	&expr_ops_meta,
	&expr_ops_nat,
	&expr_ops_payload,
	&expr_ops_target,
	&expr_ops_log,
	&expr_ops_lookup,
	NULL,
};

struct expr_ops *nft_expr_ops_lookup(const char *name)
{
	int i = 0;

	while (expr_ops[i] != NULL) {
		if (strcmp(expr_ops[i]->name, name) == 0)
			return expr_ops[i];

		i++;
	}

	return NULL;
}
