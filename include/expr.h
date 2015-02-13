#ifndef _LIBNFTNL_EXPR_INTERNAL_H_
#define _LIBNFTNL_EXPR_INTERNAL_H_

struct expr_ops;

struct nft_rule_expr {
	struct list_head	head;
	uint32_t		flags;
	struct expr_ops		*ops;
	uint8_t			data[];
};

#endif
