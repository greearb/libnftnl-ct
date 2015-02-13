#ifndef _EXPR_OPS_H_
#define _EXPR_OPS_H_

#include <stdint.h>
#include "internal.h"

struct nlattr;
struct nlmsghdr;
struct nft_rule_expr;

struct expr_ops {
	struct list_head head;

	const char *name;
	uint32_t alloc_len;
	int	max_attr;
	void	(*free)(struct nft_rule_expr *e);
	int	(*set)(struct nft_rule_expr *e, uint16_t type, const void *data, uint32_t data_len);
	const void *(*get)(const struct nft_rule_expr *e, uint16_t type, uint32_t *data_len);
	int 	(*parse)(struct nft_rule_expr *e, struct nlattr *attr);
	void	(*build)(struct nlmsghdr *nlh, struct nft_rule_expr *e);
	int	(*snprintf)(char *buf, size_t len, uint32_t type, uint32_t flags, struct nft_rule_expr *e);
	int	(*xml_parse)(struct nft_rule_expr *e, mxml_node_t *tree,
			     struct nft_parse_err *err);
	int	(*json_parse)(struct nft_rule_expr *e, json_t *data,
			      struct nft_parse_err *err);
};

void nft_expr_ops_register(struct expr_ops *ops);
struct expr_ops *nft_expr_ops_lookup(const char *name);

#define nft_expr_data(ops) (void *)ops->data

#endif
