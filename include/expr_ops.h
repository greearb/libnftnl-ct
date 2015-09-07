#ifndef _EXPR_OPS_H_
#define _EXPR_OPS_H_

#include <stdint.h>
#include "internal.h"

struct nlattr;
struct nlmsghdr;
struct nftnl_expr;

struct expr_ops {
	const char *name;
	uint32_t alloc_len;
	int	max_attr;
	void	(*free)(struct nftnl_expr *e);
	int	(*set)(struct nftnl_expr *e, uint16_t type, const void *data, uint32_t data_len);
	const void *(*get)(const struct nftnl_expr *e, uint16_t type, uint32_t *data_len);
	int 	(*parse)(struct nftnl_expr *e, struct nlattr *attr);
	void	(*build)(struct nlmsghdr *nlh, struct nftnl_expr *e);
	int	(*snprintf)(char *buf, size_t len, uint32_t type, uint32_t flags, struct nftnl_expr *e);
	int	(*xml_parse)(struct nftnl_expr *e, mxml_node_t *tree,
			     struct nftnl_parse_err *err);
	int	(*json_parse)(struct nftnl_expr *e, json_t *data,
			      struct nftnl_parse_err *err);
};

struct expr_ops *nftnl_expr_ops_lookup(const char *name);

#define nftnl_expr_data(ops) (void *)ops->data

#endif
