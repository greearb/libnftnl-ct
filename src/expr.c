/*
 * (C) 2012 by Pablo Neira Ayuso <pablo@netfilter.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This code has been sponsored by Sophos Astaro <http://www.sophos.com>
 */
#include "internal.h"
#include "expr_ops.h"

#include <time.h>
#include <endian.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>

#include <libmnl/libmnl.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nf_tables.h>

#include <libnftables/expr.h>

#include "linux_list.h"

struct nft_rule_expr *nft_rule_expr_alloc(const char *name)
{
	struct nft_rule_expr *expr;
	struct expr_ops *ops;

	ops = nft_expr_ops_lookup(name);
	if (ops == NULL)
		return NULL;

	expr = calloc(1, sizeof(struct nft_rule_expr) + ops->alloc_len);
	if (expr == NULL)
		return NULL;

	/* Manually set expression name attribute */
	expr->flags |= (1 << NFT_RULE_EXPR_ATTR_NAME);
	expr->ops = ops;

	return expr;
}
EXPORT_SYMBOL(nft_rule_expr_alloc);

void nft_rule_expr_free(struct nft_rule_expr *expr)
{
	free(expr);
}
EXPORT_SYMBOL(nft_rule_expr_free);

bool nft_rule_expr_is_set(const struct nft_rule_expr *expr, uint16_t type)
{
	return expr->flags & (1 << type);
}
EXPORT_SYMBOL(nft_rule_expr_is_set);

void
nft_rule_expr_set(struct nft_rule_expr *expr, uint16_t type,
		  const void *data, size_t data_len)
{
	switch(type) {
	case NFT_RULE_EXPR_ATTR_NAME:	/* cannot be modified */
		return;
	default:
		if (expr->ops->set(expr, type, data, data_len) < 0)
			return;
	}
	expr->flags |= (1 << type);
}
EXPORT_SYMBOL(nft_rule_expr_set);

void
nft_rule_expr_set_u8(struct nft_rule_expr *expr, uint16_t type, uint8_t data)
{
	nft_rule_expr_set(expr, type, &data, sizeof(uint8_t));
}
EXPORT_SYMBOL(nft_rule_expr_set_u8);

void
nft_rule_expr_set_u32(struct nft_rule_expr *expr, uint16_t type, uint32_t data)
{
	nft_rule_expr_set(expr, type, &data, sizeof(uint32_t));
}
EXPORT_SYMBOL(nft_rule_expr_set_u32);

void
nft_rule_expr_set_u64(struct nft_rule_expr *expr, uint16_t type, uint64_t data)
{
	nft_rule_expr_set(expr, type, &data, sizeof(uint64_t));
}
EXPORT_SYMBOL(nft_rule_expr_set_u64);

void
nft_rule_expr_set_str(struct nft_rule_expr *expr, uint16_t type, const char *str)
{
	nft_rule_expr_set(expr, type, str, strlen(str)+1);
}
EXPORT_SYMBOL(nft_rule_expr_set_str);

const void *nft_rule_expr_get(struct nft_rule_expr *expr, uint16_t type, size_t *data_len)
{
	const void *ret = NULL;

	switch(type) {
	case NFT_RULE_EXPR_ATTR_NAME:
		if (!(expr->flags & (1 << NFT_RULE_EXPR_ATTR_NAME)))
			return NULL;

		ret = expr->ops->name;
		break;
	default:
		ret = expr->ops->get(expr, type, data_len);
		break;
	}

	return ret;
}
EXPORT_SYMBOL(nft_rule_expr_get);

uint8_t nft_rule_expr_get_u8(struct nft_rule_expr *expr, uint16_t type)
{
	const void *data;
	size_t data_len;

	data = nft_rule_expr_get(expr, type, &data_len);
	if (data == NULL)
		return 0;

	if (data_len != sizeof(uint8_t))
		return 0;

	return *((uint8_t *)data);
}
EXPORT_SYMBOL(nft_rule_expr_get_u8);

uint32_t nft_rule_expr_get_u32(struct nft_rule_expr *expr, uint16_t type)
{
	const void *data;
	size_t data_len;

	data = nft_rule_expr_get(expr, type, &data_len);
	if (data == NULL)
		return 0;

	if (data_len != sizeof(uint32_t))
		return 0;

	return *((uint32_t *)data);
}
EXPORT_SYMBOL(nft_rule_expr_get_u32);

uint64_t nft_rule_expr_get_u64(struct nft_rule_expr *expr, uint16_t type)
{
	const void *data;
	size_t data_len;

	data = nft_rule_expr_get(expr, type, &data_len);
	if (data == NULL)
		return 0;

	if (data_len != sizeof(uint64_t))
		return 0;

	return *((uint64_t *)data);
}
EXPORT_SYMBOL(nft_rule_expr_get_u64);

const char *nft_rule_expr_get_str(struct nft_rule_expr *expr, uint16_t type)
{
	size_t data_len;

	return (const char *)nft_rule_expr_get(expr, type, &data_len);
}
EXPORT_SYMBOL(nft_rule_expr_get_str);

void
nft_rule_expr_build_payload(struct nlmsghdr *nlh, struct nft_rule_expr *expr)
{
	struct nlattr *nest1, *nest2;

	nest1 = mnl_attr_nest_start(nlh, NFTA_LIST_ELEM);
	mnl_attr_put_strz(nlh, NFTA_EXPR_NAME, expr->ops->name);

	nest2 = mnl_attr_nest_start(nlh, NFTA_EXPR_DATA);
	expr->ops->build(nlh, expr);
	mnl_attr_nest_end(nlh, nest2);

	mnl_attr_nest_end(nlh, nest1);
}
EXPORT_SYMBOL(nft_rule_expr_build_payload);
