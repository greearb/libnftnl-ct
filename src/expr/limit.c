/*
 * (C) 2012-2013 by Pablo Neira Ayuso <pablo@netfilter.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This code has been sponsored by Sophos Astaro <http://www.sophos.com>
 */

#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <arpa/inet.h>
#include <errno.h>
#include <linux/netfilter/nf_tables.h>

#include "internal.h"
#include <libmnl/libmnl.h>
#include <libnftables/expr.h>
#include <libnftables/rule.h>
#include "expr_ops.h"

struct nft_expr_limit {
	uint64_t		rate;
	uint64_t		depth;
};

static int
nft_rule_expr_limit_set(struct nft_rule_expr *e, uint16_t type,
		       const void *data, size_t data_len)
{
	struct nft_expr_limit *limit = (struct nft_expr_limit *)e->data;

	switch(type) {
	case NFT_EXPR_LIMIT_RATE:
		limit->rate = *((uint64_t *)data);
		break;
	case NFT_EXPR_LIMIT_DEPTH:
		limit->depth = *((uint64_t *)data);
		break;
	default:
		return -1;
	}
	return 0;
}

static const void *
nft_rule_expr_limit_get(const struct nft_rule_expr *e, uint16_t type,
			size_t *data_len)
{
	struct nft_expr_limit *limit = (struct nft_expr_limit *)e->data;

	switch(type) {
	case NFT_EXPR_LIMIT_RATE:
		if (e->flags & (1 << NFT_EXPR_LIMIT_RATE))
			return &limit->rate;
		else
			return NULL;
		break;
	case NFT_EXPR_LIMIT_DEPTH:
		if (e->flags & (1 << NFT_EXPR_LIMIT_DEPTH))
			return &limit->depth;
		else
			return NULL;
		break;
	default:
		break;
	}
	return NULL;
}

static int nft_rule_expr_limit_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, NFTA_LIMIT_MAX) < 0)
		return MNL_CB_OK;

	switch(type) {
	case NFTA_LIMIT_RATE:
	case NFTA_LIMIT_DEPTH:
		if (mnl_attr_validate(attr, MNL_TYPE_U64) < 0) {
			perror("mnl_attr_validate");
			return MNL_CB_ERROR;
		}
		break;
	}

	tb[type] = attr;
	return MNL_CB_OK;
}

static void
nft_rule_expr_limit_build(struct nlmsghdr *nlh, struct nft_rule_expr *e)
{
	struct nft_expr_limit *limit = (struct nft_expr_limit *)e->data;

	if (e->flags & (1 << NFT_EXPR_LIMIT_RATE))
		mnl_attr_put_u64(nlh, NFTA_LIMIT_RATE, htobe64(limit->rate));
	if (e->flags & (1 << NFT_EXPR_LIMIT_DEPTH))
		mnl_attr_put_u64(nlh, NFTA_LIMIT_DEPTH, htobe64(limit->depth));
}

static int
nft_rule_expr_limit_parse(struct nft_rule_expr *e, struct nlattr *attr)
{
	struct nft_expr_limit *limit = (struct nft_expr_limit *)e->data;
	struct nlattr *tb[NFTA_LIMIT_MAX+1] = {};

	if (mnl_attr_parse_nested(attr, nft_rule_expr_limit_cb, tb) < 0)
		return -1;

	if (tb[NFTA_LIMIT_RATE]) {
		limit->rate = be64toh(mnl_attr_get_u64(tb[NFTA_LIMIT_RATE]));
		e->flags |= (1 << NFT_EXPR_LIMIT_RATE);
	}
	if (tb[NFTA_LIMIT_DEPTH]) {
		limit->depth = be64toh(mnl_attr_get_u64(tb[NFTA_LIMIT_DEPTH]));
		e->flags |= (1 << NFT_EXPR_LIMIT_DEPTH);
	}

	return 0;
}

static int nft_rule_expr_limit_xml_parse(struct nft_rule_expr *e, mxml_node_t *tree)
{
#ifdef XML_PARSING
	struct nft_expr_limit *limit = (struct nft_expr_limit *)e->data;
	mxml_node_t *node = NULL;
	uint64_t tmp;
	char *endptr;

	node = mxmlFindElement(tree, tree, "rate", NULL, NULL,
			       MXML_DESCEND_FIRST);
	if (node == NULL)
		goto err;

	tmp = strtoull(node->child->value.opaque, &endptr, 10);
	if (tmp > UINT64_MAX || tmp < 0 || *endptr)
		goto err;

	limit->rate = tmp;
	e->flags |= (1 << NFT_EXPR_LIMIT_RATE);

	node = mxmlFindElement(tree, tree, "depth", NULL, NULL,
			       MXML_DESCEND);
	if (node == NULL)
		goto err;

	tmp = strtoull(node->child->value.opaque, &endptr, 10);
	if (tmp > UINT64_MAX || tmp < 0 || *endptr)
		goto err;

	limit->depth = tmp;
	e->flags |= (1 << NFT_EXPR_LIMIT_DEPTH);

	return 0;
err:
	errno = EINVAL;
	return -1;
#else
	errno = EOPNOTSUPP;
	return -1;
#endif
}

static int
nft_rule_expr_limit_snprintf(char *buf, size_t len, uint32_t type,
			    uint32_t flags, struct nft_rule_expr *e)
{
	struct nft_expr_limit *limit = (struct nft_expr_limit *)e->data;

	switch(type) {
	case NFT_RULE_O_DEFAULT:
		return snprintf(buf, len, "rate %"PRIu64" depth %"PRIu64" ",
				limit->rate, limit->depth);
	case NFT_RULE_O_XML:
		return snprintf(buf, len, "<rate>%"PRIu64"</rate>"
					  "<depth>%"PRIu64"</depth>",
				limit->rate, limit->depth);
	case NFT_RULE_O_JSON:
		return snprintf(buf, len, "\"rate\" : %"PRIu64", "
					  "\"depth\" : %"PRIu64" ",
				limit->rate, limit->depth);
	default:
		break;
	}
	return -1;
}

struct expr_ops expr_ops_limit = {
	.name		= "limit",
	.alloc_len	= sizeof(struct nft_expr_limit),
	.max_attr	= NFTA_LIMIT_MAX,
	.set		= nft_rule_expr_limit_set,
	.get		= nft_rule_expr_limit_get,
	.parse		= nft_rule_expr_limit_parse,
	.build		= nft_rule_expr_limit_build,
	.snprintf	= nft_rule_expr_limit_snprintf,
	.xml_parse	= nft_rule_expr_limit_xml_parse,
};

static void __init expr_limit_init(void)
{
	nft_expr_ops_register(&expr_ops_limit);
}
