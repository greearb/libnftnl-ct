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
	uint64_t		unit;
};

static int
nft_rule_expr_limit_set(struct nft_rule_expr *e, uint16_t type,
		       const void *data, uint32_t data_len)
{
	struct nft_expr_limit *limit = nft_expr_data(e);

	switch(type) {
	case NFT_EXPR_LIMIT_RATE:
		limit->rate = *((uint64_t *)data);
		break;
	case NFT_EXPR_LIMIT_UNIT:
		limit->unit = *((uint64_t *)data);
		break;
	default:
		return -1;
	}
	return 0;
}

static const void *
nft_rule_expr_limit_get(const struct nft_rule_expr *e, uint16_t type,
			uint32_t *data_len)
{
	struct nft_expr_limit *limit = nft_expr_data(e);

	switch(type) {
	case NFT_EXPR_LIMIT_RATE:
		*data_len = sizeof(uint64_t);
		return &limit->rate;
	case NFT_EXPR_LIMIT_UNIT:
		*data_len = sizeof(uint64_t);
		return &limit->unit;
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
	case NFTA_LIMIT_UNIT:
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
	struct nft_expr_limit *limit = nft_expr_data(e);

	if (e->flags & (1 << NFT_EXPR_LIMIT_RATE))
		mnl_attr_put_u64(nlh, NFTA_LIMIT_RATE, htobe64(limit->rate));
	if (e->flags & (1 << NFT_EXPR_LIMIT_UNIT))
		mnl_attr_put_u64(nlh, NFTA_LIMIT_UNIT, htobe64(limit->unit));
}

static int
nft_rule_expr_limit_parse(struct nft_rule_expr *e, struct nlattr *attr)
{
	struct nft_expr_limit *limit = nft_expr_data(e);
	struct nlattr *tb[NFTA_LIMIT_MAX+1] = {};

	if (mnl_attr_parse_nested(attr, nft_rule_expr_limit_cb, tb) < 0)
		return -1;

	if (tb[NFTA_LIMIT_RATE]) {
		limit->rate = be64toh(mnl_attr_get_u64(tb[NFTA_LIMIT_RATE]));
		e->flags |= (1 << NFT_EXPR_LIMIT_RATE);
	}
	if (tb[NFTA_LIMIT_UNIT]) {
		limit->unit = be64toh(mnl_attr_get_u64(tb[NFTA_LIMIT_UNIT]));
		e->flags |= (1 << NFT_EXPR_LIMIT_UNIT);
	}

	return 0;
}

static int nft_rule_expr_limit_json_parse(struct nft_rule_expr *e, json_t *root,
					  struct nft_parse_err *err)
{
#ifdef JSON_PARSING
	uint64_t uval64;

	if (nft_jansson_parse_val(root, "rate", NFT_TYPE_U64, &uval64, err) < 0)
		return -1;

	nft_rule_expr_set_u64(e, NFT_EXPR_LIMIT_RATE, uval64);

	if (nft_jansson_parse_val(root, "unit", NFT_TYPE_U64, &uval64, err) < 0)
		return -1;

	nft_rule_expr_set_u64(e, NFT_EXPR_LIMIT_UNIT, uval64);

	return 0;
#else
	errno = EOPNOTSUPP;
	return -1;
#endif
}

static int nft_rule_expr_limit_xml_parse(struct nft_rule_expr *e,
					 mxml_node_t *tree,
					 struct nft_parse_err *err)
{
#ifdef XML_PARSING
	struct nft_expr_limit *limit = nft_expr_data(e);

	if (nft_mxml_num_parse(tree, "rate", MXML_DESCEND_FIRST, BASE_DEC,
			       &limit->rate, NFT_TYPE_U64, NFT_XML_MAND,
			       err) != 0)
		return -1;

	e->flags |= (1 << NFT_EXPR_LIMIT_RATE);

	if (nft_mxml_num_parse(tree, "unit", MXML_DESCEND_FIRST, BASE_DEC,
			       &limit->unit, NFT_TYPE_U64, NFT_XML_MAND,
			       err) != 0)
		return -1;

	e->flags |= (1 << NFT_EXPR_LIMIT_UNIT);

	return 0;
#else
	errno = EOPNOTSUPP;
	return -1;
#endif
}

static const char *get_unit(uint64_t u)
{
	switch (u) {
	case 1: return "second";
	case 60: return "minute";
	case 60 * 60: return "hour";
	case 60 * 60 * 24: return "day";
	case 60 * 60 * 24 * 7: return "week";
	}
	return "error";
}

static int
nft_rule_expr_limit_snprintf(char *buf, size_t len, uint32_t type,
			    uint32_t flags, struct nft_rule_expr *e)
{
	struct nft_expr_limit *limit = nft_expr_data(e);

	switch(type) {
	case NFT_OUTPUT_DEFAULT:
		return snprintf(buf, len, "rate %"PRIu64"/%s ",
				limit->rate, get_unit(limit->unit));
	case NFT_OUTPUT_XML:
		return snprintf(buf, len, "<rate>%"PRIu64"</rate>"
					  "<unit>%"PRIu64"</unit>",
				limit->rate, limit->unit);
	case NFT_OUTPUT_JSON:
		return snprintf(buf, len, "\"rate\":%"PRIu64","
					  "\"unit\":%"PRIu64"",
				limit->rate, limit->unit);
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
	.json_parse	= nft_rule_expr_limit_json_parse,
};

static void __init expr_limit_init(void)
{
	nft_expr_ops_register(&expr_ops_limit);
}
