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
#include <libnftnl/expr.h>
#include <libnftnl/rule.h>

struct nftnl_expr_limit {
	uint64_t		rate;
	uint64_t		unit;
};

static int
nftnl_rule_expr_limit_set(struct nftnl_rule_expr *e, uint16_t type,
		       const void *data, uint32_t data_len)
{
	struct nftnl_expr_limit *limit = nftnl_expr_data(e);

	switch(type) {
	case NFTNL_EXPR_LIMIT_RATE:
		limit->rate = *((uint64_t *)data);
		break;
	case NFTNL_EXPR_LIMIT_UNIT:
		limit->unit = *((uint64_t *)data);
		break;
	default:
		return -1;
	}
	return 0;
}

static const void *
nftnl_rule_expr_limit_get(const struct nftnl_rule_expr *e, uint16_t type,
			uint32_t *data_len)
{
	struct nftnl_expr_limit *limit = nftnl_expr_data(e);

	switch(type) {
	case NFTNL_EXPR_LIMIT_RATE:
		*data_len = sizeof(uint64_t);
		return &limit->rate;
	case NFTNL_EXPR_LIMIT_UNIT:
		*data_len = sizeof(uint64_t);
		return &limit->unit;
	}
	return NULL;
}

static int nftnl_rule_expr_limit_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, NFTA_LIMIT_MAX) < 0)
		return MNL_CB_OK;

	switch(type) {
	case NFTA_LIMIT_RATE:
	case NFTA_LIMIT_UNIT:
		if (mnl_attr_validate(attr, MNL_TYPE_U64) < 0)
			abi_breakage();
		break;
	}

	tb[type] = attr;
	return MNL_CB_OK;
}

static void
nftnl_rule_expr_limit_build(struct nlmsghdr *nlh, struct nftnl_rule_expr *e)
{
	struct nftnl_expr_limit *limit = nftnl_expr_data(e);

	if (e->flags & (1 << NFTNL_EXPR_LIMIT_RATE))
		mnl_attr_put_u64(nlh, NFTA_LIMIT_RATE, htobe64(limit->rate));
	if (e->flags & (1 << NFTNL_EXPR_LIMIT_UNIT))
		mnl_attr_put_u64(nlh, NFTA_LIMIT_UNIT, htobe64(limit->unit));
}

static int
nftnl_rule_expr_limit_parse(struct nftnl_rule_expr *e, struct nlattr *attr)
{
	struct nftnl_expr_limit *limit = nftnl_expr_data(e);
	struct nlattr *tb[NFTA_LIMIT_MAX+1] = {};

	if (mnl_attr_parse_nested(attr, nftnl_rule_expr_limit_cb, tb) < 0)
		return -1;

	if (tb[NFTA_LIMIT_RATE]) {
		limit->rate = be64toh(mnl_attr_get_u64(tb[NFTA_LIMIT_RATE]));
		e->flags |= (1 << NFTNL_EXPR_LIMIT_RATE);
	}
	if (tb[NFTA_LIMIT_UNIT]) {
		limit->unit = be64toh(mnl_attr_get_u64(tb[NFTA_LIMIT_UNIT]));
		e->flags |= (1 << NFTNL_EXPR_LIMIT_UNIT);
	}

	return 0;
}

static int nftnl_rule_expr_limit_json_parse(struct nftnl_rule_expr *e, json_t *root,
					  struct nftnl_parse_err *err)
{
#ifdef JSON_PARSING
	uint64_t uval64;

	if (nftnl_jansson_parse_val(root, "rate", NFTNL_TYPE_U64, &uval64, err) == 0)
		nftnl_rule_expr_set_u64(e, NFTNL_EXPR_LIMIT_RATE, uval64);

	if (nftnl_jansson_parse_val(root, "unit", NFTNL_TYPE_U64, &uval64, err) == 0)
		nftnl_rule_expr_set_u64(e, NFTNL_EXPR_LIMIT_UNIT, uval64);

	return 0;
#else
	errno = EOPNOTSUPP;
	return -1;
#endif
}

static int nftnl_rule_expr_limit_xml_parse(struct nftnl_rule_expr *e,
					 mxml_node_t *tree,
					 struct nftnl_parse_err *err)
{
#ifdef XML_PARSING
	uint64_t rate, unit;

	if (nftnl_mxml_num_parse(tree, "rate", MXML_DESCEND_FIRST, BASE_DEC,
			       &rate, NFTNL_TYPE_U64, NFTNL_XML_MAND, err) == 0)
		nftnl_rule_expr_set_u64(e, NFTNL_EXPR_LIMIT_RATE, rate);

	if (nftnl_mxml_num_parse(tree, "unit", MXML_DESCEND_FIRST, BASE_DEC,
			       &unit, NFTNL_TYPE_U64, NFTNL_XML_MAND, err) == 0)
		nftnl_rule_expr_set_u64(e, NFTNL_EXPR_LIMIT_UNIT, unit);

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

static int nftnl_rule_expr_limit_export(char *buf, size_t size,
				      struct nftnl_rule_expr *e, int type)
{
	struct nftnl_expr_limit *limit = nftnl_expr_data(e);
	NFTNL_BUF_INIT(b, buf, size);

	if (e->flags & (1 << NFTNL_EXPR_LIMIT_RATE))
		nftnl_buf_u64(&b, type, limit->rate, RATE);
	if (e->flags & (1 << NFTNL_EXPR_LIMIT_UNIT))
		nftnl_buf_u64(&b, type, limit->unit, UNIT);

	return nftnl_buf_done(&b);
}

static int nftnl_rule_expr_limit_snprintf_default(char *buf, size_t len,
						struct nftnl_rule_expr *e)
{
	struct nftnl_expr_limit *limit = nftnl_expr_data(e);

	return snprintf(buf, len, "rate %"PRIu64"/%s ",
			limit->rate, get_unit(limit->unit));
}

static int
nftnl_rule_expr_limit_snprintf(char *buf, size_t len, uint32_t type,
			    uint32_t flags, struct nftnl_rule_expr *e)
{

	switch(type) {
	case NFTNL_OUTPUT_DEFAULT:
		return nftnl_rule_expr_limit_snprintf_default(buf, len, e);
	case NFTNL_OUTPUT_XML:
	case NFTNL_OUTPUT_JSON:
		return nftnl_rule_expr_limit_export(buf, len, e, type);
	default:
		break;
	}
	return -1;
}

struct expr_ops expr_ops_limit = {
	.name		= "limit",
	.alloc_len	= sizeof(struct nftnl_expr_limit),
	.max_attr	= NFTA_LIMIT_MAX,
	.set		= nftnl_rule_expr_limit_set,
	.get		= nftnl_rule_expr_limit_get,
	.parse		= nftnl_rule_expr_limit_parse,
	.build		= nftnl_rule_expr_limit_build,
	.snprintf	= nftnl_rule_expr_limit_snprintf,
	.xml_parse	= nftnl_rule_expr_limit_xml_parse,
	.json_parse	= nftnl_rule_expr_limit_json_parse,
};
