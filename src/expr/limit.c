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
	uint32_t		burst;
	enum nft_limit_type	type;
	uint32_t		flags;
};

static int
nftnl_expr_limit_set(struct nftnl_expr *e, uint16_t type,
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
	case NFTNL_EXPR_LIMIT_BURST:
		limit->burst = *((uint32_t *)data);
		break;
	case NFTNL_EXPR_LIMIT_TYPE:
		limit->type = *((uint32_t *)data);
		break;
	case NFTNL_EXPR_LIMIT_FLAGS:
		limit->flags = *((uint32_t *)data);
		break;
	default:
		return -1;
	}
	return 0;
}

static const void *
nftnl_expr_limit_get(const struct nftnl_expr *e, uint16_t type,
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
	case NFTNL_EXPR_LIMIT_BURST:
		*data_len = sizeof(uint32_t);
		return &limit->burst;
	case NFTNL_EXPR_LIMIT_TYPE:
		*data_len = sizeof(uint32_t);
		return &limit->type;
	case NFTNL_EXPR_LIMIT_FLAGS:
		*data_len = sizeof(uint32_t);
		return &limit->flags;
	}
	return NULL;
}

static int nftnl_expr_limit_cb(const struct nlattr *attr, void *data)
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
	case NFTA_LIMIT_BURST:
	case NFTA_LIMIT_TYPE:
	case NFTA_LIMIT_FLAGS:
		if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0)
			abi_breakage();
		break;
	}

	tb[type] = attr;
	return MNL_CB_OK;
}

static void
nftnl_expr_limit_build(struct nlmsghdr *nlh, const struct nftnl_expr *e)
{
	struct nftnl_expr_limit *limit = nftnl_expr_data(e);

	if (e->flags & (1 << NFTNL_EXPR_LIMIT_RATE))
		mnl_attr_put_u64(nlh, NFTA_LIMIT_RATE, htobe64(limit->rate));
	if (e->flags & (1 << NFTNL_EXPR_LIMIT_UNIT))
		mnl_attr_put_u64(nlh, NFTA_LIMIT_UNIT, htobe64(limit->unit));
	if (e->flags & (1 << NFTNL_EXPR_LIMIT_BURST))
		mnl_attr_put_u32(nlh, NFTA_LIMIT_BURST, htonl(limit->burst));
	if (e->flags & (1 << NFTNL_EXPR_LIMIT_TYPE))
		mnl_attr_put_u32(nlh, NFTA_LIMIT_TYPE, htonl(limit->type));
	if (e->flags & (1 << NFTNL_EXPR_LIMIT_FLAGS))
		mnl_attr_put_u32(nlh, NFTA_LIMIT_FLAGS, htonl(limit->flags));
}

static int
nftnl_expr_limit_parse(struct nftnl_expr *e, struct nlattr *attr)
{
	struct nftnl_expr_limit *limit = nftnl_expr_data(e);
	struct nlattr *tb[NFTA_LIMIT_MAX+1] = {};

	if (mnl_attr_parse_nested(attr, nftnl_expr_limit_cb, tb) < 0)
		return -1;

	if (tb[NFTA_LIMIT_RATE]) {
		limit->rate = be64toh(mnl_attr_get_u64(tb[NFTA_LIMIT_RATE]));
		e->flags |= (1 << NFTNL_EXPR_LIMIT_RATE);
	}
	if (tb[NFTA_LIMIT_UNIT]) {
		limit->unit = be64toh(mnl_attr_get_u64(tb[NFTA_LIMIT_UNIT]));
		e->flags |= (1 << NFTNL_EXPR_LIMIT_UNIT);
	}
	if (tb[NFTA_LIMIT_BURST]) {
		limit->burst = ntohl(mnl_attr_get_u32(tb[NFTA_LIMIT_BURST]));
		e->flags |= (1 << NFTNL_EXPR_LIMIT_BURST);
	}
	if (tb[NFTA_LIMIT_TYPE]) {
		limit->type = ntohl(mnl_attr_get_u32(tb[NFTA_LIMIT_TYPE]));
		e->flags |= (1 << NFTNL_EXPR_LIMIT_TYPE);
	}
	if (tb[NFTA_LIMIT_FLAGS]) {
		limit->flags = ntohl(mnl_attr_get_u32(tb[NFTA_LIMIT_FLAGS]));
		e->flags |= (1 << NFTNL_EXPR_LIMIT_FLAGS);
	}

	return 0;
}

static int nftnl_expr_limit_json_parse(struct nftnl_expr *e, json_t *root,
					  struct nftnl_parse_err *err)
{
#ifdef JSON_PARSING
	uint64_t uval64;
	uint32_t uval32;

	if (nftnl_jansson_parse_val(root, "rate", NFTNL_TYPE_U64, &uval64, err) == 0)
		nftnl_expr_set_u64(e, NFTNL_EXPR_LIMIT_RATE, uval64);

	if (nftnl_jansson_parse_val(root, "unit", NFTNL_TYPE_U64, &uval64, err) == 0)
		nftnl_expr_set_u64(e, NFTNL_EXPR_LIMIT_UNIT, uval64);
	if (nftnl_jansson_parse_val(root, "burst", NFTNL_TYPE_U32, &uval32, err) == 0)
		nftnl_expr_set_u32(e, NFTNL_EXPR_LIMIT_BURST, uval32);
	if (nftnl_jansson_parse_val(root, "type", NFTNL_TYPE_U32, &uval32, err) == 0)
		nftnl_expr_set_u32(e, NFTNL_EXPR_LIMIT_TYPE, uval32);
	if (nftnl_jansson_parse_val(root, "flags", NFTNL_TYPE_U32, &uval32, err) == 0)
		nftnl_expr_set_u32(e, NFTNL_EXPR_LIMIT_FLAGS, uval32);

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

static int nftnl_expr_limit_export(char *buf, size_t size,
				   const struct nftnl_expr *e, int type)
{
	struct nftnl_expr_limit *limit = nftnl_expr_data(e);
	NFTNL_BUF_INIT(b, buf, size);

	if (e->flags & (1 << NFTNL_EXPR_LIMIT_RATE))
		nftnl_buf_u64(&b, type, limit->rate, RATE);
	if (e->flags & (1 << NFTNL_EXPR_LIMIT_UNIT))
		nftnl_buf_u64(&b, type, limit->unit, UNIT);
	if (e->flags & (1 << NFTNL_EXPR_LIMIT_BURST))
		nftnl_buf_u32(&b, type, limit->burst, BURST);
	if (e->flags & (1 << NFTNL_EXPR_LIMIT_TYPE))
		nftnl_buf_u32(&b, type, limit->type, TYPE);
	if (e->flags & (1 << NFTNL_EXPR_LIMIT_FLAGS))
		nftnl_buf_u32(&b, type, limit->flags, FLAGS);

	return nftnl_buf_done(&b);
}

static const char *limit_to_type(enum nft_limit_type type)
{
	switch (type) {
	default:
	case NFT_LIMIT_PKTS:
		return "packets";
	case NFT_LIMIT_PKT_BYTES:
		return "bytes";
	}
}

static int nftnl_expr_limit_snprintf_default(char *buf, size_t len,
					     const struct nftnl_expr *e)
{
	struct nftnl_expr_limit *limit = nftnl_expr_data(e);

	return snprintf(buf, len, "rate %"PRIu64"/%s burst %u type %s flags 0x%x ",
			limit->rate, get_unit(limit->unit), limit->burst,
			limit_to_type(limit->type), limit->flags);
}

static int
nftnl_expr_limit_snprintf(char *buf, size_t len, uint32_t type,
			  uint32_t flags, const struct nftnl_expr *e)
{
	if (len)
		buf[0] = '\0';

	switch(type) {
	case NFTNL_OUTPUT_DEFAULT:
		return nftnl_expr_limit_snprintf_default(buf, len, e);
	case NFTNL_OUTPUT_XML:
	case NFTNL_OUTPUT_JSON:
		return nftnl_expr_limit_export(buf, len, e, type);
	default:
		break;
	}
	return -1;
}

static bool nftnl_expr_limit_cmp(const struct nftnl_expr *e1,
				 const struct nftnl_expr *e2)
{
	struct nftnl_expr_limit *l1 = nftnl_expr_data(e1);
	struct nftnl_expr_limit *l2 = nftnl_expr_data(e2);
	bool eq = true;

	if (e1->flags & (1 << NFTNL_EXPR_LIMIT_RATE))
		eq &= (l1->rate == l2->rate);
	if (e1->flags & (1 << NFTNL_EXPR_LIMIT_UNIT))
		eq &= (l1->unit == l2->unit);
	if (e1->flags & (1 << NFTNL_EXPR_LIMIT_BURST))
		eq &= (l1->burst == l2->burst);
	if (e1->flags & (1 << NFTNL_EXPR_LIMIT_TYPE))
		eq &= (l1->type == l2->type);
	if (e1->flags & (1 << NFTNL_EXPR_LIMIT_FLAGS))
		eq &= (l1->flags == l2->flags);

	return eq;
}

struct expr_ops expr_ops_limit = {
	.name		= "limit",
	.alloc_len	= sizeof(struct nftnl_expr_limit),
	.max_attr	= NFTA_LIMIT_MAX,
	.set		= nftnl_expr_limit_set,
	.cmp		= nftnl_expr_limit_cmp,
	.get		= nftnl_expr_limit_get,
	.parse		= nftnl_expr_limit_parse,
	.build		= nftnl_expr_limit_build,
	.snprintf	= nftnl_expr_limit_snprintf,
	.json_parse	= nftnl_expr_limit_json_parse,
};
