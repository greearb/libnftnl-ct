/*
 * (C) 2016 by Laura Garcia <nevola@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include <errno.h>
#include <linux/netfilter/nf_tables.h>

#include "internal.h"
#include <libmnl/libmnl.h>
#include <libnftnl/expr.h>
#include <libnftnl/rule.h>

struct nftnl_expr_ng {
	enum nft_registers	dreg;
	unsigned int		modulus;
	enum nft_ng_types	type;
	unsigned int		offset;
};

static int
nftnl_expr_ng_set(struct nftnl_expr *e, uint16_t type,
		  const void *data, uint32_t data_len)
{
	struct nftnl_expr_ng *ng = nftnl_expr_data(e);

	switch (type) {
	case NFTNL_EXPR_NG_DREG:
		ng->dreg = *((uint32_t *)data);
		break;
	case NFTNL_EXPR_NG_MODULUS:
		ng->modulus = *((uint32_t *)data);
		break;
	case NFTNL_EXPR_NG_TYPE:
		ng->type = *((uint32_t *)data);
		break;
	case NFTNL_EXPR_NG_OFFSET:
		ng->offset = *((uint32_t *)data);
		break;
	default:
		return -1;
	}
	return 0;
}

static const void *
nftnl_expr_ng_get(const struct nftnl_expr *e, uint16_t type,
		  uint32_t *data_len)
{
	struct nftnl_expr_ng *ng = nftnl_expr_data(e);

	switch (type) {
	case NFTNL_EXPR_NG_DREG:
		*data_len = sizeof(ng->dreg);
		return &ng->dreg;
	case NFTNL_EXPR_NG_MODULUS:
		*data_len = sizeof(ng->modulus);
		return &ng->modulus;
	case NFTNL_EXPR_NG_TYPE:
		*data_len = sizeof(ng->type);
		return &ng->type;
	case NFTNL_EXPR_NG_OFFSET:
		*data_len = sizeof(ng->offset);
		return &ng->offset;
	}
	return NULL;
}

static int nftnl_expr_ng_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, NFTA_NG_MAX) < 0)
		return MNL_CB_OK;

	switch (type) {
	case NFTA_NG_DREG:
	case NFTA_NG_MODULUS:
	case NFTA_NG_TYPE:
	case NFTA_NG_OFFSET:
		if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0)
			abi_breakage();
		break;
	}

	tb[type] = attr;
	return MNL_CB_OK;
}

static void
nftnl_expr_ng_build(struct nlmsghdr *nlh, const struct nftnl_expr *e)
{
	struct nftnl_expr_ng *ng = nftnl_expr_data(e);

	if (e->flags & (1 << NFTNL_EXPR_NG_DREG))
		mnl_attr_put_u32(nlh, NFTA_NG_DREG, htonl(ng->dreg));
	if (e->flags & (1 << NFTNL_EXPR_NG_MODULUS))
		mnl_attr_put_u32(nlh, NFTA_NG_MODULUS, htonl(ng->modulus));
	if (e->flags & (1 << NFTNL_EXPR_NG_TYPE))
		mnl_attr_put_u32(nlh, NFTA_NG_TYPE, htonl(ng->type));
	if (e->flags & (1 << NFTNL_EXPR_NG_OFFSET))
		mnl_attr_put_u32(nlh, NFTA_NG_OFFSET, htonl(ng->offset));
}

static int
nftnl_expr_ng_parse(struct nftnl_expr *e, struct nlattr *attr)
{
	struct nftnl_expr_ng *ng = nftnl_expr_data(e);
	struct nlattr *tb[NFTA_NG_MAX+1] = {};
	int ret = 0;

	if (mnl_attr_parse_nested(attr, nftnl_expr_ng_cb, tb) < 0)
		return -1;

	if (tb[NFTA_NG_DREG]) {
		ng->dreg = ntohl(mnl_attr_get_u32(tb[NFTA_NG_DREG]));
		e->flags |= (1 << NFTNL_EXPR_NG_DREG);
	}
	if (tb[NFTA_NG_MODULUS]) {
		ng->modulus = ntohl(mnl_attr_get_u32(tb[NFTA_NG_MODULUS]));
		e->flags |= (1 << NFTNL_EXPR_NG_MODULUS);
	}
	if (tb[NFTA_NG_TYPE]) {
		ng->type = ntohl(mnl_attr_get_u32(tb[NFTA_NG_TYPE]));
		e->flags |= (1 << NFTNL_EXPR_NG_TYPE);
	}
	if (tb[NFTA_NG_OFFSET]) {
		ng->offset = ntohl(mnl_attr_get_u32(tb[NFTA_NG_OFFSET]));
		e->flags |= (1 << NFTNL_EXPR_NG_OFFSET);
	}

	return ret;
}

static int nftnl_expr_ng_json_parse(struct nftnl_expr *e, json_t *root,
				    struct nftnl_parse_err *err)
{
#ifdef JSON_PARSING
	uint32_t dreg, modulus, type, offset;

	if (nftnl_jansson_parse_reg(root, "dreg", NFTNL_TYPE_U32,
				    &dreg, err) == 0)
		nftnl_expr_set_u32(e, NFTNL_EXPR_NG_DREG, dreg);

	if (nftnl_jansson_parse_val(root, "modulus", NFTNL_TYPE_U32,
				    &modulus, err) == 0)
		nftnl_expr_set_u32(e, NFTNL_EXPR_NG_MODULUS, modulus);

	if (nftnl_jansson_parse_val(root, "type", NFTNL_TYPE_U32,
				    &type, err) == 0)
		nftnl_expr_set_u32(e, NFTNL_EXPR_NG_TYPE, type);

	if (nftnl_jansson_parse_val(root, "offset", NFTNL_TYPE_U32,
				    &offset, err) == 0)
		nftnl_expr_set_u32(e, NFTNL_EXPR_NG_OFFSET, offset);

	return 0;
#else
	errno = EOPNOTSUPP;
	return -1;
#endif
}

static int
nftnl_expr_ng_snprintf_default(char *buf, size_t size,
			       const struct nftnl_expr *e)
{
	struct nftnl_expr_ng *ng = nftnl_expr_data(e);
	int remain = size, offset = 0, ret;

	switch (ng->type) {
	case NFT_NG_INCREMENTAL:
		ret = snprintf(buf, remain, "reg %u = inc mod %u ",
			       ng->dreg, ng->modulus);
		SNPRINTF_BUFFER_SIZE(ret, remain, offset);
		break;
	case NFT_NG_RANDOM:
		ret = snprintf(buf, remain, "reg %u = random mod %u ",
			       ng->dreg, ng->modulus);
		SNPRINTF_BUFFER_SIZE(ret, remain, offset);
		break;
	default:
		return 0;
	}

	if (ng->offset) {
		ret = snprintf(buf + offset, remain, "offset %u ", ng->offset);
		SNPRINTF_BUFFER_SIZE(ret, remain, offset);
	}

	return offset;
}

static int nftnl_expr_ng_export(char *buf, size_t size,
				const struct nftnl_expr *e, int type)
{
	struct nftnl_expr_ng *ng = nftnl_expr_data(e);

	NFTNL_BUF_INIT(b, buf, size);

	if (e->flags & (1 << NFTNL_EXPR_NG_DREG))
		nftnl_buf_u32(&b, type, ng->dreg, DREG);
	if (e->flags & (1 << NFTNL_EXPR_NG_MODULUS))
		nftnl_buf_u32(&b, type, ng->modulus, MODULUS);
	if (e->flags & (1 << NFTNL_EXPR_NG_TYPE))
		nftnl_buf_u32(&b, type, ng->type, TYPE);
	if (e->flags & (1 << NFTNL_EXPR_NG_OFFSET))
		nftnl_buf_u32(&b, type, ng->type, OFFSET);

	return nftnl_buf_done(&b);
}

static int
nftnl_expr_ng_snprintf(char *buf, size_t len, uint32_t type,
		       uint32_t flags, const struct nftnl_expr *e)
{
	if (len)
		buf[0] = '\0';

	switch (type) {
	case NFTNL_OUTPUT_DEFAULT:
		return nftnl_expr_ng_snprintf_default(buf, len, e);
	case NFTNL_OUTPUT_XML:
	case NFTNL_OUTPUT_JSON:
		return nftnl_expr_ng_export(buf, len, e, type);
	default:
		break;
	}
	return -1;
}

static bool nftnl_expr_ng_cmp(const struct nftnl_expr *e1,
			      const struct nftnl_expr *e2)
{
	struct nftnl_expr_ng *n1 = nftnl_expr_data(e1);
	struct nftnl_expr_ng *n2 = nftnl_expr_data(e2);
	bool eq = true;

	if (e1->flags & (1 << NFTNL_EXPR_NG_DREG))
		eq &= (n1->dreg == n2->dreg);
	if (e1->flags & (1 << NFTNL_EXPR_NG_MODULUS))
		eq &= (n1->modulus == n2->modulus);
	if (e1->flags & (1 << NFTNL_EXPR_NG_TYPE))
		eq &= (n1->type == n2->type);
	if (e1->flags & (1 << NFTNL_EXPR_NG_OFFSET))
		eq &= (n1->offset == n2->offset);

	return eq;
}

struct expr_ops expr_ops_ng = {
	.name		= "numgen",
	.alloc_len	= sizeof(struct nftnl_expr_ng),
	.max_attr	= NFTA_NG_MAX,
	.cmp		= nftnl_expr_ng_cmp,
	.set		= nftnl_expr_ng_set,
	.get		= nftnl_expr_ng_get,
	.parse		= nftnl_expr_ng_parse,
	.build		= nftnl_expr_ng_build,
	.snprintf	= nftnl_expr_ng_snprintf,
	.json_parse	= nftnl_expr_ng_json_parse,
};
