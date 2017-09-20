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

#include "internal.h"

#include <stdio.h>
#include <stdint.h>
#include <string.h> /* for memcpy */
#include <arpa/inet.h>
#include <errno.h>
#include <libmnl/libmnl.h>
#include <linux/netfilter/nf_tables.h>
#include <libnftnl/expr.h>
#include <libnftnl/rule.h>

struct nftnl_expr_byteorder {
	enum nft_registers	sreg;
	enum nft_registers	dreg;
	enum nft_byteorder_ops	op;
	unsigned int		len;
	unsigned int		size;
};

static int
nftnl_expr_byteorder_set(struct nftnl_expr *e, uint16_t type,
			  const void *data, uint32_t data_len)
{
	struct nftnl_expr_byteorder *byteorder = nftnl_expr_data(e);

	switch(type) {
	case NFTNL_EXPR_BYTEORDER_SREG:
		byteorder->sreg = *((uint32_t *)data);
		break;
	case NFTNL_EXPR_BYTEORDER_DREG:
		byteorder->dreg = *((uint32_t *)data);
		break;
	case NFTNL_EXPR_BYTEORDER_OP:
		byteorder->op = *((uint32_t *)data);
		break;
	case NFTNL_EXPR_BYTEORDER_LEN:
		byteorder->len = *((unsigned int *)data);
		break;
	case NFTNL_EXPR_BYTEORDER_SIZE:
		byteorder->size = *((unsigned int *)data);
		break;
	default:
		return -1;
	}
	return 0;
}

static const void *
nftnl_expr_byteorder_get(const struct nftnl_expr *e, uint16_t type,
			    uint32_t *data_len)
{
	struct nftnl_expr_byteorder *byteorder = nftnl_expr_data(e);

	switch(type) {
	case NFTNL_EXPR_BYTEORDER_SREG:
		*data_len = sizeof(byteorder->sreg);
		return &byteorder->sreg;
	case NFTNL_EXPR_BYTEORDER_DREG:
		*data_len = sizeof(byteorder->dreg);
		return &byteorder->dreg;
	case NFTNL_EXPR_BYTEORDER_OP:
		*data_len = sizeof(byteorder->op);
		return &byteorder->op;
	case NFTNL_EXPR_BYTEORDER_LEN:
		*data_len = sizeof(byteorder->len);
		return &byteorder->len;
	case NFTNL_EXPR_BYTEORDER_SIZE:
		*data_len = sizeof(byteorder->size);
		return &byteorder->size;
	}
	return NULL;
}

static int nftnl_expr_byteorder_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, NFTA_BYTEORDER_MAX) < 0)
		return MNL_CB_OK;

	switch(type) {
	case NFTA_BYTEORDER_SREG:
	case NFTA_BYTEORDER_DREG:
	case NFTA_BYTEORDER_OP:
	case NFTA_BYTEORDER_LEN:
	case NFTA_BYTEORDER_SIZE:
		if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0)
			abi_breakage();
		break;
	}

	tb[type] = attr;
	return MNL_CB_OK;
}

static void
nftnl_expr_byteorder_build(struct nlmsghdr *nlh, const struct nftnl_expr *e)
{
	struct nftnl_expr_byteorder *byteorder = nftnl_expr_data(e);

	if (e->flags & (1 << NFTNL_EXPR_BYTEORDER_SREG)) {
		mnl_attr_put_u32(nlh, NFTA_BYTEORDER_SREG,
				 htonl(byteorder->sreg));
	}
	if (e->flags & (1 << NFTNL_EXPR_BYTEORDER_DREG)) {
		mnl_attr_put_u32(nlh, NFTA_BYTEORDER_DREG,
				 htonl(byteorder->dreg));
	}
	if (e->flags & (1 << NFTNL_EXPR_BYTEORDER_OP)) {
		mnl_attr_put_u32(nlh, NFTA_BYTEORDER_OP,
				 htonl(byteorder->op));
	}
	if (e->flags & (1 << NFTNL_EXPR_BYTEORDER_LEN)) {
		mnl_attr_put_u32(nlh, NFTA_BYTEORDER_LEN,
				 htonl(byteorder->len));
	}
	if (e->flags & (1 << NFTNL_EXPR_BYTEORDER_SIZE)) {
		mnl_attr_put_u32(nlh, NFTA_BYTEORDER_SIZE,
				 htonl(byteorder->size));
	}
}

static int
nftnl_expr_byteorder_parse(struct nftnl_expr *e, struct nlattr *attr)
{
	struct nftnl_expr_byteorder *byteorder = nftnl_expr_data(e);
	struct nlattr *tb[NFTA_BYTEORDER_MAX+1] = {};
	int ret = 0;

	if (mnl_attr_parse_nested(attr, nftnl_expr_byteorder_cb, tb) < 0)
		return -1;

	if (tb[NFTA_BYTEORDER_SREG]) {
		byteorder->sreg =
			ntohl(mnl_attr_get_u32(tb[NFTA_BYTEORDER_SREG]));
		e->flags |= (1 << NFTNL_EXPR_BYTEORDER_SREG);
	}
	if (tb[NFTA_BYTEORDER_DREG]) {
		byteorder->dreg =
			ntohl(mnl_attr_get_u32(tb[NFTA_BYTEORDER_DREG]));
		e->flags |= (1 << NFTNL_EXPR_BYTEORDER_DREG);
	}
	if (tb[NFTA_BYTEORDER_OP]) {
		byteorder->op =
			ntohl(mnl_attr_get_u32(tb[NFTA_BYTEORDER_OP]));
		e->flags |= (1 << NFTNL_EXPR_BYTEORDER_OP);
	}
	if (tb[NFTA_BYTEORDER_LEN]) {
		byteorder->len =
			ntohl(mnl_attr_get_u32(tb[NFTA_BYTEORDER_LEN]));
		e->flags |= (1 << NFTNL_EXPR_BYTEORDER_LEN);
	}
	if (tb[NFTA_BYTEORDER_SIZE]) {
		byteorder->size =
			ntohl(mnl_attr_get_u32(tb[NFTA_BYTEORDER_SIZE]));
		e->flags |= (1 << NFTNL_EXPR_BYTEORDER_SIZE);
	}

	return ret;
}

static const char *expr_byteorder_str[] = {
	[NFT_BYTEORDER_HTON] = "hton",
	[NFT_BYTEORDER_NTOH] = "ntoh",
};

static const char *bo2str(uint32_t type)
{
	if (type > NFT_BYTEORDER_HTON)
		return "unknown";

	return expr_byteorder_str[type];
}

static inline int nftnl_str2ntoh(const char *op)
{
	if (strcmp(op, "ntoh") == 0)
		return NFT_BYTEORDER_NTOH;
	else if (strcmp(op, "hton") == 0)
		return NFT_BYTEORDER_HTON;
	else {
		errno = EINVAL;
		return -1;
	}
}

static int
nftnl_expr_byteorder_json_parse(struct nftnl_expr *e, json_t *root,
				   struct nftnl_parse_err *err)
{
#ifdef JSON_PARSING
	const char *op;
	uint32_t sreg, dreg, len, size;
	int ntoh;

	if (nftnl_jansson_parse_reg(root, "sreg", NFTNL_TYPE_U32, &sreg, err) == 0)
		nftnl_expr_set_u32(e, NFTNL_EXPR_BYTEORDER_SREG, sreg);

	if (nftnl_jansson_parse_reg(root, "dreg", NFTNL_TYPE_U32, &dreg, err) == 0)
		nftnl_expr_set_u32(e, NFTNL_EXPR_BYTEORDER_DREG, dreg);

	op = nftnl_jansson_parse_str(root, "op", err);
	if (op != NULL) {
		ntoh = nftnl_str2ntoh(op);
		if (ntoh < 0)
			return -1;

		nftnl_expr_set_u32(e, NFTNL_EXPR_BYTEORDER_OP, ntoh);
	}

	if (nftnl_jansson_parse_val(root, "len", NFTNL_TYPE_U32, &len, err) == 0)
		nftnl_expr_set_u32(e, NFTNL_EXPR_BYTEORDER_LEN, len);

	if (nftnl_jansson_parse_val(root, "size", NFTNL_TYPE_U32, &size, err) == 0)
		nftnl_expr_set_u32(e, NFTNL_EXPR_BYTEORDER_SIZE, size);

	return 0;
#else
	errno = EOPNOTSUPP;
	return -1;
#endif
}

static int nftnl_expr_byteorder_export(char *buf, size_t size,
				       const struct nftnl_expr *e, int type)
{
	struct nftnl_expr_byteorder *byteorder = nftnl_expr_data(e);
	NFTNL_BUF_INIT(b, buf, size);

	if (e->flags & (1 << NFTNL_EXPR_BYTEORDER_SREG))
		nftnl_buf_u32(&b, type, byteorder->sreg, SREG);
	if (e->flags & (1 << NFTNL_EXPR_BYTEORDER_DREG))
		nftnl_buf_u32(&b, type, byteorder->dreg, DREG);
	if (e->flags & (1 << NFTNL_EXPR_BYTEORDER_OP))
		nftnl_buf_str(&b, type, bo2str(byteorder->op), OP);
	if (e->flags & (1 << NFTNL_EXPR_BYTEORDER_LEN))
		nftnl_buf_u32(&b, type, byteorder->len, LEN);
	if (e->flags & (1 << NFTNL_EXPR_BYTEORDER_SIZE))
		nftnl_buf_u32(&b, type, byteorder->size, SIZE);

	return nftnl_buf_done(&b);
}

static int nftnl_expr_byteorder_snprintf_default(char *buf, size_t size,
						 const struct nftnl_expr *e)
{
	struct nftnl_expr_byteorder *byteorder = nftnl_expr_data(e);
	int remain = size, offset = 0, ret;

	ret = snprintf(buf, remain, "reg %u = %s(reg %u, %u, %u) ",
		       byteorder->dreg, bo2str(byteorder->op),
		       byteorder->sreg, byteorder->size, byteorder->len);
	SNPRINTF_BUFFER_SIZE(ret, remain, offset);

	return offset;
}

static int
nftnl_expr_byteorder_snprintf(char *buf, size_t size, uint32_t type,
			      uint32_t flags, const struct nftnl_expr *e)
{
	if (size)
		buf[0] = '\0';

	switch (type) {
	case NFTNL_OUTPUT_DEFAULT:
		return nftnl_expr_byteorder_snprintf_default(buf, size, e);
	case NFTNL_OUTPUT_XML:
	case NFTNL_OUTPUT_JSON:
		return nftnl_expr_byteorder_export(buf, size, e, type);
	default:
		break;
	}
	return -1;
}

static bool nftnl_expr_byteorder_cmp(const struct nftnl_expr *e1,
				     const struct nftnl_expr *e2)
{
	struct nftnl_expr_byteorder *b1 = nftnl_expr_data(e1);
	struct nftnl_expr_byteorder *b2 = nftnl_expr_data(e2);
	bool eq = true;

	if (e1->flags & (1 << NFTNL_EXPR_BYTEORDER_SREG))
		eq &= (b1->sreg == b2->sreg);
	if (e1->flags & (1 << NFTNL_EXPR_BYTEORDER_DREG))
		eq &= (b1->dreg == b2->dreg);
	if (e1->flags & (1 << NFTNL_EXPR_BYTEORDER_OP))
		eq &= (b1->op == b2->op);
	if (e1->flags & (1 << NFTNL_EXPR_BYTEORDER_LEN))
		eq &= (b1->len == b2->len);
	if (e1->flags & (1 << NFTNL_EXPR_BYTEORDER_SIZE))
		eq &= (b1->size == b2->size);

	return eq;
}

struct expr_ops expr_ops_byteorder = {
	.name		= "byteorder",
	.alloc_len	= sizeof(struct nftnl_expr_byteorder),
	.max_attr	= NFTA_BYTEORDER_MAX,
	.cmp		= nftnl_expr_byteorder_cmp,
	.set		= nftnl_expr_byteorder_set,
	.get		= nftnl_expr_byteorder_get,
	.parse		= nftnl_expr_byteorder_parse,
	.build		= nftnl_expr_byteorder_build,
	.snprintf	= nftnl_expr_byteorder_snprintf,
	.json_parse	= nftnl_expr_byteorder_json_parse,
};
