/*
 * (C) 2014 by Arturo Borrero Gonzalez <arturo@debian.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>

#include <linux/netfilter/nf_tables.h>

#include "internal.h"
#include <libmnl/libmnl.h>
#include <libnftnl/expr.h>
#include <libnftnl/rule.h>

struct nftnl_expr_redir {
	enum nft_registers sreg_proto_min;
	enum nft_registers sreg_proto_max;
	uint32_t	flags;
};

static int
nftnl_expr_redir_set(struct nftnl_expr *e, uint16_t type,
			const void *data, uint32_t data_len)
{
	struct nftnl_expr_redir *redir = nftnl_expr_data(e);

	switch (type) {
	case NFTNL_EXPR_REDIR_REG_PROTO_MIN:
		redir->sreg_proto_min = *((uint32_t *)data);
		break;
	case NFTNL_EXPR_REDIR_REG_PROTO_MAX:
		redir->sreg_proto_max = *((uint32_t *)data);
		break;
	case NFTNL_EXPR_REDIR_FLAGS:
		redir->flags = *((uint32_t *)data);
		break;
	default:
		return -1;
	}
	return 0;
}

static const void *
nftnl_expr_redir_get(const struct nftnl_expr *e, uint16_t type,
			uint32_t *data_len)
{
	struct nftnl_expr_redir *redir = nftnl_expr_data(e);

	switch (type) {
	case NFTNL_EXPR_REDIR_REG_PROTO_MIN:
		*data_len = sizeof(redir->sreg_proto_min);
		return &redir->sreg_proto_min;
	case NFTNL_EXPR_REDIR_REG_PROTO_MAX:
		*data_len = sizeof(redir->sreg_proto_max);
		return &redir->sreg_proto_max;
	case NFTNL_EXPR_REDIR_FLAGS:
		*data_len = sizeof(redir->flags);
		return &redir->flags;
	}
	return NULL;
}

static int nftnl_expr_redir_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, NFTA_REDIR_MAX) < 0)
		return MNL_CB_OK;

	switch (type) {
	case NFTA_REDIR_REG_PROTO_MIN:
	case NFTA_REDIR_REG_PROTO_MAX:
	case NFTA_REDIR_FLAGS:
		if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0)
			abi_breakage();
		break;
	}

	tb[type] = attr;
	return MNL_CB_OK;
}

static void
nftnl_expr_redir_build(struct nlmsghdr *nlh, const struct nftnl_expr *e)
{
	struct nftnl_expr_redir *redir = nftnl_expr_data(e);

	if (e->flags & (1 << NFTNL_EXPR_REDIR_REG_PROTO_MIN))
		mnl_attr_put_u32(nlh, NFTA_REDIR_REG_PROTO_MIN,
				 htobe32(redir->sreg_proto_min));
	if (e->flags & (1 << NFTNL_EXPR_REDIR_REG_PROTO_MAX))
		mnl_attr_put_u32(nlh, NFTA_REDIR_REG_PROTO_MAX,
				 htobe32(redir->sreg_proto_max));
	if (e->flags & (1 << NFTNL_EXPR_REDIR_FLAGS))
		mnl_attr_put_u32(nlh, NFTA_REDIR_FLAGS, htobe32(redir->flags));
}

static int
nftnl_expr_redir_parse(struct nftnl_expr *e, struct nlattr *attr)
{
	struct nftnl_expr_redir *redir = nftnl_expr_data(e);
	struct nlattr *tb[NFTA_REDIR_MAX + 1] = {};

	if (mnl_attr_parse_nested(attr, nftnl_expr_redir_cb, tb) < 0)
		return -1;

	if (tb[NFTA_REDIR_REG_PROTO_MIN]) {
		redir->sreg_proto_min =
			ntohl(mnl_attr_get_u32(tb[NFTA_REDIR_REG_PROTO_MIN]));
		e->flags |= (1 << NFTNL_EXPR_REDIR_REG_PROTO_MIN);
	}
	if (tb[NFTA_REDIR_REG_PROTO_MAX]) {
		redir->sreg_proto_max =
			ntohl(mnl_attr_get_u32(tb[NFTA_REDIR_REG_PROTO_MAX]));
		e->flags |= (1 << NFTNL_EXPR_REDIR_REG_PROTO_MAX);
	}
	if (tb[NFTA_REDIR_FLAGS]) {
		redir->flags = be32toh(mnl_attr_get_u32(tb[NFTA_REDIR_FLAGS]));
		e->flags |= (1 << NFTNL_EXPR_REDIR_FLAGS);
	}

	return 0;
}

static int
nftnl_expr_redir_json_parse(struct nftnl_expr *e, json_t *root,
			       struct nftnl_parse_err *err)
{
#ifdef JSON_PARSING
	uint32_t reg, flags;

	if (nftnl_jansson_parse_reg(root, "sreg_proto_min", NFTNL_TYPE_U32,
				  &reg, err) == 0)
		nftnl_expr_set_u32(e, NFTNL_EXPR_REDIR_REG_PROTO_MIN, reg);

	if (nftnl_jansson_parse_reg(root, "sreg_proto_max", NFTNL_TYPE_U32,
				  &reg, err) == 0)
		nftnl_expr_set_u32(e, NFTNL_EXPR_REDIR_REG_PROTO_MAX, reg);

	if (nftnl_jansson_parse_val(root, "flags", NFTNL_TYPE_U32, &flags,
				  err) == 0)
		nftnl_expr_set_u32(e, NFTNL_EXPR_REDIR_FLAGS, flags);

	return 0;
#else
	errno = EOPNOTSUPP;
	return -1;
#endif
}

static int nftnl_expr_redir_export(char *buf, size_t size,
				   const struct nftnl_expr *e, int type)
{
	struct nftnl_expr_redir *redir = nftnl_expr_data(e);
        NFTNL_BUF_INIT(b, buf, size);

	if (e->flags & (1 << NFTNL_EXPR_REDIR_REG_PROTO_MIN))
		nftnl_buf_u32(&b, type, redir->sreg_proto_min, SREG_PROTO_MIN);
	if (e->flags & (1 << NFTNL_EXPR_REDIR_REG_PROTO_MAX))
		nftnl_buf_u32(&b, type, redir->sreg_proto_max, SREG_PROTO_MAX);
	if (e->flags & (1 << NFTNL_EXPR_REDIR_FLAGS))
		nftnl_buf_u32(&b, type, redir->flags, FLAGS);

	return nftnl_buf_done(&b);
}

static int nftnl_expr_redir_snprintf_default(char *buf, size_t len,
					     const struct nftnl_expr *e)
{
	int ret, size = len, offset = 0;
	struct nftnl_expr_redir *redir = nftnl_expr_data(e);

	if (nftnl_expr_is_set(e, NFTNL_EXPR_REDIR_REG_PROTO_MIN)) {
		ret = snprintf(buf + offset, len, "proto_min reg %u ",
			       redir->sreg_proto_min);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	if (nftnl_expr_is_set(e, NFTNL_EXPR_REDIR_REG_PROTO_MAX)) {
		ret = snprintf(buf + offset, len, "proto_max reg %u ",
			       redir->sreg_proto_max);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	if (nftnl_expr_is_set(e, NFTNL_EXPR_REDIR_FLAGS)) {
		ret = snprintf(buf + offset , len, "flags 0x%x ",
			       redir->flags);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	return offset;
}

static int
nftnl_expr_redir_snprintf(char *buf, size_t len, uint32_t type,
			  uint32_t flags, const struct nftnl_expr *e)
{
	switch (type) {
	case NFTNL_OUTPUT_DEFAULT:
		return nftnl_expr_redir_snprintf_default(buf, len, e);
	case NFTNL_OUTPUT_XML:
	case NFTNL_OUTPUT_JSON:
		return nftnl_expr_redir_export(buf, len, e, type);
	default:
		break;
	}
	return -1;
}

static bool nftnl_expr_redir_cmp(const struct nftnl_expr *e1,
				 const struct nftnl_expr *e2)
{
	struct nftnl_expr_redir *r1 = nftnl_expr_data(e1);
	struct nftnl_expr_redir *r2 = nftnl_expr_data(e2);
	bool eq = true;

	if (e1->flags & (1 << NFTNL_EXPR_REDIR_REG_PROTO_MIN))
		eq &= (r1->sreg_proto_min== r2->sreg_proto_min);
	if (e1->flags & (1 << NFTNL_EXPR_REDIR_REG_PROTO_MAX))
		eq &= (r1->sreg_proto_max== r2->sreg_proto_max);
	if (e1->flags & (1 << NFTNL_EXPR_REDIR_FLAGS))
		eq &= (r1->flags== r2->flags);

	return eq;
}

struct expr_ops expr_ops_redir = {
	.name		= "redir",
	.alloc_len	= sizeof(struct nftnl_expr_redir),
	.max_attr	= NFTA_REDIR_MAX,
	.cmp		= nftnl_expr_redir_cmp,
	.set		= nftnl_expr_redir_set,
	.get		= nftnl_expr_redir_get,
	.parse		= nftnl_expr_redir_parse,
	.build		= nftnl_expr_redir_build,
	.snprintf	= nftnl_expr_redir_snprintf,
	.json_parse	= nftnl_expr_redir_json_parse,
};
