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
#include <libnftnl/rule.h>
#include <libnftnl/expr.h>

struct nftnl_expr_lookup {
	enum nft_registers	sreg;
	enum nft_registers	dreg;
	char			*set_name;
	uint32_t		set_id;
	uint32_t		flags;
};

static int
nftnl_expr_lookup_set(struct nftnl_expr *e, uint16_t type,
			  const void *data, uint32_t data_len)
{
	struct nftnl_expr_lookup *lookup = nftnl_expr_data(e);

	switch(type) {
	case NFTNL_EXPR_LOOKUP_SREG:
		lookup->sreg = *((uint32_t *)data);
		break;
	case NFTNL_EXPR_LOOKUP_DREG:
		lookup->dreg = *((uint32_t *)data);
		break;
	case NFTNL_EXPR_LOOKUP_SET:
		lookup->set_name = strdup((const char *)data);
		if (!lookup->set_name)
			return -1;
		break;
	case NFTNL_EXPR_LOOKUP_SET_ID:
		lookup->set_id = *((uint32_t *)data);
		break;
	case NFTNL_EXPR_LOOKUP_FLAGS:
		lookup->flags = *((uint32_t *)data);
		break;
	default:
		return -1;
	}
	return 0;
}

static const void *
nftnl_expr_lookup_get(const struct nftnl_expr *e, uint16_t type,
			 uint32_t *data_len)
{
	struct nftnl_expr_lookup *lookup = nftnl_expr_data(e);

	switch(type) {
	case NFTNL_EXPR_LOOKUP_SREG:
		*data_len = sizeof(lookup->sreg);
		return &lookup->sreg;
	case NFTNL_EXPR_LOOKUP_DREG:
		*data_len = sizeof(lookup->dreg);
		return &lookup->dreg;
	case NFTNL_EXPR_LOOKUP_SET:
		*data_len = strlen(lookup->set_name) + 1;
		return lookup->set_name;
	case NFTNL_EXPR_LOOKUP_SET_ID:
		*data_len = sizeof(lookup->set_id);
		return &lookup->set_id;
	case NFTNL_EXPR_LOOKUP_FLAGS:
		*data_len = sizeof(lookup->flags);
		return &lookup->flags;
	}
	return NULL;
}

static int nftnl_expr_lookup_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, NFTA_LOOKUP_MAX) < 0)
		return MNL_CB_OK;

	switch(type) {
	case NFTA_LOOKUP_SREG:
	case NFTA_LOOKUP_DREG:
	case NFTA_LOOKUP_SET_ID:
	case NFTA_LOOKUP_FLAGS:
		if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0)
			abi_breakage();
		break;
	case NFTA_LOOKUP_SET:
		if (mnl_attr_validate(attr, MNL_TYPE_STRING) < 0)
			abi_breakage();
		break;
	}

	tb[type] = attr;
	return MNL_CB_OK;
}

static void
nftnl_expr_lookup_build(struct nlmsghdr *nlh, const struct nftnl_expr *e)
{
	struct nftnl_expr_lookup *lookup = nftnl_expr_data(e);

	if (e->flags & (1 << NFTNL_EXPR_LOOKUP_SREG))
		mnl_attr_put_u32(nlh, NFTA_LOOKUP_SREG, htonl(lookup->sreg));
	if (e->flags & (1 << NFTNL_EXPR_LOOKUP_DREG))
		mnl_attr_put_u32(nlh, NFTA_LOOKUP_DREG, htonl(lookup->dreg));
	if (e->flags & (1 << NFTNL_EXPR_LOOKUP_SET))
		mnl_attr_put_strz(nlh, NFTA_LOOKUP_SET, lookup->set_name);
	if (e->flags & (1 << NFTNL_EXPR_LOOKUP_SET_ID))
		mnl_attr_put_u32(nlh, NFTA_LOOKUP_SET_ID,
				 htonl(lookup->set_id));
	if (e->flags & (1 << NFTNL_EXPR_LOOKUP_FLAGS))
		mnl_attr_put_u32(nlh, NFTA_LOOKUP_FLAGS, htonl(lookup->flags));
}

static int
nftnl_expr_lookup_parse(struct nftnl_expr *e, struct nlattr *attr)
{
	struct nftnl_expr_lookup *lookup = nftnl_expr_data(e);
	struct nlattr *tb[NFTA_LOOKUP_MAX+1] = {};
	int ret = 0;

	if (mnl_attr_parse_nested(attr, nftnl_expr_lookup_cb, tb) < 0)
		return -1;

	if (tb[NFTA_LOOKUP_SREG]) {
		lookup->sreg = ntohl(mnl_attr_get_u32(tb[NFTA_LOOKUP_SREG]));
		e->flags |= (1 << NFTNL_EXPR_LOOKUP_SREG);
	}
	if (tb[NFTA_LOOKUP_DREG]) {
		lookup->dreg = ntohl(mnl_attr_get_u32(tb[NFTA_LOOKUP_DREG]));
		e->flags |= (1 << NFTNL_EXPR_LOOKUP_DREG);
	}
	if (tb[NFTA_LOOKUP_SET]) {
		lookup->set_name =
			strdup(mnl_attr_get_str(tb[NFTA_LOOKUP_SET]));
		if (!lookup->set_name)
			return -1;
		e->flags |= (1 << NFTNL_EXPR_LOOKUP_SET);
	}
	if (tb[NFTA_LOOKUP_SET_ID]) {
		lookup->set_id =
			ntohl(mnl_attr_get_u32(tb[NFTA_LOOKUP_SET_ID]));
		e->flags |= (1 << NFTNL_EXPR_LOOKUP_SET_ID);
	}
	if (tb[NFTA_LOOKUP_FLAGS]) {
		lookup->flags = ntohl(mnl_attr_get_u32(tb[NFTA_LOOKUP_FLAGS]));
		e->flags |= (1 << NFTNL_EXPR_LOOKUP_FLAGS);
	}

	return ret;
}

static int
nftnl_expr_lookup_json_parse(struct nftnl_expr *e, json_t *root,
				struct nftnl_parse_err *err)
{
#ifdef JSON_PARSING
	const char *set_name;
	uint32_t sreg, dreg, flags;

	set_name = nftnl_jansson_parse_str(root, "set", err);
	if (set_name != NULL)
		nftnl_expr_set_str(e, NFTNL_EXPR_LOOKUP_SET, set_name);

	if (nftnl_jansson_parse_reg(root, "sreg", NFTNL_TYPE_U32, &sreg, err) == 0)
		nftnl_expr_set_u32(e, NFTNL_EXPR_LOOKUP_SREG, sreg);

	if (nftnl_jansson_parse_reg(root, "dreg", NFTNL_TYPE_U32, &dreg, err) == 0)
		nftnl_expr_set_u32(e, NFTNL_EXPR_LOOKUP_DREG, dreg);

	if (nftnl_jansson_parse_val(root, "flags", NFTNL_TYPE_U32,
				    &flags, err) == 0)
		nftnl_expr_set_u32(e, NFTNL_EXPR_LOOKUP_FLAGS, flags);

	return 0;
#else
	errno = EOPNOTSUPP;
	return -1;
#endif
}

static int
nftnl_expr_lookup_export(char *buf, size_t size,
			 const struct nftnl_expr *e, int type)
{
	struct nftnl_expr_lookup *l = nftnl_expr_data(e);
	NFTNL_BUF_INIT(b, buf, size);

	if (e->flags & (1 << NFTNL_EXPR_LOOKUP_SET))
		nftnl_buf_str(&b, type, l->set_name, SET);
	if (e->flags & (1 << NFTNL_EXPR_LOOKUP_SREG))
		nftnl_buf_u32(&b, type, l->sreg, SREG);
	if (e->flags & (1 << NFTNL_EXPR_LOOKUP_DREG))
		nftnl_buf_u32(&b, type, l->dreg, DREG);
	if (e->flags & (1 << NFTNL_EXPR_LOOKUP_FLAGS))
		nftnl_buf_u32(&b, type, l->flags, FLAGS);

	return nftnl_buf_done(&b);
}

static int
nftnl_expr_lookup_snprintf_default(char *buf, size_t size,
				   const struct nftnl_expr *e)
{
	int remain = size, offset = 0, ret;
	struct nftnl_expr_lookup *l = nftnl_expr_data(e);

	ret = snprintf(buf, remain, "reg %u set %s ", l->sreg, l->set_name);
	SNPRINTF_BUFFER_SIZE(ret, remain, offset);

	if (e->flags & (1 << NFTNL_EXPR_LOOKUP_DREG)) {
		ret = snprintf(buf + offset, remain, "dreg %u ", l->dreg);
		SNPRINTF_BUFFER_SIZE(ret, remain, offset);
	}

	if (e->flags & (1 << NFTNL_EXPR_LOOKUP_FLAGS)) {
		ret = snprintf(buf + offset, remain, "0x%x ", l->flags);
		SNPRINTF_BUFFER_SIZE(ret, remain, offset);
	}

	return offset;
}

static int
nftnl_expr_lookup_snprintf(char *buf, size_t size, uint32_t type,
			   uint32_t flags, const struct nftnl_expr *e)
{

	switch(type) {
	case NFTNL_OUTPUT_DEFAULT:
		return nftnl_expr_lookup_snprintf_default(buf, size, e);
	case NFTNL_OUTPUT_XML:
	case NFTNL_OUTPUT_JSON:
		return nftnl_expr_lookup_export(buf, size, e, type);
	default:
		break;
	}
	return -1;
}

static void nftnl_expr_lookup_free(const struct nftnl_expr *e)
{
	struct nftnl_expr_lookup *lookup = nftnl_expr_data(e);

	xfree(lookup->set_name);
}

static bool nftnl_expr_lookup_cmp(const struct nftnl_expr *e1,
				  const struct nftnl_expr *e2)
{
	struct nftnl_expr_lookup *l1 = nftnl_expr_data(e1);
	struct nftnl_expr_lookup *l2 = nftnl_expr_data(e2);
	bool eq = true;

	if (e1->flags & (1 << NFTNL_EXPR_LOOKUP_SREG))
		eq &= (l1->sreg == l2->sreg);
	if (e1->flags & (1 << NFTNL_EXPR_LOOKUP_DREG))
		eq &= (l1->dreg == l2->dreg);
	if (e1->flags & (1 << NFTNL_EXPR_LOOKUP_SET))
		eq &= !strcmp(l1->set_name, l2->set_name);
	if (e1->flags & (1 << NFTNL_EXPR_LOOKUP_SET_ID))
		eq &= (l1->set_id == l2->set_id);
	if (e1->flags & (1 << NFTNL_EXPR_LOOKUP_FLAGS))
		eq &= (l1->flags == l2->flags);

	return eq;
}

struct expr_ops expr_ops_lookup = {
	.name		= "lookup",
	.alloc_len	= sizeof(struct nftnl_expr_lookup),
	.max_attr	= NFTA_LOOKUP_MAX,
	.free		= nftnl_expr_lookup_free,
	.cmp		= nftnl_expr_lookup_cmp,
	.set		= nftnl_expr_lookup_set,
	.get		= nftnl_expr_lookup_get,
	.parse		= nftnl_expr_lookup_parse,
	.build		= nftnl_expr_lookup_build,
	.snprintf	= nftnl_expr_lookup_snprintf,
	.json_parse	= nftnl_expr_lookup_json_parse,
};
