/*
 * Copyright (c) 2014, 2015 Patrick McHardy <kaber@trash.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include "internal.h"

#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <errno.h>
#include <arpa/inet.h>
#include <libmnl/libmnl.h>
#include <linux/netfilter/nf_tables.h>
#include <libnftnl/rule.h>
#include <libnftnl/expr.h>
#include "data_reg.h"
#include "expr_ops.h"
#include <buffer.h>

struct nftnl_expr_dynset {
	enum nft_registers	sreg_key;
	enum nft_registers	sreg_data;
	enum nft_dynset_ops	op;
	uint64_t		timeout;
	struct nftnl_expr	*expr;
	char			*set_name;
	uint32_t		set_id;
};

static int
nftnl_expr_dynset_set(struct nftnl_expr *e, uint16_t type,
			 const void *data, uint32_t data_len)
{
	struct nftnl_expr_dynset *dynset = nftnl_expr_data(e);

	switch (type) {
	case NFTNL_EXPR_DYNSET_SREG_KEY:
		dynset->sreg_key = *((uint32_t *)data);
		break;
	case NFTNL_EXPR_DYNSET_SREG_DATA:
		dynset->sreg_data = *((uint32_t *)data);
		break;
	case NFTNL_EXPR_DYNSET_OP:
		dynset->op = *((uint32_t *)data);
		break;
	case NFTNL_EXPR_DYNSET_TIMEOUT:
		dynset->timeout = *((uint64_t *)data);
		break;
	case NFTNL_EXPR_DYNSET_SET_NAME:
		dynset->set_name = strdup((const char *)data);
		if (!dynset->set_name)
			return -1;
		break;
	case NFTNL_EXPR_DYNSET_SET_ID:
		dynset->set_id = *((uint32_t *)data);
		break;
	case NFTNL_EXPR_DYNSET_EXPR:
		dynset->expr = (void *)data;
		break;
	default:
		return -1;
	}
	return 0;
}

static const void *
nftnl_expr_dynset_get(const struct nftnl_expr *e, uint16_t type,
			 uint32_t *data_len)
{
	struct nftnl_expr_dynset *dynset = nftnl_expr_data(e);

	switch (type) {
	case NFTNL_EXPR_DYNSET_SREG_KEY:
		*data_len = sizeof(dynset->sreg_key);
		return &dynset->sreg_key;
	case NFTNL_EXPR_DYNSET_SREG_DATA:
		*data_len = sizeof(dynset->sreg_data);
		return &dynset->sreg_data;
	case NFTNL_EXPR_DYNSET_OP:
		*data_len = sizeof(dynset->op);
		return &dynset->op;
	case NFTNL_EXPR_DYNSET_TIMEOUT:
		*data_len = sizeof(dynset->timeout);
		return &dynset->timeout;
	case NFTNL_EXPR_DYNSET_SET_NAME:
		return dynset->set_name;
	case NFTNL_EXPR_DYNSET_SET_ID:
		return &dynset->set_id;
	case NFTNL_EXPR_DYNSET_EXPR:
		return dynset->expr;
	}
	return NULL;
}

static int nftnl_expr_dynset_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, NFTA_SET_MAX) < 0)
		return MNL_CB_OK;

	switch (type) {
	case NFTA_DYNSET_SREG_KEY:
	case NFTA_DYNSET_SREG_DATA:
	case NFTA_DYNSET_SET_ID:
	case NFTA_DYNSET_OP:
		if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0)
			abi_breakage();
		break;
	case NFTA_DYNSET_TIMEOUT:
		if (mnl_attr_validate(attr, MNL_TYPE_U64) < 0)
			abi_breakage();
		break;
	case NFTA_DYNSET_SET_NAME:
		if (mnl_attr_validate(attr, MNL_TYPE_STRING) < 0)
			abi_breakage();
		break;
	case NFTA_DYNSET_EXPR:
		if (mnl_attr_validate(attr, MNL_TYPE_NESTED) < 0)
			abi_breakage();
		break;
	}

	tb[type] = attr;
	return MNL_CB_OK;
}

static void
nftnl_expr_dynset_build(struct nlmsghdr *nlh, const struct nftnl_expr *e)
{
	struct nftnl_expr_dynset *dynset = nftnl_expr_data(e);
	struct nlattr *nest;

	if (e->flags & (1 << NFTNL_EXPR_DYNSET_SREG_KEY))
		mnl_attr_put_u32(nlh, NFTA_DYNSET_SREG_KEY, htonl(dynset->sreg_key));
	if (e->flags & (1 << NFTNL_EXPR_DYNSET_SREG_DATA))
		mnl_attr_put_u32(nlh, NFTA_DYNSET_SREG_DATA, htonl(dynset->sreg_data));
	if (e->flags & (1 << NFTNL_EXPR_DYNSET_OP))
		mnl_attr_put_u32(nlh, NFTA_DYNSET_OP, htonl(dynset->op));
	if (e->flags & (1 << NFTNL_EXPR_DYNSET_TIMEOUT))
		mnl_attr_put_u64(nlh, NFTA_DYNSET_TIMEOUT, htobe64(dynset->timeout));
	if (e->flags & (1 << NFTNL_EXPR_DYNSET_SET_NAME))
		mnl_attr_put_strz(nlh, NFTA_DYNSET_SET_NAME, dynset->set_name);
	if (e->flags & (1 << NFTNL_EXPR_DYNSET_SET_ID))
		mnl_attr_put_u32(nlh, NFTA_DYNSET_SET_ID, htonl(dynset->set_id));
	if (e->flags & (1 << NFTNL_EXPR_DYNSET_EXPR)) {
		nest = mnl_attr_nest_start(nlh, NFTA_DYNSET_EXPR);
		nftnl_expr_build_payload(nlh, dynset->expr);
		mnl_attr_nest_end(nlh, nest);
	}
}

static int
nftnl_expr_dynset_parse(struct nftnl_expr *e, struct nlattr *attr)
{
	struct nftnl_expr_dynset *dynset = nftnl_expr_data(e);
	struct nlattr *tb[NFTA_SET_MAX+1] = {};
	int ret = 0;

	if (mnl_attr_parse_nested(attr, nftnl_expr_dynset_cb, tb) < 0)
		return -1;

	if (tb[NFTA_DYNSET_SREG_KEY]) {
		dynset->sreg_key = ntohl(mnl_attr_get_u32(tb[NFTA_DYNSET_SREG_KEY]));
		e->flags |= (1 << NFTNL_EXPR_DYNSET_SREG_KEY);
	}
	if (tb[NFTA_DYNSET_SREG_DATA]) {
		dynset->sreg_data = ntohl(mnl_attr_get_u32(tb[NFTA_DYNSET_SREG_DATA]));
		e->flags |= (1 << NFTNL_EXPR_DYNSET_SREG_DATA);
	}
	if (tb[NFTA_DYNSET_OP]) {
		dynset->op = ntohl(mnl_attr_get_u32(tb[NFTA_DYNSET_OP]));
		e->flags |= (1 << NFTNL_EXPR_DYNSET_OP);
	}
	if (tb[NFTA_DYNSET_TIMEOUT]) {
		dynset->timeout = be64toh(mnl_attr_get_u64(tb[NFTA_DYNSET_TIMEOUT]));
		e->flags |= (1 << NFTNL_EXPR_DYNSET_TIMEOUT);
	}
	if (tb[NFTA_DYNSET_SET_NAME]) {
		dynset->set_name =
			strdup(mnl_attr_get_str(tb[NFTA_DYNSET_SET_NAME]));
		if (!dynset->set_name)
			return -1;
		e->flags |= (1 << NFTNL_EXPR_DYNSET_SET_NAME);
	}
	if (tb[NFTA_DYNSET_SET_ID]) {
		dynset->set_id = ntohl(mnl_attr_get_u32(tb[NFTA_DYNSET_SET_ID]));
		e->flags |= (1 << NFTNL_EXPR_DYNSET_SET_ID);
	}
	if (tb[NFTA_DYNSET_EXPR]) {
		e->flags |= (1 << NFTNL_EXPR_DYNSET_EXPR);
		dynset->expr = nftnl_expr_parse(tb[NFTA_DYNSET_EXPR]);
		if (dynset->expr == NULL)
			return -1;
	}

	return ret;
}

static int
nftnl_expr_dynset_json_parse(struct nftnl_expr *e, json_t *root,
				struct nftnl_parse_err *err)
{
#ifdef JSON_PARSING
	const char *set_name;
	uint32_t uval32;
	uint64_t uval64;

	set_name = nftnl_jansson_parse_str(root, "set", err);
	if (set_name != NULL)
		nftnl_expr_set_str(e, NFTNL_EXPR_DYNSET_SET_NAME, set_name);

	if (nftnl_jansson_parse_reg(root, "sreg_key",
				  NFTNL_TYPE_U32, &uval32, err) == 0)
		nftnl_expr_set_u32(e, NFTNL_EXPR_DYNSET_SREG_KEY, uval32);

	if (nftnl_jansson_parse_reg(root, "sreg_data",
				  NFTNL_TYPE_U32, &uval32, err) == 0)
		nftnl_expr_set_u32(e, NFTNL_EXPR_DYNSET_SREG_DATA, uval32);

	if (nftnl_jansson_parse_val(root, "op", NFTNL_TYPE_U32, &uval32,
				  err) == 0)
		nftnl_expr_set_u32(e, NFTNL_EXPR_DYNSET_OP, uval32);

	if (nftnl_jansson_parse_val(root, "timeout", NFTNL_TYPE_U64, &uval64,
				  err) == 0)
		nftnl_expr_set_u64(e, NFTNL_EXPR_DYNSET_TIMEOUT, uval64);

	return 0;
#else
	errno = EOPNOTSUPP;
	return -1;
#endif
}

static int
nftnl_expr_dynset_xml_parse(struct nftnl_expr *e, mxml_node_t *tree,
			       struct nftnl_parse_err *err)
{
#ifdef XML_PARSING
	const char *set_name;
	uint32_t uval32;
	uint64_t uval64;

	set_name = nftnl_mxml_str_parse(tree, "set", MXML_DESCEND_FIRST,
				      NFTNL_XML_MAND, err);
	if (set_name != NULL)
		nftnl_expr_set_str(e, NFTNL_EXPR_DYNSET_SET_NAME, set_name);

	if (nftnl_mxml_reg_parse(tree, "sreg_key", &uval32, MXML_DESCEND,
			       NFTNL_XML_MAND, err) == 0)
		nftnl_expr_set_u32(e, NFTNL_EXPR_DYNSET_SREG_KEY, uval32);

	if (nftnl_mxml_reg_parse(tree, "sreg_data", &uval32, MXML_DESCEND,
			       NFTNL_XML_MAND, err) == 0)
		nftnl_expr_set_u32(e, NFTNL_EXPR_DYNSET_SREG_DATA, uval32);

	if (nftnl_mxml_num_parse(tree, "op", MXML_DESCEND_FIRST, BASE_DEC,
			       &uval32, NFTNL_TYPE_U32, NFTNL_XML_MAND,  err) == 0)
		nftnl_expr_set_u32(e, NFTNL_EXPR_DYNSET_OP, uval32);

	if (nftnl_mxml_num_parse(tree, "timeout", MXML_DESCEND_FIRST, BASE_DEC,
			       &uval64, NFTNL_TYPE_U64, NFTNL_XML_MAND,  err) == 0)
		nftnl_expr_set_u64(e, NFTNL_EXPR_DYNSET_TIMEOUT, uval64);

	return 0;
#else
	errno = EOPNOTSUPP;
	return -1;
#endif
}

static int
nftnl_expr_dynset_export(char *buf, size_t size,
			 const struct nftnl_expr *e, int type)
{
	struct nftnl_expr_dynset *dynset = nftnl_expr_data(e);
	NFTNL_BUF_INIT(b, buf, size);

	if (e->flags & (1 << NFTNL_EXPR_DYNSET_SET_NAME))
		nftnl_buf_str(&b, type, dynset->set_name, SET_NAME);
	if (e->flags & (1 << NFTNL_EXPR_DYNSET_SREG_KEY))
		nftnl_buf_u32(&b, type, dynset->sreg_key, SREG_KEY);
	if (e->flags & (1 << NFTNL_EXPR_DYNSET_SREG_DATA))
		nftnl_buf_u32(&b, type, dynset->sreg_data, SREG_DATA);

	return nftnl_buf_done(&b);
}

static char *op2str_array[] = {
	[NFT_DYNSET_OP_ADD]		= "add",
	[NFT_DYNSET_OP_UPDATE] 		= "update",
};

static const char *op2str(enum nft_dynset_ops op)
{
	if (op > NFT_DYNSET_OP_UPDATE)
		return "unknown";
	return op2str_array[op];
}

static int
nftnl_expr_dynset_snprintf_default(char *buf, size_t size,
				   const struct nftnl_expr *e)
{
	struct nftnl_expr_dynset *dynset = nftnl_expr_data(e);
	struct nftnl_expr *expr;
	int len = size, offset = 0, ret;

	ret = snprintf(buf, len, "%s reg_key %u set %s ",
		       op2str(dynset->op), dynset->sreg_key, dynset->set_name);
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	if (e->flags & (1 << NFTNL_EXPR_DYNSET_SREG_DATA)) {
		ret = snprintf(buf+offset, len, "sreg_data %u ", dynset->sreg_data);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}
	if (e->flags & (1 << NFTNL_EXPR_DYNSET_TIMEOUT)) {
		ret = snprintf(buf+offset, len, "timeout %"PRIu64"ms ",
			       dynset->timeout);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}
	if (e->flags & (1 << NFTNL_EXPR_DYNSET_EXPR)) {
		expr = dynset->expr;
		ret = snprintf(buf+offset, len, "expr [ %s ",
			       expr->ops->name);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

		ret = nftnl_expr_snprintf(buf+offset, len, expr,
					     NFTNL_OUTPUT_DEFAULT,
					     NFTNL_OF_EVENT_ANY);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

		ret = snprintf(buf+offset, len, "] ");
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	return offset;
}

static int
nftnl_expr_dynset_snprintf(char *buf, size_t size, uint32_t type,
			   uint32_t flags, const struct nftnl_expr *e)
{

	switch (type) {
	case NFTNL_OUTPUT_DEFAULT:
		return nftnl_expr_dynset_snprintf_default(buf, size, e);
	case NFTNL_OUTPUT_XML:
	case NFTNL_OUTPUT_JSON:
		return nftnl_expr_dynset_export(buf, size, e, type);
	default:
		break;
	}
	return -1;
}

static void nftnl_expr_dynset_free(const struct nftnl_expr *e)
{
	struct nftnl_expr_dynset *dynset = nftnl_expr_data(e);

	xfree(dynset->set_name);
}

struct expr_ops expr_ops_dynset = {
	.name		= "dynset",
	.alloc_len	= sizeof(struct nftnl_expr_dynset),
	.max_attr	= NFTA_DYNSET_MAX,
	.free		= nftnl_expr_dynset_free,
	.set		= nftnl_expr_dynset_set,
	.get		= nftnl_expr_dynset_get,
	.parse		= nftnl_expr_dynset_parse,
	.build		= nftnl_expr_dynset_build,
	.snprintf	= nftnl_expr_dynset_snprintf,
	.xml_parse	= nftnl_expr_dynset_xml_parse,
	.json_parse	= nftnl_expr_dynset_json_parse,
};
