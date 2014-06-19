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

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include <errno.h>

#include <libmnl/libmnl.h>
#include <linux/netfilter/nf_tables.h>
#include <libnftnl/expr.h>
#include <libnftnl/rule.h>
#include "expr_ops.h"
#include "data_reg.h"

struct nft_expr_cmp {
	union nft_data_reg	data;
	enum nft_registers	sreg;
	enum nft_cmp_ops	op;
};

static int
nft_rule_expr_cmp_set(struct nft_rule_expr *e, uint16_t type,
		      const void *data, uint32_t data_len)
{
	struct nft_expr_cmp *cmp = nft_expr_data(e);

	switch(type) {
	case NFT_EXPR_CMP_SREG:
		cmp->sreg = *((uint32_t *)data);
		break;
	case NFT_EXPR_CMP_OP:
		cmp->op = *((uint32_t *)data);
		break;
	case NFT_EXPR_CMP_DATA:
		memcpy(&cmp->data.val, data, data_len);
		cmp->data.len = data_len;
		break;
	default:
		return -1;
	}
	return 0;
}

static const void *
nft_rule_expr_cmp_get(const struct nft_rule_expr *e, uint16_t type,
		      uint32_t *data_len)
{
	struct nft_expr_cmp *cmp = nft_expr_data(e);

	switch(type) {
	case NFT_EXPR_CMP_SREG:
		*data_len = sizeof(cmp->sreg);
		return &cmp->sreg;
	case NFT_EXPR_CMP_OP:
		*data_len = sizeof(cmp->op);
		return &cmp->op;
	case NFT_EXPR_CMP_DATA:
		*data_len = cmp->data.len;
		return &cmp->data.val;
	}
	return NULL;
}

static int nft_rule_expr_cmp_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, NFTA_CMP_MAX) < 0)
		return MNL_CB_OK;

	switch(type) {
	case NFTA_CMP_SREG:
	case NFTA_CMP_OP:
		if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0) {
			perror("mnl_attr_validate");
			return MNL_CB_ERROR;
		}
		break;
	case NFTA_CMP_DATA:
		if (mnl_attr_validate(attr, MNL_TYPE_BINARY) < 0) {
			perror("mnl_attr_validate");
			return MNL_CB_ERROR;
		}
		break;
	}

	tb[type] = attr;
	return MNL_CB_OK;
}

static void
nft_rule_expr_cmp_build(struct nlmsghdr *nlh, struct nft_rule_expr *e)
{
	struct nft_expr_cmp *cmp = nft_expr_data(e);

	if (e->flags & (1 << NFT_EXPR_CMP_SREG))
		mnl_attr_put_u32(nlh, NFTA_CMP_SREG, htonl(cmp->sreg));
	if (e->flags & (1 << NFT_EXPR_CMP_OP))
		mnl_attr_put_u32(nlh, NFTA_CMP_OP, htonl(cmp->op));
	if (e->flags & (1 << NFT_EXPR_CMP_DATA)) {
		struct nlattr *nest;

		nest = mnl_attr_nest_start(nlh, NFTA_CMP_DATA);
		mnl_attr_put(nlh, NFTA_DATA_VALUE, cmp->data.len, cmp->data.val);
		mnl_attr_nest_end(nlh, nest);
	}
}

static int
nft_rule_expr_cmp_parse(struct nft_rule_expr *e, struct nlattr *attr)
{
	struct nft_expr_cmp *cmp = nft_expr_data(e);
	struct nlattr *tb[NFTA_CMP_MAX+1] = {};
	int ret = 0;

	if (mnl_attr_parse_nested(attr, nft_rule_expr_cmp_cb, tb) < 0)
		return -1;

	if (tb[NFTA_CMP_SREG]) {
		cmp->sreg = ntohl(mnl_attr_get_u32(tb[NFTA_CMP_SREG]));
		e->flags |= (1 << NFTA_CMP_SREG);
	}
	if (tb[NFTA_CMP_OP]) {
		cmp->op = ntohl(mnl_attr_get_u32(tb[NFTA_CMP_OP]));
		e->flags |= (1 << NFTA_CMP_OP);
	}
	if (tb[NFTA_CMP_DATA]) {
		ret = nft_parse_data(&cmp->data, tb[NFTA_CMP_DATA], NULL);
		e->flags |= (1 << NFTA_CMP_DATA);
	}

	return ret;
}

static char *expr_cmp_str[] = {
	[NFT_CMP_EQ]	= "eq",
	[NFT_CMP_NEQ]	= "neq",
	[NFT_CMP_LT]	= "lt",
	[NFT_CMP_LTE]	= "lte",
	[NFT_CMP_GT]	= "gt",
	[NFT_CMP_GTE]	= "gte",
};

static inline int nft_str2cmp(const char *op)
{
	if (strcmp(op, "eq") == 0)
		return NFT_CMP_EQ;
	else if (strcmp(op, "neq") == 0)
		return NFT_CMP_NEQ;
	else if (strcmp(op, "lt") == 0)
		return NFT_CMP_LT;
	else if (strcmp(op, "lte") == 0)
		return NFT_CMP_LTE;
	else if (strcmp(op, "gt") == 0)
		return NFT_CMP_GT;
	else if (strcmp(op, "gte") == 0)
		return NFT_CMP_GTE;
	else {
		errno = EINVAL;
		return -1;
	}
}

static int nft_rule_expr_cmp_json_parse(struct nft_rule_expr *e, json_t *root,
					struct nft_parse_err *err)
{
#ifdef JSON_PARSING
	struct nft_expr_cmp *cmp = nft_expr_data(e);
	const char *op;
	uint32_t uval32;
	int base;

	if (nft_jansson_parse_val(root, "sreg", NFT_TYPE_U32, &uval32, err) < 0)
		return -1;

	nft_rule_expr_set_u32(e, NFT_EXPR_CMP_SREG, uval32);

	op = nft_jansson_parse_str(root, "op", err);
	if (op == NULL)
		return -1;

	base = nft_str2cmp(op);
	if (base < 0)
		return -1;

	nft_rule_expr_set_u32(e, NFT_EXPR_CMP_OP, base);

	if (nft_jansson_data_reg_parse(root, "cmpdata",
				       &cmp->data, err) != DATA_VALUE)
		return -1;

	e->flags |= (1 << NFT_EXPR_CMP_DATA);

	return 0;
#else
	errno = EOPNOTSUPP;
	return -1;
#endif
}

static int nft_rule_expr_cmp_xml_parse(struct nft_rule_expr *e, mxml_node_t *tree,
				       struct nft_parse_err *err)
{
#ifdef XML_PARSING
	struct nft_expr_cmp *cmp = nft_expr_data(e);
	const char *op;
	int32_t op_value;
	uint32_t reg;

	if (nft_mxml_reg_parse(tree, "sreg", &reg, MXML_DESCEND_FIRST,
			       NFT_XML_MAND, err) != 0)
		return -1;

	cmp->sreg = reg;
	e->flags |= (1 << NFT_EXPR_CMP_SREG);

	op = nft_mxml_str_parse(tree, "op", MXML_DESCEND_FIRST, NFT_XML_MAND,
				err);
	if (op == NULL)
		return -1;

	op_value = nft_str2cmp(op);
	if (op_value < 0)
		return -1;

	cmp->op = op_value;
	e->flags |= (1 << NFT_EXPR_CMP_OP);

	if (nft_mxml_data_reg_parse(tree, "cmpdata",
				    &cmp->data, NFT_XML_MAND,
				    err) != DATA_VALUE)
		return -1;

	e->flags |= (1 << NFT_EXPR_CMP_DATA);

	return 0;
#else
	errno = EOPNOTSUPP;
	return -1;
#endif
}

static int nft_rule_expr_cmp_snprintf_json(char *buf, size_t size,
					   struct nft_rule_expr *e)
{
	struct nft_expr_cmp *cmp = nft_expr_data(e);
	int len = size, offset = 0, ret;

	ret = snprintf(buf, len, "\"sreg\":%u,\"op\":\"%s\",",
		       cmp->sreg, expr_cmp_str[cmp->op]);
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	ret = nft_data_reg_snprintf(buf+offset, len, &cmp->data,
				    NFT_OUTPUT_JSON, 0, DATA_VALUE);
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	return offset;
}

static int nft_rule_expr_cmp_snprintf_xml(char *buf, size_t size,
					  struct nft_rule_expr *e)
{
	struct nft_expr_cmp *cmp = nft_expr_data(e);
	int len = size, offset = 0, ret;

	ret = snprintf(buf, len, "<sreg>%u</sreg><op>%s</op>",
		       cmp->sreg, expr_cmp_str[cmp->op]);
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	ret = nft_data_reg_snprintf(buf+offset, len, &cmp->data,
				    NFT_OUTPUT_XML, 0, DATA_VALUE);
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	return offset;
}

static int nft_rule_expr_cmp_snprintf_default(char *buf, size_t size,
					      struct nft_rule_expr *e)
{
	struct nft_expr_cmp *cmp = nft_expr_data(e);
	int len = size, offset = 0, ret;

	ret = snprintf(buf, len, "%s reg %u ",
		       expr_cmp_str[cmp->op], cmp->sreg);
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	ret = nft_data_reg_snprintf(buf+offset, len, &cmp->data,
				    NFT_OUTPUT_DEFAULT, 0, DATA_VALUE);
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	return offset;
}

static int
nft_rule_expr_cmp_snprintf(char *buf, size_t size, uint32_t type,
			   uint32_t flags, struct nft_rule_expr *e)
{
	switch(type) {
	case NFT_OUTPUT_DEFAULT:
		return nft_rule_expr_cmp_snprintf_default(buf, size, e);
	case NFT_OUTPUT_XML:
		return nft_rule_expr_cmp_snprintf_xml(buf, size, e);
	case NFT_OUTPUT_JSON:
		return nft_rule_expr_cmp_snprintf_json(buf, size, e);
	default:
		break;
	}
	return -1;
}

struct expr_ops expr_ops_cmp = {
	.name		= "cmp",
	.alloc_len	= sizeof(struct nft_expr_cmp),
	.max_attr	= NFTA_CMP_MAX,
	.set		= nft_rule_expr_cmp_set,
	.get		= nft_rule_expr_cmp_get,
	.parse		= nft_rule_expr_cmp_parse,
	.build		= nft_rule_expr_cmp_build,
	.snprintf	= nft_rule_expr_cmp_snprintf,
	.xml_parse	= nft_rule_expr_cmp_xml_parse,
	.json_parse	= nft_rule_expr_cmp_json_parse,
};
static void __init expr_cmp_init(void)
{
	nft_expr_ops_register(&expr_ops_cmp);
}
