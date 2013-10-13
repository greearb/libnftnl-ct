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
#include <libnftables/expr.h>
#include <libnftables/rule.h>
#include "data_reg.h"
#include "expr_ops.h"

struct nft_expr_byteorder {
	enum nft_registers	sreg;
	enum nft_registers	dreg;
	enum nft_byteorder_ops	op;
	unsigned int		len;
	unsigned int		size;
};

static int
nft_rule_expr_byteorder_set(struct nft_rule_expr *e, uint16_t type,
			  const void *data, uint32_t data_len)
{
	struct nft_expr_byteorder *byteorder = nft_expr_data(e);

	switch(type) {
	case NFT_EXPR_BYTEORDER_SREG:
		byteorder->sreg = *((uint32_t *)data);
		break;
	case NFT_EXPR_BYTEORDER_DREG:
		byteorder->dreg = *((uint32_t *)data);
		break;
	case NFT_EXPR_BYTEORDER_OP:
		byteorder->op = *((uint32_t *)data);
		break;
	case NFT_EXPR_BYTEORDER_LEN:
		byteorder->len = *((unsigned int *)data);
		break;
	case NFT_EXPR_BYTEORDER_SIZE:
		byteorder->size = *((unsigned int *)data);
		break;
	default:
		return -1;
	}
	return 0;
}

static const void *
nft_rule_expr_byteorder_get(const struct nft_rule_expr *e, uint16_t type,
			    uint32_t *data_len)
{
	struct nft_expr_byteorder *byteorder = nft_expr_data(e);

	switch(type) {
	case NFT_EXPR_BYTEORDER_SREG:
		*data_len = sizeof(byteorder->sreg);
		return &byteorder->sreg;
	case NFT_EXPR_BYTEORDER_DREG:
		*data_len = sizeof(byteorder->dreg);
		return &byteorder->dreg;
	case NFT_EXPR_BYTEORDER_OP:
		*data_len = sizeof(byteorder->op);
		return &byteorder->op;
	case NFT_EXPR_BYTEORDER_LEN:
		*data_len = sizeof(byteorder->len);
		return &byteorder->len;
	case NFT_EXPR_BYTEORDER_SIZE:
		*data_len = sizeof(byteorder->size);
		return &byteorder->size;
	}
	return NULL;
}

static int nft_rule_expr_byteorder_cb(const struct nlattr *attr, void *data)
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
		if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0) {
			perror("mnl_attr_validate");
			return MNL_CB_ERROR;
		}
		break;
	}

	tb[type] = attr;
	return MNL_CB_OK;
}

static void
nft_rule_expr_byteorder_build(struct nlmsghdr *nlh, struct nft_rule_expr *e)
{
	struct nft_expr_byteorder *byteorder = nft_expr_data(e);

	if (e->flags & (1 << NFT_EXPR_BYTEORDER_SREG)) {
		mnl_attr_put_u32(nlh, NFTA_BYTEORDER_SREG,
				 htonl(byteorder->sreg));
	}
	if (e->flags & (1 << NFT_EXPR_BYTEORDER_DREG)) {
		mnl_attr_put_u32(nlh, NFTA_BYTEORDER_DREG,
				 htonl(byteorder->dreg));
	}
	if (e->flags & (1 << NFT_EXPR_BYTEORDER_OP)) {
		mnl_attr_put_u32(nlh, NFTA_BYTEORDER_OP,
				 htonl(byteorder->op));
	}
	if (e->flags & (1 << NFT_EXPR_BYTEORDER_LEN)) {
		mnl_attr_put_u32(nlh, NFTA_BYTEORDER_LEN,
				 htonl(byteorder->len));
	}
	if (e->flags & (1 << NFT_EXPR_BYTEORDER_SIZE)) {
		mnl_attr_put_u32(nlh, NFTA_BYTEORDER_SIZE,
				 htonl(byteorder->size));
	}
}

static int
nft_rule_expr_byteorder_parse(struct nft_rule_expr *e, struct nlattr *attr)
{
	struct nft_expr_byteorder *byteorder = nft_expr_data(e);
	struct nlattr *tb[NFTA_BYTEORDER_MAX+1] = {};
	int ret = 0;

	if (mnl_attr_parse_nested(attr, nft_rule_expr_byteorder_cb, tb) < 0)
		return -1;

	if (tb[NFTA_BYTEORDER_SREG]) {
		byteorder->sreg =
			ntohl(mnl_attr_get_u32(tb[NFTA_BYTEORDER_SREG]));
		e->flags |= (1 << NFT_EXPR_BYTEORDER_SREG);
	}
	if (tb[NFTA_BYTEORDER_DREG]) {
		byteorder->dreg =
			ntohl(mnl_attr_get_u32(tb[NFTA_BYTEORDER_DREG]));
		e->flags |= (1 << NFT_EXPR_BYTEORDER_DREG);
	}
	if (tb[NFTA_BYTEORDER_OP]) {
		byteorder->op =
			ntohl(mnl_attr_get_u32(tb[NFTA_BYTEORDER_OP]));
		e->flags |= (1 << NFT_EXPR_BYTEORDER_OP);
	}
	if (tb[NFTA_BYTEORDER_LEN]) {
		byteorder->len =
			ntohl(mnl_attr_get_u32(tb[NFTA_BYTEORDER_LEN]));
		e->flags |= (1 << NFT_EXPR_BYTEORDER_LEN);
	}
	if (tb[NFTA_BYTEORDER_SIZE]) {
		byteorder->size =
			ntohl(mnl_attr_get_u32(tb[NFTA_BYTEORDER_SIZE]));
		e->flags |= (1 << NFT_EXPR_BYTEORDER_SIZE);
	}

	return ret;
}

static char *expr_byteorder_str[] = {
	[NFT_BYTEORDER_HTON] = "hton",
	[NFT_BYTEORDER_NTOH] = "ntoh",
};

static inline int nft_str2ntoh(const char *op)
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
nft_rule_expr_byteorder_json_parse(struct nft_rule_expr *e, json_t *root)
{
#ifdef JSON_PARSING
	const char *op;
	uint32_t uval32;
	int ntoh;

	if (nft_jansson_parse_reg(root, "sreg", NFT_TYPE_U32, &uval32) < 0)
		return -1;

	nft_rule_expr_set_u32(e, NFT_EXPR_BYTEORDER_SREG, uval32);

	if (nft_jansson_parse_reg(root, "dreg", NFT_TYPE_U32, &uval32) < 0)
		return -1;

	nft_rule_expr_set_u32(e, NFT_EXPR_BYTEORDER_DREG, uval32);

	op = nft_jansson_parse_str(root, "op");
	if (op == NULL)
		return -1;

	ntoh = nft_str2ntoh(op);
	if (ntoh < 0)
		return -1;

	nft_rule_expr_set_u32(e, NFT_EXPR_BYTEORDER_OP, ntoh);

	if (nft_jansson_parse_val(root, "len", NFT_TYPE_U32, &uval32) < 0)
		return -1;

	nft_rule_expr_set_u32(e, NFT_EXPR_BYTEORDER_LEN, uval32);

	if (nft_jansson_parse_val(root, "size", NFT_TYPE_U32, &uval32) < 0)
		return -1;

	nft_rule_expr_set_u32(e, NFT_EXPR_BYTEORDER_SIZE, uval32);

	return 0;
#else
	errno = EOPNOTSUPP;
	return -1;
#endif
}

static int
nft_rule_expr_byteorder_xml_parse(struct nft_rule_expr *e, mxml_node_t *tree)
{
#ifdef XML_PARSING
	struct nft_expr_byteorder *byteorder = nft_expr_data(e);
	const char *op;
	int32_t reg, ntoh;

	reg = nft_mxml_reg_parse(tree, "sreg", MXML_DESCEND_FIRST);
	if (reg < 0)
		return -1;

	byteorder->sreg = reg;
	e->flags |= (1 << NFT_EXPR_BYTEORDER_SREG);

	reg = nft_mxml_reg_parse(tree, "dreg", MXML_DESCEND);
	if (reg < 0)
		return -1;

	byteorder->dreg = reg;
	e->flags |= (1 << NFT_EXPR_BYTEORDER_DREG);

	op = nft_mxml_str_parse(tree, "op", MXML_DESCEND_FIRST, NFT_XML_MAND);
	if (op == NULL)
		return -1;

	ntoh = nft_str2ntoh(op);
	if (ntoh < 0)
		return -1;

	byteorder->op = ntoh;
	e->flags |= (1 << NFT_EXPR_BYTEORDER_OP);

	if (nft_mxml_num_parse(tree, "len", MXML_DESCEND_FIRST, BASE_DEC,
			       &byteorder->len, NFT_TYPE_U8,
			       NFT_XML_MAND) != 0)
		return -1;

	e->flags |= (1 << NFT_EXPR_BYTEORDER_LEN);

	if (nft_mxml_num_parse(tree, "size", MXML_DESCEND_FIRST, BASE_DEC,
			       &byteorder->size, NFT_TYPE_U8,
			       NFT_XML_MAND) != 0)
		return -1;

	e->flags |= (1 << NFT_EXPR_BYTEORDER_SIZE);

	return 0;
#else
	errno = EOPNOTSUPP;
	return -1;
#endif
}

static int
nft_rule_expr_byteorder_snprintf_json(char *buf, size_t size,
				       struct nft_expr_byteorder *byteorder)
{
	int len = size, offset = 0, ret;

	ret = snprintf(buf, len, "\"sreg\":%u,"
				 "\"dreg\":%u,"
				 "\"op\":\"%s\","
				 "\"len\":%u,"
				 "\"size\":%u",
		       byteorder->sreg, byteorder->dreg,
		       expr_byteorder_str[byteorder->op],
		       byteorder->len, byteorder->size);
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	return offset;
}

static int
nft_rule_expr_byteorder_snprintf_xml(char *buf, size_t size,
				   struct nft_expr_byteorder *byteorder)
{
	int len = size, offset = 0, ret;

	ret = snprintf(buf, len, "<sreg>%u</sreg>"
				 "<dreg>%u</dreg>"
				 "<op>%s</op>"
				 "<len>%u</len>"
				 "<size>%u</size>",
		       byteorder->sreg, byteorder->dreg,
		       expr_byteorder_str[byteorder->op],
		       byteorder->len, byteorder->size);
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	return offset;
}

static int
nft_rule_expr_byteorder_snprintf_default(char *buf, size_t size,
				       struct nft_expr_byteorder *byteorder)
{
	int len = size, offset = 0, ret;

	ret = snprintf(buf, len, "reg %u = %s(reg %u, %u, %u) ",
		       byteorder->dreg, expr_byteorder_str[byteorder->op],
		       byteorder->sreg, byteorder->size, byteorder->len);
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	return offset;
}

static int
nft_rule_expr_byteorder_snprintf(char *buf, size_t size, uint32_t type,
			       uint32_t flags, struct nft_rule_expr *e)
{
	struct nft_expr_byteorder *byteorder = nft_expr_data(e);

	switch(type) {
	case NFT_RULE_O_DEFAULT:
		return nft_rule_expr_byteorder_snprintf_default(buf, size,
								byteorder);
	case NFT_RULE_O_XML:
		return nft_rule_expr_byteorder_snprintf_xml(buf, size,
							    byteorder);
	case NFT_RULE_O_JSON:
		return nft_rule_expr_byteorder_snprintf_json(buf, size,
							    byteorder);
	default:
		break;
	}
	return -1;
}

struct expr_ops expr_ops_byteorder = {
	.name		= "byteorder",
	.alloc_len	= sizeof(struct nft_expr_byteorder),
	.max_attr	= NFTA_BYTEORDER_MAX,
	.set		= nft_rule_expr_byteorder_set,
	.get		= nft_rule_expr_byteorder_get,
	.parse		= nft_rule_expr_byteorder_parse,
	.build		= nft_rule_expr_byteorder_build,
	.snprintf	= nft_rule_expr_byteorder_snprintf,
	.xml_parse	= nft_rule_expr_byteorder_xml_parse,
	.json_parse	= nft_rule_expr_byteorder_json_parse,
};

static void __init expr_byteorder_init(void)
{
	nft_expr_ops_register(&expr_ops_byteorder);
}
