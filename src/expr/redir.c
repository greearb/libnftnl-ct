/*
 * (C) 2014 by Arturo Borrero Gonzalez <arturo.borrero.glez@gmail.com>
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
#include "expr_ops.h"

struct nft_expr_redir {
	enum nft_registers sreg_proto_min;
	enum nft_registers sreg_proto_max;
	uint32_t	flags;
};

static int
nft_rule_expr_redir_set(struct nft_rule_expr *e, uint16_t type,
			const void *data, uint32_t data_len)
{
	struct nft_expr_redir *redir = nft_expr_data(e);

	switch (type) {
	case NFT_EXPR_REDIR_REG_PROTO_MIN:
		redir->sreg_proto_min = *((uint32_t *)data);
		break;
	case NFT_EXPR_REDIR_REG_PROTO_MAX:
		redir->sreg_proto_max = *((uint32_t *)data);
		break;
	case NFT_EXPR_REDIR_FLAGS:
		redir->flags = *((uint32_t *)data);
		break;
	default:
		return -1;
	}
	return 0;
}

static const void *
nft_rule_expr_redir_get(const struct nft_rule_expr *e, uint16_t type,
			uint32_t *data_len)
{
	struct nft_expr_redir *redir = nft_expr_data(e);

	switch (type) {
	case NFT_EXPR_REDIR_REG_PROTO_MIN:
		*data_len = sizeof(redir->sreg_proto_min);
		return &redir->sreg_proto_min;
	case NFT_EXPR_REDIR_REG_PROTO_MAX:
		*data_len = sizeof(redir->sreg_proto_max);
		return &redir->sreg_proto_max;
	case NFT_EXPR_REDIR_FLAGS:
		*data_len = sizeof(redir->flags);
		return &redir->flags;
	}
	return NULL;
}

static int nft_rule_expr_redir_cb(const struct nlattr *attr, void *data)
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
nft_rule_expr_redir_build(struct nlmsghdr *nlh, struct nft_rule_expr *e)
{
	struct nft_expr_redir *redir = nft_expr_data(e);

	if (e->flags & (1 << NFT_EXPR_REDIR_REG_PROTO_MIN))
		mnl_attr_put_u32(nlh, NFTA_REDIR_REG_PROTO_MIN,
				 htobe32(redir->sreg_proto_min));
	if (e->flags & (1 << NFT_EXPR_REDIR_REG_PROTO_MAX))
		mnl_attr_put_u32(nlh, NFTA_REDIR_REG_PROTO_MAX,
				 htobe32(redir->sreg_proto_max));
	if (e->flags & (1 << NFT_EXPR_REDIR_FLAGS))
		mnl_attr_put_u32(nlh, NFTA_REDIR_FLAGS, htobe32(redir->flags));
}

static int
nft_rule_expr_redir_parse(struct nft_rule_expr *e, struct nlattr *attr)
{
	struct nft_expr_redir *redir = nft_expr_data(e);
	struct nlattr *tb[NFTA_REDIR_MAX + 1] = {};

	if (mnl_attr_parse_nested(attr, nft_rule_expr_redir_cb, tb) < 0)
		return -1;

	if (tb[NFTA_REDIR_REG_PROTO_MIN]) {
		redir->sreg_proto_min =
			ntohl(mnl_attr_get_u32(tb[NFTA_REDIR_REG_PROTO_MIN]));
		e->flags |= (1 << NFT_EXPR_REDIR_REG_PROTO_MIN);
	}
	if (tb[NFTA_REDIR_REG_PROTO_MAX]) {
		redir->sreg_proto_max =
			ntohl(mnl_attr_get_u32(tb[NFTA_REDIR_REG_PROTO_MAX]));
		e->flags |= (1 << NFT_EXPR_REDIR_REG_PROTO_MAX);
	}
	if (tb[NFTA_REDIR_FLAGS]) {
		redir->flags = be32toh(mnl_attr_get_u32(tb[NFTA_REDIR_FLAGS]));
		e->flags |= (1 << NFT_EXPR_REDIR_FLAGS);
	}

	return 0;
}

static int
nft_rule_expr_redir_json_parse(struct nft_rule_expr *e, json_t *root,
			       struct nft_parse_err *err)
{
#ifdef JSON_PARSING
	uint32_t reg, flags;

	if (nft_jansson_parse_reg(root, "sreg_proto_min", NFT_TYPE_U32,
				  &reg, err) == 0)
		nft_rule_expr_set_u32(e, NFT_EXPR_REDIR_REG_PROTO_MIN, reg);

	if (nft_jansson_parse_reg(root, "sreg_proto_max", NFT_TYPE_U32,
				  &reg, err) == 0)
		nft_rule_expr_set_u32(e, NFT_EXPR_REDIR_REG_PROTO_MAX, reg);

	if (nft_jansson_parse_val(root, "flags", NFT_TYPE_U32, &flags,
				  err) == 0)
		nft_rule_expr_set_u32(e, NFT_EXPR_REDIR_FLAGS, flags);

	return 0;
#else
	errno = EOPNOTSUPP;
	return -1;
#endif
}

static int
nft_rule_expr_redir_xml_parse(struct nft_rule_expr *e, mxml_node_t *tree,
			      struct nft_parse_err *err)
{
#ifdef XML_PARSING
	uint32_t reg, flags;

	if (nft_mxml_reg_parse(tree, "sreg_proto_min", &reg,
			       MXML_DESCEND, NFT_XML_OPT, err) == 0)
		nft_rule_expr_set_u32(e, NFT_EXPR_REDIR_REG_PROTO_MIN, reg);

	if (nft_mxml_reg_parse(tree, "sreg_proto_max", &reg,
			       MXML_DESCEND, NFT_XML_OPT, err) == 0)
		nft_rule_expr_set_u32(e, NFT_EXPR_REDIR_REG_PROTO_MAX, reg);

	if (nft_mxml_num_parse(tree, "flags", MXML_DESCEND_FIRST, BASE_DEC,
			       &flags, NFT_TYPE_U32, NFT_XML_OPT, err) == 0)
		nft_rule_expr_set_u32(e, NFT_EXPR_REDIR_FLAGS, flags);

	return 0;
#else
	errno = EOPNOTSUPP;
	return -1;
#endif
}

static int nft_rule_expr_redir_snprintf_json(char *buf, size_t len,
					     struct nft_rule_expr *e)
{
	int ret, size = len, offset = 0;
	struct nft_expr_redir *redir = nft_expr_data(e);

	if (nft_rule_expr_is_set(e, NFT_EXPR_REDIR_REG_PROTO_MIN)) {
		ret = snprintf(buf + offset, len, "\"sreg_proto_min\":%u,",
			       redir->sreg_proto_min);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	if (nft_rule_expr_is_set(e, NFT_EXPR_REDIR_REG_PROTO_MAX)) {
		ret = snprintf(buf + offset, len, "\"sreg_proto_max\":%u,",
			       redir->sreg_proto_max);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	if (nft_rule_expr_is_set(e, NFT_EXPR_REDIR_FLAGS)) {
		ret = snprintf(buf + offset, len, "\"flags\":%u",
			       redir->flags);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	return offset;
}

static int nft_rule_expr_redir_snprintf_xml(char *buf, size_t len,
					    struct nft_rule_expr *e)
{
	int ret, size = len, offset = 0;
	struct nft_expr_redir *redir = nft_expr_data(e);

	if (nft_rule_expr_is_set(e, NFT_EXPR_REDIR_REG_PROTO_MIN)) {
		ret = snprintf(buf + offset, len,
			       "<sreg_proto_min>%u<sreg_proto_min>",
			       redir->sreg_proto_min);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	if (nft_rule_expr_is_set(e, NFT_EXPR_REDIR_REG_PROTO_MAX)) {
		ret = snprintf(buf + offset, len,
			       "<sreg_proto_max>%u</sreg_proto_max>",
			       redir->sreg_proto_max);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	if (nft_rule_expr_is_set(e, NFT_EXPR_REDIR_FLAGS)) {
		ret = snprintf(buf + offset, len, "<flags>%u</flags>",
			       redir->flags);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	return offset;
}

static int nft_rule_expr_redir_snprintf_default(char *buf, size_t len,
						struct nft_rule_expr *e)
{
	int ret, size = len, offset = 0;
	struct nft_expr_redir *redir = nft_expr_data(e);

	if (nft_rule_expr_is_set(e, NFT_EXPR_REDIR_REG_PROTO_MIN)) {
		ret = snprintf(buf + offset, len, "proto_min reg %u ",
			       redir->sreg_proto_min);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	if (nft_rule_expr_is_set(e, NFT_EXPR_REDIR_REG_PROTO_MAX)) {
		ret = snprintf(buf + offset, len, "proto_max reg %u ",
			       redir->sreg_proto_max);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	if (nft_rule_expr_is_set(e, NFT_EXPR_REDIR_FLAGS)) {
		ret = snprintf(buf + offset , len, "flags 0x%x ",
			       redir->flags);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	return 0;
}

static int
nft_rule_expr_redir_snprintf(char *buf, size_t len, uint32_t type,
			     uint32_t flags, struct nft_rule_expr *e)
{
	switch (type) {
	case NFT_OUTPUT_DEFAULT:
		return nft_rule_expr_redir_snprintf_default(buf, len, e);
	case NFT_OUTPUT_XML:
		return nft_rule_expr_redir_snprintf_xml(buf, len, e);
	case NFT_OUTPUT_JSON:
		return nft_rule_expr_redir_snprintf_json(buf, len, e);
	default:
		break;
	}
	return -1;
}

struct expr_ops expr_ops_redir = {
	.name		= "redir",
	.alloc_len	= sizeof(struct nft_expr_redir),
	.max_attr	= NFTA_REDIR_MAX,
	.set		= nft_rule_expr_redir_set,
	.get		= nft_rule_expr_redir_get,
	.parse		= nft_rule_expr_redir_parse,
	.build		= nft_rule_expr_redir_build,
	.snprintf	= nft_rule_expr_redir_snprintf,
	.xml_parse	= nft_rule_expr_redir_xml_parse,
	.json_parse	= nft_rule_expr_redir_json_parse,
};

static void __init expr_redir_init(void)
{
	nft_expr_ops_register(&expr_ops_redir);
}
