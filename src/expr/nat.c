/*
 * (C) 2012-2014 Pablo Neira Ayuso <pablo@netfilter.org>
 * (C) 2012 Intel Corporation
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Authors:
 * 	Tomasz Bursztyka <tomasz.bursztyka@linux.intel.com>
 */

#include "internal.h"

#include <stdio.h>
#include <stdint.h>
#include <limits.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <libmnl/libmnl.h>
#include <linux/netfilter/nf_tables.h>
#include <libnftnl/expr.h>
#include <libnftnl/rule.h>

struct nft_expr_nat {
	enum nft_registers sreg_addr_min;
	enum nft_registers sreg_addr_max;
	enum nft_registers sreg_proto_min;
	enum nft_registers sreg_proto_max;
	int                family;
	enum nft_nat_types type;
	uint32_t	   flags;
};

static int
nft_rule_expr_nat_set(struct nft_rule_expr *e, uint16_t type,
		      const void *data, uint32_t data_len)
{
	struct nft_expr_nat *nat = nft_expr_data(e);

	switch(type) {
	case NFT_EXPR_NAT_TYPE:
		nat->type = *((uint32_t *)data);
		break;
	case NFT_EXPR_NAT_FAMILY:
		nat->family = *((uint32_t *)data);
		break;
	case NFT_EXPR_NAT_REG_ADDR_MIN:
		nat->sreg_addr_min = *((uint32_t *)data);
		break;
	case NFT_EXPR_NAT_REG_ADDR_MAX:
		nat->sreg_addr_max = *((uint32_t *)data);
		break;
	case NFT_EXPR_NAT_REG_PROTO_MIN:
		nat->sreg_proto_min = *((uint32_t *)data);
		break;
	case NFT_EXPR_NAT_REG_PROTO_MAX:
		nat->sreg_proto_max = *((uint32_t *)data);
		break;
	case NFT_EXPR_NAT_FLAGS:
		nat->flags = *((uint32_t *)data);
		break;
	default:
		return -1;
	}

	return 0;
}

static const void *
nft_rule_expr_nat_get(const struct nft_rule_expr *e, uint16_t type,
		      uint32_t *data_len)
{
	struct nft_expr_nat *nat = nft_expr_data(e);

	switch(type) {
	case NFT_EXPR_NAT_TYPE:
		*data_len = sizeof(nat->type);
		return &nat->type;
	case NFT_EXPR_NAT_FAMILY:
		*data_len = sizeof(nat->family);
		return &nat->family;
	case NFT_EXPR_NAT_REG_ADDR_MIN:
		*data_len = sizeof(nat->sreg_addr_min);
		return &nat->sreg_addr_min;
	case NFT_EXPR_NAT_REG_ADDR_MAX:
		*data_len = sizeof(nat->sreg_addr_max);
		return &nat->sreg_addr_max;
	case NFT_EXPR_NAT_REG_PROTO_MIN:
		*data_len = sizeof(nat->sreg_proto_min);
		return &nat->sreg_proto_min;
	case NFT_EXPR_NAT_REG_PROTO_MAX:
		*data_len = sizeof(nat->sreg_proto_max);
		return &nat->sreg_proto_max;
	case NFT_EXPR_NAT_FLAGS:
		*data_len = sizeof(nat->flags);
		return &nat->flags;
	}
	return NULL;
}

static int nft_rule_expr_nat_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, NFTA_NAT_MAX) < 0)
		return MNL_CB_OK;

	switch(type) {
	case NFTA_NAT_TYPE:
	case NFTA_NAT_FAMILY:
	case NFTA_NAT_REG_ADDR_MIN:
	case NFTA_NAT_REG_ADDR_MAX:
	case NFTA_NAT_REG_PROTO_MIN:
	case NFTA_NAT_REG_PROTO_MAX:
	case NFTA_NAT_FLAGS:
		if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0)
			abi_breakage();
		break;
	}

	tb[type] = attr;
	return MNL_CB_OK;
}

static int
nft_rule_expr_nat_parse(struct nft_rule_expr *e, struct nlattr *attr)
{
	struct nft_expr_nat *nat = nft_expr_data(e);
	struct nlattr *tb[NFTA_NAT_MAX+1] = {};

	if (mnl_attr_parse_nested(attr, nft_rule_expr_nat_cb, tb) < 0)
		return -1;

	if (tb[NFTA_NAT_TYPE]) {
		nat->type = ntohl(mnl_attr_get_u32(tb[NFTA_NAT_TYPE]));
		e->flags |= (1 << NFT_EXPR_NAT_TYPE);
	}
	if (tb[NFTA_NAT_FAMILY]) {
		nat->family = ntohl(mnl_attr_get_u32(tb[NFTA_NAT_FAMILY]));
		e->flags |= (1 << NFT_EXPR_NAT_FAMILY);
	}
	if (tb[NFTA_NAT_REG_ADDR_MIN]) {
		nat->sreg_addr_min =
			ntohl(mnl_attr_get_u32(tb[NFTA_NAT_REG_ADDR_MIN]));
		e->flags |= (1 << NFT_EXPR_NAT_REG_ADDR_MIN);
	}
	if (tb[NFTA_NAT_REG_ADDR_MAX]) {
		nat->sreg_addr_max =
			ntohl(mnl_attr_get_u32(tb[NFTA_NAT_REG_ADDR_MAX]));
		e->flags |= (1 << NFT_EXPR_NAT_REG_ADDR_MAX);
	}
	if (tb[NFTA_NAT_REG_PROTO_MIN]) {
		nat->sreg_proto_min =
			ntohl(mnl_attr_get_u32(tb[NFTA_NAT_REG_PROTO_MIN]));
		e->flags |= (1 << NFT_EXPR_NAT_REG_PROTO_MIN);
	}
	if (tb[NFTA_NAT_REG_PROTO_MAX]) {
		nat->sreg_proto_max =
			ntohl(mnl_attr_get_u32(tb[NFTA_NAT_REG_PROTO_MAX]));
		e->flags |= (1 << NFT_EXPR_NAT_REG_PROTO_MAX);
	}
	if (tb[NFTA_NAT_FLAGS]) {
		nat->flags = ntohl(mnl_attr_get_u32(tb[NFTA_NAT_FLAGS]));
		e->flags |= (1 << NFT_EXPR_NAT_FLAGS);
	}

	return 0;
}

static void
nft_rule_expr_nat_build(struct nlmsghdr *nlh, struct nft_rule_expr *e)
{
	struct nft_expr_nat *nat = nft_expr_data(e);

	if (e->flags & (1 << NFT_EXPR_NAT_TYPE))
		mnl_attr_put_u32(nlh, NFTA_NAT_TYPE, htonl(nat->type));
	if (e->flags & (1 << NFT_EXPR_NAT_FAMILY))
		mnl_attr_put_u32(nlh, NFTA_NAT_FAMILY, htonl(nat->family));
	if (e->flags & (1 << NFT_EXPR_NAT_REG_ADDR_MIN))
		mnl_attr_put_u32(nlh, NFTA_NAT_REG_ADDR_MIN,
				 htonl(nat->sreg_addr_min));
	if (e->flags & (1 << NFT_EXPR_NAT_REG_ADDR_MAX))
		mnl_attr_put_u32(nlh, NFTA_NAT_REG_ADDR_MAX,
				 htonl(nat->sreg_addr_max));
	if (e->flags & (1 << NFT_EXPR_NAT_REG_PROTO_MIN))
		mnl_attr_put_u32(nlh, NFTA_NAT_REG_PROTO_MIN,
				 htonl(nat->sreg_proto_min));
	if (e->flags & (1 << NFT_EXPR_NAT_REG_PROTO_MAX))
		mnl_attr_put_u32(nlh, NFTA_NAT_REG_PROTO_MAX,
				 htonl(nat->sreg_proto_max));
	if (e->flags & (1 << NFT_EXPR_NAT_FLAGS))
		mnl_attr_put_u32(nlh, NFTA_NAT_FLAGS, htonl(nat->flags));
}

static inline const char *nat2str(uint16_t nat)
{
	switch (nat) {
	case NFT_NAT_SNAT:
		return "snat";
	case NFT_NAT_DNAT:
		return "dnat";
	default:
		return "unknown";
	}
}

static inline int nft_str2nat(const char *nat)
{
	if (strcmp(nat, "snat") == 0)
		return NFT_NAT_SNAT;
	else if (strcmp(nat, "dnat") == 0)
		return NFT_NAT_DNAT;
	else {
		errno = EINVAL;
		return -1;
	}
}

static int nft_rule_expr_nat_json_parse(struct nft_rule_expr *e, json_t *root,
					struct nft_parse_err *err)
{
#ifdef JSON_PARSING
	const char *nat_type, *family_str;
	uint32_t reg, flags;
	int val32;

	nat_type = nft_jansson_parse_str(root, "nat_type", err);
	if (nat_type == NULL)
		return -1;

	val32 = nft_str2nat(nat_type);
	if (val32 < 0)
		return -1;

	nft_rule_expr_set_u32(e, NFT_EXPR_NAT_TYPE, val32);

	family_str = nft_jansson_parse_str(root, "family", err);
	if (family_str == NULL)
		return -1;

	val32 = nft_str2family(family_str);
	if (val32 < 0)
		return -1;

	nft_rule_expr_set_u32(e, NFT_EXPR_NAT_FAMILY, val32);

	if (nft_jansson_parse_reg(root, "sreg_addr_min", NFT_TYPE_U32,
				  &reg, err) == 0)
		nft_rule_expr_set_u32(e, NFT_EXPR_NAT_REG_ADDR_MIN, reg);

	if (nft_jansson_parse_reg(root, "sreg_addr_max", NFT_TYPE_U32,
				  &reg, err) == 0)
		nft_rule_expr_set_u32(e, NFT_EXPR_NAT_REG_ADDR_MAX, reg);

	if (nft_jansson_parse_reg(root, "sreg_proto_min", NFT_TYPE_U32,
				  &reg, err) == 0)
		nft_rule_expr_set_u32(e, NFT_EXPR_NAT_REG_PROTO_MIN, reg);

	if (nft_jansson_parse_reg(root, "sreg_proto_max", NFT_TYPE_U32,
				  &reg, err) == 0)
		nft_rule_expr_set_u32(e, NFT_EXPR_NAT_REG_PROTO_MAX, reg);

	if (nft_jansson_parse_val(root, "flags", NFT_TYPE_U32,
				  &flags, err) == 0)
		nft_rule_expr_set_u32(e, NFT_EXPR_NAT_FLAGS, flags);

	return 0;
#else
	errno = EOPNOTSUPP;
	return -1;
#endif
}

static int nft_rule_expr_nat_xml_parse(struct nft_rule_expr *e, mxml_node_t *tree,
				       struct nft_parse_err *err)
{
#ifdef XML_PARSING
	const char *nat_type;
	uint32_t family, nat_type_value, flags;
	uint32_t reg_addr_min, reg_addr_max;
	uint32_t reg_proto_min, reg_proto_max;

	nat_type = nft_mxml_str_parse(tree, "nat_type", MXML_DESCEND_FIRST,
				      NFT_XML_MAND, err);
	if (nat_type == NULL)
		return -1;

	nat_type_value = nft_str2nat(nat_type);
	if (nat_type_value < 0)
		return -1;
	nft_rule_expr_set_u32(e, NFT_EXPR_NAT_TYPE, nat_type_value);

	family = nft_mxml_family_parse(tree, "family", MXML_DESCEND_FIRST,
				       NFT_XML_MAND, err);
	if (family < 0) {
		mxmlDelete(tree);
		return -1;
	}
	nft_rule_expr_set_u32(e, NFT_EXPR_NAT_FAMILY, family);

	if (nft_mxml_reg_parse(tree, "sreg_addr_min", &reg_addr_min,
			       MXML_DESCEND, NFT_XML_MAND, err) == 0)
		nft_rule_expr_set_u32(e, NFT_EXPR_NAT_REG_ADDR_MIN, reg_addr_min);

	if (nft_mxml_reg_parse(tree, "sreg_addr_max", &reg_addr_max,
			       MXML_DESCEND, NFT_XML_MAND, err) == 0)
		nft_rule_expr_set_u32(e, NFT_EXPR_NAT_REG_ADDR_MAX, reg_addr_max);

	if (nft_mxml_reg_parse(tree, "sreg_proto_min", &reg_proto_min,
			       MXML_DESCEND, NFT_XML_MAND, err) == 0)
		nft_rule_expr_set_u32(e, NFT_EXPR_NAT_REG_PROTO_MIN, reg_proto_min);

	if (nft_mxml_reg_parse(tree, "sreg_proto_max", &reg_proto_max,
			       MXML_DESCEND, NFT_XML_MAND, err) == 0)
		nft_rule_expr_set_u32(e, NFT_EXPR_NAT_REG_PROTO_MAX, reg_proto_max);

	if (nft_mxml_num_parse(tree, "flags", MXML_DESCEND, BASE_DEC, &flags,
			       NFT_TYPE_U32, NFT_XML_MAND, err) == 0)
		nft_rule_expr_set_u32(e, NFT_EXPR_NAT_FLAGS, flags);

	return 0;
#else
	errno = EOPNOTSUPP;
	return -1;
#endif
}

static int nft_rule_expr_nat_export(char *buf, size_t size,
				    struct nft_rule_expr *e, int type)
{
	struct nft_expr_nat *nat = nft_expr_data(e);
	NFT_BUF_INIT(b, buf, size);

	if (e->flags & (1 << NFT_EXPR_NAT_TYPE))
		nft_buf_str(&b, type, nat2str(nat->type), NAT_TYPE);
	if (e->flags & (1 << NFT_EXPR_NAT_FAMILY))
		nft_buf_str(&b, type, nft_family2str(nat->family), FAMILY);
	if (e->flags & (1 << NFT_EXPR_NAT_REG_ADDR_MIN))
		nft_buf_u32(&b, type, nat->sreg_addr_min, SREG_ADDR_MIN);
	if (e->flags & (1 << NFT_EXPR_NAT_REG_ADDR_MAX))
		nft_buf_u32(&b, type, nat->sreg_addr_max, SREG_ADDR_MAX);
	if (e->flags & (1 << NFT_EXPR_NAT_REG_PROTO_MIN))
		nft_buf_u32(&b, type, nat->sreg_proto_min, SREG_PROTO_MIN);
	if (e->flags & (1 << NFT_EXPR_NAT_REG_PROTO_MAX))
		nft_buf_u32(&b, type, nat->sreg_proto_max, SREG_PROTO_MAX);
	if (e->flags & (1 << NFT_EXPR_NAT_FLAGS))
		nft_buf_u32(&b, type, nat->flags, FLAGS);

	return nft_buf_done(&b);
}

static int
nft_rule_expr_nat_snprintf_default(char *buf, size_t size,
				   struct nft_rule_expr *e)
{
	struct nft_expr_nat *nat = nft_expr_data(e);
	int len = size, offset = 0, ret = 0;

	ret = snprintf(buf, len, "%s ", nat2str(nat->type));
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	ret = snprintf(buf+offset, len, "%s ", nft_family2str(nat->family));
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	if (e->flags & (1 << NFT_EXPR_NAT_REG_ADDR_MIN)) {
		ret = snprintf(buf+offset, len,
			       "addr_min reg %u addr_max reg %u ",
			       nat->sreg_addr_min, nat->sreg_addr_max);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	if (e->flags & (1 << NFT_EXPR_NAT_REG_PROTO_MIN)) {
		ret = snprintf(buf+offset, len,
			       "proto_min reg %u proto_max reg %u ",
			       nat->sreg_proto_min, nat->sreg_proto_max);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	if (e->flags & (1 << NFT_EXPR_NAT_FLAGS)) {
		ret = snprintf(buf+offset, len, "flags %u", nat->flags);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	return offset;
}

static int
nft_rule_expr_nat_snprintf(char *buf, size_t size, uint32_t type,
			   uint32_t flags, struct nft_rule_expr *e)
{
	switch (type) {
	case NFT_OUTPUT_DEFAULT:
		return nft_rule_expr_nat_snprintf_default(buf, size, e);
	case NFT_OUTPUT_XML:
	case NFT_OUTPUT_JSON:
		return nft_rule_expr_nat_export(buf, size, e, type);
	default:
		break;
	}
	return -1;
}

struct expr_ops expr_ops_nat = {
	.name		= "nat",
	.alloc_len	= sizeof(struct nft_expr_nat),
	.max_attr	= NFTA_NAT_MAX,
	.set		= nft_rule_expr_nat_set,
	.get		= nft_rule_expr_nat_get,
	.parse		= nft_rule_expr_nat_parse,
	.build		= nft_rule_expr_nat_build,
	.snprintf	= nft_rule_expr_nat_snprintf,
	.xml_parse	= nft_rule_expr_nat_xml_parse,
	.json_parse	= nft_rule_expr_nat_json_parse,
};
