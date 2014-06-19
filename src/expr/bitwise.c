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
#include <string.h> /* for memcpy */
#include <arpa/inet.h>
#include <errno.h>
#include <libmnl/libmnl.h>
#include <linux/netfilter/nf_tables.h>
#include <libnftnl/expr.h>
#include <libnftnl/rule.h>
#include "data_reg.h"
#include "expr_ops.h"

struct nft_expr_bitwise {
	enum nft_registers	sreg;
	enum nft_registers	dreg;
	unsigned int		len;
	union nft_data_reg	mask;
	union nft_data_reg	xor;
};

static int
nft_rule_expr_bitwise_set(struct nft_rule_expr *e, uint16_t type,
			  const void *data, uint32_t data_len)
{
	struct nft_expr_bitwise *bitwise = nft_expr_data(e);

	switch(type) {
	case NFT_EXPR_BITWISE_SREG:
		bitwise->sreg = *((uint32_t *)data);
		break;
	case NFT_EXPR_BITWISE_DREG:
		bitwise->dreg = *((uint32_t *)data);
		break;
	case NFT_EXPR_BITWISE_LEN:
		bitwise->len = *((unsigned int *)data);
		break;
	case NFT_EXPR_BITWISE_MASK:
		memcpy(&bitwise->mask.val, data, data_len);
		bitwise->mask.len = data_len;
		break;
	case NFT_EXPR_BITWISE_XOR:
		memcpy(&bitwise->xor.val, data, data_len);
		bitwise->xor.len = data_len;
		break;
	default:
		return -1;
	}
	return 0;
}

static const void *
nft_rule_expr_bitwise_get(const struct nft_rule_expr *e, uint16_t type,
			  uint32_t *data_len)
{
	struct nft_expr_bitwise *bitwise = nft_expr_data(e);

	switch(type) {
	case NFT_EXPR_BITWISE_SREG:
		*data_len = sizeof(bitwise->sreg);
		return &bitwise->sreg;
	case NFT_EXPR_BITWISE_DREG:
		*data_len = sizeof(bitwise->dreg);
		return &bitwise->dreg;
	case NFT_EXPR_BITWISE_LEN:
		*data_len = sizeof(bitwise->len);
		return &bitwise->len;
	case NFT_EXPR_BITWISE_MASK:
		*data_len = bitwise->mask.len;
		return &bitwise->mask.val;
	case NFT_EXPR_BITWISE_XOR:
		*data_len = bitwise->xor.len;
		return &bitwise->xor.val;
	}
	return NULL;
}

static int nft_rule_expr_bitwise_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, NFTA_BITWISE_MAX) < 0)
		return MNL_CB_OK;

	switch(type) {
	case NFTA_BITWISE_SREG:
	case NFTA_BITWISE_DREG:
	case NFTA_BITWISE_LEN:
		if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0) {
			perror("mnl_attr_validate");
			return MNL_CB_ERROR;
		}
		break;
	case NFTA_BITWISE_MASK:
	case NFTA_BITWISE_XOR:
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
nft_rule_expr_bitwise_build(struct nlmsghdr *nlh, struct nft_rule_expr *e)
{
	struct nft_expr_bitwise *bitwise = nft_expr_data(e);

	if (e->flags & (1 << NFT_EXPR_BITWISE_SREG))
		mnl_attr_put_u32(nlh, NFTA_BITWISE_SREG, htonl(bitwise->sreg));
	if (e->flags & (1 << NFT_EXPR_BITWISE_DREG))
		mnl_attr_put_u32(nlh, NFTA_BITWISE_DREG, htonl(bitwise->dreg));
	if (e->flags & (1 << NFT_EXPR_BITWISE_LEN))
		mnl_attr_put_u32(nlh, NFTA_BITWISE_LEN, htonl(bitwise->len));
	if (e->flags & (1 << NFT_EXPR_BITWISE_MASK)) {
		struct nlattr *nest;

		nest = mnl_attr_nest_start(nlh, NFTA_BITWISE_MASK);
		mnl_attr_put(nlh, NFTA_DATA_VALUE, bitwise->mask.len,
				bitwise->mask.val);
		mnl_attr_nest_end(nlh, nest);
	}
	if (e->flags & (1 << NFT_EXPR_BITWISE_XOR)) {
		struct nlattr *nest;

		nest = mnl_attr_nest_start(nlh, NFTA_BITWISE_XOR);
		mnl_attr_put(nlh, NFTA_DATA_VALUE, bitwise->xor.len,
				bitwise->xor.val);
		mnl_attr_nest_end(nlh, nest);
	}
}

static int
nft_rule_expr_bitwise_parse(struct nft_rule_expr *e, struct nlattr *attr)
{
	struct nft_expr_bitwise *bitwise = nft_expr_data(e);
	struct nlattr *tb[NFTA_BITWISE_MAX+1] = {};
	int ret = 0;

	if (mnl_attr_parse_nested(attr, nft_rule_expr_bitwise_cb, tb) < 0)
		return -1;

	if (tb[NFTA_BITWISE_SREG]) {
		bitwise->sreg = ntohl(mnl_attr_get_u32(tb[NFTA_BITWISE_SREG]));
		e->flags |= (1 << NFT_EXPR_BITWISE_SREG);
	}
	if (tb[NFTA_BITWISE_DREG]) {
		bitwise->dreg = ntohl(mnl_attr_get_u32(tb[NFTA_BITWISE_DREG]));
		e->flags |= (1 << NFT_EXPR_BITWISE_DREG);
	}
	if (tb[NFTA_BITWISE_LEN]) {
		bitwise->len = ntohl(mnl_attr_get_u32(tb[NFTA_BITWISE_LEN]));
		e->flags |= (1 << NFT_EXPR_BITWISE_LEN);
	}
	if (tb[NFTA_BITWISE_MASK]) {
		ret = nft_parse_data(&bitwise->mask, tb[NFTA_BITWISE_MASK], NULL);
		e->flags |= (1 << NFTA_BITWISE_MASK);
	}
	if (tb[NFTA_BITWISE_XOR]) {
		ret = nft_parse_data(&bitwise->xor, tb[NFTA_BITWISE_XOR], NULL);
		e->flags |= (1 << NFTA_BITWISE_XOR);
	}

	return ret;
}

static int
nft_rule_expr_bitwise_json_parse(struct nft_rule_expr *e, json_t *root,
				 struct nft_parse_err *err)
{
#ifdef JSON_PARSING
	struct nft_expr_bitwise *bitwise = nft_expr_data(e);
	uint32_t reg, len;

	if (nft_jansson_parse_reg(root, "sreg", NFT_TYPE_U32, &reg, err) == 0)
		nft_rule_expr_set_u32(e, NFT_EXPR_BITWISE_SREG, reg);

	if (nft_jansson_parse_reg(root, "dreg", NFT_TYPE_U32, &reg, err) == 0)
		nft_rule_expr_set_u32(e, NFT_EXPR_BITWISE_DREG, reg);

	if (nft_jansson_parse_val(root, "len", NFT_TYPE_U32, &len, err) == 0)
		nft_rule_expr_set_u32(e, NFT_EXPR_BITWISE_LEN, len);

	if (nft_jansson_data_reg_parse(root, "mask", &bitwise->mask,
				       err) == DATA_VALUE)
		e->flags |= (1 << NFT_EXPR_BITWISE_MASK);

	if (nft_jansson_data_reg_parse(root, "xor", &bitwise->xor,
				       err) == DATA_VALUE)
		e->flags |= (1 << NFT_EXPR_BITWISE_XOR);

	if (bitwise->mask.len != bitwise->xor.len)
		return -1;

	return 0;
#else
	errno = EOPNOTSUPP;
	return -1;
#endif
}

static int
nft_rule_expr_bitwise_xml_parse(struct nft_rule_expr *e, mxml_node_t *tree,
				struct nft_parse_err *err)
{
#ifdef XML_PARSING
	struct nft_expr_bitwise *bitwise = nft_expr_data(e);
	uint32_t sreg, dreg, len;

	if (nft_mxml_reg_parse(tree, "sreg", &sreg, MXML_DESCEND_FIRST,
			       NFT_XML_MAND, err) == 0)
		nft_rule_expr_set_u32(e, NFT_EXPR_BITWISE_SREG, sreg);

	if (nft_mxml_reg_parse(tree, "dreg", &dreg, MXML_DESCEND_FIRST,
			       NFT_XML_MAND, err) == 0)
		nft_rule_expr_set_u32(e, NFT_EXPR_BITWISE_DREG, dreg);

	if (nft_mxml_num_parse(tree, "len", MXML_DESCEND_FIRST, BASE_DEC,
			       &len, NFT_TYPE_U32, NFT_XML_MAND, err) == 0)
		nft_rule_expr_set_u32(e, NFT_EXPR_BITWISE_LEN, len);

	if (nft_mxml_data_reg_parse(tree, "mask", &bitwise->mask, NFT_XML_MAND,
				    err) == DATA_VALUE)
		e->flags |= (1 << NFT_EXPR_BITWISE_MASK);

	if (nft_mxml_data_reg_parse(tree, "xor", &bitwise->xor, NFT_XML_MAND,
				    err) == DATA_VALUE)
		e->flags |= (1 << NFT_EXPR_BITWISE_XOR);

	/* Additional validation: mask and xor must use the same number of
	 * data registers.
	 */
	if (bitwise->mask.len != bitwise->xor.len)
		return -1;

	return 0;
#else
	errno = EOPNOTSUPP;
	return -1;
#endif
}

static int nft_rule_expr_bitwise_snprintf_json(char *buf, size_t size,
					       struct nft_rule_expr *e)
{
	int len = size, offset = 0, ret;
	struct nft_expr_bitwise *bitwise = nft_expr_data(e);

	if (e->flags & (1 << NFT_EXPR_BITWISE_SREG)) {
		ret = snprintf(buf + offset, len, "\"sreg\":%u,",
			       bitwise->sreg);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}
	if (e->flags & (1 << NFT_EXPR_BITWISE_DREG)) {
		ret = snprintf(buf + offset, len, "\"dreg\":%u,",
			       bitwise->dreg);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}
	if (e->flags & (1 << NFT_EXPR_BITWISE_LEN)) {
		ret = snprintf(buf + offset, len, "\"len\":%u,",
			       bitwise->len);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}
	if (e->flags & (1 << NFT_EXPR_BITWISE_MASK)) {
		ret = snprintf(buf + offset, len, "\"mask\":{");
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

		ret = nft_data_reg_snprintf(buf+offset, len, &bitwise->mask,
					    NFT_OUTPUT_JSON, 0, DATA_VALUE);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

		ret = snprintf(buf + offset, len, "},");
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	}
	if (e->flags & (1 << NFT_EXPR_BITWISE_XOR)) {
		ret = snprintf(buf+offset, len, "\"xor\":{");
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

		ret = nft_data_reg_snprintf(buf+offset, len, &bitwise->xor,
					    NFT_OUTPUT_JSON, 0, DATA_VALUE);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

		ret = snprintf(buf+offset, len, "},");
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	if (offset > 0)
		offset--;

	return offset;
}

static int nft_rule_expr_bitwise_snprintf_xml(char *buf, size_t size,
					      struct nft_rule_expr *e)
{
	struct nft_expr_bitwise *bitwise = nft_expr_data(e);
	int len = size, offset = 0, ret;

	if (e->flags & (1 << NFT_EXPR_BITWISE_SREG)) {
		ret = snprintf(buf + offset, len, "<sreg>%u</sreg>",
			       bitwise->sreg);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}
	if (e->flags & (1 << NFT_EXPR_BITWISE_DREG)) {
		ret = snprintf(buf + offset, len, "<dreg>%u</dreg>",
			       bitwise->dreg);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}
	if (e->flags & (1 << NFT_EXPR_BITWISE_LEN)) {
		ret = snprintf(buf + offset, len, "<len>%u</len>",
			       bitwise->len);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}
	if (e->flags & (1 << NFT_EXPR_BITWISE_MASK)) {
		ret = snprintf(buf + offset, len, "<mask>");
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

		ret = nft_data_reg_snprintf(buf + offset, len, &bitwise->mask,
					    NFT_OUTPUT_XML, 0, DATA_VALUE);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

		ret = snprintf(buf + offset, len, "</mask>");
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}
	if (e->flags & (1 << NFT_EXPR_BITWISE_XOR)) {
		ret = snprintf(buf + offset, len, "<xor>");
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

		ret = nft_data_reg_snprintf(buf + offset, len, &bitwise->xor,
					    NFT_OUTPUT_XML, 0, DATA_VALUE);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

		ret = snprintf(buf + offset, len, "</xor>");
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	return offset;
}

static int nft_rule_expr_bitwise_snprintf_default(char *buf, size_t size,
						  struct nft_rule_expr *e)
{
	struct nft_expr_bitwise *bitwise = nft_expr_data(e);
	int len = size, offset = 0, ret;

	ret = snprintf(buf, len, "reg %u = (reg=%u & ",
		       bitwise->dreg, bitwise->sreg);
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	ret = nft_data_reg_snprintf(buf+offset, len, &bitwise->mask,
				    NFT_OUTPUT_DEFAULT, 0, DATA_VALUE);
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	ret = snprintf(buf+offset, len, ") ^ ");
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	ret = nft_data_reg_snprintf(buf+offset, len, &bitwise->xor,
				    NFT_OUTPUT_DEFAULT, 0, DATA_VALUE);
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	return offset;
}

static int
nft_rule_expr_bitwise_snprintf(char *buf, size_t size, uint32_t type,
			       uint32_t flags, struct nft_rule_expr *e)
{
	switch(type) {
	case NFT_OUTPUT_DEFAULT:
		return nft_rule_expr_bitwise_snprintf_default(buf, size, e);
	case NFT_OUTPUT_XML:
		return nft_rule_expr_bitwise_snprintf_xml(buf, size, e);
	case NFT_OUTPUT_JSON:
		return nft_rule_expr_bitwise_snprintf_json(buf, size, e);
	default:
		break;
	}
	return -1;
}

struct expr_ops expr_ops_bitwise = {
	.name		= "bitwise",
	.alloc_len	= sizeof(struct nft_expr_bitwise),
	.max_attr	= NFTA_BITWISE_MAX,
	.set		= nft_rule_expr_bitwise_set,
	.get		= nft_rule_expr_bitwise_get,
	.parse		= nft_rule_expr_bitwise_parse,
	.build		= nft_rule_expr_bitwise_build,
	.snprintf	= nft_rule_expr_bitwise_snprintf,
	.xml_parse	= nft_rule_expr_bitwise_xml_parse,
	.json_parse	= nft_rule_expr_bitwise_json_parse,
};

static void __init expr_bitwise(void)
{
	nft_expr_ops_register(&expr_ops_bitwise);
}
