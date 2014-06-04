/*
 * (C) 2013 by Pablo Neira Ayuso <pablo@netfilter.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This code has been sponsored by Sophos Astaro <http://www.sophos.com>
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
#include "expr_ops.h"

struct nft_expr_reject {
	uint32_t		type;
	uint8_t			icmp_code;
};

static int nft_rule_expr_reject_set(struct nft_rule_expr *e, uint16_t type,
				    const void *data, uint32_t data_len)
{
	struct nft_expr_reject *reject = nft_expr_data(e);

	switch(type) {
	case NFT_EXPR_REJECT_TYPE:
		reject->type = *((uint32_t *)data);
		break;
	case NFT_EXPR_REJECT_CODE:
		reject->icmp_code = *((uint8_t *)data);
		break;
	default:
		return -1;
	}
	return 0;
}

static const void *
nft_rule_expr_reject_get(const struct nft_rule_expr *e, uint16_t type,
			 uint32_t *data_len)
{
	struct nft_expr_reject *reject = nft_expr_data(e);

	switch(type) {
	case NFT_EXPR_REJECT_TYPE:
		*data_len = sizeof(reject->type);
		return &reject->type;
	case NFT_EXPR_REJECT_CODE:
		*data_len = sizeof(reject->icmp_code);
		return &reject->icmp_code;
	}
	return NULL;
}

static int nft_rule_expr_reject_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, NFTA_REJECT_MAX) < 0)
		return MNL_CB_OK;

	switch(type) {
	case NFTA_REJECT_TYPE:
		if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0) {
			perror("mnl_attr_validate");
			return MNL_CB_ERROR;
		}
		break;
	case NFTA_REJECT_ICMP_CODE:
		if (mnl_attr_validate(attr, MNL_TYPE_U8) < 0) {
			perror("mnl_attr_validate");
			return MNL_CB_ERROR;
		}
		break;
	}

	tb[type] = attr;
	return MNL_CB_OK;
}

static void
nft_rule_expr_reject_build(struct nlmsghdr *nlh, struct nft_rule_expr *e)
{
	struct nft_expr_reject *reject = nft_expr_data(e);

	if (e->flags & (1 << NFT_EXPR_REJECT_TYPE))
		mnl_attr_put_u32(nlh, NFTA_REJECT_TYPE, htonl(reject->type));
	if (e->flags & (1 << NFT_EXPR_REJECT_CODE))
		mnl_attr_put_u8(nlh, NFTA_REJECT_ICMP_CODE, reject->icmp_code);
}

static int
nft_rule_expr_reject_parse(struct nft_rule_expr *e, struct nlattr *attr)
{
	struct nft_expr_reject *reject = nft_expr_data(e);
	struct nlattr *tb[NFTA_REJECT_MAX+1] = {};

	if (mnl_attr_parse_nested(attr, nft_rule_expr_reject_cb, tb) < 0)
		return -1;

	if (tb[NFTA_REJECT_TYPE]) {
		reject->type = ntohl(mnl_attr_get_u32(tb[NFTA_REJECT_TYPE]));
		e->flags |= (1 << NFT_EXPR_REJECT_TYPE);
	}
	if (tb[NFTA_REJECT_ICMP_CODE]) {
		reject->icmp_code = mnl_attr_get_u8(tb[NFTA_REJECT_ICMP_CODE]);
		e->flags |= (1 << NFT_EXPR_REJECT_CODE);
	}

	return 0;
}

static int
nft_rule_expr_reject_json_parse(struct nft_rule_expr *e, json_t *root,
				struct nft_parse_err *err)
{
#ifdef JSON_PARSING
	uint32_t type;
	uint8_t code;

	if (nft_jansson_parse_val(root, "type", NFT_TYPE_U32, &type, err) < 0)
		return -1;

	nft_rule_expr_set_u32(e, NFT_EXPR_REJECT_TYPE, type);

	if (nft_jansson_parse_val(root, "code", NFT_TYPE_U8, &code, err) < 0)
		return -1;

	nft_rule_expr_set_u8(e, NFT_EXPR_REJECT_CODE, code);

	return 0;
#else
	errno = EOPNOTSUPP;
	return -1;
#endif
}

static int
nft_rule_expr_reject_xml_parse(struct nft_rule_expr *e, mxml_node_t *tree,
			       struct nft_parse_err *err)
{
#ifdef XML_PARSING
	uint32_t type;
	uint8_t code;

	if (nft_mxml_num_parse(tree, "type", MXML_DESCEND_FIRST, BASE_DEC,
			       &type, NFT_TYPE_U32, NFT_XML_MAND, err) == 0)
		nft_rule_expr_set_u32(e, NFT_EXPR_REJECT_TYPE, type);

	if (nft_mxml_num_parse(tree, "code", MXML_DESCEND_FIRST, BASE_DEC,
			       &code, NFT_TYPE_U8, NFT_XML_MAND, err) == 0)
		nft_rule_expr_set_u8(e, NFT_EXPR_REJECT_CODE, code);

	return 0;
#else
	errno = EOPNOTSUPP;
	return -1;
#endif
}

static int nft_rule_expr_reject_snprintf_default(char *buf, size_t len,
						 struct nft_rule_expr *e)
{
	struct nft_expr_reject *reject = nft_expr_data(e);

	return snprintf(buf, len, "type %u code %u ",
			reject->type, reject->icmp_code);
}

static int nft_rule_expr_reject_snprintf_xml(char *buf, size_t len,
					     struct nft_rule_expr *e)
{
	int ret, size = len, offset = 0;
	struct nft_expr_reject *reject = nft_expr_data(e);

	if (e->flags & (1 << NFT_EXPR_REJECT_TYPE)) {
		ret = snprintf(buf+offset, len, "<type>%u</type>",
			       reject->type);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}
	if (e->flags & (1 << NFT_EXPR_REJECT_CODE)) {
		ret = snprintf(buf+offset, len, "<code>%u</code>",
			       reject->icmp_code);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	return offset;
}

static int nft_rule_expr_reject_snprintf_json(char *buf, size_t len,
					      struct nft_rule_expr *e)
{
	struct nft_expr_reject *reject = nft_expr_data(e);

	return snprintf(buf, len, "\"type\":%u,"
				  "\"code\":%u,",
			reject->type, reject->icmp_code);
}

static int
nft_rule_expr_reject_snprintf(char *buf, size_t len, uint32_t type,
			      uint32_t flags, struct nft_rule_expr *e)
{
	switch(type) {
	case NFT_OUTPUT_DEFAULT:
		return nft_rule_expr_reject_snprintf_default(buf, len, e);
	case NFT_OUTPUT_XML:
		return nft_rule_expr_reject_snprintf_xml(buf, len, e);
	case NFT_OUTPUT_JSON:
		return nft_rule_expr_reject_snprintf_json(buf, len, e);
	default:
		break;
	}
	return -1;
}

struct expr_ops expr_ops_reject = {
	.name		= "reject",
	.alloc_len	= sizeof(struct nft_expr_reject),
	.max_attr	= NFTA_REJECT_MAX,
	.set		= nft_rule_expr_reject_set,
	.get		= nft_rule_expr_reject_get,
	.parse		= nft_rule_expr_reject_parse,
	.build		= nft_rule_expr_reject_build,
	.snprintf	= nft_rule_expr_reject_snprintf,
	.xml_parse	= nft_rule_expr_reject_xml_parse,
	.json_parse	= nft_rule_expr_reject_json_parse,
};

static void __init expr_reject_init(void)
{
	nft_expr_ops_register(&expr_ops_reject);
}
