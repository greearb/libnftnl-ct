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
#include <limits.h>
#include <arpa/inet.h>
#include <errno.h>
#include <libmnl/libmnl.h>

#include <linux/netfilter/nf_tables.h>

#include <libnftnl/expr.h>
#include <libnftnl/rule.h>

struct nft_expr_payload {
	enum nft_registers	dreg;
	enum nft_payload_bases	base;
	uint32_t		offset;
	uint32_t		len;
};

static int
nft_rule_expr_payload_set(struct nft_rule_expr *e, uint16_t type,
			  const void *data, uint32_t data_len)
{
	struct nft_expr_payload *payload = nft_expr_data(e);

	switch(type) {
	case NFT_EXPR_PAYLOAD_DREG:
		payload->dreg = *((uint32_t *)data);
		break;
	case NFT_EXPR_PAYLOAD_BASE:
		payload->base = *((uint32_t *)data);
		break;
	case NFT_EXPR_PAYLOAD_OFFSET:
		payload->offset = *((unsigned int *)data);
		break;
	case NFT_EXPR_PAYLOAD_LEN:
		payload->len = *((unsigned int *)data);
		break;
	default:
		return -1;
	}
	return 0;
}

static const void *
nft_rule_expr_payload_get(const struct nft_rule_expr *e, uint16_t type,
			  uint32_t *data_len)
{
	struct nft_expr_payload *payload = nft_expr_data(e);

	switch(type) {
	case NFT_EXPR_PAYLOAD_DREG:
		*data_len = sizeof(payload->dreg);
		return &payload->dreg;
	case NFT_EXPR_PAYLOAD_BASE:
		*data_len = sizeof(payload->base);
		return &payload->base;
	case NFT_EXPR_PAYLOAD_OFFSET:
		*data_len = sizeof(payload->offset);
		return &payload->offset;
	case NFT_EXPR_PAYLOAD_LEN:
		*data_len = sizeof(payload->len);
		return &payload->len;
	}
	return NULL;
}

static int nft_rule_expr_payload_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, NFTA_PAYLOAD_MAX) < 0)
		return MNL_CB_OK;

	switch(type) {
	case NFTA_PAYLOAD_DREG:
	case NFTA_PAYLOAD_BASE:
	case NFTA_PAYLOAD_OFFSET:
	case NFTA_PAYLOAD_LEN:
		if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0)
			abi_breakage();
		break;
	}

	tb[type] = attr;
	return MNL_CB_OK;
}

static void
nft_rule_expr_payload_build(struct nlmsghdr *nlh, struct nft_rule_expr *e)
{
	struct nft_expr_payload *payload = nft_expr_data(e);

	if (e->flags & (1 << NFT_EXPR_PAYLOAD_DREG))
		mnl_attr_put_u32(nlh, NFTA_PAYLOAD_DREG, htonl(payload->dreg));
	if (e->flags & (1 << NFT_EXPR_PAYLOAD_BASE))
		mnl_attr_put_u32(nlh, NFTA_PAYLOAD_BASE, htonl(payload->base));
	if (e->flags & (1 << NFT_EXPR_PAYLOAD_OFFSET))
		mnl_attr_put_u32(nlh, NFTA_PAYLOAD_OFFSET, htonl(payload->offset));
	if (e->flags & (1 << NFT_EXPR_PAYLOAD_LEN))
		mnl_attr_put_u32(nlh, NFTA_PAYLOAD_LEN, htonl(payload->len));
}

static int
nft_rule_expr_payload_parse(struct nft_rule_expr *e, struct nlattr *attr)
{
	struct nft_expr_payload *payload = nft_expr_data(e);
	struct nlattr *tb[NFTA_PAYLOAD_MAX+1] = {};

	if (mnl_attr_parse_nested(attr, nft_rule_expr_payload_cb, tb) < 0)
		return -1;

	if (tb[NFTA_PAYLOAD_DREG]) {
		payload->dreg = ntohl(mnl_attr_get_u32(tb[NFTA_PAYLOAD_DREG]));
		e->flags |= (1 << NFT_EXPR_PAYLOAD_DREG);
	}
	if (tb[NFTA_PAYLOAD_BASE]) {
		payload->base = ntohl(mnl_attr_get_u32(tb[NFTA_PAYLOAD_BASE]));
		e->flags |= (1 << NFT_EXPR_PAYLOAD_BASE);
	}
	if (tb[NFTA_PAYLOAD_OFFSET]) {
		payload->offset = ntohl(mnl_attr_get_u32(tb[NFTA_PAYLOAD_OFFSET]));
		e->flags |= (1 << NFT_EXPR_PAYLOAD_OFFSET);
	}
	if (tb[NFTA_PAYLOAD_LEN]) {
		payload->len = ntohl(mnl_attr_get_u32(tb[NFTA_PAYLOAD_LEN]));
		e->flags |= (1 << NFT_EXPR_PAYLOAD_LEN);
	}

	return 0;
}

static char *base2str_array[NFT_PAYLOAD_TRANSPORT_HEADER+1] = {
	[NFT_PAYLOAD_LL_HEADER]		= "link",
	[NFT_PAYLOAD_NETWORK_HEADER] 	= "network",
	[NFT_PAYLOAD_TRANSPORT_HEADER]	= "transport",
};

static const char *base2str(enum nft_payload_bases base)
{
	if (base > NFT_PAYLOAD_TRANSPORT_HEADER)
		return "unknown";

	return base2str_array[base];
}

static inline int nft_str2base(const char *base)
{
	if (strcmp(base, "link") == 0)
		return NFT_PAYLOAD_LL_HEADER;
	else if (strcmp(base, "network") == 0)
		return NFT_PAYLOAD_NETWORK_HEADER;
	else if (strcmp(base, "transport") == 0)
		return NFT_PAYLOAD_TRANSPORT_HEADER;
	else {
		errno = EINVAL;
		return -1;
	}
}

static int
nft_rule_expr_payload_json_parse(struct nft_rule_expr *e, json_t *root,
				 struct nft_parse_err *err)
{
#ifdef JSON_PARSING
	const char *base_str;
	uint32_t reg, uval32;
	int base;

	if (nft_jansson_parse_reg(root, "dreg", NFT_TYPE_U32, &reg, err) == 0)
		nft_rule_expr_set_u32(e, NFT_EXPR_PAYLOAD_DREG, reg);

	base_str = nft_jansson_parse_str(root, "base", err);
	if (base_str != NULL) {
		base = nft_str2base(base_str);
		if (base < 0)
			return -1;

		nft_rule_expr_set_u32(e, NFT_EXPR_PAYLOAD_BASE, base);
	}

	if (nft_jansson_parse_val(root, "offset", NFT_TYPE_U32, &uval32,
				  err) == 0)
		nft_rule_expr_set_u32(e, NFT_EXPR_PAYLOAD_OFFSET, uval32);

	if (nft_jansson_parse_val(root, "len", NFT_TYPE_U32, &uval32, err) == 0)
		nft_rule_expr_set_u32(e, NFT_EXPR_PAYLOAD_LEN, uval32);

	return 0;
#else
	errno = EOPNOTSUPP;
	return -1;
#endif
}

static int
nft_rule_expr_payload_xml_parse(struct nft_rule_expr *e, mxml_node_t *tree,
				struct nft_parse_err *err)
{
#ifdef XML_PARSING
	const char *base_str;
	int32_t base;
	uint32_t dreg, offset, len;

	if (nft_mxml_reg_parse(tree, "dreg", &dreg, MXML_DESCEND_FIRST,
			       NFT_XML_MAND, err) == 0)
		nft_rule_expr_set_u32(e, NFT_EXPR_PAYLOAD_DREG, dreg);

	base_str = nft_mxml_str_parse(tree, "base", MXML_DESCEND_FIRST,
				      NFT_XML_MAND, err);
	if (base_str != NULL) {
		base = nft_str2base(base_str);
		if (base < 0)
			return -1;

		nft_rule_expr_set_u32(e, NFT_EXPR_PAYLOAD_BASE, base);
	}

	if (nft_mxml_num_parse(tree, "offset", MXML_DESCEND_FIRST, BASE_DEC,
			       &offset, NFT_TYPE_U32, NFT_XML_MAND, err) == 0)
		nft_rule_expr_set_u32(e, NFT_EXPR_PAYLOAD_OFFSET, offset);


	if (nft_mxml_num_parse(tree, "len", MXML_DESCEND_FIRST, BASE_DEC,
			       &len, NFT_TYPE_U32, NFT_XML_MAND, err) == 0)
		nft_rule_expr_set_u32(e, NFT_EXPR_PAYLOAD_LEN, len);

	return 0;
#else
	errno = EOPNOTSUPP;
	return -1;
#endif
}

static int nft_rule_expr_payload_export(char *buf, size_t size, uint32_t flags,
					struct nft_rule_expr *e, int type)
{
	struct nft_expr_payload *payload = nft_expr_data(e);
	NFT_BUF_INIT(b, buf, size);

	if (e->flags & (1 << NFT_EXPR_PAYLOAD_DREG))
		nft_buf_u32(&b, type, payload->dreg, DREG);
	if (e->flags & (1 << NFT_EXPR_PAYLOAD_OFFSET))
		nft_buf_u32(&b, type, payload->offset, OFFSET);
	if (e->flags & (1 << NFT_EXPR_PAYLOAD_LEN))
		nft_buf_u32(&b, type, payload->len, LEN);
	if (e->flags & (1 << NFT_EXPR_PAYLOAD_BASE))
		nft_buf_str(&b, type, base2str(payload->base), BASE);

	return nft_buf_done(&b);
}

static int
nft_rule_expr_payload_snprintf(char *buf, size_t len, uint32_t type,
			       uint32_t flags, struct nft_rule_expr *e)
{
	struct nft_expr_payload *payload = nft_expr_data(e);

	switch (type) {
	case NFT_OUTPUT_DEFAULT:
		return snprintf(buf, len, "load %ub @ %s header + %u => reg %u ",
				payload->len, base2str(payload->base),
				payload->offset, payload->dreg);
	case NFT_OUTPUT_XML:
	case NFT_OUTPUT_JSON:
		return nft_rule_expr_payload_export(buf, len, flags, e, type);
	default:
		break;
	}
	return -1;
}

struct expr_ops expr_ops_payload = {
	.name		= "payload",
	.alloc_len	= sizeof(struct nft_expr_payload),
	.max_attr	= NFTA_PAYLOAD_MAX,
	.set		= nft_rule_expr_payload_set,
	.get		= nft_rule_expr_payload_get,
	.parse		= nft_rule_expr_payload_parse,
	.build		= nft_rule_expr_payload_build,
	.snprintf	= nft_rule_expr_payload_snprintf,
	.xml_parse	= nft_rule_expr_payload_xml_parse,
	.json_parse	= nft_rule_expr_payload_json_parse,
};
