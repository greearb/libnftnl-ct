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

#include <libnftables/expr.h>
#include <libnftables/rule.h>

#include "expr_ops.h"

struct nft_expr_payload {
	enum nft_registers	dreg;
	enum nft_payload_bases	base;
	unsigned int		offset;
	unsigned int		len;
};

static int
nft_rule_expr_payload_set(struct nft_rule_expr *e, uint16_t type,
			  const void *data, size_t data_len)
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
			  size_t *data_len)
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

static int
nft_rule_expr_payload_snprintf_json(char *buf, size_t len, uint32_t flags,
				   struct nft_expr_payload *p)
{
	int size = len, offset = 0, ret;

	ret = snprintf(buf, len, "\"dreg\" : %u, "
				 "\"offset\" : %u, "
				 "\"len\" : %u, "
				 "\"base\" : \"%s\"",
		       p->dreg, p->offset, p->len, base2str(p->base));
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	return offset;
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
nft_rule_expr_payload_json_parse(struct nft_rule_expr *e, json_t *root)
{
#ifdef JSON_PARSING
	const char *base_str;
	uint32_t reg, uval32;
	int base;

	if (nft_jansson_parse_reg(root, "dreg", NFT_TYPE_U32, &reg) < 0)
		return -1;

	nft_rule_expr_set_u32(e, NFT_EXPR_PAYLOAD_DREG, reg);

	base_str = nft_jansson_parse_str(root, "base");
	if (base_str == NULL)
		return -1;

	base = nft_str2base(base_str);
	if (base < 0)
		return -1;

	nft_rule_expr_set_u32(e, NFT_EXPR_PAYLOAD_BASE, base);

	if (nft_jansson_parse_val(root, "offset", NFT_TYPE_U32, &uval32) < 0)
		return -1;

	nft_rule_expr_set_u32(e, NFT_EXPR_PAYLOAD_OFFSET, uval32);

	if (nft_jansson_parse_val(root, "len", NFT_TYPE_U32, &uval32) < 0)
		return -1;

	nft_rule_expr_set_u32(e, NFT_EXPR_PAYLOAD_LEN, uval32);

	return 0;
#else
	errno = EOPNOTSUPP;
	return -1;
#endif
}

static int
nft_rule_expr_payload_xml_parse(struct nft_rule_expr *e, mxml_node_t *tree)
{
#ifdef XML_PARSING
	struct nft_expr_payload *payload = nft_expr_data(e);
	const char *base_str;
	int32_t reg, base;

	reg = nft_mxml_reg_parse(tree, "dreg", MXML_DESCEND_FIRST);
	if (reg < 0)
		return -1;

	payload->dreg = reg;
	e->flags |= (1 << NFT_EXPR_PAYLOAD_DREG);

	base_str = nft_mxml_str_parse(tree, "base", MXML_DESCEND_FIRST);
	if (base_str == NULL)
		return -1;

	base = nft_str2base(base_str);
	if (base < 0)
		return -1;

	payload->base = base;
	e->flags |= (1 << NFT_EXPR_PAYLOAD_BASE);

	if (nft_mxml_num_parse(tree, "offset", MXML_DESCEND_FIRST, BASE_DEC,
			       &payload->offset, NFT_TYPE_U8) != 0)
		return -1;

	e->flags |= (1 << NFT_EXPR_PAYLOAD_OFFSET);

	if (nft_mxml_num_parse(tree, "len", MXML_DESCEND_FIRST, BASE_DEC,
			       &payload->len, NFT_TYPE_U8) != 0)
		return -1;

	e->flags |= (1 << NFT_EXPR_PAYLOAD_LEN);
	return 0;
#else
	errno = EOPNOTSUPP;
	return -1;
#endif
}

static int
nft_rule_expr_payload_snprintf_xml(char *buf, size_t len, uint32_t flags,
				   struct nft_expr_payload *p)
{
	int size = len, offset = 0, ret;

	ret = snprintf(buf, len, "<dreg>%u</dreg>"
				 "<offset>%u</offset>"
				 "<len>%u</len>"
				 "<base>%s</base>",
		       p->dreg, p->offset, p->len, base2str(p->base));
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	return offset;
}

static int
nft_rule_expr_payload_snprintf(char *buf, size_t len, uint32_t type,
			       uint32_t flags, struct nft_rule_expr *e)
{
	struct nft_expr_payload *payload = nft_expr_data(e);

	switch(type) {
	case NFT_RULE_O_DEFAULT:
		return snprintf(buf, len, "load %ub @ %s header + %u => reg %u ",
				payload->len, base2str(payload->base),
				payload->offset, payload->dreg);
	case NFT_RULE_O_XML:
		return nft_rule_expr_payload_snprintf_xml(buf, len, flags,
							  payload);
	case NFT_RULE_O_JSON:
		return nft_rule_expr_payload_snprintf_json(buf, len, flags,
							  payload);
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

static void __init expr_payload_init(void)
{
	nft_expr_ops_register(&expr_ops_payload);
}
