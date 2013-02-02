/*
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
#include <arpa/inet.h>
#include <libmnl/libmnl.h>
#include <linux/netfilter/nf_tables.h>
#include <libnftables/expr.h>
#include "expr_ops.h"

struct nft_expr_nat {
	enum nft_registers sreg_addr_min;
	enum nft_registers sreg_addr_max;
	enum nft_registers sreg_proto_min;
	enum nft_registers sreg_proto_max;
	int                family;
	enum nft_nat_types type;
};

static int
nft_rule_expr_nat_set(struct nft_rule_expr *e, uint16_t type,
		      const void *data, size_t data_len)
{
	struct nft_expr_nat *nat = (struct nft_expr_nat *)e->data;

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
	default:
		return -1;
	}

	return 0;
}

static const void *
nft_rule_expr_nat_get(struct nft_rule_expr *e, uint16_t type, size_t *data_len)
{
	struct nft_expr_nat *nat = (struct nft_expr_nat *)e->data;

	switch(type) {
	case NFT_EXPR_NAT_TYPE:
		if (e->flags & (1 << NFT_EXPR_NAT_TYPE)) {
			*data_len = sizeof(nat->type);
			return &nat->type;
		}
		break;
	case NFT_EXPR_NAT_FAMILY:
		if (e->flags & (1 << NFT_EXPR_NAT_FAMILY)) {
			*data_len = sizeof(nat->family);
			return &nat->family;
		}
		break;
	case NFT_EXPR_NAT_REG_ADDR_MIN:
		if (e->flags & (1 << NFT_EXPR_NAT_REG_ADDR_MIN)) {
			*data_len = sizeof(nat->sreg_addr_min);
			return &nat->sreg_addr_min;
		}
		break;
	case NFT_EXPR_NAT_REG_ADDR_MAX:
		if (e->flags & (1 << NFT_EXPR_NAT_REG_ADDR_MAX)) {
			*data_len = sizeof(nat->sreg_addr_max);
			return &nat->sreg_addr_max;
		}
		break;
	case NFT_EXPR_NAT_REG_PROTO_MIN:
		if (e->flags & (1 << NFT_EXPR_NAT_REG_PROTO_MIN)) {
			*data_len = sizeof(nat->sreg_proto_min);
			return &nat->sreg_proto_min;
		}
		break;
	case NFT_EXPR_NAT_REG_PROTO_MAX:
		if (e->flags & (1 << NFT_EXPR_NAT_REG_PROTO_MAX)) {
			*data_len = sizeof(nat->sreg_proto_max);
			return &nat->sreg_proto_max;
		}
		break;
	default:
		break;
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
		if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0) {
			perror("mnl_attr_validate");
			return MNL_CB_ERROR;
		}
		break;
	}

	tb[type] = attr;
	return MNL_CB_OK;
}

static int
nft_rule_expr_nat_parse(struct nft_rule_expr *e, struct nlattr *attr)
{
	struct nft_expr_nat *nat = (struct nft_expr_nat *)e->data;
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

	return 0;
}

static void
nft_rule_expr_nat_build(struct nlmsghdr *nlh, struct nft_rule_expr *e)
{
	struct nft_expr_nat *nat = (struct nft_expr_nat *)e->data;

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
}

static int
nft_rule_expr_nat_snprintf(char *buf, size_t size, uint32_t type,
			   uint32_t flags, struct nft_rule_expr *e)
{
	struct nft_expr_nat *nat = (struct nft_expr_nat *)e->data;
	int len = size, offset = 0, ret = 0;

	switch (nat->type) {
	case NFT_NAT_SNAT:
		ret = snprintf(buf, len, "type=NFT_NAT_SNAT ");
		break;
	case NFT_NAT_DNAT:
		ret = snprintf(buf, len, "type=NFT_NAT_DNAT ");
		break;
	}
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	ret = snprintf(buf, len, "family=%s ",
		       nat->family == AF_INET ? "AF_INET" : "AF_INET6");
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	if (e->flags & (1 << NFT_EXPR_NAT_REG_ADDR_MIN)) {
		ret = snprintf(buf, len,
			       "sreg_addr_min_v4=%u sreg_addr_max_v4=%u ",
			       nat->sreg_addr_min, nat->sreg_addr_max);
	}

	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	if (e->flags & (1 << NFT_EXPR_NAT_REG_PROTO_MIN)) {
		ret = snprintf(buf, len,
			       "sreg_proto_min=%u sreg_proto_max=%u ",
			       nat->sreg_proto_min, nat->sreg_proto_max);
	}
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	return offset;
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
};