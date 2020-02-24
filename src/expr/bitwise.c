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

struct nftnl_expr_bitwise {
	enum nft_registers	sreg;
	enum nft_registers	dreg;
	enum nft_bitwise_ops	op;
	unsigned int		len;
	union nftnl_data_reg	mask;
	union nftnl_data_reg	xor;
	union nftnl_data_reg	data;
	enum nft_registers	mreg;
	enum nft_registers	xreg;
};

static int
nftnl_expr_bitwise_set(struct nftnl_expr *e, uint16_t type,
		       const void *data, uint32_t data_len)
{
	struct nftnl_expr_bitwise *bitwise = nftnl_expr_data(e);

	switch(type) {
	case NFTNL_EXPR_BITWISE_SREG:
		memcpy(&bitwise->sreg, data, sizeof(bitwise->sreg));
		break;
	case NFTNL_EXPR_BITWISE_DREG:
		memcpy(&bitwise->dreg, data, sizeof(bitwise->dreg));
		break;
	case NFTNL_EXPR_BITWISE_OP:
		memcpy(&bitwise->op, data, sizeof(bitwise->op));
		break;
	case NFTNL_EXPR_BITWISE_LEN:
		memcpy(&bitwise->len, data, sizeof(bitwise->len));
		break;
	case NFTNL_EXPR_BITWISE_MASK:
		if (e->flags & (1 << NFTNL_EXPR_BITWISE_MREG))
			return -1;
		memcpy(&bitwise->mask.val, data, data_len);
		bitwise->mask.len = data_len;
		break;
	case NFTNL_EXPR_BITWISE_XOR:
		if (e->flags & (1 << NFTNL_EXPR_BITWISE_XREG))
			return -1;
		memcpy(&bitwise->xor.val, data, data_len);
		bitwise->xor.len = data_len;
		break;
	case NFTNL_EXPR_BITWISE_DATA:
		memcpy(&bitwise->data.val, data, data_len);
		bitwise->data.len = data_len;
		break;
	case NFTNL_EXPR_BITWISE_MREG:
		if (e->flags & (1 << NFTNL_EXPR_BITWISE_MASK))
			return -1;
		memcpy(&bitwise->mreg, data, sizeof(bitwise->mreg));
		break;
	case NFTNL_EXPR_BITWISE_XREG:
		if (e->flags & (1 << NFTNL_EXPR_BITWISE_XOR))
			return -1;
		memcpy(&bitwise->xreg, data, sizeof(bitwise->xreg));
		break;
	default:
		return -1;
	}
	return 0;
}

static const void *
nftnl_expr_bitwise_get(const struct nftnl_expr *e, uint16_t type,
		       uint32_t *data_len)
{
	struct nftnl_expr_bitwise *bitwise = nftnl_expr_data(e);

	switch(type) {
	case NFTNL_EXPR_BITWISE_SREG:
		*data_len = sizeof(bitwise->sreg);
		return &bitwise->sreg;
	case NFTNL_EXPR_BITWISE_DREG:
		*data_len = sizeof(bitwise->dreg);
		return &bitwise->dreg;
	case NFTNL_EXPR_BITWISE_OP:
		*data_len = sizeof(bitwise->op);
		return &bitwise->op;
	case NFTNL_EXPR_BITWISE_LEN:
		*data_len = sizeof(bitwise->len);
		return &bitwise->len;
	case NFTNL_EXPR_BITWISE_MASK:
		*data_len = bitwise->mask.len;
		return &bitwise->mask.val;
	case NFTNL_EXPR_BITWISE_XOR:
		*data_len = bitwise->xor.len;
		return &bitwise->xor.val;
	case NFTNL_EXPR_BITWISE_DATA:
		*data_len = bitwise->data.len;
		return &bitwise->data.val;
	case NFTNL_EXPR_BITWISE_MREG:
		*data_len = sizeof(bitwise->mreg);
		return &bitwise->mreg;
	case NFTNL_EXPR_BITWISE_XREG:
		*data_len = sizeof(bitwise->xreg);
		return &bitwise->xreg;
	}
	return NULL;
}

static int nftnl_expr_bitwise_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, NFTA_BITWISE_MAX) < 0)
		return MNL_CB_OK;

	switch(type) {
	case NFTA_BITWISE_SREG:
	case NFTA_BITWISE_DREG:
	case NFTA_BITWISE_OP:
	case NFTA_BITWISE_LEN:
	case NFTA_BITWISE_MREG:
	case NFTA_BITWISE_XREG:
		if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0)
			abi_breakage();
		break;
	case NFTA_BITWISE_MASK:
	case NFTA_BITWISE_XOR:
	case NFTA_BITWISE_DATA:
		if (mnl_attr_validate(attr, MNL_TYPE_BINARY) < 0)
			abi_breakage();
		break;
	}

	tb[type] = attr;
	return MNL_CB_OK;
}

static void
nftnl_expr_bitwise_build(struct nlmsghdr *nlh, const struct nftnl_expr *e)
{
	struct nftnl_expr_bitwise *bitwise = nftnl_expr_data(e);

	if (e->flags & (1 << NFTNL_EXPR_BITWISE_SREG))
		mnl_attr_put_u32(nlh, NFTA_BITWISE_SREG, htonl(bitwise->sreg));
	if (e->flags & (1 << NFTNL_EXPR_BITWISE_DREG))
		mnl_attr_put_u32(nlh, NFTA_BITWISE_DREG, htonl(bitwise->dreg));
	if (e->flags & (1 << NFTNL_EXPR_BITWISE_OP))
		mnl_attr_put_u32(nlh, NFTA_BITWISE_OP, htonl(bitwise->op));
	if (e->flags & (1 << NFTNL_EXPR_BITWISE_LEN))
		mnl_attr_put_u32(nlh, NFTA_BITWISE_LEN, htonl(bitwise->len));
	if (e->flags & (1 << NFTNL_EXPR_BITWISE_MASK)) {
		struct nlattr *nest;

		nest = mnl_attr_nest_start(nlh, NFTA_BITWISE_MASK);
		mnl_attr_put(nlh, NFTA_DATA_VALUE, bitwise->mask.len,
			     bitwise->mask.val);
		mnl_attr_nest_end(nlh, nest);
	}
	if (e->flags & (1 << NFTNL_EXPR_BITWISE_XOR)) {
		struct nlattr *nest;

		nest = mnl_attr_nest_start(nlh, NFTA_BITWISE_XOR);
		mnl_attr_put(nlh, NFTA_DATA_VALUE, bitwise->xor.len,
			     bitwise->xor.val);
		mnl_attr_nest_end(nlh, nest);
	}
	if (e->flags & (1 << NFTNL_EXPR_BITWISE_DATA)) {
		struct nlattr *nest;

		nest = mnl_attr_nest_start(nlh, NFTA_BITWISE_DATA);
		mnl_attr_put(nlh, NFTA_DATA_VALUE, bitwise->data.len,
				bitwise->data.val);
		mnl_attr_nest_end(nlh, nest);
	}
	if (e->flags & (1 << NFTNL_EXPR_BITWISE_MREG))
		mnl_attr_put_u32(nlh, NFTA_BITWISE_MREG, htonl(bitwise->mreg));
	if (e->flags & (1 << NFTNL_EXPR_BITWISE_XREG))
		mnl_attr_put_u32(nlh, NFTA_BITWISE_XREG, htonl(bitwise->xreg));
}

static int
nftnl_expr_bitwise_parse(struct nftnl_expr *e, struct nlattr *attr)
{
	struct nftnl_expr_bitwise *bitwise = nftnl_expr_data(e);
	struct nlattr *tb[NFTA_BITWISE_MAX+1] = {};
	int ret = 0;

	if (mnl_attr_parse_nested(attr, nftnl_expr_bitwise_cb, tb) < 0)
		return -1;

	if (tb[NFTA_BITWISE_SREG]) {
		bitwise->sreg = ntohl(mnl_attr_get_u32(tb[NFTA_BITWISE_SREG]));
		e->flags |= (1 << NFTNL_EXPR_BITWISE_SREG);
	}
	if (tb[NFTA_BITWISE_DREG]) {
		bitwise->dreg = ntohl(mnl_attr_get_u32(tb[NFTA_BITWISE_DREG]));
		e->flags |= (1 << NFTNL_EXPR_BITWISE_DREG);
	}
	if (tb[NFTA_BITWISE_OP]) {
		bitwise->op = ntohl(mnl_attr_get_u32(tb[NFTA_BITWISE_OP]));
		e->flags |= (1 << NFTNL_EXPR_BITWISE_OP);
	}
	if (tb[NFTA_BITWISE_LEN]) {
		bitwise->len = ntohl(mnl_attr_get_u32(tb[NFTA_BITWISE_LEN]));
		e->flags |= (1 << NFTNL_EXPR_BITWISE_LEN);
	}
	if (tb[NFTA_BITWISE_MASK]) {
		ret = nftnl_parse_data(&bitwise->mask, tb[NFTA_BITWISE_MASK], NULL);
		e->flags |= (1 << NFTA_BITWISE_MASK);
	}
	if (tb[NFTA_BITWISE_XOR]) {
		ret = nftnl_parse_data(&bitwise->xor, tb[NFTA_BITWISE_XOR], NULL);
		e->flags |= (1 << NFTA_BITWISE_XOR);
	}
	if (tb[NFTA_BITWISE_DATA]) {
		ret = nftnl_parse_data(&bitwise->data, tb[NFTA_BITWISE_DATA], NULL);
		e->flags |= (1 << NFTNL_EXPR_BITWISE_DATA);
	}
	if (tb[NFTA_BITWISE_MREG]) {
		bitwise->mreg = ntohl(mnl_attr_get_u32(tb[NFTA_BITWISE_MREG]));
		e->flags |= (1 << NFTNL_EXPR_BITWISE_MREG);
	}
	if (tb[NFTA_BITWISE_XREG]) {
		bitwise->xreg = ntohl(mnl_attr_get_u32(tb[NFTA_BITWISE_XREG]));
		e->flags |= (1 << NFTNL_EXPR_BITWISE_XREG);
	}

	return ret;
}

static int
nftnl_expr_bitwise_snprintf_bool(char *buf, size_t size,
				 const struct nftnl_expr_bitwise *bitwise,
				 uint32_t flags)
{
	int remain = size, offset = 0, ret;

	ret = snprintf(buf, remain, "reg %u = (reg=%u & ",
		       bitwise->dreg, bitwise->sreg);
	SNPRINTF_BUFFER_SIZE(ret, remain, offset);

	if (flags & (1 << NFTA_BITWISE_MASK))
		ret = nftnl_data_reg_snprintf(buf + offset, remain,
					      &bitwise->mask,
					      NFTNL_OUTPUT_DEFAULT, 0,
					      DATA_VALUE);
	else
		ret = snprintf(buf + offset, remain, "reg %u ", bitwise->mreg);
	SNPRINTF_BUFFER_SIZE(ret, remain, offset);

	ret = snprintf(buf + offset, remain, ") ^ ");
	SNPRINTF_BUFFER_SIZE(ret, remain, offset);

	if (flags & (1 << NFTA_BITWISE_XOR))
		ret = nftnl_data_reg_snprintf(buf + offset, remain,
					      &bitwise->xor,
					      NFTNL_OUTPUT_DEFAULT, 0,
					      DATA_VALUE);
	else
		ret = snprintf(buf + offset, remain, "reg %u ", bitwise->xreg);
	SNPRINTF_BUFFER_SIZE(ret, remain, offset);

	return offset;
}

static int
nftnl_expr_bitwise_snprintf_shift(char *buf, size_t size, const char *op,
				  const struct nftnl_expr_bitwise *bitwise)
{	int remain = size, offset = 0, ret;

	ret = snprintf(buf, remain, "reg %u = ( reg %u %s ",
		       bitwise->dreg, bitwise->sreg, op);
	SNPRINTF_BUFFER_SIZE(ret, remain, offset);

	ret = nftnl_data_reg_snprintf(buf + offset, remain, &bitwise->data,
				      NFTNL_OUTPUT_DEFAULT, 0, DATA_VALUE);
	SNPRINTF_BUFFER_SIZE(ret, remain, offset);

	ret = snprintf(buf + offset, remain, ") ");
	SNPRINTF_BUFFER_SIZE(ret, remain, offset);

	return offset;
}

static int nftnl_expr_bitwise_snprintf_default(char *buf, size_t size,
					       const struct nftnl_expr *e)
{
	struct nftnl_expr_bitwise *bitwise = nftnl_expr_data(e);
	int err = -1;

	switch (bitwise->op) {
	case NFT_BITWISE_BOOL:
		err = nftnl_expr_bitwise_snprintf_bool(buf, size, bitwise,
						       e->flags);
		break;
	case NFT_BITWISE_LSHIFT:
		err = nftnl_expr_bitwise_snprintf_shift(buf, size, "<<", bitwise);
		break;
	case NFT_BITWISE_RSHIFT:
		err = nftnl_expr_bitwise_snprintf_shift(buf, size, ">>", bitwise);
		break;
	}

	return err;
}

static int
nftnl_expr_bitwise_snprintf(char *buf, size_t size, uint32_t type,
			    uint32_t flags, const struct nftnl_expr *e)
{
	switch (type) {
	case NFTNL_OUTPUT_DEFAULT:
		return nftnl_expr_bitwise_snprintf_default(buf, size, e);
	default:
		break;
	}
	return -1;
}

struct expr_ops expr_ops_bitwise = {
	.name		= "bitwise",
	.alloc_len	= sizeof(struct nftnl_expr_bitwise),
	.max_attr	= NFTA_BITWISE_MAX,
	.set		= nftnl_expr_bitwise_set,
	.get		= nftnl_expr_bitwise_get,
	.parse		= nftnl_expr_bitwise_parse,
	.build		= nftnl_expr_bitwise_build,
	.snprintf	= nftnl_expr_bitwise_snprintf,
};
