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

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <errno.h>
#include <linux/netfilter/nf_tables.h>

#include "internal.h"
#include <libmnl/libmnl.h>
#include <libnftnl/expr.h>
#include <libnftnl/rule.h>

struct nftnl_expr_ct {
	enum nft_ct_keys        key;
	enum nft_registers	dreg;
	enum nft_registers	sreg;
	uint8_t			dir;
};

#define IP_CT_DIR_ORIGINAL	0
#define IP_CT_DIR_REPLY		1

#ifndef NFT_CT_MAX
#define NFT_CT_MAX (NFT_CT_EVENTMASK + 1)
#endif

static int
nftnl_expr_ct_set(struct nftnl_expr *e, uint16_t type,
		       const void *data, uint32_t data_len)
{
	struct nftnl_expr_ct *ct = nftnl_expr_data(e);

	switch(type) {
	case NFTNL_EXPR_CT_KEY:
		ct->key = *((uint32_t *)data);
		break;
	case NFTNL_EXPR_CT_DIR:
		ct->dir = *((uint8_t *)data);
		break;
	case NFTNL_EXPR_CT_DREG:
		ct->dreg = *((uint32_t *)data);
		break;
	case NFTNL_EXPR_CT_SREG:
		ct->sreg = *((uint32_t *)data);
		break;
	default:
		return -1;
	}
	return 0;
}

static const void *
nftnl_expr_ct_get(const struct nftnl_expr *e, uint16_t type,
		     uint32_t *data_len)
{
	struct nftnl_expr_ct *ct = nftnl_expr_data(e);

	switch(type) {
	case NFTNL_EXPR_CT_KEY:
		*data_len = sizeof(ct->key);
		return &ct->key;
	case NFTNL_EXPR_CT_DIR:
		*data_len = sizeof(ct->dir);
		return &ct->dir;
	case NFTNL_EXPR_CT_DREG:
		*data_len = sizeof(ct->dreg);
		return &ct->dreg;
	case NFTNL_EXPR_CT_SREG:
		*data_len = sizeof(ct->sreg);
		return &ct->sreg;
	}
	return NULL;
}

static int nftnl_expr_ct_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, NFTA_CT_MAX) < 0)
		return MNL_CB_OK;

	switch(type) {
	case NFTA_CT_KEY:
	case NFTA_CT_DREG:
	case NFTA_CT_SREG:
		if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0)
			abi_breakage();
		break;
	case NFTA_CT_DIRECTION:
		if (mnl_attr_validate(attr, MNL_TYPE_U8) < 0)
			abi_breakage();
		break;
	}

	tb[type] = attr;
	return MNL_CB_OK;
}

static void
nftnl_expr_ct_build(struct nlmsghdr *nlh, const struct nftnl_expr *e)
{
	struct nftnl_expr_ct *ct = nftnl_expr_data(e);

	if (e->flags & (1 << NFTNL_EXPR_CT_KEY))
		mnl_attr_put_u32(nlh, NFTA_CT_KEY, htonl(ct->key));
	if (e->flags & (1 << NFTNL_EXPR_CT_DREG))
		mnl_attr_put_u32(nlh, NFTA_CT_DREG, htonl(ct->dreg));
	if (e->flags & (1 << NFTNL_EXPR_CT_DIR))
		mnl_attr_put_u8(nlh, NFTA_CT_DIRECTION, ct->dir);
	if (e->flags & (1 << NFTNL_EXPR_CT_SREG))
		mnl_attr_put_u32(nlh, NFTA_CT_SREG, htonl(ct->sreg));
}

static int
nftnl_expr_ct_parse(struct nftnl_expr *e, struct nlattr *attr)
{
	struct nftnl_expr_ct *ct = nftnl_expr_data(e);
	struct nlattr *tb[NFTA_CT_MAX+1] = {};

	if (mnl_attr_parse_nested(attr, nftnl_expr_ct_cb, tb) < 0)
		return -1;

	if (tb[NFTA_CT_KEY]) {
		ct->key = ntohl(mnl_attr_get_u32(tb[NFTA_CT_KEY]));
		e->flags |= (1 << NFTNL_EXPR_CT_KEY);
	}
	if (tb[NFTA_CT_DREG]) {
		ct->dreg = ntohl(mnl_attr_get_u32(tb[NFTA_CT_DREG]));
		e->flags |= (1 << NFTNL_EXPR_CT_DREG);
	}
	if (tb[NFTA_CT_SREG]) {
		ct->sreg = ntohl(mnl_attr_get_u32(tb[NFTA_CT_SREG]));
		e->flags |= (1 << NFTNL_EXPR_CT_SREG);
	}
	if (tb[NFTA_CT_DIRECTION]) {
		ct->dir = mnl_attr_get_u8(tb[NFTA_CT_DIRECTION]);
		e->flags |= (1 << NFTNL_EXPR_CT_DIR);
	}

	return 0;
}

static const char *ctkey2str_array[NFT_CT_MAX] = {
	[NFT_CT_STATE]		= "state",
	[NFT_CT_DIRECTION]	= "direction",
	[NFT_CT_STATUS]		= "status",
	[NFT_CT_MARK]		= "mark",
	[NFT_CT_SECMARK]	= "secmark",
	[NFT_CT_EXPIRATION]	= "expiration",
	[NFT_CT_HELPER]		= "helper",
	[NFT_CT_L3PROTOCOL]	= "l3protocol",
	[NFT_CT_PROTOCOL]	= "protocol",
	[NFT_CT_SRC]		= "src",
	[NFT_CT_DST]		= "dst",
	[NFT_CT_PROTO_SRC]	= "proto_src",
	[NFT_CT_PROTO_DST]	= "proto_dst",
	[NFT_CT_LABELS]		= "label",
	[NFT_CT_PKTS]		= "packets",
	[NFT_CT_BYTES]		= "bytes",
	[NFT_CT_AVGPKT]		= "avgpkt",
	[NFT_CT_ZONE]		= "zone",
	[NFT_CT_EVENTMASK]	= "eventmask",
};

static const char *ctkey2str(uint32_t ctkey)
{
	if (ctkey >= NFT_CT_MAX)
		return "unknown";

	return ctkey2str_array[ctkey];
}

static inline int str2ctkey(const char *ctkey)
{
	int i;

	for (i = 0; i < NFT_CT_MAX; i++) {
		if (strcmp(ctkey2str_array[i], ctkey) == 0)
			return i;
	}

	return -1;
}

static const char *ctdir2str(uint8_t ctdir)
{
	switch (ctdir) {
	case IP_CT_DIR_ORIGINAL:
		return "original";
	case IP_CT_DIR_REPLY:
		return "reply";
	default:
		return "unknown";
	}
}

static inline int str2ctdir(const char *str, uint8_t *ctdir)
{
	if (strcmp(str, "original") == 0) {
		*ctdir = IP_CT_DIR_ORIGINAL;
		return 0;
	}

	if (strcmp(str, "reply") == 0) {
		*ctdir = IP_CT_DIR_REPLY;
		return 0;
	}

	return -1;
}

static int nftnl_expr_ct_json_parse(struct nftnl_expr *e, json_t *root,
				       struct nftnl_parse_err *err)
{
#ifdef JSON_PARSING
	const char *key_str, *dir_str;
	uint32_t reg;
	uint8_t dir;
	int key;

	if (nftnl_jansson_parse_reg(root, "dreg", NFTNL_TYPE_U32, &reg, err) == 0)
		nftnl_expr_set_u32(e, NFTNL_EXPR_CT_DREG, reg);

	if (nftnl_jansson_parse_reg(root, "sreg", NFTNL_TYPE_U32, &reg, err) == 0)
		nftnl_expr_set_u32(e, NFTNL_EXPR_CT_SREG, reg);

	key_str = nftnl_jansson_parse_str(root, "key", err);
	if (key_str != NULL) {
		key = str2ctkey(key_str);
		if (key < 0)
			return -1;

		nftnl_expr_set_u32(e, NFTNL_EXPR_CT_KEY, key);
	}

	dir_str = nftnl_jansson_parse_str(root, "dir", err);
	if (dir_str != NULL) {
		if (str2ctdir(dir_str, &dir) != 0) {
			err->node_name = "dir";
			err->error = NFTNL_PARSE_EBADTYPE;
			goto err;
		}
		nftnl_expr_set_u8(e, NFTNL_EXPR_CT_DIR, dir);
	}

	return 0;
err:
	errno = EINVAL;
	return -1;
#else
	errno = EOPNOTSUPP;
	return -1;
#endif
}


static int
nftnl_expr_ct_export(char *buf, size_t size, const struct nftnl_expr *e,
		     int type)
{
	struct nftnl_expr_ct *ct = nftnl_expr_data(e);
	NFTNL_BUF_INIT(b, buf, size);

	if (e->flags & (1 << NFTNL_EXPR_CT_SREG))
		nftnl_buf_u32(&b, type, ct->sreg, SREG);
	if (e->flags & (1 << NFTNL_EXPR_CT_DREG))
		nftnl_buf_u32(&b, type, ct->dreg, DREG);
	if (e->flags & (1 << NFTNL_EXPR_CT_KEY))
		nftnl_buf_str(&b, type, ctkey2str(ct->key), KEY);
	if (e->flags & (1 << NFTNL_EXPR_CT_DIR))
		nftnl_buf_str(&b, type, ctdir2str(ct->dir), DIR);

	return nftnl_buf_done(&b);
}

static int
nftnl_expr_ct_snprintf_default(char *buf, size_t size,
			       const struct nftnl_expr *e)
{
	int ret, len = size, offset = 0;
	struct nftnl_expr_ct *ct = nftnl_expr_data(e);

	if (e->flags & (1 << NFTNL_EXPR_CT_SREG)) {
		ret = snprintf(buf, size, "set %s with reg %u ",
				ctkey2str(ct->key), ct->sreg);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	if (e->flags & (1 << NFTNL_EXPR_CT_DREG)) {
		ret = snprintf(buf, len, "load %s => reg %u ",
			       ctkey2str(ct->key), ct->dreg);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	if (nftnl_expr_is_set(e, NFTNL_EXPR_CT_DIR)) {
		ret = snprintf(buf+offset, len, ", dir %s ",
			       ctdir2str(ct->dir));
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	return offset;
}

static int
nftnl_expr_ct_snprintf(char *buf, size_t len, uint32_t type,
		       uint32_t flags, const struct nftnl_expr *e)
{
	switch (type) {
	case NFTNL_OUTPUT_DEFAULT:
		return nftnl_expr_ct_snprintf_default(buf, len, e);
	case NFTNL_OUTPUT_XML:
	case NFTNL_OUTPUT_JSON:
		return nftnl_expr_ct_export(buf, len, e, type);
	default:
		break;
	}
	return -1;
}

static bool nftnl_expr_ct_cmp(const struct nftnl_expr *e1,
			      const struct nftnl_expr *e2)
{
	struct nftnl_expr_ct *c1 = nftnl_expr_data(e1);
	struct nftnl_expr_ct *c2 = nftnl_expr_data(e2);
	bool eq = true;

	if (e1->flags & (1 << NFTNL_EXPR_CT_KEY))
		eq &= (c1->key == c2->key);
	if (e1->flags & (1 << NFTNL_EXPR_CT_DREG))
		eq &= (c1->dreg == c2->dreg);
	if (e1->flags & (1 << NFTNL_EXPR_CT_SREG))
		eq &= (c1->sreg == c2->sreg);
	if (e1->flags & (1 << NFTNL_EXPR_CT_DIR))
		eq &= (c1->dir == c2->dir);

	return eq;
}

struct expr_ops expr_ops_ct = {
	.name		= "ct",
	.alloc_len	= sizeof(struct nftnl_expr_ct),
	.max_attr	= NFTA_CT_MAX,
	.cmp		= nftnl_expr_ct_cmp,
	.set		= nftnl_expr_ct_set,
	.get		= nftnl_expr_ct_get,
	.parse		= nftnl_expr_ct_parse,
	.build		= nftnl_expr_ct_build,
	.snprintf	= nftnl_expr_ct_snprintf,
	.json_parse	= nftnl_expr_ct_json_parse,
};
