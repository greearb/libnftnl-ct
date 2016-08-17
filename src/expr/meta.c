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

#ifndef NFT_META_MAX
#define NFT_META_MAX (NFT_META_PRANDOM + 1)
#endif

struct nftnl_expr_meta {
	enum nft_meta_keys	key;
	enum nft_registers	dreg;
	enum nft_registers	sreg;
};

static int
nftnl_expr_meta_set(struct nftnl_expr *e, uint16_t type,
		       const void *data, uint32_t data_len)
{
	struct nftnl_expr_meta *meta = nftnl_expr_data(e);

	switch(type) {
	case NFTNL_EXPR_META_KEY:
		meta->key = *((uint32_t *)data);
		break;
	case NFTNL_EXPR_META_DREG:
		meta->dreg = *((uint32_t *)data);
		break;
	case NFTNL_EXPR_META_SREG:
		meta->sreg = *((uint32_t *)data);
		break;
	default:
		return -1;
	}
	return 0;
}

static const void *
nftnl_expr_meta_get(const struct nftnl_expr *e, uint16_t type,
		       uint32_t *data_len)
{
	struct nftnl_expr_meta *meta = nftnl_expr_data(e);

	switch(type) {
	case NFTNL_EXPR_META_KEY:
		*data_len = sizeof(meta->key);
		return &meta->key;
	case NFTNL_EXPR_META_DREG:
		*data_len = sizeof(meta->dreg);
		return &meta->dreg;
	case NFTNL_EXPR_META_SREG:
		*data_len = sizeof(meta->sreg);
		return &meta->sreg;
	}
	return NULL;
}

static int nftnl_expr_meta_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, NFTA_META_MAX) < 0)
		return MNL_CB_OK;

	switch(type) {
	case NFTA_META_KEY:
	case NFTA_META_DREG:
	case NFTA_META_SREG:
		if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0)
			abi_breakage();
		break;
	}

	tb[type] = attr;
	return MNL_CB_OK;
}

static void
nftnl_expr_meta_build(struct nlmsghdr *nlh, const struct nftnl_expr *e)
{
	struct nftnl_expr_meta *meta = nftnl_expr_data(e);

	if (e->flags & (1 << NFTNL_EXPR_META_KEY))
		mnl_attr_put_u32(nlh, NFTA_META_KEY, htonl(meta->key));
	if (e->flags & (1 << NFTNL_EXPR_META_DREG))
		mnl_attr_put_u32(nlh, NFTA_META_DREG, htonl(meta->dreg));
	if (e->flags & (1 << NFTNL_EXPR_META_SREG))
		mnl_attr_put_u32(nlh, NFTA_META_SREG, htonl(meta->sreg));
}

static int
nftnl_expr_meta_parse(struct nftnl_expr *e, struct nlattr *attr)
{
	struct nftnl_expr_meta *meta = nftnl_expr_data(e);
	struct nlattr *tb[NFTA_META_MAX+1] = {};

	if (mnl_attr_parse_nested(attr, nftnl_expr_meta_cb, tb) < 0)
		return -1;

	if (tb[NFTA_META_KEY]) {
		meta->key = ntohl(mnl_attr_get_u32(tb[NFTA_META_KEY]));
		e->flags |= (1 << NFTNL_EXPR_META_KEY);
	}
	if (tb[NFTA_META_DREG]) {
		meta->dreg = ntohl(mnl_attr_get_u32(tb[NFTA_META_DREG]));
		e->flags |= (1 << NFTNL_EXPR_META_DREG);
	}
	if (tb[NFTA_META_SREG]) {
		meta->sreg = ntohl(mnl_attr_get_u32(tb[NFTA_META_SREG]));
		e->flags |= (1 << NFTNL_EXPR_META_SREG);
	}

	return 0;
}

static const char *meta_key2str_array[NFT_META_MAX] = {
	[NFT_META_LEN]		= "len",
	[NFT_META_PROTOCOL]	= "protocol",
	[NFT_META_NFPROTO]	= "nfproto",
	[NFT_META_L4PROTO]	= "l4proto",
	[NFT_META_PRIORITY]	= "priority",
	[NFT_META_MARK]		= "mark",
	[NFT_META_IIF]		= "iif",
	[NFT_META_OIF]		= "oif",
	[NFT_META_IIFNAME]	= "iifname",
	[NFT_META_OIFNAME]	= "oifname",
	[NFT_META_IIFTYPE]	= "iiftype",
	[NFT_META_OIFTYPE]	= "oiftype",
	[NFT_META_SKUID]	= "skuid",
	[NFT_META_SKGID]	= "skgid",
	[NFT_META_NFTRACE]	= "nftrace",
	[NFT_META_RTCLASSID]	= "rtclassid",
	[NFT_META_SECMARK]	= "secmark",
	[NFT_META_BRI_IIFNAME]	= "bri_iifname",
	[NFT_META_BRI_OIFNAME]	= "bri_oifname",
	[NFT_META_PKTTYPE]	= "pkttype",
	[NFT_META_CPU]		= "cpu",
	[NFT_META_IIFGROUP]	= "iifgroup",
	[NFT_META_OIFGROUP]	= "oifgroup",
	[NFT_META_CGROUP]	= "cgroup",
	[NFT_META_PRANDOM]	= "prandom",
};

static const char *meta_key2str(uint8_t key)
{
	if (key < NFT_META_MAX)
		return meta_key2str_array[key];

	return "unknown";
}

static inline int str2meta_key(const char *str)
{
	int i;

	for (i = 0; i < NFT_META_MAX; i++) {
		if (strcmp(str, meta_key2str_array[i]) == 0)
			return i;
	}

	errno = EINVAL;
	return -1;
}

static int nftnl_expr_meta_json_parse(struct nftnl_expr *e, json_t *root,
					 struct nftnl_parse_err *err)
{
#ifdef JSON_PARSING
	const char *key_str;
	uint32_t reg;
	int key;

	key_str = nftnl_jansson_parse_str(root, "key", err);
	if (key_str != NULL) {
		key = str2meta_key(key_str);
		if (key >= 0)
			nftnl_expr_set_u32(e, NFTNL_EXPR_META_KEY, key);
	}

	if (nftnl_jansson_node_exist(root, "dreg")) {
		if (nftnl_jansson_parse_reg(root, "dreg", NFTNL_TYPE_U32, &reg,
					  err) == 0)
			nftnl_expr_set_u32(e, NFTNL_EXPR_META_DREG, reg);
	}

	if (nftnl_jansson_node_exist(root, "sreg")) {
		if (nftnl_jansson_parse_reg(root, "sreg", NFTNL_TYPE_U32, &reg,
					  err) == 0)
			nftnl_expr_set_u32(e, NFTNL_EXPR_META_SREG, reg);
	}

	return 0;
#else
	errno = EOPNOTSUPP;
	return -1;
#endif
}


static int nftnl_expr_meta_xml_parse(struct nftnl_expr *e, mxml_node_t *tree,
					struct nftnl_parse_err *err)
{
#ifdef XML_PARSING
	const char *key_str;
	int key;
	uint32_t dreg, sreg;

	key_str = nftnl_mxml_str_parse(tree, "key", MXML_DESCEND_FIRST,
				     NFTNL_XML_MAND, err);
	if (key_str != NULL) {
		key = str2meta_key(key_str);
		if (key >= 0)
			nftnl_expr_set_u32(e, NFTNL_EXPR_META_KEY, key);
	}

	if (nftnl_mxml_reg_parse(tree, "dreg", &dreg, MXML_DESCEND_FIRST,
			       NFTNL_XML_OPT, err) == 0)
		nftnl_expr_set_u32(e, NFTNL_EXPR_META_DREG, dreg);

	if (nftnl_mxml_reg_parse(tree, "sreg", &sreg, MXML_DESCEND_FIRST,
			       NFTNL_XML_OPT, err) == 0)
		nftnl_expr_set_u32(e, NFTNL_EXPR_META_SREG, sreg);

	return 0;
#else
	errno = EOPNOTSUPP;
	return -1;
#endif
}

static int
nftnl_expr_meta_snprintf_default(char *buf, size_t len,
				 const struct nftnl_expr *e)
{
	struct nftnl_expr_meta *meta = nftnl_expr_data(e);

	if (e->flags & (1 << NFTNL_EXPR_META_SREG)) {
		return snprintf(buf, len, "set %s with reg %u ",
				meta_key2str(meta->key), meta->sreg);
	}
	if (e->flags & (1 << NFTNL_EXPR_META_DREG)) {
		return snprintf(buf, len, "load %s => reg %u ",
				meta_key2str(meta->key), meta->dreg);
	}
	return 0;
}

static int nftnl_expr_meta_export(char *buf, size_t size,
				  const struct nftnl_expr *e, int type)
{
	struct nftnl_expr_meta *meta = nftnl_expr_data(e);
	NFTNL_BUF_INIT(b, buf, size);

	if (e->flags & (1 << NFTNL_EXPR_META_DREG))
		nftnl_buf_u32(&b, type, meta->dreg, DREG);
	if (e->flags & (1 << NFTNL_EXPR_META_KEY))
		nftnl_buf_str(&b, type, meta_key2str(meta->key), KEY);
	if (e->flags & (1 << NFTNL_EXPR_META_SREG))
		nftnl_buf_u32(&b, type, meta->sreg, SREG);

	return nftnl_buf_done(&b);
}

static int
nftnl_expr_meta_snprintf(char *buf, size_t len, uint32_t type,
			 uint32_t flags, const struct nftnl_expr *e)
{
	switch (type) {
	case NFTNL_OUTPUT_DEFAULT:
		return nftnl_expr_meta_snprintf_default(buf, len, e);
	case NFTNL_OUTPUT_XML:
	case NFTNL_OUTPUT_JSON:
		return nftnl_expr_meta_export(buf, len, e, type);
	default:
		break;
	}
	return -1;
}

static bool nftnl_expr_meta_cmp(const struct nftnl_expr *e1,
				     const struct nftnl_expr *e2)
{
	struct nftnl_expr_meta *m1 = nftnl_expr_data(e1);
	struct nftnl_expr_meta *m2 = nftnl_expr_data(e2);
	bool eq = true;

	if (e1->flags & (1 << NFTNL_EXPR_META_KEY))
		eq &= (m1->key == m2->key);
	if (e1->flags & (1 << NFTNL_EXPR_META_DREG))
		eq &= (m1->dreg == m2->dreg);
	if (e1->flags & (1 << NFTNL_EXPR_META_SREG))
		eq &= (m1->sreg == m2->sreg);

	return eq;
}

struct expr_ops expr_ops_meta = {
	.name		= "meta",
	.alloc_len	= sizeof(struct nftnl_expr_meta),
	.max_attr	= NFTA_META_MAX,
	.cmp		= nftnl_expr_meta_cmp,
	.set		= nftnl_expr_meta_set,
	.get		= nftnl_expr_meta_get,
	.parse		= nftnl_expr_meta_parse,
	.build		= nftnl_expr_meta_build,
	.snprintf	= nftnl_expr_meta_snprintf,
	.xml_parse 	= nftnl_expr_meta_xml_parse,
	.json_parse 	= nftnl_expr_meta_json_parse,
};
