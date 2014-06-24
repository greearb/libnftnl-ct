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
#include "expr_ops.h"

struct nft_expr_ct {
	enum nft_ct_keys        key;
	enum nft_registers	dreg;
	enum nft_registers	sreg;
	uint8_t			dir;
};

#define IP_CT_DIR_ORIGINAL	0
#define IP_CT_DIR_REPLY		1

#ifndef NFT_CT_MAX
#define NFT_CT_MAX (NFT_CT_LABELS + 1)
#endif

static int
nft_rule_expr_ct_set(struct nft_rule_expr *e, uint16_t type,
		       const void *data, uint32_t data_len)
{
	struct nft_expr_ct *ct = nft_expr_data(e);

	switch(type) {
	case NFT_EXPR_CT_KEY:
		ct->key = *((uint32_t *)data);
		break;
	case NFT_EXPR_CT_DIR:
		ct->dir = *((uint8_t *)data);
		break;
	case NFT_EXPR_CT_DREG:
		ct->dreg = *((uint32_t *)data);
		break;
	case NFT_EXPR_CT_SREG:
		ct->sreg = *((uint32_t *)data);
		break;
	default:
		return -1;
	}
	return 0;
}

static const void *
nft_rule_expr_ct_get(const struct nft_rule_expr *e, uint16_t type,
		     uint32_t *data_len)
{
	struct nft_expr_ct *ct = nft_expr_data(e);

	switch(type) {
	case NFT_EXPR_CT_KEY:
		*data_len = sizeof(ct->key);
		return &ct->key;
	case NFT_EXPR_CT_DIR:
		*data_len = sizeof(ct->dir);
		return &ct->dir;
	case NFT_EXPR_CT_DREG:
		*data_len = sizeof(ct->dreg);
		return &ct->dreg;
	case NFT_EXPR_CT_SREG:
		*data_len = sizeof(ct->sreg);
		return &ct->sreg;
	}
	return NULL;
}

static int nft_rule_expr_ct_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, NFTA_CT_MAX) < 0)
		return MNL_CB_OK;

	switch(type) {
	case NFTA_CT_KEY:
	case NFTA_CT_DREG:
	case NFTA_CT_SREG:
		if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0) {
			perror("mnl_attr_validate");
			return MNL_CB_ERROR;
		}
		break;
	case NFTA_CT_DIRECTION:
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
nft_rule_expr_ct_build(struct nlmsghdr *nlh, struct nft_rule_expr *e)
{
	struct nft_expr_ct *ct = nft_expr_data(e);

	if (e->flags & (1 << NFT_EXPR_CT_KEY))
		mnl_attr_put_u32(nlh, NFTA_CT_KEY, htonl(ct->key));
	if (e->flags & (1 << NFT_EXPR_CT_DREG))
		mnl_attr_put_u32(nlh, NFTA_CT_DREG, htonl(ct->dreg));
	if (e->flags & (1 << NFT_EXPR_CT_DIR))
		mnl_attr_put_u8(nlh, NFTA_CT_DIRECTION, ct->dir);
	if (e->flags & (1 << NFT_EXPR_CT_SREG))
		mnl_attr_put_u32(nlh, NFTA_CT_SREG, htonl(ct->sreg));
}

static int
nft_rule_expr_ct_parse(struct nft_rule_expr *e, struct nlattr *attr)
{
	struct nft_expr_ct *ct = nft_expr_data(e);
	struct nlattr *tb[NFTA_CT_MAX+1] = {};

	if (mnl_attr_parse_nested(attr, nft_rule_expr_ct_cb, tb) < 0)
		return -1;

	if (tb[NFTA_CT_KEY]) {
		ct->key = ntohl(mnl_attr_get_u32(tb[NFTA_CT_KEY]));
		e->flags |= (1 << NFT_EXPR_CT_KEY);
	}
	if (tb[NFTA_CT_DREG]) {
		ct->dreg = ntohl(mnl_attr_get_u32(tb[NFTA_CT_DREG]));
		e->flags |= (1 << NFT_EXPR_CT_DREG);
	}
	if (tb[NFTA_CT_SREG]) {
		ct->sreg = ntohl(mnl_attr_get_u32(tb[NFTA_CT_SREG]));
		e->flags |= (1 << NFT_EXPR_CT_SREG);
	}
	if (tb[NFTA_CT_DIRECTION]) {
		ct->dir = mnl_attr_get_u8(tb[NFTA_CT_DIRECTION]);
		e->flags |= (1 << NFT_EXPR_CT_DIR);
	}

	return 0;
}

const char *ctkey2str_array[NFT_CT_MAX] = {
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
};

static const char *ctkey2str(uint32_t ctkey)
{
	if (ctkey > NFT_CT_MAX)
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
		return "unknow";
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

static int nft_rule_expr_ct_json_parse(struct nft_rule_expr *e, json_t *root,
				       struct nft_parse_err *err)
{
#ifdef JSON_PARSING
	const char *key_str, *dir_str;
	uint32_t reg;
	uint8_t dir;
	int key;

	if (nft_jansson_node_exist(root, "dreg")) {
		if (nft_jansson_parse_reg(root, "dreg", NFT_TYPE_U32, &reg, err) < 0)
			return -1;

		nft_rule_expr_set_u32(e, NFT_EXPR_CT_DREG, reg);
	}

	if (nft_jansson_node_exist(root, "sreg")) {
		if (nft_jansson_parse_reg(root, "sreg", NFT_TYPE_U32, &reg, err) < 0)
			return -1;

		nft_rule_expr_set_u32(e, NFT_EXPR_CT_SREG, reg);
	}

	if (nft_jansson_node_exist(root, "key")) {
		key_str = nft_jansson_parse_str(root, "key", err);
		if (key_str == NULL)
			return -1;

		key = str2ctkey(key_str);
		if (key < 0)
			goto err;

		nft_rule_expr_set_u32(e, NFT_EXPR_CT_KEY, key);

	}

	if (nft_jansson_node_exist(root, "dir")) {
		dir_str = nft_jansson_parse_str(root, "dir", err);
		if (dir_str == NULL)
			return -1;

		if (str2ctdir(dir_str, &dir) != 0) {
			err->node_name = "dir";
			err->error = NFT_PARSE_EBADTYPE;
			goto err;
		}

		nft_rule_expr_set_u8(e, NFT_EXPR_CT_DIR, dir);
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


static int nft_rule_expr_ct_xml_parse(struct nft_rule_expr *e, mxml_node_t *tree,
				      struct nft_parse_err *err)
{
#ifdef XML_PARSING
	const char *key_str, *dir_str;
	int key;
	uint8_t dir;
	uint32_t dreg, sreg;

	if (nft_mxml_reg_parse(tree, "dreg", &dreg, MXML_DESCEND_FIRST,
			       NFT_XML_OPT, err) == 0)
		nft_rule_expr_set_u32(e, NFT_EXPR_CT_DREG, dreg);

	if (nft_mxml_reg_parse(tree, "sreg", &sreg, MXML_DESCEND_FIRST,
			       NFT_XML_OPT, err) == 0)
		nft_rule_expr_set_u32(e, NFT_EXPR_CT_SREG, sreg);

	key_str = nft_mxml_str_parse(tree, "key", MXML_DESCEND_FIRST,
				     NFT_XML_MAND, err);
	if (key_str != NULL) {
		key = str2ctkey(key_str);
		if (key < 0)
			return -1;

		nft_rule_expr_set_u32(e, NFT_EXPR_CT_KEY, key);
	}
	dir_str = nft_mxml_str_parse(tree, "dir", MXML_DESCEND_FIRST,
				     NFT_XML_OPT, err);
	if (dir_str != NULL) {
		if (str2ctdir(dir_str, &dir) != 0) {
			err->node_name = "dir";
			err->error = NFT_PARSE_EBADTYPE;
			goto err;
		}
		nft_rule_expr_set_u8(e, NFT_EXPR_CT_DIR, dir);
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
nft_expr_ct_snprintf_json(char *buf, size_t size, struct nft_rule_expr *e)
{
	int ret, len = size, offset = 0;
	struct nft_expr_ct *ct = nft_expr_data(e);

	if (e->flags & (1 << NFT_EXPR_CT_DREG)) {
		ret = snprintf(buf+offset, len, "\"dreg\":%u,", ct->dreg);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	if (e->flags & (1 << NFT_EXPR_CT_SREG)) {
		ret = snprintf(buf+offset, len, "\"sreg:\":%u,", ct->sreg);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	if (e->flags & (1 << NFT_EXPR_CT_KEY)) {
		ret = snprintf(buf+offset, len, "\"key\":\"%s\",",
						ctkey2str(ct->key));
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	if (nft_rule_expr_is_set(e, NFT_EXPR_CT_DIR)) {
		ret = snprintf(buf+offset, len, "\"dir\":\"%s\",",
			       ctdir2str(ct->dir));
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	/* Remove the last separator characther  */
	buf[offset-1] = '\0';

	return offset-1;
}

static int
nft_expr_ct_snprintf_xml(char *buf, size_t size, struct nft_rule_expr *e)
{
	int ret, len = size, offset = 0;
	struct nft_expr_ct *ct = nft_expr_data(e);

	if (e->flags & (1 << NFT_EXPR_CT_DREG)) {
		ret = snprintf(buf + offset, len, "<dreg>%u</dreg>", ct->dreg);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}
	if (e->flags & (1 << NFT_EXPR_CT_SREG)) {
		ret = snprintf(buf + offset, len, "<sreg>%u</sreg>", ct->sreg);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}
	if (e->flags & (1 << NFT_EXPR_CT_KEY)) {
		ret = snprintf(buf + offset, len, "<key>%s</key>",
			       ctkey2str(ct->key));
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}
	if (nft_rule_expr_is_set(e, NFT_EXPR_CT_DIR)) {
		ret = snprintf(buf + offset, len, "<dir>%s</dir>",
			       ctdir2str(ct->dir));
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	return offset;
}

static int
nft_expr_ct_snprintf_default(char *buf, size_t size, struct nft_rule_expr *e)
{
	int ret, len = size, offset = 0;
	struct nft_expr_ct *ct = nft_expr_data(e);

	if (e->flags & (1 << NFT_EXPR_CT_SREG)) {
		ret = snprintf(buf, size, "set %s with reg %u ",
				ctkey2str(ct->key), ct->sreg);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	if (e->flags & (1 << NFT_EXPR_CT_DREG)) {
		ret = snprintf(buf, len, "load %s => reg %u ",
			       ctkey2str(ct->key), ct->dreg);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	if (nft_rule_expr_is_set(e, NFT_EXPR_CT_DIR)) {
		ret = snprintf(buf+offset, len, ", dir %s ",
			       ctdir2str(ct->dir));
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	return offset;
}

static int
nft_rule_expr_ct_snprintf(char *buf, size_t len, uint32_t type,
			    uint32_t flags, struct nft_rule_expr *e)
{
	switch(type) {
	case NFT_OUTPUT_DEFAULT:
		return nft_expr_ct_snprintf_default(buf, len, e);
	case NFT_OUTPUT_XML:
		return nft_expr_ct_snprintf_xml(buf, len, e);
	case NFT_OUTPUT_JSON:
		return nft_expr_ct_snprintf_json(buf, len, e);
	default:
		break;
	}
	return -1;
}

struct expr_ops expr_ops_ct = {
	.name		= "ct",
	.alloc_len	= sizeof(struct nft_expr_ct),
	.max_attr	= NFTA_CT_MAX,
	.set		= nft_rule_expr_ct_set,
	.get		= nft_rule_expr_ct_get,
	.parse		= nft_rule_expr_ct_parse,
	.build		= nft_rule_expr_ct_build,
	.snprintf	= nft_rule_expr_ct_snprintf,
	.xml_parse	= nft_rule_expr_ct_xml_parse,
	.json_parse	= nft_rule_expr_ct_json_parse,
};

static void __init expr_ct_init(void)
{
	nft_expr_ops_register(&expr_ops_ct);
}
