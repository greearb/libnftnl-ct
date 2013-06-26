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
#include <libnftables/expr.h>
#include <libnftables/rule.h>
#include "expr_ops.h"

struct nft_expr_ct {
	enum nft_ct_keys        key;
	uint32_t		dreg;	/* enum nft_registers */
	uint8_t			dir;
};

#define IP_CT_DIR_ORIGINAL	0
#define IP_CT_DIR_REPLY		1

#ifndef NFT_CT_MAX
#define NFT_CT_MAX (NFT_CT_PROTO_DST + 1)
#endif

static int
nft_rule_expr_ct_set(struct nft_rule_expr *e, uint16_t type,
		       const void *data, size_t data_len)
{
	struct nft_expr_ct *ct = (struct nft_expr_ct *)e->data;

	switch(type) {
	case NFT_EXPR_CT_KEY:
		ct->key = *((uint32_t *)data);
		break;
	case NFT_EXPR_CT_DIR:
		ct->dreg = *((uint8_t *)data);
		break;
	case NFT_EXPR_CT_DREG:
		ct->dreg = *((uint32_t *)data);
		break;
	default:
		return -1;
	}
	return 0;
}

static const void *
nft_rule_expr_ct_get(const struct nft_rule_expr *e, uint16_t type,
		     size_t *data_len)
{
	struct nft_expr_ct *ct = (struct nft_expr_ct *)e->data;

	switch(type) {
	case NFT_EXPR_CT_KEY:
		if (e->flags & (1 << NFT_EXPR_CT_KEY)) {
			*data_len = sizeof(ct->key);
			return &ct->key;
		} else
			return NULL;
		break;
	case NFT_EXPR_CT_DIR:
		if (e->flags & (1 << NFT_EXPR_CT_DIR)) {
			*data_len = sizeof(ct->dir);
			return &ct->dir;
		} else
			return NULL;
		break;
	case NFT_EXPR_CT_DREG:
		if (e->flags & (1 << NFT_EXPR_CT_DREG)) {
			*data_len = sizeof(ct->dreg);
			return &ct->dreg;
		} else
			return NULL;
		break;
	default:
		break;
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
	struct nft_expr_ct *ct = (struct nft_expr_ct *)e->data;

	if (e->flags & (1 << NFT_EXPR_CT_KEY))
		mnl_attr_put_u32(nlh, NFTA_CT_KEY, htonl(ct->key));
	if (e->flags & (1 << NFT_EXPR_CT_DREG))
		mnl_attr_put_u32(nlh, NFTA_CT_DREG, htonl(ct->dreg));
	if (e->flags & (1 << NFT_EXPR_CT_DIR))
		mnl_attr_put_u8(nlh, NFTA_CT_DIRECTION, ct->dir);
}

static int
nft_rule_expr_ct_parse(struct nft_rule_expr *e, struct nlattr *attr)
{
	struct nft_expr_ct *ct = (struct nft_expr_ct *)e->data;
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
	[NFT_CT_PROTOCOL]	= "protocol",
	[NFT_CT_SRC]		= "src",
	[NFT_CT_DST]		= "dst",
	[NFT_CT_PROTO_SRC]	= "proto_src",
	[NFT_CT_PROTO_DST]	= "proto_dst"
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

static int nft_rule_expr_ct_xml_parse(struct nft_rule_expr *e, char *xml)
{
#ifdef XML_PARSING
	struct nft_expr_ct *ct = (struct nft_expr_ct *)e->data;
	mxml_node_t *tree = NULL;
	mxml_node_t *node = NULL;
	uint64_t tmp;
	char *endptr;
	int key;

	tree = mxmlLoadString(NULL, xml, MXML_OPAQUE_CALLBACK);
	if (tree == NULL)
		return -1;

	if (mxmlElementGetAttr(tree, "type") == NULL)
		goto err;

	if (strcmp("ct", mxmlElementGetAttr(tree, "type")) != 0)
		goto err;

	node = mxmlFindElement(tree, tree, "dreg", NULL, NULL,
			       MXML_DESCEND_FIRST);
	if (node == NULL)
		goto err;

	tmp = strtoull(node->child->value.opaque, &endptr, 10);
	if (tmp > UINT8_MAX || tmp < 0 || *endptr)
		goto err;

	if (tmp > NFT_REG_MAX)
		goto err;

	ct->dreg = tmp;
	e->flags |= (1 << NFT_EXPR_CT_DREG);

	node = mxmlFindElement(tree, tree, "key", NULL, NULL, MXML_DESCEND);
	if (node == NULL)
		goto err;

	key = str2ctkey(node->child->value.opaque);
	if (key < 0)
		goto err;

	ct->key = key;
	e->flags |= (1 << NFT_EXPR_CT_KEY);

	node = mxmlFindElement(tree, tree, "dir", NULL, NULL, MXML_DESCEND);
	if (node == NULL)
		goto err;

	tmp = strtoull(node->child->value.opaque, &endptr, 10);
	if (tmp > UINT8_MAX || tmp < 0 || *endptr)
		goto err;

	if (tmp != IP_CT_DIR_ORIGINAL && tmp != IP_CT_DIR_REPLY)
		goto err;

	ct->dir = tmp;
	e->flags |= (1 << NFT_EXPR_CT_DIR);

	mxmlDelete(tree);
	return 0;
err:
	mxmlDelete(tree);
	errno = EINVAL;
	return -1;
#else
	errno = EOPNOTSUPP;
	return -1;
#endif
}

static int
nft_rule_expr_ct_snprintf(char *buf, size_t len, uint32_t type,
			    uint32_t flags, struct nft_rule_expr *e)
{
	struct nft_expr_ct *ct = (struct nft_expr_ct *)e->data;

	switch(type) {
	case NFT_RULE_O_DEFAULT:
		return snprintf(buf, len, "dreg=%u key=%s dir=%u ",
				ct->dreg, ctkey2str(ct->key), ct->dir);
	case NFT_RULE_O_XML:
		return snprintf(buf, len, "<dreg>%u</dreg>"
					  "<key>%s</key>"
					  "<dir>%u</dir>",
				ct->dreg, ctkey2str(ct->key), ct->dir);
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
};
