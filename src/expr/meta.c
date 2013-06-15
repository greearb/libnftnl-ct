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
#include <arpa/inet.h>
#include <errno.h>
#include <linux/netfilter/nf_tables.h>

#include "internal.h"
#include <libmnl/libmnl.h>
#include <libnftables/expr.h>
#include <libnftables/rule.h>
#include "expr_ops.h"

struct nft_expr_meta {
	uint8_t			key;	/* enum nft_meta_keys */
	uint8_t			dreg;	/* enum nft_registers */
};

static int
nft_rule_expr_meta_set(struct nft_rule_expr *e, uint16_t type,
		       const void *data, size_t data_len)
{
	struct nft_expr_meta *meta = (struct nft_expr_meta *)e->data;

	switch(type) {
	case NFT_EXPR_META_KEY:
		meta->key = *((uint32_t *)data);
		break;
	case NFT_EXPR_META_DREG:
		meta->dreg = *((uint32_t *)data);
		break;
	default:
		return -1;
	}
	return 0;
}

static const void *
nft_rule_expr_meta_get(const struct nft_rule_expr *e, uint16_t type,
		       size_t *data_len)
{
	struct nft_expr_meta *meta = (struct nft_expr_meta *)e->data;

	switch(type) {
	case NFT_EXPR_META_KEY:
		if (e->flags & (1 << NFT_EXPR_META_KEY)) {
			*data_len = sizeof(meta->key);
			return &meta->key;
		} else
			return NULL;
		break;
	case NFT_EXPR_META_DREG:
		if (e->flags & (1 << NFT_EXPR_META_DREG)) {
			*data_len = sizeof(meta->dreg);
			return &meta->dreg;
		} else
			return NULL;
		break;
	default:
		break;
	}
	return NULL;
}

static int nft_rule_expr_meta_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, NFTA_META_MAX) < 0)
		return MNL_CB_OK;

	switch(type) {
	case NFTA_META_KEY:
	case NFTA_META_DREG:
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
nft_rule_expr_meta_build(struct nlmsghdr *nlh, struct nft_rule_expr *e)
{
	struct nft_expr_meta *meta = (struct nft_expr_meta *)e->data;

	if (e->flags & (1 << NFT_EXPR_META_KEY))
		mnl_attr_put_u32(nlh, NFTA_META_KEY, htonl(meta->key));
	if (e->flags & (1 << NFT_EXPR_META_DREG))
		mnl_attr_put_u32(nlh, NFTA_META_DREG, htonl(meta->dreg));
}

static int
nft_rule_expr_meta_parse(struct nft_rule_expr *e, struct nlattr *attr)
{
	struct nft_expr_meta *meta = (struct nft_expr_meta *)e->data;
	struct nlattr *tb[NFTA_META_MAX+1] = {};

	if (mnl_attr_parse_nested(attr, nft_rule_expr_meta_cb, tb) < 0)
		return -1;

	if (tb[NFTA_META_KEY]) {
		meta->key = ntohl(mnl_attr_get_u32(tb[NFTA_META_KEY]));
		e->flags |= (1 << NFT_EXPR_META_KEY);
	}
	if (tb[NFTA_META_DREG]) {
		meta->dreg = ntohl(mnl_attr_get_u32(tb[NFTA_META_DREG]));
		e->flags |= (1 << NFT_EXPR_META_DREG);
	}

	return 0;
}

static int nft_rule_expr_meta_xml_parse(struct nft_rule_expr *e, char *xml)
{
#ifdef XML_PARSING
	struct nft_expr_meta *meta = (struct nft_expr_meta *)e->data;
	mxml_node_t *tree = NULL;
	mxml_node_t *node = NULL;
	uint64_t tmp;
	char *endptr;

	tree = mxmlLoadString(NULL, xml, MXML_OPAQUE_CALLBACK);
	if (tree == NULL)
		return -1;

	if (mxmlElementGetAttr(tree, "type") == NULL) {
		mxmlDelete(tree);
		return -1;
	}

	if (strcmp("meta", mxmlElementGetAttr(tree, "type")) != 0) {
		mxmlDelete(tree);
		return -1;
	}

	/* Get and set <dreg>. Is mandatory */
	node = mxmlFindElement(tree, tree, "dreg", NULL, NULL,
			       MXML_DESCEND_FIRST);
	if (node == NULL) {
		mxmlDelete(tree);
		return -1;
	}

	tmp = strtoull(node->child->value.opaque, &endptr, 10);
	if (tmp > UINT8_MAX || tmp < 0 || *endptr) {
		mxmlDelete(tree);
		return -1;
	}

	meta->dreg = (uint8_t)tmp;
	e->flags |= (1 << NFT_EXPR_META_DREG);

	/* Get and set <key>. Is mandatory */
	node = mxmlFindElement(tree, tree, "key", NULL, NULL, MXML_DESCEND);
	if (node == NULL) {
		mxmlDelete(tree);
		return -1;
	}

	tmp = strtoull(node->child->value.opaque, &endptr, 10);
	if (tmp > UINT8_MAX || tmp < 0 || *endptr) {
		mxmlDelete(tree);
		return -1;
	}

	meta->key = (uint8_t)tmp;
	e->flags |= (1 << NFT_EXPR_META_KEY);

	mxmlDelete(tree);
	return 0;
#else
	errno = EOPNOTSUPP;
	return -1;
#endif
}

static int
nft_rule_expr_meta_snprintf(char *buf, size_t len, uint32_t type,
			    uint32_t flags, struct nft_rule_expr *e)
{
	struct nft_expr_meta *meta = (struct nft_expr_meta *)e->data;

	switch(type) {
	case NFT_RULE_O_XML:
		return snprintf(buf, len, "<dreg>%u</dreg>"
					  "<key>%u</key>",
				meta->dreg, meta->key);
	case NFT_RULE_O_DEFAULT:
		return snprintf(buf, len, "dreg=%u key=%u ",
				meta->dreg, meta->key);
	default:
		break;
	}
	return -1;
}

struct expr_ops expr_ops_meta = {
	.name		= "meta",
	.alloc_len	= sizeof(struct nft_expr_meta),
	.max_attr	= NFTA_META_MAX,
	.set		= nft_rule_expr_meta_set,
	.get		= nft_rule_expr_meta_get,
	.parse		= nft_rule_expr_meta_parse,
	.build		= nft_rule_expr_meta_build,
	.snprintf	= nft_rule_expr_meta_snprintf,
	.xml_parse = nft_rule_expr_meta_xml_parse,
};
