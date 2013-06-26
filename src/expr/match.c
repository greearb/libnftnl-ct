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
#include <string.h>	/* for memcpy */
#include <arpa/inet.h>
#include <errno.h>
#include <libmnl/libmnl.h>

#include <linux/netfilter/nf_tables.h>
#include <linux/netfilter/nf_tables_compat.h>
#include <linux/netfilter/x_tables.h>

#include <libnftables/expr.h>
#include <libnftables/rule.h>

#include "expr_ops.h"

struct nft_expr_match {
	char		name[XT_EXTENSION_MAXNAMELEN];
	uint32_t	rev;
	uint32_t	data_len;
	const void	*data;
};

static int
nft_rule_expr_match_set(struct nft_rule_expr *e, uint16_t type,
			 const void *data, size_t data_len)
{
	struct nft_expr_match *mt = (struct nft_expr_match *)e->data;

	switch(type) {
	case NFT_EXPR_MT_NAME:
		memcpy(mt->name, data, XT_EXTENSION_MAXNAMELEN);
		mt->name[XT_EXTENSION_MAXNAMELEN-1] = '\0';
		break;
	case NFT_EXPR_MT_REV:
		mt->rev = *((uint32_t *)data);
		break;
	case NFT_EXPR_MT_INFO:
		if (mt->data)
			free((void *)mt->data);

		mt->data = data;
		mt->data_len = data_len;
		break;
	default:
		return -1;
	}
	return 0;
}

static const void *
nft_rule_expr_match_get(const struct nft_rule_expr *e, uint16_t type,
			size_t *data_len)
{
	struct nft_expr_match *mt = (struct nft_expr_match *)e->data;

	switch(type) {
	case NFT_EXPR_MT_NAME:
		if (e->flags & (1 << NFT_EXPR_MT_NAME)) {
			*data_len = sizeof(mt->name);
			return mt->name;
		} else
			return NULL;
		break;
	case NFT_EXPR_MT_REV:
		if (e->flags & (1 << NFT_EXPR_MT_REV)) {
			*data_len = sizeof(mt->rev);
			return &mt->rev;
		} else
			return NULL;
		break;
	case NFT_EXPR_MT_INFO:
		if (e->flags & (1 << NFT_EXPR_MT_INFO)) {
			*data_len = mt->data_len;
			return mt->data;
		} else
			return NULL;
		break;
	default:
		break;
	}
	return NULL;
}

static int nft_rule_expr_match_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, NFTA_MATCH_MAX) < 0)
		return MNL_CB_OK;

	switch(type) {
	case NFTA_MATCH_NAME:
		if (mnl_attr_validate(attr, MNL_TYPE_NUL_STRING) < 0) {
			perror("mnl_attr_validate");
			return MNL_CB_ERROR;
		}
		break;
	case NFTA_MATCH_REV:
		if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0) {
			perror("mnl_attr_validate");
			return MNL_CB_ERROR;
		}
		break;
	case NFTA_MATCH_INFO:
		if (mnl_attr_validate(attr, MNL_TYPE_BINARY) < 0) {
			perror("mnl_attr_validate");
			return MNL_CB_ERROR;
		}
		break;
	}

	tb[type] = attr;
	return MNL_CB_OK;
}

static void
nft_rule_expr_match_build(struct nlmsghdr *nlh, struct nft_rule_expr *e)
{
	struct nft_expr_match *mt = (struct nft_expr_match *)e->data;

	if (e->flags & (1 << NFT_EXPR_MT_NAME))
		mnl_attr_put_strz(nlh, NFTA_MATCH_NAME, mt->name);
	if (e->flags & (1 << NFT_EXPR_MT_REV))
		mnl_attr_put_u32(nlh, NFTA_MATCH_REV, htonl(mt->rev));
	if (e->flags & (1 << NFT_EXPR_MT_INFO))
		mnl_attr_put(nlh, NFTA_MATCH_INFO, XT_ALIGN(mt->data_len), mt->data);
}

static int nft_rule_expr_match_parse(struct nft_rule_expr *e, struct nlattr *attr)
{
	struct nft_expr_match *match = (struct nft_expr_match *)e->data;
	struct nlattr *tb[NFTA_MATCH_MAX+1] = {};

	if (mnl_attr_parse_nested(attr, nft_rule_expr_match_cb, tb) < 0)
		return -1;

	if (tb[NFTA_MATCH_NAME]) {
		snprintf(match->name, XT_EXTENSION_MAXNAMELEN, "%s",
			 mnl_attr_get_str(tb[NFTA_MATCH_NAME]));

		match->name[XT_EXTENSION_MAXNAMELEN-1] = '\0';
		e->flags |= (1 << NFTA_MATCH_NAME);
	}

	if (tb[NFTA_MATCH_REV]) {
		match->rev = ntohl(mnl_attr_get_u32(tb[NFTA_MATCH_REV]));
		e->flags |= (1 << NFTA_MATCH_REV);
	}

	if (tb[NFTA_MATCH_INFO]) {
		uint32_t len = mnl_attr_get_payload_len(tb[NFTA_MATCH_INFO]);
		void *match_data;

		if (match->data)
			free((void *) match->data);

		match_data = calloc(1, len);
		if (match_data == NULL)
			return -1;

		memcpy(match_data, mnl_attr_get_payload(tb[NFTA_MATCH_INFO]), len);

		match->data = match_data;
		match->data_len = len;

		e->flags |= (1 << NFTA_MATCH_INFO);
	}

	return 0;
}

static int nft_rule_expr_match_xml_parse(struct nft_rule_expr *e, char *xml)
{
#ifdef XML_PARSING
	struct nft_expr_match *mt = (struct nft_expr_match *)e->data;
	mxml_node_t *tree = NULL;
	mxml_node_t *node = NULL;

	/* load the tree */
	tree = mxmlLoadString(NULL, xml, MXML_OPAQUE_CALLBACK);
	if (tree == NULL)
		return -1;

	if (mxmlElementGetAttr(tree, "type") == NULL) {
		mxmlDelete(tree);
		return -1;
	}

	if (strcmp("match", mxmlElementGetAttr(tree, "type")) != 0) {
		mxmlDelete(tree);
		return -1;
	}

	/* get and set <name>. Not mandatory */
	node = mxmlFindElement(tree, tree, "name", NULL, NULL,
			       MXML_DESCEND_FIRST);
	if (node != NULL) {
		memcpy(mt->name, node->child->value.opaque,
		       XT_EXTENSION_MAXNAMELEN);
		mt->name[XT_EXTENSION_MAXNAMELEN-1] = '\0';
		e->flags |= (1 << NFT_EXPR_MT_NAME);
	}

	/* mt->info is ignored until other solution is reached */

	mxmlDelete(tree);
	return 0;
#else
	errno = EOPNOTSUPP;
	return -1;
#endif
}

static int nft_rule_expr_match_snprintf_xml(char *buf, size_t len,
					    struct nft_expr_match *mt)
{
	int ret, size=len;
	int offset = 0;

	ret = snprintf(buf, len, "<name>%s</name>", mt->name);
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	return offset;
}


static int
nft_rule_expr_match_snprintf(char *buf, size_t len, uint32_t type,
			     uint32_t flags, struct nft_rule_expr *e)
{
	struct nft_expr_match *match = (struct nft_expr_match *)e->data;

	switch(type) {
	case NFT_RULE_O_XML:
		return nft_rule_expr_match_snprintf_xml(buf, len, match);
	case NFT_RULE_O_DEFAULT:
		return snprintf(buf, len, "name=%s rev=%u ",
				match->name, match->rev);
	default:
		break;
	}
	return -1;
}

struct expr_ops expr_ops_match = {
	.name		= "match",
	.alloc_len	= sizeof(struct nft_expr_match),
	.max_attr	= NFTA_MATCH_MAX,
	.set		= nft_rule_expr_match_set,
	.get		= nft_rule_expr_match_get,
	.parse		= nft_rule_expr_match_parse,
	.build		= nft_rule_expr_match_build,
	.snprintf	= nft_rule_expr_match_snprintf,
	.xml_parse = nft_rule_expr_match_xml_parse,
};
