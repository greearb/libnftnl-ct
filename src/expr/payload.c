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
	struct nft_expr_payload *payload = (struct nft_expr_payload *)e->data;

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
	struct nft_expr_payload *payload = (struct nft_expr_payload *)e->data;

	switch(type) {
	case NFT_EXPR_PAYLOAD_DREG:
		if (e->flags & (1 << NFT_EXPR_PAYLOAD_DREG)) {
			*data_len = sizeof(payload->dreg);
			return &payload->dreg;
		} else
			return NULL;
		break;
	case NFT_EXPR_PAYLOAD_BASE:
		if (e->flags & (1 << NFT_EXPR_PAYLOAD_BASE)) {
			*data_len = sizeof(payload->base);
			return &payload->base;
		} else
			return NULL;
		break;
	case NFT_EXPR_PAYLOAD_OFFSET:
		if (e->flags & (1 << NFT_EXPR_PAYLOAD_OFFSET)) {
			*data_len = sizeof(payload->offset);
			return &payload->offset;
		} else
			return NULL;
		break;
	case NFT_EXPR_PAYLOAD_LEN:
		if (e->flags & (1 << NFT_EXPR_PAYLOAD_LEN)) {
			*data_len = sizeof(payload->len);
			return &payload->len;
		} else
			return NULL;
		break;
	default:
		break;
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
	struct nft_expr_payload *payload = (struct nft_expr_payload *)e->data;

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
	struct nft_expr_payload *payload = (struct nft_expr_payload *)e->data;
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

static int
nft_rule_expr_payload_xml_parse(struct nft_rule_expr *e, char *xml)
{
#ifdef XML_PARSING
	struct nft_expr_payload *payload = (struct nft_expr_payload *)e->data;
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

	if (strcmp("payload", mxmlElementGetAttr(tree, "type")) != 0) {
		mxmlDelete(tree);
		return -1;
	}

	/* Get and set <dreg>. Not mandatory */
	node = mxmlFindElement(tree, tree, "dreg", NULL, NULL,
			       MXML_DESCEND_FIRST);
	if (node != NULL) {
		tmp = strtoull(node->child->value.opaque, &endptr, 10);
		if (tmp > UINT32_MAX || tmp < 0 || *endptr) {
			mxmlDelete(tree);
			return -1;
		}

		if (tmp > NFT_REG_MAX) {
			mxmlDelete(tree);
			return -1;
		}

		payload->dreg = (uint32_t)tmp;
		e->flags |= (1 << NFT_EXPR_PAYLOAD_DREG);
	}

	/* Get and set <base>. Not mandatory */
	node = mxmlFindElement(tree, tree, "base", NULL, NULL, MXML_DESCEND);
	if (node != NULL) {

		if (strcmp(node->child->value.opaque, "link") == 0) {
			payload->base = NFT_PAYLOAD_LL_HEADER;
		} else if (strcmp(node->child->value.opaque, "network") == 0) {
			payload->base = NFT_PAYLOAD_NETWORK_HEADER;
		} else if (strcmp(node->child->value.opaque,
				  "transport") == 0) {
			payload->base = NFT_PAYLOAD_TRANSPORT_HEADER;
		} else {
			mxmlDelete(tree);
			return -1;
		}

		e->flags |= (1 << NFT_EXPR_PAYLOAD_BASE);
	}

	/* Get and set <offset>. Not mandatory */
	node = mxmlFindElement(tree, tree, "offset", NULL, NULL,
			       MXML_DESCEND);
	if (node != NULL) {
		tmp = strtoull(node->child->value.opaque, &endptr, 10);
		if (tmp > UINT_MAX || tmp < 0 || *endptr) {
			mxmlDelete(tree);
			return -1;
		}

		payload->offset = (unsigned int)tmp;
		e->flags |= (1 << NFT_EXPR_PAYLOAD_OFFSET);
	}

	/* Get and set <len>. Not mandatory */
	node = mxmlFindElement(tree, tree, "len", NULL, NULL, MXML_DESCEND);
	if (node != NULL) {
		tmp = strtoull(node->child->value.opaque, &endptr, 10);
		if (tmp > UINT_MAX || tmp < 0 || *endptr) {
			mxmlDelete(tree);
			return -1;
		}

		payload->len = (unsigned int)tmp;
		e->flags |= (1 << NFT_EXPR_PAYLOAD_LEN);
	}
	mxmlDelete(tree);
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

	ret = snprintf(buf, len, "<dreg>%u</dreg><offset>%u</offset>"
		       "<len>%u</len>", p->dreg, p->offset, p->len);
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	/* A default option is not provided.
	 * The <base> node will be missing; Is not mandatory.
	 */

	switch (p->base) {
	case NFT_PAYLOAD_LL_HEADER:
		ret = snprintf(buf+offset, len, "<base>link</base>");
		break;
	case NFT_PAYLOAD_NETWORK_HEADER:
		ret = snprintf(buf+offset, len, "<base>network</base>");
		break;
	case NFT_PAYLOAD_TRANSPORT_HEADER:
		ret = snprintf(buf+offset, len, "<base>transport</base>");
		break;
	default:
		ret = snprintf(buf+offset, len, "<base>unknown</base>");
		break;
	}

	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	return offset;
}


static int
nft_rule_expr_payload_snprintf(char *buf, size_t len, uint32_t type,
			       uint32_t flags, struct nft_rule_expr *e)
{
	struct nft_expr_payload *payload = (struct nft_expr_payload *)e->data;

	switch(type) {
	case NFT_RULE_O_XML:
		return nft_rule_expr_payload_snprintf_xml(buf, len, flags,
							  payload);
	case NFT_RULE_O_DEFAULT:
		return snprintf(buf, len, "dreg=%u base=%u offset=%u len=%u ",
				payload->dreg, payload->base,
				payload->offset, payload->len);
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
};
