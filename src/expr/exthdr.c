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

#include "internal.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>
#include <arpa/inet.h>
#include <errno.h>
#include <libmnl/libmnl.h>

#include <linux/netfilter/nf_tables.h>

#include <libnftables/expr.h>
#include <libnftables/rule.h>

#include "expr_ops.h"

#ifndef IPPROTO_MH
#define IPPROTO_MH 135
#endif

struct nft_expr_exthdr {
	enum nft_registers	dreg;
	uint8_t			type;
	unsigned int		offset;
	unsigned int		len;
};

static int
nft_rule_expr_exthdr_set(struct nft_rule_expr *e, uint16_t type,
			  const void *data, size_t data_len)
{
	struct nft_expr_exthdr *exthdr = (struct nft_expr_exthdr *)e->data;

	switch(type) {
	case NFT_EXPR_EXTHDR_DREG:
		exthdr->dreg = *((uint32_t *)data);
		break;
	case NFT_EXPR_EXTHDR_TYPE:
		exthdr->type = *((uint8_t *)data);
		break;
	case NFT_EXPR_EXTHDR_OFFSET:
		exthdr->offset = *((unsigned int *)data);
		break;
	case NFT_EXPR_EXTHDR_LEN:
		exthdr->len = *((unsigned int *)data);
		break;
	default:
		return -1;
	}
	return 0;
}

static const void *
nft_rule_expr_exthdr_get(const struct nft_rule_expr *e, uint16_t type,
			 size_t *data_len)
{
	struct nft_expr_exthdr *exthdr = (struct nft_expr_exthdr *)e->data;

	switch(type) {
	case NFT_EXPR_EXTHDR_DREG:
		if (e->flags & (1 << NFT_EXPR_EXTHDR_DREG)) {
			*data_len = sizeof(exthdr->dreg);
			return &exthdr->dreg;
		} else
			return NULL;
		break;
	case NFT_EXPR_EXTHDR_TYPE:
		if (e->flags & (1 << NFT_EXPR_EXTHDR_TYPE)) {
			*data_len = sizeof(exthdr->type);
			return &exthdr->type;
		} else
			return NULL;
		break;
	case NFT_EXPR_EXTHDR_OFFSET:
		if (e->flags & (1 << NFT_EXPR_EXTHDR_OFFSET)) {
			*data_len = sizeof(exthdr->offset);
			return &exthdr->offset;
		} else
			return NULL;
		break;
	case NFT_EXPR_EXTHDR_LEN:
		if (e->flags & (1 << NFT_EXPR_EXTHDR_LEN)) {
			*data_len = sizeof(exthdr->len);
			return &exthdr->len;
		} else
			return NULL;
		break;
	default:
		break;
	}
	return NULL;
}

static int nft_rule_expr_exthdr_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, NFTA_EXTHDR_MAX) < 0)
		return MNL_CB_OK;

	switch(type) {
	case NFTA_EXTHDR_TYPE:
		if (mnl_attr_validate(attr, MNL_TYPE_U8) < 0) {
			perror("mnl_attr_validate");
			return MNL_CB_ERROR;
		}
		break;
	case NFTA_EXTHDR_DREG:
	case NFTA_EXTHDR_OFFSET:
	case NFTA_EXTHDR_LEN:
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
nft_rule_expr_exthdr_build(struct nlmsghdr *nlh, struct nft_rule_expr *e)
{
	struct nft_expr_exthdr *exthdr = (struct nft_expr_exthdr *)e->data;

	if (e->flags & (1 << NFT_EXPR_EXTHDR_DREG))
		mnl_attr_put_u32(nlh, NFTA_EXTHDR_DREG, htonl(exthdr->dreg));
	if (e->flags & (1 << NFT_EXPR_EXTHDR_TYPE))
		mnl_attr_put_u8(nlh, NFTA_EXTHDR_TYPE, exthdr->type);
	if (e->flags & (1 << NFT_EXPR_EXTHDR_OFFSET))
		mnl_attr_put_u32(nlh, NFTA_EXTHDR_OFFSET, htonl(exthdr->offset));
	if (e->flags & (1 << NFT_EXPR_EXTHDR_LEN))
		mnl_attr_put_u32(nlh, NFTA_EXTHDR_LEN, htonl(exthdr->len));
}

static int
nft_rule_expr_exthdr_parse(struct nft_rule_expr *e, struct nlattr *attr)
{
	struct nft_expr_exthdr *exthdr = (struct nft_expr_exthdr *)e->data;
	struct nlattr *tb[NFTA_EXTHDR_MAX+1] = {};

	if (mnl_attr_parse_nested(attr, nft_rule_expr_exthdr_cb, tb) < 0)
		return -1;

	if (tb[NFTA_EXTHDR_DREG]) {
		exthdr->dreg = ntohl(mnl_attr_get_u32(tb[NFTA_EXTHDR_DREG]));
		e->flags |= (1 << NFT_EXPR_EXTHDR_DREG);
	}
	if (tb[NFTA_EXTHDR_TYPE]) {
		exthdr->type = mnl_attr_get_u8(tb[NFTA_EXTHDR_TYPE]);
		e->flags |= (1 << NFT_EXPR_EXTHDR_TYPE);
	}
	if (tb[NFTA_EXTHDR_OFFSET]) {
		exthdr->offset = ntohl(mnl_attr_get_u32(tb[NFTA_EXTHDR_OFFSET]));
		e->flags |= (1 << NFT_EXPR_EXTHDR_OFFSET);
	}
	if (tb[NFTA_EXTHDR_LEN]) {
		exthdr->len = ntohl(mnl_attr_get_u32(tb[NFTA_EXTHDR_LEN]));
		e->flags |= (1 << NFT_EXPR_EXTHDR_LEN);
	}

	return 0;
}

static const char *exthdr_type2str(uint32_t type)
{
	switch (type) {
	case IPPROTO_HOPOPTS:
		return "hopopts";
	case IPPROTO_ROUTING:
		return "routing";
	case IPPROTO_FRAGMENT:
		return "fragment";
	case IPPROTO_DSTOPTS:
		return "dstopts";
	case IPPROTO_MH:
		return "mh";
	default:
		return "unknown";
	}
}

static inline int str2exthdr_type(char *str)
{
	if (strcmp(str, "hopopts") == 0)
		return IPPROTO_HOPOPTS;
	else if (strcmp(str, "routing") == 0)
		return IPPROTO_ROUTING;
	else if (strcmp(str, "fragment") == 0)
		return IPPROTO_FRAGMENT;
	else if (strcmp(str, "dstopts") == 0)
		return IPPROTO_DSTOPTS;
	else if (strcmp(str, "mh") == 0)
		return IPPROTO_MH;

	return -1;
}


static int
nft_rule_expr_exthdr_xml_parse(struct nft_rule_expr *e, mxml_node_t *tree)
{
#ifdef XML_PARSING
	struct nft_expr_exthdr *exthdr = (struct nft_expr_exthdr *)e->data;
	mxml_node_t *node = NULL;
	uint64_t tmp;
	char *endptr;
	int32_t reg;
	int type;

	reg = nft_mxml_reg_parse(tree, "dreg", MXML_DESCEND_FIRST);
	if (reg < 0)
		return -1;

	exthdr->dreg = reg;
	e->flags |= (1 << NFT_EXPR_EXTHDR_DREG);

	/* Get and set <exthdr_type> */
	node = mxmlFindElement(tree, tree, "exthdr_type", NULL, NULL,
			       MXML_DESCEND);
	if (node == NULL)
		return -1;

	type = str2exthdr_type(node->child->value.opaque);
	if (type < 0)
		return -1;

	exthdr->type = type;
	e->flags |= (1 << NFT_EXPR_EXTHDR_TYPE);

	/* Get and set <offset> */
	node = mxmlFindElement(tree, tree, "offset", NULL, NULL,
			       MXML_DESCEND);
	if (node == NULL)
		return -1;

	tmp = strtoull(node->child->value.opaque, &endptr, 10);
	if (tmp > UINT_MAX || tmp < 0 || *endptr)
		return -1;

	exthdr->offset = tmp;
	e->flags |= (1 << NFT_EXPR_EXTHDR_OFFSET);

	/* Get and set <len> */
	node = mxmlFindElement(tree, tree, "len", NULL, NULL, MXML_DESCEND);
	if (node == NULL)
		return -1;

	tmp = strtoull(node->child->value.opaque, &endptr, 10);
	if (tmp > UINT_MAX || tmp < 0 || *endptr)
		return -1;

	exthdr->len = tmp;
	e->flags |= (1 << NFT_EXPR_EXTHDR_LEN);

	return 0;
#else
	errno = EOPNOTSUPP;
	return -1;
#endif
}

static int
nft_rule_expr_exthdr_snprintf(char *buf, size_t len, uint32_t type,
			       uint32_t flags, struct nft_rule_expr *e)
{
	struct nft_expr_exthdr *exthdr = (struct nft_expr_exthdr *)e->data;

	switch(type) {
	case NFT_RULE_O_DEFAULT:
		return snprintf(buf, len, "dreg=%u type=%u offset=%u len=%u ",
				exthdr->dreg, exthdr->type,
				exthdr->offset, exthdr->len);
	case NFT_RULE_O_XML:
		return snprintf(buf, len, "<dreg>%u</dreg>"
					  "<exthdr_type>%s</exthdr_type>"
					  "<offset>%u</offset>"
					  "<len>%u</len>",
					exthdr->dreg,
					exthdr_type2str(exthdr->type),
					exthdr->offset, exthdr->len);
	case NFT_RULE_O_JSON:
		return snprintf(buf, len, "\"dreg\" : %u, "
					  "\"exthdr_type\" : \"%s\", \"offset\" : %u, "
					  "\"len\" : %u",
					exthdr->dreg,
					exthdr_type2str(exthdr->type),
					exthdr->offset, exthdr->len);
	default:
		break;
	}
	return -1;
}

struct expr_ops expr_ops_exthdr = {
	.name		= "exthdr",
	.alloc_len	= sizeof(struct nft_expr_exthdr),
	.max_attr	= NFTA_EXTHDR_MAX,
	.set		= nft_rule_expr_exthdr_set,
	.get		= nft_rule_expr_exthdr_get,
	.parse		= nft_rule_expr_exthdr_parse,
	.build		= nft_rule_expr_exthdr_build,
	.snprintf	= nft_rule_expr_exthdr_snprintf,
	.xml_parse	= nft_rule_expr_exthdr_xml_parse,
};
