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
#include "internal.h"
#include <libmnl/libmnl.h>
#include <linux/netfilter/nf_tables.h>
#include <libnftables/expr.h>
#include <libnftables/rule.h>
#include "expr_ops.h"
#include "data_reg.h"

struct nft_expr_immediate {
	union nft_data_reg	data;
	enum nft_registers	dreg;
};

static int
nft_rule_expr_immediate_set(struct nft_rule_expr *e, uint16_t type,
			    const void *data, size_t data_len)
{
	struct nft_expr_immediate *imm = (struct nft_expr_immediate *)e->data;

	switch(type) {
	case NFT_EXPR_IMM_DREG:
		imm->dreg = *((uint32_t *)data);
		break;
	case NFT_EXPR_IMM_DATA:
		memcpy(&imm->data.val, data, data_len);
		imm->data.len = data_len;
		break;
	case NFT_EXPR_IMM_VERDICT:
		imm->data.verdict = *((uint32_t *)data);
		break;
	case NFT_EXPR_IMM_CHAIN:
		if (imm->data.chain)
			free(imm->data.chain);

		imm->data.chain = strdup(data);
		break;
	default:
		return -1;
	}
	return 0;
}

static const void *
nft_rule_expr_immediate_get(const struct nft_rule_expr *e, uint16_t type,
			    size_t *data_len)
{
	struct nft_expr_immediate *imm = (struct nft_expr_immediate *)e->data;

	switch(type) {
	case NFT_EXPR_IMM_DREG:
		if (e->flags & (1 << NFT_EXPR_IMM_DREG)) {
			*data_len = sizeof(imm->dreg);
			return &imm->dreg;
		} else
			return NULL;
		break;
	case NFT_EXPR_IMM_DATA:
		if (e->flags & (1 << NFT_EXPR_IMM_DATA)) {
			*data_len = imm->data.len;
			return &imm->data.val;
		} else
			return NULL;
		break;
	case NFT_EXPR_IMM_VERDICT:
		if (e->flags & (1 << NFT_EXPR_IMM_VERDICT)) {
			*data_len = sizeof(imm->data.verdict);
			return &imm->data.verdict;
		} else
			return NULL;
		break;
	case NFT_EXPR_IMM_CHAIN:
		if (e->flags & (1 << NFT_EXPR_IMM_CHAIN)) {
			*data_len = strlen(imm->data.chain)+1;
			return imm->data.chain;
		} else
			return NULL;
		break;
	default:
		break;
	}
	return NULL;
}

static int nft_rule_expr_immediate_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, NFTA_IMMEDIATE_MAX) < 0)
		return MNL_CB_OK;

	switch(type) {
	case NFTA_IMMEDIATE_DREG:
		if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0) {
			perror("mnl_attr_validate");
			return MNL_CB_ERROR;
		}
		break;
	case NFTA_IMMEDIATE_DATA:
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
nft_rule_expr_immediate_build(struct nlmsghdr *nlh, struct nft_rule_expr *e)
{
	struct nft_expr_immediate *imm = (struct nft_expr_immediate *)e->data;

	if (e->flags & (1 << NFT_EXPR_IMM_DREG))
		mnl_attr_put_u32(nlh, NFTA_IMMEDIATE_DREG, htonl(imm->dreg));

	/* Sane configurations allows you to set ONLY one of these two below */
	if (e->flags & (1 << NFT_EXPR_IMM_DATA)) {
		struct nlattr *nest;

		nest = mnl_attr_nest_start(nlh, NFTA_IMMEDIATE_DATA);
		mnl_attr_put(nlh, NFTA_DATA_VALUE, imm->data.len, imm->data.val);
		mnl_attr_nest_end(nlh, nest);

	} else if (e->flags & (1 << NFT_EXPR_IMM_VERDICT)) {
		struct nlattr *nest1, *nest2;

		nest1 = mnl_attr_nest_start(nlh, NFTA_IMMEDIATE_DATA);
		nest2 = mnl_attr_nest_start(nlh, NFTA_DATA_VERDICT);
		mnl_attr_put_u32(nlh, NFTA_VERDICT_CODE, htonl(imm->data.verdict));
		if (e->flags & (1 << NFT_EXPR_IMM_CHAIN))
			mnl_attr_put_strz(nlh, NFTA_VERDICT_CHAIN, imm->data.chain);

		mnl_attr_nest_end(nlh, nest1);
		mnl_attr_nest_end(nlh, nest2);
	}
}

static int
nft_rule_expr_immediate_parse(struct nft_rule_expr *e, struct nlattr *attr)
{
	struct nft_expr_immediate *imm = (struct nft_expr_immediate *)e->data;
	struct nlattr *tb[NFTA_IMMEDIATE_MAX+1] = {};
	int ret = 0;

	if (mnl_attr_parse_nested(attr, nft_rule_expr_immediate_cb, tb) < 0)
		return -1;

	if (tb[NFTA_IMMEDIATE_DREG]) {
		imm->dreg = ntohl(mnl_attr_get_u32(tb[NFTA_IMMEDIATE_DREG]));
		e->flags |= (1 << NFT_EXPR_IMM_DREG);
	}
	if (tb[NFTA_IMMEDIATE_DATA]) {
		int type;

		ret = nft_parse_data(&imm->data, tb[NFTA_IMMEDIATE_DATA], &type);
		if (ret < 0)
			return ret;

		switch(type) {
		case DATA_VALUE:
			/* real immediate data to be loaded to destination */
			e->flags |= (1 << NFT_EXPR_IMM_DATA);
			break;
		case DATA_VERDICT:
			/* NF_ACCEPT, NF_DROP, NF_QUEUE and NFT_RETURN case */
			e->flags |= (1 << NFT_EXPR_IMM_VERDICT);
			break;
		case DATA_CHAIN:
			/* NFT_GOTO and NFT_JUMP case */
			e->flags |= (1 << NFT_EXPR_IMM_VERDICT) |
				    (1 << NFT_EXPR_IMM_CHAIN);
			break;
		}
	}

	return ret;
}

static int
nft_rule_expr_immediate_xml_parse(struct nft_rule_expr *e, char *xml)
{
#ifdef XML_PARSING
	struct nft_expr_immediate *imm = (struct nft_expr_immediate *)e->data;
	mxml_node_t *tree = NULL;
	mxml_node_t *node = NULL;
	mxml_node_t *save = NULL;
	union nft_data_reg data_regtmp;
	uint64_t tmp;
	char *endptr;

	/* load the tree */
	tree = mxmlLoadString(NULL, xml, MXML_OPAQUE_CALLBACK);
	if (tree == NULL)
		return -1;

	if (mxmlElementGetAttr(tree, "type") == NULL) {
		mxmlDelete(tree);
		return -1;
	}

	if (strcmp("immediate", mxmlElementGetAttr(tree, "type")) != 0) {
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
	if (tmp > UINT32_MAX || tmp < 0 || *endptr) {
		mxmlDelete(tree);
		return -1;
	}

	imm->dreg = (uint32_t)tmp;
	e->flags |= (1 << NFT_EXPR_IMM_DREG);

	/* Get and set <immdata>. Is mandatory */
	node = mxmlFindElement(tree, tree, "immdata", NULL, NULL,
			       MXML_DESCEND);
	if (node == NULL) {
		mxmlDelete(tree);
		return -1;
	}

	/* hack for mxmSaveAllocString to print just the current node */
	save = node->next;
	node->next = NULL;

	if (nft_data_reg_xml_parse(&data_regtmp,
			mxmlSaveAllocString(node, MXML_NO_CALLBACK)) < 0) {
		mxmlDelete(tree);
		return -1;
	}
	node->next = save;

	/* data_reg type switch */
	node = mxmlFindElement(tree, tree, "data_reg", NULL, NULL,
			       MXML_DESCEND);
	if (node == NULL) {
		mxmlDelete(tree);
		return -1;
	}

	if (mxmlElementGetAttr(node, "type") == NULL) {
		mxmlDelete(tree);
		return -1;
	}

	if (strcmp(mxmlElementGetAttr(node, "type"), "value") == 0) {
		memcpy(&imm->data.val, data_regtmp.val, data_regtmp.len);
		imm->data.len = data_regtmp.len;
		e->flags |= (1 << NFT_EXPR_IMM_DATA);
	} else if (strcmp(mxmlElementGetAttr(node, "type"), "verdict") == 0) {
		imm->data.verdict = data_regtmp.verdict;
		e->flags |= (1 << NFT_EXPR_IMM_VERDICT);
	} else if (strcmp(mxmlElementGetAttr(node, "type"), "chain") == 0) {
		if (imm->data.chain)
			free(imm->data.chain);

		imm->data.chain = strdup(data_regtmp.chain);
		e->flags |= (1 << NFT_EXPR_IMM_CHAIN);
	}

	mxmlDelete(tree);
	return 0;
#else
	errno = EOPNOTSUPP;
	return -1;
#endif
}

static int
nft_rule_expr_immediate_snprintf_xml(char *buf, size_t len,
				     struct nft_rule_expr *e, uint32_t flags)
{
	int size = len, offset = 0, ret;
	struct nft_expr_immediate *imm = (struct nft_expr_immediate *)e->data;

	ret = snprintf(buf, len, "<dreg>%u</dreg>"
				"<immediatedata>", imm->dreg);
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);


	if (e->flags & (1 << NFT_EXPR_IMM_DATA)) {
		ret = nft_data_reg_snprintf(buf+offset, len, &imm->data,
					    NFT_RULE_O_XML, flags, DATA_VALUE);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	} else if (e->flags & (1 << NFT_EXPR_IMM_VERDICT)) {
		ret = nft_data_reg_snprintf(buf+offset, len, &imm->data,
					  NFT_RULE_O_XML, flags, DATA_VERDICT);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	} else if (e->flags & (1 << NFT_EXPR_IMM_CHAIN)) {
		ret = nft_data_reg_snprintf(buf+offset, len, &imm->data,
					    NFT_RULE_O_XML, flags, DATA_CHAIN);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	ret = snprintf(buf+offset, len, "</immediatedata>");
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	return offset;
}

static int
nft_rule_expr_immediate_snprintf_default(char *buf, size_t len,
				struct nft_rule_expr *e, uint32_t flags)
{
	int size = len, offset = 0, ret;
	struct nft_expr_immediate *imm = (struct nft_expr_immediate *)e->data;

	ret = snprintf(buf, len, "dreg=%u ", imm->dreg);
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	if (e->flags & (1 << NFT_EXPR_IMM_DATA)) {
		ret = nft_data_reg_snprintf(buf+offset, len, &imm->data,
					NFT_RULE_O_DEFAULT, flags, DATA_VALUE);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	} else if (e->flags & (1 << NFT_EXPR_IMM_VERDICT)) {
		ret = nft_data_reg_snprintf(buf+offset, len, &imm->data,
				NFT_RULE_O_DEFAULT, flags, DATA_VERDICT);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	} else if (e->flags & (1 << NFT_EXPR_IMM_CHAIN)) {
		ret = nft_data_reg_snprintf(buf+offset, len, &imm->data,
					NFT_RULE_O_DEFAULT, flags, DATA_CHAIN);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	return offset;
}

static int
nft_rule_expr_immediate_snprintf(char *buf, size_t len, uint32_t type,
				 uint32_t flags, struct nft_rule_expr *e)
{
	switch(type) {
	case NFT_RULE_O_XML:
		return nft_rule_expr_immediate_snprintf_xml(buf, len, e, flags);
	case NFT_RULE_O_DEFAULT:
		return nft_rule_expr_immediate_snprintf_default(buf, len, e, flags);
	default:
		break;
	}
	return -1;
}

struct expr_ops expr_ops_immediate = {
	.name		= "immediate",
	.alloc_len	= sizeof(struct nft_expr_immediate),
	.max_attr	= NFTA_IMMEDIATE_MAX,
	.set		= nft_rule_expr_immediate_set,
	.get		= nft_rule_expr_immediate_get,
	.parse		= nft_rule_expr_immediate_parse,
	.build		= nft_rule_expr_immediate_build,
	.snprintf	= nft_rule_expr_immediate_snprintf,
	.xml_parse	= nft_rule_expr_immediate_xml_parse,
};
