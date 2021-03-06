/*
 * (C) 2014 by Arturo Borrero Gonzalez <arturo.borrero.glez@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>

#include <linux/netfilter/nf_tables.h>

#include "internal.h"
#include <libmnl/libmnl.h>
#include <libnftnl/expr.h>
#include <libnftnl/rule.h>

struct nft_expr_masq {
	uint32_t	flags;
};

static int
nft_rule_expr_masq_set(struct nft_rule_expr *e, uint16_t type,
		       const void *data, uint32_t data_len)
{
	struct nft_expr_masq *masq = nft_expr_data(e);

	switch (type) {
	case NFT_EXPR_MASQ_FLAGS:
		masq->flags = *((uint32_t *)data);
		break;
	default:
		return -1;
	}
	return 0;
}

static const void *
nft_rule_expr_masq_get(const struct nft_rule_expr *e, uint16_t type,
		       uint32_t *data_len)
{
	struct nft_expr_masq *masq = nft_expr_data(e);

	switch (type) {
	case NFT_EXPR_MASQ_FLAGS:
		*data_len = sizeof(masq->flags);
		return &masq->flags;
	}
	return NULL;
}

static int nft_rule_expr_masq_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, NFTA_MASQ_MAX) < 0)
		return MNL_CB_OK;

	switch (type) {
	case NFTA_MASQ_FLAGS:
		if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0)
			abi_breakage();
		break;
	}

	tb[type] = attr;
	return MNL_CB_OK;
}

static void
nft_rule_expr_masq_build(struct nlmsghdr *nlh, struct nft_rule_expr *e)
{
	struct nft_expr_masq *masq = nft_expr_data(e);

	if (e->flags & (1 << NFT_EXPR_MASQ_FLAGS))
		mnl_attr_put_u32(nlh, NFTA_MASQ_FLAGS, htobe32(masq->flags));
}

static int
nft_rule_expr_masq_parse(struct nft_rule_expr *e, struct nlattr *attr)
{
	struct nft_expr_masq *masq = nft_expr_data(e);
	struct nlattr *tb[NFTA_MASQ_MAX+1] = {};

	if (mnl_attr_parse_nested(attr, nft_rule_expr_masq_cb, tb) < 0)
		return -1;

	if (tb[NFTA_MASQ_FLAGS]) {
		masq->flags = be32toh(mnl_attr_get_u32(tb[NFTA_MASQ_FLAGS]));
		e->flags |= (1 << NFT_EXPR_MASQ_FLAGS);
	}

	return 0;
}

static int
nft_rule_expr_masq_json_parse(struct nft_rule_expr *e, json_t *root,
			      struct nft_parse_err *err)
{
#ifdef JSON_PARSING
	uint32_t flags;

	if (nft_jansson_parse_val(root, "flags", NFT_TYPE_U32, &flags,
				  err) == 0)
		nft_rule_expr_set_u32(e, NFT_EXPR_MASQ_FLAGS, flags);

	return 0;
#else
	errno = EOPNOTSUPP;
	return -1;
#endif
}

static int
nft_rule_expr_masq_xml_parse(struct nft_rule_expr *e, mxml_node_t *tree,
			     struct nft_parse_err *err)
{
#ifdef XML_PARSING
	uint32_t flags;

	if (nft_mxml_num_parse(tree, "flags", MXML_DESCEND_FIRST, BASE_DEC,
			       &flags, NFT_TYPE_U32, NFT_XML_MAND, err) == 0)
		nft_rule_expr_set_u32(e, NFT_EXPR_MASQ_FLAGS, flags);

	return 0;
#else
	errno = EOPNOTSUPP;
	return -1;
#endif
}
static int nft_rule_expr_masq_export(char *buf, size_t size,
				     struct nft_rule_expr *e, int type)
{
	struct nft_expr_masq *masq = nft_expr_data(e);
	NFT_BUF_INIT(b, buf, size);

	if (e->flags & (1 << NFT_EXPR_MASQ_FLAGS))
		nft_buf_u32(&b, type, masq->flags, FLAGS);

	return nft_buf_done(&b);
}

static int nft_rule_expr_masq_snprintf_default(char *buf, size_t len,
					       struct nft_rule_expr *e)
{
	struct nft_expr_masq *masq = nft_expr_data(e);

	if (e->flags & (1 << NFT_EXPR_MASQ_FLAGS))
		return snprintf(buf, len, "flags 0x%x ", masq->flags);

	return 0;
}

static int nft_rule_expr_masq_snprintf(char *buf, size_t len, uint32_t type,
				       uint32_t flags, struct nft_rule_expr *e)
{
	switch (type) {
	case NFT_OUTPUT_DEFAULT:
		return nft_rule_expr_masq_snprintf_default(buf, len, e);
	case NFT_OUTPUT_XML:
	case NFT_OUTPUT_JSON:
		return nft_rule_expr_masq_export(buf, len, e, type);
	default:
		break;
	}
	return -1;
}

struct expr_ops expr_ops_masq = {
	.name		= "masq",
	.alloc_len	= sizeof(struct nft_expr_masq),
	.max_attr	= NFTA_MASQ_MAX,
	.set		= nft_rule_expr_masq_set,
	.get		= nft_rule_expr_masq_get,
	.parse		= nft_rule_expr_masq_parse,
	.build		= nft_rule_expr_masq_build,
	.snprintf	= nft_rule_expr_masq_snprintf,
	.xml_parse	= nft_rule_expr_masq_xml_parse,
	.json_parse	= nft_rule_expr_masq_json_parse,
};

static void __init expr_masq_init(void)
{
	nft_expr_ops_register(&expr_ops_masq);
}
