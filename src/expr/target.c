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

#include <libnftnl/expr.h>
#include <libnftnl/rule.h>

#include "expr_ops.h"

/* From include/linux/netfilter/x_tables.h */
#define XT_EXTENSION_MAXNAMELEN 29

struct nft_expr_target {
	char		name[XT_EXTENSION_MAXNAMELEN];
	uint32_t	rev;
	uint32_t	data_len;
	const void	*data;
};

static int
nft_rule_expr_target_set(struct nft_rule_expr *e, uint16_t type,
			 const void *data, uint32_t data_len)
{
	struct nft_expr_target *tg = nft_expr_data(e);

	switch(type) {
	case NFT_EXPR_TG_NAME:
		snprintf(tg->name, sizeof(tg->name), "%.*s", data_len,
			 (const char *) data);
		break;
	case NFT_EXPR_TG_REV:
		tg->rev = *((uint32_t *)data);
		break;
	case NFT_EXPR_TG_INFO:
		if (tg->data)
			xfree(tg->data);

		tg->data = data;
		tg->data_len = data_len;
		break;
	default:
		return -1;
	}
	return 0;
}

static const void *
nft_rule_expr_target_get(const struct nft_rule_expr *e, uint16_t type,
			 uint32_t *data_len)
{
	struct nft_expr_target *tg = nft_expr_data(e);

	switch(type) {
	case NFT_EXPR_TG_NAME:
		*data_len = sizeof(tg->name);
		return tg->name;
	case NFT_EXPR_TG_REV:
		*data_len = sizeof(tg->rev);
		return &tg->rev;
	case NFT_EXPR_TG_INFO:
		*data_len = tg->data_len;
		return tg->data;
	}
	return NULL;
}

static int nft_rule_expr_target_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, NFTA_TARGET_MAX) < 0)
		return MNL_CB_OK;

	switch(type) {
	case NFTA_TARGET_NAME:
		if (mnl_attr_validate(attr, MNL_TYPE_NUL_STRING) < 0)
			abi_breakage();
		break;
	case NFTA_TARGET_REV:
		if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0)
			abi_breakage();
		break;
	case NFTA_TARGET_INFO:
		if (mnl_attr_validate(attr, MNL_TYPE_BINARY) < 0)
			abi_breakage();
		break;
	}

	tb[type] = attr;
	return MNL_CB_OK;
}

static void
nft_rule_expr_target_build(struct nlmsghdr *nlh, struct nft_rule_expr *e)
{
	struct nft_expr_target *tg = nft_expr_data(e);

	if (e->flags & (1 << NFT_EXPR_TG_NAME))
		mnl_attr_put_strz(nlh, NFTA_TARGET_NAME, tg->name);
	if (e->flags & (1 << NFT_EXPR_TG_REV))
		mnl_attr_put_u32(nlh, NFTA_TARGET_REV, htonl(tg->rev));
	if (e->flags & (1 << NFT_EXPR_TG_INFO))
		mnl_attr_put(nlh, NFTA_TARGET_INFO, tg->data_len, tg->data);
}

static int nft_rule_expr_target_parse(struct nft_rule_expr *e, struct nlattr *attr)
{
	struct nft_expr_target *target = nft_expr_data(e);
	struct nlattr *tb[NFTA_TARGET_MAX+1] = {};

	if (mnl_attr_parse_nested(attr, nft_rule_expr_target_cb, tb) < 0)
		return -1;

	if (tb[NFTA_TARGET_NAME]) {
		snprintf(target->name, XT_EXTENSION_MAXNAMELEN, "%s",
			 mnl_attr_get_str(tb[NFTA_TARGET_NAME]));

		target->name[XT_EXTENSION_MAXNAMELEN-1] = '\0';
		e->flags |= (1 << NFT_EXPR_TG_NAME);
	}

	if (tb[NFTA_TARGET_REV]) {
		target->rev = ntohl(mnl_attr_get_u32(tb[NFTA_TARGET_REV]));
		e->flags |= (1 << NFT_EXPR_TG_REV);
	}

	if (tb[NFTA_TARGET_INFO]) {
		uint32_t len = mnl_attr_get_payload_len(tb[NFTA_TARGET_INFO]);
		void *target_data;

		if (target->data)
			xfree(target->data);

		target_data = calloc(1, len);
		if (target_data == NULL)
			return -1;

		memcpy(target_data, mnl_attr_get_payload(tb[NFTA_TARGET_INFO]), len);

		target->data = target_data;
		target->data_len = len;

		e->flags |= (1 << NFT_EXPR_TG_INFO);
	}

	return 0;
}

static int
nft_rule_expr_target_json_parse(struct nft_rule_expr *e, json_t *root,
				struct nft_parse_err *err)
{
#ifdef JSON_PARSING
	const char *name;

	name = nft_jansson_parse_str(root, "name", err);
	if (name != NULL)
		nft_rule_expr_set_str(e, NFT_EXPR_TG_NAME, name);

	return 0;
#else
	errno = EOPNOTSUPP;
	return -1;
#endif
}

static int
nft_rule_expr_target_xml_parse(struct nft_rule_expr *e, mxml_node_t *tree,
			       struct nft_parse_err *err)
{
#ifdef XML_PARSING
	const char *name;

	name = nft_mxml_str_parse(tree, "name", MXML_DESCEND_FIRST,
				  NFT_XML_MAND, err);
	if (name != NULL)
		nft_rule_expr_set_str(e, NFT_EXPR_TG_NAME, name);

	/* tg->info is ignored until other solution is reached */

	return 0;
#else
	errno = EOPNOTSUPP;
	return -1;
#endif
}

static int nft_rule_exp_target_snprintf_json(char *buf, size_t len,
					     struct nft_rule_expr *e)
{
	struct nft_expr_target *target = nft_expr_data(e);
	int ret, size = len, offset = 0;

	if (e->flags & (1 << NFT_EXPR_TG_NAME)) {
		ret = snprintf(buf, len, "\"name\":\"%s\"", target->name);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	return offset;
}

static int nft_rule_exp_target_snprintf_xml(char *buf, size_t len,
					    struct nft_rule_expr *e)
{
	struct nft_expr_target *target = nft_expr_data(e);
	int ret, size=len;
	int offset = 0;

	if (e->flags & (1 << NFT_EXPR_TG_NAME)) {
		ret = snprintf(buf, len, "<name>%s</name>", target->name);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	return offset;
}

static int
nft_rule_expr_target_snprintf(char *buf, size_t len, uint32_t type,
			      uint32_t flags, struct nft_rule_expr *e)
{
	struct nft_expr_target *target = nft_expr_data(e);

	switch(type) {
	case NFT_OUTPUT_DEFAULT:
		return snprintf(buf, len, "name %s rev %u ",
				target->name, target->rev);
	case NFT_OUTPUT_XML:
		return nft_rule_exp_target_snprintf_xml(buf, len, e);
	case NFT_OUTPUT_JSON:
		return nft_rule_exp_target_snprintf_json(buf, len, e);
	default:
		break;
	}
	return -1;
}

static void nft_rule_expr_target_free(struct nft_rule_expr *e)
{
	struct nft_expr_target *target = nft_expr_data(e);

	xfree(target->data);
}

struct expr_ops expr_ops_target = {
	.name		= "target",
	.alloc_len	= sizeof(struct nft_expr_target),
	.max_attr	= NFTA_TARGET_MAX,
	.free		= nft_rule_expr_target_free,
	.set		= nft_rule_expr_target_set,
	.get		= nft_rule_expr_target_get,
	.parse		= nft_rule_expr_target_parse,
	.build		= nft_rule_expr_target_build,
	.snprintf	= nft_rule_expr_target_snprintf,
	.xml_parse	= nft_rule_expr_target_xml_parse,
	.json_parse	= nft_rule_expr_target_json_parse,
};

static void __init expr_target_init(void)
{
	nft_expr_ops_register(&expr_ops_target);
}
