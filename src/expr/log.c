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
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include <errno.h>
#include <linux/netfilter/nf_tables.h>

#include "internal.h"
#include <libmnl/libmnl.h>
#include <libnftables/expr.h>
#include <libnftables/rule.h>
#include "expr_ops.h"

struct nft_expr_log {
	uint32_t		snaplen;
	uint16_t		group;
	uint16_t		qthreshold;
	const char		*prefix;
};

static int nft_rule_expr_log_set(struct nft_rule_expr *e, uint16_t type,
				 const void *data, size_t data_len)
{
	struct nft_expr_log *log = nft_expr_data(e);

	switch(type) {
	case NFT_EXPR_LOG_PREFIX:
		if (log->prefix)
			xfree(log->prefix);

		log->prefix = strdup(data);
		break;
	case NFT_EXPR_LOG_GROUP:
		log->group = *((uint16_t *)data);
		break;
	case NFT_EXPR_LOG_SNAPLEN:
		log->snaplen = *((uint32_t *)data);
		break;
	case NFT_EXPR_LOG_QTHRESHOLD:
		log->qthreshold = *((uint16_t *)data);
		break;
	default:
		return -1;
	}
	return 0;
}

static const void *
nft_rule_expr_log_get(const struct nft_rule_expr *e, uint16_t type,
		      size_t *data_len)
{
	struct nft_expr_log *log = nft_expr_data(e);

	switch(type) {
	case NFT_EXPR_LOG_PREFIX:
		return log->prefix;
	case NFT_EXPR_LOG_GROUP:
		return &log->group;
	case NFT_EXPR_LOG_SNAPLEN:
		return &log->snaplen;
	case NFT_EXPR_LOG_QTHRESHOLD:
		return &log->qthreshold;
	}
	return NULL;
}

static int nft_rule_expr_log_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, NFTA_LOG_MAX) < 0)
		return MNL_CB_OK;

	switch(type) {
	case NFTA_LOG_PREFIX:
		if (mnl_attr_validate(attr, MNL_TYPE_STRING) < 0) {
			perror("mnl_attr_validate");
			return MNL_CB_ERROR;
		}
		break;
	case NFTA_LOG_GROUP:
	case NFTA_LOG_SNAPLEN:
		if (mnl_attr_validate(attr, MNL_TYPE_U16) < 0) {
			perror("mnl_attr_validate");
			return MNL_CB_ERROR;
		}
		break;
	case NFTA_LOG_QTHRESHOLD:
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
nft_rule_expr_log_build(struct nlmsghdr *nlh, struct nft_rule_expr *e)
{
	struct nft_expr_log *log = nft_expr_data(e);

	if (e->flags & (1 << NFT_EXPR_LOG_PREFIX))
		mnl_attr_put_str(nlh, NFTA_LOG_PREFIX, log->prefix);
	if (e->flags & (1 << NFT_EXPR_LOG_GROUP))
		mnl_attr_put_u16(nlh, NFTA_LOG_GROUP, htons(log->group));
	if (e->flags & (1 << NFT_EXPR_LOG_SNAPLEN))
		mnl_attr_put_u32(nlh, NFTA_LOG_SNAPLEN, htonl(log->snaplen));
	if (e->flags & (1 << NFT_EXPR_LOG_QTHRESHOLD))
		mnl_attr_put_u16(nlh, NFTA_LOG_QTHRESHOLD, htons(log->qthreshold));
}

static int
nft_rule_expr_log_parse(struct nft_rule_expr *e, struct nlattr *attr)
{
	struct nft_expr_log *log = nft_expr_data(e);
	struct nlattr *tb[NFTA_LOG_MAX+1] = {};

	if (mnl_attr_parse_nested(attr, nft_rule_expr_log_cb, tb) < 0)
		return -1;

	if (tb[NFTA_LOG_PREFIX]) {
		if (log->prefix)
			xfree(log->prefix);

		log->prefix = strdup(mnl_attr_get_str(tb[NFTA_LOG_PREFIX]));
		e->flags |= (1 << NFT_EXPR_LOG_GROUP);
	}
	if (tb[NFTA_LOG_GROUP]) {
		log->group = ntohs(mnl_attr_get_u16(tb[NFTA_LOG_GROUP]));
		e->flags |= (1 << NFT_EXPR_LOG_GROUP);
	}
	if (tb[NFTA_LOG_SNAPLEN]) {
		log->snaplen = ntohl(mnl_attr_get_u32(tb[NFTA_LOG_SNAPLEN]));
		e->flags |= (1 << NFT_EXPR_LOG_SNAPLEN);
	}
	if (tb[NFTA_LOG_QTHRESHOLD]) {
		log->qthreshold = ntohs(mnl_attr_get_u16(tb[NFTA_LOG_QTHRESHOLD]));
		e->flags |= (1 << NFT_EXPR_LOG_QTHRESHOLD);
	}

	return 0;
}

static int nft_rule_expr_log_xml_parse(struct nft_rule_expr *e, mxml_node_t *tree)
{
#ifdef XML_PARSING
	struct nft_expr_log *log = nft_expr_data(e);
	const char *prefix;

	prefix = nft_mxml_str_parse(tree, "prefix", MXML_DESCEND_FIRST);
	if (prefix == NULL)
		return -1;

	log->prefix = strdup(prefix);
	e->flags |= (1 << NFT_EXPR_LOG_PREFIX);

	if (nft_mxml_num_parse(tree, "group", MXML_DESCEND_FIRST, BASE_DEC,
			       &log->group, NFT_TYPE_U16) != 0)
		return -1;

	e->flags |= (1 << NFT_EXPR_LOG_GROUP);

	if (nft_mxml_num_parse(tree, "snaplen", MXML_DESCEND_FIRST, BASE_DEC,
			       &log->snaplen, NFT_TYPE_U32) != 0)
		return -1;

	e->flags |= (1 << NFT_EXPR_LOG_SNAPLEN);

	if (nft_mxml_num_parse(tree, "qthreshold", MXML_DESCEND_FIRST,
			       BASE_DEC, &log->qthreshold, NFT_TYPE_U16) != 0)
		return -1;

	e->flags |= (1 << NFT_EXPR_LOG_QTHRESHOLD);

	return 0;
#else
	errno = EOPNOTSUPP;
	return -1;
#endif
}

static int
nft_rule_expr_log_snprintf(char *buf, size_t len, uint32_t type,
			    uint32_t flags, struct nft_rule_expr *e)
{
	struct nft_expr_log *log = nft_expr_data(e);

	switch(type) {
	case NFT_RULE_O_DEFAULT:
		return snprintf(buf, len, "prefix '%s' group %u "
					  "snaplen %u qthreshold %u ",
				log->prefix, log->group,
				log->snaplen, log->qthreshold);
	case NFT_RULE_O_XML:
		return snprintf(buf, len, "<prefix>%s</prefix>"
					  "<group>%u</group>"
					  "<snaplen>%u</snaplen>"
					  "<qthreshold>%u</qthreshold>",
				log->prefix, log->group,
				log->snaplen, log->qthreshold);
	case NFT_RULE_O_JSON:
		return snprintf(buf, len, "\"prefix\" : \"%s\", "
					  "\"group\" : %u, "
					  "\"snaplen\" : %u, "
					  "\"qthreshold\" : %u ",
				log->prefix, log->group,
				log->snaplen, log->qthreshold);
	default:
		break;
	}
	return -1;
}

struct expr_ops expr_ops_log = {
	.name		= "log",
	.alloc_len	= sizeof(struct nft_expr_log),
	.max_attr	= NFTA_LOG_MAX,
	.set		= nft_rule_expr_log_set,
	.get		= nft_rule_expr_log_get,
	.parse		= nft_rule_expr_log_parse,
	.build		= nft_rule_expr_log_build,
	.snprintf	= nft_rule_expr_log_snprintf,
	.xml_parse	= nft_rule_expr_log_xml_parse,
};

static void __init expr_log_init(void)
{
	nft_expr_ops_register(&expr_ops_log);
}
