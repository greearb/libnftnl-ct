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
#include <libnftnl/expr.h>
#include <libnftnl/rule.h>

struct nft_expr_log {
	uint32_t		snaplen;
	uint16_t		group;
	uint16_t		qthreshold;
	uint32_t		level;
	uint32_t		flags;
	const char		*prefix;
};

static int nft_rule_expr_log_set(struct nft_rule_expr *e, uint16_t type,
				 const void *data, uint32_t data_len)
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
	case NFT_EXPR_LOG_LEVEL:
		log->level = *((uint32_t *)data);
		break;
	case NFT_EXPR_LOG_FLAGS:
		log->flags = *((uint32_t *)data);
		break;
	default:
		return -1;
	}
	return 0;
}

static const void *
nft_rule_expr_log_get(const struct nft_rule_expr *e, uint16_t type,
		      uint32_t *data_len)
{
	struct nft_expr_log *log = nft_expr_data(e);

	switch(type) {
	case NFT_EXPR_LOG_PREFIX:
		*data_len = strlen(log->prefix)+1;
		return log->prefix;
	case NFT_EXPR_LOG_GROUP:
		*data_len = sizeof(log->group);
		return &log->group;
	case NFT_EXPR_LOG_SNAPLEN:
		*data_len = sizeof(log->snaplen);
		return &log->snaplen;
	case NFT_EXPR_LOG_QTHRESHOLD:
		*data_len = sizeof(log->qthreshold);
		return &log->qthreshold;
	case NFT_EXPR_LOG_LEVEL:
		*data_len = sizeof(log->level);
		return &log->level;
	case NFT_EXPR_LOG_FLAGS:
		*data_len = sizeof(log->flags);
		return &log->flags;
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
		if (mnl_attr_validate(attr, MNL_TYPE_STRING) < 0)
			abi_breakage();
		break;
	case NFTA_LOG_GROUP:
	case NFTA_LOG_QTHRESHOLD:
		if (mnl_attr_validate(attr, MNL_TYPE_U16) < 0)
			abi_breakage();
		break;
	case NFTA_LOG_SNAPLEN:
	case NFTA_LOG_LEVEL:
	case NFTA_LOG_FLAGS:
		if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0)
			abi_breakage();
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
		mnl_attr_put_strz(nlh, NFTA_LOG_PREFIX, log->prefix);
	if (e->flags & (1 << NFT_EXPR_LOG_GROUP))
		mnl_attr_put_u16(nlh, NFTA_LOG_GROUP, htons(log->group));
	if (e->flags & (1 << NFT_EXPR_LOG_SNAPLEN))
		mnl_attr_put_u32(nlh, NFTA_LOG_SNAPLEN, htonl(log->snaplen));
	if (e->flags & (1 << NFT_EXPR_LOG_QTHRESHOLD))
		mnl_attr_put_u16(nlh, NFTA_LOG_QTHRESHOLD, htons(log->qthreshold));
	if (e->flags & (1 << NFT_EXPR_LOG_LEVEL))
		mnl_attr_put_u32(nlh, NFTA_LOG_LEVEL, htonl(log->level));
	if (e->flags & (1 << NFT_EXPR_LOG_FLAGS))
		mnl_attr_put_u32(nlh, NFTA_LOG_FLAGS, htonl(log->flags));
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
		e->flags |= (1 << NFT_EXPR_LOG_PREFIX);
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
	if (tb[NFTA_LOG_LEVEL]) {
		log->level = ntohl(mnl_attr_get_u32(tb[NFTA_LOG_LEVEL]));
		e->flags |= (1 << NFT_EXPR_LOG_LEVEL);
	}
	if (tb[NFTA_LOG_FLAGS]) {
		log->flags = ntohl(mnl_attr_get_u32(tb[NFTA_LOG_FLAGS]));
		e->flags |= (1 << NFT_EXPR_LOG_FLAGS);
	}

	return 0;
}

static int nft_rule_expr_log_json_parse(struct nft_rule_expr *e, json_t *root,
					struct nft_parse_err *err)
{
#ifdef JSON_PARSING
	const char *prefix;
	uint32_t snaplen, level, flags;
	uint16_t group, qthreshold;

	prefix = nft_jansson_parse_str(root, "prefix", err);
	if (prefix != NULL)
		nft_rule_expr_set_str(e, NFT_EXPR_LOG_PREFIX, prefix);

	if (nft_jansson_parse_val(root, "group", NFT_TYPE_U16, &group,
				  err) == 0)
		nft_rule_expr_set_u16(e, NFT_EXPR_LOG_GROUP, group);

	if (nft_jansson_parse_val(root, "snaplen", NFT_TYPE_U32, &snaplen,
				  err) == 0)
		nft_rule_expr_set_u32(e, NFT_EXPR_LOG_SNAPLEN, snaplen);

	if (nft_jansson_parse_val(root, "qthreshold", NFT_TYPE_U16,
				  &qthreshold, err) == 0)
		nft_rule_expr_set_u16(e, NFT_EXPR_LOG_QTHRESHOLD, qthreshold);

	if (nft_jansson_parse_val(root, "level", NFT_TYPE_U32, &level,
				  err) == 0)
		nft_rule_expr_set_u32(e, NFT_EXPR_LOG_LEVEL, level);

	if (nft_jansson_parse_val(root, "flags", NFT_TYPE_U32, &flags,
				  err) == 0)
		nft_rule_expr_set_u32(e, NFT_EXPR_LOG_FLAGS, flags);

	return 0;
#else
	errno = EOPNOTSUPP;
	return -1;
#endif
}

static int nft_rule_expr_log_xml_parse(struct nft_rule_expr *e,
				       mxml_node_t *tree,
				       struct nft_parse_err *err)
{
#ifdef XML_PARSING
	const char *prefix;
	uint32_t snaplen, level, flags;
	uint16_t group, qthreshold;

	prefix = nft_mxml_str_parse(tree, "prefix", MXML_DESCEND_FIRST,
				    NFT_XML_MAND, err);
	if (prefix != NULL)
		nft_rule_expr_set_str(e, NFT_EXPR_LOG_PREFIX, prefix);

	if (nft_mxml_num_parse(tree, "group", MXML_DESCEND_FIRST, BASE_DEC,
			       &group, NFT_TYPE_U16, NFT_XML_MAND, err) == 0)
		nft_rule_expr_set_u16(e, NFT_EXPR_LOG_GROUP, group);

	if (nft_mxml_num_parse(tree, "snaplen", MXML_DESCEND_FIRST, BASE_DEC,
			       &snaplen, NFT_TYPE_U32, NFT_XML_MAND, err) == 0)
		nft_rule_expr_set_u32(e, NFT_EXPR_LOG_SNAPLEN, snaplen);

	if (nft_mxml_num_parse(tree, "qthreshold", MXML_DESCEND_FIRST, BASE_DEC,
			       &qthreshold, NFT_TYPE_U16, NFT_XML_MAND,
			       err) == 0)
		nft_rule_expr_set_u16(e, NFT_EXPR_LOG_QTHRESHOLD, qthreshold);

	if (nft_mxml_num_parse(tree, "level", MXML_DESCEND_FIRST, BASE_DEC,
			       &level, NFT_TYPE_U16, NFT_XML_MAND,
			       err) == 0)
		nft_rule_expr_set_u32(e, NFT_EXPR_LOG_LEVEL, level);

	if (nft_mxml_num_parse(tree, "flags", MXML_DESCEND_FIRST, BASE_DEC,
			       &flags, NFT_TYPE_U16, NFT_XML_MAND,
			       err) == 0)
		nft_rule_expr_set_u32(e, NFT_EXPR_LOG_FLAGS, flags);

	return 0;
#else
	errno = EOPNOTSUPP;
	return -1;
#endif
}

static int nft_rule_expr_log_snprintf_default(char *buf, size_t size,
					      struct nft_rule_expr *e)
{
	struct nft_expr_log *log = nft_expr_data(e);
	int ret, offset = 0, len = size;

	ret = snprintf(buf, len, "prefix %s ", log->prefix);
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	if (e->flags & (1 << NFT_EXPR_LOG_GROUP)) {
		ret = snprintf(buf + offset, len,
			       "group %u snaplen %u qthreshold %u",
			       log->group, log->snaplen, log->qthreshold);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	} else if (e->flags & (1 << NFT_EXPR_LOG_LEVEL)) {
		ret = snprintf(buf + offset, len, "level %u flags %u",
			       log->level, log->flags);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	return offset;
}

static int nft_rule_expr_log_export(char *buf, size_t size,
				    struct nft_rule_expr *e, int type)
{
	struct nft_expr_log *log = nft_expr_data(e);
	NFT_BUF_INIT(b, buf, size);

	if (e->flags & (1 << NFT_EXPR_LOG_PREFIX))
		nft_buf_str(&b, type, log->prefix, PREFIX);
	if (e->flags & (1 << NFT_EXPR_LOG_GROUP))
		nft_buf_u32(&b, type, log->group, GROUP);
	if (e->flags & (1 << NFT_EXPR_LOG_SNAPLEN))
		nft_buf_u32(&b, type, log->snaplen, SNAPLEN);
	if (e->flags & (1 << NFT_EXPR_LOG_QTHRESHOLD))
		nft_buf_u32(&b, type, log->qthreshold, QTHRESH);
	if (e->flags & (1 << NFT_EXPR_LOG_LEVEL))
		nft_buf_u32(&b, type, log->level, LEVEL);
	if (e->flags & (1 << NFT_EXPR_LOG_FLAGS))
		nft_buf_u32(&b, type, log->level, FLAGS);

	return nft_buf_done(&b);
}

static int
nft_rule_expr_log_snprintf(char *buf, size_t len, uint32_t type,
			    uint32_t flags, struct nft_rule_expr *e)
{
	switch(type) {
	case NFT_OUTPUT_DEFAULT:
		return nft_rule_expr_log_snprintf_default(buf, len, e);
	case NFT_OUTPUT_XML:
	case NFT_OUTPUT_JSON:
		return nft_rule_expr_log_export(buf, len, e, type);
	default:
		break;
	}
	return -1;
}

static void nft_rule_expr_log_free(struct nft_rule_expr *e)
{
	struct nft_expr_log *log = nft_expr_data(e);

	xfree(log->prefix);
}

struct expr_ops expr_ops_log = {
	.name		= "log",
	.alloc_len	= sizeof(struct nft_expr_log),
	.max_attr	= NFTA_LOG_MAX,
	.free		= nft_rule_expr_log_free,
	.set		= nft_rule_expr_log_set,
	.get		= nft_rule_expr_log_get,
	.parse		= nft_rule_expr_log_parse,
	.build		= nft_rule_expr_log_build,
	.snprintf	= nft_rule_expr_log_snprintf,
	.xml_parse	= nft_rule_expr_log_xml_parse,
	.json_parse	= nft_rule_expr_log_json_parse,
};
