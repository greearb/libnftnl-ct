/*
 * (C) 2016 by Pablo Neira Ayuso <pablo@netfilter.org>
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

struct nftnl_expr_quota {
	uint64_t	bytes;
	uint32_t	flags;
};

static int nftnl_expr_quota_set(struct nftnl_expr *e, uint16_t type,
				const void *data, uint32_t data_len)
{
	struct nftnl_expr_quota *quota = nftnl_expr_data(e);

	switch (type) {
	case NFTNL_EXPR_QUOTA_BYTES:
		quota->bytes = *((uint64_t *)data);
		break;
	case NFTNL_EXPR_QUOTA_FLAGS:
		quota->flags = *((uint32_t *)data);
		break;
	default:
		return -1;
	}
	return 0;
}

static const void *nftnl_expr_quota_get(const struct nftnl_expr *e,
					uint16_t type, uint32_t *data_len)
{
	struct nftnl_expr_quota *quota = nftnl_expr_data(e);

	switch (type) {
	case NFTNL_EXPR_QUOTA_BYTES:
		*data_len = sizeof(quota->bytes);
		return &quota->bytes;
	case NFTNL_EXPR_QUOTA_FLAGS:
		*data_len = sizeof(quota->flags);
		return &quota->flags;
	}
	return NULL;
}

static int nftnl_expr_quota_cb(const struct nlattr *attr, void *data)
{
	int type = mnl_attr_get_type(attr);
	const struct nlattr **tb = data;

	if (mnl_attr_type_valid(attr, NFTA_QUOTA_MAX) < 0)
		return MNL_CB_OK;

	switch(type) {
	case NFTA_QUOTA_BYTES:
		if (mnl_attr_validate(attr, MNL_TYPE_U64) < 0)
			abi_breakage();
		break;
	case NFTA_QUOTA_FLAGS:
		if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0)
			abi_breakage();
		break;
	}

	tb[type] = attr;
	return MNL_CB_OK;
}

static void
nftnl_expr_quota_build(struct nlmsghdr *nlh, const struct nftnl_expr *e)
{
	struct nftnl_expr_quota *quota = nftnl_expr_data(e);

	if (e->flags & (1 << NFTNL_EXPR_QUOTA_BYTES))
		mnl_attr_put_u64(nlh, NFTA_QUOTA_BYTES, htobe64(quota->bytes));
	if (e->flags & (1 << NFTNL_EXPR_QUOTA_FLAGS))
		mnl_attr_put_u32(nlh, NFTA_QUOTA_FLAGS, htonl(quota->flags));
}

static int
nftnl_expr_quota_parse(struct nftnl_expr *e, struct nlattr *attr)
{
	struct nftnl_expr_quota *quota = nftnl_expr_data(e);
	struct nlattr *tb[NFTA_QUOTA_MAX + 1] = {};

	if (mnl_attr_parse_nested(attr, nftnl_expr_quota_cb, tb) < 0)
		return -1;

	if (tb[NFTA_QUOTA_BYTES]) {
		quota->bytes = be64toh(mnl_attr_get_u64(tb[NFTA_QUOTA_BYTES]));
		e->flags |= (1 << NFTNL_EXPR_QUOTA_BYTES);
	}
	if (tb[NFTA_QUOTA_FLAGS]) {
		quota->flags = ntohl(mnl_attr_get_u32(tb[NFTA_QUOTA_FLAGS]));
		e->flags |= (1 << NFTNL_EXPR_QUOTA_FLAGS);
	}

	return 0;
}

static int
nftnl_expr_quota_json_parse(struct nftnl_expr *e, json_t *root,
				 struct nftnl_parse_err *err)
{
#ifdef JSON_PARSING
	uint64_t bytes;
	uint32_t flags;

	if (nftnl_jansson_parse_val(root, "bytes", NFTNL_TYPE_U64, &bytes,
				  err) == 0)
		nftnl_expr_set_u64(e, NFTNL_EXPR_QUOTA_BYTES, bytes);
	if (nftnl_jansson_parse_val(root, "flags", NFTNL_TYPE_U32, &flags,
				  err) == 0)
		nftnl_expr_set_u32(e, NFTNL_EXPR_QUOTA_FLAGS, flags);

	return 0;
#else
	errno = EOPNOTSUPP;
	return -1;
#endif
}

static int nftnl_expr_quota_xml_parse(struct nftnl_expr *e, mxml_node_t *tree,
				      struct nftnl_parse_err *err)
{
#ifdef XML_PARSING
	uint64_t bytes;
	uint32_t flags;

	if (nftnl_mxml_num_parse(tree, "bytes", MXML_DESCEND_FIRST, BASE_DEC,
				 &bytes, NFTNL_TYPE_U64, NFTNL_XML_MAND, err) == 0)
		nftnl_expr_set_u64(e, NFTNL_EXPR_QUOTA_BYTES, bytes);
	if (nftnl_mxml_num_parse(tree, "flags", MXML_DESCEND_FIRST, BASE_DEC,
				 &flags, NFTNL_TYPE_U32, NFTNL_XML_MAND,  err) == 0)
		nftnl_expr_set_u32(e, NFTNL_EXPR_QUOTA_FLAGS, flags);

	return 0;
#else
	errno = EOPNOTSUPP;
	return -1;
#endif
}

static int nftnl_expr_quota_export(char *buf, size_t size,
				   const struct nftnl_expr *e, int type)
{
	struct nftnl_expr_quota *quota = nftnl_expr_data(e);
	NFTNL_BUF_INIT(b, buf, size);

	if (e->flags & (1 << NFTNL_EXPR_QUOTA_BYTES))
		nftnl_buf_u64(&b, type, quota->bytes, BYTES);
	if (e->flags & (1 << NFTNL_EXPR_QUOTA_FLAGS))
		nftnl_buf_u32(&b, type, quota->flags, FLAGS);

	return nftnl_buf_done(&b);
}

static int nftnl_expr_quota_snprintf_default(char *buf, size_t len,
					       const struct nftnl_expr *e)
{
	struct nftnl_expr_quota *quota = nftnl_expr_data(e);

	return snprintf(buf, len, "bytes %"PRIu64" flags %u ",
			quota->bytes, quota->flags);
}

static int nftnl_expr_quota_snprintf(char *buf, size_t len, uint32_t type,
				       uint32_t flags,
				       const struct nftnl_expr *e)
{
	switch (type) {
	case NFTNL_OUTPUT_DEFAULT:
		return nftnl_expr_quota_snprintf_default(buf, len, e);
	case NFTNL_OUTPUT_XML:
	case NFTNL_OUTPUT_JSON:
		return nftnl_expr_quota_export(buf, len, e, type);
	default:
		break;
	}
	return -1;
}

struct expr_ops expr_ops_quota = {
	.name		= "quota",
	.alloc_len	= sizeof(struct nftnl_expr_quota),
	.max_attr	= NFTA_QUOTA_MAX,
	.set		= nftnl_expr_quota_set,
	.get		= nftnl_expr_quota_get,
	.parse		= nftnl_expr_quota_parse,
	.build		= nftnl_expr_quota_build,
	.snprintf	= nftnl_expr_quota_snprintf,
	.xml_parse	= nftnl_expr_quota_xml_parse,
	.json_parse	= nftnl_expr_quota_json_parse,
};
