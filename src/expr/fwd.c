/*
 * (C) 2015 Pablo Neira Ayuso <pablo@netfilter.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include <errno.h>
#include "internal.h"
#include <libmnl/libmnl.h>
#include <linux/netfilter/nf_tables.h>
#include <libnftnl/expr.h>
#include <libnftnl/rule.h>
#include "expr_ops.h"
#include "data_reg.h"
#include <buffer.h>

struct nftnl_expr_fwd {
	enum nft_registers	sreg_dev;
};

static int nftnl_expr_fwd_set(struct nftnl_expr *e, uint16_t type,
				  const void *data, uint32_t data_len)
{
	struct nftnl_expr_fwd *fwd = nftnl_expr_data(e);

	switch (type) {
	case NFTNL_EXPR_FWD_SREG_DEV:
		fwd->sreg_dev= *((uint32_t *)data);
		break;
	default:
		return -1;
	}
	return 0;
}

static const void *nftnl_expr_fwd_get(const struct nftnl_expr *e,
				      uint16_t type, uint32_t *data_len)
{
	struct nftnl_expr_fwd *fwd = nftnl_expr_data(e);

	switch (type) {
	case NFTNL_EXPR_FWD_SREG_DEV:
		*data_len = sizeof(fwd->sreg_dev);
		return &fwd->sreg_dev;
	}
	return NULL;
}

static int nftnl_expr_fwd_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, NFTA_FWD_MAX) < 0)
		return MNL_CB_OK;

	switch (type) {
	case NFTA_FWD_SREG_DEV:
		if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0)
			abi_breakage();
		break;
	}

	tb[type] = attr;
	return MNL_CB_OK;
}

static void nftnl_expr_fwd_build(struct nlmsghdr *nlh,
				 const struct nftnl_expr *e)
{
	struct nftnl_expr_fwd *fwd = nftnl_expr_data(e);

	if (e->flags & (1 << NFTNL_EXPR_FWD_SREG_DEV))
		mnl_attr_put_u32(nlh, NFTA_FWD_SREG_DEV, htonl(fwd->sreg_dev));
}

static int nftnl_expr_fwd_parse(struct nftnl_expr *e, struct nlattr *attr)
{
	struct nftnl_expr_fwd *fwd = nftnl_expr_data(e);
	struct nlattr *tb[NFTA_FWD_MAX + 1] = {};
	int ret = 0;

	if (mnl_attr_parse_nested(attr, nftnl_expr_fwd_cb, tb) < 0)
		return -1;

	if (tb[NFTA_FWD_SREG_DEV]) {
		fwd->sreg_dev = ntohl(mnl_attr_get_u32(tb[NFTA_FWD_SREG_DEV]));
		e->flags |= (1 << NFTNL_EXPR_FWD_SREG_DEV);
	}

	return ret;
}

static int nftnl_expr_fwd_json_parse(struct nftnl_expr *e, json_t *root,
				     struct nftnl_parse_err *err)
{
#ifdef JSON_PARSING
	uint32_t sreg_dev;
	int ret;

	ret = nftnl_jansson_parse_val(root, "sreg_dev", NFTNL_TYPE_U32, &sreg_dev, err);
	if (ret >= 0)
		nftnl_expr_set_u32(e, NFTNL_EXPR_FWD_SREG_DEV, sreg_dev);

	return 0;
#else
	errno = EOPNOTSUPP;
	return -1;
#endif
}

static int nftnl_expr_fwd_xml_parse(struct nftnl_expr *e, mxml_node_t *tree,
				    struct nftnl_parse_err *err)
{
#ifdef XML_PARSING
	uint32_t sreg_dev;

	if (nftnl_mxml_reg_parse(tree, "sreg_dev", &sreg_dev, MXML_DESCEND_FIRST,
			       NFTNL_XML_OPT, err) == 0)
		nftnl_expr_set_u32(e, NFTNL_EXPR_FWD_SREG_DEV, sreg_dev);

	return 0;
#else
	errno = EOPNOTSUPP;
	return -1;
#endif
}

static int nftnl_expr_fwd_export(char *buf, size_t size,
				 const struct nftnl_expr *e, int type)
{
	struct nftnl_expr_fwd *fwd = nftnl_expr_data(e);
	NFTNL_BUF_INIT(b, buf, size);

	if (e->flags & (1 << NFTNL_EXPR_FWD_SREG_DEV))
		nftnl_buf_u32(&b, type, fwd->sreg_dev, "sreg_dev");

	return nftnl_buf_done(&b);
}

static int nftnl_expr_fwd_snprintf_default(char *buf, size_t len,
					   const struct nftnl_expr *e,
					   uint32_t flags)
{
	int size = len, offset = 0, ret;
	struct nftnl_expr_fwd *fwd = nftnl_expr_data(e);

	if (e->flags & (1 << NFTNL_EXPR_FWD_SREG_DEV)) {
		ret = snprintf(buf + offset, len, "sreg_dev %u ", fwd->sreg_dev);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	return offset;
}

static int nftnl_expr_fwd_snprintf(char *buf, size_t len, uint32_t type,
				   uint32_t flags, const struct nftnl_expr *e)
{
	switch (type) {
	case NFTNL_OUTPUT_DEFAULT:
		return nftnl_expr_fwd_snprintf_default(buf, len, e, flags);
	case NFTNL_OUTPUT_XML:
	case NFTNL_OUTPUT_JSON:
		return nftnl_expr_fwd_export(buf, len, e, type);
	default:
		break;
	}
	return -1;
}

static bool nftnl_expr_fwd_cmp(const struct nftnl_expr *e1,
			       const struct nftnl_expr *e2)
{
	struct nftnl_expr_fwd *f1 = nftnl_expr_data(e1);
	struct nftnl_expr_fwd *f2 = nftnl_expr_data(e2);
	bool eq = true;

	if (e1->flags & (1 << NFTNL_EXPR_FWD_SREG_DEV))
		eq &= (f1->sreg_dev == f2->sreg_dev);

	return eq;
}

struct expr_ops expr_ops_fwd = {
	.name		= "fwd",
	.alloc_len	= sizeof(struct nftnl_expr_fwd),
	.max_attr	= NFTA_FWD_MAX,
	.cmp		= nftnl_expr_fwd_cmp,
	.set		= nftnl_expr_fwd_set,
	.get		= nftnl_expr_fwd_get,
	.parse		= nftnl_expr_fwd_parse,
	.build		= nftnl_expr_fwd_build,
	.snprintf	= nftnl_expr_fwd_snprintf,
	.xml_parse	= nftnl_expr_fwd_xml_parse,
	.json_parse	= nftnl_expr_fwd_json_parse,
};
