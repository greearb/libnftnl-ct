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

struct nftnl_expr_masq {
	uint32_t		flags;
	enum nft_registers	sreg_proto_min;
	enum nft_registers	sreg_proto_max;
};

static int
nftnl_expr_masq_set(struct nftnl_expr *e, uint16_t type,
		       const void *data, uint32_t data_len)
{
	struct nftnl_expr_masq *masq = nftnl_expr_data(e);

	switch (type) {
	case NFTNL_EXPR_MASQ_FLAGS:
		masq->flags = *((uint32_t *)data);
		break;
	case NFTNL_EXPR_MASQ_REG_PROTO_MIN:
		masq->sreg_proto_min = *((uint32_t *)data);
		break;
	case NFTNL_EXPR_MASQ_REG_PROTO_MAX:
		masq->sreg_proto_max = *((uint32_t *)data);
		break;
	default:
		return -1;
	}
	return 0;
}

static const void *
nftnl_expr_masq_get(const struct nftnl_expr *e, uint16_t type,
		       uint32_t *data_len)
{
	struct nftnl_expr_masq *masq = nftnl_expr_data(e);

	switch (type) {
	case NFTNL_EXPR_MASQ_FLAGS:
		*data_len = sizeof(masq->flags);
		return &masq->flags;
	case NFTNL_EXPR_MASQ_REG_PROTO_MIN:
		*data_len = sizeof(masq->sreg_proto_min);
		return &masq->sreg_proto_min;
	case NFTNL_EXPR_MASQ_REG_PROTO_MAX:
		*data_len = sizeof(masq->sreg_proto_max);
		return &masq->sreg_proto_max;
	}
	return NULL;
}

static int nftnl_expr_masq_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, NFTA_MASQ_MAX) < 0)
		return MNL_CB_OK;

	switch (type) {
	case NFTA_MASQ_REG_PROTO_MIN:
	case NFTA_MASQ_REG_PROTO_MAX:
	case NFTA_MASQ_FLAGS:
		if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0)
			abi_breakage();
		break;
	}

	tb[type] = attr;
	return MNL_CB_OK;
}

static void
nftnl_expr_masq_build(struct nlmsghdr *nlh, const struct nftnl_expr *e)
{
	struct nftnl_expr_masq *masq = nftnl_expr_data(e);

	if (e->flags & (1 << NFTNL_EXPR_MASQ_FLAGS))
		mnl_attr_put_u32(nlh, NFTA_MASQ_FLAGS, htobe32(masq->flags));
	if (e->flags & (1 << NFTNL_EXPR_MASQ_REG_PROTO_MIN))
		mnl_attr_put_u32(nlh, NFTA_MASQ_REG_PROTO_MIN,
				 htobe32(masq->sreg_proto_min));
	if (e->flags & (1 << NFTNL_EXPR_MASQ_REG_PROTO_MAX))
		mnl_attr_put_u32(nlh, NFTA_MASQ_REG_PROTO_MAX,
				 htobe32(masq->sreg_proto_max));
}

static int
nftnl_expr_masq_parse(struct nftnl_expr *e, struct nlattr *attr)
{
	struct nftnl_expr_masq *masq = nftnl_expr_data(e);
	struct nlattr *tb[NFTA_MASQ_MAX+1] = {};

	if (mnl_attr_parse_nested(attr, nftnl_expr_masq_cb, tb) < 0)
		return -1;

	if (tb[NFTA_MASQ_FLAGS]) {
		masq->flags = be32toh(mnl_attr_get_u32(tb[NFTA_MASQ_FLAGS]));
		e->flags |= (1 << NFTNL_EXPR_MASQ_FLAGS);
        }
	if (tb[NFTA_MASQ_REG_PROTO_MIN]) {
		masq->sreg_proto_min =
			be32toh(mnl_attr_get_u32(tb[NFTA_MASQ_REG_PROTO_MIN]));
		e->flags |= (1 << NFTNL_EXPR_MASQ_REG_PROTO_MIN);
	}
	if (tb[NFTA_MASQ_REG_PROTO_MAX]) {
		masq->sreg_proto_max =
			be32toh(mnl_attr_get_u32(tb[NFTA_MASQ_REG_PROTO_MAX]));
		e->flags |= (1 << NFTNL_EXPR_MASQ_REG_PROTO_MAX);
	}

	return 0;
}

static int
nftnl_expr_masq_json_parse(struct nftnl_expr *e, json_t *root,
			      struct nftnl_parse_err *err)
{
#ifdef JSON_PARSING
	uint32_t reg, flags;

	if (nftnl_jansson_parse_val(root, "flags", NFTNL_TYPE_U32, &flags,
				  err) == 0)
		nftnl_expr_set_u32(e, NFTNL_EXPR_MASQ_FLAGS, flags);
	if (nftnl_jansson_parse_reg(root, "sreg_proto_min", NFTNL_TYPE_U32,
				    &reg, err) == 0)
		nftnl_expr_set_u32(e, NFTNL_EXPR_MASQ_REG_PROTO_MIN, reg);
	if (nftnl_jansson_parse_reg(root, "sreg_proto_max", NFTNL_TYPE_U32,
				    &reg, err) == 0)
		nftnl_expr_set_u32(e, NFTNL_EXPR_MASQ_REG_PROTO_MAX, reg);

	return 0;
#else
	errno = EOPNOTSUPP;
	return -1;
#endif
}

static int
nftnl_expr_masq_xml_parse(struct nftnl_expr *e, mxml_node_t *tree,
			     struct nftnl_parse_err *err)
{
#ifdef XML_PARSING
	uint32_t flags;
	uint32_t reg_proto_min, reg_proto_max;

	if (nftnl_mxml_num_parse(tree, "flags", MXML_DESCEND_FIRST, BASE_DEC,
			       &flags, NFTNL_TYPE_U32, NFTNL_XML_MAND, err) == 0)
		nftnl_expr_set_u32(e, NFTNL_EXPR_MASQ_FLAGS, flags);
	if (nftnl_mxml_reg_parse(tree, "sreg_proto_min", &reg_proto_min,
				 MXML_DESCEND, NFTNL_XML_MAND, err) == 0)
		nftnl_expr_set_u32(e, NFTNL_EXPR_MASQ_REG_PROTO_MIN,
				   reg_proto_min);
	if (nftnl_mxml_reg_parse(tree, "sreg_proto_max", &reg_proto_max,
				 MXML_DESCEND, NFTNL_XML_MAND, err) == 0)
		nftnl_expr_set_u32(e, NFTNL_EXPR_MASQ_REG_PROTO_MAX,
				   reg_proto_max);

	return 0;
#else
	errno = EOPNOTSUPP;
	return -1;
#endif
}
static int nftnl_expr_masq_export(char *buf, size_t size,
				  const struct nftnl_expr *e, int type)
{
	struct nftnl_expr_masq *masq = nftnl_expr_data(e);
	NFTNL_BUF_INIT(b, buf, size);

	if (e->flags & (1 << NFTNL_EXPR_MASQ_FLAGS))
		nftnl_buf_u32(&b, type, masq->flags, FLAGS);
	if (e->flags & (1 << NFTNL_EXPR_MASQ_REG_PROTO_MIN))
		nftnl_buf_u32(&b, type, masq->sreg_proto_min, SREG_PROTO_MIN);
	if (e->flags & (1 << NFTNL_EXPR_MASQ_REG_PROTO_MAX))
		nftnl_buf_u32(&b, type, masq->sreg_proto_max, SREG_PROTO_MAX);

	return nftnl_buf_done(&b);
}

static int nftnl_expr_masq_snprintf_default(char *buf, size_t len,
					    const struct nftnl_expr *e)
{
	struct nftnl_expr_masq *masq = nftnl_expr_data(e);

	if (e->flags & (1 << NFTNL_EXPR_MASQ_FLAGS))
		return snprintf(buf, len, "flags 0x%x ", masq->flags);
	if (e->flags & (1 << NFTNL_EXPR_MASQ_REG_PROTO_MIN)) {
		return snprintf(buf, len,
				"proto_min reg %u proto_max reg %u ",
				masq->sreg_proto_min, masq->sreg_proto_max);
	}

	return 0;
}

static int nftnl_expr_masq_snprintf(char *buf, size_t len, uint32_t type,
				    uint32_t flags, const struct nftnl_expr *e)
{
	switch (type) {
	case NFTNL_OUTPUT_DEFAULT:
		return nftnl_expr_masq_snprintf_default(buf, len, e);
	case NFTNL_OUTPUT_XML:
	case NFTNL_OUTPUT_JSON:
		return nftnl_expr_masq_export(buf, len, e, type);
	default:
		break;
	}
	return -1;
}

static bool nftnl_expr_masq_cmp(const struct nftnl_expr *e1,
				const struct nftnl_expr *e2)
{
	struct nftnl_expr_masq *m1 = nftnl_expr_data(e1);
	struct nftnl_expr_masq *m2 = nftnl_expr_data(e2);
	bool eq = true;

	if (e1->flags & (1 << NFTNL_EXPR_MASQ_FLAGS))
		eq &= (m1->flags == m2->flags);
	if (e1->flags & (1 << NFTNL_EXPR_MASQ_REG_PROTO_MIN))
		eq &= (m1->sreg_proto_min == m2->sreg_proto_min);
	if (e1->flags & (1 << NFTNL_EXPR_MASQ_REG_PROTO_MAX))
		eq &= (m1->sreg_proto_max == m2->sreg_proto_max);

	return eq;
}

struct expr_ops expr_ops_masq = {
	.name		= "masq",
	.alloc_len	= sizeof(struct nftnl_expr_masq),
	.max_attr	= NFTA_MASQ_MAX,
	.cmp		= nftnl_expr_masq_cmp,
	.set		= nftnl_expr_masq_set,
	.get		= nftnl_expr_masq_get,
	.parse		= nftnl_expr_masq_parse,
	.build		= nftnl_expr_masq_build,
	.snprintf	= nftnl_expr_masq_snprintf,
	.xml_parse	= nftnl_expr_masq_xml_parse,
	.json_parse	= nftnl_expr_masq_json_parse,
};
