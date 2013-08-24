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
#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>

#include <linux/netfilter/nf_tables.h>

#include "internal.h"
#include <libmnl/libmnl.h>
#include <libnftables/expr.h>
#include <libnftables/rule.h>
#include "expr_ops.h"

struct nft_expr_counter {
	uint64_t	pkts;
	uint64_t	bytes;
};

static int
nft_rule_expr_counter_set(struct nft_rule_expr *e, uint16_t type,
			  const void *data, size_t data_len)
{
	struct nft_expr_counter *ctr = nft_expr_data(e);

	switch(type) {
	case NFT_EXPR_CTR_BYTES:
		ctr->bytes = *((uint64_t *)data);
		break;
	case NFT_EXPR_CTR_PACKETS:
		ctr->pkts = *((uint64_t *)data);
		break;
	default:
		return -1;
	}
	return 0;
}

static const void *
nft_rule_expr_counter_get(const struct nft_rule_expr *e, uint16_t type,
			  size_t *data_len)
{
	struct nft_expr_counter *ctr = nft_expr_data(e);

	switch(type) {
	case NFT_EXPR_CTR_BYTES:
		*data_len = sizeof(ctr->bytes);
		return &ctr->bytes;
	case NFT_EXPR_CTR_PACKETS:
		*data_len = sizeof(ctr->pkts);
		return &ctr->pkts;
	}
	return NULL;
}

static int nft_rule_expr_counter_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, NFTA_COUNTER_MAX) < 0)
		return MNL_CB_OK;

	switch(type) {
	case NFTA_COUNTER_BYTES:
	case NFTA_COUNTER_PACKETS:
		if (mnl_attr_validate(attr, MNL_TYPE_U64) < 0) {
			perror("mnl_attr_validate");
			return MNL_CB_ERROR;
		}
		break;
	}

	tb[type] = attr;
	return MNL_CB_OK;
}

static void
nft_rule_expr_counter_build(struct nlmsghdr *nlh, struct nft_rule_expr *e)
{
	struct nft_expr_counter *ctr = nft_expr_data(e);

	if (e->flags & (1 << NFT_EXPR_CTR_BYTES))
		mnl_attr_put_u64(nlh, NFTA_COUNTER_BYTES, htobe64(ctr->bytes));
	if (e->flags & (1 << NFT_EXPR_CTR_PACKETS))
		mnl_attr_put_u64(nlh, NFTA_COUNTER_PACKETS, htobe64(ctr->pkts));
}

static int
nft_rule_expr_counter_parse(struct nft_rule_expr *e, struct nlattr *attr)
{
	struct nft_expr_counter *ctr = nft_expr_data(e);
	struct nlattr *tb[NFTA_COUNTER_MAX+1] = {};

	if (mnl_attr_parse_nested(attr, nft_rule_expr_counter_cb, tb) < 0)
		return -1;

	if (tb[NFTA_COUNTER_BYTES]) {
		ctr->bytes = be64toh(mnl_attr_get_u64(tb[NFTA_COUNTER_BYTES]));
		e->flags |= (1 << NFT_EXPR_CTR_BYTES);
	}
	if (tb[NFTA_COUNTER_PACKETS]) {
		ctr->pkts = be64toh(mnl_attr_get_u64(tb[NFTA_COUNTER_PACKETS]));
		e->flags |= (1 << NFT_EXPR_CTR_PACKETS);
	}

	return 0;
}

static int
nft_rule_expr_counter_json_parse(struct nft_rule_expr *e, json_t *root)
{
#ifdef JSON_PARSING
	uint64_t uval64;

	if (nft_jansson_parse_val(root, "pkts", NFT_TYPE_U64, &uval64) < 0)
		return -1;

	nft_rule_expr_set_u64(e, NFT_EXPR_CTR_PACKETS, uval64);

	if (nft_jansson_parse_val(root, "bytes", NFT_TYPE_U64, &uval64) < 0)
		return -1;

	nft_rule_expr_set_u64(e, NFT_EXPR_CTR_BYTES, uval64);

	return 0;
#else
	errno = EOPNOTSUPP;
	return -1;
#endif
}

static int
nft_rule_expr_counter_xml_parse(struct nft_rule_expr *e, mxml_node_t *tree)
{
#ifdef XML_PARSING
	struct nft_expr_counter *ctr = nft_expr_data(e);

	if (nft_mxml_num_parse(tree, "pkts", MXML_DESCEND_FIRST, BASE_DEC,
                               &ctr->pkts, NFT_TYPE_U64) != 0)
		return -1;

	e->flags |= (1 << NFT_EXPR_CTR_PACKETS);

	if (nft_mxml_num_parse(tree, "bytes", MXML_DESCEND_FIRST, BASE_DEC,
                               &ctr->bytes, NFT_TYPE_U64) != 0)
		return -1;

	e->flags |= (1 << NFT_EXPR_CTR_BYTES);

	return 0;
#else
	errno = EOPNOTSUPP;
	return -1;
#endif
}

static int
nft_rule_expr_counter_snprintf(char *buf, size_t len, uint32_t type,
			       uint32_t flags, struct nft_rule_expr *e)
{
	struct nft_expr_counter *ctr = nft_expr_data(e);

	switch(type) {
	case NFT_RULE_O_DEFAULT:
		return snprintf(buf, len, "pkts %"PRIu64" bytes %"PRIu64" ",
				ctr->pkts, ctr->bytes);
	case NFT_RULE_O_XML:
		return snprintf(buf, len, "<pkts>%"PRIu64"</pkts><bytes>%"PRIu64"</bytes>",
				ctr->pkts, ctr->bytes);
	case NFT_RULE_O_JSON:
		return snprintf(buf, len, "\"pkts\" : %"PRIu64", \"bytes\" : %"PRIu64"",
				ctr->pkts, ctr->bytes);
	default:
		break;
	}
	return -1;
}

struct expr_ops expr_ops_counter = {
	.name		= "counter",
	.alloc_len	= sizeof(struct nft_expr_counter),
	.max_attr	= NFTA_COUNTER_MAX,
	.set		= nft_rule_expr_counter_set,
	.get		= nft_rule_expr_counter_get,
	.parse		= nft_rule_expr_counter_parse,
	.build		= nft_rule_expr_counter_build,
	.snprintf	= nft_rule_expr_counter_snprintf,
	.xml_parse	= nft_rule_expr_counter_xml_parse,
	.json_parse	= nft_rule_expr_counter_json_parse,
};

static void __init expr_counter_init(void)
{
	nft_expr_ops_register(&expr_ops_counter);
}
