/*
 * (C) 2013 by Eric Leblond <eric@regit.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
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
#include "expr_ops.h"
#include <buffer.h>

struct nft_expr_queue {
	uint16_t		queuenum;
	uint16_t		queues_total;
	uint16_t		flags;
};

static int nft_rule_expr_queue_set(struct nft_rule_expr *e, uint16_t type,
				    const void *data, uint32_t data_len)
{
	struct nft_expr_queue *queue = nft_expr_data(e);

	switch(type) {
	case NFT_EXPR_QUEUE_NUM:
		queue->queuenum = *((uint16_t *)data);
		break;
	case NFT_EXPR_QUEUE_TOTAL:
		queue->queues_total = *((uint16_t *)data);
		break;
	case NFT_EXPR_QUEUE_FLAGS:
		queue->flags = *((uint16_t *)data);
		break;
	default:
		return -1;
	}
	return 0;
}

static const void *
nft_rule_expr_queue_get(const struct nft_rule_expr *e, uint16_t type,
			 uint32_t *data_len)
{
	struct nft_expr_queue *queue = nft_expr_data(e);

	switch(type) {
	case NFT_EXPR_QUEUE_NUM:
		*data_len = sizeof(queue->queuenum);
		return &queue->queuenum;
	case NFT_EXPR_QUEUE_TOTAL:
		*data_len = sizeof(queue->queues_total);
		return &queue->queues_total;
	case NFT_EXPR_QUEUE_FLAGS:
		*data_len = sizeof(queue->flags);
		return &queue->flags;
	}
	return NULL;
}

static int nft_rule_expr_queue_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, NFTA_QUEUE_MAX) < 0)
		return MNL_CB_OK;

	switch(type) {
	case NFTA_QUEUE_NUM:
	case NFTA_QUEUE_TOTAL:
	case NFTA_QUEUE_FLAGS:
		if (mnl_attr_validate(attr, MNL_TYPE_U16) < 0)
			abi_breakage();
		break;
	}

	tb[type] = attr;
	return MNL_CB_OK;
}

static void
nft_rule_expr_queue_build(struct nlmsghdr *nlh, struct nft_rule_expr *e)
{
	struct nft_expr_queue *queue = nft_expr_data(e);

	if (e->flags & (1 << NFT_EXPR_QUEUE_NUM))
		mnl_attr_put_u16(nlh, NFTA_QUEUE_NUM, htons(queue->queuenum));
	if (e->flags & (1 << NFT_EXPR_QUEUE_TOTAL))
		mnl_attr_put_u16(nlh, NFTA_QUEUE_TOTAL, htons(queue->queues_total));
	if (e->flags & (1 << NFT_EXPR_QUEUE_FLAGS))
		mnl_attr_put_u16(nlh, NFTA_QUEUE_FLAGS, htons(queue->flags));
}

static int
nft_rule_expr_queue_parse(struct nft_rule_expr *e, struct nlattr *attr)
{
	struct nft_expr_queue *queue = nft_expr_data(e);
	struct nlattr *tb[NFTA_QUEUE_MAX+1] = {};

	if (mnl_attr_parse_nested(attr, nft_rule_expr_queue_cb, tb) < 0)
		return -1;

	if (tb[NFTA_QUEUE_NUM]) {
		queue->queuenum = ntohs(mnl_attr_get_u16(tb[NFTA_QUEUE_NUM]));
		e->flags |= (1 << NFT_EXPR_QUEUE_NUM);
	}
	if (tb[NFTA_QUEUE_TOTAL]) {
		queue->queues_total = ntohs(mnl_attr_get_u16(tb[NFTA_QUEUE_TOTAL]));
		e->flags |= (1 << NFT_EXPR_QUEUE_TOTAL);
	}
	if (tb[NFTA_QUEUE_FLAGS]) {
		queue->flags = ntohs(mnl_attr_get_u16(tb[NFTA_QUEUE_FLAGS]));
		e->flags |= (1 << NFT_EXPR_QUEUE_FLAGS);
	}

	return 0;
}

static int
nft_rule_expr_queue_json_parse(struct nft_rule_expr *e, json_t *root,
			       struct nft_parse_err *err)
{
#ifdef JSON_PARSING
	uint16_t type;
	uint16_t code;

	if (nft_jansson_parse_val(root, "num", NFT_TYPE_U16, &type, err) == 0)
		nft_rule_expr_set_u16(e, NFT_EXPR_QUEUE_NUM, type);
	nft_rule_expr_set_u16(e, NFT_EXPR_QUEUE_NUM, type);

	if (nft_jansson_parse_val(root, "total", NFT_TYPE_U16, &code, err) == 0)
		nft_rule_expr_set_u16(e, NFT_EXPR_QUEUE_TOTAL, code);

	if (nft_jansson_parse_val(root, "flags", NFT_TYPE_U16, &code, err) == 0)
		nft_rule_expr_set_u16(e, NFT_EXPR_QUEUE_FLAGS, code);

	return 0;
#else
	errno = EOPNOTSUPP;
	return -1;
#endif
}

static int
nft_rule_expr_queue_xml_parse(struct nft_rule_expr *e, mxml_node_t *tree,
			      struct nft_parse_err *err)
{
#ifdef XML_PARSING
	uint16_t queue_num, queue_total, flags;

	if (nft_mxml_num_parse(tree, "num", MXML_DESCEND_FIRST, BASE_DEC,
			       &queue_num, NFT_TYPE_U16, NFT_XML_MAND,
			       err) == 0)
		nft_rule_expr_set_u16(e, NFT_EXPR_QUEUE_NUM, queue_num);

	if (nft_mxml_num_parse(tree, "total", MXML_DESCEND_FIRST, BASE_DEC,
			       &queue_total, NFT_TYPE_U16,
			       NFT_XML_MAND, err) == 0)
		nft_rule_expr_set_u16(e, NFT_EXPR_QUEUE_TOTAL, queue_total);

	if (nft_mxml_num_parse(tree, "flags", MXML_DESCEND_FIRST, BASE_DEC,
			       &flags, NFT_TYPE_U16,
			       NFT_XML_MAND, err) == 0)
		nft_rule_expr_set_u16(e, NFT_EXPR_QUEUE_FLAGS, flags);

	return 0;
#else
	errno = EOPNOTSUPP;
	return -1;
#endif
}

static int nft_rule_expr_queue_snprintf_default(char *buf, size_t len,
						struct nft_rule_expr *e)
{
	struct nft_expr_queue *queue = nft_expr_data(e);
	int ret, size = len, offset = 0;
	uint16_t total_queues;

	total_queues = queue->queuenum + queue->queues_total -1;

	ret = snprintf(buf + offset, len, "num %u", queue->queuenum);
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	if (queue->queues_total && total_queues != queue->queuenum) {
		ret = snprintf(buf + offset, len, "-%u", total_queues);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	if (e->flags & (1 << NFT_EXPR_QUEUE_FLAGS)) {
		if (queue->flags & (NFT_QUEUE_FLAG_BYPASS)) {
			ret = snprintf(buf + offset, len, " bypass");
			SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
		}
		if (queue->flags & (NFT_QUEUE_FLAG_CPU_FANOUT)) {
			ret = snprintf(buf + offset, len, " fanout");
			SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
		}
	}
	return offset;
}

static int nft_rule_expr_queue_export(char *buf, size_t size,
				      struct nft_rule_expr *e, int type)
{
	struct nft_expr_queue *queue = nft_expr_data(e);
	NFT_BUF_INIT(b, buf, size);

	if (e->flags & (1 << NFT_EXPR_QUEUE_NUM))
		nft_buf_u32(&b, type, queue->queuenum, NUM);
	if (e->flags & (1 << NFT_EXPR_QUEUE_TOTAL))
		nft_buf_u32(&b, type, queue->queues_total, TOTAL);
	if (e->flags & (1 << NFT_EXPR_QUEUE_FLAGS))
		nft_buf_u32(&b, type, queue->flags, FLAGS);

	return nft_buf_done(&b);
}

static int
nft_rule_expr_queue_snprintf(char *buf, size_t len, uint32_t type,
			      uint32_t flags, struct nft_rule_expr *e)
{

	switch (type) {
	case NFT_OUTPUT_DEFAULT:
		return nft_rule_expr_queue_snprintf_default(buf, len, e);
	case NFT_OUTPUT_XML:
	case NFT_OUTPUT_JSON:
		return nft_rule_expr_queue_export(buf, len, e, type);
	default:
		break;
	}
	return -1;
}

struct expr_ops expr_ops_queue = {
	.name		= "queue",
	.alloc_len	= sizeof(struct nft_expr_queue),
	.max_attr	= NFTA_QUEUE_MAX,
	.set		= nft_rule_expr_queue_set,
	.get		= nft_rule_expr_queue_get,
	.parse		= nft_rule_expr_queue_parse,
	.build		= nft_rule_expr_queue_build,
	.snprintf	= nft_rule_expr_queue_snprintf,
	.xml_parse	= nft_rule_expr_queue_xml_parse,
	.json_parse	= nft_rule_expr_queue_json_parse,
};

static void __init expr_queue_init(void)
{
	nft_expr_ops_register(&expr_ops_queue);
}
