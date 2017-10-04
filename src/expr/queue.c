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

struct nftnl_expr_queue {
	enum nft_registers	sreg_qnum;
	uint16_t		queuenum;
	uint16_t		queues_total;
	uint16_t		flags;
};

static int nftnl_expr_queue_set(struct nftnl_expr *e, uint16_t type,
				    const void *data, uint32_t data_len)
{
	struct nftnl_expr_queue *queue = nftnl_expr_data(e);

	switch(type) {
	case NFTNL_EXPR_QUEUE_NUM:
		queue->queuenum = *((uint16_t *)data);
		break;
	case NFTNL_EXPR_QUEUE_TOTAL:
		queue->queues_total = *((uint16_t *)data);
		break;
	case NFTNL_EXPR_QUEUE_FLAGS:
		queue->flags = *((uint16_t *)data);
		break;
	case NFTNL_EXPR_QUEUE_SREG_QNUM:
		queue->sreg_qnum = *((uint32_t *)data);
		break;
	default:
		return -1;
	}
	return 0;
}

static const void *
nftnl_expr_queue_get(const struct nftnl_expr *e, uint16_t type,
			 uint32_t *data_len)
{
	struct nftnl_expr_queue *queue = nftnl_expr_data(e);

	switch(type) {
	case NFTNL_EXPR_QUEUE_NUM:
		*data_len = sizeof(queue->queuenum);
		return &queue->queuenum;
	case NFTNL_EXPR_QUEUE_TOTAL:
		*data_len = sizeof(queue->queues_total);
		return &queue->queues_total;
	case NFTNL_EXPR_QUEUE_FLAGS:
		*data_len = sizeof(queue->flags);
		return &queue->flags;
	case NFTNL_EXPR_QUEUE_SREG_QNUM:
		*data_len = sizeof(queue->sreg_qnum);
		return &queue->sreg_qnum;
	}
	return NULL;
}

static int nftnl_expr_queue_cb(const struct nlattr *attr, void *data)
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
	case NFTA_QUEUE_SREG_QNUM:
		if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0)
			abi_breakage();
		break;
	}

	tb[type] = attr;
	return MNL_CB_OK;
}

static void
nftnl_expr_queue_build(struct nlmsghdr *nlh, const struct nftnl_expr *e)
{
	struct nftnl_expr_queue *queue = nftnl_expr_data(e);

	if (e->flags & (1 << NFTNL_EXPR_QUEUE_NUM))
		mnl_attr_put_u16(nlh, NFTA_QUEUE_NUM, htons(queue->queuenum));
	if (e->flags & (1 << NFTNL_EXPR_QUEUE_TOTAL))
		mnl_attr_put_u16(nlh, NFTA_QUEUE_TOTAL, htons(queue->queues_total));
	if (e->flags & (1 << NFTNL_EXPR_QUEUE_FLAGS))
		mnl_attr_put_u16(nlh, NFTA_QUEUE_FLAGS, htons(queue->flags));
	if (e->flags & (1 << NFTNL_EXPR_QUEUE_SREG_QNUM))
		mnl_attr_put_u32(nlh, NFTA_QUEUE_SREG_QNUM, htonl(queue->sreg_qnum));
}

static int
nftnl_expr_queue_parse(struct nftnl_expr *e, struct nlattr *attr)
{
	struct nftnl_expr_queue *queue = nftnl_expr_data(e);
	struct nlattr *tb[NFTA_QUEUE_MAX+1] = {};

	if (mnl_attr_parse_nested(attr, nftnl_expr_queue_cb, tb) < 0)
		return -1;

	if (tb[NFTA_QUEUE_NUM]) {
		queue->queuenum = ntohs(mnl_attr_get_u16(tb[NFTA_QUEUE_NUM]));
		e->flags |= (1 << NFTNL_EXPR_QUEUE_NUM);
	}
	if (tb[NFTA_QUEUE_TOTAL]) {
		queue->queues_total = ntohs(mnl_attr_get_u16(tb[NFTA_QUEUE_TOTAL]));
		e->flags |= (1 << NFTNL_EXPR_QUEUE_TOTAL);
	}
	if (tb[NFTA_QUEUE_FLAGS]) {
		queue->flags = ntohs(mnl_attr_get_u16(tb[NFTA_QUEUE_FLAGS]));
		e->flags |= (1 << NFTNL_EXPR_QUEUE_FLAGS);
	}
	if (tb[NFTA_QUEUE_SREG_QNUM]) {
		queue->sreg_qnum = ntohl(mnl_attr_get_u32(tb[NFTA_QUEUE_SREG_QNUM]));
		e->flags |= (1 << NFTNL_EXPR_QUEUE_SREG_QNUM);
	}

	return 0;
}

static int
nftnl_expr_queue_json_parse(struct nftnl_expr *e, json_t *root,
			       struct nftnl_parse_err *err)
{
#ifdef JSON_PARSING
	uint32_t sreg_qnum;
	uint16_t type;
	uint16_t code;

	if (nftnl_jansson_parse_val(root, "num", NFTNL_TYPE_U16, &type, err) == 0)
		nftnl_expr_set_u16(e, NFTNL_EXPR_QUEUE_NUM, type);

	if (nftnl_jansson_parse_val(root, "total", NFTNL_TYPE_U16, &code, err) == 0)
		nftnl_expr_set_u16(e, NFTNL_EXPR_QUEUE_TOTAL, code);

	if (nftnl_jansson_parse_val(root, "flags", NFTNL_TYPE_U16, &code, err) == 0)
		nftnl_expr_set_u16(e, NFTNL_EXPR_QUEUE_FLAGS, code);

	if (nftnl_jansson_parse_val(root, "sreg_qnum", NFTNL_TYPE_U32, &sreg_qnum,
				    err) == 0)
		nftnl_expr_set_u32(e, NFTNL_EXPR_QUEUE_SREG_QNUM, sreg_qnum);

	return 0;
#else
	errno = EOPNOTSUPP;
	return -1;
#endif
}

static int nftnl_expr_queue_snprintf_default(char *buf, size_t len,
					     const struct nftnl_expr *e)
{
	struct nftnl_expr_queue *queue = nftnl_expr_data(e);
	int ret, remain = len, offset = 0;
	uint16_t total_queues;

	if (e->flags & (1 << NFTNL_EXPR_QUEUE_NUM)) {
		total_queues = queue->queuenum + queue->queues_total - 1;

		ret = snprintf(buf + offset, len, "num %u", queue->queuenum);
		SNPRINTF_BUFFER_SIZE(ret, remain, offset);

		if (queue->queues_total && total_queues != queue->queuenum) {
			ret = snprintf(buf + offset, len, "-%u", total_queues);
			SNPRINTF_BUFFER_SIZE(ret, remain, offset);
		}

		ret = snprintf(buf + offset, len, " ");
		SNPRINTF_BUFFER_SIZE(ret, remain, offset);
	}

	if (e->flags & (1 << NFTNL_EXPR_QUEUE_SREG_QNUM)) {
		ret = snprintf(buf + offset, len, "sreg_qnum %u ",
			       queue->sreg_qnum);
		SNPRINTF_BUFFER_SIZE(ret, remain, offset);
	}

	if (e->flags & (1 << NFTNL_EXPR_QUEUE_FLAGS)) {
		if (queue->flags & (NFT_QUEUE_FLAG_BYPASS)) {
			ret = snprintf(buf + offset, len, "bypass ");
			SNPRINTF_BUFFER_SIZE(ret, remain, offset);
		}
		if (queue->flags & (NFT_QUEUE_FLAG_CPU_FANOUT)) {
			ret = snprintf(buf + offset, len, "fanout ");
			SNPRINTF_BUFFER_SIZE(ret, remain, offset);
		}
	}
	return offset;
}

static int nftnl_expr_queue_export(char *buf, size_t size,
				   const struct nftnl_expr *e, int type)
{
	struct nftnl_expr_queue *queue = nftnl_expr_data(e);
	NFTNL_BUF_INIT(b, buf, size);

	if (e->flags & (1 << NFTNL_EXPR_QUEUE_NUM))
		nftnl_buf_u32(&b, type, queue->queuenum, NUM);
	if (e->flags & (1 << NFTNL_EXPR_QUEUE_TOTAL))
		nftnl_buf_u32(&b, type, queue->queues_total, TOTAL);
	if (e->flags & (1 << NFTNL_EXPR_QUEUE_FLAGS))
		nftnl_buf_u32(&b, type, queue->flags, FLAGS);
	if (e->flags & (1 << NFTNL_EXPR_QUEUE_SREG_QNUM))
		nftnl_buf_u32(&b, type, queue->sreg_qnum, SREG_QNUM);

	return nftnl_buf_done(&b);
}

static int
nftnl_expr_queue_snprintf(char *buf, size_t len, uint32_t type,
			  uint32_t flags, const struct nftnl_expr *e)
{
	switch (type) {
	case NFTNL_OUTPUT_DEFAULT:
		return nftnl_expr_queue_snprintf_default(buf, len, e);
	case NFTNL_OUTPUT_XML:
	case NFTNL_OUTPUT_JSON:
		return nftnl_expr_queue_export(buf, len, e, type);
	default:
		break;
	}
	return -1;
}

static bool nftnl_expr_queue_cmp(const struct nftnl_expr *e1,
			    const struct nftnl_expr *e2)
{
	struct nftnl_expr_queue *q1 = nftnl_expr_data(e1);
	struct nftnl_expr_queue *q2 = nftnl_expr_data(e2);
	bool eq = true;

	if (e1->flags & (1 << NFTNL_EXPR_QUEUE_NUM))
		eq &= (q1->queuenum == q2->queuenum);
	if (e1->flags & (1 << NFTNL_EXPR_QUEUE_TOTAL))
		eq &= (q1->queues_total == q2->queues_total);
	if (e1->flags & (1 << NFTNL_EXPR_QUEUE_FLAGS))
		eq &= (q1->flags == q2->flags);
	if (e1->flags & (1 << NFTNL_EXPR_QUEUE_SREG_QNUM))
		eq &= (q1->sreg_qnum == q2->sreg_qnum);

	return eq;
}

struct expr_ops expr_ops_queue = {
	.name		= "queue",
	.alloc_len	= sizeof(struct nftnl_expr_queue),
	.max_attr	= NFTA_QUEUE_MAX,
	.cmp		= nftnl_expr_queue_cmp,
	.set		= nftnl_expr_queue_set,
	.get		= nftnl_expr_queue_get,
	.parse		= nftnl_expr_queue_parse,
	.build		= nftnl_expr_queue_build,
	.snprintf	= nftnl_expr_queue_snprintf,
	.json_parse	= nftnl_expr_queue_json_parse,
};
