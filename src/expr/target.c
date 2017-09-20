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

/* From include/linux/netfilter/x_tables.h */
#define XT_EXTENSION_MAXNAMELEN 29

struct nftnl_expr_target {
	char		name[XT_EXTENSION_MAXNAMELEN];
	uint32_t	rev;
	uint32_t	data_len;
	const void	*data;
};

static int
nftnl_expr_target_set(struct nftnl_expr *e, uint16_t type,
			 const void *data, uint32_t data_len)
{
	struct nftnl_expr_target *tg = nftnl_expr_data(e);

	switch(type) {
	case NFTNL_EXPR_TG_NAME:
		snprintf(tg->name, sizeof(tg->name), "%.*s", data_len,
			 (const char *) data);
		break;
	case NFTNL_EXPR_TG_REV:
		tg->rev = *((uint32_t *)data);
		break;
	case NFTNL_EXPR_TG_INFO:
		if (e->flags & (1 << NFTNL_EXPR_TG_INFO))
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
nftnl_expr_target_get(const struct nftnl_expr *e, uint16_t type,
			 uint32_t *data_len)
{
	struct nftnl_expr_target *tg = nftnl_expr_data(e);

	switch(type) {
	case NFTNL_EXPR_TG_NAME:
		*data_len = sizeof(tg->name);
		return tg->name;
	case NFTNL_EXPR_TG_REV:
		*data_len = sizeof(tg->rev);
		return &tg->rev;
	case NFTNL_EXPR_TG_INFO:
		*data_len = tg->data_len;
		return tg->data;
	}
	return NULL;
}

static int nftnl_expr_target_cb(const struct nlattr *attr, void *data)
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
nftnl_expr_target_build(struct nlmsghdr *nlh, const struct nftnl_expr *e)
{
	struct nftnl_expr_target *tg = nftnl_expr_data(e);

	if (e->flags & (1 << NFTNL_EXPR_TG_NAME))
		mnl_attr_put_strz(nlh, NFTA_TARGET_NAME, tg->name);
	if (e->flags & (1 << NFTNL_EXPR_TG_REV))
		mnl_attr_put_u32(nlh, NFTA_TARGET_REV, htonl(tg->rev));
	if (e->flags & (1 << NFTNL_EXPR_TG_INFO))
		mnl_attr_put(nlh, NFTA_TARGET_INFO, tg->data_len, tg->data);
}

static int nftnl_expr_target_parse(struct nftnl_expr *e, struct nlattr *attr)
{
	struct nftnl_expr_target *target = nftnl_expr_data(e);
	struct nlattr *tb[NFTA_TARGET_MAX+1] = {};

	if (mnl_attr_parse_nested(attr, nftnl_expr_target_cb, tb) < 0)
		return -1;

	if (tb[NFTA_TARGET_NAME]) {
		snprintf(target->name, XT_EXTENSION_MAXNAMELEN, "%s",
			 mnl_attr_get_str(tb[NFTA_TARGET_NAME]));

		target->name[XT_EXTENSION_MAXNAMELEN-1] = '\0';
		e->flags |= (1 << NFTNL_EXPR_TG_NAME);
	}

	if (tb[NFTA_TARGET_REV]) {
		target->rev = ntohl(mnl_attr_get_u32(tb[NFTA_TARGET_REV]));
		e->flags |= (1 << NFTNL_EXPR_TG_REV);
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

		e->flags |= (1 << NFTNL_EXPR_TG_INFO);
	}

	return 0;
}

static int
nftnl_expr_target_json_parse(struct nftnl_expr *e, json_t *root,
				struct nftnl_parse_err *err)
{
#ifdef JSON_PARSING
	const char *name;

	name = nftnl_jansson_parse_str(root, "name", err);
	if (name != NULL)
		nftnl_expr_set_str(e, NFTNL_EXPR_TG_NAME, name);

	return 0;
#else
	errno = EOPNOTSUPP;
	return -1;
#endif
}

static int nftnl_rule_exp_target_export(char *buf, size_t size,
				        const struct nftnl_expr *e, int type)
{
	struct nftnl_expr_target *target = nftnl_expr_data(e);
	NFTNL_BUF_INIT(b, buf, size);

	if (e->flags & (1 << NFTNL_EXPR_TG_NAME))
		nftnl_buf_str(&b, type, target->name, NAME);

	return nftnl_buf_done(&b);
}

static int
nftnl_expr_target_snprintf(char *buf, size_t len, uint32_t type,
			   uint32_t flags, const struct nftnl_expr *e)
{
	struct nftnl_expr_target *target = nftnl_expr_data(e);

	if (len)
		buf[0] = '\0';

	switch (type) {
	case NFTNL_OUTPUT_DEFAULT:
		return snprintf(buf, len, "name %s rev %u ",
				target->name, target->rev);
	case NFTNL_OUTPUT_XML:
	case NFTNL_OUTPUT_JSON:
		return nftnl_rule_exp_target_export(buf, len, e, type);
	default:
		break;
	}
	return -1;
}

static void nftnl_expr_target_free(const struct nftnl_expr *e)
{
	struct nftnl_expr_target *target = nftnl_expr_data(e);

	xfree(target->data);
}

static bool nftnl_expr_target_cmp(const struct nftnl_expr *e1,
				  const struct nftnl_expr *e2)
{
	struct nftnl_expr_target *t1 = nftnl_expr_data(e1);
	struct nftnl_expr_target *t2 = nftnl_expr_data(e2);
	bool eq = true;

	if (e1->flags & (1 << NFTNL_EXPR_TG_NAME))
		eq &= !strcmp(t1->name, t2->name);
	if (e1->flags & (1 << NFTNL_EXPR_TG_REV))
		eq &= (t1->rev == t2->rev);
	if (e1->flags & (1 << NFTNL_EXPR_TG_INFO)) {
		eq &= (t1->data_len == t2->data_len);
		eq &= !memcmp(t1->data, t2->data, t1->data_len);
	}

	return eq;
}

struct expr_ops expr_ops_target = {
	.name		= "target",
	.alloc_len	= sizeof(struct nftnl_expr_target),
	.max_attr	= NFTA_TARGET_MAX,
	.free		= nftnl_expr_target_free,
	.cmp		= nftnl_expr_target_cmp,
	.set		= nftnl_expr_target_set,
	.get		= nftnl_expr_target_get,
	.parse		= nftnl_expr_target_parse,
	.build		= nftnl_expr_target_build,
	.snprintf	= nftnl_expr_target_snprintf,
	.json_parse	= nftnl_expr_target_json_parse,
};
