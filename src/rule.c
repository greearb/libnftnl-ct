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
#include "internal.h"

#include <time.h>
#include <endian.h>
#include <stdint.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <netinet/in.h>
#include <errno.h>
#include <inttypes.h>
#include <ctype.h>

#include <libmnl/libmnl.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nf_tables.h>

#include <libnftnl/rule.h>
#include <libnftnl/expr.h>

#include "linux_list.h"
#include "expr_ops.h"

struct nft_rule {
	struct list_head head;

	uint32_t	flags;
	uint32_t	family;
	const char	*table;
	const char	*chain;
	uint64_t	handle;
	uint64_t	position;
	struct {
			void		*data;
			uint32_t	len;
	} user;
	struct {
			uint32_t	flags;
			uint32_t	proto;
	} compat;

	struct list_head expr_list;
};

struct nft_rule *nft_rule_alloc(void)
{
	struct nft_rule *r;

	r = calloc(1, sizeof(struct nft_rule));
	if (r == NULL)
		return NULL;

	INIT_LIST_HEAD(&r->expr_list);

	return r;
}
EXPORT_SYMBOL(nft_rule_alloc);

void nft_rule_free(struct nft_rule *r)
{
	struct nft_rule_expr *e, *tmp;

	list_for_each_entry_safe(e, tmp, &r->expr_list, head)
		nft_rule_expr_free(e);

	if (r->table != NULL)
		xfree(r->table);
	if (r->chain != NULL)
		xfree(r->chain);

	xfree(r);
}
EXPORT_SYMBOL(nft_rule_free);

bool nft_rule_attr_is_set(const struct nft_rule *r, uint16_t attr)
{
	return r->flags & (1 << attr);
}
EXPORT_SYMBOL(nft_rule_attr_is_set);

void nft_rule_attr_unset(struct nft_rule *r, uint16_t attr)
{
	if (!(r->flags & (1 << attr)))
		return;

	switch (attr) {
	case NFT_RULE_ATTR_TABLE:
		if (r->table) {
			xfree(r->table);
			r->table = NULL;
		}
		break;
	case NFT_RULE_ATTR_CHAIN:
		if (r->chain) {
			xfree(r->chain);
			r->chain = NULL;
		}
		break;
	case NFT_RULE_ATTR_HANDLE:
	case NFT_RULE_ATTR_COMPAT_PROTO:
	case NFT_RULE_ATTR_COMPAT_FLAGS:
	case NFT_RULE_ATTR_POSITION:
	case NFT_RULE_ATTR_FAMILY:
	case NFT_RULE_ATTR_USERDATA:
		break;
	}

	r->flags &= ~(1 << attr);
}
EXPORT_SYMBOL(nft_rule_attr_unset);

static uint32_t nft_rule_attr_validate[NFT_RULE_ATTR_MAX + 1] = {
	[NFT_RULE_ATTR_HANDLE]		= sizeof(uint64_t),
	[NFT_RULE_ATTR_COMPAT_PROTO]	= sizeof(uint32_t),
	[NFT_RULE_ATTR_COMPAT_FLAGS]	= sizeof(uint32_t),
	[NFT_RULE_ATTR_FAMILY]		= sizeof(uint32_t),
	[NFT_RULE_ATTR_POSITION]	= sizeof(uint64_t),
};

void nft_rule_attr_set_data(struct nft_rule *r, uint16_t attr,
			    const void *data, uint32_t data_len)
{
	if (attr > NFT_RULE_ATTR_MAX)
		return;

	nft_assert_validate(data, nft_rule_attr_validate, attr, data_len);

	switch(attr) {
	case NFT_RULE_ATTR_TABLE:
		if (r->table)
			xfree(r->table);

		r->table = strdup(data);
		break;
	case NFT_RULE_ATTR_CHAIN:
		if (r->chain)
			xfree(r->chain);

		r->chain = strdup(data);
		break;
	case NFT_RULE_ATTR_HANDLE:
		r->handle = *((uint64_t *)data);
		break;
	case NFT_RULE_ATTR_COMPAT_PROTO:
		r->compat.proto = *((uint32_t *)data);
		break;
	case NFT_RULE_ATTR_COMPAT_FLAGS:
		r->compat.flags = *((uint32_t *)data);
		break;
	case NFT_RULE_ATTR_FAMILY:
		r->family = *((uint32_t *)data);
		break;
	case NFT_RULE_ATTR_POSITION:
		r->position = *((uint64_t *)data);
		break;
	case NFT_RULE_ATTR_USERDATA:
		r->user.data = (void *)data;
		r->user.len = data_len;
		break;
	}
	r->flags |= (1 << attr);
}
EXPORT_SYMBOL(nft_rule_attr_set_data);

void nft_rule_attr_set(struct nft_rule *r, uint16_t attr, const void *data)
{
	nft_rule_attr_set_data(r, attr, data, nft_rule_attr_validate[attr]);
}
EXPORT_SYMBOL(nft_rule_attr_set);

void nft_rule_attr_set_u32(struct nft_rule *r, uint16_t attr, uint32_t val)
{
	nft_rule_attr_set_data(r, attr, &val, sizeof(uint32_t));
}
EXPORT_SYMBOL(nft_rule_attr_set_u32);

void nft_rule_attr_set_u64(struct nft_rule *r, uint16_t attr, uint64_t val)
{
	nft_rule_attr_set_data(r, attr, &val, sizeof(uint64_t));
}
EXPORT_SYMBOL(nft_rule_attr_set_u64);

void nft_rule_attr_set_str(struct nft_rule *r, uint16_t attr, const char *str)
{
	nft_rule_attr_set_data(r, attr, str, strlen(str));
}
EXPORT_SYMBOL(nft_rule_attr_set_str);

const void *nft_rule_attr_get_data(const struct nft_rule *r, uint16_t attr,
				   uint32_t *data_len)
{
	if (!(r->flags & (1 << attr)))
		return NULL;

	switch(attr) {
	case NFT_RULE_ATTR_FAMILY:
		*data_len = sizeof(uint32_t);
		return &r->family;
	case NFT_RULE_ATTR_TABLE:
		return r->table;
	case NFT_RULE_ATTR_CHAIN:
		return r->chain;
	case NFT_RULE_ATTR_HANDLE:
		*data_len = sizeof(uint64_t);
		return &r->handle;
	case NFT_RULE_ATTR_COMPAT_PROTO:
		*data_len = sizeof(uint32_t);
		return &r->compat.proto;
	case NFT_RULE_ATTR_COMPAT_FLAGS:
		*data_len = sizeof(uint32_t);
		return &r->compat.flags;
	case NFT_RULE_ATTR_POSITION:
		*data_len = sizeof(uint64_t);
		return &r->position;
	case NFT_RULE_ATTR_USERDATA:
		*data_len = r->user.len;
		return r->user.data;
	}
	return NULL;
}
EXPORT_SYMBOL(nft_rule_attr_get_data);

const void *nft_rule_attr_get(const struct nft_rule *r, uint16_t attr)
{
	uint32_t data_len;
	return nft_rule_attr_get_data(r, attr, &data_len);
}
EXPORT_SYMBOL(nft_rule_attr_get);

const char *nft_rule_attr_get_str(const struct nft_rule *r, uint16_t attr)
{
	return nft_rule_attr_get(r, attr);
}
EXPORT_SYMBOL(nft_rule_attr_get_str);

uint32_t nft_rule_attr_get_u32(const struct nft_rule *r, uint16_t attr)
{
	uint32_t data_len;
	const uint32_t *val = nft_rule_attr_get_data(r, attr, &data_len);

	nft_assert(val, attr, data_len == sizeof(uint32_t));

	return val ? *val : 0;
}
EXPORT_SYMBOL(nft_rule_attr_get_u32);

uint64_t nft_rule_attr_get_u64(const struct nft_rule *r, uint16_t attr)
{
	uint32_t data_len;
	const uint64_t *val = nft_rule_attr_get_data(r, attr, &data_len);

	nft_assert(val, attr, data_len == sizeof(uint64_t));

	return val ? *val : 0;
}
EXPORT_SYMBOL(nft_rule_attr_get_u64);

uint8_t nft_rule_attr_get_u8(const struct nft_rule *r, uint16_t attr)
{
	uint32_t data_len;
	const uint8_t *val = nft_rule_attr_get_data(r, attr, &data_len);

	nft_assert(val, attr, data_len == sizeof(uint8_t));

	return val ? *val : 0;
}
EXPORT_SYMBOL(nft_rule_attr_get_u8);

void nft_rule_nlmsg_build_payload(struct nlmsghdr *nlh, struct nft_rule *r)
{
	struct nft_rule_expr *expr;
	struct nlattr *nest;

	if (r->flags & (1 << NFT_RULE_ATTR_TABLE))
		mnl_attr_put_strz(nlh, NFTA_RULE_TABLE, r->table);
	if (r->flags & (1 << NFT_RULE_ATTR_CHAIN))
		mnl_attr_put_strz(nlh, NFTA_RULE_CHAIN, r->chain);
	if (r->flags & (1 << NFT_RULE_ATTR_HANDLE))
		mnl_attr_put_u64(nlh, NFTA_RULE_HANDLE, htobe64(r->handle));
	if (r->flags & (1 << NFT_RULE_ATTR_POSITION))
		mnl_attr_put_u64(nlh, NFTA_RULE_POSITION, htobe64(r->position));
	if (r->flags & (1 << NFT_RULE_ATTR_USERDATA)) {
		mnl_attr_put(nlh, NFTA_RULE_USERDATA, r->user.len,
			     r->user.data);
	}

	if (!list_empty(&r->expr_list)) {
		nest = mnl_attr_nest_start(nlh, NFTA_RULE_EXPRESSIONS);
		list_for_each_entry(expr, &r->expr_list, head) {
			nft_rule_expr_build_payload(nlh, expr);
		}
		mnl_attr_nest_end(nlh, nest);
	}

	if (r->flags & (1 << NFT_RULE_ATTR_COMPAT_PROTO) &&
	    r->flags & (1 << NFT_RULE_ATTR_COMPAT_FLAGS)) {

		nest = mnl_attr_nest_start(nlh, NFTA_RULE_COMPAT);
		mnl_attr_put_u32(nlh, NFTA_RULE_COMPAT_PROTO,
				 htonl(r->compat.proto));
		mnl_attr_put_u32(nlh, NFTA_RULE_COMPAT_FLAGS,
				 htonl(r->compat.flags));
		mnl_attr_nest_end(nlh, nest);
	}
}
EXPORT_SYMBOL(nft_rule_nlmsg_build_payload);

void nft_rule_add_expr(struct nft_rule *r, struct nft_rule_expr *expr)
{
	list_add_tail(&expr->head, &r->expr_list);
}
EXPORT_SYMBOL(nft_rule_add_expr);

static int nft_rule_parse_attr_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, NFTA_RULE_MAX) < 0)
		return MNL_CB_OK;

	switch(type) {
	case NFTA_RULE_TABLE:
	case NFTA_RULE_CHAIN:
		if (mnl_attr_validate(attr, MNL_TYPE_STRING) < 0) {
			perror("mnl_attr_validate");
			return MNL_CB_ERROR;
		}
		break;
	case NFTA_RULE_HANDLE:
		if (mnl_attr_validate(attr, MNL_TYPE_U64) < 0) {
			perror("mnl_attr_validate");
			return MNL_CB_ERROR;
		}
		break;
	case NFTA_RULE_COMPAT:
		if (mnl_attr_validate(attr, MNL_TYPE_NESTED) < 0) {
			perror("mnl_attr_validate");
			return MNL_CB_ERROR;
		}
		break;
	case NFTA_RULE_POSITION:
		if (mnl_attr_validate(attr, MNL_TYPE_U64) < 0) {
			perror("mnl_attr_validate");
			return MNL_CB_ERROR;
		}
		break;
	case NFTA_RULE_USERDATA:
		if (mnl_attr_validate(attr, MNL_TYPE_BINARY) < 0) {
			perror("mnl_attr_validate");
			return MNL_CB_ERROR;
		}
		break;
	}

	tb[type] = attr;
	return MNL_CB_OK;
}

static int nft_rule_parse_expr_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, NFTA_EXPR_MAX) < 0)
		return MNL_CB_OK;

	switch(type) {
	case NFTA_EXPR_NAME:
		if (mnl_attr_validate(attr, MNL_TYPE_STRING) < 0) {
			perror("mnl_attr_validate");
			return MNL_CB_ERROR;
		}
		break;
	case NFTA_EXPR_DATA:
		if (mnl_attr_validate(attr, MNL_TYPE_NESTED) < 0) {
			perror("mnl_attr_validate");
			return MNL_CB_ERROR;
		}
		break;
	}

	tb[type] = attr;
	return MNL_CB_OK;
}

static int nft_rule_parse_expr2(struct nlattr *attr, struct nft_rule *r)
{
	struct nlattr *tb[NFTA_EXPR_MAX+1] = {};
	struct nft_rule_expr *expr;

	if (mnl_attr_parse_nested(attr, nft_rule_parse_expr_cb, tb) < 0)
		return -1;

	expr = nft_rule_expr_alloc(mnl_attr_get_str(tb[NFTA_EXPR_NAME]));
	if (expr == NULL)
		return -1;

	if (tb[NFTA_EXPR_DATA]) {
		if (expr->ops->parse(expr, tb[NFTA_EXPR_DATA]) < 0) {
			xfree(expr);
			return -1;
		}
	}
	list_add_tail(&expr->head, &r->expr_list);

	return 0;
}

static int nft_rule_parse_expr(struct nlattr *nest, struct nft_rule *r)
{
	struct nlattr *attr;

	mnl_attr_for_each_nested(attr, nest) {
		if (mnl_attr_get_type(attr) != NFTA_LIST_ELEM)
			return -1;

		nft_rule_parse_expr2(attr, r);
	}
	return 0;
}

static int nft_rule_parse_compat_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, NFTA_RULE_COMPAT_MAX) < 0)
		return MNL_CB_OK;

	switch(type) {
	case NFTA_RULE_COMPAT_PROTO:
	case NFTA_RULE_COMPAT_FLAGS:
		if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0) {
			perror("mnl_attr_validate");
			return MNL_CB_ERROR;
		}
		break;
	}

	tb[type] = attr;
	return MNL_CB_OK;
}

static int nft_rule_parse_compat(struct nlattr *nest, struct nft_rule *r)
{
	struct nlattr *tb[NFTA_RULE_COMPAT_MAX+1] = {};

	if (mnl_attr_parse_nested(nest, nft_rule_parse_compat_cb, tb) < 0)
		return -1;

	if (tb[NFTA_RULE_COMPAT_PROTO]) {
		r->compat.proto =
			ntohl(mnl_attr_get_u32(tb[NFTA_RULE_COMPAT_PROTO]));
		r->flags |= (1 << NFT_RULE_ATTR_COMPAT_PROTO);
	}
	if (tb[NFTA_RULE_COMPAT_FLAGS]) {
		r->compat.flags =
			ntohl(mnl_attr_get_u32(tb[NFTA_RULE_COMPAT_FLAGS]));
		r->flags |= (1 << NFT_RULE_ATTR_COMPAT_FLAGS);
	}
	return 0;
}

int nft_rule_nlmsg_parse(const struct nlmsghdr *nlh, struct nft_rule *r)
{
	struct nlattr *tb[NFTA_RULE_MAX+1] = {};
	struct nfgenmsg *nfg = mnl_nlmsg_get_payload(nlh);
	int ret = 0;

	if (mnl_attr_parse(nlh, sizeof(*nfg), nft_rule_parse_attr_cb, tb) < 0)
		return -1;

	if (tb[NFTA_RULE_TABLE]) {
		r->table = strdup(mnl_attr_get_str(tb[NFTA_RULE_TABLE]));
		r->flags |= (1 << NFT_RULE_ATTR_TABLE);
	}
	if (tb[NFTA_RULE_CHAIN]) {
		r->chain = strdup(mnl_attr_get_str(tb[NFTA_RULE_CHAIN]));
		r->flags |= (1 << NFT_RULE_ATTR_CHAIN);
	}
	if (tb[NFTA_RULE_HANDLE]) {
		r->handle = be64toh(mnl_attr_get_u64(tb[NFTA_RULE_HANDLE]));
		r->flags |= (1 << NFT_RULE_ATTR_HANDLE);
	}
	if (tb[NFTA_RULE_EXPRESSIONS])
		ret = nft_rule_parse_expr(tb[NFTA_RULE_EXPRESSIONS], r);
	if (tb[NFTA_RULE_COMPAT])
		ret = nft_rule_parse_compat(tb[NFTA_RULE_COMPAT], r);
	if (tb[NFTA_RULE_POSITION]) {
		r->position = be64toh(mnl_attr_get_u64(tb[NFTA_RULE_POSITION]));
		r->flags |= (1 << NFT_RULE_ATTR_POSITION);
	}
	if (tb[NFTA_RULE_USERDATA]) {
		const void *udata =
			mnl_attr_get_payload(tb[NFTA_RULE_USERDATA]);

		if (r->user.data)
			xfree(r->user.data);

		r->user.len = mnl_attr_get_payload_len(tb[NFTA_RULE_USERDATA]);

		r->user.data = malloc(r->user.len);
		if (r->user.data == NULL)
			return -1;

		memcpy(r->user.data, udata, r->user.len);
		r->flags |= (1 << NFT_RULE_ATTR_USERDATA);
	}

	r->family = nfg->nfgen_family;
	r->flags |= (1 << NFT_RULE_ATTR_FAMILY);

	return ret;
}
EXPORT_SYMBOL(nft_rule_nlmsg_parse);

#ifdef JSON_PARSING
int nft_jansson_parse_rule(struct nft_rule *r, json_t *tree,
			   struct nft_parse_err *err)
{
	json_t *root, *array;
	struct nft_rule_expr *e;
	const char *str = NULL;
	uint64_t uval64;
	uint32_t uval32;
	int i, family;

	root = nft_jansson_get_node(tree, "rule", err);
	if (root == NULL)
		return -1;

	if (nft_jansson_node_exist(root, "family")) {
		if (nft_jansson_parse_family(root, &family, err) != 0)
			goto err;

		nft_rule_attr_set_u32(r, NFT_RULE_ATTR_FAMILY, family);
	}

	if (nft_jansson_node_exist(root, "table")) {
		str = nft_jansson_parse_str(root, "table", err);
		if (str == NULL)
			goto err;

		nft_rule_attr_set_str(r, NFT_RULE_ATTR_TABLE, str);
	}

	if (nft_jansson_node_exist(root, "chain")) {
		str = nft_jansson_parse_str(root, "chain", err);
		if (str == NULL)
			goto err;

		nft_rule_attr_set_str(r, NFT_RULE_ATTR_CHAIN, str);
	}

	if (nft_jansson_node_exist(root, "handle")) {
		if (nft_jansson_parse_val(root, "handle", NFT_TYPE_U64, &uval64,
					  err) < 0)
			goto err;

		nft_rule_attr_set_u64(r, NFT_RULE_ATTR_HANDLE, uval64);
	}

	if (nft_jansson_node_exist(root, "compat_proto") ||
	    nft_jansson_node_exist(root, "compat_flags")) {
		if (nft_jansson_parse_val(root, "compat_proto", NFT_TYPE_U32,
					  &uval32, err) < 0)
			goto err;

		nft_rule_attr_set_u32(r, NFT_RULE_ATTR_COMPAT_PROTO, uval32);

		if (nft_jansson_parse_val(root, "compat_flags", NFT_TYPE_U32,
					  &uval32, err) < 0)
			goto err;

		nft_rule_attr_set_u32(r, NFT_RULE_ATTR_COMPAT_FLAGS, uval32);
	}

	if (nft_jansson_node_exist(root, "position")) {
		if (nft_jansson_parse_val(root, "position", NFT_TYPE_U64,
					  &uval64, err) < 0)
			goto err;

		nft_rule_attr_set_u64(r, NFT_RULE_ATTR_POSITION, uval64);
	}

	array = json_object_get(root, "expr");
	if (array == NULL) {
		err->error = NFT_PARSE_EMISSINGNODE;
		err->node_name = "expr";
		goto err;
	}

	for (i = 0; i < json_array_size(array); ++i) {

		e = nft_jansson_expr_parse(json_array_get(array, i), err);
		if (e == NULL)
			goto err;

		nft_rule_add_expr(r, e);
	}

	nft_jansson_free_root(tree);
	return 0;
err:
	nft_jansson_free_root(tree);
	return -1;
}
#endif

static int nft_rule_json_parse(struct nft_rule *r, const void *json,
			       struct nft_parse_err *err,
			       enum nft_parse_input input)
{
#ifdef JSON_PARSING
	json_t *tree;
	json_error_t error;

	tree = nft_jansson_create_root(json, &error, err, input);
	if (tree == NULL)
		return -1;

	return nft_jansson_parse_rule(r, tree, err);
#else
	errno = EOPNOTSUPP;
	return -1;
#endif
}

#ifdef XML_PARSING
int nft_mxml_rule_parse(mxml_node_t *tree, struct nft_rule *r,
			struct nft_parse_err *err)
{
	mxml_node_t *node;
	struct nft_rule_expr *e;
	const char *table, *chain;
	int family;

	family = nft_mxml_family_parse(tree, "family", MXML_DESCEND_FIRST,
				       NFT_XML_MAND, err);
	if (family >= 0)
		nft_rule_attr_set_u32(r, NFT_RULE_ATTR_FAMILY, family);

	table = nft_mxml_str_parse(tree, "table", MXML_DESCEND_FIRST,
				   NFT_XML_MAND, err);
	if (table != NULL)
		nft_rule_attr_set_str(r, NFT_RULE_ATTR_TABLE, table);

	chain = nft_mxml_str_parse(tree, "chain", MXML_DESCEND_FIRST,
				   NFT_XML_MAND, err);
	if (chain != NULL)
		nft_rule_attr_set_str(r, NFT_RULE_ATTR_CHAIN, chain);

	if (nft_mxml_num_parse(tree, "handle", MXML_DESCEND_FIRST, BASE_DEC,
			      &r->handle, NFT_TYPE_U64, NFT_XML_MAND, err) >= 0)
		r->flags |= (1 << NFT_RULE_ATTR_HANDLE);

	if (nft_mxml_num_parse(tree, "compat_proto", MXML_DESCEND_FIRST,
			       BASE_DEC, &r->compat.proto, NFT_TYPE_U32,
			       NFT_XML_OPT, err) >= 0)
		r->flags |= (1 << NFT_RULE_ATTR_COMPAT_PROTO);

	if (nft_mxml_num_parse(tree, "compat_flags", MXML_DESCEND_FIRST,
			       BASE_DEC, &r->compat.flags, NFT_TYPE_U32,
			       NFT_XML_OPT, err) >= 0)
		r->flags |= (1 << NFT_RULE_ATTR_COMPAT_FLAGS);

	if (nft_rule_attr_is_set(r, NFT_RULE_ATTR_COMPAT_PROTO) !=
			nft_rule_attr_is_set(r, NFT_RULE_ATTR_COMPAT_FLAGS)) {
		errno = EINVAL;
	}

	if (nft_mxml_num_parse(tree, "position", MXML_DESCEND_FIRST,
			       BASE_DEC, &r->position, NFT_TYPE_U64,
			       NFT_XML_OPT, err) >= 0)
		r->flags |= (1 << NFT_RULE_ATTR_POSITION);

	/* Iterating over <expr> */
	for (node = mxmlFindElement(tree, tree, "expr", "type",
				    NULL, MXML_DESCEND);
		node != NULL;
		node = mxmlFindElement(node, tree, "expr", "type",
				       NULL, MXML_DESCEND)) {
		e = nft_mxml_expr_parse(node, err);
		if (e == NULL)
			return -1;

		nft_rule_add_expr(r, e);
	}

	return 0;
}
#endif

static int nft_rule_xml_parse(struct nft_rule *r, const void *xml,
			      struct nft_parse_err *err,
			      enum nft_parse_input input)
{
#ifdef XML_PARSING
	int ret;
	mxml_node_t *tree = nft_mxml_build_tree(xml, "rule", err, input);
	if (tree == NULL)
		return -1;

	ret = nft_mxml_rule_parse(tree, r, err);
	mxmlDelete(tree);
	return ret;
#else
	errno = EOPNOTSUPP;
	return -1;
#endif
}

static int nft_rule_do_parse(struct nft_rule *r, enum nft_parse_type type,
			     const void *data, struct nft_parse_err *err,
			     enum nft_parse_input input)
{
	int ret;
	struct nft_parse_err perr;

	switch (type) {
	case NFT_PARSE_XML:
		ret = nft_rule_xml_parse(r, data, &perr, input);
		break;
	case NFT_PARSE_JSON:
		ret = nft_rule_json_parse(r, data, &perr, input);
		break;
	default:
		ret = -1;
		errno = EOPNOTSUPP;
		break;
	}
	if (err != NULL)
		*err = perr;

	return ret;
}
int nft_rule_parse(struct nft_rule *r, enum nft_parse_type type,
		   const char *data, struct nft_parse_err *err)
{
	return nft_rule_do_parse(r, type, data, err, NFT_PARSE_BUFFER);
}
EXPORT_SYMBOL(nft_rule_parse);

int nft_rule_parse_file(struct nft_rule *r, enum nft_parse_type type,
			FILE *fp, struct nft_parse_err *err)
{
	return nft_rule_do_parse(r, type, fp, err, NFT_PARSE_FILE);
}
EXPORT_SYMBOL(nft_rule_parse_file);

static int nft_rule_snprintf_json(char *buf, size_t size, struct nft_rule *r,
					 uint32_t type, uint32_t flags)
{
	int ret, len = size, offset = 0;
	struct nft_rule_expr *expr;

	ret = snprintf(buf, len, "{\"rule\":{");
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	if (r->flags & (1 << NFT_RULE_ATTR_FAMILY)) {
		ret = snprintf(buf+offset, len, "\"family\":\"%s\",",
			       nft_family2str(r->family));
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	if (r->flags & (1 << NFT_RULE_ATTR_TABLE)) {
		ret = snprintf(buf+offset, len, "\"table\":\"%s\",",
			       r->table);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	if (r->flags & (1 << NFT_RULE_ATTR_CHAIN)) {
		ret = snprintf(buf+offset, len, "\"chain\":\"%s\",",
			       r->chain);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}
	if (r->flags & (1 << NFT_RULE_ATTR_HANDLE)) {
		ret = snprintf(buf+offset, len, "\"handle\":%llu,",
			       (unsigned long long)r->handle);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	if (r->flags & (1 << NFT_RULE_ATTR_COMPAT_PROTO) ||
	    r->flags & (1 << NFT_RULE_ATTR_COMPAT_FLAGS)) {
		ret = snprintf(buf+offset, len, "\"compat_flags\":%u,"
					        "\"compat_proto\":%u,",
			       r->compat.flags, r->compat.proto);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	if (r->flags & (1 << NFT_RULE_ATTR_POSITION)) {
		ret = snprintf(buf+offset, len, "\"position\":%"PRIu64",",
			       r->position);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	ret = snprintf(buf+offset, len, "\"expr\":[");
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	list_for_each_entry(expr, &r->expr_list, head) {
		ret = snprintf(buf+offset, len,
			       "{\"type\":\"%s\",", expr->ops->name);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

		ret = expr->ops->snprintf(buf+offset, len, type, flags, expr);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

		/*
		 * Remove comma from the first element if there is type
		 * key-value pair only. Example: "expr":[{"type":"log"}]
		 */
		if (ret == 0) {
			offset--;
			len--;
		}

		ret = snprintf(buf+offset, len, "},");
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	}
	/* Remove comma from last element */
	offset--;
	ret = snprintf(buf+offset, len, "]}}");
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	return offset;
}

static int nft_rule_snprintf_xml(char *buf, size_t size, struct nft_rule *r,
				 uint32_t type, uint32_t flags)
{
	int ret, len = size, offset = 0;
	struct nft_rule_expr *expr;

	ret = snprintf(buf, len, "<rule>");
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	if (r->flags & (1 << NFT_RULE_ATTR_FAMILY)) {
		ret = snprintf(buf+offset, len, "<family>%s</family>",
			       nft_family2str(r->family));
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	if (r->flags & (1 << NFT_RULE_ATTR_TABLE)) {
		ret = snprintf(buf+offset, len, "<table>%s</table>",
			       r->table);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	if (r->flags & (1 << NFT_RULE_ATTR_CHAIN)) {
		ret = snprintf(buf+offset, len, "<chain>%s</chain>",
			       r->chain);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}
	if (r->flags & (1 << NFT_RULE_ATTR_HANDLE)) {
		ret = snprintf(buf+offset, len, "<handle>%llu</handle>",
			       (unsigned long long)r->handle);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	if (r->compat.flags != 0 || r->compat.proto != 0) {
		ret = snprintf(buf+offset, len,
			       "<compat_flags>%u</compat_flags>"
			       "<compat_proto>%u</compat_proto>",
			       r->compat.flags, r->compat.proto);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	if (r->flags & (1 << NFT_RULE_ATTR_POSITION)) {
		ret = snprintf(buf+offset, len,
			       "<position>%"PRIu64"</position>",
			       r->position);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	list_for_each_entry(expr, &r->expr_list, head) {
		ret = snprintf(buf+offset, len,
				"<expr type=\"%s\">", expr->ops->name);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

		ret = nft_rule_expr_snprintf(buf+offset, len, expr,
					     type, flags);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

		ret = snprintf(buf+offset, len, "</expr>");
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	}
	ret = snprintf(buf+offset, len, "</rule>");
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	return offset;
}

static int nft_rule_snprintf_default(char *buf, size_t size, struct nft_rule *r,
				     uint32_t type, uint32_t flags)
{
	struct nft_rule_expr *expr;
	int ret, len = size, offset = 0, i;

	if (r->flags & (1 << NFT_RULE_ATTR_FAMILY)) {
		ret = snprintf(buf+offset, len, "%s ",
			       nft_family2str(r->family));
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	if (r->flags & (1 << NFT_RULE_ATTR_TABLE)) {
		ret = snprintf(buf+offset, len, "%s ",
			       r->table);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	if (r->flags & (1 << NFT_RULE_ATTR_CHAIN)) {
		ret = snprintf(buf+offset, len, "%s ",
			       r->chain);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}
	if (r->flags & (1 << NFT_RULE_ATTR_HANDLE)) {
		ret = snprintf(buf+offset, len, "%llu ",
			       (unsigned long long)r->handle);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	if (r->flags & (1 << NFT_RULE_ATTR_POSITION)) {
		ret = snprintf(buf+offset, len, "%llu ",
			       (unsigned long long)r->position);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	ret = snprintf(buf+offset, len, "\n");
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	list_for_each_entry(expr, &r->expr_list, head) {
		ret = snprintf(buf+offset, len, "  [ %s ", expr->ops->name);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

		ret = nft_rule_expr_snprintf(buf+offset, len, expr,
					     type, flags);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

		ret = snprintf(buf+offset, len, "]\n");
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	if (r->user.len) {
		ret = snprintf(buf+offset, len, "  userdata = { ");
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

		for (i = 0; i < r->user.len; i++) {
			char *c = r->user.data;

			ret = snprintf(buf+offset, len, "%c",
				       isalnum(c[i]) ? c[i] : 0);
			SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
		}

		ret = snprintf(buf+offset, len, " }\n");
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	}

	return offset;
}

int nft_rule_snprintf(char *buf, size_t size, struct nft_rule *r,
		       uint32_t type, uint32_t flags)
{
	int ret, len = size, offset = 0;
	uint32_t inner_flags = flags;

	inner_flags &= ~NFT_OF_EVENT_ANY;

	ret = nft_event_header_snprintf(buf+offset, len, type, flags);
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	switch(type) {
	case NFT_OUTPUT_DEFAULT:
		ret = nft_rule_snprintf_default(buf+offset, len, r, type,
						inner_flags);
		break;
	case NFT_OUTPUT_XML:
		ret = nft_rule_snprintf_xml(buf+offset, len, r, type,
					    inner_flags);
		break;
	case NFT_OUTPUT_JSON:
		ret = nft_rule_snprintf_json(buf+offset, len, r, type,
					     inner_flags);
		break;
	default:
		return -1;
	}

	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	ret = nft_event_footer_snprintf(buf+offset, len, type, flags);
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	return offset;
}
EXPORT_SYMBOL(nft_rule_snprintf);

static inline int nft_rule_do_snprintf(char *buf, size_t size, void *r,
				       uint32_t type, uint32_t flags)
{
	return nft_rule_snprintf(buf, size, r, type, flags);
}

int nft_rule_fprintf(FILE *fp, struct nft_rule *r, uint32_t type,
		     uint32_t flags)
{
	return nft_fprintf(fp, r, type, flags, nft_rule_do_snprintf);
}
EXPORT_SYMBOL(nft_rule_fprintf);

int nft_rule_expr_foreach(struct nft_rule *r,
                          int (*cb)(struct nft_rule_expr *e, void *data),
                          void *data)
{
       struct nft_rule_expr *cur, *tmp;
       int ret;

       list_for_each_entry_safe(cur, tmp, &r->expr_list, head) {
               ret = cb(cur, data);
               if (ret < 0)
                       return ret;
       }
       return 0;
}
EXPORT_SYMBOL(nft_rule_expr_foreach);

struct nft_rule_expr_iter {
	struct nft_rule		*r;
	struct nft_rule_expr	*cur;
};

struct nft_rule_expr_iter *nft_rule_expr_iter_create(struct nft_rule *r)
{
	struct nft_rule_expr_iter *iter;

	iter = calloc(1, sizeof(struct nft_rule_expr_iter));
	if (iter == NULL)
		return NULL;

	iter->r = r;
	iter->cur = list_entry(r->expr_list.next, struct nft_rule_expr, head);

	return iter;
}
EXPORT_SYMBOL(nft_rule_expr_iter_create);

struct nft_rule_expr *nft_rule_expr_iter_next(struct nft_rule_expr_iter *iter)
{
	struct nft_rule_expr *expr = iter->cur;

	/* get next expression, if any */
	iter->cur = list_entry(iter->cur->head.next, struct nft_rule_expr, head);
	if (&iter->cur->head == iter->r->expr_list.next)
		return NULL;

	return expr;
}
EXPORT_SYMBOL(nft_rule_expr_iter_next);

void nft_rule_expr_iter_destroy(struct nft_rule_expr_iter *iter)
{
	xfree(iter);
}
EXPORT_SYMBOL(nft_rule_expr_iter_destroy);

struct nft_rule_list {
	struct list_head list;
};

struct nft_rule_list *nft_rule_list_alloc(void)
{
	struct nft_rule_list *list;

	list = calloc(1, sizeof(struct nft_rule_list));
	if (list == NULL)
		return NULL;

	INIT_LIST_HEAD(&list->list);

	return list;
}
EXPORT_SYMBOL(nft_rule_list_alloc);

void nft_rule_list_free(struct nft_rule_list *list)
{
	struct nft_rule *r, *tmp;

	list_for_each_entry_safe(r, tmp, &list->list, head) {
		list_del(&r->head);
		nft_rule_free(r);
	}
	xfree(list);
}
EXPORT_SYMBOL(nft_rule_list_free);

int nft_rule_list_is_empty(struct nft_rule_list *list)
{
	return list_empty(&list->list);
}
EXPORT_SYMBOL(nft_rule_list_is_empty);

void nft_rule_list_add(struct nft_rule *r, struct nft_rule_list *list)
{
	list_add(&r->head, &list->list);
}
EXPORT_SYMBOL(nft_rule_list_add);

void nft_rule_list_add_tail(struct nft_rule *r, struct nft_rule_list *list)
{
	list_add_tail(&r->head, &list->list);
}
EXPORT_SYMBOL(nft_rule_list_add_tail);

void nft_rule_list_del(struct nft_rule *r)
{
	list_del(&r->head);
}
EXPORT_SYMBOL(nft_rule_list_del);

int nft_rule_list_foreach(struct nft_rule_list *rule_list,
			  int (*cb)(struct nft_rule *r, void *data),
			  void *data)
{
	struct nft_rule *cur, *tmp;
	int ret;

	list_for_each_entry_safe(cur, tmp, &rule_list->list, head) {
		ret = cb(cur, data);
		if (ret < 0)
			return ret;
	}
	return 0;
}
EXPORT_SYMBOL(nft_rule_list_foreach);

struct nft_rule_list_iter {
	struct nft_rule_list	*list;
	struct nft_rule		*cur;
};

struct nft_rule_list_iter *nft_rule_list_iter_create(struct nft_rule_list *l)
{
	struct nft_rule_list_iter *iter;

	iter = calloc(1, sizeof(struct nft_rule_list_iter));
	if (iter == NULL)
		return NULL;

	iter->list = l;
	iter->cur = list_entry(l->list.next, struct nft_rule, head);

	return iter;
}
EXPORT_SYMBOL(nft_rule_list_iter_create);

struct nft_rule *nft_rule_list_iter_cur(struct nft_rule_list_iter *iter)
{
	return iter->cur;
}
EXPORT_SYMBOL(nft_rule_list_iter_cur);

struct nft_rule *nft_rule_list_iter_next(struct nft_rule_list_iter *iter)
{
	struct nft_rule *r = iter->cur;

	/* get next rule, if any */
	iter->cur = list_entry(iter->cur->head.next, struct nft_rule, head);
	if (&iter->cur->head == iter->list->list.next)
		return NULL;

	return r;
}
EXPORT_SYMBOL(nft_rule_list_iter_next);

void nft_rule_list_iter_destroy(struct nft_rule_list_iter *iter)
{
	xfree(iter);
}
EXPORT_SYMBOL(nft_rule_list_iter_destroy);
