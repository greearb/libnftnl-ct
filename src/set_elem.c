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
#include <string.h>
#include <netinet/in.h>
#include <errno.h>
#include <ctype.h>

#include <libmnl/libmnl.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nf_tables.h>

#include <libnftnl/set.h>
#include <libnftnl/rule.h>
#include <libnftnl/expr.h>

struct nftnl_set_elem *nftnl_set_elem_alloc(void)
{
	struct nftnl_set_elem *s;

	s = calloc(1, sizeof(struct nftnl_set_elem));
	if (s == NULL)
		return NULL;

	return s;
}
EXPORT_SYMBOL_ALIAS(nftnl_set_elem_alloc, nft_set_elem_alloc);

void nftnl_set_elem_free(struct nftnl_set_elem *s)
{
	if (s->flags & (1 << NFTNL_SET_ELEM_CHAIN)) {
		if (s->data.chain) {
			xfree(s->data.chain);
			s->data.chain = NULL;
		}
	}

	if (s->flags & (1 << NFTNL_SET_ELEM_EXPR))
		nftnl_expr_free(s->expr);

	if (s->flags & (1 << NFTNL_SET_ELEM_USERDATA))
		xfree(s->user.data);

	xfree(s);
}
EXPORT_SYMBOL_ALIAS(nftnl_set_elem_free, nft_set_elem_free);

bool nftnl_set_elem_is_set(const struct nftnl_set_elem *s, uint16_t attr)
{
	return s->flags & (1 << attr);
}
EXPORT_SYMBOL_ALIAS(nftnl_set_elem_is_set, nft_set_elem_attr_is_set);

void nftnl_set_elem_unset(struct nftnl_set_elem *s, uint16_t attr)
{
	switch (attr) {
	case NFTNL_SET_ELEM_CHAIN:
		if (s->flags & (1 << NFTNL_SET_ELEM_CHAIN)) {
			if (s->data.chain) {
				xfree(s->data.chain);
				s->data.chain = NULL;
			}
		}
		break;
	case NFTNL_SET_ELEM_FLAGS:
	case NFTNL_SET_ELEM_KEY:	/* NFTA_SET_ELEM_KEY */
	case NFTNL_SET_ELEM_VERDICT:	/* NFTA_SET_ELEM_DATA */
	case NFTNL_SET_ELEM_DATA:	/* NFTA_SET_ELEM_DATA */
	case NFTNL_SET_ELEM_TIMEOUT:	/* NFTA_SET_ELEM_TIMEOUT */
	case NFTNL_SET_ELEM_EXPIRATION:	/* NFTA_SET_ELEM_EXPIRATION */
		break;
	case NFTNL_SET_ELEM_USERDATA:	/* NFTA_SET_ELEM_USERDATA */
		xfree(s->user.data);
		break;
	case NFTNL_SET_ELEM_EXPR:
		if (s->flags & (1 << NFTNL_SET_ELEM_EXPR)) {
			nftnl_expr_free(s->expr);
			s->expr = NULL;
		}
		break;
	default:
		return;
	}

	s->flags &= ~(1 << attr);
}
EXPORT_SYMBOL_ALIAS(nftnl_set_elem_unset, nft_set_elem_attr_unset);

int nftnl_set_elem_set(struct nftnl_set_elem *s, uint16_t attr,
		       const void *data, uint32_t data_len)
{
	switch(attr) {
	case NFTNL_SET_ELEM_FLAGS:
		s->set_elem_flags = *((uint32_t *)data);
		break;
	case NFTNL_SET_ELEM_KEY:	/* NFTA_SET_ELEM_KEY */
		memcpy(&s->key.val, data, data_len);
		s->key.len = data_len;
		break;
	case NFTNL_SET_ELEM_VERDICT:	/* NFTA_SET_ELEM_DATA */
		s->data.verdict = *((uint32_t *)data);
		break;
	case NFTNL_SET_ELEM_CHAIN:	/* NFTA_SET_ELEM_DATA */
		if (s->data.chain)
			xfree(s->data.chain);

		s->data.chain = strdup(data);
		if (!s->data.chain)
			return -1;
		break;
	case NFTNL_SET_ELEM_DATA:	/* NFTA_SET_ELEM_DATA */
		memcpy(s->data.val, data, data_len);
		s->data.len = data_len;
		break;
	case NFTNL_SET_ELEM_TIMEOUT:	/* NFTA_SET_ELEM_TIMEOUT */
		s->timeout = *((uint64_t *)data);
		break;
	case NFTNL_SET_ELEM_USERDATA: /* NFTA_SET_ELEM_USERDATA */
		if (s->user.data != NULL)
			xfree(s->user.data);

		s->user.data = malloc(data_len);
		if (!s->user.data)
			return -1;
		memcpy(s->user.data, data, data_len);
		s->user.len = data_len;
		break;
	}
	s->flags |= (1 << attr);
	return -1;
}
EXPORT_SYMBOL_ALIAS(nftnl_set_elem_set, nft_set_elem_attr_set);

void nftnl_set_elem_set_u32(struct nftnl_set_elem *s, uint16_t attr, uint32_t val)
{
	nftnl_set_elem_set(s, attr, &val, sizeof(uint32_t));
}
EXPORT_SYMBOL_ALIAS(nftnl_set_elem_set_u32, nft_set_elem_attr_set_u32);

void nftnl_set_elem_set_u64(struct nftnl_set_elem *s, uint16_t attr, uint64_t val)
{
	nftnl_set_elem_set(s, attr, &val, sizeof(uint64_t));
}
EXPORT_SYMBOL_ALIAS(nftnl_set_elem_set_u64, nft_set_elem_attr_set_u64);

int nftnl_set_elem_set_str(struct nftnl_set_elem *s, uint16_t attr, const char *str)
{
	return nftnl_set_elem_set(s, attr, str, strlen(str));
}
EXPORT_SYMBOL_ALIAS(nftnl_set_elem_set_str, nft_set_elem_attr_set_str);

const void *nftnl_set_elem_get(struct nftnl_set_elem *s, uint16_t attr, uint32_t *data_len)
{
	if (!(s->flags & (1 << attr)))
		return NULL;

	switch(attr) {
	case NFTNL_SET_ELEM_FLAGS:
		return &s->set_elem_flags;
	case NFTNL_SET_ELEM_KEY:	/* NFTA_SET_ELEM_KEY */
		*data_len = s->key.len;
		return &s->key.val;
	case NFTNL_SET_ELEM_VERDICT:	/* NFTA_SET_ELEM_DATA */
		return &s->data.verdict;
	case NFTNL_SET_ELEM_CHAIN:	/* NFTA_SET_ELEM_DATA */
		return s->data.chain;
	case NFTNL_SET_ELEM_DATA:	/* NFTA_SET_ELEM_DATA */
		*data_len = s->data.len;
		return &s->data.val;
	case NFTNL_SET_ELEM_TIMEOUT:	/* NFTA_SET_ELEM_TIMEOUT */
		return &s->timeout;
	case NFTNL_SET_ELEM_EXPIRATION:	/* NFTA_SET_ELEM_EXPIRATION */
		return &s->expiration;
	case NFTNL_SET_ELEM_USERDATA:
		*data_len = s->user.len;
		return s->user.data;
	case NFTNL_SET_ELEM_EXPR:
		return s->expr;
	}
	return NULL;
}
EXPORT_SYMBOL_ALIAS(nftnl_set_elem_get, nft_set_elem_attr_get);

const char *nftnl_set_elem_get_str(struct nftnl_set_elem *s, uint16_t attr)
{
	uint32_t size;

	return nftnl_set_elem_get(s, attr, &size);
}
EXPORT_SYMBOL_ALIAS(nftnl_set_elem_get_str, nft_set_elem_attr_get_str);

uint32_t nftnl_set_elem_get_u32(struct nftnl_set_elem *s, uint16_t attr)
{
	uint32_t size;
	uint32_t val = *((uint32_t *)nftnl_set_elem_get(s, attr, &size));
	return val;
}
EXPORT_SYMBOL_ALIAS(nftnl_set_elem_get_u32, nft_set_elem_attr_get_u32);

uint64_t nftnl_set_elem_get_u64(struct nftnl_set_elem *s, uint16_t attr)
{
	uint32_t size;
	uint64_t val = *((uint64_t *)nftnl_set_elem_get(s, attr, &size));
	return val;
}
EXPORT_SYMBOL_ALIAS(nftnl_set_elem_get_u64, nft_set_elem_attr_get_u64);

struct nftnl_set_elem *nftnl_set_elem_clone(struct nftnl_set_elem *elem)
{
	struct nftnl_set_elem *newelem;

	newelem = nftnl_set_elem_alloc();
	if (newelem == NULL)
		return NULL;

	memcpy(newelem, elem, sizeof(*elem));

	if (elem->flags & (1 << NFTNL_SET_ELEM_CHAIN)) {
		newelem->data.chain = strdup(elem->data.chain);
		if (!newelem->data.chain)
			goto err;
	}

	return newelem;
err:
	nftnl_set_elem_free(newelem);
	return NULL;
}

void nftnl_set_elem_nlmsg_build_payload(struct nlmsghdr *nlh,
				      struct nftnl_set_elem *e)
{
	if (e->flags & (1 << NFTNL_SET_ELEM_FLAGS))
		mnl_attr_put_u32(nlh, NFTA_SET_ELEM_FLAGS, htonl(e->set_elem_flags));
	if (e->flags & (1 << NFTNL_SET_ELEM_TIMEOUT))
		mnl_attr_put_u64(nlh, NFTA_SET_ELEM_TIMEOUT, htobe64(e->timeout));
	if (e->flags & (1 << NFTNL_SET_ELEM_KEY)) {
		struct nlattr *nest1;

		nest1 = mnl_attr_nest_start(nlh, NFTA_SET_ELEM_KEY);
		mnl_attr_put(nlh, NFTA_DATA_VALUE, e->key.len, e->key.val);
		mnl_attr_nest_end(nlh, nest1);
	}
	if (e->flags & (1 << NFTNL_SET_ELEM_VERDICT)) {
		struct nlattr *nest1, *nest2;

		nest1 = mnl_attr_nest_start(nlh, NFTA_SET_ELEM_DATA);
		nest2 = mnl_attr_nest_start(nlh, NFTA_DATA_VERDICT);
		mnl_attr_put_u32(nlh, NFTA_VERDICT_CODE, htonl(e->data.verdict));
		if (e->flags & (1 << NFTNL_SET_ELEM_CHAIN))
			mnl_attr_put_strz(nlh, NFTA_VERDICT_CHAIN, e->data.chain);

		mnl_attr_nest_end(nlh, nest1);
		mnl_attr_nest_end(nlh, nest2);
	}
	if (e->flags & (1 << NFTNL_SET_ELEM_DATA)) {
		struct nlattr *nest1;

		nest1 = mnl_attr_nest_start(nlh, NFTA_SET_ELEM_DATA);
		mnl_attr_put(nlh, NFTA_DATA_VALUE, e->data.len, e->data.val);
		mnl_attr_nest_end(nlh, nest1);
	}
	if (e->flags & (1 << NFTNL_SET_ELEM_USERDATA))
		mnl_attr_put(nlh, NFTA_SET_ELEM_USERDATA, e->user.len, e->user.data);
}

static void nftnl_set_elem_nlmsg_build_def(struct nlmsghdr *nlh,
					 struct nftnl_set *s)
{
	if (s->flags & (1 << NFTNL_SET_NAME))
		mnl_attr_put_strz(nlh, NFTA_SET_ELEM_LIST_SET, s->name);
	if (s->flags & (1 << NFTNL_SET_ID))
		mnl_attr_put_u32(nlh, NFTA_SET_ELEM_LIST_SET_ID, htonl(s->id));
	if (s->flags & (1 << NFTNL_SET_TABLE))
		mnl_attr_put_strz(nlh, NFTA_SET_ELEM_LIST_TABLE, s->table);
}

static struct nlattr *nftnl_set_elem_build(struct nlmsghdr *nlh,
					      struct nftnl_set_elem *elem, int i)
{
	struct nlattr *nest2;

	nest2 = mnl_attr_nest_start(nlh, i);
	nftnl_set_elem_nlmsg_build_payload(nlh, elem);
	mnl_attr_nest_end(nlh, nest2);

	return nest2;
}

void nftnl_set_elems_nlmsg_build_payload(struct nlmsghdr *nlh, struct nftnl_set *s)
{
	struct nftnl_set_elem *elem;
	struct nlattr *nest1;
	int i = 0;

	nftnl_set_elem_nlmsg_build_def(nlh, s);

	nest1 = mnl_attr_nest_start(nlh, NFTA_SET_ELEM_LIST_ELEMENTS);
	list_for_each_entry(elem, &s->element_list, head)
		nftnl_set_elem_build(nlh, elem, ++i);

	mnl_attr_nest_end(nlh, nest1);
}
EXPORT_SYMBOL_ALIAS(nftnl_set_elems_nlmsg_build_payload, nft_set_elems_nlmsg_build_payload);

static int nftnl_set_elem_parse_attr_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, NFTA_SET_MAX) < 0)
		return MNL_CB_OK;

	switch(type) {
	case NFTA_SET_ELEM_FLAGS:
		if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0)
			abi_breakage();
		break;
	case NFTA_SET_ELEM_TIMEOUT:
	case NFTA_SET_ELEM_EXPIRATION:
		if (mnl_attr_validate(attr, MNL_TYPE_U64) < 0)
			abi_breakage();
		break;
	case NFTA_SET_ELEM_KEY:
	case NFTA_SET_ELEM_DATA:
	case NFTA_SET_ELEM_EXPR:
		if (mnl_attr_validate(attr, MNL_TYPE_NESTED) < 0)
			abi_breakage();
		break;
	case NFTA_SET_ELEM_USERDATA:
		if (mnl_attr_validate(attr, MNL_TYPE_BINARY) < 0)
			abi_breakage();
		break;
	}

	tb[type] = attr;
	return MNL_CB_OK;
}

static int nftnl_set_elems_parse2(struct nftnl_set *s, const struct nlattr *nest)
{
	struct nlattr *tb[NFTA_SET_ELEM_MAX+1] = {};
	struct nftnl_set_elem *e;
	int ret = 0, type;

	e = nftnl_set_elem_alloc();
	if (e == NULL)
		return -1;

	if (mnl_attr_parse_nested(nest, nftnl_set_elem_parse_attr_cb, tb) < 0) {
		nftnl_set_elem_free(e);
		return -1;
	}

	if (tb[NFTA_SET_ELEM_FLAGS]) {
		e->set_elem_flags =
			ntohl(mnl_attr_get_u32(tb[NFTA_SET_ELEM_FLAGS]));
		e->flags |= (1 << NFTNL_SET_ELEM_FLAGS);
	}
	if (tb[NFTA_SET_ELEM_TIMEOUT]) {
		e->timeout = be64toh(mnl_attr_get_u64(tb[NFTA_SET_ELEM_TIMEOUT]));
		e->flags |= (1 << NFTNL_SET_ELEM_TIMEOUT);
	}
	if (tb[NFTA_SET_ELEM_EXPIRATION]) {
		e->expiration = be64toh(mnl_attr_get_u64(tb[NFTA_SET_ELEM_EXPIRATION]));
		e->flags |= (1 << NFTNL_SET_ELEM_EXPIRATION);
	}
        if (tb[NFTA_SET_ELEM_KEY]) {
		ret = nftnl_parse_data(&e->key, tb[NFTA_SET_ELEM_KEY], &type);
		e->flags |= (1 << NFTNL_SET_ELEM_KEY);
        }
        if (tb[NFTA_SET_ELEM_DATA]) {
		ret = nftnl_parse_data(&e->data, tb[NFTA_SET_ELEM_DATA], &type);
		switch(type) {
		case DATA_VERDICT:
			e->flags |= (1 << NFTNL_SET_ELEM_VERDICT);
			break;
		case DATA_CHAIN:
			e->flags |= (1 << NFTNL_SET_ELEM_VERDICT) |
				    (1 << NFTNL_SET_ELEM_CHAIN);
			break;
		case DATA_VALUE:
			e->flags |= (1 << NFTNL_SET_ELEM_DATA);
			break;
		}
        }
	if (tb[NFTA_SET_ELEM_EXPR]) {
		e->expr = nftnl_expr_parse(tb[NFTA_SET_ELEM_EXPR]);
		if (e->expr == NULL)
			goto err;
		e->flags |= (1 << NFTNL_SET_ELEM_EXPR);
	}
	if (tb[NFTA_SET_ELEM_USERDATA]) {
		const void *udata =
			mnl_attr_get_payload(tb[NFTA_SET_ELEM_USERDATA]);

		if (e->user.data)
			xfree(e->user.data);

		e->user.len  = mnl_attr_get_payload_len(tb[NFTA_SET_ELEM_USERDATA]);
		e->user.data = malloc(e->user.len);
		if (e->user.data == NULL)
			goto err;
		memcpy(e->user.data, udata, e->user.len);
		e->flags |= (1 << NFTNL_RULE_USERDATA);
	}

	if (ret < 0) {
err:
		nftnl_set_elem_free(e);
		return -1;
	}

	/* Add this new element to this set */
	list_add_tail(&e->head, &s->element_list);

	return ret;
}

static int
nftnl_set_elem_list_parse_attr_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, NFTA_SET_ELEM_LIST_MAX) < 0)
		return MNL_CB_OK;

	switch(type) {
	case NFTA_SET_ELEM_LIST_TABLE:
	case NFTA_SET_ELEM_LIST_SET:
		if (mnl_attr_validate(attr, MNL_TYPE_STRING) < 0)
			abi_breakage();
		break;
	case NFTA_SET_ELEM_LIST_ELEMENTS:
		if (mnl_attr_validate(attr, MNL_TYPE_NESTED) < 0)
			abi_breakage();
		break;
	}

	tb[type] = attr;
	return MNL_CB_OK;
}

static int nftnl_set_elems_parse(struct nftnl_set *s, const struct nlattr *nest)
{
	struct nlattr *attr;
	int ret = 0;

	mnl_attr_for_each_nested(attr, nest) {
		if (mnl_attr_get_type(attr) != NFTA_LIST_ELEM)
			return -1;

		ret = nftnl_set_elems_parse2(s, attr);
	}
	return ret;
}

int nftnl_set_elems_nlmsg_parse(const struct nlmsghdr *nlh, struct nftnl_set *s)
{
	struct nlattr *tb[NFTA_SET_ELEM_LIST_MAX+1] = {};
	struct nfgenmsg *nfg = mnl_nlmsg_get_payload(nlh);
	int ret = 0;

	if (mnl_attr_parse(nlh, sizeof(*nfg),
			   nftnl_set_elem_list_parse_attr_cb, tb) < 0)
		return -1;

	if (tb[NFTA_SET_ELEM_LIST_TABLE]) {
		xfree(s->table);
		s->table =
			strdup(mnl_attr_get_str(tb[NFTA_SET_ELEM_LIST_TABLE]));
		if (!s->table)
			return -1;
		s->flags |= (1 << NFTNL_SET_TABLE);
	}
	if (tb[NFTA_SET_ELEM_LIST_SET]) {
		xfree(s->name);
		s->name =
			strdup(mnl_attr_get_str(tb[NFTA_SET_ELEM_LIST_SET]));
		if (!s->name)
			return -1;
		s->flags |= (1 << NFTNL_SET_NAME);
	}
	if (tb[NFTA_SET_ELEM_LIST_SET_ID]) {
		s->id = ntohl(mnl_attr_get_u32(tb[NFTA_SET_ELEM_LIST_SET_ID]));
		s->flags |= (1 << NFTNL_SET_ID);
	}
        if (tb[NFTA_SET_ELEM_LIST_ELEMENTS])
	 	ret = nftnl_set_elems_parse(s, tb[NFTA_SET_ELEM_LIST_ELEMENTS]);

	s->family = nfg->nfgen_family;
	s->flags |= (1 << NFTNL_SET_FAMILY);

	return ret;
}
EXPORT_SYMBOL_ALIAS(nftnl_set_elems_nlmsg_parse, nft_set_elems_nlmsg_parse);

#ifdef XML_PARSING
int nftnl_mxml_set_elem_parse(mxml_node_t *tree, struct nftnl_set_elem *e,
			    struct nftnl_parse_err *err)
{
	int set_elem_data;
	uint32_t set_elem_flags;

	if (nftnl_mxml_num_parse(tree, "flags", MXML_DESCEND_FIRST, BASE_DEC,
			       &set_elem_flags, NFTNL_TYPE_U32, NFTNL_XML_MAND,
			       err) == 0)
		nftnl_set_elem_set_u32(e, NFTNL_SET_ELEM_FLAGS, set_elem_flags);

	if (nftnl_mxml_data_reg_parse(tree, "key", &e->key,
				    NFTNL_XML_MAND, err) == DATA_VALUE)
		e->flags |= (1 << NFTNL_SET_ELEM_KEY);

	/* <set_elem_data> is not mandatory */
	set_elem_data = nftnl_mxml_data_reg_parse(tree, "data",
						&e->data, NFTNL_XML_OPT, err);
	switch (set_elem_data) {
	case DATA_VALUE:
		e->flags |= (1 << NFTNL_SET_ELEM_DATA);
		break;
	case DATA_VERDICT:
		e->flags |= (1 << NFTNL_SET_ELEM_VERDICT);
		if (e->data.chain != NULL)
			e->flags |= (1 << NFTNL_SET_ELEM_CHAIN);

		break;
	}

	return 0;
}
#endif

static int nftnl_set_elem_xml_parse(struct nftnl_set_elem *e, const void *xml,
				  struct nftnl_parse_err *err,
				  enum nftnl_parse_input input)
{
#ifdef XML_PARSING
	mxml_node_t *tree;
	int ret;

	tree = nftnl_mxml_build_tree(xml, "set_elem", err, input);
	if (tree == NULL)
		return -1;

	ret = nftnl_mxml_set_elem_parse(tree, e, err);
	mxmlDelete(tree);
	return ret;
#else
	errno = EOPNOTSUPP;
	return -1;
#endif
}

static int nftnl_set_elem_json_parse(struct nftnl_set_elem *e, const void *json,
				   struct nftnl_parse_err *err,
				   enum nftnl_parse_input input)
{
#ifdef JSON_PARSING
	json_t *tree;
	json_error_t error;

	tree = nftnl_jansson_create_root(json, &error, err, input);
	if (tree == NULL)
		return -1;

	return nftnl_jansson_set_elem_parse(e, tree, err);
#else
	errno = EOPNOTSUPP;
	return -1;
#endif
}

static int
nftnl_set_elem_do_parse(struct nftnl_set_elem *e, enum nftnl_parse_type type,
		      const void *data, struct nftnl_parse_err *err,
		      enum nftnl_parse_input input)
{
	int ret;

	switch (type) {
	case NFTNL_PARSE_XML:
		ret = nftnl_set_elem_xml_parse(e, data, err, input);
		break;
	case NFTNL_PARSE_JSON:
		ret = nftnl_set_elem_json_parse(e, data, err, input);
		break;
	default:
		errno = EOPNOTSUPP;
		ret = -1;
		break;
	}

	return ret;
}
int nftnl_set_elem_parse(struct nftnl_set_elem *e, enum nftnl_parse_type type,
		       const char *data, struct nftnl_parse_err *err)
{
	return nftnl_set_elem_do_parse(e, type, data, err, NFTNL_PARSE_BUFFER);
}
EXPORT_SYMBOL_ALIAS(nftnl_set_elem_parse, nft_set_elem_parse);

int nftnl_set_elem_parse_file(struct nftnl_set_elem *e, enum nftnl_parse_type type,
			    FILE *fp, struct nftnl_parse_err *err)
{
	return nftnl_set_elem_do_parse(e, type, fp, err, NFTNL_PARSE_FILE);
}
EXPORT_SYMBOL_ALIAS(nftnl_set_elem_parse_file, nft_set_elem_parse_file);

static int nftnl_set_elem_snprintf_json(char *buf, size_t size,
					const struct nftnl_set_elem *e,
					uint32_t flags)
{
	int ret, len = size, offset = 0, type = -1;

	if (e->flags & (1 << NFTNL_SET_ELEM_FLAGS)) {
		ret = snprintf(buf, len, "\"flags\":%u,", e->set_elem_flags);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	ret = snprintf(buf + offset, len, "\"key\":{");
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	ret = nftnl_data_reg_snprintf(buf + offset, len, &e->key,
				    NFTNL_OUTPUT_JSON, flags, DATA_VALUE);
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	ret = snprintf(buf + offset, len, "}");
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	if (e->flags & (1 << NFTNL_SET_ELEM_DATA))
		type = DATA_VALUE;
	else if (e->flags & (1 << NFTNL_SET_ELEM_CHAIN))
		type = DATA_CHAIN;
	else if (e->flags & (1 << NFTNL_SET_ELEM_VERDICT))
		type = DATA_VERDICT;

	if (type != -1) {
		ret = snprintf(buf + offset, len, ",\"data\":{");
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

		ret = nftnl_data_reg_snprintf(buf + offset, len, &e->data,
					    NFTNL_OUTPUT_JSON, flags, type);
			SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

		ret = snprintf(buf + offset, len, "}");
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	return offset;
}

static int nftnl_set_elem_snprintf_default(char *buf, size_t size,
					   const struct nftnl_set_elem *e)
{
	int ret, len = size, offset = 0, i;

	ret = snprintf(buf, len, "element ");
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	for (i = 0; i < div_round_up(e->key.len, sizeof(uint32_t)); i++) {
		ret = snprintf(buf+offset, len, "%.8x ", e->key.val[i]);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	ret = snprintf(buf+offset, len, " : ");
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	for (i = 0; i < div_round_up(e->data.len, sizeof(uint32_t)); i++) {
		ret = snprintf(buf+offset, len, "%.8x ", e->data.val[i]);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	ret = snprintf(buf+offset, len, "%u [end]", e->set_elem_flags);
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	if (e->user.len) {
		ret = snprintf(buf+offset, len, "  userdata = {");
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

		for (i = 0; i < e->user.len; i++) {
			char *c = e->user.data;

			ret = snprintf(buf+offset, len, "%c",
				       isalnum(c[i]) ? c[i] : 0);
			SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
		}

		ret = snprintf(buf+offset, len, " }\n");
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	return offset;
}

static int nftnl_set_elem_snprintf_xml(char *buf, size_t size,
				       const struct nftnl_set_elem *e,
				       uint32_t flags)
{
	int ret, len = size, offset = 0, type = DATA_NONE;

	ret = snprintf(buf, size, "<set_elem>");
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	if (e->flags & (1 << NFTNL_SET_ELEM_FLAGS)) {
		ret = snprintf(buf + offset, size, "<flags>%u</flags>",
			       e->set_elem_flags);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	if (e->flags & (1 << NFTNL_SET_ELEM_KEY)) {
		ret = snprintf(buf + offset, len, "<key>");
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

		ret = nftnl_data_reg_snprintf(buf + offset, len, &e->key,
					    NFTNL_OUTPUT_XML, flags, DATA_VALUE);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

		ret = snprintf(buf + offset, len, "</key>");
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	if (e->flags & (1 << NFTNL_SET_ELEM_DATA))
		type = DATA_VALUE;
	else if (e->flags & (1 << NFTNL_SET_ELEM_CHAIN))
		type = DATA_CHAIN;
	else if (e->flags & (1 << NFTNL_SET_ELEM_VERDICT))
		type = DATA_VERDICT;

	if (type != DATA_NONE) {
		ret = snprintf(buf + offset, len, "<data>");
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

		ret = nftnl_data_reg_snprintf(buf + offset, len, &e->data,
					    NFTNL_OUTPUT_XML, flags, type);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

		ret = snprintf(buf + offset, len, "</data>");
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	ret = snprintf(buf + offset, len, "</set_elem>");
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	return offset;
}

static int nftnl_set_elem_cmd_snprintf(char *buf, size_t size,
				       const struct nftnl_set_elem *e,
				       uint32_t cmd, uint32_t type,
				       uint32_t flags)
{
	int ret, len = size, offset = 0;

	ret = nftnl_cmd_header_snprintf(buf + offset, len, cmd, type, flags);
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	switch(type) {
	case NFTNL_OUTPUT_DEFAULT:
		ret = nftnl_set_elem_snprintf_default(buf+offset, len, e);
		break;
	case NFTNL_OUTPUT_XML:
		ret = nftnl_set_elem_snprintf_xml(buf+offset, len, e, flags);
		break;
	case NFTNL_OUTPUT_JSON:
		ret = nftnl_set_elem_snprintf_json(buf+offset, len, e, flags);
		break;
	default:
		return -1;
	}

	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	ret = nftnl_cmd_footer_snprintf(buf + offset, len, cmd, type, flags);
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	return offset;
}

int nftnl_set_elem_snprintf(char *buf, size_t size,
			    const struct nftnl_set_elem *e,
			    uint32_t type, uint32_t flags)
{
	return nftnl_set_elem_cmd_snprintf(buf, size, e, nftnl_flag2cmd(flags),
					 type, flags);
}
EXPORT_SYMBOL_ALIAS(nftnl_set_elem_snprintf, nft_set_elem_snprintf);

static int nftnl_set_elem_do_snprintf(char *buf, size_t size, const void *e,
				      uint32_t cmd, uint32_t type,
				      uint32_t flags)
{
	return nftnl_set_elem_snprintf(buf, size, e, type, flags);
}

int nftnl_set_elem_fprintf(FILE *fp, struct nftnl_set_elem *se, uint32_t type,
			 uint32_t flags)
{
	return nftnl_fprintf(fp, se, NFTNL_CMD_UNSPEC, type, flags,
			   nftnl_set_elem_do_snprintf);
}
EXPORT_SYMBOL_ALIAS(nftnl_set_elem_fprintf, nft_set_elem_fprintf);

int nftnl_set_elem_foreach(struct nftnl_set *s,
			 int (*cb)(struct nftnl_set_elem *e, void *data),
			 void *data)
{
	struct nftnl_set_elem *elem;
	int ret;

	list_for_each_entry(elem, &s->element_list, head) {
		ret = cb(elem, data);
		if (ret < 0)
			return ret;
	}
	return 0;
}
EXPORT_SYMBOL_ALIAS(nftnl_set_elem_foreach, nft_set_elem_foreach);

struct nftnl_set_elems_iter {
	struct nftnl_set			*set;
	struct list_head		*list;
	struct nftnl_set_elem		*cur;
};

struct nftnl_set_elems_iter *nftnl_set_elems_iter_create(struct nftnl_set *s)
{
	struct nftnl_set_elems_iter *iter;

	iter = calloc(1, sizeof(struct nftnl_set_elems_iter));
	if (iter == NULL)
		return NULL;

	iter->set = s;
	iter->list = &s->element_list;
	if (list_empty(&s->element_list))
		iter->cur = NULL;
	else
		iter->cur = list_entry(s->element_list.next,
				       struct nftnl_set_elem, head);

	return iter;
}
EXPORT_SYMBOL_ALIAS(nftnl_set_elems_iter_create, nft_set_elems_iter_create);

struct nftnl_set_elem *nftnl_set_elems_iter_cur(struct nftnl_set_elems_iter *iter)
{
	return iter->cur;
}
EXPORT_SYMBOL_ALIAS(nftnl_set_elems_iter_cur, nft_set_elems_iter_cur);

struct nftnl_set_elem *nftnl_set_elems_iter_next(struct nftnl_set_elems_iter *iter)
{
	struct nftnl_set_elem *s = iter->cur;

	if (s == NULL)
		return NULL;

	iter->cur = list_entry(iter->cur->head.next, struct nftnl_set_elem, head);
	if (&iter->cur->head == iter->list->next)
		return NULL;

	return s;
}
EXPORT_SYMBOL_ALIAS(nftnl_set_elems_iter_next, nft_set_elems_iter_next);

void nftnl_set_elems_iter_destroy(struct nftnl_set_elems_iter *iter)
{
	xfree(iter);
}
EXPORT_SYMBOL_ALIAS(nftnl_set_elems_iter_destroy, nft_set_elems_iter_destroy);

static bool nftnl_attr_nest_overflow(struct nlmsghdr *nlh,
				   const struct nlattr *from,
				   const struct nlattr *to)
{
	int len = (void *)to + to->nla_len - (void *)from;

	/* The attribute length field is 16 bits long, thus the maximum payload
	 * that an attribute can convey is UINT16_MAX. In case of overflow,
	 * discard the last that did not fit into the attribute.
	 */
	if (len > UINT16_MAX) {
		nlh->nlmsg_len -= to->nla_len;
		return true;
	}
	return false;
}

int nftnl_set_elems_nlmsg_build_payload_iter(struct nlmsghdr *nlh,
					   struct nftnl_set_elems_iter *iter)
{
	struct nftnl_set_elem *elem;
	struct nlattr *nest1, *nest2;
	int i = 0, ret = 0;

	nftnl_set_elem_nlmsg_build_def(nlh, iter->set);

	nest1 = mnl_attr_nest_start(nlh, NFTA_SET_ELEM_LIST_ELEMENTS);
	elem = nftnl_set_elems_iter_next(iter);
	while (elem != NULL) {
		nest2 = nftnl_set_elem_build(nlh, elem, ++i);
		if (nftnl_attr_nest_overflow(nlh, nest1, nest2)) {
			/* Go back to previous not to miss this element */
			iter->cur = list_entry(iter->cur->head.prev,
					       struct nftnl_set_elem, head);
			ret = 1;
			break;
		}
		elem = nftnl_set_elems_iter_next(iter);
	}
	mnl_attr_nest_end(nlh, nest1);

	return ret;
}
EXPORT_SYMBOL_ALIAS(nftnl_set_elems_nlmsg_build_payload_iter, nft_set_elems_nlmsg_build_payload_iter);
