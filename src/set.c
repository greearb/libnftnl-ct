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
#include <inttypes.h>
#include <netinet/in.h>
#include <limits.h>
#include <errno.h>

#include <libmnl/libmnl.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nf_tables.h>

#include <libnftnl/set.h>
#include <libnftnl/expr.h>

struct nft_set *nft_set_alloc(void)
{
	struct nft_set *s;

	s = calloc(1, sizeof(struct nft_set));
	if (s == NULL)
		return NULL;

	INIT_LIST_HEAD(&s->element_list);
	return s;
}
EXPORT_SYMBOL(nft_set_alloc);

void nft_set_free(struct nft_set *s)
{
	struct nft_set_elem *elem, *tmp;

	if (s->table != NULL)
		xfree(s->table);
	if (s->name != NULL)
		xfree(s->name);

	list_for_each_entry_safe(elem, tmp, &s->element_list, head) {
		list_del(&elem->head);
		nft_set_elem_free(elem);
	}
	xfree(s);
}
EXPORT_SYMBOL(nft_set_free);

bool nft_set_attr_is_set(const struct nft_set *s, uint16_t attr)
{
	return s->flags & (1 << attr);
}
EXPORT_SYMBOL(nft_set_attr_is_set);

void nft_set_attr_unset(struct nft_set *s, uint16_t attr)
{
	switch (attr) {
	case NFT_SET_ATTR_TABLE:
		if (s->flags & (1 << NFT_SET_ATTR_TABLE))
			if (s->table) {
				xfree(s->table);
				s->table = NULL;
			}
		break;
	case NFT_SET_ATTR_NAME:
		if (s->flags & (1 << NFT_SET_ATTR_NAME))
			if (s->name) {
				xfree(s->name);
				s->name = NULL;
			}
		break;
	case NFT_SET_ATTR_FLAGS:
	case NFT_SET_ATTR_KEY_TYPE:
	case NFT_SET_ATTR_KEY_LEN:
	case NFT_SET_ATTR_DATA_TYPE:
	case NFT_SET_ATTR_DATA_LEN:
	case NFT_SET_ATTR_FAMILY:
	case NFT_SET_ATTR_ID:
	case NFT_SET_ATTR_POLICY:
	case NFT_SET_ATTR_DESC_SIZE:
	case NFT_SET_ATTR_TIMEOUT:
	case NFT_SET_ATTR_GC_INTERVAL:
		break;
	default:
		return;
	}

	s->flags &= ~(1 << attr);
}
EXPORT_SYMBOL(nft_set_attr_unset);

static uint32_t nft_set_attr_validate[NFT_SET_ATTR_MAX + 1] = {
	[NFT_SET_ATTR_FLAGS]		= sizeof(uint32_t),
	[NFT_SET_ATTR_KEY_TYPE]		= sizeof(uint32_t),
	[NFT_SET_ATTR_KEY_LEN]		= sizeof(uint32_t),
	[NFT_SET_ATTR_DATA_TYPE]	= sizeof(uint32_t),
	[NFT_SET_ATTR_DATA_LEN]		= sizeof(uint32_t),
	[NFT_SET_ATTR_FAMILY]		= sizeof(uint32_t),
	[NFT_SET_ATTR_POLICY]		= sizeof(uint32_t),
	[NFT_SET_ATTR_DESC_SIZE]	= sizeof(uint32_t),
	[NFT_SET_ATTR_TIMEOUT]		= sizeof(uint64_t),
	[NFT_SET_ATTR_GC_INTERVAL]	= sizeof(uint32_t),
};

void nft_set_attr_set_data(struct nft_set *s, uint16_t attr, const void *data,
			   uint32_t data_len)
{
	if (attr > NFT_SET_ATTR_MAX)
		return;

	nft_assert_validate(data, nft_set_attr_validate, attr, data_len);

	switch(attr) {
	case NFT_SET_ATTR_TABLE:
		if (s->table)
			xfree(s->table);

		s->table = strdup(data);
		break;
	case NFT_SET_ATTR_NAME:
		if (s->name)
			xfree(s->name);

		s->name = strdup(data);
		break;
	case NFT_SET_ATTR_FLAGS:
		s->set_flags = *((uint32_t *)data);
		break;
	case NFT_SET_ATTR_KEY_TYPE:
		s->key_type = *((uint32_t *)data);
		break;
	case NFT_SET_ATTR_KEY_LEN:
		s->key_len = *((uint32_t *)data);
		break;
	case NFT_SET_ATTR_DATA_TYPE:
		s->data_type = *((uint32_t *)data);
		break;
	case NFT_SET_ATTR_DATA_LEN:
		s->data_len = *((uint32_t *)data);
		break;
	case NFT_SET_ATTR_FAMILY:
		s->family = *((uint32_t *)data);
		break;
	case NFT_SET_ATTR_ID:
		s->id = *((uint32_t *)data);
		break;
	case NFT_SET_ATTR_POLICY:
		s->policy = *((uint32_t *)data);
		break;
	case NFT_SET_ATTR_DESC_SIZE:
		s->desc.size = *((uint32_t *)data);
		break;
	case NFT_SET_ATTR_TIMEOUT:
		s->timeout = *((uint64_t *)data);
		break;
	case NFT_SET_ATTR_GC_INTERVAL:
		s->gc_interval = *((uint32_t *)data);
		break;
	}
	s->flags |= (1 << attr);
}
EXPORT_SYMBOL(nft_set_attr_set_data);

void nft_set_attr_set(struct nft_set *s, uint16_t attr, const void *data)
{
	nft_set_attr_set_data(s, attr, data, nft_set_attr_validate[attr]);
}
EXPORT_SYMBOL(nft_set_attr_set);

void nft_set_attr_set_u32(struct nft_set *s, uint16_t attr, uint32_t val)
{
	nft_set_attr_set(s, attr, &val);
}
EXPORT_SYMBOL(nft_set_attr_set_u32);

void nft_set_attr_set_u64(struct nft_set *s, uint16_t attr, uint64_t val)
{
	nft_set_attr_set(s, attr, &val);
}
EXPORT_SYMBOL(nft_set_attr_set_u64);

void nft_set_attr_set_str(struct nft_set *s, uint16_t attr, const char *str)
{
	nft_set_attr_set(s, attr, str);
}
EXPORT_SYMBOL(nft_set_attr_set_str);

const void *nft_set_attr_get_data(struct nft_set *s, uint16_t attr,
				  uint32_t *data_len)
{
	if (!(s->flags & (1 << attr)))
		return NULL;

	switch(attr) {
	case NFT_SET_ATTR_TABLE:
		return s->table;
	case NFT_SET_ATTR_NAME:
		return s->name;
	case NFT_SET_ATTR_FLAGS:
		*data_len = sizeof(uint32_t);
		return &s->set_flags;
	case NFT_SET_ATTR_KEY_TYPE:
		*data_len = sizeof(uint32_t);
		return &s->key_type;
	case NFT_SET_ATTR_KEY_LEN:
		*data_len = sizeof(uint32_t);
		return &s->key_len;
	case NFT_SET_ATTR_DATA_TYPE:
		*data_len = sizeof(uint32_t);
		return &s->data_type;
	case NFT_SET_ATTR_DATA_LEN:
		*data_len = sizeof(uint32_t);
		return &s->data_len;
	case NFT_SET_ATTR_FAMILY:
		*data_len = sizeof(uint32_t);
		return &s->family;
	case NFT_SET_ATTR_ID:
		*data_len = sizeof(uint32_t);
		return &s->id;
	case NFT_SET_ATTR_POLICY:
		*data_len = sizeof(uint32_t);
		return &s->policy;
	case NFT_SET_ATTR_DESC_SIZE:
		*data_len = sizeof(uint32_t);
		return &s->desc.size;
	case NFT_SET_ATTR_TIMEOUT:
		*data_len = sizeof(uint64_t);
		return &s->timeout;
	case NFT_SET_ATTR_GC_INTERVAL:
		*data_len = sizeof(uint32_t);
		return &s->gc_interval;
	}
	return NULL;
}
EXPORT_SYMBOL(nft_set_attr_get_data);

const void *nft_set_attr_get(struct nft_set *s, uint16_t attr)
{
	uint32_t data_len;
	return nft_set_attr_get_data(s, attr, &data_len);
}
EXPORT_SYMBOL(nft_set_attr_get);

const char *nft_set_attr_get_str(struct nft_set *s, uint16_t attr)
{
	return nft_set_attr_get(s, attr);
}
EXPORT_SYMBOL(nft_set_attr_get_str);

uint32_t nft_set_attr_get_u32(struct nft_set *s, uint16_t attr)
{
	uint32_t data_len;
	const uint32_t *val = nft_set_attr_get_data(s, attr, &data_len);

	nft_assert(val, attr, data_len == sizeof(uint32_t));

	return val ? *val : 0;
}
EXPORT_SYMBOL(nft_set_attr_get_u32);

uint64_t nft_set_attr_get_u64(struct nft_set *s, uint16_t attr)
{
	uint32_t data_len;
	const uint64_t *val = nft_set_attr_get_data(s, attr, &data_len);

	nft_assert(val, attr, data_len == sizeof(uint64_t));

	return val ? *val : 0;
}
EXPORT_SYMBOL(nft_set_attr_get_u64);

struct nft_set *nft_set_clone(const struct nft_set *set)
{
	struct nft_set *newset;
	struct nft_set_elem *elem, *newelem;

	newset = nft_set_alloc();
	if (newset == NULL)
		return NULL;

	memcpy(newset, set, sizeof(*set));

	if (set->flags & (1 << NFT_SET_ATTR_TABLE))
		newset->table = strdup(set->table);
	if (set->flags & (1 << NFT_SET_ATTR_NAME))
		newset->name = strdup(set->name);

	INIT_LIST_HEAD(&newset->element_list);
	list_for_each_entry(elem, &set->element_list, head) {
		newelem = nft_set_elem_clone(elem);
		if (newelem == NULL)
			goto err;

		list_add_tail(&newelem->head, &newset->element_list);
	}

	return newset;
err:
	nft_set_free(newset);
	return NULL;
}

static void
nft_set_nlmsg_build_desc_payload(struct nlmsghdr *nlh, struct nft_set *s)
{
	struct nlattr *nest;

	nest = mnl_attr_nest_start(nlh, NFTA_SET_DESC);
	mnl_attr_put_u32(nlh, NFTA_SET_DESC_SIZE, htonl(s->desc.size));
	mnl_attr_nest_end(nlh, nest);
}

void nft_set_nlmsg_build_payload(struct nlmsghdr *nlh, struct nft_set *s)
{
	if (s->flags & (1 << NFT_SET_ATTR_TABLE))
		mnl_attr_put_strz(nlh, NFTA_SET_TABLE, s->table);
	if (s->flags & (1 << NFT_SET_ATTR_NAME))
		mnl_attr_put_strz(nlh, NFTA_SET_NAME, s->name);
	if (s->flags & (1 << NFT_SET_ATTR_FLAGS))
		mnl_attr_put_u32(nlh, NFTA_SET_FLAGS, htonl(s->set_flags));
	if (s->flags & (1 << NFT_SET_ATTR_KEY_TYPE))
		mnl_attr_put_u32(nlh, NFTA_SET_KEY_TYPE, htonl(s->key_type));
	if (s->flags & (1 << NFT_SET_ATTR_KEY_LEN))
		mnl_attr_put_u32(nlh, NFTA_SET_KEY_LEN, htonl(s->key_len));
	/* These are only used to map matching -> action (1:1) */
	if (s->flags & (1 << NFT_SET_ATTR_DATA_TYPE))
		mnl_attr_put_u32(nlh, NFTA_SET_DATA_TYPE, htonl(s->data_type));
	if (s->flags & (1 << NFT_SET_ATTR_DATA_LEN))
		mnl_attr_put_u32(nlh, NFTA_SET_DATA_LEN, htonl(s->data_len));
	if (s->flags & (1 << NFT_SET_ATTR_ID))
		mnl_attr_put_u32(nlh, NFTA_SET_ID, htonl(s->id));
	if (s->flags & (1 << NFT_SET_ATTR_POLICY))
		mnl_attr_put_u32(nlh, NFTA_SET_POLICY, htonl(s->policy));
	if (s->flags & (1 << NFT_SET_ATTR_DESC_SIZE))
		nft_set_nlmsg_build_desc_payload(nlh, s);
	if (s->flags & (1 << NFT_SET_ATTR_TIMEOUT))
		mnl_attr_put_u64(nlh, NFTA_SET_TIMEOUT, htobe64(s->timeout));
	if (s->flags & (1 << NFT_SET_ATTR_GC_INTERVAL))
		mnl_attr_put_u32(nlh, NFTA_SET_GC_INTERVAL, htonl(s->gc_interval));
}
EXPORT_SYMBOL(nft_set_nlmsg_build_payload);

static int nft_set_parse_attr_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, NFTA_SET_MAX) < 0)
		return MNL_CB_OK;

	switch(type) {
	case NFTA_SET_TABLE:
	case NFTA_SET_NAME:
		if (mnl_attr_validate(attr, MNL_TYPE_STRING) < 0)
			abi_breakage();
		break;
	case NFTA_SET_FLAGS:
	case NFTA_SET_KEY_TYPE:
	case NFTA_SET_KEY_LEN:
	case NFTA_SET_DATA_TYPE:
	case NFTA_SET_DATA_LEN:
	case NFTA_SET_ID:
	case NFTA_SET_POLICY:
	case NFTA_SET_GC_INTERVAL:
		if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0)
			abi_breakage();
		break;
	case NFTA_SET_TIMEOUT:
		if (mnl_attr_validate(attr, MNL_TYPE_U64) < 0)
			abi_breakage();
		break;
	case NFTA_SET_DESC:
		if (mnl_attr_validate(attr, MNL_TYPE_NESTED) < 0)
			abi_breakage();
		break;
	}

	tb[type] = attr;
	return MNL_CB_OK;
}

static int nft_set_desc_parse_attr_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, NFTA_SET_MAX) < 0)
		return MNL_CB_OK;

	switch (type) {
	case NFTA_SET_DESC_SIZE:
		if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0)
			abi_breakage();
		break;
	}

	tb[type] = attr;
	return MNL_CB_OK;
}

static int nft_set_desc_parse(struct nft_set *s,
			      const struct nlattr *attr)
{
	struct nlattr *tb[NFTA_SET_DESC_MAX + 1] = {};

	if (mnl_attr_parse_nested(attr, nft_set_desc_parse_attr_cb, tb) < 0)
		return -1;

	if (tb[NFTA_SET_DESC_SIZE]) {
		s->desc.size = ntohl(mnl_attr_get_u32(tb[NFTA_SET_DESC_SIZE]));
		s->flags |= (1 << NFT_SET_ATTR_DESC_SIZE);
	}

	return 0;
}

int nft_set_nlmsg_parse(const struct nlmsghdr *nlh, struct nft_set *s)
{
	struct nlattr *tb[NFTA_SET_MAX+1] = {};
	struct nfgenmsg *nfg = mnl_nlmsg_get_payload(nlh);
	int ret = 0;

	if (mnl_attr_parse(nlh, sizeof(*nfg), nft_set_parse_attr_cb, tb) < 0)
		return -1;

	if (tb[NFTA_SET_TABLE]) {
		xfree(s->table);
		s->table = strdup(mnl_attr_get_str(tb[NFTA_SET_TABLE]));
		s->flags |= (1 << NFT_SET_ATTR_TABLE);
	}
	if (tb[NFTA_SET_NAME]) {
		xfree(s->name);
		s->name = strdup(mnl_attr_get_str(tb[NFTA_SET_NAME]));
		s->flags |= (1 << NFT_SET_ATTR_NAME);
	}
	if (tb[NFTA_SET_FLAGS]) {
		s->set_flags = ntohl(mnl_attr_get_u32(tb[NFTA_SET_FLAGS]));
		s->flags |= (1 << NFT_SET_ATTR_FLAGS);
	}
	if (tb[NFTA_SET_KEY_TYPE]) {
		s->key_type = ntohl(mnl_attr_get_u32(tb[NFTA_SET_KEY_TYPE]));
		s->flags |= (1 << NFT_SET_ATTR_KEY_TYPE);
	}
	if (tb[NFTA_SET_KEY_LEN]) {
		s->key_len = ntohl(mnl_attr_get_u32(tb[NFTA_SET_KEY_LEN]));
		s->flags |= (1 << NFT_SET_ATTR_KEY_LEN);
	}
	if (tb[NFTA_SET_DATA_TYPE]) {
		s->data_type = ntohl(mnl_attr_get_u32(tb[NFTA_SET_DATA_TYPE]));
		s->flags |= (1 << NFT_SET_ATTR_DATA_TYPE);
	}
	if (tb[NFTA_SET_DATA_LEN]) {
		s->data_len = ntohl(mnl_attr_get_u32(tb[NFTA_SET_DATA_LEN]));
		s->flags |= (1 << NFT_SET_ATTR_DATA_LEN);
	}
	if (tb[NFTA_SET_ID]) {
		s->id = ntohl(mnl_attr_get_u32(tb[NFTA_SET_ID]));
		s->flags |= (1 << NFT_SET_ATTR_ID);
	}
	if (tb[NFTA_SET_POLICY]) {
		s->policy = ntohl(mnl_attr_get_u32(tb[NFTA_SET_POLICY]));
		s->flags |= (1 << NFT_SET_ATTR_POLICY);
	}
	if (tb[NFTA_SET_TIMEOUT]) {
		s->timeout = be64toh(mnl_attr_get_u64(tb[NFTA_SET_TIMEOUT]));
		s->flags |= (1 << NFT_SET_ATTR_TIMEOUT);
	}
	if (tb[NFTA_SET_GC_INTERVAL]) {
		s->gc_interval = ntohl(mnl_attr_get_u32(tb[NFTA_SET_GC_INTERVAL]));
		s->flags |= (1 << NFT_SET_ATTR_GC_INTERVAL);
	}
	if (tb[NFTA_SET_DESC])
		ret = nft_set_desc_parse(s, tb[NFTA_SET_DESC]);

	s->family = nfg->nfgen_family;
	s->flags |= (1 << NFT_SET_ATTR_FAMILY);

	return ret;
}
EXPORT_SYMBOL(nft_set_nlmsg_parse);

#ifdef JSON_PARSING
static int nft_jansson_parse_set_info(struct nft_set *s, json_t *tree,
				      struct nft_parse_err *err)
{
	json_t *root = tree, *array, *json_elem;
	uint32_t flags, key_type, key_len, data_type, data_len, policy, size;
	int family, i;
	const char *name, *table;
	struct nft_set_elem *elem;

	name = nft_jansson_parse_str(root, "name", err);
	if (name == NULL)
		return -1;

	nft_set_attr_set_str(s, NFT_SET_ATTR_NAME, name);

	table = nft_jansson_parse_str(root, "table", err);
	if (table == NULL)
		return -1;

	nft_set_attr_set_str(s, NFT_SET_ATTR_TABLE, table);

	if (nft_jansson_parse_family(root, &family, err) == 0)
		nft_set_attr_set_u32(s, NFT_SET_ATTR_FAMILY, family);

	if (nft_jansson_parse_val(root, "flags", NFT_TYPE_U32, &flags, err) == 0)
		nft_set_attr_set_u32(s, NFT_SET_ATTR_FLAGS, flags);

	if (nft_jansson_parse_val(root, "key_type", NFT_TYPE_U32, &key_type,
				  err) == 0)
		nft_set_attr_set_u32(s, NFT_SET_ATTR_KEY_TYPE, key_type);

	if (nft_jansson_parse_val(root, "key_len", NFT_TYPE_U32, &key_len,
				  err) == 0)
		nft_set_attr_set_u32(s, NFT_SET_ATTR_KEY_LEN, key_len);

	if (nft_jansson_node_exist(root, "data_type")) {
		if (nft_jansson_parse_val(root, "data_type", NFT_TYPE_U32,
					  &data_type, err) < 0)
			return -1;

		nft_set_attr_set_u32(s, NFT_SET_ATTR_DATA_TYPE, data_type);
	}

	if (nft_jansson_node_exist(root, "data_len")) {
		if (nft_jansson_parse_val(root, "data_len", NFT_TYPE_U32,
					  &data_len, err) < 0)
			return -1;

		nft_set_attr_set_u32(s, NFT_SET_ATTR_DATA_LEN, data_len);
	}

	if (nft_jansson_node_exist(root, "policy")) {
		if (nft_jansson_parse_val(root, "policy", NFT_TYPE_U32,
					  &policy, err) < 0)
			return -1;

		nft_set_attr_set_u32(s, NFT_SET_ATTR_POLICY, policy);
	}

	if (nft_jansson_node_exist(root, "desc_size")) {
		if (nft_jansson_parse_val(root, "desc_size", NFT_TYPE_U32,
					  &size, err) < 0)
			return -1;

		nft_set_attr_set_u32(s, NFT_SET_ATTR_DESC_SIZE, size);
	}

	if (nft_jansson_node_exist(root, "set_elem")) {
		array = json_object_get(root, "set_elem");
		for (i = 0; i < json_array_size(array); i++) {
			elem = nft_set_elem_alloc();
			if (elem == NULL)
				return -1;

			json_elem = json_array_get(array, i);
			if (json_elem == NULL)
				return -1;

			if (nft_jansson_set_elem_parse(elem,
						       json_elem, err) < 0)
				return -1;

			list_add_tail(&elem->head, &s->element_list);
		}

	}

	return 0;
}

int nft_jansson_parse_set(struct nft_set *s, json_t *tree,
			  struct nft_parse_err *err)
{
	json_t *root;

	root = nft_jansson_get_node(tree, "set", err);
	if (root == NULL)
		return -1;

	return nft_jansson_parse_set_info(s, root, err);
}

int nft_jansson_parse_elem(struct nft_set *s, json_t *tree,
			   struct nft_parse_err *err)
{
	json_t *root;

	root = nft_jansson_get_node(tree, "element", err);
	if (root == NULL)
		return -1;

	return nft_jansson_parse_set_info(s, root, err);
}
#endif

static int nft_set_json_parse(struct nft_set *s, const void *json,
			      struct nft_parse_err *err,
			      enum nft_parse_input input)
{
#ifdef JSON_PARSING
	json_t *tree;
	json_error_t error;
	int ret;

	tree = nft_jansson_create_root(json, &error, err, input);
	if (tree == NULL)
		return -1;

	ret = nft_jansson_parse_set(s, tree, err);
	nft_jansson_free_root(tree);

	return ret;
#else
	errno = EOPNOTSUPP;
	return -1;
#endif
}

#ifdef XML_PARSING
int nft_mxml_set_parse(mxml_node_t *tree, struct nft_set *s,
		       struct nft_parse_err *err)
{
	mxml_node_t *node = NULL;
	struct nft_set_elem *elem;
	const char *name, *table;
	int family;
	uint32_t set_flags, key_type, key_len;
	uint32_t data_type, data_len, policy, size;

	name = nft_mxml_str_parse(tree, "name", MXML_DESCEND_FIRST,
				  NFT_XML_MAND, err);
	if (name == NULL)
		return -1;
	nft_set_attr_set_str(s, NFT_SET_ATTR_NAME, name);

	table = nft_mxml_str_parse(tree, "table", MXML_DESCEND_FIRST,
				   NFT_XML_MAND, err);
	if (table == NULL)
		return -1;
	nft_set_attr_set_str(s, NFT_SET_ATTR_TABLE, table);

	family = nft_mxml_family_parse(tree, "family", MXML_DESCEND_FIRST,
				       NFT_XML_MAND, err);
	if (family >= 0)
		nft_set_attr_set_u32(s, NFT_SET_ATTR_FAMILY, family);

	if (nft_mxml_num_parse(tree, "flags", MXML_DESCEND_FIRST, BASE_DEC,
			       &set_flags, NFT_TYPE_U32, NFT_XML_MAND,
			       err) == 0)
		nft_set_attr_set_u32(s, NFT_SET_ATTR_FLAGS, set_flags);

	if (nft_mxml_num_parse(tree, "key_type", MXML_DESCEND_FIRST, BASE_DEC,
			       &key_type, NFT_TYPE_U32, NFT_XML_MAND, err) == 0)
		nft_set_attr_set_u32(s, NFT_SET_ATTR_KEY_TYPE, key_type);

	if (nft_mxml_num_parse(tree, "key_len", MXML_DESCEND_FIRST, BASE_DEC,
			       &key_len, NFT_TYPE_U32, NFT_XML_MAND, err) < 0)
		return -1;
	nft_set_attr_set_u32(s, NFT_SET_ATTR_KEY_LEN, key_len);

	if (nft_mxml_num_parse(tree, "data_type", MXML_DESCEND_FIRST, BASE_DEC,
			       &data_type, NFT_TYPE_U32,
			       NFT_XML_OPT, err) == 0) {
		nft_set_attr_set_u32(s, NFT_SET_ATTR_DATA_TYPE, data_type);

		if (nft_mxml_num_parse(tree, "data_len", MXML_DESCEND_FIRST,
				       BASE_DEC, &data_len, NFT_TYPE_U32,
				       NFT_XML_MAND, err) == 0)
			nft_set_attr_set_u32(s, NFT_SET_ATTR_DATA_LEN, data_len);

	}

	if (nft_mxml_num_parse(tree, "policy", MXML_DESCEND_FIRST,
			       BASE_DEC, &policy, NFT_TYPE_U32,
			       NFT_XML_OPT, err) == 0)
		nft_set_attr_set_u32(s, NFT_SET_ATTR_POLICY, policy);

	if (nft_mxml_num_parse(tree, "desc_size", MXML_DESCEND_FIRST,
			       BASE_DEC, &size, NFT_TYPE_U32,
			       NFT_XML_OPT, err) == 0)
		nft_set_attr_set_u32(s, NFT_SET_ATTR_DESC_SIZE, policy);

	for (node = mxmlFindElement(tree, tree, "set_elem", NULL,
				    NULL, MXML_DESCEND);
		node != NULL;
		node = mxmlFindElement(node, tree, "set_elem", NULL,
				       NULL, MXML_DESCEND)) {

		elem = nft_set_elem_alloc();
		if (elem == NULL)
			return -1;

		if (nft_mxml_set_elem_parse(node, elem, err) < 0)
			return -1;

		list_add_tail(&elem->head, &s->element_list);
	}

	return 0;
}
#endif

static int nft_set_xml_parse(struct nft_set *s, const void *xml,
			     struct nft_parse_err *err,
			     enum nft_parse_input input)
{
#ifdef XML_PARSING
	int ret;
	mxml_node_t *tree = nft_mxml_build_tree(xml, "set", err, input);
	if (tree == NULL)
		return -1;

	ret = nft_mxml_set_parse(tree, s, err);
	mxmlDelete(tree);
	return ret;
#else
	errno = EOPNOTSUPP;
	return -1;
#endif
}

static int nft_set_do_parse(struct nft_set *s, enum nft_parse_type type,
			    const void *data, struct nft_parse_err *err,
			    enum nft_parse_input input)
{
	int ret;
	struct nft_parse_err perr;

	switch (type) {
	case NFT_PARSE_XML:
		ret = nft_set_xml_parse(s, data, &perr, input);
		break;
	case NFT_PARSE_JSON:
		ret = nft_set_json_parse(s, data, &perr, input);
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
int nft_set_parse(struct nft_set *s, enum nft_parse_type type,
		  const char *data, struct nft_parse_err *err)
{
	return nft_set_do_parse(s, type, data, err, NFT_PARSE_BUFFER);
}
EXPORT_SYMBOL(nft_set_parse);

int nft_set_parse_file(struct nft_set *s, enum nft_parse_type type,
		       FILE *fp, struct nft_parse_err *err)
{
	return nft_set_do_parse(s, type, fp, err, NFT_PARSE_FILE);
}
EXPORT_SYMBOL(nft_set_parse_file);

static int nft_set_snprintf_json(char *buf, size_t size, struct nft_set *s,
				  uint32_t type, uint32_t flags)
{
	int len = size, offset = 0, ret;
	struct nft_set_elem *elem;

	ret = snprintf(buf, len, "{\"set\":{");
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	if (s->flags & (1 << NFT_SET_ATTR_NAME)) {
		ret = snprintf(buf + offset, len, "\"name\":\"%s\"",
			       s->name);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}
	if (s->flags & (1 << NFT_SET_ATTR_TABLE)) {
		ret = snprintf(buf + offset, len, ",\"table\":\"%s\"",
			       s->table);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}
	if (s->flags & (1 << NFT_SET_ATTR_FLAGS)) {
		ret = snprintf(buf + offset, len, ",\"flags\":%u",
			       s->set_flags);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}
	if (s->flags & (1 << NFT_SET_ATTR_FAMILY)) {
		ret = snprintf(buf + offset, len, ",\"family\":\"%s\"",
			       nft_family2str(s->family));
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}
	if (s->flags & (1 << NFT_SET_ATTR_KEY_TYPE)) {
		ret = snprintf(buf + offset, len, ",\"key_type\":%u",
			       s->key_type);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}
	if (s->flags & (1 << NFT_SET_ATTR_KEY_LEN)) {
		ret = snprintf(buf + offset, len, ",\"key_len\":%u",
			       s->key_len);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}
	if(s->flags & (1 << NFT_SET_ATTR_DATA_TYPE)) {
		ret = snprintf(buf + offset, len,
				  ",\"data_type\":%u", s->data_type);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}
	if(s->flags & (1 << NFT_SET_ATTR_DATA_LEN)) {
		ret = snprintf(buf + offset, len, ",\"data_len\":%u", s->data_len);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	if (s->flags & (1 << NFT_SET_ATTR_POLICY)) {
		ret = snprintf(buf + offset, len, ",\"policy\":%u",
			       s->policy);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	if (s->flags & (1 << NFT_SET_ATTR_DESC_SIZE)) {
		ret = snprintf(buf + offset, len, ",\"desc_size\":%u",
			       s->desc.size);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	/* Empty set? Skip printinf of elements */
	if (list_empty(&s->element_list)){
		ret = snprintf(buf + offset, len, "}}");
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
		return offset;
	}

	ret = snprintf(buf + offset, len, ",\"set_elem\":[");
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	list_for_each_entry(elem, &s->element_list, head) {
		ret = snprintf(buf + offset, len, "{");
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

		ret = nft_set_elem_snprintf(buf + offset, len, elem, type,
					    flags);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

		ret = snprintf(buf + offset, len, "},");
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}
	/* Overwrite trailing ", " from last set element */
	offset --;

	ret = snprintf(buf + offset, len, "]}}");
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	return offset;
}

static int nft_set_snprintf_default(char *buf, size_t size, struct nft_set *s,
				    uint32_t type, uint32_t flags)
{
	int ret;
	int len = size, offset = 0;
	struct nft_set_elem *elem;

	ret = snprintf(buf, len, "%s %s %x",
			s->name, s->table, s->set_flags);
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	if (s->flags & (1 << NFT_SET_ATTR_TIMEOUT)) {
		ret = snprintf(buf + offset, len, " timeout %"PRIu64"ms",
			       s->timeout);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	if (s->flags & (1 << NFT_SET_ATTR_GC_INTERVAL)) {
		ret = snprintf(buf + offset, len, " gc_interval %ums",
			       s->gc_interval);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	if (s->flags & (1 << NFT_SET_ATTR_POLICY)) {
		ret = snprintf(buf + offset, len, " policy %u", s->policy);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	if (s->flags & (1 << NFT_SET_ATTR_DESC_SIZE)) {
		ret = snprintf(buf + offset, len, " size %u", s->desc.size);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	/* Empty set? Skip printinf of elements */
	if (list_empty(&s->element_list))
		return offset;

	ret = snprintf(buf+offset, len, "\n");
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	list_for_each_entry(elem, &s->element_list, head) {
		ret = snprintf(buf+offset, len, "\t");
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

		ret = nft_set_elem_snprintf(buf+offset, len, elem, type, flags);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	return offset;
}

static int nft_set_snprintf_xml(char *buf, size_t size, struct nft_set *s,
				uint32_t flags)
{
	int ret;
	int len = size, offset = 0;
	struct nft_set_elem *elem;

	ret = snprintf(buf, len, "<set>");
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	if (s->flags & (1 << NFT_SET_ATTR_FAMILY)) {
		ret = snprintf(buf + offset, len, "<family>%s</family>",
			       nft_family2str(s->family));
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	if (s->flags & (1 << NFT_SET_ATTR_TABLE)) {
		ret = snprintf(buf + offset, len, "<table>%s</table>",
			       s->table);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	if (s->flags & (1 << NFT_SET_ATTR_NAME)) {
		ret = snprintf(buf + offset, len, "<name>%s</name>",
			       s->name);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	if (s->flags & (1 << NFT_SET_ATTR_FLAGS)) {
		ret = snprintf(buf + offset, len, "<flags>%u</flags>",
			       s->set_flags);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}
	if (s->flags & (1 << NFT_SET_ATTR_KEY_TYPE)) {
		ret = snprintf(buf + offset, len, "<key_type>%u</key_type>",
			       s->key_type);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}
	if (s->flags & (1 << NFT_SET_ATTR_KEY_LEN)) {
		ret = snprintf(buf + offset, len, "<key_len>%u</key_len>",
			       s->key_len);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	if (s->flags & (1 << NFT_SET_ATTR_DATA_TYPE)) {
		ret = snprintf(buf + offset, len, "<data_type>%u</data_type>",
			       s->data_type);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}
	if (s->flags & (1 << NFT_SET_ATTR_DATA_LEN)) {
		ret = snprintf(buf + offset, len, "<data_len>%u</data_len>",
			       s->data_len);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	if (s->flags & (1 << NFT_SET_ATTR_POLICY)) {
		ret = snprintf(buf + offset, len, "<policy>%u</policy>",
			       s->policy);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	if (s->flags & (1 << NFT_SET_ATTR_DESC_SIZE)) {
		ret = snprintf(buf + offset, len, "<desc_size>%u</desc_size>",
			       s->desc.size);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	if (!list_empty(&s->element_list)) {
		list_for_each_entry(elem, &s->element_list, head) {
			ret = nft_set_elem_snprintf(buf + offset, len, elem,
						    NFT_OUTPUT_XML, flags);
			SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
		}
	}

	ret = snprintf(buf + offset, len, "</set>");
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	return offset;
}

static int nft_set_cmd_snprintf(char *buf, size_t size, struct nft_set *s,
				uint32_t cmd, uint32_t type, uint32_t flags)
{
	int ret, len = size, offset = 0;
	uint32_t inner_flags = flags;

	/* prevent set_elems to print as events */
	inner_flags &= ~NFT_OF_EVENT_ANY;

	ret = nft_cmd_header_snprintf(buf + offset, len, cmd, type, flags);
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	switch(type) {
	case NFT_OUTPUT_DEFAULT:
		ret = nft_set_snprintf_default(buf+offset, len, s, type,
					       inner_flags);
		break;
	case NFT_OUTPUT_XML:
		ret = nft_set_snprintf_xml(buf+offset, len, s, inner_flags);
		break;
	case NFT_OUTPUT_JSON:
		ret = nft_set_snprintf_json(buf+offset, len, s, type,
					    inner_flags);
		break;
	default:
		return -1;
	}

	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	ret = nft_cmd_footer_snprintf(buf + offset, len, cmd, type, flags);
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	return offset;
}

int nft_set_snprintf(char *buf, size_t size, struct nft_set *s,
		     uint32_t type, uint32_t flags)
{
	return nft_set_cmd_snprintf(buf, size, s, nft_flag2cmd(flags), type,
				    flags);
}
EXPORT_SYMBOL(nft_set_snprintf);

static inline int nft_set_do_snprintf(char *buf, size_t size, void *s,
				      uint32_t cmd, uint32_t type,
				      uint32_t flags)
{
	return nft_set_snprintf(buf, size, s, type, flags);
}

int nft_set_fprintf(FILE *fp, struct nft_set *s, uint32_t type,
		    uint32_t flags)
{
	return nft_fprintf(fp, s, NFT_CMD_UNSPEC, type, flags,
			   nft_set_do_snprintf);
}
EXPORT_SYMBOL(nft_set_fprintf);

void nft_set_elem_add(struct nft_set *s, struct nft_set_elem *elem)
{
	list_add_tail(&elem->head, &s->element_list);
}
EXPORT_SYMBOL(nft_set_elem_add);

struct nft_set_list {
	struct list_head list;
};

struct nft_set_list *nft_set_list_alloc(void)
{
	struct nft_set_list *list;

	list = calloc(1, sizeof(struct nft_set_list));
	if (list == NULL)
		return NULL;

	INIT_LIST_HEAD(&list->list);

	return list;
}
EXPORT_SYMBOL(nft_set_list_alloc);

void nft_set_list_free(struct nft_set_list *list)
{
	struct nft_set *s, *tmp;

	list_for_each_entry_safe(s, tmp, &list->list, head) {
		list_del(&s->head);
		nft_set_free(s);
	}
	xfree(list);
}
EXPORT_SYMBOL(nft_set_list_free);

int nft_set_list_is_empty(struct nft_set_list *list)
{
	return list_empty(&list->list);
}
EXPORT_SYMBOL(nft_set_list_is_empty);

void nft_set_list_add(struct nft_set *s, struct nft_set_list *list)
{
	list_add(&s->head, &list->list);
}
EXPORT_SYMBOL(nft_set_list_add);

void nft_set_list_add_tail(struct nft_set *s, struct nft_set_list *list)
{
	list_add_tail(&s->head, &list->list);
}
EXPORT_SYMBOL(nft_set_list_add_tail);

void nft_set_list_del(struct nft_set *s)
{
	list_del(&s->head);
}
EXPORT_SYMBOL(nft_set_list_del);

int nft_set_list_foreach(struct nft_set_list *set_list,
			 int (*cb)(struct nft_set *t, void *data), void *data)
{
	struct nft_set *cur, *tmp;
	int ret;

	list_for_each_entry_safe(cur, tmp, &set_list->list, head) {
		ret = cb(cur, data);
		if (ret < 0)
			return ret;
	}
	return 0;
}
EXPORT_SYMBOL(nft_set_list_foreach);

struct nft_set_list_iter {
	struct nft_set_list	*list;
	struct nft_set		*cur;
};

struct nft_set_list_iter *nft_set_list_iter_create(struct nft_set_list *l)
{
	struct nft_set_list_iter *iter;

	iter = calloc(1, sizeof(struct nft_set_list_iter));
	if (iter == NULL)
		return NULL;

	iter->list = l;
	if (nft_set_list_is_empty(l))
		iter->cur = NULL;
	else
		iter->cur = list_entry(l->list.next, struct nft_set, head);

	return iter;
}
EXPORT_SYMBOL(nft_set_list_iter_create);

struct nft_set *nft_set_list_iter_cur(struct nft_set_list_iter *iter)
{
	return iter->cur;
}
EXPORT_SYMBOL(nft_set_list_iter_cur);

struct nft_set *nft_set_list_iter_next(struct nft_set_list_iter *iter)
{
	struct nft_set *s = iter->cur;

	if (s == NULL)
		return NULL;

	/* get next rule, if any */
	iter->cur = list_entry(iter->cur->head.next, struct nft_set, head);
	if (&iter->cur->head == iter->list->list.next)
		return NULL;

	return s;
}
EXPORT_SYMBOL(nft_set_list_iter_next);

void nft_set_list_iter_destroy(struct nft_set_list_iter *iter)
{
	xfree(iter);
}
EXPORT_SYMBOL(nft_set_list_iter_destroy);

static struct nft_set *nft_set_lookup(const char *this_set_name,
				      struct nft_set_list *set_list)
{
	struct nft_set_list_iter *iter;
	struct nft_set *s;
	const char *set_name;

	iter = nft_set_list_iter_create(set_list);
	if (iter == NULL)
		return NULL;

	s = nft_set_list_iter_cur(iter);
	while (s != NULL) {
		set_name  = nft_set_attr_get_str(s, NFT_SET_ATTR_NAME);
		if (strcmp(this_set_name, set_name) == 0)
			break;

		s = nft_set_list_iter_next(iter);
	}
	nft_set_list_iter_destroy(iter);

	return s;
}

int nft_set_lookup_id(struct nft_rule_expr *e,
		      struct nft_set_list *set_list, uint32_t *set_id)
{
	const char *set_name;
	struct nft_set *s;

	set_name = nft_rule_expr_get_str(e, NFT_EXPR_LOOKUP_SET);
	if (set_name == NULL)
		return 0;

	s = nft_set_lookup(set_name, set_list);
	if (s == NULL)
		return 0;

	*set_id = nft_set_attr_get_u32(s, NFT_SET_ATTR_ID);
	return 1;
}
