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

struct nftnl_set *nftnl_set_alloc(void)
{
	struct nftnl_set *s;

	s = calloc(1, sizeof(struct nftnl_set));
	if (s == NULL)
		return NULL;

	INIT_LIST_HEAD(&s->element_list);
	return s;
}
EXPORT_SYMBOL(nftnl_set_alloc, nft_set_alloc);

void nftnl_set_free(struct nftnl_set *s)
{
	struct nftnl_set_elem *elem, *tmp;

	if (s->table != NULL)
		xfree(s->table);
	if (s->name != NULL)
		xfree(s->name);

	list_for_each_entry_safe(elem, tmp, &s->element_list, head) {
		list_del(&elem->head);
		nftnl_set_elem_free(elem);
	}
	xfree(s);
}
EXPORT_SYMBOL(nftnl_set_free, nft_set_free);

bool nftnl_set_attr_is_set(const struct nftnl_set *s, uint16_t attr)
{
	return s->flags & (1 << attr);
}
EXPORT_SYMBOL(nftnl_set_attr_is_set, nft_set_attr_is_set);

void nftnl_set_attr_unset(struct nftnl_set *s, uint16_t attr)
{
	switch (attr) {
	case NFTNL_SET_ATTR_TABLE:
		if (s->flags & (1 << NFTNL_SET_ATTR_TABLE))
			if (s->table) {
				xfree(s->table);
				s->table = NULL;
			}
		break;
	case NFTNL_SET_ATTR_NAME:
		if (s->flags & (1 << NFTNL_SET_ATTR_NAME))
			if (s->name) {
				xfree(s->name);
				s->name = NULL;
			}
		break;
	case NFTNL_SET_ATTR_FLAGS:
	case NFTNL_SET_ATTR_KEY_TYPE:
	case NFTNL_SET_ATTR_KEY_LEN:
	case NFTNL_SET_ATTR_DATA_TYPE:
	case NFTNL_SET_ATTR_DATA_LEN:
	case NFTNL_SET_ATTR_FAMILY:
	case NFTNL_SET_ATTR_ID:
	case NFTNL_SET_ATTR_POLICY:
	case NFTNL_SET_ATTR_DESC_SIZE:
	case NFTNL_SET_ATTR_TIMEOUT:
	case NFTNL_SET_ATTR_GC_INTERVAL:
		break;
	default:
		return;
	}

	s->flags &= ~(1 << attr);
}
EXPORT_SYMBOL(nftnl_set_attr_unset, nft_set_attr_unset);

static uint32_t nftnl_set_attr_validate[NFTNL_SET_ATTR_MAX + 1] = {
	[NFTNL_SET_ATTR_FLAGS]		= sizeof(uint32_t),
	[NFTNL_SET_ATTR_KEY_TYPE]		= sizeof(uint32_t),
	[NFTNL_SET_ATTR_KEY_LEN]		= sizeof(uint32_t),
	[NFTNL_SET_ATTR_DATA_TYPE]	= sizeof(uint32_t),
	[NFTNL_SET_ATTR_DATA_LEN]		= sizeof(uint32_t),
	[NFTNL_SET_ATTR_FAMILY]		= sizeof(uint32_t),
	[NFTNL_SET_ATTR_POLICY]		= sizeof(uint32_t),
	[NFTNL_SET_ATTR_DESC_SIZE]	= sizeof(uint32_t),
	[NFTNL_SET_ATTR_TIMEOUT]		= sizeof(uint64_t),
	[NFTNL_SET_ATTR_GC_INTERVAL]	= sizeof(uint32_t),
};

void nftnl_set_attr_set_data(struct nftnl_set *s, uint16_t attr, const void *data,
			   uint32_t data_len)
{
	if (attr > NFTNL_SET_ATTR_MAX)
		return;

	nftnl_assert_validate(data, nftnl_set_attr_validate, attr, data_len);

	switch(attr) {
	case NFTNL_SET_ATTR_TABLE:
		if (s->table)
			xfree(s->table);

		s->table = strdup(data);
		break;
	case NFTNL_SET_ATTR_NAME:
		if (s->name)
			xfree(s->name);

		s->name = strdup(data);
		break;
	case NFTNL_SET_ATTR_FLAGS:
		s->set_flags = *((uint32_t *)data);
		break;
	case NFTNL_SET_ATTR_KEY_TYPE:
		s->key_type = *((uint32_t *)data);
		break;
	case NFTNL_SET_ATTR_KEY_LEN:
		s->key_len = *((uint32_t *)data);
		break;
	case NFTNL_SET_ATTR_DATA_TYPE:
		s->data_type = *((uint32_t *)data);
		break;
	case NFTNL_SET_ATTR_DATA_LEN:
		s->data_len = *((uint32_t *)data);
		break;
	case NFTNL_SET_ATTR_FAMILY:
		s->family = *((uint32_t *)data);
		break;
	case NFTNL_SET_ATTR_ID:
		s->id = *((uint32_t *)data);
		break;
	case NFTNL_SET_ATTR_POLICY:
		s->policy = *((uint32_t *)data);
		break;
	case NFTNL_SET_ATTR_DESC_SIZE:
		s->desc.size = *((uint32_t *)data);
		break;
	case NFTNL_SET_ATTR_TIMEOUT:
		s->timeout = *((uint64_t *)data);
		break;
	case NFTNL_SET_ATTR_GC_INTERVAL:
		s->gc_interval = *((uint32_t *)data);
		break;
	}
	s->flags |= (1 << attr);
}
EXPORT_SYMBOL(nftnl_set_attr_set_data, nft_set_attr_set_data);

void nftnl_set_attr_set(struct nftnl_set *s, uint16_t attr, const void *data)
{
	nftnl_set_attr_set_data(s, attr, data, nftnl_set_attr_validate[attr]);
}
EXPORT_SYMBOL(nftnl_set_attr_set, nft_set_attr_set);

void nftnl_set_attr_set_u32(struct nftnl_set *s, uint16_t attr, uint32_t val)
{
	nftnl_set_attr_set(s, attr, &val);
}
EXPORT_SYMBOL(nftnl_set_attr_set_u32, nft_set_attr_set_u32);

void nftnl_set_attr_set_u64(struct nftnl_set *s, uint16_t attr, uint64_t val)
{
	nftnl_set_attr_set(s, attr, &val);
}
EXPORT_SYMBOL(nftnl_set_attr_set_u64, nft_set_attr_set_u64);

void nftnl_set_attr_set_str(struct nftnl_set *s, uint16_t attr, const char *str)
{
	nftnl_set_attr_set(s, attr, str);
}
EXPORT_SYMBOL(nftnl_set_attr_set_str, nft_set_attr_set_str);

const void *nftnl_set_attr_get_data(struct nftnl_set *s, uint16_t attr,
				  uint32_t *data_len)
{
	if (!(s->flags & (1 << attr)))
		return NULL;

	switch(attr) {
	case NFTNL_SET_ATTR_TABLE:
		return s->table;
	case NFTNL_SET_ATTR_NAME:
		return s->name;
	case NFTNL_SET_ATTR_FLAGS:
		*data_len = sizeof(uint32_t);
		return &s->set_flags;
	case NFTNL_SET_ATTR_KEY_TYPE:
		*data_len = sizeof(uint32_t);
		return &s->key_type;
	case NFTNL_SET_ATTR_KEY_LEN:
		*data_len = sizeof(uint32_t);
		return &s->key_len;
	case NFTNL_SET_ATTR_DATA_TYPE:
		*data_len = sizeof(uint32_t);
		return &s->data_type;
	case NFTNL_SET_ATTR_DATA_LEN:
		*data_len = sizeof(uint32_t);
		return &s->data_len;
	case NFTNL_SET_ATTR_FAMILY:
		*data_len = sizeof(uint32_t);
		return &s->family;
	case NFTNL_SET_ATTR_ID:
		*data_len = sizeof(uint32_t);
		return &s->id;
	case NFTNL_SET_ATTR_POLICY:
		*data_len = sizeof(uint32_t);
		return &s->policy;
	case NFTNL_SET_ATTR_DESC_SIZE:
		*data_len = sizeof(uint32_t);
		return &s->desc.size;
	case NFTNL_SET_ATTR_TIMEOUT:
		*data_len = sizeof(uint64_t);
		return &s->timeout;
	case NFTNL_SET_ATTR_GC_INTERVAL:
		*data_len = sizeof(uint32_t);
		return &s->gc_interval;
	}
	return NULL;
}
EXPORT_SYMBOL(nftnl_set_attr_get_data, nft_set_attr_get_data);

const void *nftnl_set_attr_get(struct nftnl_set *s, uint16_t attr)
{
	uint32_t data_len;
	return nftnl_set_attr_get_data(s, attr, &data_len);
}
EXPORT_SYMBOL(nftnl_set_attr_get, nft_set_attr_get);

const char *nftnl_set_attr_get_str(struct nftnl_set *s, uint16_t attr)
{
	return nftnl_set_attr_get(s, attr);
}
EXPORT_SYMBOL(nftnl_set_attr_get_str, nft_set_attr_get_str);

uint32_t nftnl_set_attr_get_u32(struct nftnl_set *s, uint16_t attr)
{
	uint32_t data_len;
	const uint32_t *val = nftnl_set_attr_get_data(s, attr, &data_len);

	nftnl_assert(val, attr, data_len == sizeof(uint32_t));

	return val ? *val : 0;
}
EXPORT_SYMBOL(nftnl_set_attr_get_u32, nft_set_attr_get_u32);

uint64_t nftnl_set_attr_get_u64(struct nftnl_set *s, uint16_t attr)
{
	uint32_t data_len;
	const uint64_t *val = nftnl_set_attr_get_data(s, attr, &data_len);

	nftnl_assert(val, attr, data_len == sizeof(uint64_t));

	return val ? *val : 0;
}
EXPORT_SYMBOL(nftnl_set_attr_get_u64, nft_set_attr_get_u64);

struct nftnl_set *nftnl_set_clone(const struct nftnl_set *set)
{
	struct nftnl_set *newset;
	struct nftnl_set_elem *elem, *newelem;

	newset = nftnl_set_alloc();
	if (newset == NULL)
		return NULL;

	memcpy(newset, set, sizeof(*set));

	if (set->flags & (1 << NFTNL_SET_ATTR_TABLE))
		newset->table = strdup(set->table);
	if (set->flags & (1 << NFTNL_SET_ATTR_NAME))
		newset->name = strdup(set->name);

	INIT_LIST_HEAD(&newset->element_list);
	list_for_each_entry(elem, &set->element_list, head) {
		newelem = nftnl_set_elem_clone(elem);
		if (newelem == NULL)
			goto err;

		list_add_tail(&newelem->head, &newset->element_list);
	}

	return newset;
err:
	nftnl_set_free(newset);
	return NULL;
}

static void
nftnl_set_nlmsg_build_desc_payload(struct nlmsghdr *nlh, struct nftnl_set *s)
{
	struct nlattr *nest;

	nest = mnl_attr_nest_start(nlh, NFTA_SET_DESC);
	mnl_attr_put_u32(nlh, NFTA_SET_DESC_SIZE, htonl(s->desc.size));
	mnl_attr_nest_end(nlh, nest);
}

void nftnl_set_nlmsg_build_payload(struct nlmsghdr *nlh, struct nftnl_set *s)
{
	if (s->flags & (1 << NFTNL_SET_ATTR_TABLE))
		mnl_attr_put_strz(nlh, NFTA_SET_TABLE, s->table);
	if (s->flags & (1 << NFTNL_SET_ATTR_NAME))
		mnl_attr_put_strz(nlh, NFTA_SET_NAME, s->name);
	if (s->flags & (1 << NFTNL_SET_ATTR_FLAGS))
		mnl_attr_put_u32(nlh, NFTA_SET_FLAGS, htonl(s->set_flags));
	if (s->flags & (1 << NFTNL_SET_ATTR_KEY_TYPE))
		mnl_attr_put_u32(nlh, NFTA_SET_KEY_TYPE, htonl(s->key_type));
	if (s->flags & (1 << NFTNL_SET_ATTR_KEY_LEN))
		mnl_attr_put_u32(nlh, NFTA_SET_KEY_LEN, htonl(s->key_len));
	/* These are only used to map matching -> action (1:1) */
	if (s->flags & (1 << NFTNL_SET_ATTR_DATA_TYPE))
		mnl_attr_put_u32(nlh, NFTA_SET_DATA_TYPE, htonl(s->data_type));
	if (s->flags & (1 << NFTNL_SET_ATTR_DATA_LEN))
		mnl_attr_put_u32(nlh, NFTA_SET_DATA_LEN, htonl(s->data_len));
	if (s->flags & (1 << NFTNL_SET_ATTR_ID))
		mnl_attr_put_u32(nlh, NFTA_SET_ID, htonl(s->id));
	if (s->flags & (1 << NFTNL_SET_ATTR_POLICY))
		mnl_attr_put_u32(nlh, NFTA_SET_POLICY, htonl(s->policy));
	if (s->flags & (1 << NFTNL_SET_ATTR_DESC_SIZE))
		nftnl_set_nlmsg_build_desc_payload(nlh, s);
	if (s->flags & (1 << NFTNL_SET_ATTR_TIMEOUT))
		mnl_attr_put_u64(nlh, NFTA_SET_TIMEOUT, htobe64(s->timeout));
	if (s->flags & (1 << NFTNL_SET_ATTR_GC_INTERVAL))
		mnl_attr_put_u32(nlh, NFTA_SET_GC_INTERVAL, htonl(s->gc_interval));
}
EXPORT_SYMBOL(nftnl_set_nlmsg_build_payload, nft_set_nlmsg_build_payload);

static int nftnl_set_parse_attr_cb(const struct nlattr *attr, void *data)
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

static int nftnl_set_desc_parse_attr_cb(const struct nlattr *attr, void *data)
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

static int nftnl_set_desc_parse(struct nftnl_set *s,
			      const struct nlattr *attr)
{
	struct nlattr *tb[NFTA_SET_DESC_MAX + 1] = {};

	if (mnl_attr_parse_nested(attr, nftnl_set_desc_parse_attr_cb, tb) < 0)
		return -1;

	if (tb[NFTA_SET_DESC_SIZE]) {
		s->desc.size = ntohl(mnl_attr_get_u32(tb[NFTA_SET_DESC_SIZE]));
		s->flags |= (1 << NFTNL_SET_ATTR_DESC_SIZE);
	}

	return 0;
}

int nftnl_set_nlmsg_parse(const struct nlmsghdr *nlh, struct nftnl_set *s)
{
	struct nlattr *tb[NFTA_SET_MAX+1] = {};
	struct nfgenmsg *nfg = mnl_nlmsg_get_payload(nlh);
	int ret = 0;

	if (mnl_attr_parse(nlh, sizeof(*nfg), nftnl_set_parse_attr_cb, tb) < 0)
		return -1;

	if (tb[NFTA_SET_TABLE]) {
		xfree(s->table);
		s->table = strdup(mnl_attr_get_str(tb[NFTA_SET_TABLE]));
		s->flags |= (1 << NFTNL_SET_ATTR_TABLE);
	}
	if (tb[NFTA_SET_NAME]) {
		xfree(s->name);
		s->name = strdup(mnl_attr_get_str(tb[NFTA_SET_NAME]));
		s->flags |= (1 << NFTNL_SET_ATTR_NAME);
	}
	if (tb[NFTA_SET_FLAGS]) {
		s->set_flags = ntohl(mnl_attr_get_u32(tb[NFTA_SET_FLAGS]));
		s->flags |= (1 << NFTNL_SET_ATTR_FLAGS);
	}
	if (tb[NFTA_SET_KEY_TYPE]) {
		s->key_type = ntohl(mnl_attr_get_u32(tb[NFTA_SET_KEY_TYPE]));
		s->flags |= (1 << NFTNL_SET_ATTR_KEY_TYPE);
	}
	if (tb[NFTA_SET_KEY_LEN]) {
		s->key_len = ntohl(mnl_attr_get_u32(tb[NFTA_SET_KEY_LEN]));
		s->flags |= (1 << NFTNL_SET_ATTR_KEY_LEN);
	}
	if (tb[NFTA_SET_DATA_TYPE]) {
		s->data_type = ntohl(mnl_attr_get_u32(tb[NFTA_SET_DATA_TYPE]));
		s->flags |= (1 << NFTNL_SET_ATTR_DATA_TYPE);
	}
	if (tb[NFTA_SET_DATA_LEN]) {
		s->data_len = ntohl(mnl_attr_get_u32(tb[NFTA_SET_DATA_LEN]));
		s->flags |= (1 << NFTNL_SET_ATTR_DATA_LEN);
	}
	if (tb[NFTA_SET_ID]) {
		s->id = ntohl(mnl_attr_get_u32(tb[NFTA_SET_ID]));
		s->flags |= (1 << NFTNL_SET_ATTR_ID);
	}
	if (tb[NFTA_SET_POLICY]) {
		s->policy = ntohl(mnl_attr_get_u32(tb[NFTA_SET_POLICY]));
		s->flags |= (1 << NFTNL_SET_ATTR_POLICY);
	}
	if (tb[NFTA_SET_TIMEOUT]) {
		s->timeout = be64toh(mnl_attr_get_u64(tb[NFTA_SET_TIMEOUT]));
		s->flags |= (1 << NFTNL_SET_ATTR_TIMEOUT);
	}
	if (tb[NFTA_SET_GC_INTERVAL]) {
		s->gc_interval = ntohl(mnl_attr_get_u32(tb[NFTA_SET_GC_INTERVAL]));
		s->flags |= (1 << NFTNL_SET_ATTR_GC_INTERVAL);
	}
	if (tb[NFTA_SET_DESC])
		ret = nftnl_set_desc_parse(s, tb[NFTA_SET_DESC]);

	s->family = nfg->nfgen_family;
	s->flags |= (1 << NFTNL_SET_ATTR_FAMILY);

	return ret;
}
EXPORT_SYMBOL(nftnl_set_nlmsg_parse, nft_set_nlmsg_parse);

#ifdef JSON_PARSING
static int nftnl_jansson_parse_set_info(struct nftnl_set *s, json_t *tree,
				      struct nftnl_parse_err *err)
{
	json_t *root = tree, *array, *json_elem;
	uint32_t flags, key_type, key_len, data_type, data_len, policy, size;
	int family, i;
	const char *name, *table;
	struct nftnl_set_elem *elem;

	name = nftnl_jansson_parse_str(root, "name", err);
	if (name == NULL)
		return -1;

	nftnl_set_attr_set_str(s, NFTNL_SET_ATTR_NAME, name);

	table = nftnl_jansson_parse_str(root, "table", err);
	if (table == NULL)
		return -1;

	nftnl_set_attr_set_str(s, NFTNL_SET_ATTR_TABLE, table);

	if (nftnl_jansson_parse_family(root, &family, err) == 0)
		nftnl_set_attr_set_u32(s, NFTNL_SET_ATTR_FAMILY, family);

	if (nftnl_jansson_parse_val(root, "flags", NFTNL_TYPE_U32, &flags, err) == 0)
		nftnl_set_attr_set_u32(s, NFTNL_SET_ATTR_FLAGS, flags);

	if (nftnl_jansson_parse_val(root, "key_type", NFTNL_TYPE_U32, &key_type,
				  err) == 0)
		nftnl_set_attr_set_u32(s, NFTNL_SET_ATTR_KEY_TYPE, key_type);

	if (nftnl_jansson_parse_val(root, "key_len", NFTNL_TYPE_U32, &key_len,
				  err) == 0)
		nftnl_set_attr_set_u32(s, NFTNL_SET_ATTR_KEY_LEN, key_len);

	if (nftnl_jansson_node_exist(root, "data_type")) {
		if (nftnl_jansson_parse_val(root, "data_type", NFTNL_TYPE_U32,
					  &data_type, err) < 0)
			return -1;

		nftnl_set_attr_set_u32(s, NFTNL_SET_ATTR_DATA_TYPE, data_type);
	}

	if (nftnl_jansson_node_exist(root, "data_len")) {
		if (nftnl_jansson_parse_val(root, "data_len", NFTNL_TYPE_U32,
					  &data_len, err) < 0)
			return -1;

		nftnl_set_attr_set_u32(s, NFTNL_SET_ATTR_DATA_LEN, data_len);
	}

	if (nftnl_jansson_node_exist(root, "policy")) {
		if (nftnl_jansson_parse_val(root, "policy", NFTNL_TYPE_U32,
					  &policy, err) < 0)
			return -1;

		nftnl_set_attr_set_u32(s, NFTNL_SET_ATTR_POLICY, policy);
	}

	if (nftnl_jansson_node_exist(root, "desc_size")) {
		if (nftnl_jansson_parse_val(root, "desc_size", NFTNL_TYPE_U32,
					  &size, err) < 0)
			return -1;

		nftnl_set_attr_set_u32(s, NFTNL_SET_ATTR_DESC_SIZE, size);
	}

	if (nftnl_jansson_node_exist(root, "set_elem")) {
		array = json_object_get(root, "set_elem");
		for (i = 0; i < json_array_size(array); i++) {
			elem = nftnl_set_elem_alloc();
			if (elem == NULL)
				return -1;

			json_elem = json_array_get(array, i);
			if (json_elem == NULL)
				return -1;

			if (nftnl_jansson_set_elem_parse(elem,
						       json_elem, err) < 0)
				return -1;

			list_add_tail(&elem->head, &s->element_list);
		}

	}

	return 0;
}

int nftnl_jansson_parse_set(struct nftnl_set *s, json_t *tree,
			  struct nftnl_parse_err *err)
{
	json_t *root;

	root = nftnl_jansson_get_node(tree, "set", err);
	if (root == NULL)
		return -1;

	return nftnl_jansson_parse_set_info(s, root, err);
}

int nftnl_jansson_parse_elem(struct nftnl_set *s, json_t *tree,
			   struct nftnl_parse_err *err)
{
	json_t *root;

	root = nftnl_jansson_get_node(tree, "element", err);
	if (root == NULL)
		return -1;

	return nftnl_jansson_parse_set_info(s, root, err);
}
#endif

static int nftnl_set_json_parse(struct nftnl_set *s, const void *json,
			      struct nftnl_parse_err *err,
			      enum nftnl_parse_input input)
{
#ifdef JSON_PARSING
	json_t *tree;
	json_error_t error;
	int ret;

	tree = nftnl_jansson_create_root(json, &error, err, input);
	if (tree == NULL)
		return -1;

	ret = nftnl_jansson_parse_set(s, tree, err);
	nftnl_jansson_free_root(tree);

	return ret;
#else
	errno = EOPNOTSUPP;
	return -1;
#endif
}

#ifdef XML_PARSING
int nftnl_mxml_set_parse(mxml_node_t *tree, struct nftnl_set *s,
		       struct nftnl_parse_err *err)
{
	mxml_node_t *node = NULL;
	struct nftnl_set_elem *elem;
	const char *name, *table;
	int family;
	uint32_t set_flags, key_type, key_len;
	uint32_t data_type, data_len, policy, size;

	name = nftnl_mxml_str_parse(tree, "name", MXML_DESCEND_FIRST,
				  NFTNL_XML_MAND, err);
	if (name == NULL)
		return -1;
	nftnl_set_attr_set_str(s, NFTNL_SET_ATTR_NAME, name);

	table = nftnl_mxml_str_parse(tree, "table", MXML_DESCEND_FIRST,
				   NFTNL_XML_MAND, err);
	if (table == NULL)
		return -1;
	nftnl_set_attr_set_str(s, NFTNL_SET_ATTR_TABLE, table);

	family = nftnl_mxml_family_parse(tree, "family", MXML_DESCEND_FIRST,
				       NFTNL_XML_MAND, err);
	if (family >= 0)
		nftnl_set_attr_set_u32(s, NFTNL_SET_ATTR_FAMILY, family);

	if (nftnl_mxml_num_parse(tree, "flags", MXML_DESCEND_FIRST, BASE_DEC,
			       &set_flags, NFTNL_TYPE_U32, NFTNL_XML_MAND,
			       err) == 0)
		nftnl_set_attr_set_u32(s, NFTNL_SET_ATTR_FLAGS, set_flags);

	if (nftnl_mxml_num_parse(tree, "key_type", MXML_DESCEND_FIRST, BASE_DEC,
			       &key_type, NFTNL_TYPE_U32, NFTNL_XML_MAND, err) == 0)
		nftnl_set_attr_set_u32(s, NFTNL_SET_ATTR_KEY_TYPE, key_type);

	if (nftnl_mxml_num_parse(tree, "key_len", MXML_DESCEND_FIRST, BASE_DEC,
			       &key_len, NFTNL_TYPE_U32, NFTNL_XML_MAND, err) < 0)
		return -1;
	nftnl_set_attr_set_u32(s, NFTNL_SET_ATTR_KEY_LEN, key_len);

	if (nftnl_mxml_num_parse(tree, "data_type", MXML_DESCEND_FIRST, BASE_DEC,
			       &data_type, NFTNL_TYPE_U32,
			       NFTNL_XML_OPT, err) == 0) {
		nftnl_set_attr_set_u32(s, NFTNL_SET_ATTR_DATA_TYPE, data_type);

		if (nftnl_mxml_num_parse(tree, "data_len", MXML_DESCEND_FIRST,
				       BASE_DEC, &data_len, NFTNL_TYPE_U32,
				       NFTNL_XML_MAND, err) == 0)
			nftnl_set_attr_set_u32(s, NFTNL_SET_ATTR_DATA_LEN, data_len);

	}

	if (nftnl_mxml_num_parse(tree, "policy", MXML_DESCEND_FIRST,
			       BASE_DEC, &policy, NFTNL_TYPE_U32,
			       NFTNL_XML_OPT, err) == 0)
		nftnl_set_attr_set_u32(s, NFTNL_SET_ATTR_POLICY, policy);

	if (nftnl_mxml_num_parse(tree, "desc_size", MXML_DESCEND_FIRST,
			       BASE_DEC, &size, NFTNL_TYPE_U32,
			       NFTNL_XML_OPT, err) == 0)
		nftnl_set_attr_set_u32(s, NFTNL_SET_ATTR_DESC_SIZE, policy);

	for (node = mxmlFindElement(tree, tree, "set_elem", NULL,
				    NULL, MXML_DESCEND);
		node != NULL;
		node = mxmlFindElement(node, tree, "set_elem", NULL,
				       NULL, MXML_DESCEND)) {

		elem = nftnl_set_elem_alloc();
		if (elem == NULL)
			return -1;

		if (nftnl_mxml_set_elem_parse(node, elem, err) < 0)
			return -1;

		list_add_tail(&elem->head, &s->element_list);
	}

	return 0;
}
#endif

static int nftnl_set_xml_parse(struct nftnl_set *s, const void *xml,
			     struct nftnl_parse_err *err,
			     enum nftnl_parse_input input)
{
#ifdef XML_PARSING
	int ret;
	mxml_node_t *tree = nftnl_mxml_build_tree(xml, "set", err, input);
	if (tree == NULL)
		return -1;

	ret = nftnl_mxml_set_parse(tree, s, err);
	mxmlDelete(tree);
	return ret;
#else
	errno = EOPNOTSUPP;
	return -1;
#endif
}

static int nftnl_set_do_parse(struct nftnl_set *s, enum nftnl_parse_type type,
			    const void *data, struct nftnl_parse_err *err,
			    enum nftnl_parse_input input)
{
	int ret;
	struct nftnl_parse_err perr;

	switch (type) {
	case NFTNL_PARSE_XML:
		ret = nftnl_set_xml_parse(s, data, &perr, input);
		break;
	case NFTNL_PARSE_JSON:
		ret = nftnl_set_json_parse(s, data, &perr, input);
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
int nftnl_set_parse(struct nftnl_set *s, enum nftnl_parse_type type,
		  const char *data, struct nftnl_parse_err *err)
{
	return nftnl_set_do_parse(s, type, data, err, NFTNL_PARSE_BUFFER);
}
EXPORT_SYMBOL(nftnl_set_parse, nft_set_parse);

int nftnl_set_parse_file(struct nftnl_set *s, enum nftnl_parse_type type,
		       FILE *fp, struct nftnl_parse_err *err)
{
	return nftnl_set_do_parse(s, type, fp, err, NFTNL_PARSE_FILE);
}
EXPORT_SYMBOL(nftnl_set_parse_file, nft_set_parse_file);

static int nftnl_set_snprintf_json(char *buf, size_t size, struct nftnl_set *s,
				  uint32_t type, uint32_t flags)
{
	int len = size, offset = 0, ret;
	struct nftnl_set_elem *elem;

	ret = snprintf(buf, len, "{\"set\":{");
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	if (s->flags & (1 << NFTNL_SET_ATTR_NAME)) {
		ret = snprintf(buf + offset, len, "\"name\":\"%s\"",
			       s->name);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}
	if (s->flags & (1 << NFTNL_SET_ATTR_TABLE)) {
		ret = snprintf(buf + offset, len, ",\"table\":\"%s\"",
			       s->table);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}
	if (s->flags & (1 << NFTNL_SET_ATTR_FLAGS)) {
		ret = snprintf(buf + offset, len, ",\"flags\":%u",
			       s->set_flags);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}
	if (s->flags & (1 << NFTNL_SET_ATTR_FAMILY)) {
		ret = snprintf(buf + offset, len, ",\"family\":\"%s\"",
			       nftnl_family2str(s->family));
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}
	if (s->flags & (1 << NFTNL_SET_ATTR_KEY_TYPE)) {
		ret = snprintf(buf + offset, len, ",\"key_type\":%u",
			       s->key_type);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}
	if (s->flags & (1 << NFTNL_SET_ATTR_KEY_LEN)) {
		ret = snprintf(buf + offset, len, ",\"key_len\":%u",
			       s->key_len);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}
	if(s->flags & (1 << NFTNL_SET_ATTR_DATA_TYPE)) {
		ret = snprintf(buf + offset, len,
				  ",\"data_type\":%u", s->data_type);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}
	if(s->flags & (1 << NFTNL_SET_ATTR_DATA_LEN)) {
		ret = snprintf(buf + offset, len, ",\"data_len\":%u", s->data_len);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	if (s->flags & (1 << NFTNL_SET_ATTR_POLICY)) {
		ret = snprintf(buf + offset, len, ",\"policy\":%u",
			       s->policy);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	if (s->flags & (1 << NFTNL_SET_ATTR_DESC_SIZE)) {
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

		ret = nftnl_set_elem_snprintf(buf + offset, len, elem, type,
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

static int nftnl_set_snprintf_default(char *buf, size_t size, struct nftnl_set *s,
				    uint32_t type, uint32_t flags)
{
	int ret;
	int len = size, offset = 0;
	struct nftnl_set_elem *elem;

	ret = snprintf(buf, len, "%s %s %x",
			s->name, s->table, s->set_flags);
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	if (s->flags & (1 << NFTNL_SET_ATTR_TIMEOUT)) {
		ret = snprintf(buf + offset, len, " timeout %"PRIu64"ms",
			       s->timeout);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	if (s->flags & (1 << NFTNL_SET_ATTR_GC_INTERVAL)) {
		ret = snprintf(buf + offset, len, " gc_interval %ums",
			       s->gc_interval);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	if (s->flags & (1 << NFTNL_SET_ATTR_POLICY)) {
		ret = snprintf(buf + offset, len, " policy %u", s->policy);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	if (s->flags & (1 << NFTNL_SET_ATTR_DESC_SIZE)) {
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

		ret = nftnl_set_elem_snprintf(buf+offset, len, elem, type, flags);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	return offset;
}

static int nftnl_set_snprintf_xml(char *buf, size_t size, struct nftnl_set *s,
				uint32_t flags)
{
	int ret;
	int len = size, offset = 0;
	struct nftnl_set_elem *elem;

	ret = snprintf(buf, len, "<set>");
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	if (s->flags & (1 << NFTNL_SET_ATTR_FAMILY)) {
		ret = snprintf(buf + offset, len, "<family>%s</family>",
			       nftnl_family2str(s->family));
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	if (s->flags & (1 << NFTNL_SET_ATTR_TABLE)) {
		ret = snprintf(buf + offset, len, "<table>%s</table>",
			       s->table);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	if (s->flags & (1 << NFTNL_SET_ATTR_NAME)) {
		ret = snprintf(buf + offset, len, "<name>%s</name>",
			       s->name);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	if (s->flags & (1 << NFTNL_SET_ATTR_FLAGS)) {
		ret = snprintf(buf + offset, len, "<flags>%u</flags>",
			       s->set_flags);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}
	if (s->flags & (1 << NFTNL_SET_ATTR_KEY_TYPE)) {
		ret = snprintf(buf + offset, len, "<key_type>%u</key_type>",
			       s->key_type);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}
	if (s->flags & (1 << NFTNL_SET_ATTR_KEY_LEN)) {
		ret = snprintf(buf + offset, len, "<key_len>%u</key_len>",
			       s->key_len);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	if (s->flags & (1 << NFTNL_SET_ATTR_DATA_TYPE)) {
		ret = snprintf(buf + offset, len, "<data_type>%u</data_type>",
			       s->data_type);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}
	if (s->flags & (1 << NFTNL_SET_ATTR_DATA_LEN)) {
		ret = snprintf(buf + offset, len, "<data_len>%u</data_len>",
			       s->data_len);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	if (s->flags & (1 << NFTNL_SET_ATTR_POLICY)) {
		ret = snprintf(buf + offset, len, "<policy>%u</policy>",
			       s->policy);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	if (s->flags & (1 << NFTNL_SET_ATTR_DESC_SIZE)) {
		ret = snprintf(buf + offset, len, "<desc_size>%u</desc_size>",
			       s->desc.size);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	if (!list_empty(&s->element_list)) {
		list_for_each_entry(elem, &s->element_list, head) {
			ret = nftnl_set_elem_snprintf(buf + offset, len, elem,
						    NFTNL_OUTPUT_XML, flags);
			SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
		}
	}

	ret = snprintf(buf + offset, len, "</set>");
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	return offset;
}

static int nftnl_set_cmd_snprintf(char *buf, size_t size, struct nftnl_set *s,
				uint32_t cmd, uint32_t type, uint32_t flags)
{
	int ret, len = size, offset = 0;
	uint32_t inner_flags = flags;

	/* prevent set_elems to print as events */
	inner_flags &= ~NFTNL_OF_EVENT_ANY;

	ret = nftnl_cmd_header_snprintf(buf + offset, len, cmd, type, flags);
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	switch(type) {
	case NFTNL_OUTPUT_DEFAULT:
		ret = nftnl_set_snprintf_default(buf+offset, len, s, type,
					       inner_flags);
		break;
	case NFTNL_OUTPUT_XML:
		ret = nftnl_set_snprintf_xml(buf+offset, len, s, inner_flags);
		break;
	case NFTNL_OUTPUT_JSON:
		ret = nftnl_set_snprintf_json(buf+offset, len, s, type,
					    inner_flags);
		break;
	default:
		return -1;
	}

	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	ret = nftnl_cmd_footer_snprintf(buf + offset, len, cmd, type, flags);
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	return offset;
}

int nftnl_set_snprintf(char *buf, size_t size, struct nftnl_set *s,
		     uint32_t type, uint32_t flags)
{
	return nftnl_set_cmd_snprintf(buf, size, s, nftnl_flag2cmd(flags), type,
				    flags);
}
EXPORT_SYMBOL(nftnl_set_snprintf, nft_set_snprintf);

static inline int nftnl_set_do_snprintf(char *buf, size_t size, void *s,
				      uint32_t cmd, uint32_t type,
				      uint32_t flags)
{
	return nftnl_set_snprintf(buf, size, s, type, flags);
}

int nftnl_set_fprintf(FILE *fp, struct nftnl_set *s, uint32_t type,
		    uint32_t flags)
{
	return nftnl_fprintf(fp, s, NFTNL_CMD_UNSPEC, type, flags,
			   nftnl_set_do_snprintf);
}
EXPORT_SYMBOL(nftnl_set_fprintf, nft_set_fprintf);

void nftnl_set_elem_add(struct nftnl_set *s, struct nftnl_set_elem *elem)
{
	list_add_tail(&elem->head, &s->element_list);
}
EXPORT_SYMBOL(nftnl_set_elem_add, nft_set_elem_add);

struct nftnl_set_list {
	struct list_head list;
};

struct nftnl_set_list *nftnl_set_list_alloc(void)
{
	struct nftnl_set_list *list;

	list = calloc(1, sizeof(struct nftnl_set_list));
	if (list == NULL)
		return NULL;

	INIT_LIST_HEAD(&list->list);

	return list;
}
EXPORT_SYMBOL(nftnl_set_list_alloc, nft_set_list_alloc);

void nftnl_set_list_free(struct nftnl_set_list *list)
{
	struct nftnl_set *s, *tmp;

	list_for_each_entry_safe(s, tmp, &list->list, head) {
		list_del(&s->head);
		nftnl_set_free(s);
	}
	xfree(list);
}
EXPORT_SYMBOL(nftnl_set_list_free, nft_set_list_free);

int nftnl_set_list_is_empty(struct nftnl_set_list *list)
{
	return list_empty(&list->list);
}
EXPORT_SYMBOL(nftnl_set_list_is_empty, nft_set_list_is_empty);

void nftnl_set_list_add(struct nftnl_set *s, struct nftnl_set_list *list)
{
	list_add(&s->head, &list->list);
}
EXPORT_SYMBOL(nftnl_set_list_add, nft_set_list_add);

void nftnl_set_list_add_tail(struct nftnl_set *s, struct nftnl_set_list *list)
{
	list_add_tail(&s->head, &list->list);
}
EXPORT_SYMBOL(nftnl_set_list_add_tail, nft_set_list_add_tail);

void nftnl_set_list_del(struct nftnl_set *s)
{
	list_del(&s->head);
}
EXPORT_SYMBOL(nftnl_set_list_del, nft_set_list_del);

int nftnl_set_list_foreach(struct nftnl_set_list *set_list,
			 int (*cb)(struct nftnl_set *t, void *data), void *data)
{
	struct nftnl_set *cur, *tmp;
	int ret;

	list_for_each_entry_safe(cur, tmp, &set_list->list, head) {
		ret = cb(cur, data);
		if (ret < 0)
			return ret;
	}
	return 0;
}
EXPORT_SYMBOL(nftnl_set_list_foreach, nft_set_list_foreach);

struct nftnl_set_list_iter {
	struct nftnl_set_list	*list;
	struct nftnl_set		*cur;
};

struct nftnl_set_list_iter *nftnl_set_list_iter_create(struct nftnl_set_list *l)
{
	struct nftnl_set_list_iter *iter;

	iter = calloc(1, sizeof(struct nftnl_set_list_iter));
	if (iter == NULL)
		return NULL;

	iter->list = l;
	if (nftnl_set_list_is_empty(l))
		iter->cur = NULL;
	else
		iter->cur = list_entry(l->list.next, struct nftnl_set, head);

	return iter;
}
EXPORT_SYMBOL(nftnl_set_list_iter_create, nft_set_list_iter_create);

struct nftnl_set *nftnl_set_list_iter_cur(struct nftnl_set_list_iter *iter)
{
	return iter->cur;
}
EXPORT_SYMBOL(nftnl_set_list_iter_cur, nft_set_list_iter_cur);

struct nftnl_set *nftnl_set_list_iter_next(struct nftnl_set_list_iter *iter)
{
	struct nftnl_set *s = iter->cur;

	if (s == NULL)
		return NULL;

	/* get next rule, if any */
	iter->cur = list_entry(iter->cur->head.next, struct nftnl_set, head);
	if (&iter->cur->head == iter->list->list.next)
		return NULL;

	return s;
}
EXPORT_SYMBOL(nftnl_set_list_iter_next, nft_set_list_iter_next);

void nftnl_set_list_iter_destroy(struct nftnl_set_list_iter *iter)
{
	xfree(iter);
}
EXPORT_SYMBOL(nftnl_set_list_iter_destroy, nft_set_list_iter_destroy);

static struct nftnl_set *nftnl_set_lookup(const char *this_set_name,
				      struct nftnl_set_list *set_list)
{
	struct nftnl_set_list_iter *iter;
	struct nftnl_set *s;
	const char *set_name;

	iter = nftnl_set_list_iter_create(set_list);
	if (iter == NULL)
		return NULL;

	s = nftnl_set_list_iter_cur(iter);
	while (s != NULL) {
		set_name  = nftnl_set_attr_get_str(s, NFTNL_SET_ATTR_NAME);
		if (strcmp(this_set_name, set_name) == 0)
			break;

		s = nftnl_set_list_iter_next(iter);
	}
	nftnl_set_list_iter_destroy(iter);

	return s;
}

int nftnl_set_lookup_id(struct nftnl_rule_expr *e,
		      struct nftnl_set_list *set_list, uint32_t *set_id)
{
	const char *set_name;
	struct nftnl_set *s;

	set_name = nftnl_rule_expr_get_str(e, NFTNL_EXPR_LOOKUP_SET);
	if (set_name == NULL)
		return 0;

	s = nftnl_set_lookup(set_name, set_list);
	if (s == NULL)
		return 0;

	*set_id = nftnl_set_attr_get_u32(s, NFTNL_SET_ATTR_ID);
	return 1;
}
