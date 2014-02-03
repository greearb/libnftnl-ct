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
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <errno.h>

#include <libmnl/libmnl.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nf_tables.h>

#include <libnftnl/table.h>

struct nft_table {
	struct list_head head;

	const char	*name;
	uint8_t		family;
	uint32_t	table_flags;
	uint32_t	use;
	uint32_t	flags;
};

struct nft_table *nft_table_alloc(void)
{
	return calloc(1, sizeof(struct nft_table));
}
EXPORT_SYMBOL(nft_table_alloc);

void nft_table_free(struct nft_table *t)
{
	if (t->flags & (1 << NFT_TABLE_ATTR_NAME))
		xfree(t->name);

	xfree(t);
}
EXPORT_SYMBOL(nft_table_free);

bool nft_table_attr_is_set(const struct nft_table *t, uint16_t attr)
{
	return t->flags & (1 << attr);
}
EXPORT_SYMBOL(nft_table_attr_is_set);

void nft_table_attr_unset(struct nft_table *t, uint16_t attr)
{
	if (!(t->flags & (1 << attr)))
		return;

	switch (attr) {
	case NFT_TABLE_ATTR_NAME:
		if (t->name) {
			xfree(t->name);
			t->name = NULL;
		}
		break;
	case NFT_TABLE_ATTR_FLAGS:
	case NFT_TABLE_ATTR_FAMILY:
		break;
	case NFT_TABLE_ATTR_USE:
		/* Cannot be unset, ignoring it */
		return;
	}
	t->flags &= ~(1 << attr);
}
EXPORT_SYMBOL(nft_table_attr_unset);

void nft_table_attr_set(struct nft_table *t, uint16_t attr, const void *data)
{
	switch (attr) {
	case NFT_TABLE_ATTR_NAME:
		if (t->name)
			xfree(t->name);

		t->name = strdup(data);
		t->flags |= (1 << NFT_TABLE_ATTR_NAME);
		break;
	case NFT_TABLE_ATTR_FLAGS:
		t->table_flags = *((uint32_t *)data);
		t->flags |= (1 << NFT_TABLE_ATTR_FLAGS);
		break;
	case NFT_TABLE_ATTR_FAMILY:
		t->family = *((uint8_t *)data);
		t->flags |= (1 << NFT_TABLE_ATTR_FAMILY);
		break;
	case NFT_TABLE_ATTR_USE:
		/* Cannot be unset, ignoring it */
		break;
	}
}
EXPORT_SYMBOL(nft_table_attr_set);

void nft_table_attr_set_u32(struct nft_table *t, uint16_t attr, uint32_t val)
{
	nft_table_attr_set(t, attr, &val);
}
EXPORT_SYMBOL(nft_table_attr_set_u32);

void nft_table_attr_set_u8(struct nft_table *t, uint16_t attr, uint8_t val)
{
	nft_table_attr_set(t, attr, &val);
}
EXPORT_SYMBOL(nft_table_attr_set_u8);

void nft_table_attr_set_str(struct nft_table *t, uint16_t attr, const char *str)
{
	nft_table_attr_set(t, attr, str);
}
EXPORT_SYMBOL(nft_table_attr_set_str);

const void *nft_table_attr_get(struct nft_table *t, uint16_t attr)
{
	if (!(t->flags & (1 << attr)))
		return NULL;

	switch(attr) {
	case NFT_TABLE_ATTR_NAME:
		return t->name;
	case NFT_TABLE_ATTR_FLAGS:
		return &t->table_flags;
	case NFT_TABLE_ATTR_FAMILY:
		return &t->family;
	case NFT_TABLE_ATTR_USE:
		return &t->use;
	}
	return NULL;
}
EXPORT_SYMBOL(nft_table_attr_get);

uint32_t nft_table_attr_get_u32(struct nft_table *t, uint16_t attr)
{
	const void *ret = nft_table_attr_get(t, attr);
	return ret == NULL ? 0 : *((uint32_t *)ret);
}
EXPORT_SYMBOL(nft_table_attr_get_u32);

uint8_t nft_table_attr_get_u8(struct nft_table *t, uint16_t attr)
{
	const void *ret = nft_table_attr_get(t, attr);
	return ret == NULL ? 0 : *((uint8_t *)ret);
}
EXPORT_SYMBOL(nft_table_attr_get_u8);

const char *nft_table_attr_get_str(struct nft_table *t, uint16_t attr)
{
	return nft_table_attr_get(t, attr);
}
EXPORT_SYMBOL(nft_table_attr_get_str);

void nft_table_nlmsg_build_payload(struct nlmsghdr *nlh, const struct nft_table *t)
{
	if (t->flags & (1 << NFT_TABLE_ATTR_NAME))
		mnl_attr_put_strz(nlh, NFTA_TABLE_NAME, t->name);
	if (t->flags & (1 << NFT_TABLE_ATTR_FLAGS))
		mnl_attr_put_u32(nlh, NFTA_TABLE_FLAGS, htonl(t->table_flags));
}
EXPORT_SYMBOL(nft_table_nlmsg_build_payload);

static int nft_table_parse_attr_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, NFTA_TABLE_MAX) < 0)
		return MNL_CB_OK;

	switch(type) {
	case NFTA_TABLE_NAME:
		if (mnl_attr_validate(attr, MNL_TYPE_STRING) < 0) {
			perror("mnl_attr_validate");
			return MNL_CB_ERROR;
		}
		break;
	case NFTA_TABLE_FLAGS:
		if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0) {
			perror("mnl_attr_validate");
			return MNL_CB_ERROR;
		}
		break;
	case NFTA_TABLE_USE:
		if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0) {
			perror("mnl_attr_validate");
			return MNL_CB_ERROR;
		}
		break;
	}

	tb[type] = attr;
	return MNL_CB_OK;
}

int nft_table_nlmsg_parse(const struct nlmsghdr *nlh, struct nft_table *t)
{
	struct nlattr *tb[NFTA_TABLE_MAX+1] = {};
	struct nfgenmsg *nfg = mnl_nlmsg_get_payload(nlh);

	mnl_attr_parse(nlh, sizeof(*nfg), nft_table_parse_attr_cb, tb);
	if (tb[NFTA_TABLE_NAME]) {
		t->name = strdup(mnl_attr_get_str(tb[NFTA_TABLE_NAME]));
		t->flags |= (1 << NFT_TABLE_ATTR_NAME);
	}
	if (tb[NFTA_TABLE_FLAGS]) {
		t->table_flags = ntohl(mnl_attr_get_u32(tb[NFTA_TABLE_FLAGS]));
		t->flags |= (1 << NFT_TABLE_ATTR_FLAGS);
	}
	if (tb[NFTA_TABLE_USE]) {
		t->use = ntohl(mnl_attr_get_u32(tb[NFTA_TABLE_USE]));
		t->flags |= (1 << NFT_TABLE_ATTR_USE);
	}

	t->family = nfg->nfgen_family;
	t->flags |= (1 << NFT_TABLE_ATTR_FAMILY);

	return 0;
}
EXPORT_SYMBOL(nft_table_nlmsg_parse);

#ifdef XML_PARSING
int nft_mxml_table_parse(mxml_node_t *tree, struct nft_table *t,
			 struct nft_parse_err *err)
{
	const char *name;
	int family;

	name = nft_mxml_str_parse(tree, "name", MXML_DESCEND_FIRST,
				  NFT_XML_MAND, err);
	if (name == NULL)
		return -1;

	if (t->name)
		xfree(t->name);

	t->name = strdup(name);
	t->flags |= (1 << NFT_TABLE_ATTR_NAME);

	family = nft_mxml_family_parse(tree, "family", MXML_DESCEND_FIRST,
				       NFT_XML_MAND, err);
	if (family < 0)
		return -1;

	t->family = family;
	t->flags |= (1 << NFT_TABLE_ATTR_FAMILY);

	if (nft_mxml_num_parse(tree, "flags", MXML_DESCEND, BASE_DEC,
			       &t->table_flags, NFT_TYPE_U32,
			       NFT_XML_MAND, err) != 0)
		return -1;

	t->flags |= (1 << NFT_TABLE_ATTR_FLAGS);

	return 0;
}
#endif

static int nft_table_xml_parse(struct nft_table *t, const void *data,
			       struct nft_parse_err *err,
			       enum nft_parse_input input)
{
#ifdef XML_PARSING
	int ret;
	mxml_node_t *tree = nft_mxml_build_tree(data, "table", err, input);
	if (tree == NULL)
		return -1;

	ret = nft_mxml_table_parse(tree, t, err);
	mxmlDelete(tree);
	return ret;
#else
	errno = EOPNOTSUPP;
	return -1;
#endif
}

#ifdef JSON_PARSING
int nft_jansson_parse_table(struct nft_table *t, json_t *tree,
			    struct nft_parse_err *err)
{
	json_t *root;
	uint32_t flags;
	const char *str;
	int family;

	root = nft_jansson_get_node(tree, "table", err);
	if (root == NULL)
		return -1;

	str = nft_jansson_parse_str(root, "name", err);
	if (str == NULL)
		goto err;

	nft_table_attr_set_str(t, NFT_TABLE_ATTR_NAME, str);

	if (nft_jansson_parse_family(root, &family, err) != 0)
		goto err;

	nft_table_attr_set_u32(t, NFT_TABLE_ATTR_FAMILY, family);

	if (nft_jansson_parse_val(root, "flags", NFT_TYPE_U32, &flags, err) < 0)
		goto err;

	nft_table_attr_set_u32(t, NFT_TABLE_ATTR_FLAGS, flags);

	nft_jansson_free_root(tree);
	return 0;
err:
	nft_jansson_free_root(tree);
	return -1;
}
#endif

static int nft_table_json_parse(struct nft_table *t, const void *json,
				struct nft_parse_err *err,
				enum nft_parse_input input)
{
#ifdef JSON_PARSING
	json_t *tree;
	json_error_t error;

	tree = nft_jansson_create_root(json, &error, err, input);
	if (tree == NULL)
		return -1;

	return nft_jansson_parse_table(t, tree, err);
#else
	errno = EOPNOTSUPP;
	return -1;
#endif
}

static int nft_table_do_parse(struct nft_table *t, enum nft_parse_type type,
			      const void *data, struct nft_parse_err *err,
			      enum nft_parse_input input)
{
	int ret;
	struct nft_parse_err perr;

	switch (type) {
	case NFT_PARSE_XML:
		ret = nft_table_xml_parse(t, data, &perr, input);
		break;
	case NFT_PARSE_JSON:
		ret = nft_table_json_parse(t, data, &perr, input);
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

int nft_table_parse(struct nft_table *t, enum nft_parse_type type,
		    const char *data, struct nft_parse_err *err)
{
	return nft_table_do_parse(t, type, data, err, NFT_PARSE_BUFFER);
}
EXPORT_SYMBOL(nft_table_parse);

int nft_table_parse_file(struct nft_table *t, enum nft_parse_type type,
			 FILE *fp, struct nft_parse_err *err)
{
	return nft_table_do_parse(t, type, fp, err, NFT_PARSE_FILE);
}
EXPORT_SYMBOL(nft_table_parse_file);

static int nft_table_snprintf_json(char *buf, size_t size, struct nft_table *t)
{
	return snprintf(buf, size,
			"{\"table\":{"
			"\"name\":\"%s\","
			"\"family\":\"%s\","
			"\"flags\":%d,"
			"\"use\":%d"
			"}"
			"}" ,
			t->name, nft_family2str(t->family),
			t->table_flags, t->use);
}

static int nft_table_snprintf_xml(char *buf, size_t size, struct nft_table *t)
{
	return snprintf(buf, size, "<table><name>%s</name><family>%s</family>"
			"<flags>%d</flags><use>%d</use></table>",
			t->name, nft_family2str(t->family),
			t->table_flags, t->use);
}

static int nft_table_snprintf_default(char *buf, size_t size, struct nft_table *t)
{
	return snprintf(buf, size, "table %s %s flags %x use %d",
			t->name, nft_family2str(t->family),
			t->table_flags, t->use);
}

int nft_table_snprintf(char *buf, size_t size, struct nft_table *t,
		       uint32_t type, uint32_t flags)
{
	switch(type) {
	case NFT_OUTPUT_DEFAULT:
		return nft_table_snprintf_default(buf, size, t);
	case NFT_OUTPUT_XML:
		return nft_table_snprintf_xml(buf, size, t);
	case NFT_OUTPUT_JSON:
		return nft_table_snprintf_json(buf, size, t);
	default:
		break;
	}
	return -1;
}
EXPORT_SYMBOL(nft_table_snprintf);

static inline int nft_table_do_snprintf(char *buf, size_t size, void *t,
					uint32_t type, uint32_t flags)
{
	return nft_table_snprintf(buf, size, t, type, flags);
}

int nft_table_fprintf(FILE *fp, struct nft_table *t, uint32_t type,
		      uint32_t flags)
{
	return nft_fprintf(fp, t, type, flags, nft_table_do_snprintf);
}
EXPORT_SYMBOL(nft_table_fprintf);

struct nft_table_list {
	struct list_head list;
};

struct nft_table_list *nft_table_list_alloc(void)
{
	struct nft_table_list *list;

	list = calloc(1, sizeof(struct nft_table_list));
	if (list == NULL)
		return NULL;

	INIT_LIST_HEAD(&list->list);

	return list;
}
EXPORT_SYMBOL(nft_table_list_alloc);

void nft_table_list_free(struct nft_table_list *list)
{
	struct nft_table *r, *tmp;

	list_for_each_entry_safe(r, tmp, &list->list, head) {
		list_del(&r->head);
		nft_table_free(r);
	}
	xfree(list);
}
EXPORT_SYMBOL(nft_table_list_free);

int nft_table_list_is_empty(struct nft_table_list *list)
{
	return list_empty(&list->list);
}
EXPORT_SYMBOL(nft_table_list_is_empty);

void nft_table_list_add(struct nft_table *r, struct nft_table_list *list)
{
	list_add(&r->head, &list->list);
}
EXPORT_SYMBOL(nft_table_list_add);

void nft_table_list_add_tail(struct nft_table *r, struct nft_table_list *list)
{
	list_add_tail(&r->head, &list->list);
}
EXPORT_SYMBOL(nft_table_list_add_tail);

void nft_table_list_del(struct nft_table *t)
{
	list_del(&t->head);
}
EXPORT_SYMBOL(nft_table_list_del);

int nft_table_list_foreach(struct nft_table_list *table_list,
			   int (*cb)(struct nft_table *t, void *data),
			   void *data)
{
	struct nft_table *cur, *tmp;
	int ret;

	list_for_each_entry_safe(cur, tmp, &table_list->list, head) {
		ret = cb(cur, data);
		if (ret < 0)
			return ret;
	}
	return 0;
}
EXPORT_SYMBOL(nft_table_list_foreach);

struct nft_table_list_iter {
	struct nft_table_list	*list;
	struct nft_table	*cur;
};

struct nft_table_list_iter *nft_table_list_iter_create(struct nft_table_list *l)
{
	struct nft_table_list_iter *iter;

	iter = calloc(1, sizeof(struct nft_table_list_iter));
	if (iter == NULL)
		return NULL;

	iter->list = l;
	iter->cur = list_entry(l->list.next, struct nft_table, head);

	return iter;
}
EXPORT_SYMBOL(nft_table_list_iter_create);

struct nft_table *nft_table_list_iter_next(struct nft_table_list_iter *iter)
{
	struct nft_table *r = iter->cur;

	/* get next table, if any */
	iter->cur = list_entry(iter->cur->head.next, struct nft_table, head);
	if (&iter->cur->head == iter->list->list.next)
		return NULL;

	return r;
}
EXPORT_SYMBOL(nft_table_list_iter_next);

void nft_table_list_iter_destroy(struct nft_table_list_iter *iter)
{
	xfree(iter);
}
EXPORT_SYMBOL(nft_table_list_iter_destroy);
