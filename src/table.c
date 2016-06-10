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
#include <buffer.h>

struct nftnl_table {
	struct list_head head;

	const char	*name;
	uint32_t	family;
	uint32_t	table_flags;
	uint32_t	use;
	uint32_t	flags;
};

struct nftnl_table *nftnl_table_alloc(void)
{
	return calloc(1, sizeof(struct nftnl_table));
}
EXPORT_SYMBOL_ALIAS(nftnl_table_alloc, nft_table_alloc);

void nftnl_table_free(const struct nftnl_table *t)
{
	if (t->flags & (1 << NFTNL_TABLE_NAME))
		xfree(t->name);

	xfree(t);
}
EXPORT_SYMBOL_ALIAS(nftnl_table_free, nft_table_free);

bool nftnl_table_is_set(const struct nftnl_table *t, uint16_t attr)
{
	return t->flags & (1 << attr);
}
EXPORT_SYMBOL_ALIAS(nftnl_table_is_set, nft_table_attr_is_set);

void nftnl_table_unset(struct nftnl_table *t, uint16_t attr)
{
	if (!(t->flags & (1 << attr)))
		return;

	switch (attr) {
	case NFTNL_TABLE_NAME:
		xfree(t->name);
		break;
	case NFTNL_TABLE_FLAGS:
	case NFTNL_TABLE_FAMILY:
		break;
	case NFTNL_TABLE_USE:
		break;
	}
	t->flags &= ~(1 << attr);
}
EXPORT_SYMBOL_ALIAS(nftnl_table_unset, nft_table_attr_unset);

static uint32_t nftnl_table_validate[NFTNL_TABLE_MAX + 1] = {
	[NFTNL_TABLE_FLAGS]	= sizeof(uint32_t),
	[NFTNL_TABLE_FAMILY]	= sizeof(uint32_t),
};

int nftnl_table_set_data(struct nftnl_table *t, uint16_t attr,
			 const void *data, uint32_t data_len)
{
	nftnl_assert_attr_exists(attr, NFTNL_TABLE_MAX);
	nftnl_assert_validate(data, nftnl_table_validate, attr, data_len);

	switch (attr) {
	case NFTNL_TABLE_NAME:
		if (t->flags & (1 << NFTNL_TABLE_NAME))
			xfree(t->name);

		t->name = strdup(data);
		if (!t->name)
			return -1;
		break;
	case NFTNL_TABLE_FLAGS:
		t->table_flags = *((uint32_t *)data);
		break;
	case NFTNL_TABLE_FAMILY:
		t->family = *((uint32_t *)data);
		break;
	case NFTNL_TABLE_USE:
		t->use = *((uint32_t *)data);
		break;
	}
	t->flags |= (1 << attr);
	return 0;
}
EXPORT_SYMBOL_ALIAS(nftnl_table_set_data, nft_table_attr_set_data);

void nftnl_table_set(struct nftnl_table *t, uint16_t attr, const void *data)
{
	nftnl_table_set_data(t, attr, data, nftnl_table_validate[attr]);
}
EXPORT_SYMBOL_ALIAS(nftnl_table_set, nft_table_attr_set);

void nftnl_table_set_u32(struct nftnl_table *t, uint16_t attr, uint32_t val)
{
	nftnl_table_set_data(t, attr, &val, sizeof(uint32_t));
}
EXPORT_SYMBOL_ALIAS(nftnl_table_set_u32, nft_table_attr_set_u32);

void nftnl_table_set_u8(struct nftnl_table *t, uint16_t attr, uint8_t val)
{
	nftnl_table_set_data(t, attr, &val, sizeof(uint8_t));
}
EXPORT_SYMBOL_ALIAS(nftnl_table_set_u8, nft_table_attr_set_u8);

int nftnl_table_set_str(struct nftnl_table *t, uint16_t attr, const char *str)
{
	return nftnl_table_set_data(t, attr, str, 0);
}
EXPORT_SYMBOL_ALIAS(nftnl_table_set_str, nft_table_attr_set_str);

const void *nftnl_table_get_data(const struct nftnl_table *t, uint16_t attr,
				 uint32_t *data_len)
{
	if (!(t->flags & (1 << attr)))
		return NULL;

	switch(attr) {
	case NFTNL_TABLE_NAME:
		return t->name;
	case NFTNL_TABLE_FLAGS:
		*data_len = sizeof(uint32_t);
		return &t->table_flags;
	case NFTNL_TABLE_FAMILY:
		*data_len = sizeof(uint32_t);
		return &t->family;
	case NFTNL_TABLE_USE:
		*data_len = sizeof(uint32_t);
		return &t->use;
	}
	return NULL;
}
EXPORT_SYMBOL_ALIAS(nftnl_table_get_data, nft_table_attr_get_data);

const void *nftnl_table_get(const struct nftnl_table *t, uint16_t attr)
{
	uint32_t data_len;
	return nftnl_table_get_data(t, attr, &data_len);
}
EXPORT_SYMBOL_ALIAS(nftnl_table_get, nft_table_attr_get);

uint32_t nftnl_table_get_u32(const struct nftnl_table *t, uint16_t attr)
{
	const void *ret = nftnl_table_get(t, attr);
	return ret == NULL ? 0 : *((uint32_t *)ret);
}
EXPORT_SYMBOL_ALIAS(nftnl_table_get_u32, nft_table_attr_get_u32);

uint8_t nftnl_table_get_u8(const struct nftnl_table *t, uint16_t attr)
{
	const void *ret = nftnl_table_get(t, attr);
	return ret == NULL ? 0 : *((uint8_t *)ret);
}
EXPORT_SYMBOL_ALIAS(nftnl_table_get_u8, nft_table_attr_get_u8);

const char *nftnl_table_get_str(const struct nftnl_table *t, uint16_t attr)
{
	return nftnl_table_get(t, attr);
}
EXPORT_SYMBOL_ALIAS(nftnl_table_get_str, nft_table_attr_get_str);

void nftnl_table_nlmsg_build_payload(struct nlmsghdr *nlh, const struct nftnl_table *t)
{
	if (t->flags & (1 << NFTNL_TABLE_NAME))
		mnl_attr_put_strz(nlh, NFTA_TABLE_NAME, t->name);
	if (t->flags & (1 << NFTNL_TABLE_FLAGS))
		mnl_attr_put_u32(nlh, NFTA_TABLE_FLAGS, htonl(t->table_flags));
}
EXPORT_SYMBOL_ALIAS(nftnl_table_nlmsg_build_payload, nft_table_nlmsg_build_payload);

static int nftnl_table_parse_attr_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, NFTA_TABLE_MAX) < 0)
		return MNL_CB_OK;

	switch(type) {
	case NFTA_TABLE_NAME:
		if (mnl_attr_validate(attr, MNL_TYPE_STRING) < 0)
			abi_breakage();
		break;
	case NFTA_TABLE_FLAGS:
	case NFTA_TABLE_USE:
		if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0)
			abi_breakage();
		break;
	}

	tb[type] = attr;
	return MNL_CB_OK;
}

int nftnl_table_nlmsg_parse(const struct nlmsghdr *nlh, struct nftnl_table *t)
{
	struct nlattr *tb[NFTA_TABLE_MAX+1] = {};
	struct nfgenmsg *nfg = mnl_nlmsg_get_payload(nlh);

	if (mnl_attr_parse(nlh, sizeof(*nfg), nftnl_table_parse_attr_cb, tb) < 0)
		return -1;

	if (tb[NFTA_TABLE_NAME]) {
		if (t->flags & (1 << NFTNL_TABLE_NAME))
			xfree(t->name);
		t->name = strdup(mnl_attr_get_str(tb[NFTA_TABLE_NAME]));
		if (!t->name)
			return -1;
		t->flags |= (1 << NFTNL_TABLE_NAME);
	}
	if (tb[NFTA_TABLE_FLAGS]) {
		t->table_flags = ntohl(mnl_attr_get_u32(tb[NFTA_TABLE_FLAGS]));
		t->flags |= (1 << NFTNL_TABLE_FLAGS);
	}
	if (tb[NFTA_TABLE_USE]) {
		t->use = ntohl(mnl_attr_get_u32(tb[NFTA_TABLE_USE]));
		t->flags |= (1 << NFTNL_TABLE_USE);
	}

	t->family = nfg->nfgen_family;
	t->flags |= (1 << NFTNL_TABLE_FAMILY);

	return 0;
}
EXPORT_SYMBOL_ALIAS(nftnl_table_nlmsg_parse, nft_table_nlmsg_parse);

#ifdef XML_PARSING
int nftnl_mxml_table_parse(mxml_node_t *tree, struct nftnl_table *t,
			 struct nftnl_parse_err *err)
{
	const char *name;
	int family;
	uint32_t flags, use;

	name = nftnl_mxml_str_parse(tree, "name", MXML_DESCEND_FIRST,
				  NFTNL_XML_MAND, err);
	if (name != NULL)
		nftnl_table_set_str(t, NFTNL_TABLE_NAME, name);

	family = nftnl_mxml_family_parse(tree, "family", MXML_DESCEND_FIRST,
				       NFTNL_XML_MAND, err);
	if (family >= 0)
		nftnl_table_set_u32(t, NFTNL_TABLE_FAMILY, family);

	if (nftnl_mxml_num_parse(tree, "flags", MXML_DESCEND, BASE_DEC,
			       &flags, NFTNL_TYPE_U32, NFTNL_XML_MAND, err) == 0)
		nftnl_table_set_u32(t, NFTNL_TABLE_FLAGS, flags);

	if (nftnl_mxml_num_parse(tree, "use", MXML_DESCEND, BASE_DEC,
			       &use, NFTNL_TYPE_U32, NFTNL_XML_MAND, err) == 0)
		nftnl_table_set_u32(t, NFTNL_TABLE_USE, use);

	return 0;
}
#endif

static int nftnl_table_xml_parse(struct nftnl_table *t, const void *data,
			       struct nftnl_parse_err *err,
			       enum nftnl_parse_input input)
{
#ifdef XML_PARSING
	int ret;
	mxml_node_t *tree = nftnl_mxml_build_tree(data, "table", err, input);
	if (tree == NULL)
		return -1;

	ret = nftnl_mxml_table_parse(tree, t, err);
	mxmlDelete(tree);
	return ret;
#else
	errno = EOPNOTSUPP;
	return -1;
#endif
}

#ifdef JSON_PARSING
int nftnl_jansson_parse_table(struct nftnl_table *t, json_t *tree,
			    struct nftnl_parse_err *err)
{
	json_t *root;
	uint32_t flags, use;
	const char *str;
	int family;

	root = nftnl_jansson_get_node(tree, "table", err);
	if (root == NULL)
		return -1;

	str = nftnl_jansson_parse_str(root, "name", err);
	if (str != NULL)
		nftnl_table_set_str(t, NFTNL_TABLE_NAME, str);

	if (nftnl_jansson_parse_family(root, &family, err) == 0)
		nftnl_table_set_u32(t, NFTNL_TABLE_FAMILY, family);

	if (nftnl_jansson_parse_val(root, "flags", NFTNL_TYPE_U32, &flags,
				  err) == 0)
		nftnl_table_set_u32(t, NFTNL_TABLE_FLAGS, flags);

	if (nftnl_jansson_parse_val(root, "use", NFTNL_TYPE_U32, &use, err) == 0)
		nftnl_table_set_u32(t, NFTNL_TABLE_USE, use);

	return 0;
}
#endif

static int nftnl_table_json_parse(struct nftnl_table *t, const void *json,
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

	ret = nftnl_jansson_parse_table(t, tree, err);

	nftnl_jansson_free_root(tree);

	return ret;
#else
	errno = EOPNOTSUPP;
	return -1;
#endif
}

static int nftnl_table_do_parse(struct nftnl_table *t, enum nftnl_parse_type type,
			      const void *data, struct nftnl_parse_err *err,
			      enum nftnl_parse_input input)
{
	int ret;
	struct nftnl_parse_err perr;

	switch (type) {
	case NFTNL_PARSE_XML:
		ret = nftnl_table_xml_parse(t, data, &perr, input);
		break;
	case NFTNL_PARSE_JSON:
		ret = nftnl_table_json_parse(t, data, &perr, input);
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

int nftnl_table_parse(struct nftnl_table *t, enum nftnl_parse_type type,
		    const char *data, struct nftnl_parse_err *err)
{
	return nftnl_table_do_parse(t, type, data, err, NFTNL_PARSE_BUFFER);
}
EXPORT_SYMBOL_ALIAS(nftnl_table_parse, nft_table_parse);

int nftnl_table_parse_file(struct nftnl_table *t, enum nftnl_parse_type type,
			 FILE *fp, struct nftnl_parse_err *err)
{
	return nftnl_table_do_parse(t, type, fp, err, NFTNL_PARSE_FILE);
}
EXPORT_SYMBOL_ALIAS(nftnl_table_parse_file, nft_table_parse_file);

static int nftnl_table_export(char *buf, size_t size,
			      const struct nftnl_table *t, int type)
{
	NFTNL_BUF_INIT(b, buf, size);

	nftnl_buf_open(&b, type, TABLE);
	if (t->flags & (1 << NFTNL_TABLE_NAME))
		nftnl_buf_str(&b, type, t->name, NAME);
	if (t->flags & (1 << NFTNL_TABLE_FAMILY))
		nftnl_buf_str(&b, type, nftnl_family2str(t->family), FAMILY);
	if (t->flags & (1 << NFTNL_TABLE_FLAGS))
		nftnl_buf_u32(&b, type, t->table_flags, FLAGS);
	if (t->flags & (1 << NFTNL_TABLE_USE))
		nftnl_buf_u32(&b, type, t->use, USE);

	nftnl_buf_close(&b, type, TABLE);

	return nftnl_buf_done(&b);
}

static int nftnl_table_snprintf_default(char *buf, size_t size,
					const struct nftnl_table *t)
{
	return snprintf(buf, size, "table %s %s flags %x use %d",
			t->name, nftnl_family2str(t->family),
			t->table_flags, t->use);
}

static int nftnl_table_cmd_snprintf(char *buf, size_t size,
				    const struct nftnl_table *t, uint32_t cmd,
				    uint32_t type, uint32_t flags)
{
	int ret, len = size, offset = 0;

	ret = nftnl_cmd_header_snprintf(buf + offset, len, cmd, type, flags);
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	switch (type) {
	case NFTNL_OUTPUT_DEFAULT:
		ret = nftnl_table_snprintf_default(buf+offset, len, t);
		break;
	case NFTNL_OUTPUT_XML:
	case NFTNL_OUTPUT_JSON:
		ret = nftnl_table_export(buf+offset, len, t, type);
		break;
	default:
		return -1;
	}
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	ret = nftnl_cmd_footer_snprintf(buf + offset, len, cmd, type, flags);
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	return offset;
}

int nftnl_table_snprintf(char *buf, size_t size, const struct nftnl_table *t,
			 uint32_t type, uint32_t flags)
{
	return nftnl_table_cmd_snprintf(buf, size, t, nftnl_flag2cmd(flags), type,
				      flags);
}
EXPORT_SYMBOL_ALIAS(nftnl_table_snprintf, nft_table_snprintf);

static int nftnl_table_do_snprintf(char *buf, size_t size, const void *t,
				   uint32_t cmd, uint32_t type, uint32_t flags)
{
	return nftnl_table_snprintf(buf, size, t, type, flags);
}

int nftnl_table_fprintf(FILE *fp, const struct nftnl_table *t, uint32_t type,
			uint32_t flags)
{
	return nftnl_fprintf(fp, t, NFTNL_CMD_UNSPEC, type, flags,
			   nftnl_table_do_snprintf);
}
EXPORT_SYMBOL_ALIAS(nftnl_table_fprintf, nft_table_fprintf);

struct nftnl_table_list {
	struct list_head list;
};

struct nftnl_table_list *nftnl_table_list_alloc(void)
{
	struct nftnl_table_list *list;

	list = calloc(1, sizeof(struct nftnl_table_list));
	if (list == NULL)
		return NULL;

	INIT_LIST_HEAD(&list->list);

	return list;
}
EXPORT_SYMBOL_ALIAS(nftnl_table_list_alloc, nft_table_list_alloc);

void nftnl_table_list_free(struct nftnl_table_list *list)
{
	struct nftnl_table *r, *tmp;

	list_for_each_entry_safe(r, tmp, &list->list, head) {
		list_del(&r->head);
		nftnl_table_free(r);
	}
	xfree(list);
}
EXPORT_SYMBOL_ALIAS(nftnl_table_list_free, nft_table_list_free);

int nftnl_table_list_is_empty(const struct nftnl_table_list *list)
{
	return list_empty(&list->list);
}
EXPORT_SYMBOL_ALIAS(nftnl_table_list_is_empty, nft_table_list_is_empty);

void nftnl_table_list_add(struct nftnl_table *r, struct nftnl_table_list *list)
{
	list_add(&r->head, &list->list);
}
EXPORT_SYMBOL_ALIAS(nftnl_table_list_add, nft_table_list_add);

void nftnl_table_list_add_tail(struct nftnl_table *r, struct nftnl_table_list *list)
{
	list_add_tail(&r->head, &list->list);
}
EXPORT_SYMBOL_ALIAS(nftnl_table_list_add_tail, nft_table_list_add_tail);

void nftnl_table_list_del(struct nftnl_table *t)
{
	list_del(&t->head);
}
EXPORT_SYMBOL_ALIAS(nftnl_table_list_del, nft_table_list_del);

int nftnl_table_list_foreach(struct nftnl_table_list *table_list,
			   int (*cb)(struct nftnl_table *t, void *data),
			   void *data)
{
	struct nftnl_table *cur, *tmp;
	int ret;

	list_for_each_entry_safe(cur, tmp, &table_list->list, head) {
		ret = cb(cur, data);
		if (ret < 0)
			return ret;
	}
	return 0;
}
EXPORT_SYMBOL_ALIAS(nftnl_table_list_foreach, nft_table_list_foreach);

struct nftnl_table_list_iter {
	struct nftnl_table_list	*list;
	struct nftnl_table	*cur;
};

struct nftnl_table_list_iter *nftnl_table_list_iter_create(struct nftnl_table_list *l)
{
	struct nftnl_table_list_iter *iter;

	iter = calloc(1, sizeof(struct nftnl_table_list_iter));
	if (iter == NULL)
		return NULL;

	iter->list = l;
	if (nftnl_table_list_is_empty(l))
		iter->cur = NULL;
	else
		iter->cur = list_entry(l->list.next, struct nftnl_table, head);

	return iter;
}
EXPORT_SYMBOL_ALIAS(nftnl_table_list_iter_create, nft_table_list_iter_create);

struct nftnl_table *nftnl_table_list_iter_next(struct nftnl_table_list_iter *iter)
{
	struct nftnl_table *r = iter->cur;

	if (r == NULL)
		return NULL;

	/* get next table, if any */
	iter->cur = list_entry(iter->cur->head.next, struct nftnl_table, head);
	if (&iter->cur->head == iter->list->list.next)
		return NULL;

	return r;
}
EXPORT_SYMBOL_ALIAS(nftnl_table_list_iter_next, nft_table_list_iter_next);

void nftnl_table_list_iter_destroy(const struct nftnl_table_list_iter *iter)
{
	xfree(iter);
}
EXPORT_SYMBOL_ALIAS(nftnl_table_list_iter_destroy, nft_table_list_iter_destroy);
