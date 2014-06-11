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

#include <libmnl/libmnl.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nf_tables.h>

#include <libnftnl/set.h>
#include <libnftnl/rule.h>

#include "linux_list.h"
#include "expr/data_reg.h"

struct nft_set_elem *nft_set_elem_alloc(void)
{
	struct nft_set_elem *s;

	s = calloc(1, sizeof(struct nft_set_elem));
	if (s == NULL)
		return NULL;

	return s;
}
EXPORT_SYMBOL(nft_set_elem_alloc);

void nft_set_elem_free(struct nft_set_elem *s)
{
	if (s->flags & (1 << NFT_SET_ELEM_ATTR_CHAIN)) {
		if (s->data.chain) {
			xfree(s->data.chain);
			s->data.chain = NULL;
		}
	}
	xfree(s);
}
EXPORT_SYMBOL(nft_set_elem_free);

bool nft_set_elem_attr_is_set(const struct nft_set_elem *s, uint16_t attr)
{
	return s->flags & (1 << attr);
}
EXPORT_SYMBOL(nft_set_elem_attr_is_set);

void nft_set_elem_attr_unset(struct nft_set_elem *s, uint16_t attr)
{
	switch (attr) {
	case NFT_SET_ELEM_ATTR_CHAIN:
		if (s->flags & (1 << NFT_SET_ELEM_ATTR_CHAIN)) {
			if (s->data.chain) {
				xfree(s->data.chain);
				s->data.chain = NULL;
			}
		}
		break;
	case NFT_SET_ELEM_ATTR_FLAGS:
	case NFT_SET_ELEM_ATTR_KEY:	/* NFTA_SET_ELEM_KEY */
	case NFT_SET_ELEM_ATTR_VERDICT:	/* NFTA_SET_ELEM_DATA */
	case NFT_SET_ELEM_ATTR_DATA:	/* NFTA_SET_ELEM_DATA */
		break;
	default:
		return;
	}

	s->flags &= ~(1 << attr);
}
EXPORT_SYMBOL(nft_set_elem_attr_unset);

void nft_set_elem_attr_set(struct nft_set_elem *s, uint16_t attr,
			   const void *data, uint32_t data_len)
{
	switch(attr) {
	case NFT_SET_ELEM_ATTR_FLAGS:
		s->set_elem_flags = *((uint32_t *)data);
		break;
	case NFT_SET_ELEM_ATTR_KEY:	/* NFTA_SET_ELEM_KEY */
		memcpy(&s->key.val, data, data_len);
		s->key.len = data_len;
		break;
	case NFT_SET_ELEM_ATTR_VERDICT:	/* NFTA_SET_ELEM_DATA */
		s->data.verdict = *((uint32_t *)data);
		break;
	case NFT_SET_ELEM_ATTR_CHAIN:	/* NFTA_SET_ELEM_DATA */
		if (s->data.chain)
			xfree(s->data.chain);

		s->data.chain = strdup(data);
		break;
	case NFT_SET_ELEM_ATTR_DATA:	/* NFTA_SET_ELEM_DATA */
		memcpy(s->data.val, data, data_len);
		s->data.len = data_len;
		break;
	default:
		return;
	}
	s->flags |= (1 << attr);
}
EXPORT_SYMBOL(nft_set_elem_attr_set);

void nft_set_elem_attr_set_u32(struct nft_set_elem *s, uint16_t attr, uint32_t val)
{
	nft_set_elem_attr_set(s, attr, &val, sizeof(uint32_t));
}
EXPORT_SYMBOL(nft_set_elem_attr_set_u32);

void nft_set_elem_attr_set_str(struct nft_set_elem *s, uint16_t attr, const char *str)
{
	nft_set_elem_attr_set(s, attr, str, strlen(str));
}
EXPORT_SYMBOL(nft_set_elem_attr_set_str);

const void *nft_set_elem_attr_get(struct nft_set_elem *s, uint16_t attr, uint32_t *data_len)
{
	if (!(s->flags & (1 << attr)))
		return NULL;

	switch(attr) {
	case NFT_SET_ELEM_ATTR_FLAGS:
		return &s->set_elem_flags;
	case NFT_SET_ELEM_ATTR_KEY:	/* NFTA_SET_ELEM_KEY */
		*data_len = s->key.len;
		return &s->key.val;
	case NFT_SET_ELEM_ATTR_VERDICT:	/* NFTA_SET_ELEM_DATA */
		return &s->data.verdict;
	case NFT_SET_ELEM_ATTR_CHAIN:	/* NFTA_SET_ELEM_DATA */
		return s->data.chain;
	case NFT_SET_ELEM_ATTR_DATA:	/* NFTA_SET_ELEM_DATA */
		*data_len = s->data.len;
		return &s->data.val;
	}
	return NULL;
}
EXPORT_SYMBOL(nft_set_elem_attr_get);

const char *nft_set_elem_attr_get_str(struct nft_set_elem *s, uint16_t attr)
{
	uint32_t size;

	return nft_set_elem_attr_get(s, attr, &size);
}
EXPORT_SYMBOL(nft_set_elem_attr_get_str);

uint32_t nft_set_elem_attr_get_u32(struct nft_set_elem *s, uint16_t attr)
{
	uint32_t size;
	uint32_t val = *((uint32_t *)nft_set_elem_attr_get(s, attr, &size));
	return val;
}
EXPORT_SYMBOL(nft_set_elem_attr_get_u32);

void nft_set_elem_nlmsg_build_payload(struct nlmsghdr *nlh,
				      struct nft_set_elem *e)
{
	if (e->flags & (1 << NFT_SET_ELEM_ATTR_FLAGS))
		mnl_attr_put_u32(nlh, NFTA_SET_ELEM_FLAGS, htonl(e->set_elem_flags));
	if (e->flags & (1 << NFT_SET_ELEM_ATTR_KEY)) {
		struct nlattr *nest1;

		nest1 = mnl_attr_nest_start(nlh, NFTA_SET_ELEM_KEY);
		mnl_attr_put(nlh, NFTA_DATA_VALUE, e->key.len, e->key.val);
		mnl_attr_nest_end(nlh, nest1);
	}
	if (e->flags & (1 << NFT_SET_ELEM_ATTR_VERDICT)) {
		struct nlattr *nest1, *nest2;

		nest1 = mnl_attr_nest_start(nlh, NFTA_SET_ELEM_DATA);
		nest2 = mnl_attr_nest_start(nlh, NFTA_DATA_VERDICT);
		mnl_attr_put_u32(nlh, NFTA_VERDICT_CODE, htonl(e->data.verdict));
		if (e->flags & (1 << NFT_SET_ELEM_ATTR_CHAIN))
			mnl_attr_put_strz(nlh, NFTA_VERDICT_CHAIN, e->data.chain);

		mnl_attr_nest_end(nlh, nest1);
		mnl_attr_nest_end(nlh, nest2);
	}
	if (e->flags & (1 << NFT_SET_ELEM_ATTR_DATA)) {
		struct nlattr *nest1;

		nest1 = mnl_attr_nest_start(nlh, NFTA_SET_ELEM_DATA);
		mnl_attr_put(nlh, NFTA_DATA_VALUE, e->data.len, e->data.val);
		mnl_attr_nest_end(nlh, nest1);
	}
}

void nft_set_elems_nlmsg_build_payload(struct nlmsghdr *nlh, struct nft_set *s)
{
	struct nft_set_elem *elem;
	struct nlattr *nest1;
	int i = 0;

	if (s->flags & (1 << NFT_SET_ATTR_NAME))
		mnl_attr_put_strz(nlh, NFTA_SET_ELEM_LIST_SET, s->name);
	if (s->flags & (1 << NFT_SET_ATTR_ID))
		mnl_attr_put_u32(nlh, NFTA_SET_ELEM_LIST_SET_ID, htonl(s->id));
	if (s->flags & (1 << NFT_SET_ATTR_TABLE))
		mnl_attr_put_strz(nlh, NFTA_SET_ELEM_LIST_TABLE, s->table);

	nest1 = mnl_attr_nest_start(nlh, NFTA_SET_ELEM_LIST_ELEMENTS);
	list_for_each_entry(elem, &s->element_list, head) {
		struct nlattr *nest2;

		nest2 = mnl_attr_nest_start(nlh, ++i);
		nft_set_elem_nlmsg_build_payload(nlh, elem);
		mnl_attr_nest_end(nlh, nest2);
	}
	mnl_attr_nest_end(nlh, nest1);
}
EXPORT_SYMBOL(nft_set_elems_nlmsg_build_payload);

static int nft_set_elem_parse_attr_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, NFTA_SET_MAX) < 0)
		return MNL_CB_OK;

	switch(type) {
	case NFTA_SET_ELEM_FLAGS:
		if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0) {
			perror("mnl_attr_validate");
			return MNL_CB_ERROR;
		}
		break;
	case NFTA_SET_ELEM_KEY:
	case NFTA_SET_ELEM_DATA:
		if (mnl_attr_validate(attr, MNL_TYPE_NESTED) < 0) {
			perror("mnl_attr_validate");
			return MNL_CB_ERROR;
		}
		break;
	}

	tb[type] = attr;
	return MNL_CB_OK;
}

static int nft_set_elems_parse2(struct nft_set *s, const struct nlattr *nest)
{
	struct nlattr *tb[NFTA_SET_ELEM_MAX+1] = {};
	struct nft_set_elem *e;
	int ret = 0, type;

	e = nft_set_elem_alloc();
	if (e == NULL)
		return -1;

	if (mnl_attr_parse_nested(nest, nft_set_elem_parse_attr_cb, tb) < 0) {
		nft_set_elem_free(e);
		return -1;
	}

	if (tb[NFTA_SET_ELEM_FLAGS]) {
		e->set_elem_flags =
			ntohl(mnl_attr_get_u32(tb[NFTA_SET_ELEM_FLAGS]));
		e->flags |= (1 << NFT_SET_ELEM_ATTR_FLAGS);
	}
        if (tb[NFTA_SET_ELEM_KEY]) {
		ret = nft_parse_data(&e->key, tb[NFTA_SET_ELEM_KEY], &type);
		e->flags |= (1 << NFT_SET_ELEM_ATTR_KEY);
        }
        if (tb[NFTA_SET_ELEM_DATA]) {
		ret = nft_parse_data(&e->data, tb[NFTA_SET_ELEM_DATA], &type);
		switch(type) {
		case DATA_VERDICT:
			e->flags |= (1 << NFT_SET_ELEM_ATTR_VERDICT);
			break;
		case DATA_CHAIN:
			e->flags |= (1 << NFT_SET_ELEM_ATTR_VERDICT) |
				    (1 << NFT_SET_ELEM_ATTR_CHAIN);
			break;
		case DATA_VALUE:
			e->flags |= (1 << NFT_SET_ELEM_ATTR_DATA);
			break;
		}
        }
	if (ret < 0) {
		xfree(e);
		return -1;
	}

	/* Add this new element to this set */
	list_add_tail(&e->head, &s->element_list);

	return ret;
}

static int
nft_set_elem_list_parse_attr_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, NFTA_SET_ELEM_LIST_MAX) < 0)
		return MNL_CB_OK;

	switch(type) {
	case NFTA_SET_ELEM_LIST_TABLE:
	case NFTA_SET_ELEM_LIST_SET:
		if (mnl_attr_validate(attr, MNL_TYPE_STRING) < 0) {
			perror("mnl_attr_validate");
			return MNL_CB_ERROR;
		}
		break;
	case NFTA_SET_ELEM_LIST_ELEMENTS:
		if (mnl_attr_validate(attr, MNL_TYPE_NESTED) < 0) {
			perror("mnl_attr_validate");
			return MNL_CB_ERROR;
		}
		break;
	}

	tb[type] = attr;
	return MNL_CB_OK;
}

static int nft_set_elems_parse(struct nft_set *s, const struct nlattr *nest)
{
	struct nlattr *attr;
	int ret = 0;

	mnl_attr_for_each_nested(attr, nest) {
		if (mnl_attr_get_type(attr) != NFTA_LIST_ELEM)
			return -1;

		ret = nft_set_elems_parse2(s, attr);
	}
	return ret;
}

int nft_set_elems_nlmsg_parse(const struct nlmsghdr *nlh, struct nft_set *s)
{
	struct nlattr *tb[NFTA_SET_ELEM_LIST_MAX+1] = {};
	struct nfgenmsg *nfg = mnl_nlmsg_get_payload(nlh);
	int ret = 0;

	if (mnl_attr_parse(nlh, sizeof(*nfg),
			   nft_set_elem_list_parse_attr_cb, tb) < 0)
		return -1;

	if (tb[NFTA_SET_ELEM_LIST_TABLE]) {
		s->table =
			strdup(mnl_attr_get_str(tb[NFTA_SET_ELEM_LIST_TABLE]));
		s->flags |= (1 << NFT_SET_ATTR_TABLE);
	}
	if (tb[NFTA_SET_ELEM_LIST_SET]) {
		s->name =
			strdup(mnl_attr_get_str(tb[NFTA_SET_ELEM_LIST_SET]));
		s->flags |= (1 << NFT_SET_ATTR_NAME);
	}
	if (tb[NFTA_SET_ELEM_LIST_SET_ID]) {
		s->id = ntohl(mnl_attr_get_u32(tb[NFTA_SET_ELEM_LIST_SET_ID]));
		s->flags |= (1 << NFT_SET_ATTR_ID);
	}
        if (tb[NFTA_SET_ELEM_LIST_ELEMENTS])
	 	ret = nft_set_elems_parse(s, tb[NFTA_SET_ELEM_LIST_ELEMENTS]);

	s->family = nfg->nfgen_family;
	s->flags |= (1 << NFT_SET_ATTR_FAMILY);

	return ret;
}
EXPORT_SYMBOL(nft_set_elems_nlmsg_parse);

#ifdef XML_PARSING
int nft_mxml_set_elem_parse(mxml_node_t *tree, struct nft_set_elem *e,
			    struct nft_parse_err *err)
{
	int set_elem_data;
	uint32_t set_elem_flags;

	if (nft_mxml_num_parse(tree, "flags", MXML_DESCEND_FIRST, BASE_DEC,
			       &set_elem_flags, NFT_TYPE_U32, NFT_XML_MAND,
			       err) == 0)
		nft_set_elem_attr_set_u32(e, NFT_SET_ELEM_ATTR_FLAGS, set_elem_flags);

	if (nft_mxml_data_reg_parse(tree, "key", &e->key,
				    NFT_XML_MAND, err) == DATA_VALUE)
		e->flags |= (1 << NFT_SET_ELEM_ATTR_KEY);

	/* <set_elem_data> is not mandatory */
	set_elem_data = nft_mxml_data_reg_parse(tree, "data",
						&e->data, NFT_XML_OPT, err);
	switch (set_elem_data) {
	case DATA_VALUE:
		e->flags |= (1 << NFT_SET_ELEM_ATTR_DATA);
		break;
	case DATA_VERDICT:
		e->flags |= (1 << NFT_SET_ELEM_ATTR_VERDICT);
		if (e->data.chain != NULL)
			e->flags |= (1 << NFT_SET_ELEM_ATTR_CHAIN);

		break;
	}

	return 0;
}
#endif

static int nft_set_elem_xml_parse(struct nft_set_elem *e, const void *xml,
				  struct nft_parse_err *err,
				  enum nft_parse_input input)
{
#ifdef XML_PARSING
	mxml_node_t *tree;
	int ret;

	tree = nft_mxml_build_tree(xml, "set_elem", err, input);
	if (tree == NULL)
		return -1;

	ret = nft_mxml_set_elem_parse(tree, e, err);
	mxmlDelete(tree);
	return ret;
#else
	errno = EOPNOTSUPP;
	return -1;
#endif
}

static int nft_set_elem_json_parse(struct nft_set_elem *e, const void *json,
				   struct nft_parse_err *err,
				   enum nft_parse_input input)
{
#ifdef JSON_PARSING
	json_t *tree;
	json_error_t error;

	tree = nft_jansson_create_root(json, &error, err, input);
	if (tree == NULL)
		return -1;

	return nft_jansson_set_elem_parse(e, tree, err);
#else
	errno = EOPNOTSUPP;
	return -1;
#endif
}

static int
nft_set_elem_do_parse(struct nft_set_elem *e, enum nft_parse_type type,
		      const void *data, struct nft_parse_err *err,
		      enum nft_parse_input input)
{
	int ret;

	switch (type) {
	case NFT_PARSE_XML:
		ret = nft_set_elem_xml_parse(e, data, err, input);
		break;
	case NFT_PARSE_JSON:
		ret = nft_set_elem_json_parse(e, data, err, input);
		break;
	default:
		errno = EOPNOTSUPP;
		ret = -1;
		break;
	}

	return ret;
}
int nft_set_elem_parse(struct nft_set_elem *e, enum nft_parse_type type,
		       const char *data, struct nft_parse_err *err)
{
	return nft_set_elem_do_parse(e, type, data, err, NFT_PARSE_BUFFER);
}
EXPORT_SYMBOL(nft_set_elem_parse);

int nft_set_elem_parse_file(struct nft_set_elem *e, enum nft_parse_type type,
			    FILE *fp, struct nft_parse_err *err)
{
	return nft_set_elem_do_parse(e, type, fp, err, NFT_PARSE_FILE);
}
EXPORT_SYMBOL(nft_set_elem_parse_file);

static int nft_set_elem_snprintf_json(char *buf, size_t size,
				      struct nft_set_elem *e, uint32_t flags)
{
	int ret, len = size, offset = 0, type = -1;

	if (e->flags & (1 << NFT_SET_ELEM_ATTR_FLAGS)) {
		ret = snprintf(buf, len, "\"flags\":%u,", e->set_elem_flags);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	ret = snprintf(buf + offset, len, "\"key\":{");
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	ret = nft_data_reg_snprintf(buf + offset, len, &e->key,
				    NFT_OUTPUT_JSON, flags, DATA_VALUE);
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	ret = snprintf(buf + offset, len, "}");
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	if (e->flags & (1 << NFT_SET_ELEM_ATTR_DATA))
		type = DATA_VALUE;
	else if (e->flags & (1 << NFT_SET_ELEM_ATTR_CHAIN))
		type = DATA_CHAIN;
	else if (e->flags & (1 << NFT_SET_ELEM_ATTR_VERDICT))
		type = DATA_VERDICT;

	if (type != -1) {
		ret = snprintf(buf + offset, len, ",\"data\":{");
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

		ret = nft_data_reg_snprintf(buf + offset, len, &e->data,
					    NFT_OUTPUT_JSON, flags, type);
			SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

		ret = snprintf(buf + offset, len, "}");
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	return offset;
}

static int nft_set_elem_snprintf_default(char *buf, size_t size,
					 struct nft_set_elem *e)
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

	return offset;
}

static int nft_set_elem_snprintf_xml(char *buf, size_t size,
				     struct nft_set_elem *e, uint32_t flags)
{
	int ret, len = size, offset = 0, type = DATA_NONE;

	ret = snprintf(buf, size, "<set_elem>");
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	if (e->flags & (1 << NFT_SET_ELEM_ATTR_FLAGS)) {
		ret = snprintf(buf + offset, size, "<flags>%u</flags>",
			       e->set_elem_flags);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	if (e->flags & (1 << NFT_SET_ELEM_ATTR_KEY)) {
		ret = snprintf(buf + offset, len, "<key>");
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

		ret = nft_data_reg_snprintf(buf + offset, len, &e->key,
					    NFT_OUTPUT_XML, flags, DATA_VALUE);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

		ret = snprintf(buf + offset, len, "</key>");
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	if (e->flags & (1 << NFT_SET_ELEM_ATTR_DATA))
		type = DATA_VALUE;
	else if (e->flags & (1 << NFT_SET_ELEM_ATTR_CHAIN))
		type = DATA_CHAIN;
	else if (e->flags & (1 << NFT_SET_ELEM_ATTR_VERDICT))
		type = DATA_VERDICT;

	if (type != DATA_NONE) {
		ret = snprintf(buf + offset, len, "<data>");
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

		ret = nft_data_reg_snprintf(buf + offset, len, &e->data,
					    NFT_OUTPUT_XML, flags, type);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

		ret = snprintf(buf + offset, len, "</data>");
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	ret = snprintf(buf + offset, len, "</set_elem>");
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	return offset;
}

int nft_set_elem_snprintf(char *buf, size_t size, struct nft_set_elem *e,
			   uint32_t type, uint32_t flags)
{
	int ret, len = size, offset = 0;

	ret = nft_event_header_snprintf(buf+offset, len, type, flags);
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	switch(type) {
	case NFT_OUTPUT_DEFAULT:
		ret = nft_set_elem_snprintf_default(buf+offset, len, e);
		break;
	case NFT_OUTPUT_XML:
		ret = nft_set_elem_snprintf_xml(buf+offset, len, e, flags);
		break;
	case NFT_OUTPUT_JSON:
		ret = nft_set_elem_snprintf_json(buf+offset, len, e, flags);
		break;
	default:
		return -1;
	}

	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	ret = nft_event_footer_snprintf(buf+offset, len, type, flags);
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	return offset;
}
EXPORT_SYMBOL(nft_set_elem_snprintf);

static inline int nft_set_elem_do_snprintf(char *buf, size_t size, void *e,
					   uint32_t type, uint32_t flags)
{
	return nft_set_elem_snprintf(buf, size, e, type, flags);
}

int nft_set_elem_fprintf(FILE *fp, struct nft_set_elem *se, uint32_t type,
			 uint32_t flags)
{
	return nft_fprintf(fp, se, type, flags, nft_set_elem_do_snprintf);
}
EXPORT_SYMBOL(nft_set_elem_fprintf);

int nft_set_elem_foreach(struct nft_set *s,
			 int (*cb)(struct nft_set_elem *e, void *data),
			 void *data)
{
	struct nft_set_elem *elem;
	int ret;

	list_for_each_entry(elem, &s->element_list, head) {
		ret = cb(elem, data);
		if (ret < 0)
			return ret;
	}
	return 0;
}
EXPORT_SYMBOL(nft_set_elem_foreach);

struct nft_set_elems_iter {
	struct list_head		*list;
	struct nft_set_elem		*cur;
};

struct nft_set_elems_iter *nft_set_elems_iter_create(struct nft_set *s)
{
	struct nft_set_elems_iter *iter;

	iter = calloc(1, sizeof(struct nft_set_elems_iter));
	if (iter == NULL)
		return NULL;

	iter->list = &s->element_list;
	iter->cur = list_entry(s->element_list.next, struct nft_set_elem, head);

	return iter;
}
EXPORT_SYMBOL(nft_set_elems_iter_create);

struct nft_set_elem *nft_set_elems_iter_cur(struct nft_set_elems_iter *iter)
{
	return iter->cur;
}
EXPORT_SYMBOL(nft_set_elems_iter_cur);

struct nft_set_elem *nft_set_elems_iter_next(struct nft_set_elems_iter *iter)
{
	struct nft_set_elem *s = iter->cur;

	iter->cur = list_entry(iter->cur->head.next, struct nft_set_elem, head);
	if (&iter->cur->head == iter->list->next)
		return NULL;

	return s;
}
EXPORT_SYMBOL(nft_set_elems_iter_next);

void nft_set_elems_iter_destroy(struct nft_set_elems_iter *iter)
{
	xfree(iter);
}
EXPORT_SYMBOL(nft_set_elems_iter_destroy);
