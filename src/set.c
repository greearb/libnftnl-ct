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
#include <limits.h>
#include <errno.h>

#include <libmnl/libmnl.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nf_tables.h>

#include <libnftnl/set.h>

#include "linux_list.h"
#include "expr/data_reg.h"

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
		if (mnl_attr_validate(attr, MNL_TYPE_STRING) < 0) {
			perror("mnl_attr_validate");
			return MNL_CB_ERROR;
		}
		break;
	case NFTA_SET_FLAGS:
	case NFTA_SET_KEY_TYPE:
	case NFTA_SET_KEY_LEN:
	case NFTA_SET_DATA_TYPE:
	case NFTA_SET_DATA_LEN:
		if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0) {
			perror("mnl_attr_validate");
			return MNL_CB_ERROR;
		}
		break;
	}

	tb[type] = attr;
	return MNL_CB_OK;
}

int nft_set_nlmsg_parse(const struct nlmsghdr *nlh, struct nft_set *s)
{
	struct nlattr *tb[NFTA_SET_MAX+1] = {};
	struct nfgenmsg *nfg = mnl_nlmsg_get_payload(nlh);

	if (mnl_attr_parse(nlh, sizeof(*nfg), nft_set_parse_attr_cb, tb) < 0)
		return -1;

	if (tb[NFTA_SET_TABLE]) {
		s->table = strdup(mnl_attr_get_str(tb[NFTA_SET_TABLE]));
		s->flags |= (1 << NFT_SET_ATTR_TABLE);
	}
	if (tb[NFTA_SET_NAME]) {
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
	s->family = nfg->nfgen_family;
	s->flags |= (1 << NFT_SET_ATTR_FAMILY);

	return 0;
}
EXPORT_SYMBOL(nft_set_nlmsg_parse);

#ifdef JSON_PARSING
int nft_jansson_parse_set(struct nft_set *s, json_t *tree,
			  struct nft_parse_err *err)
{
	json_t *root, *array, *json_elem;
	uint32_t uval32;
	int family, i;
	const char *valstr;
	struct nft_set_elem *elem;

	root = nft_jansson_get_node(tree, "set", err);
	if (root == NULL)
		return -1;

	valstr = nft_jansson_parse_str(root, "name", err);
	if (valstr == NULL)
		return -1;

	nft_set_attr_set_str(s, NFT_SET_ATTR_NAME, valstr);

	valstr = nft_jansson_parse_str(root, "table", err);
	if (valstr == NULL)
		return -1;

	nft_set_attr_set_str(s, NFT_SET_ATTR_TABLE, valstr);

	if (nft_jansson_parse_val(root, "flags", NFT_TYPE_U32, &uval32, err) < 0)
		return -1;

	nft_set_attr_set_u32(s, NFT_SET_ATTR_FLAGS, uval32);

	if (nft_jansson_parse_family(root, &family, err) < 0)
		return -1;

	nft_set_attr_set_u32(s, NFT_SET_ATTR_FAMILY, family);

	if (nft_jansson_parse_val(root, "key_type", NFT_TYPE_U32, &uval32,
				  err) < 0)
		return -1;

	nft_set_attr_set_u32(s, NFT_SET_ATTR_KEY_TYPE, uval32);

	if (nft_jansson_parse_val(root, "key_len", NFT_TYPE_U32, &uval32,
				  err) < 0)
		return -1;

	nft_set_attr_set_u32(s, NFT_SET_ATTR_KEY_LEN, uval32);

	if (nft_jansson_node_exist(root, "data_type")) {
		if (nft_jansson_parse_val(root, "data_type", NFT_TYPE_U32,
					  &uval32, err) < 0)
			goto err;

		nft_set_attr_set_u32(s, NFT_SET_ATTR_DATA_TYPE, uval32);
	}

	if (nft_jansson_node_exist(root, "data_len")) {
		if (nft_jansson_parse_val(root, "data_len", NFT_TYPE_U32,
					  &uval32, err) < 0)
			goto err;

		nft_set_attr_set_u32(s, NFT_SET_ATTR_DATA_LEN, uval32);
	}

	if (nft_jansson_node_exist(root, "set_elem")) {
		array = json_object_get(root, "set_elem");
		for (i = 0; i < json_array_size(array); i++) {
			elem = nft_set_elem_alloc();
			if (elem == NULL)
				goto err;

			json_elem = json_array_get(array, i);
			if (json_elem == NULL)
				goto err;

			if (nft_jansson_set_elem_parse(elem,
						       json_elem, err) < 0)
				goto err;

			list_add_tail(&elem->head, &s->element_list);
		}

	}

	nft_jansson_free_root(tree);
	return 0;
err:
	nft_jansson_free_root(tree);
	return -1;

}
#endif

static int nft_set_json_parse(struct nft_set *s, const void *json,
			      struct nft_parse_err *err,
			      enum nft_parse_input input)
{
#ifdef JSON_PARSING
	json_t *tree;
	json_error_t error;

	tree = nft_jansson_create_root(json, &error, err, input);
	if (tree == NULL)
		return -1;

	return nft_jansson_parse_set(s, tree, err);
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

	name = nft_mxml_str_parse(tree, "name", MXML_DESCEND_FIRST,
				  NFT_XML_MAND, err);
	if (name == NULL)
		return -1;

	if (s->name)
		xfree(s->name);

	s->name = strdup(name);
	s->flags |= (1 << NFT_SET_ATTR_NAME);

	table = nft_mxml_str_parse(tree, "table", MXML_DESCEND_FIRST,
				   NFT_XML_MAND, err);
	if (table == NULL)
		return -1;

	if (s->table)
		xfree(s->table);

	s->table = strdup(table);
	s->flags |= (1 << NFT_SET_ATTR_TABLE);

	family = nft_mxml_family_parse(tree, "family", MXML_DESCEND_FIRST,
				       NFT_XML_MAND, err);
	if (family < 0)
		return -1;

	s->family = family;

	s->flags |= (1 << NFT_SET_ATTR_FAMILY);

	if (nft_mxml_num_parse(tree, "flags", MXML_DESCEND_FIRST, BASE_DEC,
			       &s->set_flags, NFT_TYPE_U32, NFT_XML_MAND, err) != 0)
		return -1;

	s->flags |= (1 << NFT_SET_ATTR_FLAGS);

	if (nft_mxml_num_parse(tree, "key_type", MXML_DESCEND_FIRST, BASE_DEC,
			       &s->key_type, NFT_TYPE_U32, NFT_XML_MAND, err) != 0)
		return -1;

	s->flags |= (1 << NFT_SET_ATTR_KEY_TYPE);

	if (nft_mxml_num_parse(tree, "key_len", MXML_DESCEND_FIRST, BASE_DEC,
			       &s->key_len, NFT_TYPE_U32, NFT_XML_MAND, err) != 0)
		return -1;

	s->flags |= (1 << NFT_SET_ATTR_KEY_LEN);

	if (nft_mxml_num_parse(tree, "data_type", MXML_DESCEND_FIRST, BASE_DEC,
			       &s->data_type, NFT_TYPE_U32,
			       NFT_XML_OPT, err) == 0) {
		s->flags |= (1 << NFT_SET_ATTR_DATA_TYPE);

		if (nft_mxml_num_parse(tree, "data_len", MXML_DESCEND_FIRST,
				       BASE_DEC, &s->data_len, NFT_TYPE_U32,
				       NFT_XML_MAND, err) != 0)
			return -1;

		s->flags |= (1 << NFT_SET_ATTR_DATA_LEN);
	}

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

	ret = snprintf(buf, len, "{\"set\":{\"name\":\"%s\","
				  "\"table\":\"%s\","
				  "\"flags\":%u,\"family\":\"%s\","
				  "\"key_type\":%u,\"key_len\":%u",
			s->name, s->table, s->set_flags,
			nft_family2str(s->family), s->key_type, s->key_len);
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	if(s->flags & (1 << NFT_SET_ATTR_DATA_TYPE) &&
	   s->flags & (1 << NFT_SET_ATTR_DATA_LEN)){
		ret = snprintf(buf+offset, len,
				  ",\"data_type\":%u,\"data_len\":%u",
			s->data_type, s->data_len);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	/* Empty set? Skip printinf of elements */
	if (list_empty(&s->element_list)){
		ret = snprintf(buf+offset, len, "}}");
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
		return offset;
	}

	ret = snprintf(buf+offset, len, ",\"set_elem\":[");
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	list_for_each_entry(elem, &s->element_list, head) {
		ret = snprintf(buf+offset, len, "{");
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

		ret = nft_set_elem_snprintf(buf+offset, len, elem, type, flags);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

		ret = snprintf(buf+offset, len, "},");
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}
	/* Overwrite trailing ", " from last set element */
	offset --;

	ret = snprintf(buf+offset, len, "]}}");
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

	ret = snprintf(buf, len, "<set><family>%s</family>"
				  "<table>%s</table>"
				  "<name>%s</name>"
				  "<flags>%u</flags>"
				  "<key_type>%u</key_type>"
				  "<key_len>%u</key_len>",
			nft_family2str(s->family), s->table, s->name,
			s->set_flags, s->key_type, s->key_len);
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	if (s->flags & (1 << NFT_SET_ATTR_DATA_TYPE) &&
	    s->flags & (1 << NFT_SET_ATTR_DATA_LEN)) {
		ret = snprintf(buf+offset, len, "<data_type>%u</data_type>"
			       "<data_len>%u</data_len>",
			       s->data_type, s->data_len);

		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	if (!list_empty(&s->element_list)) {
		list_for_each_entry(elem, &s->element_list, head) {
			ret = nft_set_elem_snprintf(buf+offset, len, elem,
						    NFT_OUTPUT_XML, flags);
			SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
		}
	}

	ret = snprintf(buf+offset, len, "</set>");
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	return offset;
}

int nft_set_snprintf(char *buf, size_t size, struct nft_set *s,
		     uint32_t type, uint32_t flags)
{
	switch(type) {
	case NFT_OUTPUT_DEFAULT:
		return nft_set_snprintf_default(buf, size, s, type, flags);
	case NFT_OUTPUT_XML:
		return nft_set_snprintf_xml(buf, size, s, flags);
	case NFT_OUTPUT_JSON:
		return nft_set_snprintf_json(buf, size, s, type, flags);
	default:
		break;
	}
	return -1;
}
EXPORT_SYMBOL(nft_set_snprintf);

static inline int nft_set_do_snprintf(char *buf, size_t size, void *s,
				      uint32_t type, uint32_t flags)
{
	return nft_set_snprintf(buf, size, s, type, flags);
}

int nft_set_fprintf(FILE *fp, struct nft_set *s, uint32_t type,
		    uint32_t flags)
{
	return nft_fprintf(fp, s, type, flags, nft_set_do_snprintf);
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
