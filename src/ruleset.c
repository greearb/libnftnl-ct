/*
 * (C) 2012-2013 by Pablo Neira Ayuso <pablo@netfilter.org>
 * (C) 2013 by Arturo Borrero Gonzalez <arturo.borrero.glez@gmail.com>
 * (C) 2013 by Alvaro Neira Ayuso <alvaroneay@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This code has been sponsored by Sophos Astaro <http://www.sophos.com>
 */

#include <errno.h>

#include "internal.h"

#include <libmnl/libmnl.h>
#include <libnftables/ruleset.h>
#include <libnftables/table.h>
#include <libnftables/chain.h>
#include <libnftables/set.h>
#include <libnftables/rule.h>

struct nft_ruleset {
	struct nft_table_list	*table_list;
	struct nft_chain_list	*chain_list;
	struct nft_set_list	*set_list;
	struct nft_rule_list	*rule_list;

	uint16_t		flags;
};

struct nft_ruleset *nft_ruleset_alloc(void)
{
	return calloc(1, sizeof(struct nft_ruleset));
}
EXPORT_SYMBOL(nft_ruleset_alloc);

void nft_ruleset_free(struct nft_ruleset *r)
{
	if (r->flags & (1 << NFT_RULESET_ATTR_TABLELIST))
		nft_table_list_free(r->table_list);
	if (r->flags & (1 << NFT_RULESET_ATTR_CHAINLIST))
		nft_chain_list_free(r->chain_list);
	if (r->flags & (1 << NFT_RULESET_ATTR_SETLIST))
		nft_set_list_free(r->set_list);
	if (r->flags & (1 << NFT_RULESET_ATTR_RULELIST))
		nft_rule_list_free(r->rule_list);
	xfree(r);
}
EXPORT_SYMBOL(nft_ruleset_free);

bool nft_ruleset_attr_is_set(const struct nft_ruleset *r, uint16_t attr)
{
	return r->flags & (1 << attr);
}
EXPORT_SYMBOL(nft_ruleset_attr_is_set);

void nft_ruleset_attr_unset(struct nft_ruleset *r, uint16_t attr)
{
	if (!(r->flags & (1 << attr)))
		return;

	switch (attr) {
	case NFT_RULESET_ATTR_TABLELIST:
		nft_table_list_free(r->table_list);
		r->table_list = NULL;
		break;
	case NFT_RULESET_ATTR_CHAINLIST:
		nft_chain_list_free(r->chain_list);
		r->chain_list = NULL;
		break;
	case NFT_RULESET_ATTR_SETLIST:
		nft_set_list_free(r->set_list);
		r->set_list = NULL;
		break;
	case NFT_RULESET_ATTR_RULELIST:
		nft_rule_list_free(r->rule_list);
		r->rule_list = NULL;
		break;
	}
	r->flags &= ~(1 << attr);
}
EXPORT_SYMBOL(nft_ruleset_attr_unset);

void nft_ruleset_attr_set(struct nft_ruleset *r, uint16_t attr, void *data)
{
	switch (attr) {
	case NFT_RULESET_ATTR_TABLELIST:
		nft_ruleset_attr_unset(r, NFT_RULESET_ATTR_TABLELIST);
		r->table_list = data;
		break;
	case NFT_RULESET_ATTR_CHAINLIST:
		nft_ruleset_attr_unset(r, NFT_RULESET_ATTR_CHAINLIST);
		r->chain_list = data;
		break;
	case NFT_RULESET_ATTR_SETLIST:
		nft_ruleset_attr_unset(r, NFT_RULESET_ATTR_SETLIST);
		r->set_list = data;
		break;
	case NFT_RULESET_ATTR_RULELIST:
		nft_ruleset_attr_unset(r, NFT_RULESET_ATTR_RULELIST);
		r->rule_list = data;
		break;
	default:
		return;
	}
	r->flags |= (1 << attr);
}
EXPORT_SYMBOL(nft_ruleset_attr_set);

const void *nft_ruleset_attr_get(const struct nft_ruleset *r, uint16_t attr)
{
	if (!(r->flags & (1 << attr)))
		return NULL;

	switch (attr) {
	case NFT_RULESET_ATTR_TABLELIST:
		return r->table_list;
	case NFT_RULESET_ATTR_CHAINLIST:
		return r->chain_list;
	case NFT_RULESET_ATTR_SETLIST:
		return r->set_list;
	case NFT_RULESET_ATTR_RULELIST:
		return r->rule_list;
	default:
		return NULL;
	}
}
EXPORT_SYMBOL(nft_ruleset_attr_get);

#ifdef JSON_PARSING
static int nft_ruleset_json_parse_tables(struct nft_ruleset *rs, json_t *array)
{
	int i, len;
	json_t *node;
	struct nft_table *o;
	struct nft_table_list *list = nft_table_list_alloc();

	if (list == NULL) {
		errno = ENOMEM;
		return -1;
	}

	len = json_array_size(array);
	for (i = 0; i < len; i++) {
		node = json_array_get(array, i);
		if (node == NULL) {
			errno = EINVAL;
			goto err;
		}

		if (!(nft_jansson_node_exist(node, "table")))
			continue;

		o = nft_table_alloc();
		if (o == NULL) {
			errno = ENOMEM;
			goto err;
		}

		if (nft_jansson_parse_table(o, node) < 0) {
			nft_table_free(o);
			goto err;
		}

		nft_table_list_add_tail(o, list);
	}

	if (!nft_table_list_is_empty(list))
		nft_ruleset_attr_set(rs, NFT_RULESET_ATTR_TABLELIST, list);
	else
		nft_table_list_free(list);

	return 0;
err:
	nft_table_list_free(list);
	return -1;
}

static int nft_ruleset_json_parse_chains(struct nft_ruleset *rs, json_t *array)
{
	int i, len;
	json_t *node;
	struct nft_chain *o;
	struct nft_chain_list *list = nft_chain_list_alloc();

	if (list == NULL) {
		errno = ENOMEM;
		return -1;
	}

	len = json_array_size(array);
	for (i = 0; i < len; i++) {
		node = json_array_get(array, i);
		if (node == NULL) {
			errno = EINVAL;
			goto err;
		}

		if (!(nft_jansson_node_exist(node, "chain")))
			continue;

		o = nft_chain_alloc();
		if (o == NULL) {
			errno = ENOMEM;
			goto err;
		}

		if (nft_jansson_parse_chain(o, node) < 0) {
			nft_chain_free(o);
			goto err;
		}

		nft_chain_list_add_tail(o, list);
	}

	if (!nft_chain_list_is_empty(list))
		nft_ruleset_attr_set(rs, NFT_RULESET_ATTR_CHAINLIST, list);
	else
		nft_chain_list_free(list);

	return 0;
err:
	nft_chain_list_free(list);
	return -1;
}

static int nft_ruleset_json_parse_sets(struct nft_ruleset *rs, json_t *array)
{
	int i, len;
	json_t *node;
	struct nft_set *s = NULL;
	struct nft_set_list *list = nft_set_list_alloc();

	if (list == NULL) {
		errno = ENOMEM;
		return -1;
	}

	len = json_array_size(array);
	for (i = 0; i < len; i++) {
		node = json_array_get(array, i);
		if (node == NULL) {
			errno = EINVAL;
			goto err;
		}

		if (!(nft_jansson_node_exist(node, "set")))
			continue;

		s = nft_set_alloc();
		if (s == NULL) {
			errno = ENOMEM;
			goto err;
		}

		if (nft_jansson_parse_set(s, node) < 0) {
			nft_set_free(s);
			goto err;
		}

		nft_set_list_add_tail(s, list);
	}

	if (!nft_set_list_is_empty(list))
		nft_ruleset_attr_set(rs, NFT_RULESET_ATTR_SETLIST, list);
	else
		nft_set_list_free(list);

	return 0;
err:
	nft_set_list_free(list);
	return -1;
}

static int nft_ruleset_json_parse_rules(struct nft_ruleset *rs, json_t *array)
{
	int i, len;
	json_t *node;
	struct nft_rule *o = NULL;
	struct nft_rule_list *list = nft_rule_list_alloc();

	if (list == NULL) {
		errno = ENOMEM;
		return -1;
	}

	len = json_array_size(array);
	for (i = 0; i < len; i++) {
		node = json_array_get(array, i);
		if (node == NULL) {
			errno = EINVAL;
			goto err;
		}

		if (!(nft_jansson_node_exist(node, "rule")))
			continue;

		o = nft_rule_alloc();
		if (o == NULL) {
			errno = ENOMEM;
			goto err;
		}

		if (nft_jansson_parse_rule(o, node) < 0) {
			nft_rule_free(o);
			goto err;
		}

		nft_rule_list_add_tail(o, list);
	}

	if (!nft_rule_list_is_empty(list))
		nft_ruleset_attr_set(rs, NFT_RULESET_ATTR_RULELIST, list);
	else
		nft_rule_list_free(list);

	return 0;
err:
	nft_rule_list_free(list);
	return -1;
}

#endif

static int nft_ruleset_json_parse(struct nft_ruleset *rs, const char *json)
{
#ifdef JSON_PARSING
	json_t *root, *array;
	json_error_t error;

	root = nft_jansson_create_root(json, &error);
	if (root == NULL)
		return -1;

	array = json_object_get(root, "nftables");
	if (array == NULL) {
		errno = EINVAL;
		goto err;
	}

	if (nft_ruleset_json_parse_tables(rs, array) != 0)
		goto err;

	if (nft_ruleset_json_parse_chains(rs, array) != 0)
		goto err;

	if (nft_ruleset_json_parse_sets(rs, array) != 0)
		goto err;

	if (nft_ruleset_json_parse_rules(rs, array) != 0)
		goto err;

	nft_jansson_free_root(root);
	return 0;
err:
	nft_jansson_free_root(root);
	return -1;
#else
	errno = EOPNOTSUPP;
	return -1;
#endif
}

#ifdef XML_PARSING
static int
nft_ruleset_xml_parse_tables(struct nft_ruleset *rs, mxml_node_t *tree)
{
	mxml_node_t *node;
	struct nft_table *t;
	struct nft_table_list *table_list = nft_table_list_alloc();
	if (table_list == NULL) {
		errno = ENOMEM;
		return -1;
	}

	for (node = mxmlFindElement(tree, tree, "table", NULL, NULL,
				    MXML_DESCEND_FIRST);
	     node != NULL;
	     node = mxmlFindElement(node, tree, "table", NULL, NULL,
				    MXML_NO_DESCEND)) {
		t = nft_table_alloc();
		if (t == NULL)
			goto err_free;

		if (nft_mxml_table_parse(node, t) != 0) {
			nft_table_free(t);
			goto err_free;
		}

		nft_table_list_add_tail(t, table_list);
	}

	if (!nft_table_list_is_empty(table_list))
		nft_ruleset_attr_set(rs, NFT_RULESET_ATTR_TABLELIST,
				     table_list);
	else
		nft_table_list_free(table_list);

	return 0;
err_free:
	nft_table_list_free(table_list);
	return -1;
}

static int
nft_ruleset_xml_parse_chains(struct nft_ruleset *rs, mxml_node_t *tree)
{
	mxml_node_t *node;
	struct nft_chain *c;
	struct nft_chain_list *chain_list = nft_chain_list_alloc();
	if (chain_list == NULL) {
		errno = ENOMEM;
		return -1;
	}

	for (node = mxmlFindElement(tree, tree, "chain", NULL, NULL,
				    MXML_DESCEND_FIRST);
	     node != NULL;
	     node = mxmlFindElement(node, tree, "chain", NULL, NULL,
				    MXML_NO_DESCEND)) {
		c = nft_chain_alloc();
		if (c == NULL)
			goto err_free;

		if (nft_mxml_chain_parse(node, c) != 0) {
			nft_chain_free(c);
			goto err_free;
		}

		nft_chain_list_add_tail(c, chain_list);
	}

	if (!nft_chain_list_is_empty(chain_list))
		nft_ruleset_attr_set(rs, NFT_RULESET_ATTR_CHAINLIST,
				     chain_list);
	else
		nft_chain_list_free(chain_list);

	return 0;
err_free:
	nft_chain_list_free(chain_list);
	return -1;
}

static int
nft_ruleset_xml_parse_sets(struct nft_ruleset *rs, mxml_node_t *tree)
{
	mxml_node_t *node;
	struct nft_set *s;
	struct nft_set_list *set_list = nft_set_list_alloc();
	if (set_list == NULL) {
		errno = ENOMEM;
		return -1;
	}

	for (node = mxmlFindElement(tree, tree, "set", NULL, NULL,
				    MXML_DESCEND_FIRST);
	     node != NULL;
	     node = mxmlFindElement(node, tree, "set", NULL, NULL,
				    MXML_NO_DESCEND)) {
		s = nft_set_alloc();
		if (s == NULL)
			goto err_free;

		if (nft_mxml_set_parse(node, s) != 0) {
			nft_set_free(s);
			goto err_free;
		}

		nft_set_list_add_tail(s, set_list);
	}

	if (!nft_set_list_is_empty(set_list))
		nft_ruleset_attr_set(rs, NFT_RULESET_ATTR_SETLIST, set_list);
	else
		nft_set_list_free(set_list);

	return 0;
err_free:
	nft_set_list_free(set_list);
	return -1;
}

static int
nft_ruleset_xml_parse_rules(struct nft_ruleset *rs, mxml_node_t *tree)
{
	mxml_node_t *node;
	struct nft_rule *r;
	struct nft_rule_list *rule_list = nft_rule_list_alloc();
	if (rule_list == NULL) {
		errno = ENOMEM;
		return -1;
	}

	for (node = mxmlFindElement(tree, tree, "rule", NULL, NULL,
				    MXML_DESCEND_FIRST);
	     node != NULL;
	     node = mxmlFindElement(node, tree, "rule", NULL, NULL,
				    MXML_NO_DESCEND)) {
		r = nft_rule_alloc();
		if (r == NULL)
			goto err_free;

		if (nft_mxml_rule_parse(node, r) != 0) {
			nft_rule_free(r);
			goto err_free;
		}

		nft_rule_list_add_tail(r, rule_list);
	}

	if (!nft_rule_list_is_empty(rule_list))
		nft_ruleset_attr_set(rs, NFT_RULESET_ATTR_RULELIST, rule_list);
	else
		nft_rule_list_free(rule_list);

	return 0;
err_free:
	nft_rule_list_free(rule_list);
	return -1;
}
#endif

static int nft_ruleset_xml_parse(struct nft_ruleset *rs, const char *xml)
{
#ifdef XML_PARSING
	mxml_node_t *tree;

	tree = nft_mxml_build_tree(xml, "nftables");
	if (tree == NULL)
		return -1;

	if (nft_ruleset_xml_parse_tables(rs, tree) != 0)
		goto err;

	if (nft_ruleset_xml_parse_chains(rs, tree) != 0)
		goto err;

	if (nft_ruleset_xml_parse_sets(rs, tree) != 0)
		goto err;

	if (nft_ruleset_xml_parse_rules(rs, tree) != 0)
		goto err;

	mxmlDelete(tree);
	return 0;
err:
	mxmlDelete(tree);
	return -1;
#else
	errno = EOPNOTSUPP;
	return -1;
#endif
}

int nft_ruleset_parse(struct nft_ruleset *r, enum nft_ruleset_parse_type type,
		      const char *data)
{
	int ret;

	switch (type) {
	case NFT_RULESET_PARSE_XML:
		ret = nft_ruleset_xml_parse(r, data);
		break;
	case NFT_RULESET_PARSE_JSON:
		ret = nft_ruleset_json_parse(r, data);
		break;
	default:
		ret = -1;
		errno = EOPNOTSUPP;
		break;
	}

	return ret;
}
EXPORT_SYMBOL(nft_ruleset_parse);

static int separator_snprintf(char *buf, size_t size, void *obj, uint32_t type)
{
	if (obj == NULL)
		return 0;

	switch (type) {
	case NFT_RULESET_O_JSON:
		return snprintf(buf, size, ",");
	case NFT_RULESET_O_DEFAULT:
		return snprintf(buf, size, "\n");
	default:
		return 0;
	}
}

static int
nft_ruleset_snprintf_table(char *buf, size_t size,
			   const struct nft_ruleset *rs, uint32_t type,
			   uint32_t flags)
{
	struct nft_table *t;
	struct nft_table_list_iter *ti;
	int ret, len = size, offset = 0;

	ti = nft_table_list_iter_create(rs->table_list);
	if (ti == NULL)
		return 0;

	t = nft_table_list_iter_next(ti);
	while (t != NULL) {
		ret = nft_table_snprintf(buf+offset, len, t, type, flags);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

		t = nft_table_list_iter_next(ti);
		ret = separator_snprintf(buf+offset, len, t, type);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}
	nft_table_list_iter_destroy(ti);

	return offset;
}

static int
nft_ruleset_snprintf_chain(char *buf, size_t size,
			   const struct nft_ruleset *rs, uint32_t type,
			   uint32_t flags)
{
	struct nft_chain *c;
	struct nft_chain_list_iter *ci;
	int ret, len = size, offset = 0;

	ci = nft_chain_list_iter_create(rs->chain_list);
	if (ci == NULL)
		return 0;

	c = nft_chain_list_iter_next(ci);
	while (c != NULL) {
		ret = nft_chain_snprintf(buf+offset, len, c, type, flags);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

		c = nft_chain_list_iter_next(ci);
		ret = separator_snprintf(buf+offset, len, c, type);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}
	nft_chain_list_iter_destroy(ci);

	return offset;
}

static int
nft_ruleset_snprintf_set(char *buf, size_t size,
			 const struct nft_ruleset *rs, uint32_t type,
			 uint32_t flags)
{
	struct nft_set *s;
	struct nft_set_list_iter *si;
	int ret, len = size, offset = 0;

	si = nft_set_list_iter_create(rs->set_list);
	if (si == NULL)
		return 0;

	s = nft_set_list_iter_next(si);
	while (s != NULL) {
		ret = nft_set_snprintf(buf+offset, len, s, type, flags);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

		s = nft_set_list_iter_next(si);
		ret = separator_snprintf(buf+offset, len, s, type);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}
	nft_set_list_iter_destroy(si);

	return offset;
}

static int
nft_ruleset_snprintf_rule(char *buf, size_t size,
			  const struct nft_ruleset *rs, uint32_t type,
			  uint32_t flags)
{
	struct nft_rule *r;
	struct nft_rule_list_iter *ri;
	int ret, len = size, offset = 0;

	ri = nft_rule_list_iter_create(rs->rule_list);
	if (ri == NULL)
		return 0;

	r = nft_rule_list_iter_next(ri);
	while (r != NULL) {
		ret = nft_rule_snprintf(buf+offset, len, r, type, flags);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

		r = nft_rule_list_iter_next(ri);
		ret = separator_snprintf(buf+offset, len, r, type);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}
	nft_rule_list_iter_destroy(ri);

	return offset;
}

static int
nft_ruleset_do_snprintf(char *buf, size_t size, const struct nft_ruleset *rs,
			uint32_t type, uint32_t flags)
{
	int ret, len = size, offset = 0;
	void *prev = NULL;

	if (nft_ruleset_attr_is_set(rs, NFT_RULESET_ATTR_TABLELIST) &&
	    (!nft_table_list_is_empty(rs->table_list))) {
		ret = nft_ruleset_snprintf_table(buf+offset, len, rs,
						 type, flags);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

		if (ret > 0)
			prev = rs->table_list;
	}

	if (nft_ruleset_attr_is_set(rs, NFT_RULESET_ATTR_CHAINLIST) &&
	    (!nft_chain_list_is_empty(rs->chain_list))) {
		ret = separator_snprintf(buf+offset, len, prev, type);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

		ret = nft_ruleset_snprintf_chain(buf+offset, len, rs,
						 type, flags);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

		if (ret > 0)
			prev = rs->chain_list;
	}

	if (nft_ruleset_attr_is_set(rs, NFT_RULESET_ATTR_SETLIST) &&
	    (!nft_set_list_is_empty(rs->set_list))) {
		ret = separator_snprintf(buf+offset, len, prev, type);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

		ret = nft_ruleset_snprintf_set(buf+offset, len, rs,
					       type, flags);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

		if (ret > 0)
			prev = rs->set_list;
	}

	if (nft_ruleset_attr_is_set(rs, NFT_RULESET_ATTR_RULELIST) &&
	    (!nft_rule_list_is_empty(rs->rule_list))) {
		ret = separator_snprintf(buf+offset, len, prev, type);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

		ret = nft_ruleset_snprintf_rule(buf+offset, len, rs,
						type, flags);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	return offset;
}

static int
nft_ruleset_snprintf_xml(char *buf, size_t size, const struct nft_ruleset *rs,
			 uint32_t flags)
{
	int ret, len = size, offset = 0;

	ret = snprintf(buf, size, "<nftables>");
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	ret = nft_ruleset_do_snprintf(buf+offset, len, rs, NFT_RULESET_O_XML,
				      flags);
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	ret = snprintf(buf+offset, len, "</nftables>");
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	return offset;
}

static int
nft_ruleset_snprintf_json(char *buf, size_t size, const struct nft_ruleset *rs,
			  uint32_t flags)
{
	int ret, len = size, offset = 0;

	ret = snprintf(buf, size, "{ \"nftables\": [");
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	ret = nft_ruleset_do_snprintf(buf+offset, len, rs, NFT_RULESET_O_JSON,
				      flags);
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	ret = snprintf(buf+offset, len, "]}");
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	return offset;
}

int nft_ruleset_snprintf(char *buf, size_t size, const struct nft_ruleset *r,
			 uint32_t type, uint32_t flags)
{
	switch (type) {
	case NFT_RULESET_O_DEFAULT:
		return nft_ruleset_do_snprintf(buf, size, r, type, flags);
	case NFT_RULESET_O_XML:
		return nft_ruleset_snprintf_xml(buf, size, r, flags);
	case NFT_RULESET_O_JSON:
		return nft_ruleset_snprintf_json(buf, size, r, flags);
	default:
		break;
	}
	return -1;
}
EXPORT_SYMBOL(nft_ruleset_snprintf);
