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
#include <stdlib.h>

#include <libmnl/libmnl.h>
#include <libnftnl/ruleset.h>
#include <libnftnl/table.h>
#include <libnftnl/chain.h>
#include <libnftnl/set.h>
#include <libnftnl/rule.h>

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

void *nft_ruleset_attr_get(const struct nft_ruleset *r, uint16_t attr)
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
static int nft_ruleset_json_parse_tables(struct nft_ruleset *rs, json_t *array,
					 struct nft_parse_err *err)
{
	int i, len;
	json_t *node;
	struct nft_table *table;
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

		table = nft_table_alloc();
		if (table == NULL) {
			errno = ENOMEM;
			goto err;
		}

		if (nft_jansson_parse_table(table, node, err) < 0) {
			nft_table_free(table);
			goto err;
		}

		nft_table_list_add_tail(table, list);
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

static int nft_ruleset_json_parse_chains(struct nft_ruleset *rs, json_t *array,
					 struct nft_parse_err *err)
{
	int i, len;
	json_t *node;
	struct nft_chain *chain;
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

		chain = nft_chain_alloc();
		if (chain == NULL) {
			errno = ENOMEM;
			goto err;
		}

		if (nft_jansson_parse_chain(chain, node, err) < 0) {
			nft_chain_free(chain);
			goto err;
		}

		nft_chain_list_add_tail(chain, list);
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

static int nft_ruleset_json_parse_sets(struct nft_ruleset *rs, json_t *array,
				       struct nft_parse_err *err)
{
	int i, len;
	uint32_t set_id = 0;
	json_t *node;
	struct nft_set *set;
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

		set = nft_set_alloc();
		if (set == NULL) {
			errno = ENOMEM;
			goto err;
		}

		if (nft_jansson_parse_set(set, node, err) < 0) {
			nft_set_free(set);
			goto err;
		}

		nft_set_attr_set_u32(set, NFT_SET_ATTR_ID, set_id++);
		nft_set_list_add_tail(set, list);
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

static int nft_ruleset_json_parse_rules(struct nft_ruleset *rs, json_t *array,
					struct nft_parse_err *err)
{
	int i, len;
	json_t *node;
	struct nft_rule *rule = NULL;
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

		rule = nft_rule_alloc();
		if (rule == NULL) {
			errno = ENOMEM;
			goto err;
		}

		if (nft_jansson_parse_rule(rule, node, err, rs->set_list) < 0) {
			nft_rule_free(rule);
			goto err;
		}

		nft_rule_list_add_tail(rule, list);
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

static int nft_ruleset_json_parse_ruleset(struct nft_ruleset *rs, json_t *array,
					  struct nft_parse_err *err)
{
	if (nft_ruleset_json_parse_tables(rs, array, err) != 0)
		return -1;

	if (nft_ruleset_json_parse_chains(rs, array, err) != 0)
		return -1;

	if (nft_ruleset_json_parse_sets(rs, array, err) != 0)
		return -1;

	if (nft_ruleset_json_parse_rules(rs, array, err) != 0)
		return -1;

	return 0;
}
#endif

static int nft_ruleset_json_parse(struct nft_ruleset *rs, const void *json,
				  struct nft_parse_err *err, enum nft_parse_input input)
{
#ifdef JSON_PARSING
	json_t *root, *array;
	json_error_t error;

	root = nft_jansson_create_root(json, &error, err, input);
	if (root == NULL)
		return -1;

	array = json_object_get(root, "nftables");
	if (array == NULL) {
		errno = EINVAL;
		goto err;
	}

	if (nft_ruleset_json_parse_ruleset(rs, array, err) != 0)
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
nft_ruleset_xml_parse_tables(struct nft_ruleset *rs, mxml_node_t *tree,
			     struct nft_parse_err *err)
{
	mxml_node_t *node;
	struct nft_table *table;
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
		table = nft_table_alloc();
		if (table == NULL)
			goto err_free;

		if (nft_mxml_table_parse(node, table, err) != 0) {
			nft_table_free(table);
			goto err_free;
		}

		nft_table_list_add_tail(table, table_list);
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
nft_ruleset_xml_parse_chains(struct nft_ruleset *rs, mxml_node_t *tree,
			     struct nft_parse_err *err)
{
	mxml_node_t *node;
	struct nft_chain *chain;
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
		chain = nft_chain_alloc();
		if (chain == NULL)
			goto err_free;

		if (nft_mxml_chain_parse(node, chain, err) != 0) {
			nft_chain_free(chain);
			goto err_free;
		}

		nft_chain_list_add_tail(chain, chain_list);
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
nft_ruleset_xml_parse_sets(struct nft_ruleset *rs, mxml_node_t *tree,
			   struct nft_parse_err *err)
{
	uint32_t set_id = 0;
	mxml_node_t *node;
	struct nft_set *set;
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
		set = nft_set_alloc();
		if (set == NULL)
			goto err_free;

		if (nft_mxml_set_parse(node, set, err) != 0) {
			nft_set_free(set);
			goto err_free;
		}

		nft_set_attr_set_u32(set, NFT_SET_ATTR_ID, set_id++);
		nft_set_list_add_tail(set, set_list);
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
nft_ruleset_xml_parse_rules(struct nft_ruleset *rs, mxml_node_t *tree,
			    struct nft_parse_err *err,
			    struct nft_set_list *set_list)
{
	mxml_node_t *node;
	struct nft_rule *rule;
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
		rule = nft_rule_alloc();
		if (rule == NULL)
			goto err_free;

		if (nft_mxml_rule_parse(node, rule, err, set_list) != 0) {
			nft_rule_free(rule);
			goto err_free;
		}

		nft_rule_list_add_tail(rule, rule_list);
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

static int nft_ruleset_xml_parse_ruleset(struct nft_ruleset *rs,
					 mxml_node_t *tree,
					 struct nft_parse_err *err)
{
	if (nft_ruleset_xml_parse_tables(rs, tree, err) != 0)
		return -1;

	if (nft_ruleset_xml_parse_chains(rs, tree, err) != 0)
		return -1;

	if (nft_ruleset_xml_parse_sets(rs, tree, err) != 0)
		return -1;

	if (nft_ruleset_xml_parse_rules(rs, tree, err, rs->set_list) != 0)
		return -1;

	return 0;
}
#endif

static int nft_ruleset_xml_parse(struct nft_ruleset *rs, const void *xml,
				 struct nft_parse_err *err, enum nft_parse_input input)
{
#ifdef XML_PARSING
	mxml_node_t *tree;

	tree = nft_mxml_build_tree(xml, "nftables", err, input);
	if (tree == NULL)
		return -1;

	if (nft_ruleset_xml_parse_ruleset(rs, tree, err) != 0)
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

static int
nft_ruleset_do_parse(struct nft_ruleset *r, enum nft_parse_type type,
		     const void *data, struct nft_parse_err *err,
		     enum nft_parse_input input)
{
	int ret;

	switch (type) {
	case NFT_PARSE_XML:
		ret = nft_ruleset_xml_parse(r, data, err, input);
		break;
	case NFT_PARSE_JSON:
		ret = nft_ruleset_json_parse(r, data, err, input);
		break;
	default:
		ret = -1;
		errno = EOPNOTSUPP;
		break;
	}

	return ret;
}

int nft_ruleset_parse(struct nft_ruleset *r, enum nft_parse_type type,
		      const char *data, struct nft_parse_err *err)
{
	return nft_ruleset_do_parse(r, type, data, err, NFT_PARSE_BUFFER);
}
EXPORT_SYMBOL(nft_ruleset_parse);

int nft_ruleset_parse_file(struct nft_ruleset *rs, enum nft_parse_type type,
			   FILE *fp, struct nft_parse_err *err)
{
	return nft_ruleset_do_parse(rs, type, fp, err, NFT_PARSE_FILE);
}
EXPORT_SYMBOL(nft_ruleset_parse_file);

static const char *nft_ruleset_o_opentag(uint32_t type)
{
	switch (type) {
	case NFT_OUTPUT_XML:
		return "<nftables>";
	case NFT_OUTPUT_JSON:
		return "{\"nftables\":[";
	default:
		return "";
	}
}

static const char *nft_ruleset_o_separator(void *obj, uint32_t type)
{
	if (obj == NULL)
		return "";

	switch (type) {
	case NFT_OUTPUT_JSON:
		return ",";
	case NFT_OUTPUT_DEFAULT:
		return "\n";
	default:
		return "";
	}
}

static const char *nft_ruleset_o_closetag(uint32_t type)
{
	switch (type) {
	case NFT_OUTPUT_XML:
		return "</nftables>";
	case NFT_OUTPUT_JSON:
		return "]}";
	default:
		return "";
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

		ret = snprintf(buf+offset, len, "%s",
			       nft_ruleset_o_separator(t, type));
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

		ret = snprintf(buf+offset, len, "%s",
			       nft_ruleset_o_separator(c, type));
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

		ret = snprintf(buf+offset, len, "%s",
			       nft_ruleset_o_separator(s, type));
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

		ret = snprintf(buf+offset, len, "%s",
			       nft_ruleset_o_separator(r, type));
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}
	nft_rule_list_iter_destroy(ri);

	return offset;
}

static int
nft_ruleset_do_snprintf(char *buf, size_t size, const struct nft_ruleset *rs,
			uint32_t cmd, uint32_t type, uint32_t flags)
{
	int ret, len = size, offset = 0;
	void *prev = NULL;
	uint32_t inner_flags = flags;

	/* dont pass events flags to child calls of _snprintf() */
	inner_flags &= ~NFT_OF_EVENT_ANY;

	ret = snprintf(buf + offset, len, "%s", nft_ruleset_o_opentag(type));
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	ret = nft_cmd_header_snprintf(buf + offset, len, cmd, type, flags);
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	if (nft_ruleset_attr_is_set(rs, NFT_RULESET_ATTR_TABLELIST) &&
	    (!nft_table_list_is_empty(rs->table_list))) {
		ret = nft_ruleset_snprintf_table(buf+offset, len, rs,
						 type, inner_flags);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

		if (ret > 0)
			prev = rs->table_list;
	}

	if (nft_ruleset_attr_is_set(rs, NFT_RULESET_ATTR_CHAINLIST) &&
	    (!nft_chain_list_is_empty(rs->chain_list))) {
		ret = snprintf(buf+offset, len, "%s",
			       nft_ruleset_o_separator(prev, type));
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

		ret = nft_ruleset_snprintf_chain(buf+offset, len, rs,
						 type, inner_flags);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

		if (ret > 0)
			prev = rs->chain_list;
	}

	if (nft_ruleset_attr_is_set(rs, NFT_RULESET_ATTR_SETLIST) &&
	    (!nft_set_list_is_empty(rs->set_list))) {
		ret = snprintf(buf+offset, len, "%s",
			       nft_ruleset_o_separator(prev, type));
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

		ret = nft_ruleset_snprintf_set(buf+offset, len, rs,
					       type, inner_flags);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

		if (ret > 0)
			prev = rs->set_list;
	}

	if (nft_ruleset_attr_is_set(rs, NFT_RULESET_ATTR_RULELIST) &&
	    (!nft_rule_list_is_empty(rs->rule_list))) {
		ret = snprintf(buf+offset, len, "%s",
			       nft_ruleset_o_separator(prev, type));
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

		ret = nft_ruleset_snprintf_rule(buf+offset, len, rs,
						type, inner_flags);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	ret = nft_cmd_footer_snprintf(buf + offset, len, cmd, type, flags);
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	ret = snprintf(buf + offset, len, "%s", nft_ruleset_o_closetag(type));
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	return offset;
}

static int nft_ruleset_cmd_snprintf(char *buf, size_t size,
				    const struct nft_ruleset *r, uint32_t cmd,
				    uint32_t type, uint32_t flags)
{
	switch (type) {
	case NFT_OUTPUT_DEFAULT:
	case NFT_OUTPUT_XML:
	case NFT_OUTPUT_JSON:
		return nft_ruleset_do_snprintf(buf, size, r, cmd, type, flags);
	default:
		errno = EOPNOTSUPP;
		return -1;
	}
}

int nft_ruleset_snprintf(char *buf, size_t size, const struct nft_ruleset *r,
			 uint32_t type, uint32_t flags)
{
	switch (type) {
	case NFT_OUTPUT_DEFAULT:
	case NFT_OUTPUT_XML:
	case NFT_OUTPUT_JSON:
		return nft_ruleset_cmd_snprintf(buf, size, r,
						nft_flag2cmd(flags), type,
						flags);
	default:
		errno = EOPNOTSUPP;
		return -1;
	}
}
EXPORT_SYMBOL(nft_ruleset_snprintf);

static int nft_ruleset_fprintf_tables(FILE *fp, const struct nft_ruleset *rs,
				      uint32_t type, uint32_t flags)
{
	int len = 0, ret = 0;
	struct nft_table *t;
	struct nft_table_list_iter *ti;

	ti = nft_table_list_iter_create(rs->table_list);
	if (ti == NULL)
		return -1;

	t = nft_table_list_iter_next(ti);
	while (t != NULL) {
		ret = nft_table_fprintf(fp, t, type, flags);
		if (ret < 0)
			goto err;

		len += ret;

		t = nft_table_list_iter_next(ti);

		ret = fprintf(fp, "%s", nft_ruleset_o_separator(t, type));
		if (ret < 0)
			goto err;

		len += ret;
	}
	nft_table_list_iter_destroy(ti);

	return len;
err:
	nft_table_list_iter_destroy(ti);
	return -1;
}

static int nft_ruleset_fprintf_chains(FILE *fp, const struct nft_ruleset *rs,
				      uint32_t type, uint32_t flags)
{
	int len = 0, ret = 0;
	struct nft_chain *o;
	struct nft_chain_list_iter *i;

	i = nft_chain_list_iter_create(rs->chain_list);
	if (i == NULL)
		return -1;

	o = nft_chain_list_iter_next(i);
	while (o != NULL) {
		ret = nft_chain_fprintf(fp, o, type, flags);
		if (ret < 0)
			goto err;

		len += ret;

		o = nft_chain_list_iter_next(i);

		ret = fprintf(fp, "%s", nft_ruleset_o_separator(o, type));
		if (ret < 0)
			goto err;

		len += ret;
	}
	nft_chain_list_iter_destroy(i);

	return len;
err:
	nft_chain_list_iter_destroy(i);
	return -1;
}

static int nft_ruleset_fprintf_sets(FILE *fp, const struct nft_ruleset *rs,
				    uint32_t type, uint32_t flags)
{
	int len = 0, ret = 0;
	struct nft_set *o;
	struct nft_set_list_iter *i;

	i = nft_set_list_iter_create(rs->set_list);
	if (i == NULL)
		return -1;

	o = nft_set_list_iter_next(i);
	while (o != NULL) {
		ret = nft_set_fprintf(fp, o, type, flags);
		if (ret < 0)
			goto err;

		len += ret;

		o = nft_set_list_iter_next(i);

		ret = fprintf(fp, "%s", nft_ruleset_o_separator(o, type));
		if (ret < 0)
			goto err;

		len += ret;
	}
	nft_set_list_iter_destroy(i);

	return len;
err:
	nft_set_list_iter_destroy(i);
	return -1;
}

static int nft_ruleset_fprintf_rules(FILE *fp, const struct nft_ruleset *rs,
				    uint32_t type, uint32_t flags)
{
	int len = 0, ret = 0;
	struct nft_rule *o;
	struct nft_rule_list_iter *i;

	i = nft_rule_list_iter_create(rs->rule_list);
	if (i == NULL)
		return -1;

	o = nft_rule_list_iter_next(i);
	while (o != NULL) {
		ret = nft_rule_fprintf(fp, o, type, flags);
		if (ret < 0)
			goto err;

		len += ret;

		o = nft_rule_list_iter_next(i);

		ret = fprintf(fp, "%s", nft_ruleset_o_separator(o, type));
		if (ret < 0)
			goto err;

		len += ret;
	}
	nft_rule_list_iter_destroy(i);

	return len;
err:
	nft_rule_list_iter_destroy(i);
	return -1;
}

#define NFT_FPRINTF_RETURN_OR_FIXLEN(ret, len)	\
	if (ret < 0)				\
		return -1;			\
	len += ret;

static int nft_ruleset_cmd_fprintf(FILE *fp, const struct nft_ruleset *rs,
				   uint32_t cmd, uint32_t type, uint32_t flags)
{
	int len = 0, ret = 0;
	void *prev = NULL;
	uint32_t inner_flags = flags;

	/* dont pass events flags to child calls of _snprintf() */
	inner_flags &= ~NFT_OF_EVENT_ANY;

	ret = fprintf(fp, "%s", nft_ruleset_o_opentag(type));
	NFT_FPRINTF_RETURN_OR_FIXLEN(ret, len);

	ret = nft_cmd_header_fprintf(fp, cmd, type, flags);
	NFT_FPRINTF_RETURN_OR_FIXLEN(ret, len);

	if ((nft_ruleset_attr_is_set(rs, NFT_RULESET_ATTR_TABLELIST)) &&
	    (!nft_table_list_is_empty(rs->table_list))) {
		ret = nft_ruleset_fprintf_tables(fp, rs, type, inner_flags);
		NFT_FPRINTF_RETURN_OR_FIXLEN(ret, len);

		if (ret > 0)
			prev = rs->table_list;
	}

	if ((nft_ruleset_attr_is_set(rs, NFT_RULESET_ATTR_CHAINLIST)) &&
	    (!nft_chain_list_is_empty(rs->chain_list))) {
		ret = fprintf(fp, "%s", nft_ruleset_o_separator(prev, type));
		NFT_FPRINTF_RETURN_OR_FIXLEN(ret, len);

		ret = nft_ruleset_fprintf_chains(fp, rs, type, inner_flags);
		NFT_FPRINTF_RETURN_OR_FIXLEN(ret, len);

		if (ret > 0)
			prev = rs->chain_list;
	}

	if ((nft_ruleset_attr_is_set(rs, NFT_RULESET_ATTR_SETLIST)) &&
	    (!nft_set_list_is_empty(rs->set_list))) {
		ret = fprintf(fp, "%s", nft_ruleset_o_separator(prev, type));
		NFT_FPRINTF_RETURN_OR_FIXLEN(ret, len);

		ret = nft_ruleset_fprintf_sets(fp, rs, type, inner_flags);
		NFT_FPRINTF_RETURN_OR_FIXLEN(ret, len);

		if (ret > 0)
			prev = rs->set_list;
	}

	if ((nft_ruleset_attr_is_set(rs, NFT_RULESET_ATTR_RULELIST)) &&
	    (!nft_rule_list_is_empty(rs->rule_list))) {
		ret = fprintf(fp, "%s", nft_ruleset_o_separator(prev, type));
		NFT_FPRINTF_RETURN_OR_FIXLEN(ret, len);

		ret = nft_ruleset_fprintf_rules(fp, rs, type, inner_flags);
		NFT_FPRINTF_RETURN_OR_FIXLEN(ret, len);
	}

	ret = nft_cmd_footer_fprintf(fp, cmd, type, flags);
	NFT_FPRINTF_RETURN_OR_FIXLEN(ret, len);

	ret = fprintf(fp, "%s", nft_ruleset_o_closetag(type));
	NFT_FPRINTF_RETURN_OR_FIXLEN(ret, len);

	return len;
}

int nft_ruleset_fprintf(FILE *fp, const struct nft_ruleset *rs, uint32_t type,
			uint32_t flags)
{
	return nft_ruleset_cmd_fprintf(fp, rs, nft_flag2cmd(flags), type,
				       flags);
}
EXPORT_SYMBOL(nft_ruleset_fprintf);
