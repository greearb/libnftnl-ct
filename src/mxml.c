/*
 * (C) 2012-2013 by Pablo Neira Ayuso <pablo@netfilter.org>
 * (C) 2013 by Arturo Borrero Gonzalez <arturo.borrero.glez@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This code has been sponsored by Sophos Astaro <http://www.sophos.com>
 */
#include "internal.h"

#include <stdint.h>
#include <limits.h>

#include <linux/netfilter/nf_tables.h>
#include <libnftnl/table.h>
#include <libnftnl/chain.h>
#include <libnftnl/rule.h>
#include <libnftnl/expr.h>
#include <libnftnl/set.h>

#ifdef XML_PARSING
mxml_node_t *nftnl_mxml_build_tree(const void *data, const char *treename,
				 struct nftnl_parse_err *err, enum nftnl_parse_input input)
{
	mxml_node_t *tree;

	switch (input) {
	case NFTNL_PARSE_BUFFER:
		tree = mxmlLoadString(NULL, data, MXML_OPAQUE_CALLBACK);
		break;
	case NFTNL_PARSE_FILE:
		tree = mxmlLoadFile(NULL, (FILE *)data, MXML_OPAQUE_CALLBACK);
		break;
	default:
		goto err;
	}

	if (tree == NULL) {
		err->error = NFTNL_PARSE_EBADINPUT;
		goto err;
	}

	if (tree->value.opaque != NULL &&
	    strcmp(tree->value.opaque, treename) == 0)
		return tree;

	err->error = NFTNL_PARSE_EMISSINGNODE;
	err->node_name = treename;

	mxmlDelete(tree);
err:
	err->line = 0;
	err->column = 0;
	errno = EINVAL;
	return NULL;
}

struct nftnl_expr *nftnl_mxml_expr_parse(mxml_node_t *node,
					  struct nftnl_parse_err *err,
					  struct nftnl_set_list *set_list)
{
	mxml_node_t *tree;
	struct nftnl_expr *e;
	const char *expr_name;
	char *xml_text;
	uint32_t set_id;
	int ret;

	expr_name = mxmlElementGetAttr(node, "type");
	if (expr_name == NULL) {
		err->node_name = "type";
		err->error = NFTNL_PARSE_EMISSINGNODE;
		goto err;
	}

	e = nftnl_expr_alloc(expr_name);
	if (e == NULL)
		goto err;

	xml_text = mxmlSaveAllocString(node, MXML_NO_CALLBACK);
	if (xml_text == NULL)
		goto err_expr;

	tree = mxmlLoadString(NULL, xml_text, MXML_OPAQUE_CALLBACK);
	xfree(xml_text);

	if (tree == NULL)
		goto err_expr;

	ret = e->ops->xml_parse(e, tree, err);
	mxmlDelete(tree);

	if (set_list != NULL &&
	    strcmp(expr_name, "lookup") == 0 &&
	    nftnl_set_lookup_id(e, set_list, &set_id))
		nftnl_expr_set_u32(e, NFTNL_EXPR_LOOKUP_SET_ID, set_id);

	return ret < 0 ? NULL : e;
err_expr:
	nftnl_expr_free(e);
err:
	mxmlDelete(tree);
	errno = EINVAL;
	return NULL;
}

int nftnl_mxml_reg_parse(mxml_node_t *tree, const char *reg_name, uint32_t *reg,
		       uint32_t mxmlflags, uint32_t flags,
		       struct nftnl_parse_err *err)
{
	mxml_node_t *node;

	node = mxmlFindElement(tree, tree, reg_name, NULL, NULL, mxmlflags);
	if (node == NULL) {
		if (!(flags & NFTNL_XML_OPT)) {
			err->error = NFTNL_PARSE_EMISSINGNODE;
			errno = EINVAL;
			goto err;
		}
		return -1;
	}

	if (nftnl_strtoi(node->child->value.opaque, BASE_DEC, reg,
		       NFTNL_TYPE_U32) != 0) {
		err->error = NFTNL_PARSE_EBADTYPE;
		goto err;
	}

	if (*reg > NFT_REG_MAX) {
		errno = ERANGE;
		goto err;
	}

	return 0;
err:
	err->node_name = reg_name;
	return -1;
}

int nftnl_mxml_data_reg_parse(mxml_node_t *tree, const char *node_name,
			    union nftnl_data_reg *data_reg, uint16_t flags,
			    struct nftnl_parse_err *err)
{
	mxml_node_t *node;

	node = mxmlFindElement(tree, tree, node_name, NULL, NULL,
			       MXML_DESCEND_FIRST);

	/* It is necessary for the compatibility with cmpdata label. */
	if (node == NULL || node->child == NULL)
		node = tree;

	return nftnl_data_reg_xml_parse(data_reg, node, err);
}

int
nftnl_mxml_num_parse(mxml_node_t *tree, const char *node_name,
		   uint32_t mxml_flags, int base, void *number,
		   enum nftnl_type type, uint16_t flags,
		   struct nftnl_parse_err *err)
{
	mxml_node_t *node = NULL;
	int ret;

	node = mxmlFindElement(tree, tree, node_name, NULL, NULL, mxml_flags);
	if (node == NULL || node->child == NULL) {
		if (!(flags & NFTNL_XML_OPT)) {
			errno = EINVAL;
			err->node_name = node_name;
			err->error = NFTNL_PARSE_EMISSINGNODE;
		}
		return -1;
	}

	ret = nftnl_strtoi(node->child->value.opaque, base, number, type);

	if (ret != 0) {
		err->error = NFTNL_PARSE_EBADTYPE;
		err->node_name = node_name;
	}
	return ret;
}

const char *nftnl_mxml_str_parse(mxml_node_t *tree, const char *node_name,
			       uint32_t mxml_flags, uint16_t flags,
			       struct nftnl_parse_err *err)
{
	mxml_node_t *node;
	const char *ret;

	node = mxmlFindElement(tree, tree, node_name, NULL, NULL, mxml_flags);
	if (node == NULL || node->child == NULL) {
		if (!(flags & NFTNL_XML_OPT)) {
			errno = EINVAL;
			err->node_name = node_name;
			err->error = NFTNL_PARSE_EMISSINGNODE;
		}
		return NULL;
	}

	ret = node->child->value.opaque;
	if (ret == NULL) {
		err->node_name = node_name;
		err->error = NFTNL_PARSE_EBADTYPE;
	}
	return ret;
}

int nftnl_mxml_family_parse(mxml_node_t *tree, const char *node_name,
			  uint32_t mxml_flags, uint16_t flags,
			  struct nftnl_parse_err *err)
{
	const char *family_str;
	int family;

	family_str = nftnl_mxml_str_parse(tree, node_name, mxml_flags,
					flags, err);
	if (family_str == NULL)
		return -1;

	family = nftnl_str2family(family_str);
	if (family < 0) {
		err->node_name = node_name;
		errno = EAFNOSUPPORT;
	}

	return family;
}
#endif
