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
#include "expr_ops.h"

#include <linux/netfilter/nf_tables.h>
#include <libnftables/rule.h>
#include <libnftables/expr.h>

struct nft_rule_expr *nft_mxml_expr_parse(mxml_node_t *node)
{
	mxml_node_t *tree;
	struct nft_rule_expr *e;
	const char *expr_name;
	char *xml_text;
	int ret;

	expr_name = mxmlElementGetAttr(node, "type");
	if (expr_name == NULL)
		goto err;

	e = nft_rule_expr_alloc(expr_name);
	if (e == NULL)
		goto err;

	xml_text = mxmlSaveAllocString(node, MXML_NO_CALLBACK);
	if (xml_text == NULL)
		goto err_expr;

	tree = mxmlLoadString(NULL, xml_text, MXML_OPAQUE_CALLBACK);
	free(xml_text);

	if (tree == NULL)
		goto err_expr;

	ret = e->ops->xml_parse(e, tree);
	mxmlDelete(tree);

	return ret < 0 ? NULL : e;
err_expr:
	nft_rule_expr_free(e);
err:
	mxmlDelete(tree);
	errno = EINVAL;
	return NULL;
}

int nft_mxml_reg_parse(mxml_node_t *tree, const char *reg_name, uint32_t flags)
{
	mxml_node_t *node;
	char *endptr;
	uint64_t val;

	node = mxmlFindElement(tree, tree, reg_name, NULL, NULL, flags);
	if (node == NULL) {
		errno = EINVAL;
		goto err;
	}

	val = strtoull(node->child->value.opaque, &endptr, 10);
	if (val > NFT_REG_MAX || val < 0 || *endptr) {
		errno = ERANGE;
		goto err;
	}
	return val;
err:
	return -1;
}
