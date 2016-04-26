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

struct nftnl_ruleset {
	struct nftnl_table_list	*table_list;
	struct nftnl_chain_list	*chain_list;
	struct nftnl_set_list	*set_list;
	struct nftnl_rule_list	*rule_list;

	uint16_t		flags;
};

struct nftnl_parse_ctx {
	enum nftnl_cmd_type cmd;
	enum nftnl_ruleset_type type;
	union {
		struct nftnl_table	*table;
		struct nftnl_chain	*chain;
		struct nftnl_rule		*rule;
		struct nftnl_set		*set;
		struct nftnl_set_elem	*set_elem;
	};
	void *data;

	/* These fields below are not exposed to the user */
	union {
		json_t			*json;
		mxml_node_t		*xml;
	};

	uint32_t format;
	uint32_t set_id;
	struct nftnl_set_list *set_list;

	int (*cb)(const struct nftnl_parse_ctx *ctx);
	uint16_t flags;
};

struct nftnl_ruleset *nftnl_ruleset_alloc(void)
{
	return calloc(1, sizeof(struct nftnl_ruleset));
}
EXPORT_SYMBOL_ALIAS(nftnl_ruleset_alloc, nft_ruleset_alloc);

void nftnl_ruleset_free(const struct nftnl_ruleset *r)
{
	if (r->flags & (1 << NFTNL_RULESET_TABLELIST))
		nftnl_table_list_free(r->table_list);
	if (r->flags & (1 << NFTNL_RULESET_CHAINLIST))
		nftnl_chain_list_free(r->chain_list);
	if (r->flags & (1 << NFTNL_RULESET_SETLIST))
		nftnl_set_list_free(r->set_list);
	if (r->flags & (1 << NFTNL_RULESET_RULELIST))
		nftnl_rule_list_free(r->rule_list);
	xfree(r);
}
EXPORT_SYMBOL_ALIAS(nftnl_ruleset_free, nft_ruleset_free);

bool nftnl_ruleset_is_set(const struct nftnl_ruleset *r, uint16_t attr)
{
	return r->flags & (1 << attr);
}
EXPORT_SYMBOL_ALIAS(nftnl_ruleset_is_set, nft_ruleset_attr_is_set);

void nftnl_ruleset_unset(struct nftnl_ruleset *r, uint16_t attr)
{
	if (!(r->flags & (1 << attr)))
		return;

	switch (attr) {
	case NFTNL_RULESET_TABLELIST:
		nftnl_table_list_free(r->table_list);
		r->table_list = NULL;
		break;
	case NFTNL_RULESET_CHAINLIST:
		nftnl_chain_list_free(r->chain_list);
		r->chain_list = NULL;
		break;
	case NFTNL_RULESET_SETLIST:
		nftnl_set_list_free(r->set_list);
		r->set_list = NULL;
		break;
	case NFTNL_RULESET_RULELIST:
		nftnl_rule_list_free(r->rule_list);
		r->rule_list = NULL;
		break;
	}
	r->flags &= ~(1 << attr);
}
EXPORT_SYMBOL_ALIAS(nftnl_ruleset_unset, nft_ruleset_attr_unset);

void nftnl_ruleset_set(struct nftnl_ruleset *r, uint16_t attr, void *data)
{
	switch (attr) {
	case NFTNL_RULESET_TABLELIST:
		nftnl_ruleset_unset(r, NFTNL_RULESET_TABLELIST);
		r->table_list = data;
		break;
	case NFTNL_RULESET_CHAINLIST:
		nftnl_ruleset_unset(r, NFTNL_RULESET_CHAINLIST);
		r->chain_list = data;
		break;
	case NFTNL_RULESET_SETLIST:
		nftnl_ruleset_unset(r, NFTNL_RULESET_SETLIST);
		r->set_list = data;
		break;
	case NFTNL_RULESET_RULELIST:
		nftnl_ruleset_unset(r, NFTNL_RULESET_RULELIST);
		r->rule_list = data;
		break;
	default:
		return;
	}
	r->flags |= (1 << attr);
}
EXPORT_SYMBOL_ALIAS(nftnl_ruleset_set, nft_ruleset_attr_set);

void *nftnl_ruleset_get(const struct nftnl_ruleset *r, uint16_t attr)
{
	if (!(r->flags & (1 << attr)))
		return NULL;

	switch (attr) {
	case NFTNL_RULESET_TABLELIST:
		return r->table_list;
	case NFTNL_RULESET_CHAINLIST:
		return r->chain_list;
	case NFTNL_RULESET_SETLIST:
		return r->set_list;
	case NFTNL_RULESET_RULELIST:
		return r->rule_list;
	default:
		return NULL;
	}
}
EXPORT_SYMBOL_ALIAS(nftnl_ruleset_get, nft_ruleset_attr_get);

void nftnl_ruleset_ctx_free(const struct nftnl_parse_ctx *ctx)
{
	switch (ctx->type) {
	case NFTNL_RULESET_TABLE:
		nftnl_table_free(ctx->table);
		break;
	case NFTNL_RULESET_CHAIN:
		nftnl_chain_free(ctx->chain);
		break;
	case NFTNL_RULESET_RULE:
		nftnl_rule_free(ctx->rule);
		break;
	case NFTNL_RULESET_SET:
	case NFTNL_RULESET_SET_ELEMS:
		nftnl_set_free(ctx->set);
		break;
	case NFTNL_RULESET_RULESET:
	case NFTNL_RULESET_UNSPEC:
		break;
	}
}
EXPORT_SYMBOL_ALIAS(nftnl_ruleset_ctx_free, nft_ruleset_ctx_free);

bool nftnl_ruleset_ctx_is_set(const struct nftnl_parse_ctx *ctx, uint16_t attr)
{
	return ctx->flags & (1 << attr);
}
EXPORT_SYMBOL_ALIAS(nftnl_ruleset_ctx_is_set, nft_ruleset_ctx_is_set);

void *nftnl_ruleset_ctx_get(const struct nftnl_parse_ctx *ctx, uint16_t attr)
{
	if (!(ctx->flags & (1 << attr)))
		return NULL;

	switch (attr) {
	case NFTNL_RULESET_CTX_CMD:
		return (void *)&ctx->cmd;
	case NFTNL_RULESET_CTX_TYPE:
		return (void *)&ctx->type;
	case NFTNL_RULESET_CTX_TABLE:
		return ctx->table;
	case NFTNL_RULESET_CTX_CHAIN:
		return ctx->chain;
	case NFTNL_RULESET_CTX_RULE:
		return ctx->rule;
	case NFTNL_RULESET_CTX_SET:
		return ctx->set;
	case NFTNL_RULESET_CTX_DATA:
		return ctx->data;
	default:
		return NULL;
	}
}
EXPORT_SYMBOL_ALIAS(nftnl_ruleset_ctx_get, nft_ruleset_ctx_get);

uint32_t nftnl_ruleset_ctx_get_u32(const struct nftnl_parse_ctx *ctx, uint16_t attr)
{
	const void *ret = nftnl_ruleset_ctx_get(ctx, attr);
	return ret == NULL ? 0 : *((uint32_t *)ret);
}
EXPORT_SYMBOL_ALIAS(nftnl_ruleset_ctx_get_u32, nft_ruleset_ctx_get_u32);

#if defined(JSON_PARSING) || defined(XML_PARSING)
static void nftnl_ruleset_ctx_set(struct nftnl_parse_ctx *ctx, uint16_t attr,
				void *data)
{
	switch (attr) {
	case NFTNL_RULESET_CTX_CMD:
		ctx->cmd = *((uint32_t *)data);
		break;
	case NFTNL_RULESET_CTX_TYPE:
		ctx->type = *((uint32_t *)data);
		break;
	case NFTNL_RULESET_CTX_TABLE:
		ctx->table = data;
		break;
	case NFTNL_RULESET_CTX_CHAIN:
		ctx->chain = data;
		break;
	case NFTNL_RULESET_CTX_RULE:
		ctx->rule = data;
		break;
	case NFTNL_RULESET_CTX_SET:
		ctx->set = data;
		break;
	case NFTNL_RULESET_CTX_DATA:
		ctx->data = data;
		break;
	}
	ctx->flags |= (1 << attr);
}

static void nftnl_ruleset_ctx_set_u32(struct nftnl_parse_ctx *ctx, uint16_t attr,
				    uint32_t val)
{
	nftnl_ruleset_ctx_set(ctx, attr, &val);
}

static int nftnl_ruleset_parse_tables(struct nftnl_parse_ctx *ctx,
				    struct nftnl_parse_err *err)
{
	struct nftnl_table *table;

	table = nftnl_table_alloc();
	if (table == NULL)
		return -1;

	switch (ctx->format) {
	case NFTNL_OUTPUT_JSON:
#ifdef JSON_PARSING
		if (nftnl_jansson_parse_table(table, ctx->json, err) < 0)
			goto err;
#endif
		break;
	case NFTNL_OUTPUT_XML:
#ifdef XML_PARSING
		if (nftnl_mxml_table_parse(ctx->xml, table, err) < 0)
			goto err;
#endif
		break;
	default:
		errno = EOPNOTSUPP;
		goto err;
	}

	nftnl_ruleset_ctx_set_u32(ctx, NFTNL_RULESET_CTX_TYPE, NFTNL_RULESET_TABLE);
	nftnl_ruleset_ctx_set(ctx, NFTNL_RULESET_CTX_TABLE, table);
	if (ctx->cb(ctx) < 0)
		goto err;

	return 0;
err:
	nftnl_table_free(table);
	return -1;
}

static int nftnl_ruleset_parse_chains(struct nftnl_parse_ctx *ctx,
				    struct nftnl_parse_err *err)
{
	struct nftnl_chain *chain;

	chain = nftnl_chain_alloc();
	if (chain == NULL)
		return -1;

	switch (ctx->format) {
	case NFTNL_OUTPUT_JSON:
#ifdef JSON_PARSING
		if (nftnl_jansson_parse_chain(chain, ctx->json, err) < 0)
			goto err;
#endif
		break;
	case NFTNL_OUTPUT_XML:
#ifdef XML_PARSING
		if (nftnl_mxml_chain_parse(ctx->xml, chain, err) < 0)
			goto err;
#endif
		break;
	default:
		errno = EOPNOTSUPP;
		goto err;
	}

	nftnl_ruleset_ctx_set_u32(ctx, NFTNL_RULESET_CTX_TYPE, NFTNL_RULESET_CHAIN);
	nftnl_ruleset_ctx_set(ctx, NFTNL_RULESET_CTX_CHAIN, chain);
	if (ctx->cb(ctx) < 0)
		goto err;

	return 0;
err:
	nftnl_chain_free(chain);
	return -1;
}

static int nftnl_ruleset_parse_set(struct nftnl_parse_ctx *ctx,
				 struct nftnl_set *set, uint32_t type,
				 struct nftnl_parse_err *err)
{
	struct nftnl_set *newset;

	nftnl_set_set_u32(set, NFTNL_SET_ID, ctx->set_id++);

	newset = nftnl_set_clone(set);
	if (newset == NULL)
		goto err;

	nftnl_set_list_add_tail(newset, ctx->set_list);

	nftnl_ruleset_ctx_set_u32(ctx, NFTNL_RULESET_CTX_TYPE, type);
	nftnl_ruleset_ctx_set(ctx, NFTNL_RULESET_CTX_SET, set);
	if (ctx->cb(ctx) < 0)
		goto err;

	return 0;
err:
	return -1;
}

static int nftnl_ruleset_parse_set_elems(struct nftnl_parse_ctx *ctx,
				       struct nftnl_parse_err *err)
{
	struct nftnl_set *set;

	set = nftnl_set_alloc();
	if (set == NULL)
		return -1;

	switch (ctx->format) {
	case NFTNL_OUTPUT_JSON:
#ifdef JSON_PARSING
		if (nftnl_jansson_parse_elem(set, ctx->json, err) < 0)
			goto err;
#endif
		break;
	case NFTNL_OUTPUT_XML:
#ifdef XML_PARSING
		if (nftnl_mxml_set_parse(ctx->xml, set, err) < 0)
			goto err;
#endif
		break;
	default:
		errno = EOPNOTSUPP;
		goto err;
	}

	if (nftnl_ruleset_parse_set(ctx, set, NFTNL_RULESET_SET_ELEMS, err) < 0)
		goto err;

	return 0;
err:
	nftnl_set_free(set);
	return -1;
}

static int nftnl_ruleset_parse_sets(struct nftnl_parse_ctx *ctx,
				  struct nftnl_parse_err *err)
{
	struct nftnl_set *set;

	set = nftnl_set_alloc();
	if (set == NULL)
		return -1;

	switch (ctx->format) {
	case NFTNL_OUTPUT_JSON:
#ifdef JSON_PARSING
		if (nftnl_jansson_parse_set(set, ctx->json, err) < 0)
			goto err;
#endif
		break;
	case NFTNL_OUTPUT_XML:
#ifdef XML_PARSING
		if (nftnl_mxml_set_parse(ctx->xml, set, err) < 0)
			goto err;
#endif
		break;
	default:
		errno = EOPNOTSUPP;
		goto err;
	}

	if (nftnl_ruleset_parse_set(ctx, set, NFTNL_RULESET_SET, err) < 0)
		goto err;

	return 0;
err:
	nftnl_set_free(set);
	return -1;
}

static int nftnl_ruleset_parse_rules(struct nftnl_parse_ctx *ctx,
				   struct nftnl_parse_err *err)
{
	struct nftnl_rule *rule;

	rule = nftnl_rule_alloc();
	if (rule == NULL)
		return -1;

	switch (ctx->format) {
	case NFTNL_OUTPUT_JSON:
#ifdef JSON_PARSING
		if (nftnl_jansson_parse_rule(rule, ctx->json, err,
					   ctx->set_list) < 0)
			goto err;
#endif
		break;
	case NFTNL_OUTPUT_XML:
#ifdef XML_PARSING
		if (nftnl_mxml_rule_parse(ctx->xml, rule, err, ctx->set_list) < 0)
			goto err;
#endif
		break;
	default:
		errno = EOPNOTSUPP;
		goto err;
	}

	nftnl_ruleset_ctx_set_u32(ctx, NFTNL_RULESET_CTX_TYPE, NFTNL_RULESET_RULE);
	nftnl_ruleset_ctx_set(ctx, NFTNL_RULESET_CTX_RULE, rule);
	if (ctx->cb(ctx) < 0)
		goto err;

	return 0;
err:
	nftnl_rule_free(rule);
	return -1;
}
#endif

#ifdef JSON_PARSING
static int nftnl_ruleset_json_parse_ruleset(struct nftnl_parse_ctx *ctx,
					  struct nftnl_parse_err *err)
{
	json_t *node, *array = ctx->json;
	int len, i, ret;

	len = json_array_size(array);
	for (i = 0; i < len; i++) {
		node = json_array_get(array, i);
		if (node == NULL) {
			errno = EINVAL;
			return -1;
		}

		ctx->json = node;
		if (nftnl_jansson_node_exist(node, "table"))
			ret = nftnl_ruleset_parse_tables(ctx, err);
		else if (nftnl_jansson_node_exist(node, "chain"))
			ret = nftnl_ruleset_parse_chains(ctx, err);
		else if (nftnl_jansson_node_exist(node, "set"))
			ret = nftnl_ruleset_parse_sets(ctx, err);
		else if (nftnl_jansson_node_exist(node, "rule"))
			ret = nftnl_ruleset_parse_rules(ctx, err);
		else if (nftnl_jansson_node_exist(node, "element"))
			ret = nftnl_ruleset_parse_set_elems(ctx, err);
		else
			return -1;

		if (ret < 0)
			return ret;
	}

	if (len == 0 && ctx->cmd == NFTNL_CMD_FLUSH) {
		nftnl_ruleset_ctx_set_u32(ctx, NFTNL_RULESET_CTX_TYPE,
					NFTNL_RULESET_RULESET);
		if (ctx->cb(ctx) < 0)
			return -1;
	}

	return 0;
}

static int nftnl_ruleset_json_parse_cmd(const char *cmd,
				      struct nftnl_parse_err *err,
				      struct nftnl_parse_ctx *ctx)
{
	uint32_t cmdnum;
	json_t *nodecmd;

	cmdnum = nftnl_str2cmd(cmd);
	if (cmdnum == NFTNL_CMD_UNSPEC) {
		err->error = NFTNL_PARSE_EMISSINGNODE;
		err->node_name = strdup(cmd);
		return -1;
	}

	nftnl_ruleset_ctx_set_u32(ctx, NFTNL_RULESET_CTX_CMD, cmdnum);

	nodecmd = json_object_get(ctx->json, cmd);
	if (nodecmd == NULL)
		return 0;

	ctx->json = nodecmd;
	if (nftnl_ruleset_json_parse_ruleset(ctx, err) != 0)
		goto err;

	return 0;
err:
	return -1;
}
#endif

static int nftnl_ruleset_json_parse(const void *json,
				  struct nftnl_parse_err *err,
				  enum nftnl_parse_input input,
				  enum nftnl_parse_type type, void *arg,
				  int (*cb)(const struct nftnl_parse_ctx *ctx))
{
#ifdef JSON_PARSING
	json_t *root, *array, *node;
	json_error_t error;
	int i, len;
	const char *key;
	struct nftnl_parse_ctx ctx;

	ctx.cb = cb;
	ctx.format = type;

	ctx.set_list = nftnl_set_list_alloc();
	if (ctx.set_list == NULL)
		return -1;

	if (arg != NULL)
		nftnl_ruleset_ctx_set(&ctx, NFTNL_RULESET_CTX_DATA, arg);

	root = nftnl_jansson_create_root(json, &error, err, input);
	if (root == NULL)
		goto err1;

	array = json_object_get(root, "nftables");
	if (array == NULL) {
		errno = EINVAL;
		goto err2;
	}

	len = json_array_size(array);
	for (i = 0; i < len; i++) {
		node = json_array_get(array, i);
		if (node == NULL) {
			errno = EINVAL;
			goto err2;
		}
		ctx.json = node;
		key = json_object_iter_key(json_object_iter(node));
		if (key == NULL)
			goto err2;

		if (nftnl_ruleset_json_parse_cmd(key, err, &ctx) < 0)
			goto err2;
	}

	nftnl_set_list_free(ctx.set_list);
	nftnl_jansson_free_root(root);
	return 0;
err2:
	nftnl_jansson_free_root(root);
err1:
	nftnl_set_list_free(ctx.set_list);
	return -1;
#else
	errno = EOPNOTSUPP;
	return -1;
#endif
}

#ifdef XML_PARSING
static int nftnl_ruleset_xml_parse_ruleset(struct nftnl_parse_ctx *ctx,
					 struct nftnl_parse_err *err)
{
	const char *node_type;
	mxml_node_t *node, *array = ctx->xml;
	int len = 0, ret;

	for (node = mxmlFindElement(array, array, NULL, NULL, NULL,
				    MXML_DESCEND_FIRST);
	     node != NULL;
	     node = mxmlFindElement(node, array, NULL, NULL, NULL,
				    MXML_NO_DESCEND)) {
		len++;
		node_type = node->value.opaque;
		ctx->xml = node;
		if (strcmp(node_type, "table") == 0)
			ret = nftnl_ruleset_parse_tables(ctx, err);
		else if (strcmp(node_type, "chain") == 0)
			ret = nftnl_ruleset_parse_chains(ctx, err);
		else if (strcmp(node_type, "set") == 0)
			ret = nftnl_ruleset_parse_sets(ctx, err);
		else if (strcmp(node_type, "rule") == 0)
			ret = nftnl_ruleset_parse_rules(ctx, err);
		else if (strcmp(node_type, "element") == 0)
			ret = nftnl_ruleset_parse_set_elems(ctx, err);
		else
			return -1;

		if (ret < 0)
			return ret;
	}

	if (len == 0 && ctx->cmd == NFTNL_CMD_FLUSH) {
		nftnl_ruleset_ctx_set_u32(ctx, NFTNL_RULESET_CTX_TYPE,
					NFTNL_RULESET_RULESET);
		if (ctx->cb(ctx) < 0)
			return -1;
	}

	return 0;
}

static int nftnl_ruleset_xml_parse_cmd(const char *cmd, struct nftnl_parse_err *err,
				     struct nftnl_parse_ctx *ctx)
{
	uint32_t cmdnum;
	mxml_node_t *nodecmd;

	cmdnum = nftnl_str2cmd(cmd);
	if (cmdnum == NFTNL_CMD_UNSPEC) {
		err->error = NFTNL_PARSE_EMISSINGNODE;
		err->node_name = strdup(cmd);
		return -1;
	}

	nodecmd = mxmlFindElement(ctx->xml, ctx->xml, cmd, NULL, NULL,
				  MXML_DESCEND_FIRST);

	ctx->xml = nodecmd;
	nftnl_ruleset_ctx_set_u32(ctx, NFTNL_RULESET_CTX_CMD, cmdnum);

	if (nftnl_ruleset_xml_parse_ruleset(ctx, err) != 0)
		goto err;

	return 0;
err:
	return -1;
}
#endif

static int nftnl_ruleset_xml_parse(const void *xml, struct nftnl_parse_err *err,
				 enum nftnl_parse_input input,
				 enum nftnl_parse_type type, void *arg,
				 int (*cb)(const struct nftnl_parse_ctx *ctx))
{
#ifdef XML_PARSING
	mxml_node_t *tree, *nodecmd = NULL;
	char *cmd;
	struct nftnl_parse_ctx ctx;

	ctx.cb = cb;
	ctx.format = type;

	ctx.set_list = nftnl_set_list_alloc();
	if (ctx.set_list == NULL)
		return -1;

	if (arg != NULL)
		nftnl_ruleset_ctx_set(&ctx, NFTNL_RULESET_CTX_DATA, arg);

	tree = nftnl_mxml_build_tree(xml, "nftables", err, input);
	if (tree == NULL)
		goto err1;

	ctx.xml = tree;

	nodecmd = mxmlWalkNext(tree, tree, MXML_DESCEND_FIRST);
	while (nodecmd != NULL) {
		cmd = nodecmd->value.opaque;
		if (nftnl_ruleset_xml_parse_cmd(cmd, err, &ctx) < 0)
			goto err2;
		nodecmd = mxmlWalkNext(tree, tree, MXML_NO_DESCEND);
	}

	nftnl_set_list_free(ctx.set_list);
	mxmlDelete(tree);
	return 0;
err2:
	mxmlDelete(tree);
err1:
	nftnl_set_list_free(ctx.set_list);
	return -1;
#else
	errno = EOPNOTSUPP;
	return -1;
#endif
}

static int
nftnl_ruleset_do_parse(enum nftnl_parse_type type, const void *data,
		     struct nftnl_parse_err *err, enum nftnl_parse_input input,
		     void *arg, int (*cb)(const struct nftnl_parse_ctx *ctx))
{
	int ret;

	switch (type) {
	case NFTNL_PARSE_XML:
		ret = nftnl_ruleset_xml_parse(data, err, input, type, arg, cb);
		break;
	case NFTNL_PARSE_JSON:
		ret = nftnl_ruleset_json_parse(data, err, input, type, arg, cb);
		break;
	default:
		ret = -1;
		errno = EOPNOTSUPP;
		break;
	}

	return ret;
}

int nftnl_ruleset_parse_file_cb(enum nftnl_parse_type type, FILE *fp,
			      struct nftnl_parse_err *err, void *data,
			      int (*cb)(const struct nftnl_parse_ctx *ctx))
{
	return nftnl_ruleset_do_parse(type, fp, err, NFTNL_PARSE_FILE, data, cb);
}
EXPORT_SYMBOL_ALIAS(nftnl_ruleset_parse_file_cb, nft_ruleset_parse_file_cb);

int nftnl_ruleset_parse_buffer_cb(enum nftnl_parse_type type, const char *buffer,
				struct nftnl_parse_err *err, void *data,
				int (*cb)(const struct nftnl_parse_ctx *ctx))
{
	return nftnl_ruleset_do_parse(type, buffer, err, NFTNL_PARSE_BUFFER, data,
				    cb);
}
EXPORT_SYMBOL_ALIAS(nftnl_ruleset_parse_buffer_cb, nft_ruleset_parse_buffer_cb);

static int nftnl_ruleset_cb(const struct nftnl_parse_ctx *ctx)
{
	struct nftnl_ruleset *r = ctx->data;

	if (ctx->cmd != NFTNL_CMD_ADD)
		return -1;

	switch (ctx->type) {
	case NFTNL_RULESET_TABLE:
		if (r->table_list == NULL) {
			r->table_list = nftnl_table_list_alloc();
			if (r->table_list == NULL)
				return -1;

			nftnl_ruleset_set(r, NFTNL_RULESET_TABLELIST,
					     r->table_list);
		}
		nftnl_table_list_add_tail(ctx->table, r->table_list);
		break;
	case NFTNL_RULESET_CHAIN:
		if (r->chain_list == NULL) {
			r->chain_list = nftnl_chain_list_alloc();
			if (r->chain_list == NULL)
				return -1;

			nftnl_ruleset_set(r, NFTNL_RULESET_CHAINLIST,
					     r->chain_list);
		}
		nftnl_chain_list_add_tail(ctx->chain, r->chain_list);
		break;
	case NFTNL_RULESET_SET:
		if (r->set_list == NULL) {
			r->set_list = nftnl_set_list_alloc();
			if (r->set_list == NULL)
				return -1;

			nftnl_ruleset_set(r, NFTNL_RULESET_SETLIST,
					     r->set_list);
		}
		nftnl_set_list_add_tail(ctx->set, r->set_list);
		break;
	case NFTNL_RULESET_RULE:
		if (r->rule_list == NULL) {
			r->rule_list = nftnl_rule_list_alloc();
			if (r->rule_list == NULL)
				return -1;

			nftnl_ruleset_set(r, NFTNL_RULESET_RULELIST,
					     r->rule_list);
		}
		nftnl_rule_list_add_tail(ctx->rule, r->rule_list);
		break;
	case NFTNL_RULESET_RULESET:
		break;
	default:
		return -1;
	}

	return 0;
}

int nftnl_ruleset_parse(struct nftnl_ruleset *r, enum nftnl_parse_type type,
		      const char *data, struct nftnl_parse_err *err)
{
	return nftnl_ruleset_parse_buffer_cb(type, data, err, r, nftnl_ruleset_cb);
}
EXPORT_SYMBOL_ALIAS(nftnl_ruleset_parse, nft_ruleset_parse);

int nftnl_ruleset_parse_file(struct nftnl_ruleset *rs, enum nftnl_parse_type type,
			   FILE *fp, struct nftnl_parse_err *err)
{
	return nftnl_ruleset_parse_file_cb(type, fp, err, rs, nftnl_ruleset_cb);
}
EXPORT_SYMBOL_ALIAS(nftnl_ruleset_parse_file, nft_ruleset_parse_file);

static const char *nftnl_ruleset_o_opentag(uint32_t type)
{
	switch (type) {
	case NFTNL_OUTPUT_XML:
		return "<nftables>";
	case NFTNL_OUTPUT_JSON:
		return "{\"nftables\":[";
	default:
		return "";
	}
}

static const char *nftnl_ruleset_o_separator(void *obj, uint32_t type)
{
	if (obj == NULL)
		return "";

	switch (type) {
	case NFTNL_OUTPUT_JSON:
		return ",";
	case NFTNL_OUTPUT_DEFAULT:
		return "\n";
	default:
		return "";
	}
}

static const char *nftnl_ruleset_o_closetag(uint32_t type)
{
	switch (type) {
	case NFTNL_OUTPUT_XML:
		return "</nftables>";
	case NFTNL_OUTPUT_JSON:
		return "]}";
	default:
		return "";
	}
}

static int
nftnl_ruleset_snprintf_table(char *buf, size_t size,
			   const struct nftnl_ruleset *rs, uint32_t type,
			   uint32_t flags)
{
	struct nftnl_table *t;
	struct nftnl_table_list_iter *ti;
	int ret, len = size, offset = 0;

	ti = nftnl_table_list_iter_create(rs->table_list);
	if (ti == NULL)
		return 0;

	t = nftnl_table_list_iter_next(ti);
	while (t != NULL) {
		ret = nftnl_table_snprintf(buf+offset, len, t, type, flags);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

		t = nftnl_table_list_iter_next(ti);

		ret = snprintf(buf+offset, len, "%s",
			       nftnl_ruleset_o_separator(t, type));
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}
	nftnl_table_list_iter_destroy(ti);

	return offset;
}

static int
nftnl_ruleset_snprintf_chain(char *buf, size_t size,
			   const struct nftnl_ruleset *rs, uint32_t type,
			   uint32_t flags)
{
	struct nftnl_chain *c;
	struct nftnl_chain_list_iter *ci;
	int ret, len = size, offset = 0;

	ci = nftnl_chain_list_iter_create(rs->chain_list);
	if (ci == NULL)
		return 0;

	c = nftnl_chain_list_iter_next(ci);
	while (c != NULL) {
		ret = nftnl_chain_snprintf(buf+offset, len, c, type, flags);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

		c = nftnl_chain_list_iter_next(ci);

		ret = snprintf(buf+offset, len, "%s",
			       nftnl_ruleset_o_separator(c, type));
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}
	nftnl_chain_list_iter_destroy(ci);

	return offset;
}

static int
nftnl_ruleset_snprintf_set(char *buf, size_t size,
			 const struct nftnl_ruleset *rs, uint32_t type,
			 uint32_t flags)
{
	struct nftnl_set *s;
	struct nftnl_set_list_iter *si;
	int ret, len = size, offset = 0;

	si = nftnl_set_list_iter_create(rs->set_list);
	if (si == NULL)
		return 0;

	s = nftnl_set_list_iter_next(si);
	while (s != NULL) {
		ret = nftnl_set_snprintf(buf+offset, len, s, type, flags);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

		s = nftnl_set_list_iter_next(si);

		ret = snprintf(buf+offset, len, "%s",
			       nftnl_ruleset_o_separator(s, type));
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}
	nftnl_set_list_iter_destroy(si);

	return offset;
}

static int
nftnl_ruleset_snprintf_rule(char *buf, size_t size,
			  const struct nftnl_ruleset *rs, uint32_t type,
			  uint32_t flags)
{
	struct nftnl_rule *r;
	struct nftnl_rule_list_iter *ri;
	int ret, len = size, offset = 0;

	ri = nftnl_rule_list_iter_create(rs->rule_list);
	if (ri == NULL)
		return 0;

	r = nftnl_rule_list_iter_next(ri);
	while (r != NULL) {
		ret = nftnl_rule_snprintf(buf+offset, len, r, type, flags);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

		r = nftnl_rule_list_iter_next(ri);

		ret = snprintf(buf+offset, len, "%s",
			       nftnl_ruleset_o_separator(r, type));
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}
	nftnl_rule_list_iter_destroy(ri);

	return offset;
}

static int
nftnl_ruleset_do_snprintf(char *buf, size_t size, const struct nftnl_ruleset *rs,
			uint32_t cmd, uint32_t type, uint32_t flags)
{
	int ret, len = size, offset = 0;
	void *prev = NULL;
	uint32_t inner_flags = flags;

	/* dont pass events flags to child calls of _snprintf() */
	inner_flags &= ~NFTNL_OF_EVENT_ANY;

	ret = snprintf(buf + offset, len, "%s", nftnl_ruleset_o_opentag(type));
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	ret = nftnl_cmd_header_snprintf(buf + offset, len, cmd, type, flags);
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	if (nftnl_ruleset_is_set(rs, NFTNL_RULESET_TABLELIST) &&
	    (!nftnl_table_list_is_empty(rs->table_list))) {
		ret = nftnl_ruleset_snprintf_table(buf+offset, len, rs,
						 type, inner_flags);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

		if (ret > 0)
			prev = rs->table_list;
	}

	if (nftnl_ruleset_is_set(rs, NFTNL_RULESET_CHAINLIST) &&
	    (!nftnl_chain_list_is_empty(rs->chain_list))) {
		ret = snprintf(buf+offset, len, "%s",
			       nftnl_ruleset_o_separator(prev, type));
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

		ret = nftnl_ruleset_snprintf_chain(buf+offset, len, rs,
						 type, inner_flags);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

		if (ret > 0)
			prev = rs->chain_list;
	}

	if (nftnl_ruleset_is_set(rs, NFTNL_RULESET_SETLIST) &&
	    (!nftnl_set_list_is_empty(rs->set_list))) {
		ret = snprintf(buf+offset, len, "%s",
			       nftnl_ruleset_o_separator(prev, type));
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

		ret = nftnl_ruleset_snprintf_set(buf+offset, len, rs,
					       type, inner_flags);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

		if (ret > 0)
			prev = rs->set_list;
	}

	if (nftnl_ruleset_is_set(rs, NFTNL_RULESET_RULELIST) &&
	    (!nftnl_rule_list_is_empty(rs->rule_list))) {
		ret = snprintf(buf+offset, len, "%s",
			       nftnl_ruleset_o_separator(prev, type));
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

		ret = nftnl_ruleset_snprintf_rule(buf+offset, len, rs,
						type, inner_flags);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	ret = nftnl_cmd_footer_snprintf(buf + offset, len, cmd, type, flags);
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	ret = snprintf(buf + offset, len, "%s", nftnl_ruleset_o_closetag(type));
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	return offset;
}

static int nftnl_ruleset_cmd_snprintf(char *buf, size_t size,
				    const struct nftnl_ruleset *r, uint32_t cmd,
				    uint32_t type, uint32_t flags)
{
	switch (type) {
	case NFTNL_OUTPUT_DEFAULT:
	case NFTNL_OUTPUT_XML:
	case NFTNL_OUTPUT_JSON:
		return nftnl_ruleset_do_snprintf(buf, size, r, cmd, type, flags);
	default:
		errno = EOPNOTSUPP;
		return -1;
	}
}

int nftnl_ruleset_snprintf(char *buf, size_t size, const struct nftnl_ruleset *r,
			 uint32_t type, uint32_t flags)
{
	switch (type) {
	case NFTNL_OUTPUT_DEFAULT:
	case NFTNL_OUTPUT_XML:
	case NFTNL_OUTPUT_JSON:
		return nftnl_ruleset_cmd_snprintf(buf, size, r,
						nftnl_flag2cmd(flags), type,
						flags);
	default:
		errno = EOPNOTSUPP;
		return -1;
	}
}
EXPORT_SYMBOL_ALIAS(nftnl_ruleset_snprintf, nft_ruleset_snprintf);

static int nftnl_ruleset_fprintf_tables(FILE *fp, const struct nftnl_ruleset *rs,
				      uint32_t type, uint32_t flags)
{
	int len = 0, ret = 0;
	struct nftnl_table *t;
	struct nftnl_table_list_iter *ti;

	ti = nftnl_table_list_iter_create(rs->table_list);
	if (ti == NULL)
		return -1;

	t = nftnl_table_list_iter_next(ti);
	while (t != NULL) {
		ret = nftnl_table_fprintf(fp, t, type, flags);
		if (ret < 0)
			goto err;

		len += ret;

		t = nftnl_table_list_iter_next(ti);

		ret = fprintf(fp, "%s", nftnl_ruleset_o_separator(t, type));
		if (ret < 0)
			goto err;

		len += ret;
	}
	nftnl_table_list_iter_destroy(ti);

	return len;
err:
	nftnl_table_list_iter_destroy(ti);
	return -1;
}

static int nftnl_ruleset_fprintf_chains(FILE *fp, const struct nftnl_ruleset *rs,
				      uint32_t type, uint32_t flags)
{
	int len = 0, ret = 0;
	struct nftnl_chain *o;
	struct nftnl_chain_list_iter *i;

	i = nftnl_chain_list_iter_create(rs->chain_list);
	if (i == NULL)
		return -1;

	o = nftnl_chain_list_iter_next(i);
	while (o != NULL) {
		ret = nftnl_chain_fprintf(fp, o, type, flags);
		if (ret < 0)
			goto err;

		len += ret;

		o = nftnl_chain_list_iter_next(i);

		ret = fprintf(fp, "%s", nftnl_ruleset_o_separator(o, type));
		if (ret < 0)
			goto err;

		len += ret;
	}
	nftnl_chain_list_iter_destroy(i);

	return len;
err:
	nftnl_chain_list_iter_destroy(i);
	return -1;
}

static int nftnl_ruleset_fprintf_sets(FILE *fp, const struct nftnl_ruleset *rs,
				    uint32_t type, uint32_t flags)
{
	int len = 0, ret = 0;
	struct nftnl_set *o;
	struct nftnl_set_list_iter *i;

	i = nftnl_set_list_iter_create(rs->set_list);
	if (i == NULL)
		return -1;

	o = nftnl_set_list_iter_next(i);
	while (o != NULL) {
		ret = nftnl_set_fprintf(fp, o, type, flags);
		if (ret < 0)
			goto err;

		len += ret;

		o = nftnl_set_list_iter_next(i);

		ret = fprintf(fp, "%s", nftnl_ruleset_o_separator(o, type));
		if (ret < 0)
			goto err;

		len += ret;
	}
	nftnl_set_list_iter_destroy(i);

	return len;
err:
	nftnl_set_list_iter_destroy(i);
	return -1;
}

static int nftnl_ruleset_fprintf_rules(FILE *fp, const struct nftnl_ruleset *rs,
				    uint32_t type, uint32_t flags)
{
	int len = 0, ret = 0;
	struct nftnl_rule *o;
	struct nftnl_rule_list_iter *i;

	i = nftnl_rule_list_iter_create(rs->rule_list);
	if (i == NULL)
		return -1;

	o = nftnl_rule_list_iter_next(i);
	while (o != NULL) {
		ret = nftnl_rule_fprintf(fp, o, type, flags);
		if (ret < 0)
			goto err;

		len += ret;

		o = nftnl_rule_list_iter_next(i);

		ret = fprintf(fp, "%s", nftnl_ruleset_o_separator(o, type));
		if (ret < 0)
			goto err;

		len += ret;
	}
	nftnl_rule_list_iter_destroy(i);

	return len;
err:
	nftnl_rule_list_iter_destroy(i);
	return -1;
}

#define NFTNL_FPRINTF_RETURN_OR_FIXLEN(ret, len)	\
	if (ret < 0)				\
		return -1;			\
	len += ret;

static int nftnl_ruleset_cmd_fprintf(FILE *fp, const struct nftnl_ruleset *rs,
				   uint32_t cmd, uint32_t type, uint32_t flags)
{
	int len = 0, ret = 0;
	void *prev = NULL;
	uint32_t inner_flags = flags;

	/* dont pass events flags to child calls of _snprintf() */
	inner_flags &= ~NFTNL_OF_EVENT_ANY;

	ret = fprintf(fp, "%s", nftnl_ruleset_o_opentag(type));
	NFTNL_FPRINTF_RETURN_OR_FIXLEN(ret, len);

	ret = nftnl_cmd_header_fprintf(fp, cmd, type, flags);
	NFTNL_FPRINTF_RETURN_OR_FIXLEN(ret, len);

	if ((nftnl_ruleset_is_set(rs, NFTNL_RULESET_TABLELIST)) &&
	    (!nftnl_table_list_is_empty(rs->table_list))) {
		ret = nftnl_ruleset_fprintf_tables(fp, rs, type, inner_flags);
		NFTNL_FPRINTF_RETURN_OR_FIXLEN(ret, len);

		if (ret > 0)
			prev = rs->table_list;
	}

	if ((nftnl_ruleset_is_set(rs, NFTNL_RULESET_CHAINLIST)) &&
	    (!nftnl_chain_list_is_empty(rs->chain_list))) {
		ret = fprintf(fp, "%s", nftnl_ruleset_o_separator(prev, type));
		NFTNL_FPRINTF_RETURN_OR_FIXLEN(ret, len);

		ret = nftnl_ruleset_fprintf_chains(fp, rs, type, inner_flags);
		NFTNL_FPRINTF_RETURN_OR_FIXLEN(ret, len);

		if (ret > 0)
			prev = rs->chain_list;
	}

	if ((nftnl_ruleset_is_set(rs, NFTNL_RULESET_SETLIST)) &&
	    (!nftnl_set_list_is_empty(rs->set_list))) {
		ret = fprintf(fp, "%s", nftnl_ruleset_o_separator(prev, type));
		NFTNL_FPRINTF_RETURN_OR_FIXLEN(ret, len);

		ret = nftnl_ruleset_fprintf_sets(fp, rs, type, inner_flags);
		NFTNL_FPRINTF_RETURN_OR_FIXLEN(ret, len);

		if (ret > 0)
			prev = rs->set_list;
	}

	if ((nftnl_ruleset_is_set(rs, NFTNL_RULESET_RULELIST)) &&
	    (!nftnl_rule_list_is_empty(rs->rule_list))) {
		ret = fprintf(fp, "%s", nftnl_ruleset_o_separator(prev, type));
		NFTNL_FPRINTF_RETURN_OR_FIXLEN(ret, len);

		ret = nftnl_ruleset_fprintf_rules(fp, rs, type, inner_flags);
		NFTNL_FPRINTF_RETURN_OR_FIXLEN(ret, len);
	}

	ret = nftnl_cmd_footer_fprintf(fp, cmd, type, flags);
	NFTNL_FPRINTF_RETURN_OR_FIXLEN(ret, len);

	ret = fprintf(fp, "%s", nftnl_ruleset_o_closetag(type));
	NFTNL_FPRINTF_RETURN_OR_FIXLEN(ret, len);

	return len;
}

int nftnl_ruleset_fprintf(FILE *fp, const struct nftnl_ruleset *rs, uint32_t type,
			uint32_t flags)
{
	return nftnl_ruleset_cmd_fprintf(fp, rs, nftnl_flag2cmd(flags), type,
				       flags);
}
EXPORT_SYMBOL_ALIAS(nftnl_ruleset_fprintf, nft_ruleset_fprintf);
