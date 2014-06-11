/*
 * (C) 2013 by Álvaro Neira Ayuso <alvaroneay@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <internal.h>
#include <stdlib.h>
#include <limits.h>
#include <stdint.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <errno.h>
#include <string.h>
#include "expr_ops.h"
#include <libnftnl/set.h>

#include <libnftnl/expr.h>
#include <linux/netfilter/nf_tables.h>

#ifdef JSON_PARSING

static int nft_jansson_load_int_node(json_t *root, const char *node_name,
				      json_int_t *val, struct nft_parse_err *err)
{
	json_t *node;

	node = json_object_get(root, node_name);
	if (node == NULL) {
		err->error = NFT_PARSE_EMISSINGNODE;
		err->node_name = node_name;
		errno = EINVAL;
		return -1;
	}

	if (!json_is_integer(node)) {
		err->error = NFT_PARSE_EBADTYPE;
		err->node_name = node_name;
		errno = ERANGE;
		return -1;
	}
	*val = json_integer_value(node);

	return 0;
}

const char *nft_jansson_parse_str(json_t *root, const char *node_name,
				  struct nft_parse_err *err)
{
	json_t *node;
	const char *val;

	node = json_object_get(root, node_name);
	if (node == NULL) {
		err->error = NFT_PARSE_EMISSINGNODE;
		err->node_name = node_name;
		errno = EINVAL;
		return NULL;
	}

	val = json_string_value(node);
	if (val == NULL) {
		err->error = NFT_PARSE_EBADTYPE;
		err->node_name = node_name;
	}

	return val;
}

int nft_jansson_parse_val(json_t *root, const char *node_name, int type,
			  void *out, struct nft_parse_err *err)
{
	json_int_t val;

	if (nft_jansson_load_int_node(root, node_name, &val, err) == -1)
		return -1;

	if (nft_get_value(type, &val, out) == -1)
		return -1;

	return 0;
}

bool nft_jansson_node_exist(json_t *root, const char *node_name)
{
	return json_object_get(root, node_name) != NULL;
}

json_t *nft_jansson_create_root(const void *json, json_error_t *error,
				struct nft_parse_err *err, enum nft_parse_input input)
{
	json_t *root;

	switch (input) {
	case NFT_PARSE_BUFFER:
		root = json_loadb(json, strlen(json), 0, error);
		break;
	case NFT_PARSE_FILE:
		root = json_loadf((FILE *)json, 0, error);
		break;
	default:
		goto err;
	}

	if (root == NULL) {
		err->error = NFT_PARSE_EBADINPUT;
		err->line = error->line;
		err->column = error->column;
		err->node_name = error->source;
		goto err;
	}

	return root;
err:
	errno = EINVAL;
	return NULL;
}

json_t *nft_jansson_get_node(json_t *root, const char *node_name,
			     struct nft_parse_err *err)
{
	json_t *node;

	node = json_object_get(root, node_name);
	if (node == NULL) {
		err->error = NFT_PARSE_EMISSINGNODE;
		err->node_name = node_name;
		errno = EINVAL;
		return NULL;
	}

	return node;
}

void nft_jansson_free_root(json_t *root)
{
	json_decref(root);
}

int nft_jansson_parse_family(json_t *root, void *out, struct nft_parse_err *err)
{
	const char *str;
	int family;

	str = nft_jansson_parse_str(root, "family", err);
	if (str == NULL)
		return -1;

	family = nft_str2family(str);
	if (family < 0) {
		err->node_name = "family";
		errno = EINVAL;
		return -1;
	}

	memcpy(out, &family, sizeof(family));
	return 0;
}

int nft_jansson_parse_reg(json_t *root, const char *node_name, int type,
			  void *out, struct nft_parse_err *err)
{
	if (nft_jansson_parse_val(root, node_name, type, out, err) < 0)
		return -1;

	if (*((uint32_t *)out) > NFT_REG_MAX){
		errno = ERANGE;
		return -1;
	}

	return 0;
}

int nft_jansson_str2num(json_t *root, const char *node_name, int base,
			void *out, enum nft_type type, struct nft_parse_err *err)
{
	const char *str;

	str = nft_jansson_parse_str(root, node_name, err);
	if (str == NULL)
		return -1;

	return nft_strtoi(str, base, out, type);
}

struct nft_rule_expr *nft_jansson_expr_parse(json_t *root,
					     struct nft_parse_err *err)
{
	struct nft_rule_expr *e;
	const char *type;
	int ret;

	type = nft_jansson_parse_str(root, "type", err);
	if (type == NULL)
		return NULL;

	e = nft_rule_expr_alloc(type);
	if (e == NULL) {
		err->node_name = "type";
		return NULL;
	}

	ret = e->ops->json_parse(e, root, err);

	return ret < 0 ? NULL : e;
}

int nft_jansson_data_reg_parse(json_t *root, const char *node_name,
			       union nft_data_reg *data_reg,
			       struct nft_parse_err *err)
{
	json_t *data;
	int ret;

	 /* It is necessary for the compatibility with cmpdata label. */
	data = json_object_get(root, node_name);
	if (data == NULL)
		data = root;

	data = json_object_get(data, "data_reg");
	if (data == NULL) {
		err->error = NFT_PARSE_EMISSINGNODE;
		err->node_name = "data_reg";
		errno = EINVAL;
		return -1;
	}

	ret = nft_data_reg_json_parse(data_reg, data, err);
	if (ret == DATA_NONE) {
		errno = EINVAL;
		return -1;
	}

	return ret;
}

int nft_jansson_set_elem_parse(struct nft_set_elem *e, json_t *root,
			       struct nft_parse_err *err)
{
	int set_elem_data;
	uint32_t flags;

	if (nft_jansson_parse_val(root, "flags", NFT_TYPE_U32, &flags, err) == 0)
		nft_set_elem_attr_set_u32(e, NFT_SET_ELEM_ATTR_FLAGS, flags);

	if (nft_jansson_data_reg_parse(root, "key", &e->key, err) == DATA_VALUE)
		e->flags |= (1 << NFT_SET_ELEM_ATTR_KEY);

	if (nft_jansson_node_exist(root, "data")) {
		set_elem_data = nft_jansson_data_reg_parse(root, "data",
							   &e->data, err);
		switch (set_elem_data) {
		case DATA_VALUE:
			e->flags |= (1 << NFT_SET_ELEM_ATTR_DATA);
			break;
		case DATA_VERDICT:
			e->flags |= (1 << NFT_SET_ELEM_ATTR_VERDICT);
			if (e->data.chain != NULL)
				e->flags |= (1 << NFT_SET_ELEM_ATTR_CHAIN);
			break;
		case DATA_NONE:
		default:
			return -1;
		}
	}

	return 0;
}
#endif
