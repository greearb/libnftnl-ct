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

static int nftnl_jansson_load_int_node(json_t *root, const char *node_name,
				      json_int_t *val, struct nftnl_parse_err *err)
{
	json_t *node;

	node = json_object_get(root, node_name);
	if (node == NULL) {
		err->error = NFTNL_PARSE_EMISSINGNODE;
		err->node_name = node_name;
		errno = EINVAL;
		return -1;
	}

	if (!json_is_integer(node)) {
		err->error = NFTNL_PARSE_EBADTYPE;
		err->node_name = node_name;
		errno = ERANGE;
		return -1;
	}
	*val = json_integer_value(node);

	return 0;
}

const char *nftnl_jansson_parse_str(json_t *root, const char *node_name,
				  struct nftnl_parse_err *err)
{
	json_t *node;
	const char *val;

	node = json_object_get(root, node_name);
	if (node == NULL) {
		err->error = NFTNL_PARSE_EMISSINGNODE;
		err->node_name = node_name;
		errno = EINVAL;
		return NULL;
	}

	val = json_string_value(node);
	if (val == NULL) {
		err->error = NFTNL_PARSE_EBADTYPE;
		err->node_name = node_name;
	}

	return val;
}

int nftnl_jansson_parse_val(json_t *root, const char *node_name, int type,
			  void *out, struct nftnl_parse_err *err)
{
	json_int_t val;

	if (nftnl_jansson_load_int_node(root, node_name, &val, err) == -1)
		return -1;

	if (nftnl_get_value(type, &val, out) == -1)
		return -1;

	return 0;
}

bool nftnl_jansson_node_exist(json_t *root, const char *node_name)
{
	return json_object_get(root, node_name) != NULL;
}

json_t *nftnl_jansson_create_root(const void *json, json_error_t *error,
				struct nftnl_parse_err *err, enum nftnl_parse_input input)
{
	json_t *root;

	switch (input) {
	case NFTNL_PARSE_BUFFER:
		root = json_loadb(json, strlen(json), 0, error);
		break;
	case NFTNL_PARSE_FILE:
		root = json_loadf((FILE *)json, 0, error);
		break;
	default:
		goto err;
	}

	if (root == NULL) {
		err->error = NFTNL_PARSE_EBADINPUT;
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

json_t *nftnl_jansson_get_node(json_t *root, const char *node_name,
			     struct nftnl_parse_err *err)
{
	json_t *node;

	node = json_object_get(root, node_name);
	if (node == NULL) {
		err->error = NFTNL_PARSE_EMISSINGNODE;
		err->node_name = node_name;
		errno = EINVAL;
		return NULL;
	}

	return node;
}

void nftnl_jansson_free_root(json_t *root)
{
	json_decref(root);
}

int nftnl_jansson_parse_family(json_t *root, void *out, struct nftnl_parse_err *err)
{
	const char *str;
	int family;

	str = nftnl_jansson_parse_str(root, "family", err);
	if (str == NULL)
		return -1;

	family = nftnl_str2family(str);
	if (family < 0) {
		err->node_name = "family";
		errno = EINVAL;
		return -1;
	}

	memcpy(out, &family, sizeof(family));
	return 0;
}

int nftnl_jansson_parse_reg(json_t *root, const char *node_name, int type,
			  void *out, struct nftnl_parse_err *err)
{
	if (nftnl_jansson_parse_val(root, node_name, type, out, err) < 0)
		return -1;

	if (*((uint32_t *)out) > NFT_REG_MAX){
		errno = ERANGE;
		return -1;
	}

	return 0;
}

int nftnl_jansson_str2num(json_t *root, const char *node_name, int base,
			void *out, enum nftnl_type type, struct nftnl_parse_err *err)
{
	const char *str;

	str = nftnl_jansson_parse_str(root, node_name, err);
	if (str == NULL)
		return -1;

	return nftnl_strtoi(str, base, out, type);
}

struct nftnl_expr *nftnl_jansson_expr_parse(json_t *root,
					     struct nftnl_parse_err *err,
					     struct nftnl_set_list *set_list)
{
	struct nftnl_expr *e;
	const char *type;
	uint32_t set_id;
	int ret;

	type = nftnl_jansson_parse_str(root, "type", err);
	if (type == NULL)
		return NULL;

	e = nftnl_expr_alloc(type);
	if (e == NULL) {
		err->node_name = "type";
		return NULL;
	}

	ret = e->ops->json_parse(e, root, err);

	if (set_list != NULL &&
	    strcmp(type, "lookup") == 0 &&
	    nftnl_set_lookup_id(e, set_list, &set_id))
		nftnl_expr_set_u32(e, NFTNL_EXPR_LOOKUP_SET_ID, set_id);

	return ret < 0 ? NULL : e;
}

int nftnl_jansson_data_reg_parse(json_t *root, const char *node_name,
			       union nftnl_data_reg *data_reg,
			       struct nftnl_parse_err *err)
{
	json_t *data;
	int ret;

	 /* It is necessary for the compatibility with cmpdata label. */
	data = json_object_get(root, node_name);
	if (data == NULL)
		data = root;

	data = json_object_get(data, "reg");
	if (data == NULL) {
		err->error = NFTNL_PARSE_EMISSINGNODE;
		err->node_name = "reg";
		errno = EINVAL;
		return -1;
	}

	ret = nftnl_data_reg_json_parse(data_reg, data, err);
	if (ret == DATA_NONE) {
		errno = EINVAL;
		return -1;
	}

	return ret;
}

int nftnl_jansson_set_elem_parse(struct nftnl_set_elem *e, json_t *root,
			       struct nftnl_parse_err *err)
{
	int set_elem_data;
	uint32_t flags;

	if (nftnl_jansson_parse_val(root, "flags", NFTNL_TYPE_U32, &flags, err) == 0)
		nftnl_set_elem_set_u32(e, NFTNL_SET_ELEM_FLAGS, flags);

	if (nftnl_jansson_data_reg_parse(root, "key", &e->key, err) == DATA_VALUE)
		e->flags |= (1 << NFTNL_SET_ELEM_KEY);

	if (nftnl_jansson_node_exist(root, "data")) {
		set_elem_data = nftnl_jansson_data_reg_parse(root, "data",
							   &e->data, err);
		switch (set_elem_data) {
		case DATA_VALUE:
			e->flags |= (1 << NFTNL_SET_ELEM_DATA);
			break;
		case DATA_VERDICT:
			e->flags |= (1 << NFTNL_SET_ELEM_VERDICT);
			if (e->data.chain != NULL)
				e->flags |= (1 << NFTNL_SET_ELEM_CHAIN);
			break;
		case DATA_NONE:
		default:
			return -1;
		}
	}

	return 0;
}
#endif
