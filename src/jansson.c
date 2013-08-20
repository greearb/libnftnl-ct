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

#include <libnftables/expr.h>
#include <linux/netfilter/nf_tables.h>

#ifdef JSON_PARSING

static int nft_jansson_load_int_node(json_t *root, const char *tag,
				      json_int_t *val)
{
	json_t *node;

	node = json_object_get(root, tag);
	if (node == NULL) {
		errno = EINVAL;
		return -1;
	}

	if (!json_is_integer(node)) {
		errno = ERANGE;
		return -1;
	}
	*val = json_integer_value(node);

	return 0;
}

const char *nft_jansson_value_parse_str(json_t *root, const char *tag)
{
	json_t *node;
	const char *val;

	node = json_object_get(root, tag);
	if (node == NULL) {
		errno = EINVAL;
		return NULL;
	}
	val = json_string_value(node);

	return val;
}

int nft_jansson_value_parse_val(json_t *root, const char *tag, int type,
				  void *out)
{
	json_int_t val;

	if (nft_jansson_load_int_node(root, tag, &val) == -1)
		return -1;

	if (nft_get_value(type, &val, out) == -1)
		return -1;

	return 0;
}

bool nft_jansson_node_exist(json_t *root, const char *tag)
{
	return json_object_get(root, tag) != NULL;
}

json_t *nft_jansson_create_root(char *json, json_error_t *err)
{
	json_t *root;

	root = json_loadb(json, strlen(json), 0, err);
	if (root == NULL) {
		errno = EINVAL;
		return NULL;
	}

	return root;
}

json_t *nft_jansson_get_node(json_t *root, const char *tag)
{
	json_t *node;

	node = json_object_get(root, tag);
	if (node == NULL) {
		errno = EINVAL;
		return NULL;
	}

	return node;
}

void nft_jansson_free_root(json_t *root)
{
	json_decref(root);
}

int nft_jansson_parse_family(json_t *root, void *out)
{
	const char *str;
	int family;

	str = nft_jansson_value_parse_str(root, "family");
	if (str == NULL)
		return -1;

	family = nft_str2family(str);
	if (family < 0) {
		errno = EINVAL;
		return -1;
	}

	memcpy(out, &family, sizeof(family));
	return 0;
}

int nft_jansson_value_parse_reg(json_t *root, const char *tag, int type,
				void *out)
{
	if (nft_jansson_value_parse_val(root, tag, type, out) != 0)
		return -1;

	if (*((uint32_t *)out) > NFT_REG_MAX){
		errno = ERANGE;
		return -1;
	}

	return 0;
}

int nft_jansson_str2num(json_t *root, const char *tag, int base,
			void *out, enum nft_type type)
{
	const char *str;

	str = nft_jansson_value_parse_str(root, tag);
	if (str == NULL)
		return -1;

	return nft_strtoi(str, base, out, type);
}

struct nft_rule_expr *nft_jansson_expr_parse(json_t *root)
{
	struct nft_rule_expr *e;
	const char *type;
	int ret;

	type = nft_jansson_value_parse_str(root, "type");
	if (type == NULL)
		return NULL;

	e = nft_rule_expr_alloc(type);
	if (e == NULL)
		return NULL;;

	ret = e->ops->json_parse(e, root);

	return ret < 0 ? NULL : e;
}

int nft_jansson_data_reg_parse(json_t *root, const char *tag,
			       union nft_data_reg *data_reg)
{
	json_t *data;
	const char *type;
	int ret;

	data = json_object_get(root, tag);
	if (data == NULL) {
		errno = EINVAL;
		return -1;
	}

	data = json_object_get(data, "data_reg");
	if (data == NULL) {
		errno = EINVAL;
		return -1;
	}

	ret = nft_data_reg_json_parse(data_reg, data);

	if (ret < 0) {
		errno = EINVAL;
		return -1;
	}

	type = nft_jansson_value_parse_str(data, "type");
	if (type == NULL)
		return -1;

	if (strcmp(type, "value") == 0)
		return DATA_VALUE;
	else if (strcmp(type, "verdict") == 0)
		return DATA_VERDICT;
	else if (strcmp(type, "chain") == 0)
		return DATA_CHAIN;
	else {
		errno = EINVAL;
		return -1;
	}
}
#endif
