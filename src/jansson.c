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
		goto err;
	}

	*val = json_integer_value(node);

	return 0;
err:
	return -1;
}

const char *nft_jansson_value_parse_str(json_t *root, const char *tag)
{
	json_t *node;
	const char *val;

	node = json_object_get(root, tag);
	if (node == NULL)
		return NULL;

	val = json_string_value(node);

	return val;
}

int nft_jansson_value_parse_val(json_t *root, const char *tag, int type,
				  void *out)
{
	json_int_t val;

	if (nft_jansson_load_int_node(root, tag, &val) == -1)
		goto err;

	if (nft_get_value(type, &val, out) == -1)
		goto err;

	return 0;
err:
	errno = ERANGE;
	return -1;
}

bool nft_jansson_node_exist(json_t *root, const char *tag)
{
	return json_object_get(root, tag) != NULL;
}
#endif
