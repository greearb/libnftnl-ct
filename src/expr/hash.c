/*
 * (C) 2016 by Laura Garcia <nevola@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include <errno.h>
#include <linux/netfilter/nf_tables.h>

#include "internal.h"
#include <libmnl/libmnl.h>
#include <libnftnl/expr.h>
#include <libnftnl/rule.h>

struct nftnl_expr_hash {
	enum nft_hash_types	type;
	enum nft_registers	sreg;
	enum nft_registers	dreg;
	unsigned int		len;
	unsigned int		modulus;
	unsigned int		seed;
	unsigned int		offset;
	struct {
		const char	*name;
		uint32_t	id;
	} map;
};

static int
nftnl_expr_hash_set(struct nftnl_expr *e, uint16_t type,
		    const void *data, uint32_t data_len)
{
	struct nftnl_expr_hash *hash = nftnl_expr_data(e);
	switch (type) {
	case NFTNL_EXPR_HASH_SREG:
		hash->sreg = *((uint32_t *)data);
		break;
	case NFTNL_EXPR_HASH_DREG:
		hash->dreg = *((uint32_t *)data);
		break;
	case NFTNL_EXPR_HASH_LEN:
		hash->len = *((uint32_t *)data);
		break;
	case NFTNL_EXPR_HASH_MODULUS:
		hash->modulus = *((uint32_t *)data);
		break;
	case NFTNL_EXPR_HASH_SEED:
		hash->seed = *((uint32_t *)data);
		break;
	case NFTNL_EXPR_HASH_OFFSET:
		hash->offset = *((uint32_t *)data);
		break;
	case NFTNL_EXPR_HASH_TYPE:
		hash->type = *((uint32_t *)data);
		break;
	case NFTNL_EXPR_HASH_SET_NAME:
		hash->map.name = strdup(data);
		if (!hash->map.name)
			return -1;
		break;
	case NFTNL_EXPR_HASH_SET_ID:
		hash->map.id = *((uint32_t *)data);
		break;
	default:
		return -1;
	}
	return 0;
}

static const void *
nftnl_expr_hash_get(const struct nftnl_expr *e, uint16_t type,
		    uint32_t *data_len)
{
	struct nftnl_expr_hash *hash = nftnl_expr_data(e);

	switch (type) {
	case NFTNL_EXPR_HASH_SREG:
		*data_len = sizeof(hash->sreg);
		return &hash->sreg;
	case NFTNL_EXPR_HASH_DREG:
		*data_len = sizeof(hash->dreg);
		return &hash->dreg;
	case NFTNL_EXPR_HASH_LEN:
		*data_len = sizeof(hash->len);
		return &hash->len;
	case NFTNL_EXPR_HASH_MODULUS:
		*data_len = sizeof(hash->modulus);
		return &hash->modulus;
	case NFTNL_EXPR_HASH_SEED:
		*data_len = sizeof(hash->seed);
		return &hash->seed;
	case NFTNL_EXPR_HASH_OFFSET:
		*data_len = sizeof(hash->offset);
		return &hash->offset;
	case NFTNL_EXPR_HASH_TYPE:
		*data_len = sizeof(hash->type);
		return &hash->type;
	case NFTNL_EXPR_HASH_SET_NAME:
		*data_len = strlen(hash->map.name) + 1;
		return hash->map.name;
	case NFTNL_EXPR_HASH_SET_ID:
		*data_len = sizeof(hash->map.id);
		return &hash->map.id;
	}
	return NULL;
}

static int nftnl_expr_hash_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, NFTA_HASH_MAX) < 0)
		return MNL_CB_OK;

	switch (type) {
	case NFTA_HASH_SREG:
	case NFTA_HASH_DREG:
	case NFTA_HASH_LEN:
	case NFTA_HASH_MODULUS:
	case NFTA_HASH_SEED:
	case NFTA_HASH_OFFSET:
	case NFTA_HASH_TYPE:
	case NFTA_HASH_SET_ID:
		if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0)
			abi_breakage();
		break;
	case NFTA_HASH_SET_NAME:
		if (mnl_attr_validate(attr, MNL_TYPE_STRING) < 0)
			abi_breakage();
		break;
	}

	tb[type] = attr;
	return MNL_CB_OK;
}

static void
nftnl_expr_hash_build(struct nlmsghdr *nlh, const struct nftnl_expr *e)
{
	struct nftnl_expr_hash *hash = nftnl_expr_data(e);

	if (e->flags & (1 << NFTNL_EXPR_HASH_SREG))
		mnl_attr_put_u32(nlh, NFTA_HASH_SREG, htonl(hash->sreg));
	if (e->flags & (1 << NFTNL_EXPR_HASH_DREG))
		mnl_attr_put_u32(nlh, NFTA_HASH_DREG, htonl(hash->dreg));
	if (e->flags & (1 << NFTNL_EXPR_HASH_LEN))
		mnl_attr_put_u32(nlh, NFTA_HASH_LEN, htonl(hash->len));
	if (e->flags & (1 << NFTNL_EXPR_HASH_MODULUS))
		mnl_attr_put_u32(nlh, NFTA_HASH_MODULUS, htonl(hash->modulus));
	if (e->flags & (1 << NFTNL_EXPR_HASH_SEED))
		mnl_attr_put_u32(nlh, NFTA_HASH_SEED, htonl(hash->seed));
	if (e->flags & (1 << NFTNL_EXPR_HASH_OFFSET))
		mnl_attr_put_u32(nlh, NFTA_HASH_OFFSET, htonl(hash->offset));
	if (e->flags & (1 << NFTNL_EXPR_HASH_TYPE))
		mnl_attr_put_u32(nlh, NFTA_HASH_TYPE, htonl(hash->type));
	if (e->flags & (1 << NFTNL_EXPR_HASH_SET_NAME))
		mnl_attr_put_str(nlh, NFTA_HASH_SET_NAME, hash->map.name);
	if (e->flags & (1 << NFTNL_EXPR_HASH_SET_ID))
		mnl_attr_put_u32(nlh, NFTA_HASH_SET_ID, htonl(hash->map.id));
}

static int
nftnl_expr_hash_parse(struct nftnl_expr *e, struct nlattr *attr)
{
	struct nftnl_expr_hash *hash = nftnl_expr_data(e);
	struct nlattr *tb[NFTA_HASH_MAX+1] = {};
	int ret = 0;

	if (mnl_attr_parse_nested(attr, nftnl_expr_hash_cb, tb) < 0)
		return -1;

	if (tb[NFTA_HASH_SREG]) {
		hash->sreg = ntohl(mnl_attr_get_u32(tb[NFTA_HASH_SREG]));
		e->flags |= (1 << NFTNL_EXPR_HASH_SREG);
	}
	if (tb[NFTA_HASH_DREG]) {
		hash->dreg = ntohl(mnl_attr_get_u32(tb[NFTA_HASH_DREG]));
		e->flags |= (1 << NFTNL_EXPR_HASH_DREG);
	}
	if (tb[NFTA_HASH_LEN]) {
		hash->len = ntohl(mnl_attr_get_u32(tb[NFTA_HASH_LEN]));
		e->flags |= (1 << NFTNL_EXPR_HASH_LEN);
	}
	if (tb[NFTA_HASH_MODULUS]) {
		hash->modulus = ntohl(mnl_attr_get_u32(tb[NFTA_HASH_MODULUS]));
		e->flags |= (1 << NFTNL_EXPR_HASH_MODULUS);
	}
	if (tb[NFTA_HASH_SEED]) {
		hash->seed = ntohl(mnl_attr_get_u32(tb[NFTA_HASH_SEED]));
		e->flags |= (1 << NFTNL_EXPR_HASH_SEED);
	}
	if (tb[NFTA_HASH_OFFSET]) {
		hash->offset = ntohl(mnl_attr_get_u32(tb[NFTA_HASH_OFFSET]));
		e->flags |= (1 << NFTNL_EXPR_HASH_OFFSET);
	}
	if (tb[NFTA_HASH_TYPE]) {
		hash->type = ntohl(mnl_attr_get_u32(tb[NFTA_HASH_TYPE]));
		e->flags |= (1 << NFTNL_EXPR_HASH_TYPE);
	}
	if (tb[NFTA_HASH_SET_NAME]) {
		hash->map.name =
			  strdup(mnl_attr_get_str(tb[NFTA_HASH_SET_NAME]));
		e->flags |= (1 << NFTNL_EXPR_HASH_SET_NAME);
	}
	if (tb[NFTA_HASH_SET_ID]) {
		hash->map.id =
			  ntohl(mnl_attr_get_u32(tb[NFTA_HASH_SET_ID]));
		e->flags |= (1 << NFTNL_EXPR_HASH_SET_ID);
	}

	return ret;
}

static int
nftnl_expr_hash_snprintf_default(char *buf, size_t size,
				 const struct nftnl_expr *e)
{
	struct nftnl_expr_hash *hash = nftnl_expr_data(e);
	int remain = size, offset = 0, ret;

	switch (hash->type) {
	case NFT_HASH_SYM:
		ret =
		snprintf(buf, remain, "reg %u = symhash() %% mod %u ",
			 hash->dreg,
			 hash->modulus);
		SNPRINTF_BUFFER_SIZE(ret, remain, offset);
		break;
	case NFT_HASH_JENKINS:
	default:
		ret =
		snprintf(buf, remain,
			 "reg %u = jhash(reg %u, %u, 0x%x) %% mod %u ",
			 hash->dreg, hash->sreg, hash->len, hash->seed,
			 hash->modulus);
		SNPRINTF_BUFFER_SIZE(ret, remain, offset);
		break;
	}

	if (hash->offset) {
		ret = snprintf(buf + offset, remain, "offset %u ",
			       hash->offset);
		SNPRINTF_BUFFER_SIZE(ret, remain, offset);
	}

	if (hash->map.id) {
		ret = snprintf(buf + offset, remain, "set %s id %u ",
			       hash->map.name, hash->map.id);
		SNPRINTF_BUFFER_SIZE(ret, remain, offset);
	}

	return offset;
}

static int
nftnl_expr_hash_snprintf(char *buf, size_t len, uint32_t type,
			 uint32_t flags, const struct nftnl_expr *e)
{
	switch (type) {
	case NFTNL_OUTPUT_DEFAULT:
		return nftnl_expr_hash_snprintf_default(buf, len, e);
	case NFTNL_OUTPUT_XML:
	case NFTNL_OUTPUT_JSON:
	default:
		break;
	}
	return -1;
}

static bool nftnl_expr_hash_cmp(const struct nftnl_expr *e1,
				const struct nftnl_expr *e2)
{
       struct nftnl_expr_hash *h1 = nftnl_expr_data(e1);
       struct nftnl_expr_hash *h2 = nftnl_expr_data(e2);
       bool eq = true;

       if (e1->flags & (1 << NFTNL_EXPR_HASH_SREG))
               eq &= (h1->sreg == h2->sreg);
       if (e1->flags & (1 << NFTNL_EXPR_HASH_DREG))
               eq &= (h1->dreg == h2->dreg);
       if (e1->flags & (1 << NFTNL_EXPR_HASH_LEN))
               eq &= (h1->len == h2->len);
       if (e1->flags & (1 << NFTNL_EXPR_HASH_MODULUS))
               eq &= (h1->modulus == h2->modulus);
       if (e1->flags & (1 << NFTNL_EXPR_HASH_SEED))
               eq &= (h1->seed == h2->seed);
	if (e1->flags & (1 << NFTNL_EXPR_HASH_OFFSET))
		eq &= (h1->offset == h2->offset);
	if (e1->flags & (1 << NFTNL_EXPR_HASH_TYPE))
		eq &= (h1->type == h2->type);
	if (e1->flags & (1 << NFTNL_EXPR_HASH_SET_NAME))
		eq &= !strcmp(h1->map.name, h2->map.name);
	if (e1->flags & (1 << NFTNL_EXPR_HASH_SET_ID))
		eq &= (h1->map.id == h2->map.id);

       return eq;
}

struct expr_ops expr_ops_hash = {
	.name		= "hash",
	.alloc_len	= sizeof(struct nftnl_expr_hash),
	.max_attr	= NFTA_HASH_MAX,
	.cmp		= nftnl_expr_hash_cmp,
	.set		= nftnl_expr_hash_set,
	.get		= nftnl_expr_hash_get,
	.parse		= nftnl_expr_hash_parse,
	.build		= nftnl_expr_hash_build,
	.snprintf	= nftnl_expr_hash_snprintf,
};
