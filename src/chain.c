/*
 * (C) 2012-2013 by Pablo Neira Ayuso <pablo@netfilter.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This code has been sponsored by Sophos Astaro <http://www.sophos.com>
 */
#include "internal.h"

#include <time.h>
#include <endian.h>
#include <stdint.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <netinet/in.h>
#include <errno.h>
#include <inttypes.h>

#include <libmnl/libmnl.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nf_tables.h>
#include <linux/netfilter.h>
#include <linux/netfilter_arp.h>

#include <libnftnl/chain.h>
#include <buffer.h>

struct nft_chain {
	struct list_head head;

	char		name[NFT_CHAIN_MAXNAMELEN];
	const char	*type;
	const char	*table;
	const char	*dev;
	uint32_t	family;
	uint32_t	policy;
	uint32_t	hooknum;
	int32_t		prio;
	uint32_t	use;
	uint64_t	packets;
	uint64_t	bytes;
	uint64_t	handle;
	uint32_t	flags;
};

static const char *nft_hooknum2str(int family, int hooknum)
{
	switch (family) {
	case NFPROTO_IPV4:
	case NFPROTO_IPV6:
	case NFPROTO_INET:
	case NFPROTO_BRIDGE:
		switch (hooknum) {
		case NF_INET_PRE_ROUTING:
			return "prerouting";
		case NF_INET_LOCAL_IN:
			return "input";
		case NF_INET_FORWARD:
			return "forward";
		case NF_INET_LOCAL_OUT:
			return "output";
		case NF_INET_POST_ROUTING:
			return "postrouting";
		}
		break;
	case NFPROTO_ARP:
		switch (hooknum) {
		case NF_ARP_IN:
			return "input";
		case NF_ARP_OUT:
			return "output";
		case NF_ARP_FORWARD:
			return "forward";
		}
		break;
	case NFPROTO_NETDEV:
		switch (hooknum) {
		case NF_NETDEV_INGRESS:
			return "ingress";
		}
		break;
	}
	return "unknown";
}

struct nft_chain *nft_chain_alloc(void)
{
	return calloc(1, sizeof(struct nft_chain));
}
EXPORT_SYMBOL(nft_chain_alloc);

void nft_chain_free(struct nft_chain *c)
{
	if (c->table != NULL)
		xfree(c->table);
	if (c->type != NULL)
		xfree(c->type);
	if (c->dev != NULL)
		xfree(c->dev);

	xfree(c);
}
EXPORT_SYMBOL(nft_chain_free);

bool nft_chain_attr_is_set(const struct nft_chain *c, uint16_t attr)
{
	return c->flags & (1 << attr);
}
EXPORT_SYMBOL(nft_chain_attr_is_set);

void nft_chain_attr_unset(struct nft_chain *c, uint16_t attr)
{
	if (!(c->flags & (1 << attr)))
		return;

	switch (attr) {
	case NFT_CHAIN_ATTR_TABLE:
		if (c->table) {
			xfree(c->table);
			c->table = NULL;
		}
		break;
	case NFT_CHAIN_ATTR_USE:
		break;
	case NFT_CHAIN_ATTR_TYPE:
		if (c->type) {
			xfree(c->type);
			c->type = NULL;
		}
		break;
	case NFT_CHAIN_ATTR_NAME:
	case NFT_CHAIN_ATTR_HOOKNUM:
	case NFT_CHAIN_ATTR_PRIO:
	case NFT_CHAIN_ATTR_POLICY:
	case NFT_CHAIN_ATTR_BYTES:
	case NFT_CHAIN_ATTR_PACKETS:
	case NFT_CHAIN_ATTR_HANDLE:
	case NFT_CHAIN_ATTR_FAMILY:
		break;
	case NFT_CHAIN_ATTR_DEV:
		if (c->dev) {
			xfree(c->dev);
			c->dev = NULL;
		}
		break;
	default:
		return;
	}

	c->flags &= ~(1 << attr);
}
EXPORT_SYMBOL(nft_chain_attr_unset);

static uint32_t nft_chain_attr_validate[NFT_CHAIN_ATTR_MAX + 1] = {
	[NFT_CHAIN_ATTR_HOOKNUM]	= sizeof(uint32_t),
	[NFT_CHAIN_ATTR_PRIO]		= sizeof(int32_t),
	[NFT_CHAIN_ATTR_POLICY]		= sizeof(uint32_t),
	[NFT_CHAIN_ATTR_BYTES]		= sizeof(uint64_t),
	[NFT_CHAIN_ATTR_PACKETS]	= sizeof(uint64_t),
	[NFT_CHAIN_ATTR_HANDLE]		= sizeof(uint64_t),
	[NFT_CHAIN_ATTR_FAMILY]		= sizeof(uint32_t),
};

void nft_chain_attr_set_data(struct nft_chain *c, uint16_t attr,
			     const void *data, uint32_t data_len)
{
	if (attr > NFT_CHAIN_ATTR_MAX)
		return;

	nft_assert_validate(data, nft_chain_attr_validate, attr, data_len);

	switch(attr) {
	case NFT_CHAIN_ATTR_NAME:
		strncpy(c->name, data, NFT_CHAIN_MAXNAMELEN);
		break;
	case NFT_CHAIN_ATTR_TABLE:
		if (c->table)
			xfree(c->table);

		c->table = strdup(data);
		break;
	case NFT_CHAIN_ATTR_HOOKNUM:
		memcpy(&c->hooknum, data, sizeof(c->hooknum));
		break;
	case NFT_CHAIN_ATTR_PRIO:
		memcpy(&c->prio, data, sizeof(c->prio));
		break;
	case NFT_CHAIN_ATTR_POLICY:
		c->policy = *((uint32_t *)data);
		break;
	case NFT_CHAIN_ATTR_USE:
		c->use = *((uint32_t *)data);
		break;
	case NFT_CHAIN_ATTR_BYTES:
		c->bytes = *((uint64_t *)data);
		break;
	case NFT_CHAIN_ATTR_PACKETS:
		c->packets = *((uint64_t *)data);
		break;
	case NFT_CHAIN_ATTR_HANDLE:
		c->handle = *((uint64_t *)data);
		break;
	case NFT_CHAIN_ATTR_FAMILY:
		c->family = *((uint32_t *)data);
		break;
	case NFT_CHAIN_ATTR_TYPE:
		if (c->type)
			xfree(c->type);

		c->type = strdup(data);
		break;
	case NFT_CHAIN_ATTR_DEV:
		if (c->dev)
			xfree(c->dev);

		c->dev = strdup(data);
		break;
	}
	c->flags |= (1 << attr);
}
EXPORT_SYMBOL(nft_chain_attr_set_data);

void nft_chain_attr_set(struct nft_chain *c, uint16_t attr, const void *data)
{
	nft_chain_attr_set_data(c, attr, data, nft_chain_attr_validate[attr]);
}
EXPORT_SYMBOL(nft_chain_attr_set);

void nft_chain_attr_set_u32(struct nft_chain *c, uint16_t attr, uint32_t data)
{
	nft_chain_attr_set_data(c, attr, &data, sizeof(uint32_t));
}
EXPORT_SYMBOL(nft_chain_attr_set_u32);

void nft_chain_attr_set_s32(struct nft_chain *c, uint16_t attr, int32_t data)
{
	nft_chain_attr_set_data(c, attr, &data, sizeof(int32_t));
}
EXPORT_SYMBOL(nft_chain_attr_set_s32);

void nft_chain_attr_set_u64(struct nft_chain *c, uint16_t attr, uint64_t data)
{
	nft_chain_attr_set_data(c, attr, &data, sizeof(uint64_t));
}
EXPORT_SYMBOL(nft_chain_attr_set_u64);

void nft_chain_attr_set_u8(struct nft_chain *c, uint16_t attr, uint8_t data)
{
	nft_chain_attr_set_data(c, attr, &data, sizeof(uint8_t));
}
EXPORT_SYMBOL(nft_chain_attr_set_u8);

void nft_chain_attr_set_str(struct nft_chain *c, uint16_t attr, const char *str)
{
	nft_chain_attr_set_data(c, attr, str, strlen(str));
}
EXPORT_SYMBOL(nft_chain_attr_set_str);

const void *nft_chain_attr_get_data(struct nft_chain *c, uint16_t attr,
				    uint32_t *data_len)
{
	if (!(c->flags & (1 << attr)))
		return NULL;

	switch(attr) {
	case NFT_CHAIN_ATTR_NAME:
		return c->name;
	case NFT_CHAIN_ATTR_TABLE:
		return c->table;
	case NFT_CHAIN_ATTR_HOOKNUM:
		*data_len = sizeof(uint32_t);
		return &c->hooknum;
	case NFT_CHAIN_ATTR_PRIO:
		*data_len = sizeof(int32_t);
		return &c->prio;
	case NFT_CHAIN_ATTR_POLICY:
		*data_len = sizeof(uint32_t);
		return &c->policy;
	case NFT_CHAIN_ATTR_USE:
		*data_len = sizeof(uint32_t);
		return &c->use;
	case NFT_CHAIN_ATTR_BYTES:
		*data_len = sizeof(uint64_t);
		return &c->bytes;
	case NFT_CHAIN_ATTR_PACKETS:
		*data_len = sizeof(uint64_t);
		return &c->packets;
	case NFT_CHAIN_ATTR_HANDLE:
		*data_len = sizeof(uint64_t);
		return &c->handle;
	case NFT_CHAIN_ATTR_FAMILY:
		*data_len = sizeof(uint32_t);
		return &c->family;
	case NFT_CHAIN_ATTR_TYPE:
		*data_len = sizeof(uint32_t);
		return c->type;
	case NFT_CHAIN_ATTR_DEV:
		return c->dev;
	}
	return NULL;
}
EXPORT_SYMBOL(nft_chain_attr_get_data);

const void *nft_chain_attr_get(struct nft_chain *c, uint16_t attr)
{
	uint32_t data_len;
	return nft_chain_attr_get_data(c, attr, &data_len);
}
EXPORT_SYMBOL(nft_chain_attr_get);

const char *nft_chain_attr_get_str(struct nft_chain *c, uint16_t attr)
{
	return nft_chain_attr_get(c, attr);
}
EXPORT_SYMBOL(nft_chain_attr_get_str);

uint32_t nft_chain_attr_get_u32(struct nft_chain *c, uint16_t attr)
{
	uint32_t data_len;
	const uint32_t *val = nft_chain_attr_get_data(c, attr, &data_len);

	nft_assert(val, attr, data_len == sizeof(uint32_t));

	return val ? *val : 0;
}
EXPORT_SYMBOL(nft_chain_attr_get_u32);

int32_t nft_chain_attr_get_s32(struct nft_chain *c, uint16_t attr)
{
	uint32_t data_len;
	const int32_t *val = nft_chain_attr_get_data(c, attr, &data_len);

	nft_assert(val, attr, data_len == sizeof(int32_t));

	return val ? *val : 0;
}
EXPORT_SYMBOL(nft_chain_attr_get_s32);

uint64_t nft_chain_attr_get_u64(struct nft_chain *c, uint16_t attr)
{
	uint32_t data_len;
	const uint64_t *val = nft_chain_attr_get_data(c, attr, &data_len);

	nft_assert(val, attr, data_len == sizeof(int64_t));

	return val ? *val : 0;
}
EXPORT_SYMBOL(nft_chain_attr_get_u64);

uint8_t nft_chain_attr_get_u8(struct nft_chain *c, uint16_t attr)
{
	uint32_t data_len;
	const uint8_t *val = nft_chain_attr_get_data(c, attr, &data_len);

	nft_assert(val, attr, data_len == sizeof(int8_t));

	return val ? *val : 0;
}
EXPORT_SYMBOL(nft_chain_attr_get_u8);

void nft_chain_nlmsg_build_payload(struct nlmsghdr *nlh, const struct nft_chain *c)
{
	if (c->flags & (1 << NFT_CHAIN_ATTR_TABLE))
		mnl_attr_put_strz(nlh, NFTA_CHAIN_TABLE, c->table);
	if (c->flags & (1 << NFT_CHAIN_ATTR_NAME))
		mnl_attr_put_strz(nlh, NFTA_CHAIN_NAME, c->name);
	if ((c->flags & (1 << NFT_CHAIN_ATTR_HOOKNUM)) &&
	    (c->flags & (1 << NFT_CHAIN_ATTR_PRIO))) {
		struct nlattr *nest;

		nest = mnl_attr_nest_start(nlh, NFTA_CHAIN_HOOK);
		mnl_attr_put_u32(nlh, NFTA_HOOK_HOOKNUM, htonl(c->hooknum));
		mnl_attr_put_u32(nlh, NFTA_HOOK_PRIORITY, htonl(c->prio));
		if (c->flags & (1 << NFT_CHAIN_ATTR_DEV))
			mnl_attr_put_strz(nlh, NFTA_HOOK_DEV, c->dev);
		mnl_attr_nest_end(nlh, nest);
	}
	if (c->flags & (1 << NFT_CHAIN_ATTR_POLICY))
		mnl_attr_put_u32(nlh, NFTA_CHAIN_POLICY, htonl(c->policy));
	if (c->flags & (1 << NFT_CHAIN_ATTR_USE))
		mnl_attr_put_u32(nlh, NFTA_CHAIN_USE, htonl(c->use));
	if ((c->flags & (1 << NFT_CHAIN_ATTR_PACKETS)) &&
	    (c->flags & (1 << NFT_CHAIN_ATTR_BYTES))) {
		struct nlattr *nest;

		nest = mnl_attr_nest_start(nlh, NFTA_CHAIN_COUNTERS);
		mnl_attr_put_u64(nlh, NFTA_COUNTER_PACKETS, be64toh(c->packets));
		mnl_attr_put_u64(nlh, NFTA_COUNTER_BYTES, be64toh(c->bytes));
		mnl_attr_nest_end(nlh, nest);
	}
	if (c->flags & (1 << NFT_CHAIN_ATTR_HANDLE))
		mnl_attr_put_u64(nlh, NFTA_CHAIN_HANDLE, be64toh(c->handle));
	if (c->flags & (1 << NFT_CHAIN_ATTR_TYPE))
		mnl_attr_put_strz(nlh, NFTA_CHAIN_TYPE, c->type);
}
EXPORT_SYMBOL(nft_chain_nlmsg_build_payload);

static int nft_chain_parse_attr_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, NFTA_CHAIN_MAX) < 0)
		return MNL_CB_OK;

	switch(type) {
	case NFTA_CHAIN_NAME:
	case NFTA_CHAIN_TABLE:
	case NFTA_CHAIN_TYPE:
		if (mnl_attr_validate(attr, MNL_TYPE_STRING) < 0)
			abi_breakage();
		break;
	case NFTA_CHAIN_HOOK:
	case NFTA_CHAIN_COUNTERS:
		if (mnl_attr_validate(attr, MNL_TYPE_NESTED) < 0)
			abi_breakage();
		break;
	case NFTA_CHAIN_POLICY:
	case NFTA_CHAIN_USE:
		if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0)
			abi_breakage();
		break;
	case NFTA_CHAIN_HANDLE:
		if (mnl_attr_validate(attr, MNL_TYPE_U64) < 0)
			abi_breakage();
		break;
	}

	tb[type] = attr;
	return MNL_CB_OK;
}

static int nft_chain_parse_counters_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, NFTA_COUNTER_MAX) < 0)
		return MNL_CB_OK;

	switch(type) {
	case NFTA_COUNTER_BYTES:
	case NFTA_COUNTER_PACKETS:
		if (mnl_attr_validate(attr, MNL_TYPE_U64) < 0)
			abi_breakage();
		break;
	}

	tb[type] = attr;
	return MNL_CB_OK;
}

static int nft_chain_parse_counters(struct nlattr *attr, struct nft_chain *c)
{
	struct nlattr *tb[NFTA_COUNTER_MAX+1] = {};

	if (mnl_attr_parse_nested(attr, nft_chain_parse_counters_cb, tb) < 0)
		return -1;

	if (tb[NFTA_COUNTER_PACKETS]) {
		c->packets = be64toh(mnl_attr_get_u64(tb[NFTA_COUNTER_PACKETS]));
		c->flags |= (1 << NFT_CHAIN_ATTR_PACKETS);
	}
	if (tb[NFTA_COUNTER_BYTES]) {
		c->bytes = be64toh(mnl_attr_get_u64(tb[NFTA_COUNTER_BYTES]));
		c->flags |= (1 << NFT_CHAIN_ATTR_BYTES);
	}

	return 0;
}
static int nft_chain_parse_hook_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, NFTA_HOOK_MAX) < 0)
		return MNL_CB_OK;

	switch(type) {
	case NFTA_HOOK_HOOKNUM:
	case NFTA_HOOK_PRIORITY:
		if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0)
			abi_breakage();
		break;
	case NFTA_HOOK_DEV:
		if (mnl_attr_validate(attr, MNL_TYPE_STRING) < 0)
			abi_breakage();
		break;
	}

	tb[type] = attr;
	return MNL_CB_OK;
}

static int nft_chain_parse_hook(struct nlattr *attr, struct nft_chain *c)
{
	struct nlattr *tb[NFTA_HOOK_MAX+1] = {};

	if (mnl_attr_parse_nested(attr, nft_chain_parse_hook_cb, tb) < 0)
		return -1;

	if (tb[NFTA_HOOK_HOOKNUM]) {
		c->hooknum = ntohl(mnl_attr_get_u32(tb[NFTA_HOOK_HOOKNUM]));
		c->flags |= (1 << NFT_CHAIN_ATTR_HOOKNUM);
	}
	if (tb[NFTA_HOOK_PRIORITY]) {
		c->prio = ntohl(mnl_attr_get_u32(tb[NFTA_HOOK_PRIORITY]));
		c->flags |= (1 << NFT_CHAIN_ATTR_PRIO);
	}
	if (tb[NFTA_HOOK_DEV]) {
		c->dev = strdup(mnl_attr_get_str(tb[NFTA_HOOK_DEV]));
		c->flags |= (1 << NFT_CHAIN_ATTR_DEV);
	}

	return 0;
}

int nft_chain_nlmsg_parse(const struct nlmsghdr *nlh, struct nft_chain *c)
{
	struct nlattr *tb[NFTA_CHAIN_MAX+1] = {};
	struct nfgenmsg *nfg = mnl_nlmsg_get_payload(nlh);
	int ret = 0;

	if (mnl_attr_parse(nlh, sizeof(*nfg), nft_chain_parse_attr_cb, tb) < 0)
		return -1;

	if (tb[NFTA_CHAIN_NAME]) {
		strncpy(c->name, mnl_attr_get_str(tb[NFTA_CHAIN_NAME]),
			NFT_CHAIN_MAXNAMELEN);
		c->flags |= (1 << NFT_CHAIN_ATTR_NAME);
	}
	if (tb[NFTA_CHAIN_TABLE]) {
		c->table = strdup(mnl_attr_get_str(tb[NFTA_CHAIN_TABLE]));
		c->flags |= (1 << NFT_CHAIN_ATTR_TABLE);
	}
	if (tb[NFTA_CHAIN_HOOK]) {
		ret = nft_chain_parse_hook(tb[NFTA_CHAIN_HOOK], c);
		if (ret < 0)
			return ret;
	}
	if (tb[NFTA_CHAIN_POLICY]) {
		c->policy = ntohl(mnl_attr_get_u32(tb[NFTA_CHAIN_POLICY]));
		c->flags |= (1 << NFT_CHAIN_ATTR_POLICY);
	}
	if (tb[NFTA_CHAIN_USE]) {
		c->use = ntohl(mnl_attr_get_u32(tb[NFTA_CHAIN_USE]));
		c->flags |= (1 << NFT_CHAIN_ATTR_USE);
	}
	if (tb[NFTA_CHAIN_COUNTERS]) {
		ret = nft_chain_parse_counters(tb[NFTA_CHAIN_COUNTERS], c);
		if (ret < 0)
			return ret;
	}
	if (tb[NFTA_CHAIN_HANDLE]) {
		c->handle = be64toh(mnl_attr_get_u64(tb[NFTA_CHAIN_HANDLE]));
		c->flags |= (1 << NFT_CHAIN_ATTR_HANDLE);
	}
	if (tb[NFTA_CHAIN_TYPE]) {
		c->type = strdup(mnl_attr_get_str(tb[NFTA_CHAIN_TYPE]));
		c->flags |= (1 << NFT_CHAIN_ATTR_TYPE);
	}

	c->family = nfg->nfgen_family;
	c->flags |= (1 << NFT_CHAIN_ATTR_FAMILY);

	return ret;
}
EXPORT_SYMBOL(nft_chain_nlmsg_parse);

static inline int nft_str2hooknum(int family, const char *hook)
{
	int hooknum;

	for (hooknum = 0; hooknum < NF_INET_NUMHOOKS; hooknum++) {
		if (strcmp(hook, nft_hooknum2str(family, hooknum)) == 0)
			return hooknum;
	}
	return -1;
}

#ifdef JSON_PARSING
int nft_jansson_parse_chain(struct nft_chain *c, json_t *tree,
			    struct nft_parse_err *err)
{
	json_t *root;
	uint64_t handle, bytes, packets;
	int policy_num;
	int32_t family, prio, hooknum, use;
	const char *name, *table, *type, *hooknum_str, *policy, *dev;

	root = nft_jansson_get_node(tree, "chain", err);
	if (root == NULL)
		return -1;

	name = nft_jansson_parse_str(root, "name", err);
	if (name != NULL)
		nft_chain_attr_set_str(c, NFT_CHAIN_ATTR_NAME, name);

	if (nft_jansson_parse_val(root, "handle", NFT_TYPE_U64, &handle,
				  err) == 0)
		nft_chain_attr_set_u64(c,NFT_CHAIN_ATTR_HANDLE, handle);

	if (nft_jansson_parse_val(root, "bytes", NFT_TYPE_U64, &bytes,
				  err) == 0)
		nft_chain_attr_set_u64(c, NFT_CHAIN_ATTR_BYTES, bytes);

	if (nft_jansson_parse_val(root, "packets", NFT_TYPE_U64, &packets,
				  err) == 0)
		nft_chain_attr_set_u64(c, NFT_CHAIN_ATTR_PACKETS, packets);

	if (nft_jansson_parse_family(root, &family, err) == 0)
		nft_chain_attr_set_u32(c, NFT_CHAIN_ATTR_FAMILY, family);

	table = nft_jansson_parse_str(root, "table", err);

	if (table != NULL)
		nft_chain_attr_set_str(c, NFT_CHAIN_ATTR_TABLE, table);

	if (nft_jansson_parse_val(root, "use", NFT_TYPE_U32, &use, err) == 0)
		nft_chain_attr_set_u32(c, NFT_CHAIN_ATTR_USE, use);

	if (nft_jansson_node_exist(root, "hooknum")) {
		type = nft_jansson_parse_str(root, "type", err);

		if (type != NULL)
			nft_chain_attr_set_str(c, NFT_CHAIN_ATTR_TYPE, type);

		if (nft_jansson_parse_val(root, "prio", NFT_TYPE_S32,
					  &prio, err) == 0)
			nft_chain_attr_set_s32(c, NFT_CHAIN_ATTR_PRIO, prio);

		hooknum_str = nft_jansson_parse_str(root, "hooknum", err);
		if (hooknum_str != NULL) {
			hooknum = nft_str2hooknum(c->family, hooknum_str);
			if (hooknum == -1)
				return -1;
			nft_chain_attr_set_u32(c, NFT_CHAIN_ATTR_HOOKNUM,
					       hooknum);
		}

		policy = nft_jansson_parse_str(root, "policy", err);
		if (policy != NULL) {
			if (nft_str2verdict(policy, &policy_num) != 0) {
				errno = EINVAL;
				err->node_name = "policy";
				err->error = NFT_PARSE_EBADTYPE;
				return -1;
			}
			nft_chain_attr_set_u32(c, NFT_CHAIN_ATTR_POLICY,
					       policy_num);
		}

		dev = nft_jansson_parse_str(root, "device", err);
		if (dev != NULL)
			nft_chain_attr_set_str(c, NFT_CHAIN_ATTR_DEV, dev);
	}

	return 0;
}
#endif

static int nft_chain_json_parse(struct nft_chain *c, const void *json,
				struct nft_parse_err *err,
				enum nft_parse_input input)
{
#ifdef JSON_PARSING
	json_t *tree;
	json_error_t error;
	int ret;

	tree = nft_jansson_create_root(json, &error, err, input);
	if (tree == NULL)
		return -1;

	ret = nft_jansson_parse_chain(c, tree, err);

	nft_jansson_free_root(tree);

	return ret;
#else
	errno = EOPNOTSUPP;
	return -1;
#endif
}

#ifdef XML_PARSING
int nft_mxml_chain_parse(mxml_node_t *tree, struct nft_chain *c,
			 struct nft_parse_err *err)
{
	const char *table, *name, *hooknum_str, *policy_str, *type, *dev;
	int family, hooknum, policy;
	uint64_t handle, bytes, packets, prio, use;

	name = nft_mxml_str_parse(tree, "name", MXML_DESCEND_FIRST,
				  NFT_XML_MAND, err);
	if (name != NULL)
		nft_chain_attr_set_str(c, NFT_CHAIN_ATTR_NAME, name);

	if (nft_mxml_num_parse(tree, "handle", MXML_DESCEND_FIRST, BASE_DEC,
			       &handle, NFT_TYPE_U64, NFT_XML_MAND, err) == 0)
		nft_chain_attr_set_u64(c, NFT_CHAIN_ATTR_HANDLE, handle);

	if (nft_mxml_num_parse(tree, "bytes", MXML_DESCEND_FIRST, BASE_DEC,
			       &bytes, NFT_TYPE_U64, NFT_XML_MAND, err) == 0)
		nft_chain_attr_set_u64(c, NFT_CHAIN_ATTR_BYTES, bytes);


	if (nft_mxml_num_parse(tree, "packets", MXML_DESCEND_FIRST, BASE_DEC,
			       &packets, NFT_TYPE_U64, NFT_XML_MAND, err) == 0)
		nft_chain_attr_set_u64(c, NFT_CHAIN_ATTR_PACKETS, packets);

	table = nft_mxml_str_parse(tree, "table", MXML_DESCEND_FIRST,
				   NFT_XML_MAND, err);

	if (table != NULL)
		nft_chain_attr_set_str(c, NFT_CHAIN_ATTR_TABLE, table);

	if (nft_mxml_num_parse(tree, "use", MXML_DESCEND_FIRST, BASE_DEC,
			       &use, NFT_TYPE_U64, NFT_XML_MAND, err) == 0)
		nft_chain_attr_set_u64(c, NFT_CHAIN_ATTR_PACKETS, use);

	family = nft_mxml_family_parse(tree, "family", MXML_DESCEND_FIRST,
				       NFT_XML_MAND, err);
	if (family >= 0)
		nft_chain_attr_set_u32(c, NFT_CHAIN_ATTR_FAMILY, family);

	hooknum_str = nft_mxml_str_parse(tree, "hooknum", MXML_DESCEND_FIRST,
					 NFT_XML_OPT, err);
	if (hooknum_str != NULL) {
		hooknum = nft_str2hooknum(c->family, hooknum_str);
		if (hooknum < 0)
			return -1;
		nft_chain_attr_set_u32(c, NFT_CHAIN_ATTR_HOOKNUM, hooknum);

		type = nft_mxml_str_parse(tree, "type", MXML_DESCEND_FIRST,
					  NFT_XML_MAND, err);

		if (type != NULL)
			nft_chain_attr_set_str(c, NFT_CHAIN_ATTR_TYPE, type);

		if (nft_mxml_num_parse(tree, "prio", MXML_DESCEND, BASE_DEC,
				       &prio, NFT_TYPE_S32, NFT_XML_MAND,
				       err) == 0)
			nft_chain_attr_set_s32(c, NFT_CHAIN_ATTR_PRIO, prio);

		policy_str = nft_mxml_str_parse(tree, "policy",
						MXML_DESCEND_FIRST,
						NFT_XML_MAND, err);
		if (policy_str != NULL) {
			if (nft_str2verdict(policy_str, &policy) != 0) {
				errno = EINVAL;
				err->node_name = "policy";
				err->error = NFT_PARSE_EBADTYPE;
				return -1;
			}
			nft_chain_attr_set_u32(c, NFT_CHAIN_ATTR_POLICY,
					       policy);
		}
		dev = nft_mxml_str_parse(tree, "device", MXML_DESCEND_FIRST,
					 NFT_XML_MAND, err);

		if (table != NULL)
			nft_chain_attr_set_str(c, NFT_CHAIN_ATTR_DEV, dev);
	}

	return 0;
}
#endif

static int nft_chain_xml_parse(struct nft_chain *c, const void *xml,
			       struct nft_parse_err *err,
			       enum nft_parse_input input)
{
#ifdef XML_PARSING
	int ret;
	mxml_node_t *tree = nft_mxml_build_tree(xml, "chain", err, input);
	if (tree == NULL)
		return -1;

	ret = nft_mxml_chain_parse(tree, c, err);
	mxmlDelete(tree);
	return ret;
#else
	errno = EOPNOTSUPP;
	return -1;
#endif
}

static int nft_chain_do_parse(struct nft_chain *c, enum nft_parse_type type,
			      const void *data, struct nft_parse_err *err,
			      enum nft_parse_input input)
{
	int ret;
	struct nft_parse_err perr;

	switch (type) {
	case NFT_PARSE_XML:
		ret = nft_chain_xml_parse(c, data, &perr, input);
		break;
	case NFT_PARSE_JSON:
		ret = nft_chain_json_parse(c, data, &perr, input);
		break;
	default:
		ret = -1;
		errno = EOPNOTSUPP;
		break;
	}

	if (err != NULL)
		*err = perr;

	return ret;
}

int nft_chain_parse(struct nft_chain *c, enum nft_parse_type type,
		    const char *data, struct nft_parse_err *err)
{
	return nft_chain_do_parse(c, type, data, err, NFT_PARSE_BUFFER);
}
EXPORT_SYMBOL(nft_chain_parse);

int nft_chain_parse_file(struct nft_chain *c, enum nft_parse_type type,
			 FILE *fp, struct nft_parse_err *err)
{
	return nft_chain_do_parse(c, type, fp, err, NFT_PARSE_FILE);
}
EXPORT_SYMBOL(nft_chain_parse_file);

static int nft_chain_export(char *buf, size_t size, struct nft_chain *c,
			    int type)
{
	NFT_BUF_INIT(b, buf, size);

	nft_buf_open(&b, type, CHAIN);
	if (c->flags & (1 << NFT_CHAIN_ATTR_NAME))
		nft_buf_str(&b, type, c->name, NAME);
	if (c->flags & (1 << NFT_CHAIN_ATTR_HANDLE))
		nft_buf_u64(&b, type, c->handle, HANDLE);
	if (c->flags & (1 << NFT_CHAIN_ATTR_BYTES))
		nft_buf_u64(&b, type, c->bytes, BYTES);
	if (c->flags & (1 << NFT_CHAIN_ATTR_PACKETS))
		nft_buf_u64(&b, type, c->packets, PACKETS);
	if (c->flags & (1 << NFT_CHAIN_ATTR_TABLE))
		nft_buf_str(&b, type, c->table, TABLE);
	if (c->flags & (1 << NFT_CHAIN_ATTR_FAMILY))
		nft_buf_str(&b, type, nft_family2str(c->family), FAMILY);
	if (c->flags & (1 << NFT_CHAIN_ATTR_USE))
		nft_buf_u32(&b, type, c->use, USE);
	if (c->flags & (1 << NFT_CHAIN_ATTR_HOOKNUM)) {
		if (c->flags & (1 << NFT_CHAIN_ATTR_TYPE))
			nft_buf_str(&b, type, c->type, TYPE);
		if (c->flags & (1 << NFT_CHAIN_ATTR_HOOKNUM))
			nft_buf_str(&b, type, nft_hooknum2str(c->family,
					 c->hooknum), HOOKNUM);
		if (c->flags & (1 << NFT_CHAIN_ATTR_PRIO))
			nft_buf_s32(&b, type, c->prio, PRIO);
		if (c->flags & (1 << NFT_CHAIN_ATTR_POLICY))
			nft_buf_str(&b, type, nft_verdict2str(c->policy), POLICY);
		if (c->flags & (1 << NFT_CHAIN_ATTR_DEV))
			nft_buf_str(&b, type, c->dev, DEVICE);
	}

	nft_buf_close(&b, type, CHAIN);

	return nft_buf_done(&b);
}

static int nft_chain_snprintf_default(char *buf, size_t size,
				      struct nft_chain *c)
{
	int ret, len = size, offset = 0;

	ret = snprintf(buf, len, "%s %s %s use %u",
		       nft_family2str(c->family), c->table, c->name, c->use);
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	if (c->flags & (1 << NFT_CHAIN_ATTR_HOOKNUM)) {
		ret = snprintf(buf+offset, len,
			       " type %s hook %s prio %d policy %s "
			       "packets %"PRIu64" bytes %"PRIu64"",
			       c->type, nft_hooknum2str(c->family, c->hooknum),
			       c->prio, nft_verdict2str(c->policy),
			       c->packets, c->bytes);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

		if (c->flags & (1 << NFT_CHAIN_ATTR_DEV)) {
			ret = snprintf(buf+offset, len, " dev %s ", c->dev);
			SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
		}
	}

	return offset;
}

static int nft_chain_cmd_snprintf(char *buf, size_t size, struct nft_chain *c,
				  uint32_t cmd, uint32_t type, uint32_t flags)
{
	int ret, len = size, offset = 0;

	ret = nft_cmd_header_snprintf(buf + offset, len, cmd, type, flags);
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	switch (type) {
	case NFT_OUTPUT_DEFAULT:
		ret = nft_chain_snprintf_default(buf+offset, len, c);
		break;
	case NFT_OUTPUT_XML:
	case NFT_OUTPUT_JSON:
		ret = nft_chain_export(buf+offset, len, c, type);
		break;
	default:
		return -1;
	}

	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	ret = nft_cmd_footer_snprintf(buf + offset, len, cmd, type, flags);
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	return offset;
}

int nft_chain_snprintf(char *buf, size_t size, struct nft_chain *c,
		       uint32_t type, uint32_t flags)
{
	return nft_chain_cmd_snprintf(buf, size, c, nft_flag2cmd(flags), type,
				      flags);
}
EXPORT_SYMBOL(nft_chain_snprintf);

static inline int nft_chain_do_snprintf(char *buf, size_t size, void *c,
					uint32_t cmd, uint32_t type,
					uint32_t flags)
{
	return nft_chain_snprintf(buf, size, c, type, flags);
}

int nft_chain_fprintf(FILE *fp, struct nft_chain *c, uint32_t type,
		      uint32_t flags)
{
	return nft_fprintf(fp, c, NFT_CMD_UNSPEC, type, flags,
			   nft_chain_do_snprintf);
}
EXPORT_SYMBOL(nft_chain_fprintf);

struct nft_chain_list {
	struct list_head list;
};

struct nft_chain_list *nft_chain_list_alloc(void)
{
	struct nft_chain_list *list;

	list = calloc(1, sizeof(struct nft_chain_list));
	if (list == NULL)
		return NULL;

	INIT_LIST_HEAD(&list->list);

	return list;
}
EXPORT_SYMBOL(nft_chain_list_alloc);

void nft_chain_list_free(struct nft_chain_list *list)
{
	struct nft_chain *r, *tmp;

	list_for_each_entry_safe(r, tmp, &list->list, head) {
		list_del(&r->head);
		nft_chain_free(r);
	}
	xfree(list);
}
EXPORT_SYMBOL(nft_chain_list_free);

int nft_chain_list_is_empty(struct nft_chain_list *list)
{
	return list_empty(&list->list);
}
EXPORT_SYMBOL(nft_chain_list_is_empty);

void nft_chain_list_add(struct nft_chain *r, struct nft_chain_list *list)
{
	list_add(&r->head, &list->list);
}
EXPORT_SYMBOL(nft_chain_list_add);

void nft_chain_list_add_tail(struct nft_chain *r, struct nft_chain_list *list)
{
	list_add_tail(&r->head, &list->list);
}
EXPORT_SYMBOL(nft_chain_list_add_tail);

void nft_chain_list_del(struct nft_chain *r)
{
	list_del(&r->head);
}
EXPORT_SYMBOL(nft_chain_list_del);

int nft_chain_list_foreach(struct nft_chain_list *chain_list,
			   int (*cb)(struct nft_chain *r, void *data),
			   void *data)
{
	struct nft_chain *cur, *tmp;
	int ret;

	list_for_each_entry_safe(cur, tmp, &chain_list->list, head) {
		ret = cb(cur, data);
		if (ret < 0)
			return ret;
	}
	return 0;
}
EXPORT_SYMBOL(nft_chain_list_foreach);

struct nft_chain_list_iter {
	struct nft_chain_list	*list;
	struct nft_chain	*cur;
};

struct nft_chain_list_iter *nft_chain_list_iter_create(struct nft_chain_list *l)
{
	struct nft_chain_list_iter *iter;

	iter = calloc(1, sizeof(struct nft_chain_list_iter));
	if (iter == NULL)
		return NULL;

	iter->list = l;
	if (nft_chain_list_is_empty(l))
		iter->cur = NULL;
	else
		iter->cur = list_entry(l->list.next, struct nft_chain, head);

	return iter;
}
EXPORT_SYMBOL(nft_chain_list_iter_create);

struct nft_chain *nft_chain_list_iter_next(struct nft_chain_list_iter *iter)
{
	struct nft_chain *r = iter->cur;

	if (r == NULL)
		return NULL;

	/* get next chain, if any */
	iter->cur = list_entry(iter->cur->head.next, struct nft_chain, head);
	if (&iter->cur->head == iter->list->list.next)
		return NULL;

	return r;
}
EXPORT_SYMBOL(nft_chain_list_iter_next);

void nft_chain_list_iter_destroy(struct nft_chain_list_iter *iter)
{
	xfree(iter);
}
EXPORT_SYMBOL(nft_chain_list_iter_destroy);
