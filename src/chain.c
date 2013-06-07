/*
 * (C) 2012 by Pablo Neira Ayuso <pablo@netfilter.org>
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

#include <libmnl/libmnl.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nf_tables.h>

#include <libnftables/chain.h>

struct nft_chain {
	struct list_head head;

	char		name[NFT_CHAIN_MAXNAMELEN];
	char		*type;
	char		*table;
	uint8_t		family;
	uint32_t	policy;
	uint32_t	hooknum;
	int32_t		prio;
	uint32_t	use;
	uint64_t	packets;
	uint64_t	bytes;
	uint64_t	handle;
	uint32_t	flags;
};

struct nft_chain *nft_chain_alloc(void)
{
	return calloc(1, sizeof(struct nft_chain));
}
EXPORT_SYMBOL(nft_chain_alloc);

void nft_chain_free(struct nft_chain *c)
{
	if (c->table != NULL)
		free(c->table);
	if (c->type != NULL)
		free(c->type);

	free(c);
}
EXPORT_SYMBOL(nft_chain_free);

void nft_chain_attr_unset(struct nft_chain *c, uint16_t attr)
{
	switch (attr) {
	case NFT_CHAIN_ATTR_TABLE:
		if (c->flags & (1 << NFT_CHAIN_ATTR_TABLE))
			if (c->table) {
				free(c->table);
				c->table = NULL;
			}
		break;
	case NFT_CHAIN_ATTR_USE:
		/* cannot be unset?, ignore it */
		return;
	case NFT_CHAIN_ATTR_TYPE:
		if (c->flags & (1 << NFT_CHAIN_ATTR_TYPE))
			if (c->type) {
				free(c->type);
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
	default:
		return;
	}

	c->flags &= ~(1 << attr);
}
EXPORT_SYMBOL(nft_chain_attr_unset);

void nft_chain_attr_set(struct nft_chain *c, uint16_t attr, const void *data)
{
	switch(attr) {
	case NFT_CHAIN_ATTR_NAME:
		strncpy(c->name, data, NFT_CHAIN_MAXNAMELEN);
		break;
	case NFT_CHAIN_ATTR_TABLE:
		if (c->table)
			free(c->table);

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
		/* cannot be set, ignore it */
		return;
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
		c->family = *((uint8_t *)data);
		break;
	case NFT_CHAIN_ATTR_TYPE:
		if (c->type)
			free(c->type);

		c->type = strdup(data);
		break;
	default:
		return;
	}
	c->flags |= (1 << attr);
}
EXPORT_SYMBOL(nft_chain_attr_set);

void nft_chain_attr_set_u32(struct nft_chain *c, uint16_t attr, uint32_t data)
{
	nft_chain_attr_set(c, attr, &data);
}
EXPORT_SYMBOL(nft_chain_attr_set_u32);

void nft_chain_attr_set_s32(struct nft_chain *c, uint16_t attr, int32_t data)
{
	nft_chain_attr_set(c, attr, &data);
}
EXPORT_SYMBOL(nft_chain_attr_set_s32);

void nft_chain_attr_set_u64(struct nft_chain *c, uint16_t attr, uint64_t data)
{
	nft_chain_attr_set(c, attr, &data);
}
EXPORT_SYMBOL(nft_chain_attr_set_u64);

void nft_chain_attr_set_str(struct nft_chain *c, uint16_t attr, const char *str)
{
	nft_chain_attr_set_str(c, attr, str);
}
EXPORT_SYMBOL(nft_chain_attr_set_str);

void *nft_chain_attr_get(struct nft_chain *c, uint16_t attr)
{
	switch(attr) {
	case NFT_CHAIN_ATTR_NAME:
		if (c->flags & (1 << NFT_CHAIN_ATTR_NAME))
			return c->name;
		else
			return NULL;
		break;
	case NFT_CHAIN_ATTR_TABLE:
		if (c->flags & (1 << NFT_CHAIN_ATTR_TABLE))
			return c->table;
		else
			return NULL;
	case NFT_CHAIN_ATTR_HOOKNUM:
		if (c->flags & (1 << NFT_CHAIN_ATTR_HOOKNUM))
			return &c->hooknum;
		else
			return NULL;
		break;
	case NFT_CHAIN_ATTR_PRIO:
		if (c->flags & (1 << NFT_CHAIN_ATTR_PRIO))
			return &c->prio;
		else
			return NULL;
		break;
	case NFT_CHAIN_ATTR_POLICY:
		if (c->flags & (1 << NFT_CHAIN_ATTR_POLICY))
			return &c->policy;
		else
			return NULL;
		break;
	case NFT_CHAIN_ATTR_USE:
		if (c->flags & (1 << NFT_CHAIN_ATTR_USE))
			return &c->use;
		else
			return NULL;
		break;
	case NFT_CHAIN_ATTR_BYTES:
		if (c->flags & (1 << NFT_CHAIN_ATTR_BYTES))
			return &c->bytes;
		else
			return NULL;
		break;
	case NFT_CHAIN_ATTR_PACKETS:
		if (c->flags & (1 << NFT_CHAIN_ATTR_PACKETS))
			return &c->packets;
		else
			return NULL;
		break;
	case NFT_CHAIN_ATTR_HANDLE:
		if (c->flags & (1 << NFT_CHAIN_ATTR_HANDLE))
			return &c->handle;
		else
			return NULL;
		break;
	case NFT_CHAIN_ATTR_FAMILY:
		if (c->flags & (1 << NFT_CHAIN_ATTR_FAMILY))
			return &c->family;
		else
			return NULL;
		break;
	case NFT_CHAIN_ATTR_TYPE:
		if (c->flags & (1 << NFT_CHAIN_ATTR_TYPE))
			return c->type;
		else
			return NULL;
		break;
	default:
		return NULL;
	}
}
EXPORT_SYMBOL(nft_chain_attr_get);

const char *nft_chain_attr_get_str(struct nft_chain *c, uint16_t attr)
{
	return nft_chain_attr_get(c, attr);
}
EXPORT_SYMBOL(nft_chain_attr_get_str);

uint32_t nft_chain_attr_get_u32(struct nft_chain *c, uint16_t attr)
{
	uint32_t *val = nft_chain_attr_get(c, attr);
	return val ? *val : 0;
}
EXPORT_SYMBOL(nft_chain_attr_get_u32);

int32_t nft_chain_attr_get_s32(struct nft_chain *c, uint16_t attr)
{
	int32_t *val = nft_chain_attr_get(c, attr);
	return val ? *val : 0;
}
EXPORT_SYMBOL(nft_chain_attr_get_s32);

uint64_t nft_chain_attr_get_u64(struct nft_chain *c, uint16_t attr)
{
	uint64_t *val = nft_chain_attr_get(c, attr);
	return val ? *val : 0;
}
EXPORT_SYMBOL(nft_chain_attr_get_u64);

struct nlmsghdr *
nft_chain_nlmsg_build_hdr(char *buf, uint16_t cmd, uint16_t family,
			  uint16_t type, uint32_t seq)
{
	struct nlmsghdr *nlh;
	struct nfgenmsg *nfh;

	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type = (NFNL_SUBSYS_NFTABLES << 8) | cmd;
	nlh->nlmsg_flags = NLM_F_REQUEST | type;
	nlh->nlmsg_seq = seq;

	nfh = mnl_nlmsg_put_extra_header(nlh, sizeof(struct nfgenmsg));
	nfh->nfgen_family = family;
	nfh->version = NFNETLINK_V0;
	nfh->res_id = 0;

	return nlh;
}
EXPORT_SYMBOL(nft_chain_nlmsg_build_hdr);

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
		mnl_attr_nest_end(nlh, nest);
	}
	if (c->flags & (1 << NFT_CHAIN_ATTR_POLICY))
		mnl_attr_put_u32(nlh, NFTA_CHAIN_POLICY, htonl(c->policy));
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
		if (mnl_attr_validate(attr, MNL_TYPE_STRING) < 0) {
			perror("mnl_attr_validate");
			return MNL_CB_ERROR;
		}
		break;
	case NFTA_CHAIN_HOOK:
	case NFTA_CHAIN_COUNTERS:
		if (mnl_attr_validate(attr, MNL_TYPE_NESTED) < 0) {
			perror("mnl_attr_validate");
			return MNL_CB_ERROR;
		}
		break;
	case NFTA_CHAIN_POLICY:
	case NFTA_CHAIN_USE:
		if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0) {
			perror("mnl_attr_validate");
			return MNL_CB_ERROR;
		}
		break;
	case NFTA_CHAIN_HANDLE:
		if (mnl_attr_validate(attr, MNL_TYPE_U64) < 0) {
			perror("mnl_attr_validate");
			return MNL_CB_ERROR;
		}
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
		if (mnl_attr_validate(attr, MNL_TYPE_U64) < 0) {
			perror("mnl_attr_validate");
			return MNL_CB_ERROR;
		}
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
		if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0) {
			perror("mnl_attr_validate");
			return MNL_CB_ERROR;
		}
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

	return 0;
}

int nft_chain_nlmsg_parse(const struct nlmsghdr *nlh, struct nft_chain *c)
{
	struct nlattr *tb[NFTA_CHAIN_MAX+1] = {};
	struct nfgenmsg *nfg = mnl_nlmsg_get_payload(nlh);
	int ret = 0;

	mnl_attr_parse(nlh, sizeof(*nfg), nft_chain_parse_attr_cb, tb);
	if (tb[NFTA_CHAIN_NAME]) {
		strncpy(c->name, mnl_attr_get_str(tb[NFTA_CHAIN_NAME]),
			NFT_CHAIN_MAXNAMELEN);
		c->flags |= (1 << NFT_CHAIN_ATTR_NAME);
	}
	if (tb[NFTA_CHAIN_TABLE]) {
		c->table = strdup(mnl_attr_get_str(tb[NFTA_CHAIN_TABLE]));
		c->flags |= (1 << NFT_CHAIN_ATTR_TABLE);
	}
	if (tb[NFTA_CHAIN_HOOK])
		ret = nft_chain_parse_hook(tb[NFTA_CHAIN_HOOK], c);
	if (tb[NFTA_CHAIN_POLICY]) {
		c->policy = ntohl(mnl_attr_get_u32(tb[NFTA_CHAIN_POLICY]));
		c->flags |= (1 << NFT_CHAIN_ATTR_POLICY);
	}
	if (tb[NFTA_CHAIN_USE]) {
		c->use = ntohl(mnl_attr_get_u32(tb[NFTA_CHAIN_USE]));
		c->flags |= (1 << NFT_CHAIN_ATTR_USE);
	}
	if (tb[NFTA_CHAIN_COUNTERS])
		ret = nft_chain_parse_counters(tb[NFTA_CHAIN_COUNTERS], c);
	if (tb[NFTA_CHAIN_HANDLE]) {
		c->handle = be64toh(mnl_attr_get_u64(tb[NFTA_CHAIN_HANDLE]));
		c->flags |= (1 << NFT_CHAIN_ATTR_HANDLE);
	}
	if (tb[NFTA_CHAIN_TYPE]) {
		c->type = strdup(mnl_attr_get_str(tb[NFTA_CHAIN_TYPE]));
		c->flags |= (1 << NFT_CHAIN_ATTR_TYPE);
	}

	c->family = nfg->nfgen_family;

	return ret;
}
EXPORT_SYMBOL(nft_chain_nlmsg_parse);

static int nft_chain_xml_parse(struct nft_chain *c, char *xml)
{
#ifdef XML_PARSING
	mxml_node_t *tree = NULL;
	mxml_node_t *node = NULL;
	char *endptr = NULL;
	uint64_t utmp;
	int64_t tmp;

	/* NOTE: all XML nodes are mandatory */

	/* Load the tree */
	tree = mxmlLoadString(NULL, xml, MXML_OPAQUE_CALLBACK);
	if (tree == NULL)
		return -1;

	/* Validate version */
	if (mxmlElementGetAttr(tree, "version") == NULL) {
		mxmlDelete(tree);
		return -1;
	}
	tmp = strtoll(mxmlElementGetAttr(tree, "version"), &endptr, 10);
	if (tmp == LLONG_MAX || *endptr || tmp != NFT_CHAIN_XML_VERSION) {
		mxmlDelete(tree);
		return -1;
	}

	/* Get and set <chain name="xxx" ... >*/
	if (mxmlElementGetAttr(tree, "name") == NULL) {
		mxmlDelete(tree);
		return -1;
	}
	strncpy(c->name, mxmlElementGetAttr(tree, "name"),
		NFT_CHAIN_MAXNAMELEN);
	c->flags |= (1 << NFT_CHAIN_ATTR_NAME);

	/* Get and set <chain handle="x" ... >*/
	if (mxmlElementGetAttr(tree, "handle") == NULL) {
		mxmlDelete(tree);
		return -1;
	}

	utmp = strtoull(mxmlElementGetAttr(tree, "handle"), &endptr, 10);
	if (utmp == UINT64_MAX || utmp < 0 || *endptr) {
		mxmlDelete(tree);
		return -1;
	}

	c->handle = utmp;
	c->flags |= (1 << NFT_CHAIN_ATTR_HANDLE);

	/* Get and set <chain bytes="x" ... >*/
	if (mxmlElementGetAttr(tree, "bytes") == NULL) {
		mxmlDelete(tree);
		return -1;
	}
	utmp = strtoull(mxmlElementGetAttr(tree, "bytes"), &endptr, 10);
	if (utmp == UINT64_MAX || utmp < 0 || *endptr) {
		mxmlDelete(tree);
		return -1;
	}
	c->bytes = utmp;
	c->flags |= (1 << NFT_CHAIN_ATTR_BYTES);

	/* Get and set <chain packets="x" ... > */
	if (mxmlElementGetAttr(tree, "packets") == NULL) {
		mxmlDelete(tree);
		return -1;
	}
	utmp = strtoull(mxmlElementGetAttr(tree, "packets"), &endptr, 10);
	if (utmp == UINT64_MAX || utmp < 0 || *endptr) {
		mxmlDelete(tree);
		return -1;
	}
	c->packets = utmp;
	c->flags |= (1 << NFT_CHAIN_ATTR_PACKETS);

	/* Ignore <properties> node */
	node = mxmlFindElement(tree, tree, "properties", NULL, NULL,
			       MXML_DESCEND_FIRST);

	/* Get and set <type> */
	node = mxmlFindElement(tree, tree, "type", NULL, NULL, MXML_DESCEND);
	if (node == NULL) {
		mxmlDelete(tree);
		return -1;
	}

	if (c->type)
		free(c->type);

	c->type = strdup(node->child->value.opaque);
	c->flags |= (1 << NFT_CHAIN_ATTR_TYPE);

	/* Get and set <table> */
	node = mxmlFindElement(tree, tree, "table", NULL, NULL,	MXML_DESCEND);
	if (node == NULL) {
		mxmlDelete(tree);
		return -1;
	}
	if (c->table)
		free(c->table);

	c->table = strdup(node->child->value.opaque);
	c->flags |= (1 << NFT_CHAIN_ATTR_TABLE);

	/* Get and set <prio> */
	node = mxmlFindElement(tree, tree, "prio", NULL, NULL, MXML_DESCEND);
	if (node == NULL) {
		mxmlDelete(tree);
		return -1;
	}
	tmp = strtoll(node->child->value.opaque, &endptr, 10);
	if (tmp > INT32_MAX || tmp < INT32_MIN || *endptr) {
		mxmlDelete(tree);
		return -1;
	}

	memcpy(&c->prio, &tmp, sizeof(c->prio));
	c->flags |= (1 << NFT_CHAIN_ATTR_PRIO);

	/* Ignore <use> (cannot be set)*/
	node = mxmlFindElement(tree, tree, "use", NULL, NULL, MXML_DESCEND);

	/* Get and set <hooknum> */
	node = mxmlFindElement(tree, tree, "hooknum", NULL, NULL,
			       MXML_DESCEND);
	if (node == NULL) {
		mxmlDelete(tree);
		return -1;
	}
	utmp = strtoull(node->child->value.opaque, &endptr, 10);
	if (utmp > UINT32_MAX || utmp < 0 || *endptr) {
		mxmlDelete(tree);
		return -1;
	}

	memcpy(&c->hooknum, &utmp, sizeof(c->hooknum));
	c->flags |= (1 << NFT_CHAIN_ATTR_HOOKNUM);

	/* Get and set <policy> */
	node = mxmlFindElement(tree, tree, "policy", NULL, NULL, MXML_DESCEND);
	if (node == NULL) {
		mxmlDelete(tree);
		return -1;
	}
	utmp = strtoull(node->child->value.opaque, &endptr, 10);
	if (utmp > UINT32_MAX || utmp < 0 || *endptr) {
		mxmlDelete(tree);
		return -1;
	}

	c->policy = (uint32_t)utmp;
	c->flags |= (1 << NFT_CHAIN_ATTR_POLICY);

	/* Get and set <family> */
	node = mxmlFindElement(tree, tree, "family", NULL, NULL, MXML_DESCEND);
	if (node == NULL) {
		mxmlDelete(tree);
		return -1;
	}
	utmp = strtoull(node->child->value.opaque, &endptr, 10);
	if (utmp > UINT8_MAX || utmp < 0 || *endptr) {
		mxmlDelete(tree);
		return -1;
	}

	c->family = (uint32_t)utmp;
	c->flags |= (1 << NFT_CHAIN_ATTR_FAMILY);

	mxmlDelete(tree);
	return 0;
#else
	errno = EOPNOTSUPP;
	return -1;
#endif
}

int nft_chain_parse(struct nft_chain *c, enum nft_chain_parse_type type,
		    char *data)
{
	int ret;

	switch (type) {
	case NFT_CHAIN_PARSE_XML:
		ret = nft_chain_xml_parse(c, data);
		break;
	default:
		ret = -1;
		errno = EOPNOTSUPP;
		break;
	}

	return ret;
}
EXPORT_SYMBOL(nft_chain_parse);

static int nft_chain_snprintf_xml(char *buf, size_t size, struct nft_chain *c)
{
	return snprintf(buf, size,
		"<chain name=\"%s\" handle=\"%lu\""
			" bytes=\"%lu\" packets=\"%lu\" version=\"%d\">"
			"<properties>"
				"<type>%s</type>"
				"<table>%s</table>"
				"<prio>%d</prio>"
				"<use>%d</use>"
				"<hooknum>%d</hooknum>"
				"<policy>%d</policy>"
				"<family>%d</family>"
			"</properties>"
		"</chain>",
			c->name, c->handle, c->bytes, c->packets,
			NFT_CHAIN_XML_VERSION, c->type, c->table,
			c->prio, c->use, c->hooknum, c->policy, c->family);
}

static int nft_chain_snprintf_default(char *buf, size_t size, struct nft_chain *c)
{
	return snprintf(buf, size, "family=%u table=%s chain=%s type=%s "
				   "hook=%u prio=%d policy=%d use=%d "
				   "packets=%lu bytes=%lu",
			c->family, c->table, c->name, c->type, c->hooknum,
			c->prio, c->policy, c->use, c->packets, c->bytes);
}

int nft_chain_snprintf(char *buf, size_t size, struct nft_chain *c,
		       uint32_t type, uint32_t flags)
{
	switch(type) {
	case NFT_CHAIN_O_XML:
		return nft_chain_snprintf_xml(buf, size, c);
	case NFT_CHAIN_O_DEFAULT:
		return nft_chain_snprintf_default(buf, size, c);
	default:
		break;
	}
	return -1;
}
EXPORT_SYMBOL(nft_chain_snprintf);

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
	free(list);
}
EXPORT_SYMBOL(nft_chain_list_free);

void nft_chain_list_add(struct nft_chain *r, struct nft_chain_list *list)
{
	list_add_tail(&r->head, &list->list);
}
EXPORT_SYMBOL(nft_chain_list_add);

void nft_chain_list_del(struct nft_chain *r)
{
	list_del(&r->head);
}
EXPORT_SYMBOL(nft_chain_list_del);

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
	iter->cur = list_entry(l->list.next, struct nft_chain, head);

	return iter;
}
EXPORT_SYMBOL(nft_chain_list_iter_create);

struct nft_chain *nft_chain_list_iter_next(struct nft_chain_list_iter *iter)
{
	struct nft_chain *r = iter->cur;

	/* get next chain, if any */
	iter->cur = list_entry(iter->cur->head.next, struct nft_chain, head);
	if (&iter->cur->head == iter->list->list.next)
		return NULL;

	return r;
}
EXPORT_SYMBOL(nft_chain_list_iter_next);

void nft_chain_list_iter_destroy(struct nft_chain_list_iter *iter)
{
	free(iter);
}
EXPORT_SYMBOL(nft_chain_list_iter_destroy);
