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
#include <string.h>
#include <netinet/in.h>

#include <libmnl/libmnl.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nf_tables.h>

#include <libnftables/table.h>

struct nft_table {
	struct list_head head;

	char		*name;
	uint8_t		family;
	uint32_t	table_flags;
	uint32_t	flags;
};

struct nft_table *nft_table_alloc(void)
{
	return calloc(1, sizeof(struct nft_table));
}
EXPORT_SYMBOL(nft_table_alloc);

void nft_table_free(struct nft_table *t)
{
	if (t->flags & (1 << NFT_TABLE_ATTR_NAME))
		free(t->name);

	free(t);
}
EXPORT_SYMBOL(nft_table_free);

void nft_table_attr_set(struct nft_table *t, uint16_t attr, void *data)
{
	switch(attr) {
	case NFT_TABLE_ATTR_NAME:
		if (t->name)
			free(t->name);

		t->name = strdup(data);
		t->flags |= (1 << NFT_TABLE_ATTR_NAME);
		break;
	case NFT_TABLE_ATTR_FLAGS:
		t->table_flags = *((uint32_t *)data);
		t->flags |= (1 << NFT_TABLE_ATTR_FLAGS);
		break;
	case NFT_TABLE_ATTR_FAMILY:
		t->family = *((uint8_t *)data);
		t->flags |= (1 << NFT_TABLE_ATTR_FAMILY);
		break;
	}
}
EXPORT_SYMBOL(nft_table_attr_set);

void nft_table_attr_set_u32(struct nft_table *t, uint16_t attr, uint32_t val)
{
	nft_table_attr_set(t, attr, &val);
}
EXPORT_SYMBOL(nft_table_attr_set_u32);

const void *nft_table_attr_get(struct nft_table *t, uint16_t attr)
{
	const void *ret = NULL;

	switch(attr) {
	case NFT_TABLE_ATTR_NAME:
		if (t->flags & (1 << NFT_TABLE_ATTR_NAME))
			ret = t->name;
		break;
	case NFT_TABLE_ATTR_FLAGS:
		if (t->flags & (1 << NFT_TABLE_ATTR_FLAGS))
			ret = &t->table_flags;
		break;
	case NFT_TABLE_ATTR_FAMILY:
		if (t->flags & (1 << NFT_TABLE_ATTR_FAMILY))
			ret = &t->family;
		break;
	}
	return ret;
}
EXPORT_SYMBOL(nft_table_attr_get);

uint32_t nft_table_attr_get_u32(struct nft_table *t, uint16_t attr)
{
	const void *ret = nft_table_attr_get(t, attr);
	return ret == NULL ? 0 : *((uint32_t *)ret);
}
EXPORT_SYMBOL(nft_table_attr_get_u32);

struct nlmsghdr *
nft_table_nlmsg_build_hdr(char *buf, uint16_t cmd, uint16_t family,
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
EXPORT_SYMBOL(nft_table_nlmsg_build_hdr);

void nft_table_nlmsg_build_payload(struct nlmsghdr *nlh, const struct nft_table *t)
{
	if (t->flags & (1 << NFT_TABLE_ATTR_NAME))
		mnl_attr_put_strz(nlh, NFTA_TABLE_NAME, t->name);
	if (t->flags & (1 << NFT_TABLE_ATTR_FLAGS))
		mnl_attr_put_u32(nlh, NFTA_TABLE_FLAGS, htonl(t->table_flags));
}
EXPORT_SYMBOL(nft_table_nlmsg_build_payload);

static int nft_table_parse_attr_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, NFTA_TABLE_MAX) < 0)
		return MNL_CB_OK;

	switch(type) {
	case NFTA_TABLE_NAME:
		if (mnl_attr_validate(attr, MNL_TYPE_STRING) < 0) {
			perror("mnl_attr_validate");
			return MNL_CB_ERROR;
		}
		break;
	case NFTA_TABLE_FLAGS:
		if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0) {
			perror("mnl_attr_validate");
			return MNL_CB_ERROR;
		}
		break;
	}

	tb[type] = attr;
	return MNL_CB_OK;
}

int nft_table_nlmsg_parse(const struct nlmsghdr *nlh, struct nft_table *t)
{
	struct nlattr *tb[NFTA_TABLE_MAX+1] = {};
	struct nfgenmsg *nfg = mnl_nlmsg_get_payload(nlh);

	mnl_attr_parse(nlh, sizeof(*nfg), nft_table_parse_attr_cb, tb);
	if (tb[NFTA_TABLE_NAME]) {
		t->name = strdup(mnl_attr_get_str(tb[NFTA_TABLE_NAME]));
		t->flags |= (1 << NFT_TABLE_ATTR_NAME);
	}
	if (tb[NFTA_TABLE_FLAGS]) {
		t->table_flags = ntohl(mnl_attr_get_u32(tb[NFTA_TABLE_FLAGS]));
		t->flags |= (1 << NFT_TABLE_ATTR_FLAGS);
	}

	t->family = nfg->nfgen_family;

	return 0;
}
EXPORT_SYMBOL(nft_table_nlmsg_parse);

static int nft_table_snprintf_xml(char *buf, size_t size, struct nft_table *t)
{
	return snprintf(buf, size,
			"<table name=\"%s\" >\n"
				"\t<properties>\n"
					"\t\t<family>%u</family>\n"
					"\t\t<flags>%d</flags>\n"
					"\t\t<table_flags>%d</table_flags>\n"
				"\t</properties>\n"
			"</table>\n" ,
			t->name, t->family, t->flags, t->table_flags);
}

static int nft_table_snprintf_default(char *buf, size_t size, struct nft_table *t)
{
	return snprintf(buf, size, "table=%s family=%u flags=%x\n",
			t->name, t->family, t->table_flags);
}

int nft_table_snprintf(char *buf, size_t size, struct nft_table *t,
		       uint32_t type, uint32_t flags)
{
	switch(type) {
	case NFT_TABLE_O_XML:
		return nft_table_snprintf_xml(buf, size, t);
	case NFT_TABLE_O_DEFAULT:
		return nft_table_snprintf_default(buf, size, t);
	default:
		break;
	}
	return -1;
}
EXPORT_SYMBOL(nft_table_snprintf);

struct nft_table_list {
	struct list_head list;
};

struct nft_table_list *nft_table_list_alloc(void)
{
	struct nft_table_list *list;

	list = calloc(1, sizeof(struct nft_table_list));
	if (list == NULL)
		return NULL;

	INIT_LIST_HEAD(&list->list);

	return list;
}
EXPORT_SYMBOL(nft_table_list_alloc);

void nft_table_list_free(struct nft_table_list *list)
{
	struct nft_table *r, *tmp;

	list_for_each_entry_safe(r, tmp, &list->list, head) {
		list_del(&r->head);
		nft_table_free(r);
	}
	free(list);
}
EXPORT_SYMBOL(nft_table_list_free);

void nft_table_list_add(struct nft_table *r, struct nft_table_list *list)
{
	list_add_tail(&r->head, &list->list);
}
EXPORT_SYMBOL(nft_table_list_add);

struct nft_table_list_iter {
	struct nft_table_list	*list;
	struct nft_table	*cur;
};

struct nft_table_list_iter *nft_table_list_iter_create(struct nft_table_list *l)
{
	struct nft_table_list_iter *iter;

	iter = calloc(1, sizeof(struct nft_table_list_iter));
	if (iter == NULL)
		return NULL;

	iter->list = l;
	iter->cur = list_entry(l->list.next, struct nft_table, head);

	return iter;
}
EXPORT_SYMBOL(nft_table_list_iter_create);

struct nft_table *nft_table_list_iter_next(struct nft_table_list_iter *iter)
{
	struct nft_table *r = iter->cur;

	/* get next table, if any */
	iter->cur = list_entry(iter->cur->head.next, struct nft_table, head);
	if (&iter->cur->head == iter->list->list.next)
		return NULL;

	return r;
}
EXPORT_SYMBOL(nft_table_list_iter_next);

void nft_table_list_iter_destroy(struct nft_table_list_iter *iter)
{
	free(iter);
}
EXPORT_SYMBOL(nft_table_list_iter_destroy);
