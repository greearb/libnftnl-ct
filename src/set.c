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
#include <string.h>
#include <netinet/in.h>

#include <libmnl/libmnl.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nf_tables.h>

#include <libnftables/set.h>

#include "linux_list.h"
#include "expr/data_reg.h"

struct nft_set *nft_set_alloc(void)
{
	struct nft_set *s;

	s = calloc(1, sizeof(struct nft_set));
	if (s == NULL)
		return NULL;

	INIT_LIST_HEAD(&s->element_list);
	return s;
}
EXPORT_SYMBOL(nft_set_alloc);

void nft_set_free(struct nft_set *s)
{
	struct nft_set_elem *elem, *tmp;

	if (s->table != NULL)
		free(s->table);
	if (s->name != NULL)
		free(s->name);

	list_for_each_entry_safe(elem, tmp, &s->element_list, head) {
		list_del(&elem->head);
		nft_set_elem_free(elem);
	}
	free(s);
}
EXPORT_SYMBOL(nft_set_free);

void nft_set_attr_unset(struct nft_set *s, uint16_t attr)
{
	switch (attr) {
	case NFT_SET_ATTR_TABLE:
		if (s->flags & (1 << NFT_SET_ATTR_TABLE))
			if (s->table) {
				free(s->table);
				s->table = NULL;
			}
		break;
	case NFT_SET_ATTR_NAME:
		if (s->flags & (1 << NFT_SET_ATTR_NAME))
			if (s->name) {
				free(s->name);
				s->name = NULL;
			}
		break;
	default:
		return;
	}

	s->flags &= ~(1 << attr);
}
EXPORT_SYMBOL(nft_set_attr_unset);

void nft_set_attr_set(struct nft_set *s, uint16_t attr, const void *data)
{
	switch(attr) {
	case NFT_SET_ATTR_TABLE:
		if (s->table)
			free(s->table);

		s->table = strdup(data);
		break;
	case NFT_SET_ATTR_NAME:
		if (s->name)
			free(s->name);

		s->name = strdup(data);
		break;
	case NFT_SET_ATTR_FLAGS:
		s->set_flags = *((uint32_t *)data);
		break;
	case NFT_SET_ATTR_KEY_TYPE:
		s->key_type = *((uint32_t *)data);
		break;
	case NFT_SET_ATTR_KEY_LEN:
		s->key_len = *((uint32_t *)data);
		break;
	default:
		return;
	}
	s->flags |= (1 << attr);
}
EXPORT_SYMBOL(nft_set_attr_set);

void nft_set_attr_set_u32(struct nft_set *s, uint16_t attr, uint32_t val)
{
	nft_set_attr_set(s, attr, &val);
}
EXPORT_SYMBOL(nft_set_attr_set_u32);

void nft_set_attr_set_str(struct nft_set *s, uint16_t attr, const char *str)
{
	nft_set_attr_set(s, attr, str);
}
EXPORT_SYMBOL(nft_set_attr_set_str);

void *nft_set_attr_get(struct nft_set *s, uint16_t attr)
{
	switch(attr) {
	case NFT_SET_ATTR_TABLE:
		if (s->flags & (1 << NFT_SET_ATTR_TABLE))
			return s->table;
		break;
	case NFT_SET_ATTR_NAME:
		if (s->flags & (1 << NFT_SET_ATTR_NAME))
			return s->name;
		break;
	case NFT_SET_ATTR_FLAGS:
		if (s->flags & (1 << NFT_SET_ATTR_FLAGS))
			return &s->key_type;
		break;
	case NFT_SET_ATTR_KEY_TYPE:
		if (s->flags & (1 << NFT_SET_ATTR_KEY_TYPE))
			return &s->key_type;
		break;
	case NFT_SET_ATTR_KEY_LEN:
		if (s->flags & (1 << NFT_SET_ATTR_KEY_LEN))
			return &s->key_len;
		break;
	case NFT_SET_ATTR_DATA_TYPE:
		if (s->flags & (1 << NFT_SET_ATTR_DATA_TYPE))
			return &s->data_type;
		break;
	case NFT_SET_ATTR_DATA_LEN:
		if (s->flags & (1 << NFT_SET_ATTR_DATA_LEN))
			return &s->data_len;
		break;
	default:
		break;
	}
	return NULL;
}
EXPORT_SYMBOL(nft_set_attr_get);

const char *nft_set_attr_get_str(struct nft_set *s, uint16_t attr)
{
	return nft_set_attr_get(s, attr);
}
EXPORT_SYMBOL(nft_set_attr_get_str);

uint32_t nft_set_attr_get_u32(struct nft_set *s, uint16_t attr)
{
	uint32_t val = *((uint32_t *)nft_set_attr_get(s, attr));
	return val;
}
EXPORT_SYMBOL(nft_set_attr_get_u32);

struct nlmsghdr *
nft_set_nlmsg_build_hdr(char *buf, uint16_t cmd, uint16_t family,
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
EXPORT_SYMBOL(nft_set_nlmsg_build_hdr);

void nft_set_nlmsg_build_payload(struct nlmsghdr *nlh, struct nft_set *s)
{
	if (s->flags & (1 << NFT_SET_ATTR_TABLE))
		mnl_attr_put_strz(nlh, NFTA_SET_TABLE, s->table);
	if (s->flags & (1 << NFT_SET_ATTR_NAME))
		mnl_attr_put_strz(nlh, NFTA_SET_NAME, s->name);
	if (s->flags & (1 << NFT_SET_ATTR_FLAGS))
		mnl_attr_put_u32(nlh, NFTA_SET_FLAGS, htonl(s->set_flags));
	if (s->flags & (1 << NFT_SET_ATTR_KEY_TYPE))
		mnl_attr_put_u32(nlh, NFTA_SET_KEY_TYPE, htonl(s->key_type));
	if (s->flags & (1 << NFT_SET_ATTR_KEY_LEN))
		mnl_attr_put_u32(nlh, NFTA_SET_KEY_LEN, htonl(s->key_len));
	/* These are only used to map matching -> action (1:1) */
	if (s->flags & (1 << NFT_SET_ATTR_DATA_TYPE))
		mnl_attr_put_u32(nlh, NFTA_SET_DATA_TYPE, htonl(s->data_type));
	if (s->flags & (1 << NFT_SET_ATTR_DATA_LEN))
		mnl_attr_put_u32(nlh, NFTA_SET_DATA_LEN, htonl(s->data_len));
}
EXPORT_SYMBOL(nft_set_nlmsg_build_payload);

static int nft_set_parse_attr_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, NFTA_SET_MAX) < 0)
		return MNL_CB_OK;

	switch(type) {
	case NFTA_SET_TABLE:
	case NFTA_SET_NAME:
		if (mnl_attr_validate(attr, MNL_TYPE_STRING) < 0) {
			perror("mnl_attr_validate");
			return MNL_CB_ERROR;
		}
		break;
	case NFTA_SET_FLAGS:
	case NFTA_SET_KEY_TYPE:
	case NFTA_SET_KEY_LEN:
	case NFTA_SET_DATA_TYPE:
	case NFTA_SET_DATA_LEN:
		if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0) {
			perror("mnl_attr_validate");
			return MNL_CB_ERROR;
		}
		break;
	}

	tb[type] = attr;
	return MNL_CB_OK;
}

int nft_set_nlmsg_parse(const struct nlmsghdr *nlh, struct nft_set *s)
{
	struct nlattr *tb[NFTA_SET_MAX+1] = {};
	struct nfgenmsg *nfg = mnl_nlmsg_get_payload(nlh);
	int ret = 0;

	mnl_attr_parse(nlh, sizeof(*nfg), nft_set_parse_attr_cb, tb);
	if (tb[NFTA_SET_TABLE]) {
		s->table = strdup(mnl_attr_get_str(tb[NFTA_SET_TABLE]));
		s->flags |= (1 << NFT_SET_ATTR_TABLE);
	}
	if (tb[NFTA_SET_NAME]) {
		s->name = strdup(mnl_attr_get_str(tb[NFTA_SET_NAME]));
		s->flags |= (1 << NFT_SET_ATTR_NAME);
	}
	if (tb[NFTA_SET_FLAGS]) {
		s->set_flags = ntohl(mnl_attr_get_u32(tb[NFTA_SET_FLAGS]));
		s->flags |= (1 << NFT_SET_ATTR_FLAGS);
	}
	if (tb[NFTA_SET_KEY_TYPE]) {
		s->key_type = ntohl(mnl_attr_get_u32(tb[NFTA_SET_KEY_TYPE]));
		s->flags |= (1 << NFT_SET_ATTR_KEY_TYPE);
	}
	if (tb[NFTA_SET_KEY_LEN]) {
		s->key_len = ntohl(mnl_attr_get_u32(tb[NFTA_SET_KEY_LEN]));
		s->flags |= (1 << NFT_SET_ATTR_KEY_LEN);
	}
	if (tb[NFTA_SET_DATA_TYPE]) {
		s->data_type = ntohl(mnl_attr_get_u32(tb[NFTA_SET_DATA_TYPE]));
		s->flags |= (1 << NFT_SET_ATTR_DATA_TYPE);
	}
	if (tb[NFTA_SET_DATA_LEN]) {
		s->data_len = ntohl(mnl_attr_get_u32(tb[NFTA_SET_DATA_LEN]));
		s->flags |= (1 << NFT_SET_ATTR_DATA_LEN);
	}

	return ret;
}
EXPORT_SYMBOL(nft_set_nlmsg_parse);

int nft_set_snprintf(char *buf, size_t size, struct nft_set *s,
		     uint32_t type, uint32_t flags)
{
	int ret;
	int len = size, offset = 0;
	struct nft_set_elem *elem;

	ret = snprintf(buf, size, "set=%s table=%s flags=%x",
			s->name, s->table, s->set_flags);
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	/* Empty set? Skip printinf of elements */
	if (list_empty(&s->element_list))
		return offset;

	ret = snprintf(buf+offset, size, "\n");
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	list_for_each_entry(elem, &s->element_list, head) {
		ret = snprintf(buf+offset, size, "\t");
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

		ret = nft_set_elem_snprintf(buf+offset, size, elem, type, flags);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	return offset;
}
EXPORT_SYMBOL(nft_set_snprintf);

void nft_set_elem_add(struct nft_set *s, struct nft_set_elem *elem)
{
	list_add_tail(&elem->head, &s->element_list);
}
EXPORT_SYMBOL(nft_set_elem_add);

struct nft_set_list {
	struct list_head list;
};

struct nft_set_list *nft_set_list_alloc(void)
{
	struct nft_set_list *list;

	list = calloc(1, sizeof(struct nft_set_list));
	if (list == NULL)
		return NULL;

	INIT_LIST_HEAD(&list->list);

	return list;
}
EXPORT_SYMBOL(nft_set_list_alloc);

void nft_set_list_free(struct nft_set_list *list)
{
	struct nft_set *s, *tmp;

	list_for_each_entry_safe(s, tmp, &list->list, head) {
		list_del(&s->head);
		nft_set_free(s);
	}
	free(list);
}
EXPORT_SYMBOL(nft_set_list_free);

void nft_set_list_add(struct nft_set *s, struct nft_set_list *list)
{
	list_add_tail(&s->head, &list->list);
}
EXPORT_SYMBOL(nft_set_list_add);

struct nft_set_list_iter {
	struct nft_set_list	*list;
	struct nft_set		*cur;
};

struct nft_set_list_iter *nft_set_list_iter_create(struct nft_set_list *l)
{
	struct nft_set_list_iter *iter;

	iter = calloc(1, sizeof(struct nft_set_list_iter));
	if (iter == NULL)
		return NULL;

	iter->list = l;
	iter->cur = list_entry(l->list.next, struct nft_set, head);

	return iter;
}
EXPORT_SYMBOL(nft_set_list_iter_create);

struct nft_set *nft_set_list_iter_cur(struct nft_set_list_iter *iter)
{
	return iter->cur;
}
EXPORT_SYMBOL(nft_set_list_iter_cur);

struct nft_set *nft_set_list_iter_next(struct nft_set_list_iter *iter)
{
	struct nft_set *s = iter->cur;

	/* get next rule, if any */
	iter->cur = list_entry(iter->cur->head.next, struct nft_set, head);
	if (&iter->cur->head == iter->list->list.next)
		return NULL;

	return s;
}
EXPORT_SYMBOL(nft_set_list_iter_next);

void nft_set_list_iter_destroy(struct nft_set_list_iter *iter)
{
	free(iter);
}
EXPORT_SYMBOL(nft_set_list_iter_destroy);
