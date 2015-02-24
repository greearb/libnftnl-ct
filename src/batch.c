/*
 * Copyright (c) 2013-2015 Pablo Neira Ayuso <pablo@netfilter.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include "internal.h"
#include <errno.h>
#include <libmnl/libmnl.h>
#include <libnftnl/batch.h>

struct nft_batch {
	uint32_t		num_pages;
	struct nft_batch_page	*current_page;
	uint32_t		page_size;
	uint32_t		page_overrun_size;
	struct list_head	page_list;
};

struct nft_batch_page {
	struct list_head	head;
	struct mnl_nlmsg_batch	*batch;
};

static struct nft_batch_page *nft_batch_page_alloc(struct nft_batch *batch)
{
	struct nft_batch_page *page;
	char *buf;

	page = malloc(sizeof(struct nft_batch_page));
	if (page == NULL)
		return NULL;

	buf = malloc(batch->page_size + batch->page_overrun_size);
	if (buf == NULL)
		goto err1;

	page->batch = mnl_nlmsg_batch_start(buf, batch->page_size);
	if (page->batch == NULL)
		goto err2;

	return page;
err2:
	free(buf);
err1:
	free(page);
	return NULL;
}

static void nft_batch_add_page(struct nft_batch_page *page,
			       struct nft_batch *batch)
{
	batch->current_page = page;
	batch->num_pages++;
	list_add_tail(&page->head, &batch->page_list);
}

struct nft_batch *nft_batch_alloc(uint32_t pg_size, uint32_t pg_overrun_size)
{
	struct nft_batch *batch;
	struct nft_batch_page *page;

	batch = calloc(1, sizeof(struct nft_batch));
	if (batch == NULL)
		return NULL;

	batch->page_size = pg_size;
	batch->page_overrun_size = pg_overrun_size;
	INIT_LIST_HEAD(&batch->page_list);

	page = nft_batch_page_alloc(batch);
	if (page == NULL)
		goto err1;

	nft_batch_add_page(page, batch);
	return batch;
err1:
	free(batch);
	return NULL;
}
EXPORT_SYMBOL(nft_batch_alloc);

void nft_batch_free(struct nft_batch *batch)
{
	struct nft_batch_page *page, *next;

	list_for_each_entry_safe(page, next, &batch->page_list, head) {
		free(mnl_nlmsg_batch_head(page->batch));
		mnl_nlmsg_batch_stop(page->batch);
		free(page);
	}

	free(batch);
}
EXPORT_SYMBOL(nft_batch_free);

int nft_batch_update(struct nft_batch *batch)
{
	struct nft_batch_page *page;
	struct nlmsghdr *last_nlh;

	if (mnl_nlmsg_batch_next(batch->current_page->batch))
		return 0;

	last_nlh = nft_batch_buffer(batch);

	page = nft_batch_page_alloc(batch);
	if (page == NULL)
		goto err1;

	nft_batch_add_page(page, batch);

	memcpy(nft_batch_buffer(batch), last_nlh, last_nlh->nlmsg_len);
	mnl_nlmsg_batch_next(batch->current_page->batch);

	return 0;
err1:
	return -1;
}
EXPORT_SYMBOL(nft_batch_update);

void *nft_batch_buffer(struct nft_batch *batch)
{
	return mnl_nlmsg_batch_current(batch->current_page->batch);
}
EXPORT_SYMBOL(nft_batch_buffer);

uint32_t nft_batch_buffer_len(struct nft_batch *batch)
{
	return mnl_nlmsg_batch_size(batch->current_page->batch);
}
EXPORT_SYMBOL(nft_batch_buffer_len);

int nft_batch_iovec_len(struct nft_batch *batch)
{
	int num_pages = batch->num_pages;

	/* Skip last page if it's empty */
	if (mnl_nlmsg_batch_is_empty(batch->current_page->batch))
		num_pages--;

	return num_pages;
}
EXPORT_SYMBOL(nft_batch_iovec_len);

void nft_batch_iovec(struct nft_batch *batch, struct iovec *iov, uint32_t iovlen)
{
	struct nft_batch_page *page;
	int i = 0;

	list_for_each_entry(page, &batch->page_list, head) {
		if (i >= iovlen)
			break;

		iov[i].iov_base = mnl_nlmsg_batch_head(page->batch);
		iov[i].iov_len = mnl_nlmsg_batch_size(page->batch);
		i++;
	}
}
EXPORT_SYMBOL(nft_batch_iovec);
