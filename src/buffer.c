/*
 * (C) 2012-2014 by Pablo Neira Ayuso <pablo@netfilter.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <buffer.h>
#include <libnftnl/common.h>
#include "internal.h"

int nft_buf_update(struct nft_buf *b, int ret)
{
	if (ret < 0) {
		b->fail = true;
	} else {
		b->off += ret;
		if (ret > b->len)
			ret = b->len;
		b->size += ret;
		b->len -= ret;
	}

	return ret;
}

int nft_buf_done(struct nft_buf *b)
{
	if (b->fail)
		return -1;

	/* Remove trailing comma in json */
	if (b->size > 0 && b->buf[b->size - 1] == ',') {
		b->off--;
		b->size--;
		b->len++;
	}

	return b->off;
}

static int nft_buf_put(struct nft_buf *b, const char *fmt, ...)
{
	int ret;
	va_list ap;

	va_start(ap, fmt);
	ret = vsnprintf(b->buf + b->off, b->len, fmt, ap);
	ret = nft_buf_update(b, ret);
	va_end(ap);

	return ret;
}

int nft_buf_open(struct nft_buf *b, int type, const char *tag)
{
	switch (type) {
	case NFT_OUTPUT_XML:
		return nft_buf_put(b, "<%s>", tag);
	case NFT_OUTPUT_JSON:
		return nft_buf_put(b, "{\"%s\":{", tag);
	default:
		return 0;
	}
}

int nft_buf_close(struct nft_buf *b, int type, const char *tag)
{
	switch (type) {
	case NFT_OUTPUT_XML:
		return nft_buf_put(b, "</%s>");
	case NFT_OUTPUT_JSON:
		/* Remove trailing comma in json */
		if (b->size > 0 && b->buf[b->size - 1] == ',') {
			b->off--;
			b->size--;
			b->len++;
		}

		return nft_buf_put(b, "}}");
	default:
		return 0;
	}
}

int nft_buf_u32(struct nft_buf *b, int type, uint32_t value, const char *tag)
{
	switch (type) {
	case NFT_OUTPUT_XML:
		return nft_buf_put(b, "<%s>%u</%s>", tag, value, tag);
	case NFT_OUTPUT_JSON:
		return nft_buf_put(b, "\"%s\":%u,", tag, value);
	default:
		return 0;
	}
}

int nft_buf_s32(struct nft_buf *b, int type, uint32_t value, const char *tag)
{
	switch (type) {
	case NFT_OUTPUT_XML:
		return nft_buf_put(b, "<%s>%d</%s>", tag, value, tag);
	case NFT_OUTPUT_JSON:
		return nft_buf_put(b, "\"%s\":%d,", tag, value);
	default:
		return 0;
	}
}

int nft_buf_u64(struct nft_buf *b, int type, uint64_t value, const char *tag)
{
	switch (type) {
	case NFT_OUTPUT_XML:
		return nft_buf_put(b, "<%s>%"PRIu64"</%s>", tag, value, tag);
	case NFT_OUTPUT_JSON:
		return nft_buf_put(b, "\"%s\":%"PRIu64",", tag, value);
	default:
		return 0;
	}
}

int nft_buf_str(struct nft_buf *b, int type, const char *str, const char *tag)
{
	switch (type) {
	case NFT_OUTPUT_XML:
		return nft_buf_put(b, "<%s>%s</%s>", tag, str, tag);
	case NFT_OUTPUT_JSON:
		return nft_buf_put(b, "\"%s\":\"%s\",", tag, str);
	default:
		return 0;
	}
}

int nft_buf_reg(struct nft_buf *b, int type, union nft_data_reg *reg,
		int reg_type, const char *tag)
{
	int ret;

	switch (type) {
	case NFT_OUTPUT_XML:
		ret = nft_buf_put(b, "<%s>", tag);
		ret = nft_data_reg_snprintf(b->buf + b->off, b->len, reg,
                                    NFT_OUTPUT_XML, 0, reg_type);
		nft_buf_update(b, ret);
		return nft_buf_put(b, "</%s>", tag);
	case NFT_OUTPUT_JSON:
		nft_buf_put(b, "\"%s\":{", tag);
		ret = nft_data_reg_snprintf(b->buf + b->off, b->len, reg,
					    NFT_OUTPUT_JSON, 0, reg_type);
		nft_buf_update(b, ret);
		return nft_buf_put(b, "},");
	}
	return 0;
}
