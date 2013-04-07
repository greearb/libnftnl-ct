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

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>

#include <libmnl/libmnl.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>
#include <libnftables/expr.h>
#include <libnftables/rule.h>
#include "expr_ops.h"
#include "data_reg.h"
#include "internal.h"

static int nft_data_reg_value_snprintf_xml(char *buf, size_t size,
					   union nft_data_reg *reg,
					   uint32_t flags)
{
	int len = size, offset = 0, ret, i, j;
	uint8_t *tmp;
	int data_len = reg->len/sizeof(uint32_t);

	ret = snprintf(buf, len, "<data_reg type=\"value\" >");
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	ret = snprintf(buf+offset, len, "<len>%d</len>", data_len);
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	for (i=0; i<data_len; i++) {
		ret = snprintf(buf+offset, len, "<data%d>0x", i);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

		tmp = (uint8_t *)&reg->val[i];

		for (j=0; j<sizeof(int); j++) {
			ret = snprintf(buf+offset, len, "%.02x", tmp[j]);
			SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
		}

		ret = snprintf(buf+offset, len, "</data%d>", i);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	ret = snprintf(buf+offset, len, "</data_reg>");
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	return offset;
}

static int
nft_data_reg_value_snprintf_default(char *buf, size_t size,
				    union nft_data_reg *reg, uint32_t flags)
{
	int len = size, offset = 0, ret, i;

	for (i=0; i<reg->len/sizeof(uint32_t); i++) {
		ret = snprintf(buf+offset, len, "0x%.8x ", reg->val[i]);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

	return offset;
}

int nft_data_reg_snprintf(char *buf, size_t size, union nft_data_reg *reg,
			  uint32_t output_format, uint32_t flags, int reg_type)
{
	switch(reg_type) {
	case DATA_VALUE:
		switch(output_format) {
		case NFT_RULE_O_XML:
			return nft_data_reg_value_snprintf_xml(buf, size,
							       reg, flags);
		case NFT_RULE_O_DEFAULT:
			return nft_data_reg_value_snprintf_default(buf, size,
								   reg, flags);
		default:
			break;
		}
	case DATA_VERDICT:
		switch(output_format) {
		case NFT_RULE_O_XML:
			return snprintf(buf, size,
					"<data_reg type=\"verdict\" >"
						"<verdict>%d</verdict>"
					"</data_reg>", reg->verdict);
		case NFT_RULE_O_DEFAULT:
			return snprintf(buf, size, "verdict=%d", reg->verdict);
		default:
			break;
		}
	case DATA_CHAIN:
		switch(output_format) {
		case NFT_RULE_O_XML:
			return snprintf(buf, size,
					"<data_reg type=\"chain\" >"
						"<chain>%s</chain>"
					"</data_reg>", reg->chain);
		case NFT_RULE_O_DEFAULT:
			return snprintf(buf, size, "chain=%s", reg->chain);
		default:
			break;
		}
	default:
		break;
	}
	return -1;
}

static int nft_data_parse_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, NFTA_DATA_MAX) < 0)
		return MNL_CB_OK;

	switch(type) {
	case NFTA_DATA_VALUE:
		if (mnl_attr_validate(attr, MNL_TYPE_BINARY) < 0) {
			perror("mnl_attr_validate");
			return MNL_CB_ERROR;
		}
		break;
	case NFTA_DATA_VERDICT:
		if (mnl_attr_validate(attr, MNL_TYPE_NESTED) < 0) {
			perror("mnl_attr_validate");
			return MNL_CB_ERROR;
		}
		break;
	}
	tb[type] = attr;
	return MNL_CB_OK;
}

static int nft_verdict_parse_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, NFTA_VERDICT_MAX) < 0)
		return MNL_CB_OK;

	switch(type) {
	case NFTA_VERDICT_CODE:
		if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0) {
			perror("mnl_attr_validate");
			return MNL_CB_ERROR;
		}
		break;
	case NFTA_VERDICT_CHAIN:
		if (mnl_attr_validate(attr, MNL_TYPE_STRING) < 0) {
			perror("mnl_attr_validate");
			return MNL_CB_ERROR;
		}
		break;
	}
	tb[type] = attr;
	return MNL_CB_OK;
}

static int
nft_parse_verdict(union nft_data_reg *data, const struct nlattr *attr, int *type)
{
	struct nlattr *tb[NFTA_VERDICT_MAX+1];

	if (mnl_attr_parse_nested(attr, nft_verdict_parse_cb, tb) < 0) {
		perror("mnl_attr_parse_nested");
		return -1;
	}

	if (!tb[NFTA_VERDICT_CODE])
		return -1;

	data->verdict = ntohl(mnl_attr_get_u32(tb[NFTA_VERDICT_CODE]));

	switch(data->verdict) {
	case NF_ACCEPT:
	case NF_DROP:
	case NF_QUEUE:
	case NFT_CONTINUE:
	case NFT_BREAK:
	case NFT_RETURN:
		if (type)
			*type = DATA_VERDICT;
		data->len = sizeof(data->verdict);
		break;
	case NFT_JUMP:
	case NFT_GOTO:
		if (!tb[NFTA_VERDICT_CHAIN])
			return -1;

		data->chain = strdup(mnl_attr_get_str(tb[NFTA_VERDICT_CHAIN]));
		if (type)
			*type = DATA_CHAIN;
		break;
	default:
		return -1;
	}

	return 0;
}

static int
__nft_parse_data(union nft_data_reg *data, const struct nlattr *attr)
{
	void *orig = mnl_attr_get_payload(attr);
	size_t data_len = mnl_attr_get_payload_len(attr);

	if (data_len == 0)
		return -1;

	if (data_len > sizeof(uint32_t) * 4)
		return -1;

	memcpy(data->val, orig, data_len);
	data->len = data_len;

	return 0;
}

int nft_parse_data(union nft_data_reg *data, struct nlattr *attr, int *type)
{
	struct nlattr *tb[NFTA_DATA_MAX+1] = {};
	int ret = 0;

	if (mnl_attr_parse_nested(attr, nft_data_parse_cb, tb) < 0) {
		perror("mnl_attr_parse_nested");
		return -1;
	}
	if (tb[NFTA_DATA_VALUE]) {
		if (type)
			*type = DATA_VALUE;

		ret = __nft_parse_data(data, tb[NFTA_DATA_VALUE]);
		if (ret < 0)
			return ret;
	}
	if (tb[NFTA_DATA_VERDICT])
		ret = nft_parse_verdict(data, tb[NFTA_DATA_VERDICT], type);

	return ret;
}
