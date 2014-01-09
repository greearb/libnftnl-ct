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
#include <limits.h>
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>

#include <libmnl/libmnl.h>
#include <libnftables/expr.h>
#include <libnftables/rule.h>
#include "internal.h"

#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>

#ifdef JSON_PARSING
static int nft_data_reg_verdict_json_parse(union nft_data_reg *reg, json_t *data)
{
	int verdict;
	const char *verdict_str;

	verdict_str = nft_jansson_parse_str(data, "verdict");
	if (verdict_str == NULL)
		return -1;

	verdict = nft_str2verdict(verdict_str);
	if (verdict < 0)
		return -1;

	reg->verdict = (uint32_t)verdict;

	return 0;
}

static int nft_data_reg_chain_json_parse(union nft_data_reg *reg, json_t *data)
{
	reg->chain = strdup(nft_jansson_parse_str(data, "chain"));
	if (reg->chain == NULL) {
		return -1;
	}

	return 0;
}

static int nft_data_reg_value_json_parse(union nft_data_reg *reg, json_t *data)
{
	int i;
	char node_name[6];

	if (nft_jansson_parse_val(data, "len", NFT_TYPE_U8, &reg->len) < 0)
			return -1;

	for (i = 0; i < div_round_up(reg->len, sizeof(uint32_t)); i++) {
		sprintf(node_name, "data%d", i);

		if (nft_jansson_str2num(data, node_name, BASE_HEX,
				        &reg->val[i], NFT_TYPE_U32) != 0)
			return -1;
	}

	return 0;
}
#endif

int nft_data_reg_json_parse(union nft_data_reg *reg, json_t *data)
{
#ifdef JSON_PARSING

	const char *type;

	type = nft_jansson_parse_str(data, "type");
	if (type == NULL)
		return -1;

	/* Select what type of parsing is needed */
	if (strcmp(type, "value") == 0) {
		return nft_data_reg_value_json_parse(reg, data);
	} else if (strcmp(type, "verdict") == 0) {
		return nft_data_reg_verdict_json_parse(reg, data);
	} else if (strcmp(type, "chain") == 0) {
		return nft_data_reg_chain_json_parse(reg, data);
	}

	return 0;
#else
	errno = EOPNOTSUPP;
	return -1;
#endif
}

#ifdef XML_PARSING
static int nft_data_reg_verdict_xml_parse(union nft_data_reg *reg,
					  mxml_node_t *tree)
{
	int verdict;
	const char *verdict_str;

	verdict_str = nft_mxml_str_parse(tree, "verdict", MXML_DESCEND_FIRST,
					 NFT_XML_MAND);
	if (verdict_str == NULL)
		return DATA_NONE;

	verdict = nft_str2verdict(verdict_str);
	if (verdict < 0)
		return DATA_NONE;

	reg->verdict = (uint32_t)verdict;

	return DATA_VERDICT;
}

static int nft_data_reg_chain_xml_parse(union nft_data_reg *reg,
					mxml_node_t *tree)
{
	const char *chain;

	chain = nft_mxml_str_parse(tree, "chain", MXML_DESCEND_FIRST,
				   NFT_XML_MAND);
	if (chain == NULL)
		return DATA_NONE;

	if (reg->chain)
		xfree(reg->chain);

	reg->chain = strdup(chain);
	return DATA_CHAIN;
}

static int nft_data_reg_value_xml_parse(union nft_data_reg *reg,
					mxml_node_t *tree)
{
	int i;
	char node_name[6];

	/*
	* <data_reg type="value">
	*    <len>16</len>
	*    <data0>0xc09a002a</data0>
	*    <data1>0x2700cac1</data1>
	*    <data2>0x00000000</data2>
	*    <data3>0x08000000</data3>
	* </data_reg>
	*/

	if (nft_mxml_num_parse(tree, "len", MXML_DESCEND_FIRST, BASE_DEC,
			       &reg->len, NFT_TYPE_U8, NFT_XML_MAND) != 0)
		return DATA_NONE;

	/* Get and set <dataN> */
	for (i = 0; i < div_round_up(reg->len, sizeof(uint32_t)); i++) {
		sprintf(node_name, "data%d", i);

		if (nft_mxml_num_parse(tree, node_name, MXML_DESCEND_FIRST,
				       BASE_HEX, &reg->val[i], NFT_TYPE_U32,
				       NFT_XML_MAND) != 0)
			return DATA_NONE;
	}

	return DATA_VALUE;
}
#endif

int nft_data_reg_xml_parse(union nft_data_reg *reg, mxml_node_t *tree)
{
#ifdef XML_PARSING
	const char *type;
	mxml_node_t *node;

	node = mxmlFindElement(tree, tree, "data_reg", "type", NULL,
			       MXML_DESCEND_FIRST);
	if (node == NULL) {
		errno = EINVAL;
		return DATA_NONE;
	}

	type = mxmlElementGetAttr(node, "type");

	if (type == NULL) {
		errno = EINVAL;
		return DATA_NONE;
	}

	if (strcmp(type, "value") == 0)
		return nft_data_reg_value_xml_parse(reg, node);
	else if (strcmp(type, "verdict") == 0)
		return nft_data_reg_verdict_xml_parse(reg, node);
	else if (strcmp(type, "chain") == 0)
		return nft_data_reg_chain_xml_parse(reg, node);

	return DATA_NONE;
#else
	errno = EOPNOTSUPP;
	return -1;
#endif
}

static int
nft_data_reg_value_snprintf_json(char *buf, size_t size,
					   union nft_data_reg *reg,
					   uint32_t flags)
{
	int len = size, offset = 0, ret, i, j;
	uint32_t utemp;
	uint8_t *tmp;

	ret = snprintf(buf, len, "\"data_reg\":{\"type\":\"value\",");
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	ret = snprintf(buf+offset, len, "\"len\":%u,", reg->len);
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	for (i = 0; i < div_round_up(reg->len, sizeof(uint32_t)); i++) {
		ret = snprintf(buf+offset, len, "\"data%d\":\"0x", i);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

		utemp = htonl(reg->val[i]);
		tmp = (uint8_t *)&utemp;

		for (j = 0; j<sizeof(uint32_t); j++) {
			ret = snprintf(buf+offset, len, "%.02x", tmp[j]);
			SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
		}

		ret = snprintf(buf+offset, len, "\",");
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}
	offset--;
	ret = snprintf(buf+offset, len, "}");
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	return offset;
}

static
int nft_data_reg_value_snprintf_xml(char *buf, size_t size,
				    union nft_data_reg *reg, uint32_t flags)
{
	int len = size, offset = 0, ret, i, j;
	uint32_t be;
	uint8_t *tmp;

	ret = snprintf(buf, len, "<data_reg type=\"value\">");
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	ret = snprintf(buf+offset, len, "<len>%u</len>", reg->len);
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	for (i = 0; i < div_round_up(reg->len, sizeof(uint32_t)); i++) {
		ret = snprintf(buf+offset, len, "<data%d>0x", i);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

		be = htonl(reg->val[i]);
		tmp = (uint8_t *)&be;

		for (j = 0; j < sizeof(uint32_t); j++) {
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

	for (i = 0; i < div_round_up(reg->len, sizeof(uint32_t)); i++) {
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
		case NFT_OUTPUT_DEFAULT:
			return nft_data_reg_value_snprintf_default(buf, size,
								   reg, flags);
		case NFT_OUTPUT_XML:
			return nft_data_reg_value_snprintf_xml(buf, size,
							       reg, flags);
		case NFT_OUTPUT_JSON:
			return nft_data_reg_value_snprintf_json(buf, size,
							       reg, flags);
		default:
			break;
		}
	case DATA_VERDICT:
		switch(output_format) {
		case NFT_OUTPUT_DEFAULT:
			return snprintf(buf, size, "%d ", reg->verdict);
		case NFT_OUTPUT_XML:
			return snprintf(buf, size,
					"<data_reg type=\"verdict\">"
						"<verdict>%s</verdict>"
					"</data_reg>",
					nft_verdict2str(reg->verdict));
		case NFT_OUTPUT_JSON:
			return snprintf(buf, size,
					"\"data_reg\":{"
					"\"type\":\"verdict\","
					"\"verdict\":\"%s\""
					"}", nft_verdict2str(reg->verdict));
		default:
			break;
		}
	case DATA_CHAIN:
		switch(output_format) {
		case NFT_OUTPUT_DEFAULT:
			return snprintf(buf, size, "%s ", reg->chain);
		case NFT_OUTPUT_XML:
			return snprintf(buf, size,
					"<data_reg type=\"chain\">"
						"<chain>%s</chain>"
					"</data_reg>", reg->chain);
		case NFT_OUTPUT_JSON:
			return snprintf(buf, size,
					"\"data_reg\":{\"type\":\"chain\","
					"\"chain\":\"%s\""
					"}", reg->chain);
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
	uint32_t data_len = mnl_attr_get_payload_len(attr);

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

