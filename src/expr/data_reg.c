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
#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>
#include <libnftables/expr.h>
#include <libnftables/rule.h>
#include "expr_ops.h"
#include "data_reg.h"
#include "internal.h"

#ifdef XML_PARSING
static int nft_data_reg_verdict_xml_parse(union nft_data_reg *reg, char *xml)
{
	mxml_node_t *tree = NULL;
	mxml_node_t *node = NULL;
	char *endptr;
	long int tmp;

	tree = mxmlLoadString(NULL, xml, MXML_OPAQUE_CALLBACK);
	if (tree == NULL)
		return -1;

	node = mxmlFindElement(tree, tree, "data_reg", NULL, NULL,
			       MXML_DESCEND_FIRST);

	if (node == NULL) {
		mxmlDelete(tree);
		return -1;
	}

	/* Get and validate <data_reg type="verdict" >*/
	if (mxmlElementGetAttr(tree, "type") == NULL) {
		mxmlDelete(tree);
		return -1;
	}

	if (strcmp(mxmlElementGetAttr(tree, "type"), "verdict") != 0) {
		mxmlDelete(tree);
		return -1;
	}

	/* Get and set <verdict> */
	node = mxmlFindElement(tree, tree, "verdict", NULL, NULL,
			       MXML_DESCEND_FIRST);
	if (node == NULL) {
		mxmlDelete(tree);
		return -1;
	}

	errno = 0;
	tmp = strtoll(node->child->value.opaque, &endptr, 10);
	if (tmp > INT_MAX || tmp < INT_MIN || errno != 0
						|| strlen(endptr) > 0) {
		mxmlDelete(tree);
		return -1;
	}

	reg->verdict = tmp;

	mxmlDelete(tree);
	return 0;
}

static int nft_data_reg_chain_xml_parse(union nft_data_reg *reg, char *xml)
{
	mxml_node_t *tree = NULL;
	mxml_node_t *node = NULL;

	tree = mxmlLoadString(NULL, xml, MXML_OPAQUE_CALLBACK);
	if (tree == NULL)
		return -1;

	node = mxmlFindElement(tree, tree, "data_reg", NULL, NULL,
			       MXML_DESCEND_FIRST);

	if (node == NULL) {
		mxmlDelete(tree);
		return -1;
	}

	/* Get and validate <data_reg type="chain" >*/
	if (mxmlElementGetAttr(tree, "type") == NULL) {
		mxmlDelete(tree);
		return -1;
	}

	if (strcmp(mxmlElementGetAttr(tree, "type"), "chain") != 0) {
		mxmlDelete(tree);
		return -1;
	}

	/* Get and set <chain> */
	node = mxmlFindElement(tree, tree, "chain", NULL, NULL, MXML_DESCEND);
	if (node == NULL) {
		mxmlDelete(tree);
		return -1;
	}

	/* no max len value to validate? */
	if (strlen(node->child->value.opaque) < 1) {
		mxmlDelete(tree);
		return -1;
	}

	if (reg->chain)
		free(reg->chain);

	reg->chain = strdup(node->child->value.opaque);

	mxmlDelete(tree);
	return 0;
}

static int nft_data_reg_value_xml_parse(union nft_data_reg *reg, char *xml)
{
	mxml_node_t *tree = NULL;
	mxml_node_t *node = NULL;
	int i;
	int64_t tmp;
	uint64_t utmp;
	char *endptr;
	char node_name[6];

	tree = mxmlLoadString(NULL, xml, MXML_OPAQUE_CALLBACK);
	if (tree == NULL)
		return -1;

	node = mxmlFindElement(tree, tree, "data_reg", NULL, NULL,
			       MXML_DESCEND_FIRST);

	if (node == NULL) {
		mxmlDelete(tree);
		return -1;
	}

	/*
	* <data_reg type="value">
	*    <len>16</len>
	*    <data0>0xc09a002a</data0>
	*    <data1>0x2700cac1</data1>
	*    <data2>0x00000000</data2>
	*    <data3>0x08000000</data3>
	* </data_reg>
	*/

	/* Get and validate <data_reg type="value" ... >*/
	if (mxmlElementGetAttr(node, "type") == NULL) {
		mxmlDelete(tree);
		return -1;
	}

	if (strcmp(mxmlElementGetAttr(node, "type"), "value") != 0) {
		mxmlDelete(tree);
		return -1;
	}

	/* Get <len> */
	node = mxmlFindElement(tree, tree, "len", NULL, NULL, MXML_DESCEND);
	if (node == NULL) {
		mxmlDelete(tree);
		return -1;
	}

	tmp = strtoll(node->child->value.opaque, &endptr, 10);
	if (tmp > INT64_MAX || tmp < 0 || *endptr) {
		mxmlDelete(tree);
		return -1;
	}

	reg->len = tmp;

	/* Get and set <dataN> */
	for (i = 0; i < div_round_up(reg->len, sizeof(uint32_t)); i++) {
		sprintf(node_name, "data%d", i);

		node = mxmlFindElement(tree, tree, node_name, NULL,
				       NULL, MXML_DESCEND);
		if (node == NULL) {
			mxmlDelete(tree);
			return -1;
		}

		utmp = strtoull(node->child->value.opaque, &endptr, 16);
		if (utmp == UINT64_MAX || utmp < 0 || *endptr) {
			mxmlDelete(tree);
			return -1;
		}
		reg->val[i] = utmp;
	}

	mxmlDelete(tree);
	return 0;
}
#endif

int nft_data_reg_xml_parse(union nft_data_reg *reg, char *xml)
{
#ifdef XML_PARSING
	mxml_node_t *node = NULL;
	mxml_node_t *tree = mxmlLoadString(NULL, xml, MXML_OPAQUE_CALLBACK);

	if (tree == NULL)
		return -1;

	node = mxmlFindElement(tree, tree, "data_reg", NULL, NULL,
			       MXML_DESCEND_FIRST);
	if (node == NULL) {
		mxmlDelete(tree);
		return -1;
	}

	/* Get <data_reg type="xxx" ... >*/
	if (mxmlElementGetAttr(node, "type") == NULL) {
		mxmlDelete(tree);
		return -1;
	}

	/* Select what type of parsing is needed */
	if (strcmp(mxmlElementGetAttr(node, "type"), "value") == 0) {
		mxmlDelete(tree);
		return nft_data_reg_value_xml_parse(reg, xml);
	} else if (strcmp(mxmlElementGetAttr(node, "type"), "verdict") == 0) {
		mxmlDelete(tree);
		return nft_data_reg_verdict_xml_parse(reg, xml);
	} else if (strcmp(mxmlElementGetAttr(node, "type"), "chain") == 0) {
		mxmlDelete(tree);
		return nft_data_reg_chain_xml_parse(reg, xml);
	}

	mxmlDelete(tree);
	return -1;
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

	ret = snprintf(buf, len, "\"data_reg\": { \"type\" : \"value\", ");
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	ret = snprintf(buf+offset, len, "\"len\" : %zd, ", reg->len);
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	for (i = 0; i < div_round_up(reg->len, sizeof(uint32_t)); i++) {
		ret = snprintf(buf+offset, len, "\"data%d\" : \"0x", i);
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

		utemp = htonl(reg->val[i]);
		tmp = (uint8_t *)&utemp;

		for (j = 0; j<sizeof(uint32_t); j++) {
			ret = snprintf(buf+offset, len, "%.02x", tmp[j]);
			SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
		}

		ret = snprintf(buf+offset, len, "\"");
		SNPRINTF_BUFFER_SIZE(ret, size, len, offset);
	}

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

	ret = snprintf(buf+offset, len, "<len>%zd</len>", reg->len);
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
		case NFT_RULE_O_DEFAULT:
			return nft_data_reg_value_snprintf_default(buf, size,
								   reg, flags);
		case NFT_RULE_O_XML:
			return nft_data_reg_value_snprintf_xml(buf, size,
							       reg, flags);
		case NFT_RULE_O_JSON:
			return nft_data_reg_value_snprintf_json(buf, size,
							       reg, flags);
		default:
			break;
		}
	case DATA_VERDICT:
		switch(output_format) {
		case NFT_RULE_O_DEFAULT:
			return snprintf(buf, size, "%d ", reg->verdict);
		case NFT_RULE_O_XML:
			return snprintf(buf, size,
					"<data_reg type=\"verdict\">"
						"<verdict>%d</verdict>"
					"</data_reg>", reg->verdict);
		case NFT_RULE_O_JSON:
			return snprintf(buf, size,
					"\"data_reg\": { \"type\" : \"verdict\", "
						"\"verdict\" : %d"
					"}", reg->verdict);
		default:
			break;
		}
	case DATA_CHAIN:
		switch(output_format) {
		case NFT_RULE_O_DEFAULT:
			return snprintf(buf, size, "%s ", reg->chain);
		case NFT_RULE_O_XML:
			return snprintf(buf, size,
					"<data_reg type=\"chain\">"
						"<chain>%s</chain>"
					"</data_reg>", reg->chain);
		case NFT_RULE_O_JSON:
			return snprintf(buf, size,
					"\"data_reg\": { \"type\" : \"chain\", "
						"\"chain\" : %d"
					"}", reg->verdict);
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

