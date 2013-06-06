#ifndef INTERNAL_H
#define INTERNAL_H 1

#include "config.h"
#ifdef HAVE_VISIBILITY_HIDDEN
#	define __visible	__attribute__((visibility("default")))
#	define EXPORT_SYMBOL(x)	typeof(x) (x) __visible
#else
#	define EXPORT_SYMBOL
#endif

#include "linux_list.h"

#include <stdint.h>

#ifdef XML_PARSING
#include <mxml.h>
#endif

#define NFT_TABLE_XML_VERSION 0
#define NFT_CHAIN_XML_VERSION 0
#define NFT_RULE_XML_VERSION 0
#define NFT_TABLE_JSON_VERSION 0

struct expr_ops;

struct nft_rule_expr {
	struct list_head head;
	uint32_t	flags;
	struct expr_ops	*ops;
	uint8_t		data[];
};

struct nlattr;

struct nft_set {
	struct list_head	head;

	uint32_t		set_flags;
	char			*table;
	char			*name;
	uint32_t		key_type;
	size_t			key_len;
	uint32_t		data_type;
	size_t			data_len;
	struct list_head	element_list;

	uint32_t		flags;
};

#include "expr/data_reg.h"

struct nft_set_elem {
	struct list_head head;
	uint32_t	set_elem_flags;
	union nft_data_reg key;
	union nft_data_reg data;
	uint32_t	flags;
};

#define SNPRINTF_BUFFER_SIZE(ret, size, len, offset)	\
	size += ret;					\
	if (ret > len)					\
		ret = len;				\
	offset += ret;					\
	len -= ret;

#endif
