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
#include <stdbool.h>

#define BASE_DEC 10
#define BASE_HEX 16

enum nft_type {
	NFT_TYPE_U8,
	NFT_TYPE_U16,
	NFT_TYPE_U32,
	NFT_TYPE_U64,
	NFT_TYPE_S8,
	NFT_TYPE_S16,
	NFT_TYPE_S32,
	NFT_TYPE_S64,
};

#ifdef XML_PARSING
#include <mxml.h>
struct nft_rule_expr *nft_mxml_expr_parse(mxml_node_t *node);
int nft_mxml_reg_parse(mxml_node_t *tree, const char *reg_name, uint32_t flags);
union nft_data_reg;
int nft_mxml_data_reg_parse(mxml_node_t *tree, const char *node_name, union nft_data_reg *data_reg);
int nft_mxml_num_parse(mxml_node_t *tree, const char *node_name, uint32_t mxml_flags, int base, void *number, enum nft_type type);
const char *nft_mxml_str_parse(mxml_node_t *tree, const char *node_name, uint32_t mxml_flags);
int nft_mxml_family_parse(mxml_node_t *tree, const char *node_name, uint32_t mxml_flags);

struct nft_set_elem;
int nft_mxml_set_elem_parse(mxml_node_t *node, struct nft_set_elem *e);
#endif

#ifdef JSON_PARSING
#include <jansson.h>
int nft_jansson_parse_val(json_t *root, const char *tag, int type, void *out);
const char *nft_jansson_parse_str(json_t *root, const char *tag);
bool nft_jansson_node_exist(json_t *root, const char *tag);
json_t *nft_jansson_create_root(const char *json, json_error_t *err);
json_t *nft_jansson_get_node(json_t *root, const char *tag);
void nft_jansson_free_root(json_t *root);
int nft_jansson_parse_family(json_t *root, void *out);
int nft_jansson_str2num(json_t *root, const char *tag, int base, void *out,
			enum nft_type type);
int nft_jansson_parse_reg(json_t *root, const char *tag, int type, void *out);
struct nft_rule_expr *nft_jansson_expr_parse(json_t *root);
union nft_data_reg;
int nft_jansson_data_reg_parse(json_t *root, const char *tag,
			       union nft_data_reg *data_reg);
int nft_set_elem_json_parse(struct nft_set_elem *e, json_t *root);
#endif

const char *nft_family2str(uint32_t family);
int nft_str2family(const char *family);
int nft_strtoi(const char *string, int base, void *number, enum nft_type type);
const char *nft_verdict2str(uint32_t verdict);
int nft_str2verdict(const char *verdict);
int nft_get_value(enum nft_type type, void *val, void *out);

void xfree(const void *ptr);

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

	uint32_t		family;
	uint32_t		set_flags;
	const char		*table;
	const char		*name;
	uint32_t		key_type;
	uint32_t		key_len;
	uint32_t		data_type;
	uint32_t		data_len;
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

#define div_round_up(n, d)	(((n) + (d) - 1) / (d))

#define __init __attribute__((constructor))

#endif
