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
#include <libnftnl/common.h>
#include <linux/netfilter/nf_tables.h>

#define xfree(ptr)	free((void *)ptr);

#define BASE_DEC 10
#define BASE_HEX 16

#define NFT_SNPRINTF_BUFSIZ 4096

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

struct nft_parse_err {
	int line;
	int column;
	int error;
	const char *node_name;
};

enum nft_parse_input {
	NFT_PARSE_BUFFER,
	NFT_PARSE_FILE,
};

#ifdef XML_PARSING
#include <mxml.h>
#define NFT_XML_MAND 0
#define NFT_XML_OPT (1 << 0)
mxml_node_t *nft_mxml_build_tree(const void *data, const char *treename,
				 struct nft_parse_err *err, enum nft_parse_input input);
struct nft_set_list;
struct nft_rule_expr *nft_mxml_expr_parse(mxml_node_t *node,
					  struct nft_parse_err *err,
					  struct nft_set_list *set_list);
int nft_mxml_reg_parse(mxml_node_t *tree, const char *reg_name, uint32_t *reg,
		       uint32_t mxmlflags, uint32_t flags,
		       struct nft_parse_err *err);
union nft_data_reg;
int nft_mxml_data_reg_parse(mxml_node_t *tree, const char *node_name,
			    union nft_data_reg *data_reg, uint16_t flags,
			    struct nft_parse_err *err);
int nft_mxml_num_parse(mxml_node_t *tree, const char *node_name,
		       uint32_t mxml_flags, int base, void *number,
		       enum nft_type type, uint16_t flags,
		       struct nft_parse_err *err);
const char *nft_mxml_str_parse(mxml_node_t *tree, const char *node_name,
			       uint32_t mxml_flags, uint16_t flags,
			       struct nft_parse_err *err);
int nft_mxml_family_parse(mxml_node_t *tree, const char *node_name,
			  uint32_t mxml_flags, uint16_t flags,
			  struct nft_parse_err *err);

struct nft_set_elem;
int nft_mxml_set_elem_parse(mxml_node_t *node, struct nft_set_elem *e,
			    struct nft_parse_err *err);
struct nft_table;
int nft_mxml_table_parse(mxml_node_t *tree, struct nft_table *t,
			 struct nft_parse_err *err);
struct nft_chain;
int nft_mxml_chain_parse(mxml_node_t *tree, struct nft_chain *c,
			 struct nft_parse_err *err);
struct nft_rule;
int nft_mxml_rule_parse(mxml_node_t *tree, struct nft_rule *r,
			struct nft_parse_err *err,
			struct nft_set_list *set_list);
struct nft_set;
int nft_mxml_set_parse(mxml_node_t *tree, struct nft_set *s,
		       struct nft_parse_err *err);
#endif

struct nft_set_list;
struct nft_rule_expr;
int nft_set_lookup_id(struct nft_rule_expr *e, struct nft_set_list *set_list,
		      uint32_t *set_id);

#ifdef JSON_PARSING
#include <jansson.h>

int nft_jansson_parse_val(json_t *root, const char *node_name, int type,
			  void *out, struct nft_parse_err *err);
const char *nft_jansson_parse_str(json_t *root, const char *node_name,
				  struct nft_parse_err *err);
bool nft_jansson_node_exist(json_t *root, const char *node_name);
json_t *nft_jansson_create_root(const void *json, json_error_t *error,
				struct nft_parse_err *err, enum nft_parse_input input);
json_t *nft_jansson_get_node(json_t *root, const char *node_name,
			     struct nft_parse_err *err);
void nft_jansson_free_root(json_t *root);
int nft_jansson_parse_family(json_t *root, void *out, struct nft_parse_err *err);
int nft_jansson_str2num(json_t *root, const char *node_name, int base, void *out,
			enum nft_type type, struct nft_parse_err *err);
int nft_jansson_parse_reg(json_t *root, const char *node_name, int type,
			  void *out, struct nft_parse_err *err);
struct nft_rule_expr *nft_jansson_expr_parse(json_t *root,
					     struct nft_parse_err *err,
					     struct nft_set_list *set_list);
union nft_data_reg;
int nft_jansson_data_reg_parse(json_t *root, const char *node_name,
			       union nft_data_reg *data_reg,
			       struct nft_parse_err *err);
struct nft_set_elem;
int nft_jansson_set_elem_parse(struct nft_set_elem *e, json_t *root,
			       struct nft_parse_err *err);
struct nft_table;
int nft_jansson_parse_table(struct nft_table *t, json_t *tree,
			    struct nft_parse_err *err);
struct nft_chain;
int nft_jansson_parse_chain(struct nft_chain *c, json_t *tree,
			    struct nft_parse_err *err);
struct nft_rule;
struct nft_set_list;
int nft_jansson_parse_rule(struct nft_rule *r, json_t *tree,
			   struct nft_parse_err *err,
			   struct nft_set_list *set_list);
struct nft_set;
int nft_jansson_parse_set(struct nft_set *s, json_t *tree,
			  struct nft_parse_err *err);
#endif

const char *nft_family2str(uint32_t family);
int nft_str2family(const char *family);
int nft_strtoi(const char *string, int base, void *number, enum nft_type type);
const char *nft_verdict2str(uint32_t verdict);
int nft_str2verdict(const char *verdict, int *verdict_num);
int nft_get_value(enum nft_type type, void *val, void *out);

#include <stdio.h>
int nft_fprintf(FILE *fp, void *obj, uint32_t type, uint32_t flags, int (*snprintf_cb)(char *buf, size_t bufsiz, void *obj, uint32_t type, uint32_t flags));
int nft_event_header_snprintf(char *buf, size_t bufsize,
			      uint32_t format, uint32_t flags);
int nft_event_header_fprintf(FILE *fp, uint32_t format, uint32_t flags);
int nft_event_footer_snprintf(char *buf, size_t bufsize,
			      uint32_t format, uint32_t flags);
int nft_event_footer_fprintf(FILE *fp, uint32_t format, uint32_t flags);

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
	uint32_t		id;
	enum nft_set_policies	policy;
	struct {
		uint32_t		size;
	} desc;
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
	if (ret < 0)					\
		return ret;				\
	offset += ret;					\
	if (ret > len)					\
		ret = len;				\
	size += ret;					\
	len -= ret;

#define div_round_up(n, d)	(((n) + (d) - 1) / (d))

#define __init __attribute__((constructor))

void __nft_assert_fail(uint16_t attr, const char *filename, int line);

#define nft_assert(val, attr, expr)			\
  ((!val || expr)					\
   ? (void)0						\
   : __nft_assert_fail(attr, __FILE__, __LINE__))

#define nft_assert_validate(data, _validate_array, _attr, _data_len)		\
({										\
	if (!data)								\
		__nft_assert_fail(attr, __FILE__, __LINE__);			\
	if (_validate_array[_attr])						\
		nft_assert(data, attr, _validate_array[_attr] == _data_len);	\
})

#define __noreturn	__attribute__((__noreturn__))

void __noreturn __abi_breakage(const char *file, int line, const char *reason);

#include <string.h>

#define abi_breakage()	\
	__abi_breakage(__FILE__, __LINE__, strerror(errno));

#endif
