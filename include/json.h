#ifndef LIBNFTNL_JSON_INTERNAL_H
#define LIBNFTNL_JSON_INTERNAL_H

#ifdef JSON_PARSING
#include <jansson.h>
#include <stdbool.h>
#include "common.h"

struct nft_table;
struct nft_chain;
struct nft_rule;
struct nft_set;
struct nft_set_elem;
struct nft_set_list;
union nft_data_reg;

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
int nft_jansson_data_reg_parse(json_t *root, const char *node_name,
			       union nft_data_reg *data_reg,
			       struct nft_parse_err *err);
int nft_jansson_set_elem_parse(struct nft_set_elem *e, json_t *root,
			       struct nft_parse_err *err);
int nft_jansson_parse_table(struct nft_table *t, json_t *tree,
			    struct nft_parse_err *err);
int nft_jansson_parse_chain(struct nft_chain *c, json_t *tree,
			    struct nft_parse_err *err);
int nft_jansson_parse_rule(struct nft_rule *r, json_t *tree,
			   struct nft_parse_err *err,
			   struct nft_set_list *set_list);
int nft_jansson_parse_set(struct nft_set *s, json_t *tree,
			  struct nft_parse_err *err);
int nft_jansson_parse_elem(struct nft_set *s, json_t *tree,
			   struct nft_parse_err *err);

int nft_data_reg_json_parse(union nft_data_reg *reg, json_t *data,
			    struct nft_parse_err *err);
#else
#define json_t void
#endif

#endif /* LIBNFTNL_JSON_INTERNAL_H */
