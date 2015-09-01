#ifndef LIBNFTNL_JSON_INTERNAL_H
#define LIBNFTNL_JSON_INTERNAL_H

#ifdef JSON_PARSING
#include <jansson.h>
#include <stdbool.h>
#include "common.h"

struct nftnl_table;
struct nftnl_chain;
struct nftnl_rule;
struct nftnl_set;
struct nftnl_set_elem;
struct nftnl_set_list;
union nftnl_data_reg;

int nftnl_jansson_parse_val(json_t *root, const char *node_name, int type,
			  void *out, struct nftnl_parse_err *err);
const char *nftnl_jansson_parse_str(json_t *root, const char *node_name,
				  struct nftnl_parse_err *err);
bool nftnl_jansson_node_exist(json_t *root, const char *node_name);
json_t *nftnl_jansson_create_root(const void *json, json_error_t *error,
				struct nftnl_parse_err *err, enum nftnl_parse_input input);
json_t *nftnl_jansson_get_node(json_t *root, const char *node_name,
			     struct nftnl_parse_err *err);
void nftnl_jansson_free_root(json_t *root);
int nftnl_jansson_parse_family(json_t *root, void *out, struct nftnl_parse_err *err);
int nftnl_jansson_str2num(json_t *root, const char *node_name, int base, void *out,
			enum nftnl_type type, struct nftnl_parse_err *err);
int nftnl_jansson_parse_reg(json_t *root, const char *node_name, int type,
			  void *out, struct nftnl_parse_err *err);
struct nftnl_rule_expr *nftnl_jansson_expr_parse(json_t *root,
					     struct nftnl_parse_err *err,
					     struct nftnl_set_list *set_list);
int nftnl_jansson_data_reg_parse(json_t *root, const char *node_name,
			       union nftnl_data_reg *data_reg,
			       struct nftnl_parse_err *err);
int nftnl_jansson_set_elem_parse(struct nftnl_set_elem *e, json_t *root,
			       struct nftnl_parse_err *err);
int nftnl_jansson_parse_table(struct nftnl_table *t, json_t *tree,
			    struct nftnl_parse_err *err);
int nftnl_jansson_parse_chain(struct nftnl_chain *c, json_t *tree,
			    struct nftnl_parse_err *err);
int nftnl_jansson_parse_rule(struct nftnl_rule *r, json_t *tree,
			   struct nftnl_parse_err *err,
			   struct nftnl_set_list *set_list);
int nftnl_jansson_parse_set(struct nftnl_set *s, json_t *tree,
			  struct nftnl_parse_err *err);
int nftnl_jansson_parse_elem(struct nftnl_set *s, json_t *tree,
			   struct nftnl_parse_err *err);

int nftnl_data_reg_json_parse(union nftnl_data_reg *reg, json_t *data,
			    struct nftnl_parse_err *err);
#else
#define json_t void
#endif

#endif /* LIBNFTNL_JSON_INTERNAL_H */
