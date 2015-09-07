#ifndef LIBNFTNL_XML_INTERNAL_H
#define LIBNFTNL_XML_INTERNAL_H

#ifdef XML_PARSING
#include <mxml.h>
#include "common.h"

#define NFTNL_XML_MAND 0
#define NFTNL_XML_OPT (1 << 0)

struct nftnl_table;
struct nftnl_chain;
struct nftnl_rule;
struct nftnl_set;
struct nftnl_set_elem;
struct nftnl_set_list;
union nftnl_data_reg;

mxml_node_t *nftnl_mxml_build_tree(const void *data, const char *treename,
				 struct nftnl_parse_err *err, enum nftnl_parse_input input);
struct nftnl_expr *nftnl_mxml_expr_parse(mxml_node_t *node,
					  struct nftnl_parse_err *err,
					  struct nftnl_set_list *set_list);
int nftnl_mxml_reg_parse(mxml_node_t *tree, const char *reg_name, uint32_t *reg,
		       uint32_t mxmlflags, uint32_t flags,
		       struct nftnl_parse_err *err);
int nftnl_mxml_data_reg_parse(mxml_node_t *tree, const char *node_name,
			    union nftnl_data_reg *data_reg, uint16_t flags,
			    struct nftnl_parse_err *err);
int nftnl_mxml_num_parse(mxml_node_t *tree, const char *node_name,
		       uint32_t mxml_flags, int base, void *number,
		       enum nftnl_type type, uint16_t flags,
		       struct nftnl_parse_err *err);
const char *nftnl_mxml_str_parse(mxml_node_t *tree, const char *node_name,
			       uint32_t mxml_flags, uint16_t flags,
			       struct nftnl_parse_err *err);
int nftnl_mxml_family_parse(mxml_node_t *tree, const char *node_name,
			  uint32_t mxml_flags, uint16_t flags,
			  struct nftnl_parse_err *err);
int nftnl_mxml_set_elem_parse(mxml_node_t *node, struct nftnl_set_elem *e,
			    struct nftnl_parse_err *err);
int nftnl_mxml_table_parse(mxml_node_t *tree, struct nftnl_table *t,
			 struct nftnl_parse_err *err);
int nftnl_mxml_chain_parse(mxml_node_t *tree, struct nftnl_chain *c,
			 struct nftnl_parse_err *err);
int nftnl_mxml_rule_parse(mxml_node_t *tree, struct nftnl_rule *r,
			struct nftnl_parse_err *err,
			struct nftnl_set_list *set_list);
int nftnl_mxml_set_parse(mxml_node_t *tree, struct nftnl_set *s,
		       struct nftnl_parse_err *err);

int nftnl_data_reg_xml_parse(union nftnl_data_reg *reg, mxml_node_t *tree,
			   struct nftnl_parse_err *err);
#else
#define mxml_node_t void
#endif

#endif /* LIBNFTNL_XML_INTERNAL_H */
