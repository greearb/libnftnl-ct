#ifndef LIBNFTNL_XML_INTERNAL_H
#define LIBNFTNL_XML_INTERNAL_H

#ifdef XML_PARSING
#include <mxml.h>
#include "common.h"

#define NFT_XML_MAND 0
#define NFT_XML_OPT (1 << 0)

struct nft_table;
struct nft_chain;
struct nft_rule;
struct nft_set;
struct nft_set_elem;
struct nft_set_list;
union nft_data_reg;

mxml_node_t *nft_mxml_build_tree(const void *data, const char *treename,
				 struct nft_parse_err *err, enum nft_parse_input input);
struct nft_rule_expr *nft_mxml_expr_parse(mxml_node_t *node,
					  struct nft_parse_err *err,
					  struct nft_set_list *set_list);
int nft_mxml_reg_parse(mxml_node_t *tree, const char *reg_name, uint32_t *reg,
		       uint32_t mxmlflags, uint32_t flags,
		       struct nft_parse_err *err);
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
int nft_mxml_set_elem_parse(mxml_node_t *node, struct nft_set_elem *e,
			    struct nft_parse_err *err);
int nft_mxml_table_parse(mxml_node_t *tree, struct nft_table *t,
			 struct nft_parse_err *err);
int nft_mxml_chain_parse(mxml_node_t *tree, struct nft_chain *c,
			 struct nft_parse_err *err);
int nft_mxml_rule_parse(mxml_node_t *tree, struct nft_rule *r,
			struct nft_parse_err *err,
			struct nft_set_list *set_list);
int nft_mxml_set_parse(mxml_node_t *tree, struct nft_set *s,
		       struct nft_parse_err *err);

int nft_data_reg_xml_parse(union nft_data_reg *reg, mxml_node_t *tree,
			   struct nft_parse_err *err);
#else
#define mxml_node_t void
#endif

#endif /* LIBNFTNL_XML_INTERNAL_H */
