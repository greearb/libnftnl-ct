#ifndef _LIBNFTNL_SET_INTERNAL_H_
#define _LIBNFTNL_SET_INTERNAL_H_

#include <linux/netfilter/nf_tables.h>

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
		uint32_t	size;
	} desc;
	struct list_head	element_list;

	uint32_t		flags;
};

struct nft_set_list;
struct nft_rule_expr;
int nft_set_lookup_id(struct nft_rule_expr *e, struct nft_set_list *set_list,
		      uint32_t *set_id);

#endif
