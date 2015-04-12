#ifndef _LIBNFTNL_SET_ELEM_INTERNAL_H_
#define _LIBNFTNL_SET_ELEM_INTERNAL_H_

#include <data_reg.h>

struct nft_set_elem {
	struct list_head	head;
	uint32_t		set_elem_flags;
	union nft_data_reg	key;
	union nft_data_reg	data;
	struct nft_rule_expr	*expr;
	uint32_t		flags;
	uint64_t		timeout;
	uint64_t		expiration;
	struct {
		void		*data;
		uint32_t	len;
	} user;
};

#endif
