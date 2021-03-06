#ifndef _LIBNFTNL_SET_ELEM_INTERNAL_H_
#define _LIBNFTNL_SET_ELEM_INTERNAL_H_

#include <data_reg.h>

struct nft_set_elem {
	struct list_head	head;
	uint32_t		set_elem_flags;
	union nft_data_reg	key;
	union nft_data_reg	data;
	uint32_t		flags;
};

#endif
