#ifndef _LIBNFTNL_SET_ELEM_INTERNAL_H_
#define _LIBNFTNL_SET_ELEM_INTERNAL_H_

#include <data_reg.h>

struct nftnl_set_elem {
	struct list_head	head;
	uint32_t		set_elem_flags;
	uint32_t		flags;
	union nftnl_data_reg	key;
	union nftnl_data_reg	key_end;
	union nftnl_data_reg	data;
	struct list_head	expr_list;
	uint64_t		timeout;
	uint64_t		expiration;
	const char		*objref;
	struct {
		void		*data;
		uint32_t	len;
	} user;
};

#endif
