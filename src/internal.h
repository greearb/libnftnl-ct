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

struct expr_ops;

struct nft_rule_expr {
	struct list_head head;
	uint32_t	flags;
	struct expr_ops	*ops;
	uint8_t		data[];
};

#define SNPRINTF_BUFFER_SIZE(ret, size, len, offset)	\
	size += ret;					\
	if (ret > len)					\
		ret = len;				\
	offset += ret;					\
	len -= ret;

#endif
