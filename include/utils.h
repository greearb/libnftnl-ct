#ifndef LIBNFTNL_UTILS_H
#define LIBNFTNL_UTILS_H 1

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <libnftnl/common.h>

#include "config.h"
#ifdef HAVE_VISIBILITY_HIDDEN
#	define __visible	__attribute__((visibility("default")))
#	define EXPORT_SYMBOL(y, x)	typeof(x) (x) __visible; __typeof (x) y __attribute ((alias (#x), visibility ("default")))
#else
#	define EXPORT_SYMBOL
#endif

#define __noreturn	__attribute__((__noreturn__))

#define xfree(ptr)	free((void *)ptr);

#define div_round_up(n, d)	(((n) + (d) - 1) / (d))

void __noreturn __abi_breakage(const char *file, int line, const char *reason);

#define abi_breakage()	\
	__abi_breakage(__FILE__, __LINE__, strerror(errno));

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

#define SNPRINTF_BUFFER_SIZE(ret, size, len, offset)	\
	if (ret < 0)					\
		return ret;				\
	offset += ret;					\
	if (ret > len)					\
		ret = len;				\
	size += ret;					\
	len -= ret;

const char *nft_family2str(uint32_t family);
int nft_str2family(const char *family);

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

int nft_strtoi(const char *string, int base, void *number, enum nft_type type);
int nft_get_value(enum nft_type type, void *val, void *out);

const char *nft_verdict2str(uint32_t verdict);
int nft_str2verdict(const char *verdict, int *verdict_num);

const char *nft_cmd2tag(enum nft_cmd_type cmd);
uint32_t nft_str2cmd(const char *cmd);

enum nft_cmd_type nft_flag2cmd(uint32_t flags);

int nft_fprintf(FILE *fp, void *obj, uint32_t cmd, uint32_t type,
		uint32_t flags, int (*snprintf_cb)(char *buf, size_t bufsiz,
		void *obj, uint32_t cmd, uint32_t type, uint32_t flags));

#endif
