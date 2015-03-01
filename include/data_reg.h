#ifndef _DATA_H_
#define _DATA_H_

#include <linux/netfilter/nf_tables.h>
#include <stdint.h>
#include <unistd.h>

enum {
	DATA_NONE,
	DATA_VALUE,
	DATA_VERDICT,
	DATA_CHAIN,
};

union nft_data_reg {
	struct {
		uint32_t	val[NFT_DATA_VALUE_MAXLEN / sizeof(uint32_t)];
		uint32_t	len;
	};
	struct {
		int		verdict;
		const char	*chain;
	};
};

int nft_data_reg_snprintf(char *buf, size_t size, union nft_data_reg *reg,
                        uint32_t output_format, uint32_t flags, int reg_type);
struct nlattr;

int nft_parse_data(union nft_data_reg *data, struct nlattr *attr, int *type);

#endif
