#ifndef _DATA_H_
#define _DATA_H_

enum {
	DATA_VALUE,
	DATA_VERDICT,
	DATA_CHAIN,
};

union nft_data_reg {
	struct {
		uint32_t	val[4];
		size_t		len;
	};
	struct {
		int		verdict;
		char		*chain;
	};
};

int nft_parse_data(union nft_data_reg *data, struct nlattr *attr, int *type);

#endif
