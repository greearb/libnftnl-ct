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
		const char	*chain;
	};
};

#ifndef JSON_PARSING
#define json_t void
#endif

int nft_data_reg_snprintf(char *buf, size_t size, union nft_data_reg *reg,
                        uint32_t output_format, uint32_t flags, int reg_type);
int nft_data_reg_xml_parse(union nft_data_reg *reg, char *xml);
int nft_parse_data(union nft_data_reg *data, struct nlattr *attr, int *type);
int nft_data_reg_json_parse(union nft_data_reg *reg, json_t *data);

#endif
