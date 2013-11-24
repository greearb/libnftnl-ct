#ifndef _LIBNFTABLES_COMMON_H_
#define _LIBNFTABLES_COMMON_H_

enum nft_output_type {
	NFT_OUTPUT_DEFAULT	= 0,
	NFT_OUTPUT_XML,
	NFT_OUTPUT_JSON,
};

enum nft_parse_type {
	NFT_PARSE_NONE		= 0,
	NFT_PARSE_XML,
	NFT_PARSE_JSON,
	NFT_PARSE_MAX,
};
#endif
