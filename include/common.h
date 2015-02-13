#ifndef _LIBNFTNL_COMMON_INTERNAL_H
#define _LIBNFTNL_COMMON_INTERNAL_H

#define BASE_DEC 10
#define BASE_HEX 16

#define NFT_SNPRINTF_BUFSIZ 4096

struct nft_parse_err {
	int line;
	int column;
	int error;
	const char *node_name;
};

enum nft_parse_input {
	NFT_PARSE_BUFFER,
	NFT_PARSE_FILE,
};

#include <stdio.h>

int nft_cmd_header_snprintf(char *buf, size_t bufsize, uint32_t cmd,
			   uint32_t format, uint32_t flags);
int nft_cmd_header_fprintf(FILE *fp, uint32_t cmd, uint32_t format,
			  uint32_t flags);
int nft_cmd_footer_snprintf(char *buf, size_t bufsize, uint32_t cmd,
			   uint32_t format, uint32_t flags);
int nft_cmd_footer_fprintf(FILE *fp, uint32_t cmd, uint32_t format,
			  uint32_t flags);

#endif
