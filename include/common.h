#ifndef _LIBNFTNL_COMMON_INTERNAL_H
#define _LIBNFTNL_COMMON_INTERNAL_H

#define BASE_DEC 10
#define BASE_HEX 16

#define NFTNL_SNPRINTF_BUFSIZ 4096

struct nftnl_parse_err {
	int line;
	int column;
	int error;
	const char *node_name;
};

enum nftnl_parse_input {
	NFTNL_PARSE_BUFFER,
	NFTNL_PARSE_FILE,
};

#include <stdio.h>

int nftnl_cmd_header_snprintf(char *buf, size_t bufsize, uint32_t cmd,
			   uint32_t format, uint32_t flags);
int nftnl_cmd_header_fprintf(FILE *fp, uint32_t cmd, uint32_t format,
			  uint32_t flags);
int nftnl_cmd_footer_snprintf(char *buf, size_t bufsize, uint32_t cmd,
			   uint32_t format, uint32_t flags);
int nftnl_cmd_footer_fprintf(FILE *fp, uint32_t cmd, uint32_t format,
			  uint32_t flags);

#endif
