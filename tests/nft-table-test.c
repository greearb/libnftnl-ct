/*
 * (C) 2013 by Ana Rey Botello <anarey@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>

#include <linux/netfilter/nf_tables.h>
#include <libnftnl/table.h>

static int test_ok = 1;

static void print_err(const char *msg)
{
	test_ok = 0;
	printf("\033[31mERROR:\e[0m %s\n", msg);
}

static void cmp_nft_table(struct nft_table *a, struct nft_table *b)
{
	if (strcmp(nft_table_attr_get_str(a, NFT_TABLE_ATTR_NAME),
		   nft_table_attr_get_str(b, NFT_TABLE_ATTR_NAME)) != 0)
		print_err("table name mismatches");
	if (nft_table_attr_get_u32(a, NFT_TABLE_ATTR_FLAGS) !=
	    nft_table_attr_get_u32(b, NFT_TABLE_ATTR_FLAGS))
		print_err("table flags mismatches");
	if (nft_table_attr_get_u32(a, NFT_TABLE_ATTR_FAMILY) !=
	    nft_table_attr_get_u32(b, NFT_TABLE_ATTR_FAMILY))
		print_err("tabke family mismatches");
}

int main(int argc, char *argv[])
{
	char buf[4096];
	struct nlmsghdr *nlh;

	struct nft_table *a = NULL;
	struct nft_table *b = NULL;
	a = nft_table_alloc();
	b = nft_table_alloc();

	if (a == NULL || b == NULL)
		print_err("OOM");

	nft_table_attr_set_str(a, NFT_TABLE_ATTR_NAME, "test");
	nft_table_attr_set_u32(a, NFT_TABLE_ATTR_FAMILY, AF_INET);
	nft_table_attr_set_u32(a, NFT_TABLE_ATTR_FLAGS, 0);

	/* cmd extracted from include/linux/netfilter/nf_tables.h */
	nlh = nft_table_nlmsg_build_hdr(buf, NFT_MSG_NEWTABLE, AF_INET, 0,
					1234);
	nft_table_nlmsg_build_payload(nlh, a);

	if (nft_table_nlmsg_parse(nlh, b) < 0)
		print_err("parsing problems");

	cmp_nft_table(a,b);

	nft_table_free(a);
	nft_table_free(b);
	if (!test_ok)
		exit(EXIT_FAILURE);

	printf("%s: \033[32mOK\e[0m\n", argv[0]);
	return EXIT_SUCCESS;
}
