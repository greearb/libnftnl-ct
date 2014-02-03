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

#include <libnftnl/set.h>

static int test_ok = 1;

static void print_err(const char *msg)
{
	test_ok = 0;
	printf("\033[31mERROR:\e[0m %s\n", msg);
}

static void cmp_nft_set(struct nft_set *a, struct nft_set *b)
{
	if (strcmp(nft_set_attr_get_str(a, NFT_SET_ATTR_TABLE),
		   nft_set_attr_get_str(b, NFT_SET_ATTR_TABLE)) != 0)
		print_err("Set table mismatches");
	if (strcmp(nft_set_attr_get_str(a, NFT_SET_ATTR_NAME),
		   nft_set_attr_get_str(b, NFT_SET_ATTR_NAME)) != 0)
		print_err("Set name mismatches");
	if (nft_set_attr_get_u32(a, NFT_SET_ATTR_FLAGS) !=
	    nft_set_attr_get_u32(b, NFT_SET_ATTR_FLAGS))
		print_err("Set flags mismatches");
	if (nft_set_attr_get_u32(a, NFT_SET_ATTR_KEY_TYPE) !=
	    nft_set_attr_get_u32(b, NFT_SET_ATTR_KEY_TYPE))
		print_err("Set key-type mismatches");
	if (nft_set_attr_get_u32(a, NFT_SET_ATTR_KEY_LEN) !=
	    nft_set_attr_get_u32(b, NFT_SET_ATTR_KEY_LEN))
		print_err("Set key-len mismatches");
	if (nft_set_attr_get_u32(a, NFT_SET_ATTR_DATA_TYPE) !=
	    nft_set_attr_get_u32(b, NFT_SET_ATTR_DATA_TYPE))
		print_err("Set data-type mismatches");
	if (nft_set_attr_get_u32(a, NFT_SET_ATTR_DATA_LEN) !=
	    nft_set_attr_get_u32(b, NFT_SET_ATTR_DATA_LEN))
		print_err("Set data-len mismatches");
}

int main(int argc, char *argv[])
{
	struct nft_set *a, *b = NULL;
	char buf[4096];
	struct nlmsghdr *nlh;

	a = nft_set_alloc();
	b = nft_set_alloc();
	if (a == NULL || b == NULL)
		print_err("OOM");

	nft_set_attr_set_str(a, NFT_SET_ATTR_TABLE, "test-table");
	nft_set_attr_set_str(a, NFT_SET_ATTR_NAME, "test-name");
	nft_set_attr_set_u32(a, NFT_SET_ATTR_FLAGS, 0x12345678);
	nft_set_attr_set_u32(a, NFT_SET_ATTR_KEY_TYPE, 0x12345678);
	nft_set_attr_set_u32(a, NFT_SET_ATTR_KEY_LEN, 0x12345678);
	nft_set_attr_set_u32(a, NFT_SET_ATTR_DATA_TYPE, 0x12345678);
	nft_set_attr_set_u32(a, NFT_SET_ATTR_DATA_LEN, 0x12345678);
	nft_set_attr_set_u32(a, NFT_SET_ATTR_FAMILY, 0x12345678);

	/* cmd extracted from include/linux/netfilter/nf_tables.h */
	nlh = nft_set_nlmsg_build_hdr(buf, NFT_MSG_NEWSET, AF_INET, 0, 1234);
	nft_set_nlmsg_build_payload(nlh, a);

	if (nft_set_nlmsg_parse(nlh, b) < 0)
		print_err("parsing problems");

	cmp_nft_set(a,b);

	nft_set_free(a); nft_set_free(b);

	if (!test_ok)
		exit(EXIT_FAILURE);

	printf("%s: \033[32mOK\e[0m\n", argv[0]);
	return EXIT_SUCCESS;
}
