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
#include <libnftnl/chain.h>

static int test_ok = 1;

static void print_err(const char *msg)
{
	test_ok = 0;
	printf("\033[31mERROR:\e[0m %s\n", msg);
}

static void cmp_nft_chain(struct nft_chain *a, struct nft_chain *b)
{

	if (strcmp(nft_chain_attr_get_str(a, NFT_CHAIN_ATTR_NAME),
		   nft_chain_attr_get_str(b, NFT_CHAIN_ATTR_NAME)) != 0)
		print_err("Chain name mismatches");
	if (strcmp(nft_chain_attr_get_str(a, NFT_CHAIN_ATTR_TABLE),
		   nft_chain_attr_get_str(b, NFT_CHAIN_ATTR_TABLE)) != 0)
		print_err("Chain table mismatches");
	if (nft_chain_attr_get_u32(a, NFT_CHAIN_ATTR_FAMILY) !=
	    nft_chain_attr_get_u32(b, NFT_CHAIN_ATTR_FAMILY))
		print_err("Chain family mismatches");
	if (nft_chain_attr_get_u32(a, NFT_CHAIN_ATTR_POLICY) !=
	    nft_chain_attr_get_u32(b, NFT_CHAIN_ATTR_POLICY))
		print_err("Chain policy mismatches");
	if (nft_chain_attr_get_u32(a, NFT_CHAIN_ATTR_HOOKNUM) !=
	    nft_chain_attr_get_u32(b, NFT_CHAIN_ATTR_HOOKNUM))
		print_err("Chain hooknum mismatches");
	if (nft_chain_attr_get_s32(a, NFT_CHAIN_ATTR_PRIO) !=
	    nft_chain_attr_get_s32(b, NFT_CHAIN_ATTR_PRIO))
		print_err("Chain Prio mismatches");
	if (nft_chain_attr_get_u32(a, NFT_CHAIN_ATTR_USE) !=
	    nft_chain_attr_get_u32(b, NFT_CHAIN_ATTR_USE))
		print_err("Chain use mismatches");
	if (nft_chain_attr_get_u64(a, NFT_CHAIN_ATTR_PACKETS) !=
	    nft_chain_attr_get_u64(b, NFT_CHAIN_ATTR_PACKETS))
		print_err("Chain packets mismatches");
	if (nft_chain_attr_get_u64(a, NFT_CHAIN_ATTR_BYTES) !=
	    nft_chain_attr_get_u64(b, NFT_CHAIN_ATTR_BYTES))
		print_err("Chain bytes mismatches");
	if (nft_chain_attr_get_u64(a, NFT_CHAIN_ATTR_HANDLE) !=
	    nft_chain_attr_get_u64(b, NFT_CHAIN_ATTR_HANDLE))
		print_err("Chain handle mismatches");
	if (strcmp(nft_chain_attr_get_str(a, NFT_CHAIN_ATTR_TYPE),
		   nft_chain_attr_get_str(b, NFT_CHAIN_ATTR_TYPE)) != 0)
		print_err("Chain type mismatches");
	if (strcmp(nft_chain_attr_get_str(a, NFT_CHAIN_ATTR_DEV),
		   nft_chain_attr_get_str(b, NFT_CHAIN_ATTR_DEV)) != 0)
		print_err("Chain device mismatches");
}

int main(int argc, char *argv[])
{
	struct nft_chain *a, *b;
	char buf[4096];
	struct nlmsghdr *nlh;

	a = nft_chain_alloc();
	b = nft_chain_alloc();
	if (a == NULL || b == NULL)
		print_err("OOM");

	nft_chain_attr_set_str(a, NFT_CHAIN_ATTR_NAME, "test");
	nft_chain_attr_set_u32(a, NFT_CHAIN_ATTR_FAMILY, AF_INET);
	nft_chain_attr_set_str(a, NFT_CHAIN_ATTR_TABLE, "Table");
	nft_chain_attr_set_u32(a, NFT_CHAIN_ATTR_POLICY,0x12345678);
	nft_chain_attr_set_u32(a, NFT_CHAIN_ATTR_HOOKNUM, 0x12345678);
	nft_chain_attr_set_s32(a, NFT_CHAIN_ATTR_PRIO, 0x12345678);
	nft_chain_attr_set_u32(a, NFT_CHAIN_ATTR_USE, 0x12345678 );
	nft_chain_attr_set_u64(a, NFT_CHAIN_ATTR_PACKETS, 0x1234567812345678);
	nft_chain_attr_set_u64(a, NFT_CHAIN_ATTR_BYTES, 0x1234567812345678);
	nft_chain_attr_set_u64(a, NFT_CHAIN_ATTR_HANDLE, 0x1234567812345678);
	nft_chain_attr_set_str(a, NFT_CHAIN_ATTR_TYPE, "Prueba");
	nft_chain_attr_set_str(a, NFT_CHAIN_ATTR_DEV, "eth0");

	/* cmd extracted from include/linux/netfilter/nf_tables.h */
	nlh = nft_chain_nlmsg_build_hdr(buf, NFT_MSG_NEWCHAIN, AF_INET,
					0, 1234);
	nft_chain_nlmsg_build_payload(nlh, a);

	if (nft_chain_nlmsg_parse(nlh, b) < 0)
		print_err("parsing problems");

	cmp_nft_chain(a, b);

	nft_chain_free(a);
	nft_chain_free(b);

	if (!test_ok)
		exit(EXIT_FAILURE);

	printf("%s: \033[32mOK\e[0m\n", argv[0]);
	return EXIT_SUCCESS;

}
