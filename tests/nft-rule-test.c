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
#include <libnftnl/rule.h>

static int test_ok = 1;

static void print_err(const char *msg)
{
	test_ok = 0;
	printf("\033[31mERROR:\e[0m %s\n", msg);
}

static void cmp_nft_rule(struct nft_rule *a, struct nft_rule *b)
{
	if (nft_rule_attr_get_u32(a, NFT_RULE_ATTR_FAMILY) !=
	    nft_rule_attr_get_u32(b, NFT_RULE_ATTR_FAMILY))
		print_err("Rule family mismatches");
	if (strcmp(nft_rule_attr_get_str(a, NFT_RULE_ATTR_TABLE),
		   nft_rule_attr_get_str(b, NFT_RULE_ATTR_TABLE)) != 0)
		print_err("Rule table mismatches");
	if (strcmp(nft_rule_attr_get_str(a, NFT_RULE_ATTR_CHAIN),
		   nft_rule_attr_get_str(b, NFT_RULE_ATTR_CHAIN)) != 0)
		print_err("Rule table mismatches");
	if (nft_rule_attr_get_u64(a, NFT_RULE_ATTR_HANDLE) !=
	    nft_rule_attr_get_u64(b, NFT_RULE_ATTR_HANDLE))
		print_err("Rule handle mismatches");
	if (nft_rule_attr_get_u32(a, NFT_RULE_ATTR_COMPAT_PROTO) !=
	    nft_rule_attr_get_u32(b, NFT_RULE_ATTR_COMPAT_PROTO))
		print_err("Rule compat_proto mismatches");
	if (nft_rule_attr_get_u32(a, NFT_RULE_ATTR_COMPAT_FLAGS) !=
	    nft_rule_attr_get_u32(b, NFT_RULE_ATTR_COMPAT_FLAGS))
		print_err("Rule compat_flags mismatches");
	if (nft_rule_attr_get_u64(a, NFT_RULE_ATTR_POSITION) !=
	    nft_rule_attr_get_u64(b, NFT_RULE_ATTR_POSITION))
		print_err("Rule compat_position mismatches");
}

int main(int argc, char *argv[])
{
	struct nft_rule *a, *b;
	char buf[4096];
	struct nlmsghdr *nlh;

	a = nft_rule_alloc();
	b = nft_rule_alloc();
	if (a == NULL || b == NULL)
		print_err("OOM");

	nft_rule_attr_set_u32(a, NFT_RULE_ATTR_FAMILY, AF_INET);
	nft_rule_attr_set_str(a, NFT_RULE_ATTR_TABLE, "table");
	nft_rule_attr_set_str(a, NFT_RULE_ATTR_CHAIN, "chain");
	nft_rule_attr_set_u64(a, NFT_RULE_ATTR_HANDLE, 0x1234567812345678);
	nft_rule_attr_set_u32(a, NFT_RULE_ATTR_COMPAT_PROTO, 0x12345678);
	nft_rule_attr_set_u32(a, NFT_RULE_ATTR_COMPAT_FLAGS, 0x12345678);
	nft_rule_attr_set_u64(a, NFT_RULE_ATTR_POSITION, 0x1234567812345678);

	nlh = nft_rule_nlmsg_build_hdr(buf, NFT_MSG_NEWRULE, AF_INET, 0, 1234);
	nft_rule_nlmsg_build_payload(nlh, a);

	if (nft_rule_nlmsg_parse(nlh, b) < 0)
		print_err("parsing problems");

	cmp_nft_rule(a,b);

	nft_rule_free(a);
	nft_rule_free(b);
	if (!test_ok)
		exit(EXIT_FAILURE);

	printf("%s: \033[32mOK\e[0m\n", argv[0]);
	return EXIT_SUCCESS;
}
