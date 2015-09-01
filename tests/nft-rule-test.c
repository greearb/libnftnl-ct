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

static void cmp_nftnl_rule(struct nftnl_rule *a, struct nftnl_rule *b)
{
	if (nftnl_rule_attr_get_u32(a, NFTNL_RULE_ATTR_FAMILY) !=
	    nftnl_rule_attr_get_u32(b, NFTNL_RULE_ATTR_FAMILY))
		print_err("Rule family mismatches");
	if (strcmp(nftnl_rule_attr_get_str(a, NFTNL_RULE_ATTR_TABLE),
		   nftnl_rule_attr_get_str(b, NFTNL_RULE_ATTR_TABLE)) != 0)
		print_err("Rule table mismatches");
	if (strcmp(nftnl_rule_attr_get_str(a, NFTNL_RULE_ATTR_CHAIN),
		   nftnl_rule_attr_get_str(b, NFTNL_RULE_ATTR_CHAIN)) != 0)
		print_err("Rule table mismatches");
	if (nftnl_rule_attr_get_u64(a, NFTNL_RULE_ATTR_HANDLE) !=
	    nftnl_rule_attr_get_u64(b, NFTNL_RULE_ATTR_HANDLE))
		print_err("Rule handle mismatches");
	if (nftnl_rule_attr_get_u32(a, NFTNL_RULE_ATTR_COMPAT_PROTO) !=
	    nftnl_rule_attr_get_u32(b, NFTNL_RULE_ATTR_COMPAT_PROTO))
		print_err("Rule compat_proto mismatches");
	if (nftnl_rule_attr_get_u32(a, NFTNL_RULE_ATTR_COMPAT_FLAGS) !=
	    nftnl_rule_attr_get_u32(b, NFTNL_RULE_ATTR_COMPAT_FLAGS))
		print_err("Rule compat_flags mismatches");
	if (nftnl_rule_attr_get_u64(a, NFTNL_RULE_ATTR_POSITION) !=
	    nftnl_rule_attr_get_u64(b, NFTNL_RULE_ATTR_POSITION))
		print_err("Rule compat_position mismatches");
}

int main(int argc, char *argv[])
{
	struct nftnl_rule *a, *b;
	char buf[4096];
	struct nlmsghdr *nlh;

	a = nftnl_rule_alloc();
	b = nftnl_rule_alloc();
	if (a == NULL || b == NULL)
		print_err("OOM");

	nftnl_rule_attr_set_u32(a, NFTNL_RULE_ATTR_FAMILY, AF_INET);
	nftnl_rule_attr_set_str(a, NFTNL_RULE_ATTR_TABLE, "table");
	nftnl_rule_attr_set_str(a, NFTNL_RULE_ATTR_CHAIN, "chain");
	nftnl_rule_attr_set_u64(a, NFTNL_RULE_ATTR_HANDLE, 0x1234567812345678);
	nftnl_rule_attr_set_u32(a, NFTNL_RULE_ATTR_COMPAT_PROTO, 0x12345678);
	nftnl_rule_attr_set_u32(a, NFTNL_RULE_ATTR_COMPAT_FLAGS, 0x12345678);
	nftnl_rule_attr_set_u64(a, NFTNL_RULE_ATTR_POSITION, 0x1234567812345678);

	nlh = nftnl_rule_nlmsg_build_hdr(buf, NFT_MSG_NEWRULE, AF_INET, 0, 1234);
	nftnl_rule_nlmsg_build_payload(nlh, a);

	if (nftnl_rule_nlmsg_parse(nlh, b) < 0)
		print_err("parsing problems");

	cmp_nftnl_rule(a,b);

	nftnl_rule_free(a);
	nftnl_rule_free(b);
	if (!test_ok)
		exit(EXIT_FAILURE);

	printf("%s: \033[32mOK\e[0m\n", argv[0]);
	return EXIT_SUCCESS;
}
