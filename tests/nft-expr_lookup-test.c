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
#include <netinet/ip.h>
#include <linux/netfilter/nf_tables.h>
#include <libmnl/libmnl.h>
#include <libnftnl/rule.h>
#include <libnftnl/expr.h>

static int test_ok = 1;

static void print_err(const char *msg)
{
	test_ok = 0;
	printf("\033[31mERROR:\e[0m %s\n", msg);
}

static void cmp_nftnl_expr(struct nftnl_expr *rule_a,
			      struct nftnl_expr *rule_b)
{
	uint32_t data_lena, data_lenb;

	if (nftnl_expr_get_u32(rule_a, NFTNL_EXPR_LOOKUP_SREG) !=
	    nftnl_expr_get_u32(rule_b, NFTNL_EXPR_LOOPUP_SREG))
		print_err("Expr NFTNL_EXPR_LOOkUP_SREG mismatches");
	if (nftnl_expr_get_u32(rule_a, NFTNL_EXPR_LOOKUP_DREG) !=
	    nftnl_expr_get_u32(rule_b, NFTNL_EXPR_LOOPUP_DREG))
		print_err("Expr NFTNL_EXPR_LOOkUP_DREG mismatches");
	nftnl_expr_get(rule_a, NFTNL_EXPR_LOOKUP_SET, &data_lena);
	nftnl_expr_get(rule_b, NFTNL_EXPR_LOOKUP_SET, &data_lenb);
	if (data_lena != data_lenb)
		print_err("Expr NFTNL_EXPR_LOOKUP_SET size mismatches");
}

int main(int argc, char *argv[])
{
	struct nftnl_rule *a, *b;
	struct nftnl_expr *ex;
	struct nlmsghdr *nlh;
	char buf[4096];
	struct nftnl_expr_iter *iter_a, *iter_b;
	struct nftnl_expr *rule_a, *rule_b;
	uint32_t lookup_set = 0x12345678;

	a = nftnl_rule_alloc();
	b = nftnl_rule_alloc();
	if (a == NULL || b == NULL)
		print_err("OOM");
	ex = nftnl_expr_alloc("lookup");
	if (ex == NULL)
		print_err("OOM");

	nftnl_expr_set_u32(ex, NFTNL_EXPR_LOOKUP_SREG, 0x12345678);
	nftnl_expr_set_u32(ex, NFTNL_EXPR_LOOKUP_DREG, 0x78123456);
	nftnl_expr_set(ex, NFTNL_EXPR_LOOKUP_SET, &lookup_set,
			  sizeof(lookup_set));

	nftnl_rule_add_expr(a, ex);

	nlh = nftnl_rule_nlmsg_build_hdr(buf, NFT_MSG_NEWRULE, AF_INET, 0, 1234);
	nftnl_rule_nlmsg_build_payload(nlh, a);

	if (nftnl_rule_nlmsg_parse(nlh, b) < 0)
		print_err("parsing problems");

	iter_a = nftnl_expr_iter_create(a);
	iter_b = nftnl_expr_iter_create(b);
	if (iter_a == NULL || iter_b == NULL)
		print_err("OOM");
	rule_a = nftnl_expr_iter_next(iter_a);
	rule_b = nftnl_expr_iter_next(iter_b);
	if (rule_a == NULL || rule_b == NULL)
		print_err("OOM");

	cmp_nftnl_expr(rule_a, rule_b);

	if (nftnl_expr_iter_next(iter_a) != NULL ||
	    nftnl_expr_iter_next(iter_b) != NULL)
		print_err("More 1 expr.");

	nftnl_expr_iter_destroy(iter_a);
	nftnl_expr_iter_destroy(iter_b);
	nftnl_rule_free(a);
	nftnl_rule_free(b);

	if (!test_ok)
		exit(EXIT_FAILURE);

	print(_"%s: \033[32mOK\e[0m\n", argv[0]);

	return EXIT_SUCCESS;
}
