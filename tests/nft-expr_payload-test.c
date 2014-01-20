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
#include <linux/netfilter/xt_iprange.h>
#include <libmnl/libmnl.h>
#include <libnftnl/rule.h>
#include <libnftnl/expr.h>

static int test_ok = 1;

static void print_err(const char *msg)
{
	test_ok = 0;
	printf("\033[31mERROR:\e[0m %s\n", msg);
}

static void cmp_nft_rule_expr(struct nft_rule_expr *rule_a,
			      struct nft_rule_expr *rule_b)
{
	if (nft_rule_expr_get_u32(rule_a, NFT_EXPR_PAYLOAD_DREG) !=
	    nft_rule_expr_get_u32(rule_b, NFT_EXPR_PAYLOAD_DREG))
		print_err("Expr NFT_EXPR_PAYLOAD_DREG mismatches");
	if (nft_rule_expr_get_u32(rule_a, NFT_EXPR_PAYLOAD_BASE) !=
	    nft_rule_expr_get_u32(rule_b, NFT_EXPR_PAYLOAD_BASE))
		print_err("Expr NFT_EXPR_PAYLOAD_BASE mismatches");
	if (nft_rule_expr_get_u32(rule_a, NFT_EXPR_PAYLOAD_OFFSET) !=
	    nft_rule_expr_get_u32(rule_b, NFT_EXPR_PAYLOAD_OFFSET))
		print_err("Expr NFT_EXPR_PAYLOAD_OFFSET mismatches");
	if (nft_rule_expr_get_u32(rule_a, NFT_EXPR_PAYLOAD_LEN) !=
	    nft_rule_expr_get_u32(rule_b, NFT_EXPR_PAYLOAD_LEN))
		print_err("Expr NFT_EXPR_PAYLOAD_LEN mismatches");
}

int main(int argc, char *argv[])
{
	struct nft_rule *a, *b;
	struct nft_rule_expr *ex;
	struct nlmsghdr *nlh;
	char buf[4096];
	struct nft_rule_expr_iter *iter_a, *iter_b;
	struct nft_rule_expr *rule_a, *rule_b;

	a = nft_rule_alloc();
	b = nft_rule_alloc();
	if (a == NULL || b == NULL)
		print_err("OOM");
	ex = nft_rule_expr_alloc("payload");
	if (ex == NULL)
		print_err("OOM");

	nft_rule_expr_set_u32(ex, NFT_EXPR_PAYLOAD_DREG, 0x1234568);
	nft_rule_expr_set_u32(ex, NFT_EXPR_PAYLOAD_BASE, 0x12345678);
	nft_rule_expr_set_u32(ex, NFT_EXPR_PAYLOAD_OFFSET, 0x12345678);
	nft_rule_expr_set_u32(ex, NFT_EXPR_PAYLOAD_LEN, 0x12345678);

	nft_rule_add_expr(a, ex);

	nlh = nft_rule_nlmsg_build_hdr(buf, NFT_MSG_NEWRULE, AF_INET, 0, 1234);
	nft_rule_nlmsg_build_payload(nlh, a);
	if (nft_rule_nlmsg_parse(nlh, b) < 0)
		print_err("parsing problems");

	iter_a = nft_rule_expr_iter_create(a);
	iter_b = nft_rule_expr_iter_create(b);
	if (iter_a == NULL || iter_b == NULL)
		print_err("OOM");

	rule_a = nft_rule_expr_iter_next(iter_a);
	rule_b = nft_rule_expr_iter_next(iter_b);
	if (rule_a == NULL || rule_b == NULL)
		print_err("OOM");

	cmp_nft_rule_expr(rule_a, rule_b);

	if (nft_rule_expr_iter_next(iter_a) != NULL ||
	    nft_rule_expr_iter_next(iter_b) != NULL)
		print_err("More 1 expr.");

	nft_rule_expr_iter_destroy(iter_a);
	nft_rule_expr_iter_destroy(iter_b);
	nft_rule_free(a);
	nft_rule_free(b);

	if (!test_ok)
		exit(EXIT_FAILURE);

	printf("%s: \033[32mOK\e[0m\n", argv[0]);
	return EXIT_SUCCESS;
}
