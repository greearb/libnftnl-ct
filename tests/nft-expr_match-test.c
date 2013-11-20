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

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <linux/netfilter/nf_tables.h>
#include <linux/netfilter/xt_iprange.h>
#include <libmnl/libmnl.h>
#include <libnftables/rule.h>
#include <libnftables/expr.h>

static int test_ok = 1;

static void print_err(const char *msg)
{
	test_ok = 0;
	printf("\033[31mERROR:\e[0m %s\n", msg);
}

static void print_err2(const char *msg, uint32_t a, uint32_t b)
{
	test_ok = 0;
	printf("\033[31mERROR:\e[0m %s size a: %d b: %d \n", msg, a, b);
}

static void cmp_nft_rule_expr(struct nft_rule_expr *rule_a,
			      struct nft_rule_expr *rule_b)
{
	uint32_t lena, lenb;

	if (strcmp(nft_rule_expr_get_str(rule_a, NFT_EXPR_MT_NAME),
		   nft_rule_expr_get_str(rule_b, NFT_EXPR_MT_NAME)) != 0)
		print_err("Expr NFT_EXPR_MT_NAME mismatches");
	if (nft_rule_expr_get_u32(rule_a, NFT_EXPR_MT_REV) !=
	    nft_rule_expr_get_u32(rule_b, NFT_EXPR_MT_REV))
		print_err("Expr NFT_EXPR_MT_REV mismatches");
	nft_rule_expr_get(rule_a, NFT_EXPR_MT_INFO, &lena);
	nft_rule_expr_get(rule_b, NFT_EXPR_MT_INFO, &lenb);
	if (lena != lenb)
		print_err2("Expr NFT_EXPR_MT_INFO size mismatches", lena, lenb);
}

int main(int argc, char *argv[])
{
	struct nft_rule *a, *b;
	struct nft_rule_expr *ex;
	struct nlmsghdr *nlh;
	char buf[4096];
	struct nft_rule_expr_iter *iter_a, *iter_b;
	struct nft_rule_expr *rule_a, *rule_b;
	struct xt_iprange_mtinfo *info;

	a = nft_rule_alloc();
	b = nft_rule_alloc();
	if (a == NULL || b == NULL)
		print_err("OOM");
	ex = nft_rule_expr_alloc("match");
	if (ex == NULL)
		print_err("OOM");

	nft_rule_expr_set_str(ex, NFT_EXPR_MT_NAME, "Tests");
	nft_rule_expr_set_u32(ex, NFT_EXPR_MT_REV, 0x12345678);

        info = calloc(1, sizeof(struct xt_iprange_mtinfo));
        if (info == NULL)
                print_err("OOM");

        info->src_min.ip = info->dst_min.ip = inet_addr("127.0.0.1");
        info->src_max.ip = info->dst_max.ip = inet_addr("127.0.0.1");
        info->flags = IPRANGE_SRC;

        nft_rule_expr_set(ex, NFT_EXPR_MT_INFO, info, sizeof(info));

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
