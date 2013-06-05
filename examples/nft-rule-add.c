/*
 * (C) 2012 by Pablo Neira Ayuso <pablo@netfilter.org>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This software has been sponsored by Sophos Astaro <http://www.sophos.com>
 */

#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <stddef.h>	/* for offsetof */
#include <netinet/in.h>
#include <arpa/inet.h>

#include <linux/netfilter/nf_tables.h>

#include <libmnl/libmnl.h>
#include <libnftables/rule.h>
#include <libnftables/expr.h>

#include <linux/netfilter_ipv4/ipt_LOG.h>
#include <linux/netfilter/xt_iprange.h>

#include <netinet/ip.h>

static void add_target_log(struct nft_rule_expr *e)
{
	struct ipt_log_info *info;

	nft_rule_expr_set(e, NFT_EXPR_TG_NAME, "LOG", strlen("LOG"));
	nft_rule_expr_set_u32(e, NFT_EXPR_TG_REV, 0);

	info = calloc(1, sizeof(struct ipt_log_info));
	if (info == NULL)
		return;

	sprintf(info->prefix, "test: ");
	info->prefix[sizeof(info->prefix)-1] = '\0';
	info->logflags = 0x0f;
	info->level = 5;

	nft_rule_expr_set(e, NFT_EXPR_TG_INFO, info, sizeof(*info));
}

static void add_expr_target(struct nft_rule *r)
{
	struct nft_rule_expr *expr;

	expr = nft_rule_expr_alloc("target");
	if (expr == NULL)
		return;

	add_target_log(expr);

	nft_rule_add_expr(r, expr);
}

static void add_match_iprange(struct nft_rule_expr *e)
{
	struct xt_iprange_mtinfo *info;

	nft_rule_expr_set(e, NFT_EXPR_MT_NAME, "iprange", strlen("iprange"));
	nft_rule_expr_set_u32(e, NFT_EXPR_MT_REV, 1);

	info = calloc(1, sizeof(struct xt_iprange_mtinfo));
	if (info == NULL)
		return;

	info->src_min.ip = info->dst_min.ip = inet_addr("127.0.0.1");
	info->src_max.ip = info->dst_max.ip = inet_addr("127.0.0.1");
	info->flags = IPRANGE_SRC;

	nft_rule_expr_set(e, NFT_EXPR_MT_INFO, info, sizeof(*info));
}

static void add_expr_match(struct nft_rule *r)
{
	struct nft_rule_expr *expr;

	expr = nft_rule_expr_alloc("match");
	if (expr == NULL)
		return;

	add_match_iprange(expr);

	nft_rule_add_expr(r, expr);
}

#define field_sizeof(t, f)	(sizeof(((t *)NULL)->f))

static void add_payload2(struct nft_rule_expr *e)
{
	nft_rule_expr_set_u32(e, NFT_EXPR_PAYLOAD_BASE,
			      NFT_PAYLOAD_NETWORK_HEADER);
	nft_rule_expr_set_u32(e, NFT_EXPR_PAYLOAD_DREG, NFT_REG_1);
	nft_rule_expr_set_u32(e, NFT_EXPR_PAYLOAD_OFFSET,
			      offsetof(struct iphdr, protocol));
	nft_rule_expr_set_u32(e, NFT_EXPR_PAYLOAD_LEN, 1);
}

static void add_payload(struct nft_rule *r)
{
	struct nft_rule_expr *expr;

	expr = nft_rule_expr_alloc("payload");
	if (expr == NULL)
		return;

	add_payload2(expr);

	nft_rule_add_expr(r, expr);
}

int main(int argc, char *argv[])
{
	struct mnl_socket *nl;
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	uint32_t portid, seq;
	struct nft_rule *r = NULL;
	int ret, family;

	if (argc != 4) {
		fprintf(stderr, "Usage: %s <family> <table> <chain>\n",
			argv[0]);
		exit(EXIT_FAILURE);
	}

	r = nft_rule_alloc();
	if (r == NULL) {
		perror("OOM");
		exit(EXIT_FAILURE);
	}

	if (strcmp(argv[1], "ip") == 0)
		family = AF_INET;
	else if (strcmp(argv[1], "ip6") == 0)
		family = AF_INET6;
	else if (strcmp(argv[1], "bridge") == 0)
		family = AF_BRIDGE;
	else {
		fprintf(stderr, "Unknown family: ip, ip6, bridge\n");
		exit(EXIT_FAILURE);
	}

	nft_rule_attr_set(r, NFT_RULE_ATTR_TABLE, argv[2]);
	nft_rule_attr_set(r, NFT_RULE_ATTR_CHAIN, argv[3]);

	add_expr_match(r);
	add_payload(r);
	add_expr_target(r);

	char tmp[1024];
	nft_rule_snprintf(tmp, sizeof(tmp), r, 0, 0);
	printf("%s\n", tmp);

	seq = time(NULL);
	nlh = nft_rule_nlmsg_build_hdr(buf, NFT_MSG_NEWRULE, family,
					NLM_F_APPEND|NLM_F_ACK|NLM_F_CREATE,
					seq);
	nft_rule_nlmsg_build_payload(nlh, r);
	nft_rule_free(r);

	nl = mnl_socket_open(NETLINK_NETFILTER);
	if (nl == NULL) {
		perror("mnl_socket_open");
		exit(EXIT_FAILURE);
	}

	if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
		perror("mnl_socket_bind");
		exit(EXIT_FAILURE);
	}
	portid = mnl_socket_get_portid(nl);

	if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
		perror("mnl_socket_send");
		exit(EXIT_FAILURE);
	}

	ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
	while (ret > 0) {
		ret = mnl_cb_run(buf, ret, seq, portid, NULL, NULL);
		if (ret <= 0)
			break;
		ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
	}
	if (ret == -1) {
		perror("error");
		exit(EXIT_FAILURE);
	}
	mnl_socket_close(nl);

	return EXIT_SUCCESS;
}
