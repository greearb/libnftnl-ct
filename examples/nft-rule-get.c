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
#include <netinet/in.h>

#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>

#include <libmnl/libmnl.h>
#include <libnftables/rule.h>

static int table_cb(const struct nlmsghdr *nlh, void *data)
{
	struct nft_rule *t;
	char buf[4096];
	uint32_t *type = data;

	t = nft_rule_alloc();
	if (t == NULL) {
		perror("OOM");
		goto err;
	}

	if (nft_rule_nlmsg_parse(nlh, t) < 0) {
		perror("nft_rule_nlmsg_parse");
		goto err_free;
	}

	nft_rule_snprintf(buf, sizeof(buf), t, *type, 0);
	printf("%s\n", buf);

err_free:
	nft_rule_free(t);
err:
	return MNL_CB_OK;
}

int main(int argc, char *argv[])
{
	struct mnl_socket *nl;
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	uint32_t portid, seq, type = NFT_RULE_O_DEFAULT;
	struct nft_rule *t = NULL;
	int ret, family;

	if (argc < 2 || argc > 3) {
		fprintf(stderr, "Usage: %s <family> [xml|json]\n",
			argv[0]);
		exit(EXIT_FAILURE);
	}

	if (strcmp(argv[1], "ip") == 0)
		family = NFPROTO_IPV4;
	else if (strcmp(argv[1], "ip6") == 0)
		family = NFPROTO_IPV6;
	else if (strcmp(argv[1], "bridge") == 0)
		family = NFPROTO_BRIDGE;
	else if (strcmp(argv[1], "arp") == 0)
		family = NFPROTO_ARP;
	else {
		fprintf(stderr, "Unknown family: ip, ip6, bridge, arp\n");
		exit(EXIT_FAILURE);
	}

	if (argc == 3) {
		if (strcmp(argv[2], "xml") == 0)
			type = NFT_RULE_O_XML;
		else if (strcmp(argv[2], "json") == 0)
			type = NFT_RULE_O_JSON;
	}

	/* XXX requires table, chain and handle attributes for selective get */

	t = nft_rule_alloc();
	if (t == NULL) {
		perror("OOM");
		exit(EXIT_FAILURE);
	}

	seq = time(NULL);
	nlh = nft_rule_nlmsg_build_hdr(buf, NFT_MSG_GETRULE, family,
					NLM_F_DUMP, seq);

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
		ret = mnl_cb_run(buf, ret, seq, portid, table_cb, &type);
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
