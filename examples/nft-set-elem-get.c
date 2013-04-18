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

#include <linux/netfilter/nf_tables.h>

#include <libmnl/libmnl.h>
#include <libnftables/set.h>

static int set_cb(const struct nlmsghdr *nlh, void *data)
{
	struct nft_set *t;
	char buf[4096];

	t = nft_set_alloc();
	if (t == NULL) {
		perror("OOM");
		goto err;
	}

	if (nft_set_elems_nlmsg_parse(nlh, t) < 0) {
		perror("nft_set_nlmsg_parse");
		goto err_free;
	}

	nft_set_snprintf(buf, sizeof(buf), t, 0, 0);
	printf("%s\n", buf);

err_free:
	nft_set_free(t);
err:
	return MNL_CB_OK;
}

int main(int argc, char *argv[])
{
	struct mnl_socket *nl;
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	uint32_t portid, seq, family;
	struct nft_set *t = NULL;
	int ret;

	if (argc != 4) {
		fprintf(stderr, "%s <family> <table> <set>\n", argv[0]);
		return EXIT_FAILURE;
	}
	t = nft_set_alloc();
	if (t == NULL) {
		perror("OOM");
		exit(EXIT_FAILURE);
	}
	seq = time(NULL);
	if (strcmp(argv[1], "ip") == 0)
		family = AF_INET;
	else if (strcmp(argv[1], "ip6") == 0)
		family = AF_INET6;
	else if (strcmp(argv[2], "bridge") == 0)
		family = AF_BRIDGE;
	else {
		fprintf(stderr, "Unknown family: ip, ip6, bridge\n");
		exit(EXIT_FAILURE);
	}

	nlh = nft_set_nlmsg_build_hdr(buf, NFT_MSG_GETSETELEM, family,
					NLM_F_DUMP|NLM_F_ACK, seq);
	nft_set_attr_set(t, NFT_SET_ATTR_NAME, argv[3]);
	nft_set_attr_set(t, NFT_SET_ATTR_TABLE, argv[2]);
	nft_set_elems_nlmsg_build_payload(nlh, t);
	nft_set_free(t);

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
		ret = mnl_cb_run(buf, ret, seq, portid, set_cb, NULL);
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
