/*
 * (C) 2013 by Álvaro Neira Ayuso <alvaroneay@gmail.com>
 *
 * Based on nft-rule-xml-add from:
 *
 * (C) 2013 by Pablo Neira Ayuso <pablo@netfilter.org>
 * (C) 2013 by Arturo Borrero Gonzalez <arturo.borrero.glez@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <stdlib.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <errno.h>

#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>

#include <libmnl/libmnl.h>
#include <libnftables/rule.h>

int main(int argc, char *argv[])
{
	struct mnl_socket *nl;
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	uint32_t portid, seq;
	struct nft_rule *r = NULL;
	int ret, fd;
	uint8_t family;
	char json[4096];
	char reprint[4096];
	struct nft_parse_err *err;

	if (argc < 2) {
		printf("Usage: %s <json-file>\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	fd = open(argv[1], O_RDONLY);
	if (fd < 0) {
		perror("open");
		exit(EXIT_FAILURE);
	}

	if (read(fd, json, sizeof(json)) < 0) {
		perror("read");
		close(fd);
		exit(EXIT_FAILURE);
	}
	close(fd);

	r = nft_rule_alloc();
	if (r == NULL) {
		perror("OOM");
		exit(EXIT_FAILURE);
	}

	err = nft_parse_err_alloc();
	if (err == NULL) {
		perror("error");
		exit(EXIT_FAILURE);
	}

	if (nft_rule_parse(r, NFT_PARSE_JSON, json, err) < 0) {
		nft_parse_perror("Unable to parse JSON file", err);
		exit(EXIT_FAILURE);
	}

	nft_rule_snprintf(reprint, sizeof(reprint), r, NFT_OUTPUT_JSON, 0);
	printf("Parsed:\n%s\n", reprint);

	nft_rule_attr_unset(r, NFT_RULE_ATTR_HANDLE);
	family = nft_rule_attr_get_u8(r, NFT_RULE_ATTR_FAMILY);

	seq = time(NULL);
	nlh = nft_rule_nlmsg_build_hdr(buf, NFT_MSG_NEWRULE, family,
				       NLM_F_CREATE|NLM_F_APPEND|NLM_F_ACK,
				       seq);
	nft_rule_nlmsg_build_payload(nlh, r);
	nft_rule_free(r);
	nft_parse_err_free(err);

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
