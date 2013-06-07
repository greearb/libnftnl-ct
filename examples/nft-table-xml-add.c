/*
 * 2013 by Arturo Borrero Gonzalez <arturo.borrero.glez@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include <linux/netfilter/nf_tables.h>

#include <libmnl/libmnl.h>
#include <libnftables/table.h>

extern struct nft_table nft_table;

int main(int argc, char *argv[])
{
	struct mnl_socket *nl;
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	uint32_t portid, seq;
	struct nft_table *t = NULL;
	int ret;
	int fd;
	uint16_t family;
	char xml[4096];
	char reprint[4096];

	if (argc < 2) {
		printf("Usage: %s <xml-file>\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	fd = open(argv[1], O_RDONLY);
	if (fd < 0) {
		perror("open");
		exit(EXIT_FAILURE);
	}

	if (read(fd, xml, sizeof(xml)) < 0) {
		perror("read");
		close(fd);
		exit(EXIT_FAILURE);
	}

	t = nft_table_alloc();
	if (t == NULL) {
		perror("OOM");
		close(fd);
		exit(EXIT_FAILURE);
	}

	/* Parsing XML now */
	if (nft_table_parse(t, NFT_TABLE_PARSE_XML, xml) < 0) {
		printf("E: Unable to parse XML file: %s\n", strerror(errno));
		close(fd);
		exit(EXIT_FAILURE);
	}

	close(fd);

	nft_table_snprintf(reprint, sizeof(reprint), t, NFT_TABLE_O_XML, 0);
	printf("Parsed:\n%s\n", reprint);


	family = (uint16_t)nft_table_attr_get_u32(t, NFT_TABLE_ATTR_FAMILY);

	seq = time(NULL);

	nlh = nft_table_nlmsg_build_hdr(buf, NFT_MSG_NEWTABLE, family,
							NLM_F_ACK, seq);
	nft_table_nlmsg_build_payload(nlh, t);
	nft_table_free(t);

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