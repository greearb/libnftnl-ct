/*
 * (C) 2013 by Álvaro Neira Ayuso <alvaroneay@gmail.com>
 *
 * Based on nft-set-xml-add from:
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
#include <string.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>
#include <linux/netfilter/nfnetlink.h>

#include <libmnl/libmnl.h>
#include <libnftnl/set.h>

static struct nft_set *set_parse_file(const char *file, uint16_t format)
{
	int fd;
	struct nft_set *s;
	struct nft_parse_err *err;
	char data[4096];

	s = nft_set_alloc();
	if (s == NULL) {
		perror("OOM");
		return NULL;
	}

	fd = open(file, O_RDONLY);
	if (fd < 0) {
		perror("open");
		return NULL;
	}

	if (read(fd, data, sizeof(data)) < 0) {
		perror("read");
		close(fd);
		return NULL;
	}
	close(fd);

	err = nft_parse_err_alloc();
	if (err == NULL) {
		perror("error");
		return NULL;
	}

	if (nft_set_parse(s, format, data, err) < 0) {
		nft_parse_perror("Unable to parse file", err);
		nft_parse_err_free(err);
		return NULL;
	}

	nft_parse_err_free(err);

	nft_set_attr_set_u32(s, NFT_SET_ATTR_ID, 1);
	return s;

}

int main(int argc, char *argv[])
{
	struct mnl_socket *nl;
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	uint32_t portid, seq, set_seq;
	struct nft_set *s;
	int ret, batching;
	uint16_t family, format, outformat;
	struct mnl_nlmsg_batch *batch;

	if (argc < 2) {
		printf("Usage: %s {xml|json} <file>\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	if (strcmp(argv[1], "xml") == 0) {
		format = NFT_PARSE_XML;
		outformat = NFT_OUTPUT_XML;
	} else if (strcmp(argv[1], "json") == 0) {
		format = NFT_PARSE_JSON;
		outformat = NFT_OUTPUT_JSON;
	} else {
		printf("Unknown format: xml, json\n");
		exit(EXIT_FAILURE);
	}

	s = set_parse_file(argv[2], format);
	if (s == NULL)
		exit(EXIT_FAILURE);

	nft_set_fprintf(stdout, s, outformat, 0);
	fprintf(stdout, "\n");

	seq = time(NULL);
	batching = nft_batch_is_supported();
	if (batching < 0) {
		perror("cannot talk to nfnetlink");
		exit(EXIT_FAILURE);
	}

	batch = mnl_nlmsg_batch_start(buf, sizeof(buf));

	if (batching) {
		nft_batch_begin(mnl_nlmsg_batch_current(batch), seq++);
		mnl_nlmsg_batch_next(batch);
	}

	family = nft_set_attr_get_u32(s, NFT_SET_ATTR_FAMILY);

	set_seq = seq;
	nlh = nft_set_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
				      NFT_MSG_NEWSET, family,
				      NLM_F_CREATE|NLM_F_ACK, seq++);
	nft_set_nlmsg_build_payload(nlh, s);
	nft_set_free(s);
	mnl_nlmsg_batch_next(batch);

	if (batching) {
		nft_batch_end(mnl_nlmsg_batch_current(batch), seq++);
		mnl_nlmsg_batch_next(batch);
	}

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

	if (mnl_socket_sendto(nl, mnl_nlmsg_batch_head(batch),
			      mnl_nlmsg_batch_size(batch)) < 0) {
		perror("mnl_socket_send");
		exit(EXIT_FAILURE);
	}

	mnl_nlmsg_batch_stop(batch);

	ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
	while (ret > 0) {
		ret = mnl_cb_run(buf, ret, set_seq, portid, NULL, NULL);
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
