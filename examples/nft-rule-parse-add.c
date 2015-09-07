/*
 * (C) 2013 by Pablo Neira Ayuso <pablo@netfilter.org>
 * (C) 2013 by Arturo Borrero Gonzalez <arturo.borrero.glez@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This code has been sponsored by Sophos Astaro <http://www.sophos.com>
 */

#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <stddef.h>	/* for offsetof */
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>

#include <libmnl/libmnl.h>
#include <libnftnl/rule.h>

static struct nftnl_rule *rule_parse_file(const char *file, uint16_t format)
{
	int fd;
	struct nftnl_rule *r;
	struct nftnl_parse_err *err;
	char data[4096];

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

	r = nftnl_rule_alloc();
	if (r == NULL) {
		perror("OOM");
		exit(EXIT_FAILURE);
	}

	err = nftnl_parse_err_alloc();
	if (err == NULL) {
		perror("error");
		exit(EXIT_FAILURE);
	}

	if (nftnl_rule_parse(r, format, data, err) < 0) {
		nftnl_parse_perror("Unable to parse file", err);
		nftnl_parse_err_free(err);
		nftnl_rule_free(r);
		return NULL;
	}

	nftnl_rule_attr_unset(r, NFTNL_RULE_HANDLE);

	nftnl_parse_err_free(err);
	return r;
}

int main(int argc, char *argv[])
{
	struct mnl_socket *nl;
	struct mnl_nlmsg_batch *batch;
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	uint32_t portid, seq, rule_seq;
	struct nftnl_rule *r;
	int ret, batching;
	uint16_t family, format, outformat;

	if (argc < 3) {
		printf("Usage: %s {xml|json} <file>\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	if (strcmp(argv[1], "xml") == 0) {
		format = NFTNL_PARSE_XML;
		outformat = NFTNL_OUTPUT_XML;
	} else if (strcmp(argv[1], "json") == 0) {
		format = NFTNL_PARSE_JSON;
		outformat = NFTNL_OUTPUT_JSON;
	} else {
		printf("Unknown format: xml, json\n");
		exit(EXIT_FAILURE);
	}

	r = rule_parse_file(argv[2], format);
	if (r == NULL)
		exit(EXIT_FAILURE);

	nftnl_rule_fprintf(stdout, r, outformat, 0);
	fprintf(stdout, "\n");

	batching = nftnl_batch_is_supported();
	if (batching < 0) {
		perror("Cannot talk to nfnetlink");
		exit(EXIT_FAILURE);
	}

	seq = time(NULL);
	batch = mnl_nlmsg_batch_start(buf, sizeof(buf));

	if (batching) {
		nftnl_batch_begin(mnl_nlmsg_batch_current(batch), seq++);
		mnl_nlmsg_batch_next(batch);
	}

	rule_seq = seq;
	family = nftnl_rule_attr_get_u32(r, NFTNL_RULE_FAMILY);
	nlh = nftnl_rule_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
				       NFT_MSG_NEWRULE, family,
				       NLM_F_CREATE|NLM_F_APPEND|NLM_F_ACK,
				       seq++);
	nftnl_rule_nlmsg_build_payload(nlh, r);
	nftnl_rule_free(r);
	mnl_nlmsg_batch_next(batch);

	if (batching) {
		nftnl_batch_end(mnl_nlmsg_batch_current(batch), seq++);
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
		ret = mnl_cb_run(buf, ret, rule_seq, portid, NULL, NULL);
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
