/*
 * (C) 2012-2013 by Pablo Neira Ayuso <pablo@netfilter.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <stdlib.h>
#include <sys/socket.h>
#include <time.h>
#include <linux/netlink.h>
#include <linux/netfilter/nfnetlink.h>

#include <libmnl/libmnl.h>
#include <libnftnl/common.h>
#include <libnftnl/set.h>

#include <errno.h>
#include "internal.h"

struct nlmsghdr *nft_nlmsg_build_hdr(char *buf, uint16_t cmd, uint16_t family,
				     uint16_t type, uint32_t seq)
{
	struct nlmsghdr *nlh;
	struct nfgenmsg *nfh;

	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type = (NFNL_SUBSYS_NFTABLES << 8) | cmd;
	nlh->nlmsg_flags = NLM_F_REQUEST | type;
	nlh->nlmsg_seq = seq;

	nfh = mnl_nlmsg_put_extra_header(nlh, sizeof(struct nfgenmsg));
	nfh->nfgen_family = family;
	nfh->version = NFNETLINK_V0;
	nfh->res_id = 0;

	return nlh;
}
EXPORT_SYMBOL(nft_nlmsg_build_hdr);

struct nft_parse_err *nft_parse_err_alloc(void)
{
	return calloc(1, sizeof(struct nft_parse_err));
}
EXPORT_SYMBOL(nft_parse_err_alloc);

void nft_parse_err_free(struct nft_parse_err *err)
{
	xfree(err);
}
EXPORT_SYMBOL(nft_parse_err_free);

int nft_parse_perror(const char *msg, struct nft_parse_err *err)
{
	switch (err->error) {
	case NFT_PARSE_EBADINPUT:
		return fprintf(stderr, "%s: Bad input format in line %d column %d\n",
			       msg, err->line, err->column);
	case NFT_PARSE_EMISSINGNODE:
		return fprintf(stderr, "%s: Node \"%s\" not found\n",
			       msg, err->node_name);
	case NFT_PARSE_EBADTYPE:
		return fprintf(stderr, "%s: Invalid type in node \"%s\"\n",
			       msg, err->node_name);
	default:
		return fprintf(stderr, "%s: Undefined error\n", msg);
	}
}
EXPORT_SYMBOL(nft_parse_perror);

int nft_event_header_snprintf(char *buf, size_t size, uint32_t type,
			      uint32_t flags)
{
	int ret = 0;

	if (!(flags & NFT_OF_EVENT_ANY))
		return 0;

	switch (type) {
	case NFT_OUTPUT_XML:
		if (flags & NFT_OF_EVENT_NEW) {
			ret = snprintf(buf, size, "<event><type>new</type>");
		} else if (flags & NFT_OF_EVENT_DEL) {
			ret = snprintf(buf, size,
				       "<event><type>delete</type>");
		} else {
			ret = snprintf(buf, size,
				       "<event><type>unknown</type>");
		}
		break;
	case NFT_OUTPUT_JSON:
		if (flags & NFT_OF_EVENT_NEW) {
			ret = snprintf(buf, size, "{event:{type:\"new\",{\"");
		} else if (flags & NFT_OF_EVENT_DEL) {
			ret = snprintf(buf, size,
				       "{event:{type:\"delete\",{\"");
		} else {
			ret = snprintf(buf, size,
				       "{event:{type:\"unknown\",{\"");
		}
		break;
	default:
		if (flags & NFT_OF_EVENT_NEW) {
			ret = snprintf(buf, size, "%9s", "[NEW] ");
		} else if (flags & NFT_OF_EVENT_DEL) {
			ret = snprintf(buf, size, "%9s", "[DELETE] ");
		} else {
			ret = snprintf(buf, size, "%9s", "[unknown] ");
		}
		break;
	}
	return ret;
}

int nft_event_header_fprintf(FILE *fp, uint32_t type, uint32_t flags)
{
	char buf[64]; /* enough for the maximum string length above */

	nft_event_header_snprintf(buf, sizeof(buf), type, flags);
	buf[sizeof(buf) - 1] = '\0';

	return fprintf(fp, "%s", buf);
}

int nft_event_footer_snprintf(char *buf, size_t size, uint32_t type,
			      uint32_t flags)
{
	if (!(flags & NFT_OF_EVENT_ANY))
		return 0;

	switch (type) {
	case NFT_OUTPUT_XML:
		return snprintf(buf, size, "</event>");
	case NFT_OUTPUT_JSON:
		return snprintf(buf, size, "}}}");
	default:
		return 0;
	}
}

static void nft_batch_build_hdr(char *buf, uint16_t type, uint32_t seq)
{
	struct nlmsghdr *nlh;
	struct nfgenmsg *nfg;

	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type = type;
	nlh->nlmsg_flags = NLM_F_REQUEST;
	nlh->nlmsg_seq = seq;

	nfg = mnl_nlmsg_put_extra_header(nlh, sizeof(*nfg));
	nfg->nfgen_family = AF_UNSPEC;
	nfg->version = NFNETLINK_V0;
	nfg->res_id = NFNL_SUBSYS_NFTABLES;
}

void nft_batch_begin(char *buf, uint32_t seq)
{
	nft_batch_build_hdr(buf, NFNL_MSG_BATCH_BEGIN, seq);
}
EXPORT_SYMBOL(nft_batch_begin);

void nft_batch_end(char *buf, uint32_t seq)
{
	nft_batch_build_hdr(buf, NFNL_MSG_BATCH_END, seq);
}
EXPORT_SYMBOL(nft_batch_end);

int nft_event_footer_fprintf(FILE *fp, uint32_t type, uint32_t flags)
{
	char buf[32]; /* enough for the maximum string length above */

	nft_event_footer_snprintf(buf, sizeof(buf), type, flags);
	buf[sizeof(buf) - 1] = '\0';

	return fprintf(fp, "%s", buf);
}

int nft_batch_is_supported(void)
{
	struct mnl_socket *nl;
	struct mnl_nlmsg_batch *b;
	char buf[MNL_SOCKET_BUFFER_SIZE];
	uint32_t seq = time(NULL), req_seq;
	int ret;

	nl = mnl_socket_open(NETLINK_NETFILTER);
	if (nl == NULL)
		return -1;

	if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0)
		return -1;

	b = mnl_nlmsg_batch_start(buf, sizeof(buf));

	nft_batch_begin(mnl_nlmsg_batch_current(b), seq++);
	mnl_nlmsg_batch_next(b);

	req_seq = seq;
	nft_set_nlmsg_build_hdr(mnl_nlmsg_batch_current(b),
				NFT_MSG_NEWSET, AF_INET,
				NLM_F_ACK, seq++);
	mnl_nlmsg_batch_next(b);

	nft_batch_end(mnl_nlmsg_batch_current(b), seq++);
	mnl_nlmsg_batch_next(b);

	ret = mnl_socket_sendto(nl, mnl_nlmsg_batch_head(b),
				mnl_nlmsg_batch_size(b));
	if (ret < 0)
		goto err;

	mnl_nlmsg_batch_stop(b);

	ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
	while (ret > 0) {
		ret = mnl_cb_run(buf, ret, req_seq, mnl_socket_get_portid(nl),
				 NULL, NULL);
		if (ret <= 0)
			break;

		ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
	}
	mnl_socket_close(nl);

	/* We're sending an incomplete message to see if the kernel supports
	 * set messages in batches. EINVAL means that we sent an incomplete
	 * message with missing attributes. The kernel just ignores messages
	 * that we cannot include in the batch.
	 */
	return (ret == -1 && errno == EINVAL) ? 1 : 0;
err:
	mnl_nlmsg_batch_stop(b);
	return -1;
}
EXPORT_SYMBOL(nft_batch_is_supported);
