/*
 * (C) 2012-2013 by Pablo Neira Ayuso <pablo@netfilter.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <linux/netlink.h>
#include <linux/netfilter/nfnetlink.h>

#include <libmnl/libmnl.h>
#include <libnftables/common.h>

#include "internal.h"
#include<stdlib.h>

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

int nft_parse_perror(const char *str, struct nft_parse_err *err)
{
	switch (err->error) {
	case NFT_PARSE_EBADINPUT:
		return fprintf(stderr, "%s : Bad input format in line %d column %d\n",
		       str, err->line, err->column);
	case NFT_PARSE_EMISSINGNODE:
		return fprintf(stderr, "%s : Node \"%s\" not found\n",
				str, err->node_name);
	case NFT_PARSE_EBADTYPE:
		return fprintf(stderr, "%s: Invalid type in node \"%s\"\n",
				str, err->node_name);
	default:
		return fprintf(stderr, "Undefined error\n");
	}
}
EXPORT_SYMBOL(nft_parse_perror);
