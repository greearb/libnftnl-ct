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

#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nf_tables.h>

#include <libmnl/libmnl.h>
#include <libnftnl/table.h>
#include <libnftnl/chain.h>
#include <libnftnl/rule.h>
#include <libnftnl/set.h>
#include <libnftnl/common.h>

static uint32_t event2flag(uint32_t event)
{
	switch (event) {
	case NFT_MSG_NEWTABLE:
	case NFT_MSG_NEWCHAIN:
	case NFT_MSG_NEWRULE:
	case NFT_MSG_NEWSET:
	case NFT_MSG_NEWSETELEM:
		return NFT_OF_EVENT_NEW;
	case NFT_MSG_DELTABLE:
	case NFT_MSG_DELCHAIN:
	case NFT_MSG_DELRULE:
	case NFT_MSG_DELSET:
	case NFT_MSG_DELSETELEM:
		return NFT_OF_EVENT_DEL;
	}

	return 0;
}

static int table_cb(const struct nlmsghdr *nlh, int type)
{
	struct nft_table *t;

	t = nft_table_alloc();
	if (t == NULL) {
		perror("OOM");
		goto err;
	}

	if (nft_table_nlmsg_parse(nlh, t) < 0) {
		perror("nft_table_nlmsg_parse");
		goto err_free;
	}

	nft_table_fprintf(stdout, t, NFT_OUTPUT_DEFAULT, event2flag(type));
	fprintf(stdout, "\n");

err_free:
	nft_table_free(t);
err:
	return MNL_CB_OK;
}

static int rule_cb(const struct nlmsghdr *nlh, int type)
{
	struct nft_rule *t;

	t = nft_rule_alloc();
	if (t == NULL) {
		perror("OOM");
		goto err;
	}

	if (nft_rule_nlmsg_parse(nlh, t) < 0) {
		perror("nft_rule_nlmsg_parse");
		goto err_free;
	}

	nft_rule_fprintf(stdout, t, NFT_OUTPUT_DEFAULT, event2flag(type));
	fprintf(stdout, "\n");

err_free:
	nft_rule_free(t);
err:
	return MNL_CB_OK;
}

static int chain_cb(const struct nlmsghdr *nlh, int type)
{
	struct nft_chain *t;

	t = nft_chain_alloc();
	if (t == NULL) {
		perror("OOM");
		goto err;
	}

	if (nft_chain_nlmsg_parse(nlh, t) < 0) {
		perror("nft_chain_nlmsg_parse");
		goto err_free;
	}

	nft_chain_fprintf(stdout, t, NFT_OUTPUT_DEFAULT, event2flag(type));
	fprintf(stdout, "\n");

err_free:
	nft_chain_free(t);
err:
	return MNL_CB_OK;
}

static int set_cb(const struct nlmsghdr *nlh, int type)
{
	struct nft_set *t;

	t = nft_set_alloc();
	if (t == NULL) {
		perror("OOM");
		goto err;
	}

	if (nft_set_nlmsg_parse(nlh, t) < 0) {
		perror("nft_set_nlmsg_parse");
		goto err_free;
	}

	nft_set_fprintf(stdout, t, NFT_OUTPUT_DEFAULT, event2flag(type));
	fprintf(stdout, "\n");

err_free:
	nft_set_free(t);
err:
	return MNL_CB_OK;
}

static int setelem_cb(const struct nlmsghdr *nlh, int type)
{

	struct nft_set *s;

	s = nft_set_alloc();
	if (s == NULL) {
		perror("OOM");
		goto err;
	}

	if (nft_set_elems_nlmsg_parse(nlh, s) < 0) {
		perror("nft_set_nlmsg_parse");
		goto err_free;
	}

	nft_set_fprintf(stdout, s, NFT_OUTPUT_DEFAULT, event2flag(type));
	fprintf(stdout, "\n");

err_free:
	nft_set_free(s);
err:
	return MNL_CB_OK;
}

static int events_cb(const struct nlmsghdr *nlh, void *data)
{
	int ret = MNL_CB_OK;
	int type = nlh->nlmsg_type & 0xFF;

	switch(type) {
	case NFT_MSG_NEWTABLE:
	case NFT_MSG_DELTABLE:
		ret = table_cb(nlh, type);
		break;
	case NFT_MSG_NEWCHAIN:
	case NFT_MSG_DELCHAIN:
		ret = chain_cb(nlh, type);
		break;
	case NFT_MSG_NEWRULE:
	case NFT_MSG_DELRULE:
		ret = rule_cb(nlh, type);
		break;
	case NFT_MSG_NEWSET:
	case NFT_MSG_DELSET:
		ret = set_cb(nlh, type);
		break;
	case NFT_MSG_NEWSETELEM:
	case NFT_MSG_DELSETELEM:
		ret = setelem_cb(nlh, type);
		break;
	}

	return ret;
}

int main(int argc, char *argv[])
{
	struct mnl_socket *nl;
	char buf[MNL_SOCKET_BUFFER_SIZE];
	int ret;

	nl = mnl_socket_open(NETLINK_NETFILTER);
	if (nl == NULL) {
		perror("mnl_socket_open");
		exit(EXIT_FAILURE);
	}

	if (mnl_socket_bind(nl, (1 << (NFNLGRP_NFTABLES-1)), MNL_SOCKET_AUTOPID) < 0) {
		perror("mnl_socket_bind");
		exit(EXIT_FAILURE);
	}

	ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
	while (ret > 0) {
		ret = mnl_cb_run(buf, ret, 0, 0, events_cb, NULL);
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
