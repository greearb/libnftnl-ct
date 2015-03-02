/*
 * (C) 2014 by Alvaro Neira Ayuso <alvaroneay@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <stddef.h>     /* for offsetof */
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>

#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nf_tables.h>

#include <libmnl/libmnl.h>
#include <libnftnl/ruleset.h>
#include <libnftnl/table.h>
#include <libnftnl/chain.h>
#include <libnftnl/rule.h>
#include <libnftnl/set.h>

struct mnl_nlmsg_batch *batch;
uint32_t seq;

static int nft_ruleset_set_elems(const struct nft_parse_ctx *ctx)
{
	struct nft_set_elems_iter *iter_elems;
	uint16_t nl_type, nl_flags;
	uint32_t cmd;
	struct nlmsghdr *nlh;
	struct nft_set *set;

	cmd = nft_ruleset_ctx_get_u32(ctx, NFT_RULESET_CTX_CMD);

	set = nft_ruleset_ctx_get(ctx, NFT_RULESET_CTX_SET);
	if (set == NULL)
		return -1;

	switch (cmd) {
	case NFT_CMD_ADD:
		nl_type = NFT_MSG_NEWSETELEM;
		nl_flags = NLM_F_CREATE|NLM_F_EXCL|NLM_F_ACK;
		break;
	case NFT_CMD_DELETE:
		nl_type = NFT_MSG_DELSETELEM;
		/* This will generate an ACK message for each request. When
		 * removing NLM_F_ACK, the kernel will only report when things
		 * go wrong
		 */
		nl_flags = NLM_F_ACK;
		break;
	default:
		goto err;
	}

	iter_elems = nft_set_elems_iter_create(set);
	if (iter_elems == NULL)
		goto err;

	nlh = nft_set_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch), nl_type,
				      nft_set_attr_get_u32(set,
							   NFT_SET_ATTR_FAMILY),
				      nl_flags, seq++);

	nft_set_elems_nlmsg_build_payload_iter(nlh, iter_elems);
	mnl_nlmsg_batch_next(batch);

	nft_set_elems_iter_destroy(iter_elems);
	nft_set_free(set);
	return 0;
err:
	nft_set_free(set);
	return -1;
}

static int nft_ruleset_set(const struct nft_parse_ctx *ctx)
{

	struct nlmsghdr *nlh;
	uint16_t nl_type, nl_flags;
	struct nft_set *set;
	uint32_t cmd;
	int ret;

	cmd = nft_ruleset_ctx_get_u32(ctx, NFT_RULESET_CTX_CMD);

	set = nft_ruleset_ctx_get(ctx, NFT_RULESET_CTX_SET);
	if (set == NULL)
		return -1;

	switch (cmd) {
	case NFT_CMD_ADD:
		nl_type = NFT_MSG_NEWSET;
		nl_flags = NLM_F_CREATE|NLM_F_ACK;
		break;
	case NFT_CMD_DELETE:
		nl_type = NFT_MSG_DELSET;
		nl_flags = NLM_F_ACK;
		break;
	default:
		goto err;
	}

	nlh = nft_set_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
				      nl_type,
				      nft_set_attr_get_u32(set,
							   NFT_SET_ATTR_FAMILY),
				      nl_flags,
				      seq++);

	nft_set_nlmsg_build_payload(nlh, set);
	mnl_nlmsg_batch_next(batch);

	ret = nft_ruleset_set_elems(ctx);
	return ret;
err:
	nft_set_free(set);
	return -1;
}

static int nft_ruleset_rule_build_msg(const struct nft_parse_ctx *ctx,
				      uint32_t cmd, struct nft_rule *rule)
{
	struct nlmsghdr *nlh;
	uint16_t nl_type, nl_flags;

	switch (cmd) {
	case NFT_CMD_ADD:
		nl_type = NFT_MSG_NEWRULE;
		nl_flags = NLM_F_APPEND|NLM_F_CREATE|NLM_F_ACK;
		nft_rule_attr_unset(rule, NFT_RULE_ATTR_HANDLE);
		break;
	case NFT_CMD_DELETE:
		nl_type = NFT_MSG_DELRULE;
		nl_flags = NLM_F_ACK;
		break;
	case NFT_CMD_REPLACE:
		nl_type = NFT_MSG_NEWRULE;
		nl_flags = NLM_F_REPLACE|NLM_F_ACK;
		break;
	case NFT_CMD_INSERT:
		nl_type = NFT_MSG_NEWRULE;
		nl_flags = NLM_F_CREATE|NLM_F_ACK;
		nft_rule_attr_unset(rule, NFT_RULE_ATTR_HANDLE);
		break;
	default:
		return -1;
	}

	nlh = nft_rule_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
				       nl_type,
				       nft_rule_attr_get_u32(rule,
							  NFT_RULE_ATTR_FAMILY),
				       nl_flags,
				       seq++);

	nft_rule_nlmsg_build_payload(nlh, rule);
	mnl_nlmsg_batch_next(batch);

	return 0;
}

static int nft_ruleset_rule(const struct nft_parse_ctx *ctx)
{
	struct nft_rule *rule;
	int ret;
	uint32_t cmd;

	cmd = nft_ruleset_ctx_get_u32(ctx, NFT_RULESET_CTX_CMD);

	rule = nft_ruleset_ctx_get(ctx, NFT_RULESET_CTX_RULE);
	if (rule == NULL)
		return -1;

	ret = nft_ruleset_rule_build_msg(ctx, cmd, rule);
	nft_rule_free(rule);

	return ret;
}

static int nft_ruleset_flush_rules(const struct nft_parse_ctx *ctx)
{
	struct nft_rule *nlr;
	struct nft_table *nlt;
	struct nft_chain *nlc;
	uint32_t type;
	int ret;

	nlr = nft_rule_alloc();
	if (nlr == NULL)
		return -1;

	type = nft_ruleset_ctx_get_u32(ctx, NFT_RULESET_CTX_TYPE);
	switch (type) {
	case NFT_RULESET_TABLE:
		nlt = nft_ruleset_ctx_get(ctx, NFT_RULESET_CTX_TABLE);
		nft_rule_attr_set(nlr, NFT_RULE_ATTR_TABLE,
				  nft_table_attr_get(nlt, NFT_TABLE_ATTR_NAME));
		nft_rule_attr_set(nlr, NFT_RULE_ATTR_FAMILY,
				nft_table_attr_get(nlt, NFT_TABLE_ATTR_FAMILY));
		break;
	case NFT_RULESET_CHAIN:
		nlc = nft_ruleset_ctx_get(ctx, NFT_RULESET_CTX_CHAIN);
		nft_rule_attr_set(nlr, NFT_RULE_ATTR_TABLE,
				  nft_chain_attr_get(nlc,
						     NFT_CHAIN_ATTR_TABLE));
		nft_rule_attr_set(nlr, NFT_RULE_ATTR_CHAIN,
				  nft_chain_attr_get(nlc,
						     NFT_CHAIN_ATTR_NAME));
		nft_rule_attr_set(nlr, NFT_RULE_ATTR_FAMILY,
				nft_chain_attr_get(nlc, NFT_TABLE_ATTR_FAMILY));
		break;
	default:
		goto err;
	}

	ret = nft_ruleset_rule_build_msg(ctx, NFT_CMD_DELETE, nlr);
	nft_rule_free(nlr);

	return ret;
err:
	nft_rule_free(nlr);
	return -1;
}

static int nft_ruleset_chain(const struct nft_parse_ctx *ctx)
{
	struct nlmsghdr *nlh;
	uint16_t nl_type, nl_flags;
	uint32_t cmd;
	struct nft_chain *chain;

	cmd = nft_ruleset_ctx_get_u32(ctx, NFT_RULESET_CTX_CMD);

	chain = nft_ruleset_ctx_get(ctx, NFT_RULESET_CTX_CHAIN);
	if (chain == NULL)
		return -1;

	switch (cmd) {
	case NFT_CMD_ADD:
		nl_type = NFT_MSG_NEWCHAIN;
		nl_flags = NLM_F_CREATE|NLM_F_ACK;
		break;
	case NFT_CMD_DELETE:
		nl_type = NFT_MSG_DELCHAIN;
		nl_flags = NLM_F_ACK;
		break;
	case NFT_CMD_FLUSH:
		return nft_ruleset_flush_rules(ctx);
	default:
		goto err;
	}

	nft_chain_attr_unset(chain, NFT_CHAIN_ATTR_HANDLE);
	nlh = nft_chain_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
					nl_type,
					nft_chain_attr_get_u32(chain,
							 NFT_CHAIN_ATTR_FAMILY),
					nl_flags,
					seq++);

	nft_chain_nlmsg_build_payload(nlh, chain);
	mnl_nlmsg_batch_next(batch);

	nft_chain_free(chain);
	return 0;
err:
	nft_chain_free(chain);
	return -1;
}

static int nft_ruleset_table_build_msg(const struct nft_parse_ctx *ctx,
				       uint32_t cmd, struct nft_table *table)
{
	struct nlmsghdr *nlh;
	uint16_t nl_type, nl_flags;

	switch (cmd) {
	case NFT_CMD_ADD:
		nl_type = NFT_MSG_NEWTABLE;
		nl_flags = NLM_F_CREATE|NLM_F_ACK;
		break;
	case NFT_CMD_DELETE:
		nl_type = NFT_MSG_DELTABLE;
		nl_flags = NLM_F_ACK;
		break;
	case NFT_CMD_FLUSH:
		return nft_ruleset_flush_rules(ctx);
	default:
		return -1;
	}

	nlh = nft_table_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
					nl_type,
					nft_table_attr_get_u32(table,
							 NFT_TABLE_ATTR_FAMILY),
					nl_flags,
					seq++);

	nft_table_nlmsg_build_payload(nlh, table);
	mnl_nlmsg_batch_next(batch);

	return 0;
}

static int nft_ruleset_table(const struct nft_parse_ctx *ctx)
{
	struct nft_table *table;
	uint32_t cmd;
	int ret;

	cmd = nft_ruleset_ctx_get_u32(ctx, NFT_RULESET_CTX_CMD);

	table = nft_ruleset_ctx_get(ctx, NFT_RULESET_CTX_TABLE);
	if (table == NULL)
		return -1;

	ret = nft_ruleset_table_build_msg(ctx, cmd, table);
	nft_table_free(table);

	return ret;
}

static int nft_ruleset_flush_ruleset(const struct nft_parse_ctx *ctx)
{
	struct nft_table *table;
	int ret;

	table = nft_table_alloc();
	if (table == NULL)
		return -1;

	ret = nft_ruleset_table_build_msg(ctx, NFT_CMD_DELETE, table);
	nft_table_free(table);

	return ret;
}

static int ruleset_elems_cb(const struct nft_parse_ctx *ctx)
{
	uint32_t type;
	int ret;

	type = nft_ruleset_ctx_get_u32(ctx, NFT_RULESET_CTX_TYPE);

	switch (type) {
	case NFT_RULESET_TABLE:
		ret = nft_ruleset_table(ctx);
		break;
	case NFT_RULESET_CHAIN:
		ret = nft_ruleset_chain(ctx);
		break;
	case NFT_RULESET_RULE:
		ret = nft_ruleset_rule(ctx);
		break;
	case NFT_RULESET_SET:
		ret = nft_ruleset_set(ctx);
		break;
	case NFT_RULESET_SET_ELEMS:
		ret = nft_ruleset_set_elems(ctx);
		break;
	case NFT_RULESET_RULESET:
		ret = nft_ruleset_flush_ruleset(ctx);
		break;
	default:
		return -1;
	}

	return ret;
}

int main(int argc, char *argv[])
{
	struct nft_parse_err *err;
	const char *filename;
	FILE *fp;
	int ret = -1, len, batching, portid;
	uint32_t ruleset_seq;
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct mnl_socket *nl;

	if (argc < 2) {
		printf("Usage: %s <file>\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	fp = fopen(argv[1], "r");
	if (fp == NULL) {
		printf("unable to open file %s: %s\n", argv[1],
		       strerror(errno));
		exit(EXIT_FAILURE);
	}

	err = nft_parse_err_alloc();
	if (err == NULL) {
		perror("error");
		exit(EXIT_FAILURE);
	}

	batching = nft_batch_is_supported();
	if (batching < 0) {
		perror("Cannot talk to nfnetlink");
		exit(EXIT_FAILURE);
	}

	seq = time(NULL);
	batch = mnl_nlmsg_batch_start(buf, sizeof(buf));

	if (batching) {
		nft_batch_begin(mnl_nlmsg_batch_current(batch), seq++);
		mnl_nlmsg_batch_next(batch);
	}
	ruleset_seq = seq;

	filename = argv[1];
	len = strlen(filename);
	if (len >= 5 && strcmp(&filename[len - 5], ".json") == 0)
		ret = nft_ruleset_parse_file_cb(NFT_PARSE_JSON, fp, err, NULL,
						&ruleset_elems_cb);
	else if (len >= 4 && strcmp(&filename[len - 4], ".xml") == 0)
		ret = nft_ruleset_parse_file_cb(NFT_PARSE_XML, fp, err, NULL,
						&ruleset_elems_cb);
	else {
		printf("the filename %s must to end in .xml or .json\n",
			filename);
		exit(EXIT_FAILURE);
	}

	if (ret < 0) {
		nft_parse_perror("fail", err);
		exit(EXIT_FAILURE);
	}

	fclose(fp);

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
		ret = mnl_cb_run(buf, ret, ruleset_seq, portid, NULL, NULL);
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
