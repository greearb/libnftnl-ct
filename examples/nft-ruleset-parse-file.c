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

static int nftnl_ruleset_set_elems(const struct nftnl_parse_ctx *ctx)
{
	struct nftnl_set_elems_iter *iter_elems;
	uint16_t nl_type, nl_flags;
	uint32_t cmd;
	struct nlmsghdr *nlh;
	struct nftnl_set *set;

	cmd = nftnl_ruleset_ctx_get_u32(ctx, NFTNL_RULESET_CTX_CMD);

	set = nftnl_ruleset_ctx_get(ctx, NFTNL_RULESET_CTX_SET);
	if (set == NULL)
		return -1;

	switch (cmd) {
	case NFTNL_CMD_ADD:
		nl_type = NFT_MSG_NEWSETELEM;
		nl_flags = NLM_F_CREATE|NLM_F_EXCL|NLM_F_ACK;
		break;
	case NFTNL_CMD_DELETE:
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

	iter_elems = nftnl_set_elems_iter_create(set);
	if (iter_elems == NULL)
		goto err;

	nlh = nftnl_set_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch), nl_type,
				      nftnl_set_attr_get_u32(set,
							   NFTNL_SET_ATTR_FAMILY),
				      nl_flags, seq++);

	nftnl_set_elems_nlmsg_build_payload_iter(nlh, iter_elems);
	mnl_nlmsg_batch_next(batch);

	nftnl_set_elems_iter_destroy(iter_elems);
	return 0;
err:
	return -1;
}

static int nftnl_ruleset_set(const struct nftnl_parse_ctx *ctx)
{

	struct nlmsghdr *nlh;
	uint16_t nl_type, nl_flags;
	struct nftnl_set *set;
	uint32_t cmd;
	int ret;

	cmd = nftnl_ruleset_ctx_get_u32(ctx, NFTNL_RULESET_CTX_CMD);

	set = nftnl_ruleset_ctx_get(ctx, NFTNL_RULESET_CTX_SET);
	if (set == NULL)
		return -1;

	switch (cmd) {
	case NFTNL_CMD_ADD:
		nl_type = NFT_MSG_NEWSET;
		nl_flags = NLM_F_CREATE|NLM_F_ACK;
		break;
	case NFTNL_CMD_DELETE:
		nl_type = NFT_MSG_DELSET;
		nl_flags = NLM_F_ACK;
		break;
	default:
		goto err;
	}

	nlh = nftnl_set_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
				      nl_type,
				      nftnl_set_attr_get_u32(set,
							   NFTNL_SET_ATTR_FAMILY),
				      nl_flags,
				      seq++);

	nftnl_set_nlmsg_build_payload(nlh, set);
	mnl_nlmsg_batch_next(batch);

	ret = nftnl_ruleset_set_elems(ctx);
	return ret;
err:
	return -1;
}

static int nftnl_ruleset_rule_build_msg(const struct nftnl_parse_ctx *ctx,
				      uint32_t cmd, struct nftnl_rule *rule)
{
	struct nlmsghdr *nlh;
	uint16_t nl_type, nl_flags;

	switch (cmd) {
	case NFTNL_CMD_ADD:
		nl_type = NFT_MSG_NEWRULE;
		nl_flags = NLM_F_APPEND|NLM_F_CREATE|NLM_F_ACK;
		nftnl_rule_attr_unset(rule, NFTNL_RULE_ATTR_HANDLE);
		break;
	case NFTNL_CMD_DELETE:
		nl_type = NFT_MSG_DELRULE;
		nl_flags = NLM_F_ACK;
		break;
	case NFTNL_CMD_REPLACE:
		nl_type = NFT_MSG_NEWRULE;
		nl_flags = NLM_F_REPLACE|NLM_F_ACK;
		break;
	case NFTNL_CMD_INSERT:
		nl_type = NFT_MSG_NEWRULE;
		nl_flags = NLM_F_CREATE|NLM_F_ACK;
		nftnl_rule_attr_unset(rule, NFTNL_RULE_ATTR_HANDLE);
		break;
	default:
		return -1;
	}

	nlh = nftnl_rule_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
				       nl_type,
				       nftnl_rule_attr_get_u32(rule,
							  NFTNL_RULE_ATTR_FAMILY),
				       nl_flags,
				       seq++);

	nftnl_rule_nlmsg_build_payload(nlh, rule);
	mnl_nlmsg_batch_next(batch);

	return 0;
}

static int nftnl_ruleset_rule(const struct nftnl_parse_ctx *ctx)
{
	struct nftnl_rule *rule;
	int ret;
	uint32_t cmd;

	cmd = nftnl_ruleset_ctx_get_u32(ctx, NFTNL_RULESET_CTX_CMD);

	rule = nftnl_ruleset_ctx_get(ctx, NFTNL_RULESET_CTX_RULE);
	if (rule == NULL)
		return -1;

	ret = nftnl_ruleset_rule_build_msg(ctx, cmd, rule);

	return ret;
}

static int nftnl_ruleset_flush_rules(const struct nftnl_parse_ctx *ctx)
{
	struct nftnl_rule *nlr;
	struct nftnl_table *nlt;
	struct nftnl_chain *nlc;
	uint32_t type;
	int ret;

	nlr = nftnl_rule_alloc();
	if (nlr == NULL)
		return -1;

	type = nftnl_ruleset_ctx_get_u32(ctx, NFTNL_RULESET_CTX_TYPE);
	switch (type) {
	case NFTNL_RULESET_TABLE:
		nlt = nftnl_ruleset_ctx_get(ctx, NFTNL_RULESET_CTX_TABLE);
		nftnl_rule_attr_set(nlr, NFTNL_RULE_ATTR_TABLE,
				  nftnl_table_attr_get(nlt, NFTNL_TABLE_ATTR_NAME));
		nftnl_rule_attr_set(nlr, NFTNL_RULE_ATTR_FAMILY,
				nftnl_table_attr_get(nlt, NFTNL_TABLE_ATTR_FAMILY));
		break;
	case NFTNL_RULESET_CHAIN:
		nlc = nftnl_ruleset_ctx_get(ctx, NFTNL_RULESET_CTX_CHAIN);
		nftnl_rule_attr_set(nlr, NFTNL_RULE_ATTR_TABLE,
				  nftnl_chain_attr_get(nlc,
						     NFTNL_CHAIN_ATTR_TABLE));
		nftnl_rule_attr_set(nlr, NFTNL_RULE_ATTR_CHAIN,
				  nftnl_chain_attr_get(nlc,
						     NFTNL_CHAIN_ATTR_NAME));
		nftnl_rule_attr_set(nlr, NFTNL_RULE_ATTR_FAMILY,
				nftnl_chain_attr_get(nlc, NFTNL_TABLE_ATTR_FAMILY));
		break;
	default:
		goto err;
	}

	ret = nftnl_ruleset_rule_build_msg(ctx, NFTNL_CMD_DELETE, nlr);
	nftnl_rule_free(nlr);

	return ret;
err:
	nftnl_rule_free(nlr);
	return -1;
}

static int nftnl_ruleset_chain(const struct nftnl_parse_ctx *ctx)
{
	struct nlmsghdr *nlh;
	uint16_t nl_type, nl_flags;
	uint32_t cmd;
	struct nftnl_chain *chain;

	cmd = nftnl_ruleset_ctx_get_u32(ctx, NFTNL_RULESET_CTX_CMD);

	chain = nftnl_ruleset_ctx_get(ctx, NFTNL_RULESET_CTX_CHAIN);
	if (chain == NULL)
		return -1;

	switch (cmd) {
	case NFTNL_CMD_ADD:
		nl_type = NFT_MSG_NEWCHAIN;
		nl_flags = NLM_F_CREATE|NLM_F_ACK;
		break;
	case NFTNL_CMD_DELETE:
		nl_type = NFT_MSG_DELCHAIN;
		nl_flags = NLM_F_ACK;
		break;
	case NFTNL_CMD_FLUSH:
		return nftnl_ruleset_flush_rules(ctx);
	default:
		goto err;
	}

	nftnl_chain_attr_unset(chain, NFTNL_CHAIN_ATTR_HANDLE);
	nlh = nftnl_chain_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
					nl_type,
					nftnl_chain_attr_get_u32(chain,
							 NFTNL_CHAIN_ATTR_FAMILY),
					nl_flags,
					seq++);

	nftnl_chain_nlmsg_build_payload(nlh, chain);
	mnl_nlmsg_batch_next(batch);

	return 0;
err:
	return -1;
}

static int nftnl_ruleset_table_build_msg(const struct nftnl_parse_ctx *ctx,
				       uint32_t cmd, struct nftnl_table *table)
{
	struct nlmsghdr *nlh;
	uint16_t nl_type, nl_flags;

	switch (cmd) {
	case NFTNL_CMD_ADD:
		nl_type = NFT_MSG_NEWTABLE;
		nl_flags = NLM_F_CREATE|NLM_F_ACK;
		break;
	case NFTNL_CMD_DELETE:
		nl_type = NFT_MSG_DELTABLE;
		nl_flags = NLM_F_ACK;
		break;
	case NFTNL_CMD_FLUSH:
		return nftnl_ruleset_flush_rules(ctx);
	default:
		return -1;
	}

	nlh = nftnl_table_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
					nl_type,
					nftnl_table_attr_get_u32(table,
							 NFTNL_TABLE_ATTR_FAMILY),
					nl_flags,
					seq++);

	nftnl_table_nlmsg_build_payload(nlh, table);
	mnl_nlmsg_batch_next(batch);

	return 0;
}

static int nftnl_ruleset_table(const struct nftnl_parse_ctx *ctx)
{
	struct nftnl_table *table;
	uint32_t cmd;
	int ret;

	cmd = nftnl_ruleset_ctx_get_u32(ctx, NFTNL_RULESET_CTX_CMD);

	table = nftnl_ruleset_ctx_get(ctx, NFTNL_RULESET_CTX_TABLE);
	if (table == NULL)
		return -1;

	ret = nftnl_ruleset_table_build_msg(ctx, cmd, table);

	return ret;
}

static int nftnl_ruleset_flush_ruleset(const struct nftnl_parse_ctx *ctx)
{
	struct nftnl_table *table;
	int ret;

	table = nftnl_table_alloc();
	if (table == NULL)
		return -1;

	ret = nftnl_ruleset_table_build_msg(ctx, NFTNL_CMD_DELETE, table);
	nftnl_table_free(table);

	return ret;
}

static int ruleset_elems_cb(const struct nftnl_parse_ctx *ctx)
{
	uint32_t type;
	int ret;

	type = nftnl_ruleset_ctx_get_u32(ctx, NFTNL_RULESET_CTX_TYPE);

	switch (type) {
	case NFTNL_RULESET_TABLE:
		ret = nftnl_ruleset_table(ctx);
		break;
	case NFTNL_RULESET_CHAIN:
		ret = nftnl_ruleset_chain(ctx);
		break;
	case NFTNL_RULESET_RULE:
		ret = nftnl_ruleset_rule(ctx);
		break;
	case NFTNL_RULESET_SET:
		ret = nftnl_ruleset_set(ctx);
		break;
	case NFTNL_RULESET_SET_ELEMS:
		ret = nftnl_ruleset_set_elems(ctx);
		break;
	case NFTNL_RULESET_RULESET:
		ret = nftnl_ruleset_flush_ruleset(ctx);
		break;
	default:
		return -1;
	}

	nftnl_ruleset_ctx_free(ctx);
	return ret;
}

int main(int argc, char *argv[])
{
	struct nftnl_parse_err *err;
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

	err = nftnl_parse_err_alloc();
	if (err == NULL) {
		perror("error");
		exit(EXIT_FAILURE);
	}

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
	ruleset_seq = seq;

	filename = argv[1];
	len = strlen(filename);
	if (len >= 5 && strcmp(&filename[len - 5], ".json") == 0)
		ret = nftnl_ruleset_parse_file_cb(NFTNL_PARSE_JSON, fp, err, NULL,
						&ruleset_elems_cb);
	else if (len >= 4 && strcmp(&filename[len - 4], ".xml") == 0)
		ret = nftnl_ruleset_parse_file_cb(NFTNL_PARSE_XML, fp, err, NULL,
						&ruleset_elems_cb);
	else {
		printf("the filename %s must to end in .xml or .json\n",
			filename);
		exit(EXIT_FAILURE);
	}

	if (ret < 0) {
		nftnl_parse_perror("fail", err);
		exit(EXIT_FAILURE);
	}

	fclose(fp);

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
