/*
 * Copyright (c) 2013 Arturo Borrero Gonzalez <arturo.borrero.glez@gmail.com>
 *
 * based on previous code from:
 *
 * Copyright (c) 2013 Pablo Neira Ayuso <pablo@netfilter.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <netinet/in.h>
#include <errno.h>

#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>

#include <libmnl/libmnl.h>
#include <libnftables/common.h>
#include <libnftables/ruleset.h>
#include <libnftables/table.h>
#include <libnftables/chain.h>
#include <libnftables/set.h>
#include <libnftables/rule.h>

static int seq;

static void memory_allocation_error(void)
{
	perror("OOM");
	exit(EXIT_FAILURE);
}

static int
mnl_talk(struct mnl_socket *nf_sock, const void *data, unsigned int len,
	 int (*cb)(const struct nlmsghdr *nlh, void *data), void *cb_data)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	uint32_t portid = mnl_socket_get_portid(nf_sock);
	int ret;

	if (mnl_socket_sendto(nf_sock, data, len) < 0)
		return -1;

	ret = mnl_socket_recvfrom(nf_sock, buf, sizeof(buf));
	while (ret > 0) {
		ret = mnl_cb_run(buf, ret, seq, portid, cb, cb_data);
		if (ret <= 0)
			goto out;

		ret = mnl_socket_recvfrom(nf_sock, buf, sizeof(buf));
	}
out:
	if (ret < 0 && errno == EAGAIN)
		return 0;

	return ret;
}

/*
 * Rule
 */
static int rule_cb(const struct nlmsghdr *nlh, void *data)
{
	struct nft_rule_list *nlr_list = data;
	struct nft_rule *r;

	r = nft_rule_alloc();
	if (r == NULL)
		memory_allocation_error();

	if (nft_rule_nlmsg_parse(nlh, r) < 0)
		goto err_free;

	nft_rule_list_add_tail(r, nlr_list);
	return MNL_CB_OK;

err_free:
	nft_rule_free(r);
	return MNL_CB_OK;
}

static struct nft_rule_list *mnl_rule_dump(struct mnl_socket *nf_sock,
					   int family)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	struct nft_rule_list *nlr_list;
	int ret;

	nlr_list = nft_rule_list_alloc();
	if (nlr_list == NULL)
		memory_allocation_error();

	nlh = nft_rule_nlmsg_build_hdr(buf, NFT_MSG_GETRULE, family,
				       NLM_F_DUMP, seq);

	ret = mnl_talk(nf_sock, nlh, nlh->nlmsg_len, rule_cb, nlr_list);
	if (ret < 0)
		goto err;

	return nlr_list;
err:
	nft_rule_list_free(nlr_list);
	return NULL;
}

/*
 * Chain
 */
static int chain_cb(const struct nlmsghdr *nlh, void *data)
{
	struct nft_chain_list *nlc_list = data;
	struct nft_chain *c;

	c = nft_chain_alloc();
	if (c == NULL)
		memory_allocation_error();

	if (nft_chain_nlmsg_parse(nlh, c) < 0)
		goto err_free;

	nft_chain_list_add_tail(c, nlc_list);
	return MNL_CB_OK;

err_free:
	nft_chain_free(c);
	return MNL_CB_OK;
}

static struct nft_chain_list *mnl_chain_dump(struct mnl_socket *nf_sock,
					     int family)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	struct nft_chain_list *nlc_list;
	int ret;

	nlc_list = nft_chain_list_alloc();
	if (nlc_list == NULL)
		memory_allocation_error();

	nlh = nft_chain_nlmsg_build_hdr(buf, NFT_MSG_GETCHAIN, family,
					NLM_F_DUMP, seq);

	ret = mnl_talk(nf_sock, nlh, nlh->nlmsg_len, chain_cb, nlc_list);
	if (ret < 0)
		goto err;

	return nlc_list;
err:
	nft_chain_list_free(nlc_list);
	return NULL;
}

/*
 * Table
 */
static int table_cb(const struct nlmsghdr *nlh, void *data)
{
	struct nft_table_list *nlt_list = data;
	struct nft_table *t;

	t = nft_table_alloc();
	if (t == NULL)
		memory_allocation_error();

	if (nft_table_nlmsg_parse(nlh, t) < 0)
		goto err_free;

	nft_table_list_add_tail(t, nlt_list);
	return MNL_CB_OK;

err_free:
	nft_table_free(t);
	return MNL_CB_OK;
}

static struct nft_table_list *mnl_table_dump(struct mnl_socket *nf_sock,
					     int family)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	struct nft_table_list *nlt_list;
	int ret;

	nlt_list = nft_table_list_alloc();
	if (nlt_list == NULL)
		memory_allocation_error();

	nlh = nft_table_nlmsg_build_hdr(buf, NFT_MSG_GETTABLE, family,
					NLM_F_DUMP, seq);

	ret = mnl_talk(nf_sock, nlh, nlh->nlmsg_len, table_cb, nlt_list);
	if (ret < 0)
		goto err;

	return nlt_list;
err:
	nft_table_list_free(nlt_list);
	return NULL;
}

/*
 * Set elements
 */
static int set_elem_cb(const struct nlmsghdr *nlh, void *data)
{
	nft_set_elems_nlmsg_parse(nlh, data);
	return MNL_CB_OK;
}

static int mnl_setelem_get(struct mnl_socket *nf_sock, struct nft_set *nls)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	uint32_t family = nft_set_attr_get_u32(nls, NFT_SET_ATTR_FAMILY);

	nlh = nft_set_nlmsg_build_hdr(buf, NFT_MSG_GETSETELEM, family,
				      NLM_F_DUMP|NLM_F_ACK, seq);
	nft_set_nlmsg_build_payload(nlh, nls);

	return mnl_talk(nf_sock, nlh, nlh->nlmsg_len, set_elem_cb, nls);
}

/*
 * Set
 */
static int set_cb(const struct nlmsghdr *nlh, void *data)
{
	struct nft_set_list *nls_list = data;
	struct nft_set *s;

	s = nft_set_alloc();
	if (s == NULL)
		memory_allocation_error();

	if (nft_set_nlmsg_parse(nlh, s) < 0)
		goto err_free;

	nft_set_list_add_tail(s, nls_list);
	return MNL_CB_OK;

err_free:
	nft_set_free(s);
	return MNL_CB_OK;
}

static struct nft_set_list *
mnl_set_dump(struct mnl_socket *nf_sock, int family)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	struct nft_set *s;
	struct nft_set_list *nls_list;
	struct nft_set *si;
	struct nft_set_list_iter *i;
	int ret;

	s = nft_set_alloc();
	if (s == NULL)
		memory_allocation_error();

	nlh = nft_set_nlmsg_build_hdr(buf, NFT_MSG_GETSET, family,
				      NLM_F_DUMP|NLM_F_ACK, seq);
	nft_set_nlmsg_build_payload(nlh, s);
	nft_set_free(s);

	nls_list = nft_set_list_alloc();
	if (nls_list == NULL)
		memory_allocation_error();

	ret = mnl_talk(nf_sock, nlh, nlh->nlmsg_len, set_cb, nls_list);
	if (ret < 0)
		goto err;

	i = nft_set_list_iter_create(nls_list);
	if (i == NULL)
		memory_allocation_error();

	si = nft_set_list_iter_next(i);
	while (si != NULL) {
		if (mnl_setelem_get(nf_sock, si) != 0) {
			perror("E: Unable to get set elements");
			nft_set_list_iter_destroy(i);
			goto err;
		}
		si = nft_set_list_iter_next(i);
	}

	nft_set_list_iter_destroy(i);

	return nls_list;
err:
	nft_set_list_free(nls_list);
	return NULL;
}

/*
 * ruleset
 */

static struct nft_ruleset *mnl_ruleset_dump(struct mnl_socket *nf_sock)
{
	struct nft_ruleset *rs;
	struct nft_table_list *t;
	struct nft_chain_list *c;
	struct nft_set_list *s;
	struct nft_rule_list *r;

	rs = nft_ruleset_alloc();
	if (rs == NULL)
		memory_allocation_error();

	t = mnl_table_dump(nf_sock, NFPROTO_UNSPEC);
	if (t != NULL)
		nft_ruleset_attr_set(rs, NFT_RULESET_ATTR_TABLELIST, t);

	c = mnl_chain_dump(nf_sock, NFPROTO_UNSPEC);
	if (c != NULL)
		nft_ruleset_attr_set(rs, NFT_RULESET_ATTR_CHAINLIST, c);

	s = mnl_set_dump(nf_sock, NFPROTO_UNSPEC);
	if (s != NULL)
		nft_ruleset_attr_set(rs, NFT_RULESET_ATTR_SETLIST, s);

	r = mnl_rule_dump(nf_sock, NFPROTO_UNSPEC);
	if (r != NULL)
		nft_ruleset_attr_set(rs, NFT_RULESET_ATTR_RULELIST, r);

	return rs;
}

int main(int argc, char *argv[])
{
	struct mnl_socket *nl;
	uint32_t type = NFT_OUTPUT_DEFAULT;
	struct nft_ruleset *rs;
	int ret;

	if (argc > 2) {
		fprintf(stderr, "%s {xml|json}\n",
			argv[0]);
		exit(EXIT_FAILURE);
	}

	if (argc == 2) {
		if (strcmp(argv[1], "xml") == 0)
			type = NFT_OUTPUT_XML;
		else if (strcmp(argv[1], "json") == 0)
			type = NFT_OUTPUT_JSON;
		else {
			fprintf(stderr, "Unknown type: {xml|json}\n");
			exit(EXIT_FAILURE);
		}
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

	seq = time(NULL);

	rs = mnl_ruleset_dump(nl);
	if (rs == NULL) {
		perror("ruleset_dump");
		exit(EXIT_FAILURE);
	}

	ret = nft_ruleset_fprintf(stdout, rs, type, 0);
	fprintf(stdout, "\n");

	if (ret == -1)
		perror("E: Error during fprintf operations");

	return 0;
}
