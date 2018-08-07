#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include <errno.h>
#include <linux/netfilter/nf_tables.h>

#include "internal.h"
#include <libmnl/libmnl.h>
#include <libnftnl/expr.h>
#include <libnftnl/rule.h>

#define OSF_GENRE_SIZE	32

struct nftnl_expr_osf {
	enum nft_registers	dreg;
};

static int nftnl_expr_osf_set(struct nftnl_expr *e, uint16_t type,
			      const void *data, uint32_t data_len)
{
	struct nftnl_expr_osf *osf = nftnl_expr_data(e);

	switch(type) {
	case NFTNL_EXPR_OSF_DREG:
		osf->dreg = *((uint32_t *)data);
		break;
	}
	return 0;
}

static const void *
nftnl_expr_osf_get(const struct nftnl_expr *e, uint16_t type,
		   uint32_t *data_len)
{
	struct nftnl_expr_osf *osf = nftnl_expr_data(e);

	switch(type) {
	case NFTNL_EXPR_OSF_DREG:
		*data_len = sizeof(osf->dreg);
		return &osf->dreg;
	}
	return NULL;
}

static int nftnl_expr_osf_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, NFTA_OSF_MAX) < 0)
		return MNL_CB_OK;

	switch(type) {
	case NFTNL_EXPR_OSF_DREG:
		if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0)
			abi_breakage();
		break;
	}

	tb[type] = attr;
	return MNL_CB_OK;
}

static void
nftnl_expr_osf_build(struct nlmsghdr *nlh, const struct nftnl_expr *e)
{
	struct nftnl_expr_osf *osf = nftnl_expr_data(e);

	if (e->flags & (1 << NFTNL_EXPR_OSF_DREG))
		mnl_attr_put_u32(nlh, NFTNL_EXPR_OSF_DREG, htonl(osf->dreg));
}

static int
nftnl_expr_osf_parse(struct nftnl_expr *e, struct nlattr *attr)
{
	struct nftnl_expr_osf *osf = nftnl_expr_data(e);
	struct nlattr *tb[NFTA_OSF_MAX + 1] = {};

	if (mnl_attr_parse_nested(attr, nftnl_expr_osf_cb, tb) < 0)
		return -1;

	if (tb[NFTA_OSF_DREG]) {
		osf->dreg = ntohl(mnl_attr_get_u32(tb[NFTA_OSF_DREG]));
		e->flags |= (1 << NFTNL_EXPR_OSF_DREG);
	}

	return 0;
}

static int nftnl_expr_osf_snprintf_default(char *buf, size_t size,
					   const struct nftnl_expr *e)
{
	struct nftnl_expr_osf *osf = nftnl_expr_data(e);
	int ret, offset = 0, len = size;

	if (e->flags & (1 << NFTNL_EXPR_OSF_DREG)) {
		ret = snprintf(buf, len, "dreg %u ", osf->dreg);
		SNPRINTF_BUFFER_SIZE(ret, len, offset);
	}

	return offset;
}

static int nftnl_expr_osf_export(char *buf, size_t size,
				 const struct nftnl_expr *e, int type)
{
	struct nftnl_expr_osf *osf = nftnl_expr_data(e);
	NFTNL_BUF_INIT(b, buf, size);

	if (e->flags & (1 << NFTNL_EXPR_OSF_DREG))
		nftnl_buf_u32(&b, type, osf->dreg, "dreg");

	return nftnl_buf_done(&b);
}

static int
nftnl_expr_osf_snprintf(char *buf, size_t len, uint32_t type,
			uint32_t flags, const struct nftnl_expr *e)
{
	switch(type) {
	case NFTNL_OUTPUT_DEFAULT:
		return nftnl_expr_osf_snprintf_default(buf, len, e);
	case NFTNL_OUTPUT_XML:
	case NFTNL_OUTPUT_JSON:
		return nftnl_expr_osf_export(buf, len, e, type);
	default:
		break;
	}
	return -1;
}

static bool nftnl_expr_osf_cmp(const struct nftnl_expr *e1,
			       const struct nftnl_expr *e2)
{
	struct nftnl_expr_osf *l1 = nftnl_expr_data(e1);
	struct nftnl_expr_osf *l2 = nftnl_expr_data(e2);
	bool eq = true;

	if (e1->flags & (1 << NFTNL_EXPR_OSF_DREG))
		eq &= (l1->dreg == l2->dreg);

	return eq;
}

struct expr_ops expr_ops_osf = {
	.name		= "osf",
	.alloc_len	= sizeof(struct nftnl_expr_osf),
	.max_attr	= NFTA_OSF_MAX,
	.cmp		= nftnl_expr_osf_cmp,
	.set		= nftnl_expr_osf_set,
	.get		= nftnl_expr_osf_get,
	.parse		= nftnl_expr_osf_parse,
	.build		= nftnl_expr_osf_build,
	.snprintf	= nftnl_expr_osf_snprintf,
};
