/*
 * (C) 2012-2013 by Pablo Neira Ayuso <pablo@netfilter.org>
 * (C) 2013 by Arturo Borrero Gonzalez <arturo.borrero.glez@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <internal.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <buffer.h>

#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>

static const char *const nft_family_str[NFPROTO_NUMPROTO] = {
	[NFPROTO_INET]		= "inet",
	[NFPROTO_IPV4]		= "ip",
	[NFPROTO_ARP]		= "arp",
	[NFPROTO_BRIDGE]	= "bridge",
	[NFPROTO_IPV6]		= "ip6",
};

const char *nft_family2str(uint32_t family)
{
	if (nft_family_str[family] == NULL)
		return "unknown";

	return nft_family_str[family];
}

int nft_str2family(const char *family)
{
	int i;

	for (i = 0; i < NFPROTO_NUMPROTO; i++) {
		if (nft_family_str[i] == NULL)
			continue;

		if (strcmp(nft_family_str[i], family) == 0)
			return i;
	}

	errno = EAFNOSUPPORT;
	return -1;
}

static struct {
	int len;
	int64_t min;
	uint64_t max;
} basetype[] = {
	[NFT_TYPE_U8]	= { .len = sizeof(uint8_t), .max = UINT8_MAX },
	[NFT_TYPE_U16]	= { .len = sizeof(uint16_t), .max = UINT16_MAX },
	[NFT_TYPE_U32]	= { .len = sizeof(uint32_t), .max = UINT32_MAX },
	[NFT_TYPE_U64]	= { .len = sizeof(uint64_t), .max = UINT64_MAX },
	[NFT_TYPE_S8]	= { .len = sizeof(int8_t), .min = INT8_MIN, .max = INT8_MAX },
	[NFT_TYPE_S16]	= { .len = sizeof(int16_t), .min = INT16_MIN, .max = INT16_MAX },
	[NFT_TYPE_S32]	= { .len = sizeof(int32_t), .min = INT32_MIN, .max = INT32_MAX },
	[NFT_TYPE_S64]	= { .len = sizeof(int64_t), .min = INT64_MIN, .max = INT64_MAX },
};


int nft_get_value(enum nft_type type, void *val, void *out)
{
	int64_t sval;
	uint64_t uval;

	switch (type) {
	case NFT_TYPE_U8:
	case NFT_TYPE_U16:
	case NFT_TYPE_U32:
	case NFT_TYPE_U64:
		uval = *((uint64_t *)val);
		if (uval > basetype[type].max) {
			errno = ERANGE;
			return -1;
		}
		memcpy(out, &uval, basetype[type].len);
		break;
	case NFT_TYPE_S8:
	case NFT_TYPE_S16:
	case NFT_TYPE_S32:
	case NFT_TYPE_S64:
		sval = *((int64_t *)val);
		if (sval < basetype[type].min ||
		    sval > (int64_t)basetype[type].max) {
			errno = ERANGE;
			return -1;
		}
		memcpy(out, &sval, basetype[type].len);
		break;
	}

	return 0;
}

int nft_strtoi(const char *string, int base, void *out, enum nft_type type)
{
	int ret;
	int64_t sval = 0;
	uint64_t uval = -1;
	char *endptr;

	switch (type) {
	case NFT_TYPE_U8:
	case NFT_TYPE_U16:
	case NFT_TYPE_U32:
	case NFT_TYPE_U64:
		uval = strtoll(string, &endptr, base);
		ret = nft_get_value(type, &uval, out);
		break;
	case NFT_TYPE_S8:
	case NFT_TYPE_S16:
	case NFT_TYPE_S32:
	case NFT_TYPE_S64:
		sval = strtoull(string, &endptr, base);
		ret = nft_get_value(type, &sval, out);
		break;
	default:
		errno = EINVAL;
		return -1;
	}

	if (*endptr) {
		errno = EINVAL;
		return -1;
	}

	return ret;
}

const char *nft_verdict2str(uint32_t verdict)
{
	switch (verdict) {
	case NF_ACCEPT:
		return "accept";
	case NF_DROP:
		return "drop";
	case NFT_RETURN:
		return "return";
	case NFT_JUMP:
		return "jump";
	case NFT_GOTO:
		return "goto";
	default:
		return "unknown";
	}
}

int nft_str2verdict(const char *verdict, int *verdict_num)
{
	if (strcmp(verdict, "accept") == 0) {
		*verdict_num = NF_ACCEPT;
		return 0;
	} else if (strcmp(verdict, "drop") == 0) {
		*verdict_num = NF_DROP;
		return 0;
	} else if (strcmp(verdict, "return") == 0) {
		*verdict_num = NFT_RETURN;
		return 0;
	} else if (strcmp(verdict, "jump") == 0) {
		*verdict_num = NFT_JUMP;
		return 0;
	} else if (strcmp(verdict, "goto") == 0) {
		*verdict_num = NFT_GOTO;
		return 0;
	}

	return -1;
}

enum nft_cmd_type nft_flag2cmd(uint32_t flags)
{
	if (flags & NFT_OF_EVENT_NEW)
		return NFT_CMD_ADD;
	else if (flags & NFT_OF_EVENT_DEL)
		return NFT_CMD_DELETE;

	return NFT_CMD_UNSPEC;
}

const char *cmd2tag[NFT_CMD_MAX] = {
	[NFT_CMD_ADD]			= ADD,
	[NFT_CMD_INSERT]		= INSERT,
	[NFT_CMD_DELETE]		= DELETE,
	[NFT_CMD_REPLACE]		= REPLACE,
	[NFT_CMD_FLUSH]			= FLUSH,
};

const char *nft_cmd2tag(enum nft_cmd_type cmd)
{
	if (cmd >= NFT_CMD_MAX)
		return "unknown";

	return cmd2tag[cmd];
}

uint32_t nft_str2cmd(const char *cmd)
{
	if (strcmp(cmd, ADD) == 0)
		return NFT_CMD_ADD;
	else if (strcmp(cmd, INSERT) == 0)
		return NFT_CMD_INSERT;
	else if (strcmp(cmd, DELETE) == 0)
		return NFT_CMD_DELETE;
	else if (strcmp(cmd, REPLACE) == 0)
		return NFT_CMD_REPLACE;
	else if (strcmp(cmd, FLUSH) == 0)
		return NFT_CMD_FLUSH;

	return NFT_CMD_UNSPEC;
}

int nft_fprintf(FILE *fp, void *obj, uint32_t cmd, uint32_t type, uint32_t flags,
		int (*snprintf_cb)(char *buf, size_t bufsiz, void *obj,
				   uint32_t cmd, uint32_t type, uint32_t flags))
{
	char _buf[NFT_SNPRINTF_BUFSIZ];
	char *buf = _buf;
	size_t bufsiz = sizeof(_buf);
	int ret;

	ret = snprintf_cb(buf, bufsiz, obj, cmd, type, flags);
	if (ret <= 0)
		goto out;

	if (ret >= NFT_SNPRINTF_BUFSIZ) {
		bufsiz = ret + 1;

		buf = malloc(bufsiz);
		if (buf == NULL)
			return -1;

		ret = snprintf_cb(buf, bufsiz, obj, cmd, type, flags);
		if (ret <= 0)
			goto out;
	}

	ret = fprintf(fp, "%s", buf);

out:
	if (buf != _buf)
		xfree(buf);

	return ret;
}

void __nft_assert_fail(uint16_t attr, const char *filename, int line)
{
	fprintf(stderr, "libnftnl: attribute %d assertion failed in %s:%d\n",
		attr, filename, line);
	exit(EXIT_FAILURE);
}

void __noreturn __abi_breakage(const char *file, int line, const char *reason)
{
       fprintf(stderr, "nf_tables kernel ABI is broken, contact your vendor.\n"
		       "%s:%d reason: %s\n", file, line, reason);
       exit(EXIT_FAILURE);
}
