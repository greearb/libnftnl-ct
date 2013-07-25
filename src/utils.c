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

#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>

const char *nft_family2str(uint32_t family)
{
	switch (family) {
	case AF_INET:
		return "ip";
	case AF_INET6:
		return "ip6";
	case AF_BRIDGE:
		return "bridge";
	case 3: /* NFPROTO_ARP */
		return "arp";
	default:
		return "unknown";
	}
}

int nft_str2family(const char *family)
{
	if (strcmp(family, "ip") == 0)
		return AF_INET;
	else if (strcmp(family, "ip6") == 0)
		return AF_INET6;
	else if (strcmp(family, "bridge") == 0)
		return AF_BRIDGE;
	else if (strcmp(family, "arp") == 0)
		return 0;

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
	int64_t sval = 0;
	uint64_t uval = -1;
	char *endptr;

	switch (type) {
	case NFT_TYPE_U8:
	case NFT_TYPE_U16:
	case NFT_TYPE_U32:
	case NFT_TYPE_U64:
		uval = strtoll(string, &endptr, base);
		nft_get_value(type, &uval, out);
		break;
	case NFT_TYPE_S8:
	case NFT_TYPE_S16:
	case NFT_TYPE_S32:
	case NFT_TYPE_S64:
		sval = strtoull(string, &endptr, base);
		nft_get_value(type, &sval, out);
		break;
	default:
		errno = EINVAL;
		return -1;
	}

	if (*endptr) {
		errno = EINVAL;
		return -1;
	}

	return 0;
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

int nft_str2verdict(const char *verdict)
{
	if (strcmp(verdict, "accept") == 0)
		return NF_ACCEPT;
	else if (strcmp(verdict, "drop") == 0)
		return NF_DROP;
	else if (strcmp(verdict, "return") == 0)
		return NFT_RETURN;
	else if (strcmp(verdict, "jump") == 0)
		return NFT_JUMP;
	else if (strcmp(verdict, "goto") == 0)
		return NFT_GOTO;

	return -1;
}
