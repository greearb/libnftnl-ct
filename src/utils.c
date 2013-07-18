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

	return -1;
}
