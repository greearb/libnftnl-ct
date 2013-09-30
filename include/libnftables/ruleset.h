#ifndef _RULESET_H_
#define _RULESET_H_

#ifdef __cplusplus
extern "C" {
#endif

struct nft_ruleset;

struct nft_ruleset *nft_ruleset_alloc(void);
void nft_ruleset_free(struct nft_ruleset *r);

enum {
	NFT_RULESET_ATTR_TABLELIST = 0,
	NFT_RULESET_ATTR_CHAINLIST,
	NFT_RULESET_ATTR_SETLIST,
	NFT_RULESET_ATTR_RULELIST,
};

bool nft_ruleset_attr_is_set(const struct nft_ruleset *r, uint16_t attr);
void nft_ruleset_attr_unset(struct nft_ruleset *r, uint16_t attr);
void nft_ruleset_attr_set(struct nft_ruleset *r, uint16_t attr, void *data);
const void *nft_ruleset_attr_get(const struct nft_ruleset *r, uint16_t attr);

enum {
	NFT_RULESET_O_DEFAULT	= 0,
	NFT_RULESET_O_XML,
	NFT_RULESET_O_JSON,
};

enum nft_ruleset_parse_type {
	NFT_RULESET_PARSE_NONE	= 0,
	NFT_RULESET_PARSE_XML,
	NFT_RULESET_PARSE_JSON,
	NFT_RULESET_PARSE_MAX,
};

int nft_ruleset_parse(struct nft_ruleset *rs, enum nft_ruleset_parse_type type, const char *data);
int nft_ruleset_snprintf(char *buf, size_t size, const struct nft_ruleset *rs, uint32_t type, uint32_t flags);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* _RULESET_H_ */
