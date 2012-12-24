#ifndef _NFT_SET_H_
#define _NFT_SET_H_

enum {
	NFT_SET_ATTR_TABLE,
	NFT_SET_ATTR_NAME,
	NFT_SET_ATTR_FLAGS,
	NFT_SET_ATTR_KEY_TYPE,
	NFT_SET_ATTR_KEY_LEN,
	NFT_SET_ATTR_VERDICT,
	NFT_SET_ATTR_CHAIN,
};

struct nft_set;

struct nft_set *nft_set_alloc(void);
void nft_set_free(struct nft_set *s);

void nft_set_attr_set(struct nft_set *s, uint16_t attr, void *data);
void nft_set_attr_set_u32(struct nft_set *s, uint16_t attr, uint32_t val);
void nft_set_attr_set_str(struct nft_set *s, uint16_t attr, char *str);

void *nft_set_attr_get(struct nft_set *s, uint16_t attr);
const char *nft_set_attr_get_str(struct nft_set *s, uint16_t attr);
uint32_t nft_set_attr_get_u32(struct nft_set *s, uint16_t attr);

struct nlmsghdr *nft_set_nlmsg_build_hdr(char *buf, uint16_t cmd, uint16_t family, uint16_t type, uint32_t seq);
void nft_set_nlmsg_build_payload(struct nlmsghdr *nlh, struct nft_set *s);
int nft_set_nlmsg_parse(const struct nlmsghdr *nlh, struct nft_set *s);

int nft_set_snprintf(char *buf, size_t size, struct nft_set *s, uint32_t type, uint32_t flags);

struct nft_set_list;

struct nft_set_list *nft_set_list_alloc(void);
void nft_set_list_free(struct nft_set_list *list);
void nft_set_list_add(struct nft_set *s, struct nft_set_list *list);

struct nft_set_list_iter;
struct nft_set_list_iter *nft_set_list_iter_create(struct nft_set_list *l);
struct nft_set *nft_set_list_iter_cur(struct nft_set_list_iter *iter);
struct nft_set *nft_set_list_iter_next(struct nft_set_list_iter *iter);
void nft_set_list_iter_destroy(struct nft_set_list_iter *iter);

#endif
