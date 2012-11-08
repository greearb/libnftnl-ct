#ifndef _TABLE_H_
#define _TABLE_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct nft_table;

struct nft_table *nft_table_alloc(void);
void nft_table_free(struct nft_table *);

enum {
	NFT_TABLE_ATTR_NAME	= 0,
	NFT_TABLE_ATTR_FAMILY,
	NFT_TABLE_ATTR_FLAGS,
};

void nft_table_attr_set(struct nft_table *t, uint16_t attr, void *data);
const void *nft_table_attr_get(struct nft_table *t, uint16_t attr);

void nft_table_attr_set_u32(struct nft_table *t, uint16_t attr, uint32_t data);
uint32_t nft_table_attr_get_u32(struct nft_table *t, uint16_t attr);

void nft_table_nlmsg_build_payload(struct nlmsghdr *nlh, const struct nft_table *t);

enum {
	NFT_TABLE_O_DEFAULT	= 0,
};

int nft_table_snprintf(char *buf, size_t size, struct nft_table *t, uint32_t type, uint32_t flags);

struct nlmsghdr *nft_table_nlmsg_build_hdr(char *buf, uint16_t cmd, uint16_t family, uint16_t type, uint32_t seq);
int nft_table_nlmsg_parse(const struct nlmsghdr *nlh, struct nft_table *t);

struct nft_table_list;

struct nft_table_list *nft_table_list_alloc(void);
void nft_table_list_free(struct nft_table_list *list);

void nft_table_list_add(struct nft_table *r, struct nft_table_list *list);

struct nft_table_list_iter;

struct nft_table_list_iter *nft_table_list_iter_create(struct nft_table_list *l);
struct nft_table *nft_table_list_iter_next(struct nft_table_list_iter *iter);
void nft_table_list_iter_destroy(struct nft_table_list_iter *iter);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* _TABLE_H_ */
