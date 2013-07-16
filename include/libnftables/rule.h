#ifndef _RULE_H_
#define _RULE_H_

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

struct nft_rule;
struct nft_rule_expr;

struct nft_rule *nft_rule_alloc(void);
void nft_rule_free(struct nft_rule *);

enum {
	NFT_RULE_ATTR_FAMILY	= 0,
	NFT_RULE_ATTR_TABLE,
	NFT_RULE_ATTR_CHAIN,
	NFT_RULE_ATTR_HANDLE,
	NFT_RULE_ATTR_FLAGS,
	NFT_RULE_ATTR_COMPAT_PROTO,
	NFT_RULE_ATTR_COMPAT_FLAGS,
};

void nft_rule_attr_unset(struct nft_rule *r, uint16_t attr);
bool nft_rule_attr_is_set(struct nft_rule *r, uint16_t attr);
void nft_rule_attr_set(struct nft_rule *r, uint16_t attr, const void *data);
void nft_rule_attr_set_u32(struct nft_rule *r, uint16_t attr, uint32_t val);
void nft_rule_attr_set_u64(struct nft_rule *r, uint16_t attr, uint64_t val);
void nft_rule_attr_set_str(struct nft_rule *r, uint16_t attr, const char *str);

const void *nft_rule_attr_get(const struct nft_rule *r, uint16_t attr);
const char *nft_rule_attr_get_str(const struct nft_rule *r, uint16_t attr);
uint8_t nft_rule_attr_get_u8(const struct nft_rule *r, uint16_t attr);
uint32_t nft_rule_attr_get_u32(const struct nft_rule *r, uint16_t attr);
uint64_t nft_rule_attr_get_u64(const struct nft_rule *r, uint16_t attr);

void nft_rule_add_expr(struct nft_rule *r, struct nft_rule_expr *expr);

void nft_rule_nlmsg_build_payload(struct nlmsghdr *nlh, struct nft_rule *t);

enum {
	NFT_RULE_O_DEFAULT	= 0,
	NFT_RULE_O_XML,
	NFT_RULE_O_JSON,
};

enum nft_rule_parse_type {
	NFT_RULE_PARSE_NONE	= 0,
	NFT_RULE_PARSE_XML,
	NFT_RULE_PARSE_MAX,
};

int nft_rule_parse(struct nft_rule *r, enum nft_rule_parse_type type, char *data);
int nft_rule_snprintf(char *buf, size_t size, struct nft_rule *t, uint32_t type, uint32_t flags);

struct nlmsghdr *nft_rule_nlmsg_build_hdr(char *buf, uint16_t cmd, uint16_t family, uint16_t type, uint32_t seq);
int nft_rule_nlmsg_parse(const struct nlmsghdr *nlh, struct nft_rule *t);

int nft_rule_expr_foreach(struct nft_rule *r,
			  int (*cb)(struct nft_rule_expr *e, void *data),
			  void *data);

struct nft_rule_expr_iter;

struct nft_rule_expr_iter *nft_rule_expr_iter_create(struct nft_rule *r);
struct nft_rule_expr *nft_rule_expr_iter_next(struct nft_rule_expr_iter *iter);
void nft_rule_expr_iter_destroy(struct nft_rule_expr_iter *iter);

struct nft_rule_list;

struct nft_rule_list *nft_rule_list_alloc(void);
void nft_rule_list_free(struct nft_rule_list *list);
int nft_rule_list_is_empty(struct nft_rule_list *list);
void nft_rule_list_add(struct nft_rule *r, struct nft_rule_list *list);
void nft_rule_list_add_tail(struct nft_rule *r, struct nft_rule_list *list);
int nft_rule_list_foreach(struct nft_rule_list *rule_list, int (*cb)(struct nft_rule *t, void *data), void *data);

struct nft_rule_list_iter;

struct nft_rule_list_iter *nft_rule_list_iter_create(struct nft_rule_list *l);
struct nft_rule *nft_rule_list_iter_cur(struct nft_rule_list_iter *iter);
struct nft_rule *nft_rule_list_iter_next(struct nft_rule_list_iter *iter);
void nft_rule_list_iter_destroy(struct nft_rule_list_iter *iter);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* _RULE_H_ */
