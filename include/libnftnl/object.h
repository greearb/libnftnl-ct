#ifndef _LIBNFTNL_OBJECT_H_
#define _LIBNFTNL_OBJECT_H_

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>

#include <libnftnl/common.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
	NFTNL_OBJ_TABLE		= 0,
	NFTNL_OBJ_NAME,
	NFTNL_OBJ_TYPE,
	NFTNL_OBJ_FAMILY,
	NFTNL_OBJ_USE,
	NFTNL_OBJ_BASE		= 16,
	__NFTNL_OBJ_MAX
};
#define NFTNL_OBJ_MAX (__NFTNL_OBJ_MAX - 1)

enum {
	NFTNL_OBJ_CTR_PKTS	= NFTNL_OBJ_BASE,
	NFTNL_OBJ_CTR_BYTES,
};

enum {
	NFTNL_OBJ_QUOTA_BYTES	= NFTNL_OBJ_BASE,
	NFTNL_OBJ_QUOTA_CONSUMED,
	NFTNL_OBJ_QUOTA_FLAGS,
};

struct nftnl_obj;

struct nftnl_obj *nftnl_obj_alloc(void);
void nftnl_obj_free(const struct nftnl_obj *ne);

bool nftnl_obj_is_set(const struct nftnl_obj *ne, uint16_t attr);
void nftnl_obj_unset(struct nftnl_obj *ne, uint16_t attr);
void nftnl_obj_set_data(struct nftnl_obj *ne, uint16_t attr, const void *data,
			uint32_t data_len);
void nftnl_obj_set(struct nftnl_obj *ne, uint16_t attr, const void *data);
void nftnl_obj_set_u32(struct nftnl_obj *ne, uint16_t attr, uint32_t val);
void nftnl_obj_set_u64(struct nftnl_obj *obj, uint16_t attr, uint64_t val);
void nftnl_obj_set_str(struct nftnl_obj *ne, uint16_t attr, const char *str);
const void *nftnl_obj_get_data(struct nftnl_obj *ne, uint16_t attr,
			       uint32_t *data_len);
const void *nftnl_obj_get(struct nftnl_obj *ne, uint16_t attr);
uint32_t nftnl_obj_get_u32(struct nftnl_obj *ne, uint16_t attr);
uint64_t nftnl_obj_get_u64(struct nftnl_obj *obj, uint16_t attr);
const char *nftnl_obj_get_str(struct nftnl_obj *ne, uint16_t attr);

void nftnl_obj_nlmsg_build_payload(struct nlmsghdr *nlh,
				   const struct nftnl_obj *ne);
int nftnl_obj_nlmsg_parse(const struct nlmsghdr *nlh, struct nftnl_obj *ne);
int nftnl_obj_parse(struct nftnl_obj *ne, enum nftnl_parse_type type,
		    const char *data, struct nftnl_parse_err *err);
int nftnl_obj_parse_file(struct nftnl_obj *ne, enum nftnl_parse_type type,
			 FILE *fp, struct nftnl_parse_err *err);
int nftnl_obj_snprintf(char *buf, size_t size, const struct nftnl_obj *ne,
		       uint32_t type, uint32_t flags);
int nftnl_obj_fprintf(FILE *fp, const struct nftnl_obj *ne, uint32_t type,
		      uint32_t flags);

struct nftnl_obj_list;
struct nftnl_obj_list *nftnl_obj_list_alloc(void);
void nftnl_obj_list_free(struct nftnl_obj_list *list);
int nftnl_obj_list_is_empty(struct nftnl_obj_list *list);
void nftnl_obj_list_add(struct nftnl_obj *r, struct nftnl_obj_list *list);
void nftnl_obj_list_add_tail(struct nftnl_obj *r, struct nftnl_obj_list *list);
void nftnl_obj_list_del(struct nftnl_obj *t);
int nftnl_obj_list_foreach(struct nftnl_obj_list *table_list,
			   int (*cb)(struct nftnl_obj *t, void *data),
			   void *data);

struct nftnl_obj_list_iter;
struct nftnl_obj_list_iter *nftnl_obj_list_iter_create(struct nftnl_obj_list *l);
struct nftnl_obj *nftnl_obj_list_iter_next(struct nftnl_obj_list_iter *iter);
void nftnl_obj_list_iter_destroy(struct nftnl_obj_list_iter *iter);

#ifdef __cplusplusg
} /* extern "C" */
#endif

#endif /* _OBJ_H_ */
