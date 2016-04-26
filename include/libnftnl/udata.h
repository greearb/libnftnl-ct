#ifndef _LIBNFTNL_UDATA_H_
#define _LIBNFTNL_UDATA_H_

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

/*
 * nftnl user data attributes API
 */
struct nftnl_udata;
struct nftnl_udata_buf;

/* nftnl_udata_buf */
struct nftnl_udata_buf *nftnl_udata_buf_alloc(uint32_t data_size);
void nftnl_udata_buf_free(const struct nftnl_udata_buf *buf);
uint32_t nftnl_udata_buf_len(const struct nftnl_udata_buf *buf);
void *nftnl_udata_buf_data(const struct nftnl_udata_buf *buf);
void nftnl_udata_buf_put(struct nftnl_udata_buf *buf, const void *data,
			 uint32_t len);
struct nftnl_udata *nftnl_udata_start(const struct nftnl_udata_buf *buf);
struct nftnl_udata *nftnl_udata_end(const struct nftnl_udata_buf *buf);

/* putters */
bool nftnl_udata_put(struct nftnl_udata_buf *buf, uint8_t type, uint32_t len,
		     const void *value);
bool nftnl_udata_put_strz(struct nftnl_udata_buf *buf, uint8_t type,
			  const char *strz);

/* nftnl_udata_attr */
uint8_t nftnl_udata_type(const struct nftnl_udata *attr);
uint8_t nftnl_udata_len(const struct nftnl_udata *attr);
void *nftnl_udata_get(const struct nftnl_udata *attr);

/* iterator */
struct nftnl_udata *nftnl_udata_next(const struct nftnl_udata *attr);

#define nftnl_udata_for_each(buf, attr)                       \
	for ((attr) = nftnl_udata_start(buf);                 \
	     (char *)(nftnl_udata_end(buf)) > (char *)(attr); \
	     (attr) = nftnl_udata_next(attr))

#define nftnl_udata_for_each_data(data, data_len, attr)  \
	for ((attr) = (struct nftnl_udata *)(data);      \
	     (char *)(data + data_len) > (char *)(attr); \
	     (attr) = nftnl_udata_next(attr))

typedef int (*nftnl_udata_cb_t)(const struct nftnl_udata *attr, void *data);
int nftnl_udata_parse(const void *data, uint32_t data_len, nftnl_udata_cb_t cb,
		      void *cb_data);

#endif /* _LIBNFTNL_UDATA_H_ */
