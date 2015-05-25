#ifndef _NFT_BUFFER_H_
#define _NFT_BUFFER_H_

#include <stdint.h>
#include <stdbool.h>

struct nft_buf {
	char		*buf;
	size_t		size;
	size_t		len;
	uint32_t	off;
	bool		fail;
};

#define NFT_BUF_INIT(__b, __buf, __len)			\
	struct nft_buf __b = {				\
		.buf	= __buf,			\
		.len	= __len,			\
	};

int nft_buf_update(struct nft_buf *b, int ret);
int nft_buf_done(struct nft_buf *b);

union nft_data_reg;

int nft_buf_open(struct nft_buf *b, int type, const char *tag);
int nft_buf_close(struct nft_buf *b, int type, const char *tag);

int nft_buf_open_array(struct nft_buf *b, int type, const char *tag);
int nft_buf_close_array(struct nft_buf *b, int type, const char *tag);

int nft_buf_u32(struct nft_buf *b, int type, uint32_t value, const char *tag);
int nft_buf_s32(struct nft_buf *b, int type, uint32_t value, const char *tag);
int nft_buf_u64(struct nft_buf *b, int type, uint64_t value, const char *tag);
int nft_buf_str(struct nft_buf *b, int type, const char *str, const char *tag);
int nft_buf_reg(struct nft_buf *b, int type, union nft_data_reg *reg,
		int reg_type, const char *tag);

#define BASE			"base"
#define BYTES			"bytes"
#define CHAIN			"chain"
#define CODE			"code"
#define DATA			"data"
#define DEVICE			"device"
#define DIR			"dir"
#define DREG			"dreg"
#define EXTHDR_TYPE		"exthdr_type"
#define FAMILY			"family"
#define FLAGS			"flags"
#define GROUP			"group"
#define HANDLE			"handle"
#define HOOKNUM			"hooknum"
#define KEY			"key"
#define LEN			"len"
#define LEVEL			"level"
#define MASK			"mask"
#define NAT_TYPE		"nat_type"
#define NAME			"name"
#define NUM			"num"
#define OFFSET			"offset"
#define OP			"op"
#define PACKETS			"packets"
#define PKTS			"pkts"
#define POLICY			"policy"
#define PREFIX			"prefix"
#define PRIO			"prio"
#define QTHRESH			"qthreshold"
#define RATE			"rate"
#define SET			"set"
#define SET_NAME		"set_name"
#define SIZE			"size"
#define SNAPLEN			"snaplen"
#define SREG_ADDR_MAX		"sreg_addr_max"
#define SREG_ADDR_MIN		"sreg_addr_min"
#define SREG_PROTO_MAX		"sreg_proto_max"
#define SREG_PROTO_MIN		"sreg_proto_min"
#define SREG_KEY		"sreg_key"
#define SREG_DATA		"sreg_data"
#define SREG			"sreg"
#define TABLE			"table"
#define TOTAL			"total"
#define TYPE			"type"
#define UNIT			"unit"
#define USE			"use"
#define XOR			"xor"
#define ADD			"add"
#define INSERT			"insert"
#define DELETE			"delete"
#define REPLACE			"replace"
#define FLUSH			"flush"

#endif
