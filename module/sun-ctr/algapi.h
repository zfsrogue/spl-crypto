/*
 * Cryptographic API for algorithms (i.e., low-level API).
 *
 * Copyright (c) 2006 Herbert Xu <herbert@gondor.apana.org.au>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 */
#ifndef _CRYPTO_XALGAPI_H
#define _CRYPTO_XALGAPI_H

#include <linux/crypto.h>
#include <linux/list.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <crypto/algapi.h>

struct module;
struct rtattr;
struct seq_file;


struct xblkcipher_walk {
	union {
		struct {
			struct page *page;
			unsigned long offset;
		} phys;

		struct {
			u8 *page;
			u8 *addr;
		} virt;
	} src, dst;

	struct scatter_walk in;
	unsigned int nbytes;

	struct scatter_walk out;
	unsigned int total;

	void *page;
	u8 *buffer;
	u8 *iv;

	int flags;
	unsigned int blocksize;
};


int xblkcipher_walk_done(struct blkcipher_desc *desc,
			struct xblkcipher_walk *walk, int err);
int xblkcipher_walk_virt(struct blkcipher_desc *desc,
			struct xblkcipher_walk *walk);
int xblkcipher_walk_phys(struct blkcipher_desc *desc,
			struct xblkcipher_walk *walk);
int xblkcipher_walk_virt_block(struct blkcipher_desc *desc,
			      struct xblkcipher_walk *walk,
			      unsigned int blocksize);

static inline void xblkcipher_walk_init(struct xblkcipher_walk *walk,
				       struct scatterlist *dst,
				       struct scatterlist *src,
				       unsigned int nbytes)
{
	walk->in.sg = src;
	walk->out.sg = dst;
	walk->total = nbytes;
}


#endif	/* _CRYPTO_ALGAPI_H */

