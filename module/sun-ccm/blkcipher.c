/*
 * Block chaining cipher operations.
 *
 * Generic encrypt/decrypt wrapper for ciphers, handles operations across
 * multiple page boundaries by using temporary blocks.  In user context,
 * the kernel is given a chance to schedule us once per page.
 *
 * Copyright (c) 2006 Herbert Xu <herbert@gondor.apana.org.au>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 */

#include <crypto/internal/skcipher.h>
#include <crypto/scatterwalk.h>
#include <linux/errno.h>
#include <linux/hardirq.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/scatterlist.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/cryptouser.h>
#include <net/netlink.h>

#include "algapi.h"

//#include "internal.h"
struct crypto_alg *crypto_alg_mod_lookup(const char *name, u32 type, u32 mask);

enum {
	BLKCIPHER_WALK_PHYS = 1 << 0,
	BLKCIPHER_WALK_SLOW = 1 << 1,
	BLKCIPHER_WALK_COPY = 1 << 2,
	BLKCIPHER_WALK_DIFF = 1 << 3,
};

static int xblkcipher_walk_next(struct blkcipher_desc *desc,
			       struct xblkcipher_walk *walk);
static int xblkcipher_walk_first(struct blkcipher_desc *desc,
				struct xblkcipher_walk *walk);

static inline void xblkcipher_map_src(struct xblkcipher_walk *walk)
{
	walk->src.virt.addr = scatterwalk_map(&walk->in);
}

static inline void xblkcipher_map_dst(struct xblkcipher_walk *walk)
{
	walk->dst.virt.addr = scatterwalk_map(&walk->out);
}

static inline void xblkcipher_unmap_src(struct xblkcipher_walk *walk)
{
	scatterwalk_unmap(walk->src.virt.addr);
}

static inline void xblkcipher_unmap_dst(struct xblkcipher_walk *walk)
{
	scatterwalk_unmap(walk->dst.virt.addr);
}

/* Get a spot of the specified length that does not straddle a page.
 * The caller needs to ensure that there is enough space for this operation.
 */
static inline u8 *xblkcipher_get_spot(u8 *start, unsigned int len)
{
	u8 *end_page = (u8 *)(((unsigned long)(start + len - 1)) & PAGE_MASK);
	return max(start, end_page);
}


static void Xscatterwalk_pagedone(struct scatter_walk *walk, int out,
                                 unsigned int more)
{

    if (out) {
        struct page *page;

        page = sg_page(walk->sg) + ((walk->offset - 1) >> PAGE_SHIFT);

#if 0
        /*
         * This call causes panic, so all these sources are just to
         * avoid this call.
         *
         * Once this issue has been fixed, we can remove the entire
         * "sun-ccm(aes)" module.
         *
         */
        if (!PageSlab(page))
            flush_dcache_page(page);
#endif
    }

    if (more) {
        walk->offset += PAGE_SIZE - 1;
        walk->offset &= PAGE_MASK;
        if (walk->offset >= walk->sg->offset + walk->sg->length)
            scatterwalk_start(walk, scatterwalk_sg_next(walk->sg));
    }

}

void Xscatterwalk_done(struct scatter_walk *walk, int out, int more)
{
    if (!(scatterwalk_pagelen(walk) & (PAGE_SIZE - 1)) || !more)
        Xscatterwalk_pagedone(walk, out, more);
}

static inline void memcpy_dir(void *buf, void *sgdata, size_t nbytes, int out)
{
    void *src = out ? buf : sgdata;
    void *dst = out ? sgdata : buf;

    memcpy(dst, src, nbytes);
}



void Xscatterwalk_copychunks(void *buf, struct scatter_walk *walk,
                            size_t nbytes, int out)
{
    for (;;) {
        unsigned int len_this_page = scatterwalk_pagelen(walk);
        u8 *vaddr;

        if (len_this_page > nbytes)
            len_this_page = nbytes;

        vaddr = scatterwalk_map(walk);
        memcpy_dir(buf, vaddr, len_this_page, out);
        scatterwalk_unmap(vaddr);

        scatterwalk_advance(walk, len_this_page);

        if (nbytes == len_this_page)
            break;

        buf += len_this_page;
        nbytes -= len_this_page;

        Xscatterwalk_pagedone(walk, out, 1);
    }
}

static inline unsigned int xblkcipher_done_slow(struct crypto_blkcipher *tfm,
					       struct xblkcipher_walk *walk,
					       unsigned int bsize)
{
	u8 *addr;
	unsigned int alignmask = crypto_blkcipher_alignmask(tfm);

	addr = (u8 *)ALIGN((unsigned long)walk->buffer, alignmask + 1);
	addr = xblkcipher_get_spot(addr, bsize);
	Xscatterwalk_copychunks(addr, &walk->out, bsize, 1);
	return bsize;
}

static inline unsigned int xblkcipher_done_fast(struct xblkcipher_walk *walk,
					       unsigned int n)
{
	if (walk->flags & BLKCIPHER_WALK_COPY) {
		xblkcipher_map_dst(walk);
		memcpy(walk->dst.virt.addr, walk->page, n);
		xblkcipher_unmap_dst(walk);
	} else if (!(walk->flags & BLKCIPHER_WALK_PHYS)) {
		if (walk->flags & BLKCIPHER_WALK_DIFF)
			xblkcipher_unmap_dst(walk);
		xblkcipher_unmap_src(walk);
	}

	scatterwalk_advance(&walk->in, n);
	scatterwalk_advance(&walk->out, n);

	return n;
}






int xblkcipher_walk_done(struct blkcipher_desc *desc,
			struct xblkcipher_walk *walk, int err)
{
	struct crypto_blkcipher *tfm = desc->tfm;
	unsigned int nbytes = 0;

	if (likely(err >= 0)) {
		unsigned int n = walk->nbytes - err;

		if (likely(!(walk->flags & BLKCIPHER_WALK_SLOW)))
			n = xblkcipher_done_fast(walk, n);
		else if (WARN_ON(err)) {
			err = -EINVAL;
			goto err;
		} else

			n = xblkcipher_done_slow(tfm, walk, n);

		nbytes = walk->total - n;
		err = 0;
	}

	scatterwalk_done(&walk->in, 0, nbytes);
    /* Avoid the call to PageSlab() */
	Xscatterwalk_done(&walk->out, 1, nbytes);

err:
	walk->total = nbytes;
	walk->nbytes = nbytes;

	if (nbytes) {
		crypto_yield(desc->flags);
		return xblkcipher_walk_next(desc, walk);
	}

	if (walk->iv != desc->info)
		memcpy(desc->info, walk->iv, crypto_blkcipher_ivsize(tfm));
	if (walk->buffer != walk->page)
		kfree(walk->buffer);
	if (walk->page)
		free_page((unsigned long)walk->page);

	return err;
}
EXPORT_SYMBOL_GPL(xblkcipher_walk_done);

static inline int xblkcipher_next_slow(struct blkcipher_desc *desc,
				      struct xblkcipher_walk *walk,
				      unsigned int bsize,
				      unsigned int alignmask)
{
	unsigned int n;
	unsigned aligned_bsize = ALIGN(bsize, alignmask + 1);

	if (walk->buffer)
		goto ok;

	walk->buffer = walk->page;
	if (walk->buffer)
		goto ok;

	n = aligned_bsize * 3 - (alignmask + 1) +
	    (alignmask & ~(crypto_tfm_ctx_alignment() - 1));
	walk->buffer = kmalloc(n, GFP_ATOMIC);
	if (!walk->buffer)
		return xblkcipher_walk_done(desc, walk, -ENOMEM);

ok:
	walk->dst.virt.addr = (u8 *)ALIGN((unsigned long)walk->buffer,
					  alignmask + 1);
	walk->dst.virt.addr = xblkcipher_get_spot(walk->dst.virt.addr, bsize);
	walk->src.virt.addr = xblkcipher_get_spot(walk->dst.virt.addr +
						 aligned_bsize, bsize);

	Xscatterwalk_copychunks(walk->src.virt.addr, &walk->in, bsize, 0);

	walk->nbytes = bsize;
	walk->flags |= BLKCIPHER_WALK_SLOW;

	return 0;
}

static inline int xblkcipher_next_copy(struct xblkcipher_walk *walk)
{
	u8 *tmp = walk->page;

	xblkcipher_map_src(walk);
	memcpy(tmp, walk->src.virt.addr, walk->nbytes);
	xblkcipher_unmap_src(walk);

	walk->src.virt.addr = tmp;
	walk->dst.virt.addr = tmp;

	return 0;
}

static inline int xblkcipher_next_fast(struct blkcipher_desc *desc,
				      struct xblkcipher_walk *walk)
{
	unsigned long diff;

	walk->src.phys.page = scatterwalk_page(&walk->in);
	walk->src.phys.offset = offset_in_page(walk->in.offset);
	walk->dst.phys.page = scatterwalk_page(&walk->out);
	walk->dst.phys.offset = offset_in_page(walk->out.offset);

	if (walk->flags & BLKCIPHER_WALK_PHYS)
		return 0;

	diff = walk->src.phys.offset - walk->dst.phys.offset;
	diff |= walk->src.virt.page - walk->dst.virt.page;

	xblkcipher_map_src(walk);
	walk->dst.virt.addr = walk->src.virt.addr;

	if (diff) {
		walk->flags |= BLKCIPHER_WALK_DIFF;
		xblkcipher_map_dst(walk);
	}

	return 0;
}

static int xblkcipher_walk_next(struct blkcipher_desc *desc,
			       struct xblkcipher_walk *walk)
{
	struct crypto_blkcipher *tfm = desc->tfm;
	unsigned int alignmask = crypto_blkcipher_alignmask(tfm);
	unsigned int bsize;
	unsigned int n;
	int err;

	n = walk->total;
	if (unlikely(n < crypto_blkcipher_blocksize(tfm))) {
		desc->flags |= CRYPTO_TFM_RES_BAD_BLOCK_LEN;
		return xblkcipher_walk_done(desc, walk, -EINVAL);
	}

	walk->flags &= ~(BLKCIPHER_WALK_SLOW | BLKCIPHER_WALK_COPY |
			 BLKCIPHER_WALK_DIFF);
	if (!scatterwalk_aligned(&walk->in, alignmask) ||
	    !scatterwalk_aligned(&walk->out, alignmask)) {
		walk->flags |= BLKCIPHER_WALK_COPY;
		if (!walk->page) {
			walk->page = (void *)__get_free_page(GFP_ATOMIC);
			if (!walk->page)
				n = 0;
		}
	}

	bsize = min(walk->blocksize, n);
	n = scatterwalk_clamp(&walk->in, n);
	n = scatterwalk_clamp(&walk->out, n);

	if (unlikely(n < bsize)) {
		err = xblkcipher_next_slow(desc, walk, bsize, alignmask);
		goto set_phys_lowmem;
	}

	walk->nbytes = n;
	if (walk->flags & BLKCIPHER_WALK_COPY) {
		err = xblkcipher_next_copy(walk);
		goto set_phys_lowmem;
	}

	return xblkcipher_next_fast(desc, walk);

set_phys_lowmem:
	if (walk->flags & BLKCIPHER_WALK_PHYS) {
		walk->src.phys.page = virt_to_page(walk->src.virt.addr);
		walk->dst.phys.page = virt_to_page(walk->dst.virt.addr);
		walk->src.phys.offset &= PAGE_SIZE - 1;
		walk->dst.phys.offset &= PAGE_SIZE - 1;
	}
	return err;
}

static inline int xblkcipher_copy_iv(struct xblkcipher_walk *walk,
				    struct crypto_blkcipher *tfm,
				    unsigned int alignmask)
{
	unsigned bs = walk->blocksize;
	unsigned int ivsize = crypto_blkcipher_ivsize(tfm);
	unsigned aligned_bs = ALIGN(bs, alignmask + 1);
	unsigned int size = aligned_bs * 2 + ivsize + max(aligned_bs, ivsize) -
			    (alignmask + 1);
	u8 *iv;

	size += alignmask & ~(crypto_tfm_ctx_alignment() - 1);
	walk->buffer = kmalloc(size, GFP_ATOMIC);
	if (!walk->buffer)
		return -ENOMEM;

	iv = (u8 *)ALIGN((unsigned long)walk->buffer, alignmask + 1);
	iv = xblkcipher_get_spot(iv, bs) + aligned_bs;
	iv = xblkcipher_get_spot(iv, bs) + aligned_bs;
	iv = xblkcipher_get_spot(iv, ivsize);

	walk->iv = memcpy(iv, walk->iv, ivsize);
	return 0;
}

int xblkcipher_walk_virt(struct blkcipher_desc *desc,
			struct xblkcipher_walk *walk)
{
	walk->flags &= ~BLKCIPHER_WALK_PHYS;
	walk->blocksize = crypto_blkcipher_blocksize(desc->tfm);
	return xblkcipher_walk_first(desc, walk);
}
EXPORT_SYMBOL_GPL(xblkcipher_walk_virt);

int xblkcipher_walk_phys(struct blkcipher_desc *desc,
			struct xblkcipher_walk *walk)
{
	walk->flags |= BLKCIPHER_WALK_PHYS;
	walk->blocksize = crypto_blkcipher_blocksize(desc->tfm);
	return xblkcipher_walk_first(desc, walk);
}
EXPORT_SYMBOL_GPL(xblkcipher_walk_phys);

static int xblkcipher_walk_first(struct blkcipher_desc *desc,
				struct xblkcipher_walk *walk)
{
	struct crypto_blkcipher *tfm = desc->tfm;
	unsigned int alignmask = crypto_blkcipher_alignmask(tfm);

	if (WARN_ON_ONCE(in_irq()))
		return -EDEADLK;

	walk->nbytes = walk->total;
	if (unlikely(!walk->total))
		return 0;

	walk->buffer = NULL;
	walk->iv = desc->info;
	if (unlikely(((unsigned long)walk->iv & alignmask))) {
		int err = xblkcipher_copy_iv(walk, tfm, alignmask);
		if (err)
			return err;
	}

	scatterwalk_start(&walk->in, walk->in.sg);
	scatterwalk_start(&walk->out, walk->out.sg);
	walk->page = NULL;

	return xblkcipher_walk_next(desc, walk);
}

int xblkcipher_walk_virt_block(struct blkcipher_desc *desc,
			      struct xblkcipher_walk *walk,
			      unsigned int blocksize)
{
	walk->flags &= ~BLKCIPHER_WALK_PHYS;
	walk->blocksize = blocksize;
	return xblkcipher_walk_first(desc, walk);
}
EXPORT_SYMBOL_GPL(xblkcipher_walk_virt_block);

static int setkey_unaligned(struct crypto_tfm *tfm, const u8 *key,
			    unsigned int keylen)
{
	struct blkcipher_alg *cipher = &tfm->__crt_alg->cra_blkcipher;
	unsigned long alignmask = crypto_tfm_alg_alignmask(tfm);
	int ret;
	u8 *buffer, *alignbuffer;
	unsigned long absize;

	absize = keylen + alignmask;
	buffer = kmalloc(absize, GFP_ATOMIC);
	if (!buffer)
		return -ENOMEM;

	alignbuffer = (u8 *)ALIGN((unsigned long)buffer, alignmask + 1);
	memcpy(alignbuffer, key, keylen);
	ret = cipher->setkey(tfm, alignbuffer, keylen);
	memset(alignbuffer, 0, keylen);
	kfree(buffer);
	return ret;
}

static int setkey(struct crypto_tfm *tfm, const u8 *key, unsigned int keylen)
{
	struct blkcipher_alg *cipher = &tfm->__crt_alg->cra_blkcipher;
	unsigned long alignmask = crypto_tfm_alg_alignmask(tfm);

	if (keylen < cipher->min_keysize || keylen > cipher->max_keysize) {
		tfm->crt_flags |= CRYPTO_TFM_RES_BAD_KEY_LEN;
		return -EINVAL;
	}

	if ((unsigned long)key & alignmask)
		return setkey_unaligned(tfm, key, keylen);

	return cipher->setkey(tfm, key, keylen);
}

static int async_setkey(struct crypto_ablkcipher *tfm, const u8 *key,
			unsigned int keylen)
{
	return setkey(crypto_ablkcipher_tfm(tfm), key, keylen);
}

static int async_encrypt(struct ablkcipher_request *req)
{
	struct crypto_tfm *tfm = req->base.tfm;
	struct blkcipher_alg *alg = &tfm->__crt_alg->cra_blkcipher;
	struct blkcipher_desc desc = {
		.tfm = __crypto_blkcipher_cast(tfm),
		.info = req->info,
		.flags = req->base.flags,
	};


	return alg->encrypt(&desc, req->dst, req->src, req->nbytes);
}

static int async_decrypt(struct ablkcipher_request *req)
{
	struct crypto_tfm *tfm = req->base.tfm;
	struct blkcipher_alg *alg = &tfm->__crt_alg->cra_blkcipher;
	struct blkcipher_desc desc = {
		.tfm = __crypto_blkcipher_cast(tfm),
		.info = req->info,
		.flags = req->base.flags,
	};

	return alg->decrypt(&desc, req->dst, req->src, req->nbytes);
}

static unsigned int crypto_xblkcipher_ctxsize(struct crypto_alg *alg, u32 type,
					     u32 mask)
{
	struct blkcipher_alg *cipher = &alg->cra_blkcipher;
	unsigned int len = alg->cra_ctxsize;

	if ((mask & CRYPTO_ALG_TYPE_MASK) == CRYPTO_ALG_TYPE_MASK &&
	    cipher->ivsize) {
		len = ALIGN(len, (unsigned long)alg->cra_alignmask + 1);
		len += cipher->ivsize;
	}

	return len;
}

static int crypto_init_xblkcipher_ops_async(struct crypto_tfm *tfm)
{
	struct ablkcipher_tfm *crt = &tfm->crt_ablkcipher;
	struct blkcipher_alg *alg = &tfm->__crt_alg->cra_blkcipher;

	crt->setkey = async_setkey;
	crt->encrypt = async_encrypt;
	crt->decrypt = async_decrypt;
	if (!alg->ivsize) {
		//crt->givencrypt = skcipher_null_givencrypt;
		//crt->givdecrypt = skcipher_null_givdecrypt;
	}
	crt->base = __crypto_ablkcipher_cast(tfm);
	crt->ivsize = alg->ivsize;

	return 0;
}

static int crypto_init_xblkcipher_ops_sync(struct crypto_tfm *tfm)
{
	struct blkcipher_tfm *crt = &tfm->crt_blkcipher;
	struct blkcipher_alg *alg = &tfm->__crt_alg->cra_blkcipher;
	unsigned long align = crypto_tfm_alg_alignmask(tfm) + 1;
	unsigned long addr;

	crt->setkey = setkey;
	crt->encrypt = alg->encrypt;
	crt->decrypt = alg->decrypt;

	addr = (unsigned long)crypto_tfm_ctx(tfm);
	addr = ALIGN(addr, align);
	addr += ALIGN(tfm->__crt_alg->cra_ctxsize, align);
	crt->iv = (void *)addr;

	return 0;
}

static int crypto_init_xblkcipher_ops(struct crypto_tfm *tfm, u32 type, u32 mask)
{
	struct blkcipher_alg *alg = &tfm->__crt_alg->cra_blkcipher;

	if (alg->ivsize > PAGE_SIZE / 8)
		return -EINVAL;

	if ((mask & CRYPTO_ALG_TYPE_MASK) == CRYPTO_ALG_TYPE_MASK)
		return crypto_init_xblkcipher_ops_sync(tfm);
	else
		return crypto_init_xblkcipher_ops_async(tfm);
}

#ifdef CONFIG_NET
static int crypto_xblkcipher_report(struct sk_buff *skb, struct crypto_alg *alg)
{
	struct crypto_report_blkcipher rblkcipher;

	snprintf(rblkcipher.type, CRYPTO_MAX_ALG_NAME, "%s", "blkcipher");
	snprintf(rblkcipher.geniv, CRYPTO_MAX_ALG_NAME, "%s",
		 alg->cra_blkcipher.geniv ?: "<default>");

	rblkcipher.blocksize = alg->cra_blocksize;
	rblkcipher.min_keysize = alg->cra_blkcipher.min_keysize;
	rblkcipher.max_keysize = alg->cra_blkcipher.max_keysize;
	rblkcipher.ivsize = alg->cra_blkcipher.ivsize;

	if (nla_put(skb, CRYPTOCFGA_REPORT_BLKCIPHER,
		    sizeof(struct crypto_report_blkcipher), &rblkcipher))
		goto nla_put_failure;
	return 0;

nla_put_failure:
	return -EMSGSIZE;
}
#else
static int crypto_xblkcipher_report(struct sk_buff *skb, struct crypto_alg *alg)
{
	return -ENOSYS;
}
#endif

static void crypto_xblkcipher_show(struct seq_file *m, struct crypto_alg *alg)
	__attribute__ ((unused));
static void crypto_xblkcipher_show(struct seq_file *m, struct crypto_alg *alg)
{
	seq_printf(m, "type         : xblkcipher\n");
	seq_printf(m, "blocksize    : %u\n", alg->cra_blocksize);
	seq_printf(m, "min keysize  : %u\n", alg->cra_blkcipher.min_keysize);
	seq_printf(m, "max keysize  : %u\n", alg->cra_blkcipher.max_keysize);
	seq_printf(m, "ivsize       : %u\n", alg->cra_blkcipher.ivsize);
	seq_printf(m, "geniv        : %s\n", alg->cra_blkcipher.geniv ?:
					     "<default>");
}

const struct crypto_type crypto_xblkcipher_type = {
	.ctxsize = crypto_xblkcipher_ctxsize,
	.init = crypto_init_xblkcipher_ops,
#ifdef CONFIG_PROC_FS
	.show = crypto_xblkcipher_show,
#endif
	.report = crypto_xblkcipher_report,
};
EXPORT_SYMBOL_GPL(crypto_xblkcipher_type);

static int crypto_grab_nivcipher(struct crypto_skcipher_spawn *spawn,
				const char *name, u32 type, u32 mask)
{
	struct crypto_alg *alg;
	int err;

	type = crypto_skcipher_type(type);
	mask = crypto_skcipher_mask(mask)| CRYPTO_ALG_GENIV;

	alg = crypto_alg_mod_lookup(name, type, mask);
	if (IS_ERR(alg))
		return PTR_ERR(alg);

	err = crypto_init_spawn(&spawn->base, alg, spawn->base.inst, mask);
	crypto_mod_put(alg);
	return err;
}

struct crypto_instance *skcipher_geniv_alloc(struct crypto_template *tmpl,
					     struct rtattr **tb, u32 type,
					     u32 mask)
{
	struct {
		int (*setkey)(struct crypto_ablkcipher *tfm, const u8 *key,
			      unsigned int keylen);
		int (*encrypt)(struct ablkcipher_request *req);
		int (*decrypt)(struct ablkcipher_request *req);

		unsigned int min_keysize;
		unsigned int max_keysize;
		unsigned int ivsize;

		const char *geniv;
	} balg;
	const char *name;
	struct crypto_skcipher_spawn *spawn;
	struct crypto_attr_type *algt;
	struct crypto_instance *inst;
	struct crypto_alg *alg;
	int err;

	algt = crypto_get_attr_type(tb);
	err = PTR_ERR(algt);
	if (IS_ERR(algt))
		return ERR_PTR(err);

	if ((algt->type ^ (CRYPTO_ALG_TYPE_GIVCIPHER | CRYPTO_ALG_GENIV)) &
	    algt->mask)
		return ERR_PTR(-EINVAL);

	name = crypto_attr_alg_name(tb[1]);
	err = PTR_ERR(name);
	if (IS_ERR(name))
		return ERR_PTR(err);

	inst = kzalloc(sizeof(*inst) + sizeof(*spawn), GFP_KERNEL);
	if (!inst)
		return ERR_PTR(-ENOMEM);

	spawn = crypto_instance_ctx(inst);

	/* Ignore async algorithms if necessary. */
	mask |= crypto_requires_sync(algt->type, algt->mask);

	crypto_set_skcipher_spawn(spawn, inst);
	err = crypto_grab_nivcipher(spawn, name, type, mask);
	if (err)
		goto err_free_inst;

	alg = crypto_skcipher_spawn_alg(spawn);

	if ((alg->cra_flags & CRYPTO_ALG_TYPE_MASK) ==
	    CRYPTO_ALG_TYPE_BLKCIPHER) {
		balg.ivsize = alg->cra_blkcipher.ivsize;
		balg.min_keysize = alg->cra_blkcipher.min_keysize;
		balg.max_keysize = alg->cra_blkcipher.max_keysize;

		balg.setkey = async_setkey;
		balg.encrypt = async_encrypt;
		balg.decrypt = async_decrypt;

		balg.geniv = alg->cra_blkcipher.geniv;
	} else {
		balg.ivsize = alg->cra_ablkcipher.ivsize;
		balg.min_keysize = alg->cra_ablkcipher.min_keysize;
		balg.max_keysize = alg->cra_ablkcipher.max_keysize;

		balg.setkey = alg->cra_ablkcipher.setkey;
		balg.encrypt = alg->cra_ablkcipher.encrypt;
		balg.decrypt = alg->cra_ablkcipher.decrypt;

		balg.geniv = alg->cra_ablkcipher.geniv;
	}

	err = -EINVAL;
	if (!balg.ivsize)
		goto err_drop_alg;

	/*
	 * This is only true if we're constructing an algorithm with its
	 * default IV generator.  For the default generator we elide the
	 * template name and double-check the IV generator.
	 */
	if (algt->mask & CRYPTO_ALG_GENIV) {
        //		if (!balg.geniv)
        //balg.geniv = crypto_default_geniv(alg);
		err = -EAGAIN;
		if (strcmp(tmpl->name, balg.geniv))
			goto err_drop_alg;

		memcpy(inst->alg.cra_name, alg->cra_name, CRYPTO_MAX_ALG_NAME);
		memcpy(inst->alg.cra_driver_name, alg->cra_driver_name,
		       CRYPTO_MAX_ALG_NAME);
	} else {
		err = -ENAMETOOLONG;
		if (snprintf(inst->alg.cra_name, CRYPTO_MAX_ALG_NAME,
			     "%s(%s)", tmpl->name, alg->cra_name) >=
		    CRYPTO_MAX_ALG_NAME)
			goto err_drop_alg;
		if (snprintf(inst->alg.cra_driver_name, CRYPTO_MAX_ALG_NAME,
			     "%s(%s)", tmpl->name, alg->cra_driver_name) >=
		    CRYPTO_MAX_ALG_NAME)
			goto err_drop_alg;
	}

	inst->alg.cra_flags = CRYPTO_ALG_TYPE_GIVCIPHER | CRYPTO_ALG_GENIV;
	inst->alg.cra_flags |= alg->cra_flags & CRYPTO_ALG_ASYNC;
	inst->alg.cra_priority = alg->cra_priority;
	inst->alg.cra_blocksize = alg->cra_blocksize;
	inst->alg.cra_alignmask = alg->cra_alignmask;
	inst->alg.cra_type = &crypto_givcipher_type;

	inst->alg.cra_ablkcipher.ivsize = balg.ivsize;
	inst->alg.cra_ablkcipher.min_keysize = balg.min_keysize;
	inst->alg.cra_ablkcipher.max_keysize = balg.max_keysize;
	inst->alg.cra_ablkcipher.geniv = balg.geniv;

	inst->alg.cra_ablkcipher.setkey = balg.setkey;
	inst->alg.cra_ablkcipher.encrypt = balg.encrypt;
	inst->alg.cra_ablkcipher.decrypt = balg.decrypt;

out:
	return inst;

err_drop_alg:
	crypto_drop_skcipher(spawn);
err_free_inst:
	kfree(inst);
	inst = ERR_PTR(err);
	goto out;
}
//EXPORT_SYMBOL_GPL(skcipher_geniv_alloc);

void skcipher_geniv_free(struct crypto_instance *inst)
{
	crypto_drop_skcipher(crypto_instance_ctx(inst));
	kfree(inst);
}
//EXPORT_SYMBOL_GPL(skcipher_geniv_free);

int skcipher_geniv_init(struct crypto_tfm *tfm)
{
	struct crypto_instance *inst = (void *)tfm->__crt_alg;
	struct crypto_ablkcipher *cipher;

	cipher = crypto_spawn_skcipher(crypto_instance_ctx(inst));
	if (IS_ERR(cipher))
		return PTR_ERR(cipher);

	tfm->crt_ablkcipher.base = cipher;
	tfm->crt_ablkcipher.reqsize += crypto_ablkcipher_reqsize(cipher);

	return 0;
}
//EXPORT_SYMBOL_GPL(skcipher_geniv_init);

void skcipher_geniv_exit(struct crypto_tfm *tfm)
{
	crypto_free_ablkcipher(tfm->crt_ablkcipher.base);
}
//EXPORT_SYMBOL_GPL(skcipher_geniv_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Generic block chaining cipher type");
