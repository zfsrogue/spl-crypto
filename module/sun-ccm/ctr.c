/*
 * CTR: Counter mode
 *
 * (C) Copyright IBM Corp. 2007 - Joy Latten <latten@us.ibm.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 */

/*
 * Make a new copy of this file/module, to avoid the PageSlab() call in
 * blcipher.c
 */


/*#include <crypto/algapi.h>*/
#include "algapi.h"
#include <crypto/ctr.h>
#include <linux/err.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/random.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>

struct crypto_ctr_ctx {
	struct crypto_cipher *child;
};

struct crypto_rfc3686_ctx {
	struct crypto_blkcipher *child;
	u8 nonce[CTR_RFC3686_NONCE_SIZE];
};

static int crypto_ctr_setkey(struct crypto_tfm *parent, const u8 *key,
			     unsigned int keylen)
{
	struct crypto_ctr_ctx *ctx = crypto_tfm_ctx(parent);
	struct crypto_cipher *child = ctx->child;
	int err;

	crypto_cipher_clear_flags(child, CRYPTO_TFM_REQ_MASK);
	crypto_cipher_set_flags(child, crypto_tfm_get_flags(parent) &
				CRYPTO_TFM_REQ_MASK);
	err = crypto_cipher_setkey(child, key, keylen);
	crypto_tfm_set_flags(parent, crypto_cipher_get_flags(child) &
			     CRYPTO_TFM_RES_MASK);

	return err;
}

static void crypto_ctr_crypt_final(struct xblkcipher_walk *walk,
				   struct crypto_cipher *tfm)
{
	unsigned int bsize = crypto_cipher_blocksize(tfm);
	unsigned long alignmask = crypto_cipher_alignmask(tfm);
	u8 *ctrblk = walk->iv;
	u8 tmp[bsize + alignmask];
	u8 *keystream = PTR_ALIGN(tmp + 0, alignmask + 1);
	u8 *src = walk->src.virt.addr;
	u8 *dst = walk->dst.virt.addr;
	unsigned int nbytes = walk->nbytes;

	crypto_cipher_encrypt_one(tfm, keystream, ctrblk);
	crypto_xor(keystream, src, nbytes);
	memcpy(dst, keystream, nbytes);

	crypto_inc(ctrblk, bsize);
}

static int crypto_ctr_crypt_segment(struct xblkcipher_walk *walk,
				    struct crypto_cipher *tfm)
{
	void (*fn)(struct crypto_tfm *, u8 *, const u8 *) =
		   crypto_cipher_alg(tfm)->cia_encrypt;
	unsigned int bsize = crypto_cipher_blocksize(tfm);
	u8 *ctrblk = walk->iv;
	u8 *src = walk->src.virt.addr;
	u8 *dst = walk->dst.virt.addr;
	unsigned int nbytes = walk->nbytes;

	do {
		/* create keystream */
		fn(crypto_cipher_tfm(tfm), dst, ctrblk);
		crypto_xor(dst, src, bsize);

		/* increment counter in counterblock */
		crypto_inc(ctrblk, bsize);

		src += bsize;
		dst += bsize;
	} while ((nbytes -= bsize) >= bsize);

	return nbytes;
}

static int crypto_ctr_crypt_inplace(struct xblkcipher_walk *walk,
				    struct crypto_cipher *tfm)
{
	void (*fn)(struct crypto_tfm *, u8 *, const u8 *) =
		   crypto_cipher_alg(tfm)->cia_encrypt;
	unsigned int bsize = crypto_cipher_blocksize(tfm);
	unsigned long alignmask = crypto_cipher_alignmask(tfm);
	unsigned int nbytes = walk->nbytes;
	u8 *ctrblk = walk->iv;
	u8 *src = walk->src.virt.addr;
	u8 tmp[bsize + alignmask];
	u8 *keystream = PTR_ALIGN(tmp + 0, alignmask + 1);

	do {
		/* create keystream */
		fn(crypto_cipher_tfm(tfm), keystream, ctrblk);
		crypto_xor(src, keystream, bsize);

		/* increment counter in counterblock */
		crypto_inc(ctrblk, bsize);

		src += bsize;
	} while ((nbytes -= bsize) >= bsize);

	return nbytes;
}

static int crypto_ctr_crypt(struct blkcipher_desc *desc,
			      struct scatterlist *dst, struct scatterlist *src,
			      unsigned int nbytes)
{
	struct xblkcipher_walk walk;
	struct crypto_blkcipher *tfm = desc->tfm;
	struct crypto_ctr_ctx *ctx = crypto_blkcipher_ctx(tfm);
	struct crypto_cipher *child = ctx->child;
	unsigned int bsize = crypto_cipher_blocksize(child);
	int err;

	xblkcipher_walk_init(&walk, dst, src, nbytes);
	err = xblkcipher_walk_virt_block(desc, &walk, bsize);

	while (walk.nbytes >= bsize) {
		if (walk.src.virt.addr == walk.dst.virt.addr)
			nbytes = crypto_ctr_crypt_inplace(&walk, child);
		else
			nbytes = crypto_ctr_crypt_segment(&walk, child);

		err = xblkcipher_walk_done(desc, &walk, nbytes);
	}

	if (walk.nbytes) {
		crypto_ctr_crypt_final(&walk, child);
		err = xblkcipher_walk_done(desc, &walk, 0);
	}

	return err;
}

static int crypto_ctr_init_tfm(struct crypto_tfm *tfm)
{
	struct crypto_instance *inst = (void *)tfm->__crt_alg;
	struct crypto_spawn *spawn = crypto_instance_ctx(inst);
	struct crypto_ctr_ctx *ctx = crypto_tfm_ctx(tfm);
	struct crypto_cipher *cipher;

	cipher = crypto_spawn_cipher(spawn);
	if (IS_ERR(cipher))
		return PTR_ERR(cipher);

	ctx->child = cipher;

	return 0;
}

static void crypto_ctr_exit_tfm(struct crypto_tfm *tfm)
{
	struct crypto_ctr_ctx *ctx = crypto_tfm_ctx(tfm);

	crypto_free_cipher(ctx->child);
}

static struct crypto_instance *crypto_ctr_alloc(struct rtattr **tb)
{
	struct crypto_instance *inst;
	struct crypto_alg *alg;
	int err;

	err = crypto_check_attr_type(tb, CRYPTO_ALG_TYPE_BLKCIPHER);
	if (err)
		return ERR_PTR(err);

	alg = crypto_attr_alg(tb[1], CRYPTO_ALG_TYPE_CIPHER,
				  CRYPTO_ALG_TYPE_MASK);
	if (IS_ERR(alg))
		return ERR_CAST(alg);

	/* Block size must be >= 4 bytes. */
	err = -EINVAL;
	if (alg->cra_blocksize < 4)
		goto out_put_alg;

	/* If this is false we'd fail the alignment of crypto_inc. */
	if (alg->cra_blocksize % 4)
		goto out_put_alg;

	inst = crypto_alloc_instance("sun-ctr", alg);
	if (IS_ERR(inst))
		goto out;

	inst->alg.cra_flags = CRYPTO_ALG_TYPE_BLKCIPHER;
	inst->alg.cra_priority = alg->cra_priority;
	inst->alg.cra_blocksize = 1;
	inst->alg.cra_alignmask = alg->cra_alignmask | (__alignof__(u32) - 1);
	inst->alg.cra_type = &crypto_blkcipher_type;

	inst->alg.cra_blkcipher.ivsize = alg->cra_blocksize;
	inst->alg.cra_blkcipher.min_keysize = alg->cra_cipher.cia_min_keysize;
	inst->alg.cra_blkcipher.max_keysize = alg->cra_cipher.cia_max_keysize;

	inst->alg.cra_ctxsize = sizeof(struct crypto_ctr_ctx);

	inst->alg.cra_init = crypto_ctr_init_tfm;
	inst->alg.cra_exit = crypto_ctr_exit_tfm;

	inst->alg.cra_blkcipher.setkey = crypto_ctr_setkey;
	inst->alg.cra_blkcipher.encrypt = crypto_ctr_crypt;
	inst->alg.cra_blkcipher.decrypt = crypto_ctr_crypt;

	inst->alg.cra_blkcipher.geniv = "chainiv";

out:
	crypto_mod_put(alg);
	return inst;

out_put_alg:
	inst = ERR_PTR(err);
	goto out;
}

static void crypto_ctr_free(struct crypto_instance *inst)
{
	crypto_drop_spawn(crypto_instance_ctx(inst));
	kfree(inst);
}


struct crypto_template crypto_ctr_tmpl = {
	.name = "sun-ctr",
	.alloc = crypto_ctr_alloc,
	.free = crypto_ctr_free,
	.module = THIS_MODULE,
};

