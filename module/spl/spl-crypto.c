#include <sys/crypto/api.h>
#include <sys/cmn_err.h>

#include <linux/scatterlist.h>
#include <linux/crypto.h>
#include <crypto/scatterwalk.h>

// ZFS_CRYPTO_VERBOSE is set in the crypto/api.h file
//#define ZFS_CRYPTO_VERBOSE

// With AEAD, we use cipher "ccm(aes)", which does MAC for us, and often crash.
// Without AEAD, we use blkcipher and call "ctr(aes)" ourselves.
#define ZFS_USE_AEAD
#define ZFS_COPYDST

#define ZFS_CIPHER "ccm(aes)"

#define ZFS_BLKCIPHER "ctr(aes)"



int crypto_mac(crypto_mechanism_t *mech, crypto_data_t *data,
               crypto_key_t *key, crypto_ctx_template_t tmpl, crypto_data_t *mac,
               crypto_call_req_t *cr)
{
#if _KERNEL
    printk("crypto_mac\n");
#endif
    return 0;
}




// So far, ZFS-crypto only uses 2 buffers. data + mac
#define SPL_CRYPTO_MAX_BUF 20


size_t crypto_map_buffers(crypto_data_t *solaris_buffer,
                       struct scatterlist **linux_buffer)
{
    uio_t *uio = NULL;
    iovec_t *iov = NULL;
    int i;
    size_t len = 0;

    // Setup SOURCE buffer(s)
    switch(solaris_buffer->cd_format) {
    case CRYPTO_DATA_RAW: // One buffer.
        *linux_buffer = kmalloc(sizeof(struct scatterlist) * 1, GFP_KERNEL);
        if (!*linux_buffer) return 0;
        sg_init_table(*linux_buffer, 1 );
        sg_set_buf(&(*linux_buffer)[0],
                   solaris_buffer->cd_raw.iov_base, // srcptr
                   solaris_buffer->cd_length);      // srclen
#ifdef ZFS_CRYPTO_VERBOSE
        printk("spl-crypto: mapping buffer to RAW->1 %p len 0x%04lx.\n",
               solaris_buffer->cd_raw.iov_base, solaris_buffer->cd_length);
#endif
        return solaris_buffer->cd_length;

    case CRYPTO_DATA_UIO: // Multiple buffers.
        uio = solaris_buffer->cd_uio;
        iov = uio->uio_iov;
        *linux_buffer = kmalloc(sizeof(struct scatterlist) * uio->uio_iovcnt,
                                GFP_KERNEL);
        if (!*linux_buffer) return 0;

        sg_init_table(*linux_buffer, uio->uio_iovcnt );
        for (i = 0; i < uio->uio_iovcnt; i++) {
            sg_set_buf(&(*linux_buffer)[i],
                       iov[i].iov_base,
                       iov[i].iov_len);
#ifdef ZFS_CRYPTO_VERBOSE
            printk("spl-crypto: mapping buffer %d to UIO->%d. %p len 0x%04lx\n",
                   i, uio->uio_iovcnt, iov[i].iov_base, iov[i].iov_len );
#endif
            len += iov[i].iov_len;
        }
        return len;

    case CRYPTO_DATA_MBLK: // network mbufs
    default:
        cmn_err(CE_PANIC, "spl-crypto: map->cd_format of unsupported type=%d",
                solaris_buffer->cd_format);
        return 0;

    }
}

struct tcrypt_result {
	struct completion completion;
	int err;
};

static void spl_async_cipher_done(struct crypto_async_request *req, int err)
{
	struct tcrypt_result *res = req->data;

#ifdef ZFS_CRYPTO_VERBOSE
    printk("cipher_work_done called: %d\n", err);
#endif

	if (err == -EINPROGRESS)
		return;

	res->err = err;
	complete(&res->completion);
}


void spl_crypto_map_iv(unsigned char *iv, int len, void *param)
{
    CK_AES_CCM_PARAMS *ccm_param = (CK_AES_CCM_PARAMS *)param;

    ASSERT(ccm_param != NULL);

    // 'iv' is set as, from Solaris kernel sources;
    // In ZFS-crypt, the "nonceSize" is always 12.
    // q = (uint8_t)((15 - nonceSize) & 0xFF);
    // cb[0] = 0x07 & (q-1);
    // cb[1..12] = supplied nonce
    // cb[13..14] = 0
    // cb[15] = 1;
    memset(iv, 0, len); // Make all bytes 0 first.
    iv[0]  = 0x02;
    memcpy(&iv[1], ccm_param->nonce, ccm_param->ulNonceSize); // 12 bytes
    iv[15] = 0x01;

}


int sg_nents(struct scatterlist *sg)
{
    int nents;
    for (nents = 0; sg; sg = sg_next(sg))
        nents++;
    return nents;
}



#ifdef ZFS_USE_AEAD
//
// Wrapper call from Solaris API, to Linux API.
//
// We convert Solaris crypto_data_t pointers (including the multi-buffer UIO)
// into Linux scatterlist buffer(s).
//
int crypto_encrypt(crypto_mechanism_t *mech, crypto_data_t *plaintext,
                   crypto_key_t *key, crypto_ctx_template_t tmpl, crypto_data_t *ciphertext,
                   crypto_call_req_t *cr)
{
#if _KERNEL
    int ret = CRYPTO_FAILED;
    struct crypto_aead  *tfm = NULL;
    struct aead_request *req = NULL;
    struct tcrypt_result result;
    struct scatterlist *linux_plain = NULL;
    struct scatterlist *linux_cipher = NULL;
    size_t plainlen = 0, cryptlen = 0, maclen = 0;
    unsigned char iv[16];
    unsigned char assoc[16];
    struct scatterlist assoctext[1];
    unsigned char *new_plain  = NULL;
    unsigned char *new_cipher = NULL;

#ifdef ZFS_CRYPTO_VERBOSE
    printk("spl-crypto: enter\n");
#endif

    ASSERT(mech != NULL);

    // We don't use assoc, but it appears it needs to be supplied.
    memset(assoc, 0, sizeof(assoc));
    sg_init_one(&assoctext[0], assoc, sizeof(assoc));

    ASSERT(key->ck_format == CRYPTO_KEY_RAW);

    // Use source len as cryptolen.
    if (!(plainlen = crypto_map_buffers(plaintext, &linux_plain)))
        goto out;
    if (!(cryptlen = crypto_map_buffers(ciphertext, &linux_cipher)))
        goto out;

    /*
     * If scatterwalk_map_and_copy() is called on large dst buffers, we will
     * "often" panic; usually in:
     * BUG: unable to handle kernel paging request at ffffeb040011a880
     * IP: [<ffffffff812f4880>] scatterwalk_done+0x50/0x60
     *     [<ffffffff812f7640>] blkcipher_walk_done+0xb0/0x230
     *     [<ffffffffa014a169>] crypto_ctr_crypt+0x129/0x2b0 [ctr]
     *
     * However, if we allocate a new buffer to use as dst, then call
     * sg_copy_from_buffer() to copy the data back, all works well.
     *
     * Does anyone know why? Note that this makes it work for "gentle use",
     * the crypto call will still scribble all over the stack "occasionally".
     *
     * Possibly, internal cipher routines are required, as the crypto/ API
     * framework is currently too sensitive. (3.5.0)
     *
     */

    // Allocate buffer to dst, total size.
#ifdef ZFS_COPYDST
    new_cipher = kmalloc(cryptlen, GFP_KERNEL);
    if (!new_cipher) goto out;
    sg_init_table(linux_cipher, 1 );
    sg_set_buf(&linux_cipher[0], new_cipher, cryptlen);
#ifdef ZFS_CRYPTO_VERBOSE
    printk("spl-crypto: using all new buffers\n");
#endif
#endif

    // What is the size of the MAC buffer?
    maclen = cryptlen - plainlen;

#ifdef ZFS_CRYPTO_VERBOSE
    printk("spl-crypto: buffers set, len 0x%04lx / 0x%04lx (mac %ld)\n",
           plainlen, cryptlen, maclen);
#endif

    // This gets us a valid cipher, but the MAC differs from Solaris 'mac(sha256)'
    tfm = crypto_alloc_aead(ZFS_CIPHER, 0, 0);
    if (!tfm || IS_ERR(tfm)) return CRYPTO_FAILED;

#ifdef ZFS_CRYPTO_VERBOSE
    printk("spl-crypto: aead alloc OK: %p\n", tfm);
#endif

    req = aead_request_alloc(tfm, GFP_KERNEL);
    if (!req) goto out;

#ifdef ZFS_CRYPTO_VERBOSE
    printk("spl-crypto: req alloc OK\n");
#endif

    crypto_aead_setkey(tfm,
                       key->ck_data,
                       key->ck_length / 8);

    spl_crypto_map_iv(iv, sizeof(iv), mech->cm_param);

    // If ASYNC is used.
    init_completion(&result.completion);
    aead_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
                              spl_async_cipher_done, &result);

    aead_request_set_crypt(req, linux_plain, linux_cipher, plainlen, iv);
    aead_request_set_assoc(req, assoctext, sizeof(assoc));
    crypto_aead_setauthsize(tfm, maclen);

#ifdef ZFS_CRYPTO_VERBOSE
    printk("spl-crypto: calling encrypt(0x%04lx)\n", plainlen);
#endif

    ret = crypto_aead_encrypt(req);

    switch(ret) {
    case 0: // Success, immedate return
        ret = CRYPTO_SUCCESS;
        break;

    case -EINPROGRESS: // Async call, wait for completion
    case -EBUSY:
        ret = wait_for_completion_interruptible(
                                                &result.completion);
        if (!ret && !(ret = result.err)) {
            INIT_COMPLETION(result.completion);
            break;
        }
        break;

    default:
        cmn_err(CE_WARN, "spl-crypto: encrypt failed: %d", ret);
        break;
    }

#ifdef ZFS_COPYDST
    // Copy back
#ifdef ZFS_CRYPTO_VERBOSE
    printk("spl-crypto: copy data back\n");
#endif
    if (!(cryptlen = crypto_map_buffers(ciphertext, &linux_cipher)))
        return CRYPTO_FAILED;
    sg_copy_from_buffer(linux_cipher, sg_nents(linux_cipher),
                        new_cipher, cryptlen);
#endif

 out:
    if (req) aead_request_free(req);
    if (tfm && !IS_ERR(tfm)) crypto_free_aead(tfm);
    if (new_plain) kfree(new_plain);
    if (new_cipher) kfree(new_cipher);
    if (linux_plain) kfree(linux_plain);
    if (linux_cipher) kfree(linux_cipher);

#ifdef ZFS_CRYPTO_VERBOSE
    printk("spl-crypto: encrypt done: ret %d\n", ret);
#endif
    return ret;
#endif
    ASSERT(1==0);
    return CRYPTO_FAILED;
}



int crypto_decrypt(crypto_mechanism_t *mech, crypto_data_t *ciphertext,
    crypto_key_t *key, crypto_ctx_template_t tmpl, crypto_data_t *plaintext,
    crypto_call_req_t *cr)
{
#if _KERNEL
    int ret = CRYPTO_FAILED;
    struct crypto_aead  *tfm = NULL;
    struct aead_request *req = NULL;
    struct tcrypt_result result;
    struct scatterlist *linux_plain = NULL;
    struct scatterlist *linux_cipher = NULL;
    size_t cryptlen = 0, plainlen = 0, maclen = 0;
    unsigned char iv[16];
    unsigned char assoc[16];
    struct scatterlist assoctext[1];
    unsigned char *new_plain  = NULL;
    unsigned char *new_cipher = NULL;

#ifdef ZFS_CRYPTO_VERBOSE
    printk("spl-crypto: decrypt enter\n");
#endif

    ASSERT(mech != NULL);

    // We don't use assoc, but it appears it needs to be supplied.
    memset(assoc, 0, sizeof(assoc));
    sg_init_one(&assoctext[0], assoc, sizeof(assoc));

    ASSERT(key->ck_format == CRYPTO_KEY_RAW);

    // Use source len as cryptolen. If we are given two buffers here,
    // the cryptolen should be msglen + maclen. ie, 512 + 16, which
    // is what linux_decrypt expects to get
    if (!(plainlen = crypto_map_buffers(plaintext, &linux_plain)))
        return CRYPTO_FAILED;
    if (!(cryptlen = crypto_map_buffers(ciphertext, &linux_cipher)))
        return CRYPTO_FAILED;

   /*
     * If scatterwalk_map_and_copy() is called on large dst buffers, we will
     * "often" panic; usually in:
     * BUG: unable to handle kernel paging request at ffffeb040011a880
     * IP: [<ffffffff812f4880>] scatterwalk_done+0x50/0x60
     *     [<ffffffff812f7640>] blkcipher_walk_done+0xb0/0x230
     *     [<ffffffffa014a169>] crypto_ctr_crypt+0x129/0x2b0 [ctr]
     *
     * However, if we allocate a new buffer to use as dst, then call
     * sg_copy_from_buffer() to copy the data back, all works well.
     *
     * Does anyone know why?
     *
     */

#ifdef ZFS_COPYDST
    // Allocate buffer to dst, total size.
    new_plain = kmalloc(plainlen, GFP_KERNEL);
    if (!new_plain) goto out;
    sg_init_table(linux_plain, 1 );
    sg_set_buf(&linux_plain[0], new_plain, plainlen);
#ifdef ZFS_CRYPTO_VERBOSE
    printk("spl-crypto: using all new buffers\n");
#endif
#endif

    maclen = cryptlen - plainlen;

#ifdef ZFS_CRYPTO_VERBOSE
    printk("spl-crypto: buffers set, len 0x%04lx / 0x%04lx (mac %ld)\n",
           plainlen, cryptlen, maclen);
#endif

    // This gets us a valid cipher, but the MAC differs from Solaris 'mac(sha256)'
    tfm = crypto_alloc_aead(ZFS_CIPHER, 0, 0);
    if (!tfm || IS_ERR(tfm)) return CRYPTO_FAILED;

    req = aead_request_alloc(tfm, GFP_KERNEL);
    if (!req) goto out;

    crypto_aead_setkey(tfm,
                       key->ck_data,
                       key->ck_length / 8);

    spl_crypto_map_iv(iv, sizeof(iv), mech->cm_param);

    // If ASYNC is used.
    init_completion(&result.completion);
    aead_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
                              spl_async_cipher_done, &result);

    aead_request_set_crypt(req, linux_cipher, linux_plain, cryptlen, iv);
    aead_request_set_assoc(req, assoctext, sizeof(assoc));
    crypto_aead_setauthsize(tfm, maclen);

#ifdef ZFS_CRYPTO_VERBOSE
    printk("spl-crypt: calling decrypt(0x%04lx / 0x%04lx maclen %ld)\n",
           plainlen, cryptlen, maclen);
#endif

    ret = crypto_aead_decrypt(req);

    switch(ret) {
    case 0: // Success, immedate return
        ret = CRYPTO_SUCCESS;
        break;

    case -EINPROGRESS: // Async call, wait for completion
    case -EBUSY:
        ret = wait_for_completion_interruptible(
                                                &result.completion);
        if (!ret && !(ret = result.err)) {
            INIT_COMPLETION(result.completion);
            break;
        }
        break;

    case EBADMSG: // Verify authenticate failed.
        cmn_err(CE_WARN, "spl-crypto: decrypt verify failed.");
        ret = CRYPTO_SUCCESS;
        break;

    default:
        cmn_err(CE_WARN, "spl-crypto: decrypt failed: %d", ret);
        break;
    }


#ifdef ZFS_COPYDST
    // Copy back
#ifdef ZFS_CRYPTO_VERBOSE
    printk("spl-crypto: copy data back\n");
#endif
    if (!(plainlen = crypto_map_buffers(plaintext, &linux_plain)))
        return CRYPTO_FAILED;

    sg_copy_from_buffer(linux_plain, sg_nents(linux_plain),
                        new_plain, plainlen);
#endif

 out:
    if (req) aead_request_free(req);
    if (tfm && !IS_ERR(tfm)) crypto_free_aead(tfm);
    if (new_plain) kfree(new_plain);
    if (new_cipher) kfree(new_cipher);
    if (linux_plain)  kfree(linux_plain);
    if (linux_cipher) kfree(linux_cipher);

#ifdef ZFS_CRYPTO_VERBOSE
    printk("spl-crypto: decrypt done.\n");
#endif
    return ret;
#endif
    ASSERT(1==0);
    return CRYPTO_FAILED;
}


// ****************************************************************************
// ****************************************************************************
// ****************************************************************************
// ****************************************************************************
// ****************************************************************************
// ****************************************************************************
// ****************************************************************************
// ****************************************************************************

#elif defined ZFS_USE_BLOCK

int crypto_encrypt(crypto_mechanism_t *mech, crypto_data_t *plaintext,
                   crypto_key_t *key, crypto_ctx_template_t tmpl, crypto_data_t *ciphertext,
                   crypto_call_req_t *cr)
{
#if _KERNEL
    int ret = CRYPTO_FAILED;
    struct crypto_ablkcipher *tfm = NULL;
    struct scatterlist *linux_plain = NULL;
    struct scatterlist *linux_cipher = NULL;
    size_t plainlen = 0, cryptlen = 0, maclen = 0;
    unsigned char iv[16];
    unsigned char assoc[16];
    struct scatterlist assoctext[1];
    struct ablkcipher_request *req = NULL;
    struct tcrypt_result result;
    unsigned char *new_cipher = NULL;

#ifdef ZFS_CRYPTO_VERBOSE
    printk("spl-crypto: enter '%s'\n", ZFS_BLKCIPHER);
#endif

    ASSERT(mech != NULL);

    // We don't use assoc, but it appears it needs to be supplied.
    memset(assoc, 0, sizeof(assoc));
    sg_init_one(&assoctext[0], assoc, sizeof(assoc));

    ASSERT(key->ck_format == CRYPTO_KEY_RAW);

    // Use source len as cryptolen.
    if (!(plainlen = crypto_map_buffers(plaintext, &linux_plain)))
        return CRYPTO_FAILED;
    if (!(cryptlen = crypto_map_buffers(ciphertext, &linux_cipher)))
        return CRYPTO_FAILED;

    /*
     * If scatterwalk_map_and_copy() is called on large dst buffers, we will
     * "often" panic; usually in:
     * BUG: unable to handle kernel paging request at ffffeb040011a880
     * IP: [<ffffffff812f4880>] scatterwalk_done+0x50/0x60
     *     [<ffffffff812f7640>] blkcipher_walk_done+0xb0/0x230
     *     [<ffffffffa014a169>] crypto_ctr_crypt+0x129/0x2b0 [ctr]
     *
     * However, if we allocate a new buffer to use as dst, then call
     * sg_copy_from_buffer() to copy the data back, all works well.
     *
     * Does anyone know why? Note that this makes it work for "gentle use",
     * the crypto call will still scribble all over the stack "occasionally".
     *
     * Possibly, internal cipher routines are required, as the crypto/ API
     * framework is currently too sensitive. (3.5.0)
     *
     */

        // Allocate buffer to dst, total size.
    new_cipher = kmalloc(cryptlen, GFP_KERNEL);
    if (!new_cipher) goto out;
    sg_init_table(linux_cipher, 1 );
    sg_set_buf(&linux_cipher[0], new_cipher, cryptlen);
    printk("spl-crypto: using all new buffers\n");



    // What is the size of the MAC buffer?
    maclen = cryptlen - plainlen;

#ifdef ZFS_CRYPTO_VERBOSE
    printk("spl-crypto: buffers set, len 0x%04lx / 0x%04lx (mac %ld)\n",
           plainlen, cryptlen, maclen);
#endif

    // This gets us a valid cipher, but the MAC differs from Solaris 'mac(sha256)'
    tfm = crypto_alloc_ablkcipher(ZFS_BLKCIPHER, 0, 0);
    if (!tfm || IS_ERR(tfm)) goto out;

    init_completion(&result.completion);

    req = ablkcipher_request_alloc(tfm, GFP_KERNEL);
    if (!req) goto out;

#ifdef ZFS_CRYPTO_VERBOSE
    printk("spl-crypto: blkcipher alloc OK: %p\n", tfm);
#endif

    ablkcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
                                    spl_async_cipher_done, &result);

    crypto_ablkcipher_setkey(tfm,
                             key->ck_data,
                             key->ck_length / 8);

    spl_crypto_map_iv(iv, sizeof(iv), mech->cm_param);

#ifdef ZFS_CRYPTO_VERBOSE
    printk("spl-crypto: calling encrypt(0x%04lx)\n", plainlen);
#endif

    ablkcipher_request_set_crypt(req, linux_plain, linux_cipher,
                                 plainlen, iv);
    ret = crypto_ablkcipher_encrypt(req);


    switch(ret) {
    case 0: // Success, immedate return
        ret = CRYPTO_SUCCESS;
        break;

    case -EINPROGRESS: // Async call, wait for completion
    case -EBUSY:
        ret = wait_for_completion_interruptible(
                                                &result.completion);
        if (!ret && !(ret = result.err)) {
            INIT_COMPLETION(result.completion);
            break;
        }
        break;

    default:
        cmn_err(CE_WARN, "spl-crypto: encrypt failed: %d", ret);
        break;
    }

    // Copy back
    printk("spl-crypto: copy data back\n");
    if (!(cryptlen = crypto_map_buffers(ciphertext, &linux_cipher)))
        return CRYPTO_FAILED;

    sg_copy_from_buffer(linux_cipher, sg_nents(linux_cipher),
                        new_cipher, cryptlen);


 out:
    if (req) ablkcipher_request_free(req);
    if (tfm && !IS_ERR(tfm)) crypto_free_ablkcipher(tfm);
    if (new_cipher) kfree(new_cipher);
    if (linux_plain) kfree(linux_plain);
    if (linux_cipher) kfree(linux_cipher);


#ifdef ZFS_CRYPTO_VERBOSE
    printk("spl-crypto: encrypt done: ret %d\n", ret);
#endif
    return ret;
#endif
    ASSERT(1==0);
    return CRYPTO_FAILED;
}



int crypto_decrypt(crypto_mechanism_t *mech, crypto_data_t *ciphertext,
    crypto_key_t *key, crypto_ctx_template_t tmpl, crypto_data_t *plaintext,
    crypto_call_req_t *cr)
{
#if _KERNEL
    int ret = CRYPTO_FAILED;
    struct crypto_ablkcipher *tfm = NULL;
    struct scatterlist *linux_plain = NULL;
    struct scatterlist *linux_cipher = NULL;
    size_t cryptlen = 0, plainlen = 0, maclen = 0;
    unsigned char iv[16];
    unsigned char assoc[16];
    struct scatterlist assoctext[1];
    struct ablkcipher_request *req = NULL;
    struct tcrypt_result result;
    unsigned char *new_plain  = NULL;


#ifdef ZFS_CRYPTO_VERBOSE
    printk("spl-crypto: decrypt enter\n");
#endif

    ASSERT(mech != NULL);

    // We don't use assoc, but it appears it needs to be supplied.
    memset(assoc, 0, sizeof(assoc));
    sg_init_one(&assoctext[0], assoc, sizeof(assoc));

    ASSERT(key->ck_format == CRYPTO_KEY_RAW);

    // Use source len as cryptolen. If we are given two buffers here,
    // the cryptolen should be msglen + maclen. ie, 512 + 16, which
    // is what linux_decrypt expects to get
    if (!(plainlen = crypto_map_buffers(plaintext, &linux_plain)))
        return CRYPTO_FAILED;
    if (!(cryptlen = crypto_map_buffers(ciphertext, &linux_cipher)))
        return CRYPTO_FAILED;

   /*
     * If scatterwalk_map_and_copy() is called on large dst buffers, we will
     * "often" panic; usually in:
     * BUG: unable to handle kernel paging request at ffffeb040011a880
     * IP: [<ffffffff812f4880>] scatterwalk_done+0x50/0x60
     *     [<ffffffff812f7640>] blkcipher_walk_done+0xb0/0x230
     *     [<ffffffffa014a169>] crypto_ctr_crypt+0x129/0x2b0 [ctr]
     *
     * However, if we allocate a new buffer to use as dst, then call
     * sg_copy_from_buffer() to copy the data back, all works well.
     *
     * Does anyone know why?
     *
     */
   // Allocate buffer to dst, total size.
    new_plain = kmalloc(plainlen, GFP_KERNEL);
    if (!new_plain) goto out;
    sg_init_table(linux_plain, 1 );
    sg_set_buf(&linux_plain[0], new_plain, plainlen);
    printk("spl-crypto: using all new buffers\n");

    maclen = cryptlen - plainlen;

#ifdef ZFS_CRYPTO_VERBOSE
    printk("spl-crypto: buffers set, len 0x%04lx / 0x%04lx (mac %ld)\n",
           plainlen, cryptlen, maclen);
#endif

    // This gets us a valid cipher, but the MAC differs from Solaris 'mac(sha256)'
    tfm = crypto_alloc_ablkcipher(ZFS_BLKCIPHER, 0, 0);
    if (!tfm || IS_ERR(tfm)) goto out;

    init_completion(&result.completion);

    req = ablkcipher_request_alloc(tfm, GFP_KERNEL);
    if (!req) goto out;

    ablkcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
                                    spl_async_cipher_done, &result);

    crypto_ablkcipher_setkey(tfm,
                             key->ck_data,
                             key->ck_length / 8);

    spl_crypto_map_iv(iv, sizeof(iv), mech->cm_param);


#ifdef ZFS_CRYPTO_VERBOSE
    printk("spl-crypt: calling decrypt(0x%04lx / 0x%04lx maclen %ld)\n",
           plainlen, cryptlen, maclen);
#endif

    ablkcipher_request_set_crypt(req, linux_cipher, linux_plain,
                                 plainlen, iv);

    ret = crypto_ablkcipher_decrypt(req);


    switch(ret) {
    case 0: // Success, immedate return
        ret = CRYPTO_SUCCESS;
        break;

    case -EINPROGRESS: // Async call, wait for completion
    case -EBUSY:
        ret = wait_for_completion_interruptible(
                                                &result.completion);
        if (!ret && !(ret = result.err)) {
            INIT_COMPLETION(result.completion);
            break;
        }
        break;

    case EBADMSG: // Verify authenticate failed.
        cmn_err(CE_WARN, "spl-crypto: decrypt verify failed.");
        ret = CRYPTO_SUCCESS;
        break;

    default:
        cmn_err(CE_WARN, "spl-crypto: decrypt failed: %d", ret);
        break;
    }

    // Copy back
    printk("spl-crypto: copy data back\n");
    if (!(plainlen = crypto_map_buffers(plaintext, &linux_plain)))
        return CRYPTO_FAILED;

    sg_copy_from_buffer(linux_plain, sg_nents(linux_plain),
                        new_plain, plainlen);

 out:
    if (req) ablkcipher_request_free(req);
    if (tfm && !IS_ERR(tfm)) crypto_free_ablkcipher(tfm);
    if (new_plain) kfree(new_plain);
    if (linux_plain) kfree(linux_plain);
    if (linux_cipher) kfree(linux_cipher);

#ifdef ZFS_CRYPTO_VERBOSE
    printk("spl-crypto: decrypt done.\n");
#endif
    return ret;
#endif
    ASSERT(1==0);
    return CRYPTO_FAILED;
}

#else

int crypto_encrypt(crypto_mechanism_t *mech, crypto_data_t *plaintext,
                   crypto_key_t *key, crypto_ctx_template_t tmpl, crypto_data_t *ciphertext,
                   crypto_call_req_t *cr)
{
    struct scatterlist *linux_plain = NULL;
    struct scatterlist *linux_cipher = NULL;
    size_t cryptlen = 0, plainlen = 0;
    static int COUNT = 0;
    void *buf = NULL;
#if _KERNEL

#ifdef ZFS_CRYPTO_VERBOSE
    COUNT++;
    printk("spl-crypto: encrypt enter. %d mech=%d\n", COUNT,
           (int)mech->cm_type);
#endif

    if (!(plainlen = crypto_map_buffers(plaintext, &linux_plain)))
        return CRYPTO_FAILED;
    if (!(cryptlen = crypto_map_buffers(ciphertext, &linux_cipher)))
        return CRYPTO_FAILED;

    printk(" copy from %p to %p \n", sg_virt(linux_plain), sg_virt(linux_cipher));

    buf = kmalloc(plainlen, GFP_KERNEL);
    if (!buf) return CRYPTO_FAILED;

    sg_copy_to_buffer(linux_plain, sg_nents(linux_plain), buf, plainlen);
    sg_copy_from_buffer(linux_cipher, sg_nents(linux_cipher), buf, plainlen);
    kfree(buf);

#ifdef ZFS_CRYPTO_VERBOSE
    printk("spl-crypto: encrypt done 0x%04lx: %d\n", plainlen, COUNT);
#endif
    if (linux_plain)  kfree(linux_plain);
    if (linux_cipher) kfree(linux_cipher);

    COUNT--;
    return CRYPTO_SUCCESS;
#endif
    ASSERT(1==0);
    return CRYPTO_FAILED;
}



int crypto_decrypt(crypto_mechanism_t *mech, crypto_data_t *ciphertext,
    crypto_key_t *key, crypto_ctx_template_t tmpl, crypto_data_t *plaintext,
    crypto_call_req_t *cr)
{
    struct scatterlist *linux_plain  = NULL;
    struct scatterlist *linux_cipher = NULL;
    size_t cryptlen = 0, plainlen = 0;
    void *buf;

#if _KERNEL

#ifdef ZFS_CRYPTO_VERBOSE
    printk("spl-crypto: decrypt enter.\n");
#endif

    if (!(plainlen = crypto_map_buffers(plaintext, &linux_plain)))
        return CRYPTO_FAILED;
    if (!(cryptlen = crypto_map_buffers(ciphertext, &linux_cipher)))
        return CRYPTO_FAILED;

    buf = kmalloc(cryptlen, GFP_KERNEL);
    if (!buf) return CRYPTO_FAILED;

    sg_copy_to_buffer(linux_cipher, sg_nents(linux_cipher), buf, cryptlen);
    sg_copy_from_buffer(linux_plain, sg_nents(linux_plain), buf, cryptlen);
    kfree(buf);

#ifdef ZFS_CRYPTO_VERBOSE
    printk("spl-crypto: decrypt done.\n");
#endif
    if (linux_plain)  kfree(linux_plain);
    if (linux_cipher) kfree(linux_cipher);

    return CRYPTO_SUCCESS;
#endif
    ASSERT(1==0);
    return CRYPTO_FAILED;
}

#endif






int crypto_create_ctx_template(crypto_mechanism_t *mech,
    crypto_key_t *key, crypto_ctx_template_t *tmpl, int kmflag)
{
    return 0;
}

void crypto_destroy_ctx_template(crypto_ctx_template_t tmpl)
{
    return;
}

crypto_mech_type_t crypto_mech2id(crypto_mech_name_t name)
{
    if (!name || !*name)
        return CRYPTO_MECH_INVALID;

#ifdef ZFS_CRYPTO_VERBOSE
#if _KERNEL
    printk("called crypto_mech2id '%s'\n", name);
#endif
#endif
    if (name && !strcmp("CKM_AES_CCM", name)) return 1;
    return CRYPTO_MECH_INVALID;
}


#if _KERNEL

EXPORT_SYMBOL(crypto_encrypt);
EXPORT_SYMBOL(crypto_mac);
EXPORT_SYMBOL(crypto_decrypt);
EXPORT_SYMBOL(crypto_create_ctx_template);
EXPORT_SYMBOL(crypto_destroy_ctx_template);
EXPORT_SYMBOL(crypto_mech2id);

#endif




