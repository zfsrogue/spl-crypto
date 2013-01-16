#include <sys/crypto/api.h>
#include <sys/cmn_err.h>

#include <linux/scatterlist.h>
#include <linux/crypto.h>
#include <crypto/scatterwalk.h>

// ZFS_CRYPTO_VERBOSE is set in the crypto/api.h file
//#define ZFS_CRYPTO_VERBOSE


/*
 * The Crypto API has a bug, to work around it, we can allocate a new linear
 * DST buffer, and copy. Which is not as efficient.
 * The modules sun-ccm etc, was written to avoid this bug,
 * and the need for copy.
 */
//#define ZFS_COPYDST


/*
 * Linux cipher types, and the Solaris equivalent.
 *
 * This is an indexed structure. First entry is not used, since return
 * of zero is considered failure. First cipher match, returns "1", then
 * "1" is used to look up the cipher name, and optional hmac.
 *
 */

enum cipher_type_t {
    CIPHER_TYPE_AEAD = 0,
    CIPHER_TYPE_BLK,
    CIPHER_TYPE_MAC,
};

struct cipher_map_s {
    enum cipher_type_t type;
    char *solaris_name;
    int power_on_test; /* If 0, check cipher exists. Set to 1 after that */
    char *linux_name;
    char *hmac_name;   /* optional hmac if not part of linux_name */
};

typedef struct cipher_map_s cipher_map_t;

static cipher_map_t cipher_map[] =
{
    /* 0, not used, must be defined */
    { CIPHER_TYPE_MAC,  "NULL Cipher", 0, NULL, NULL },
#if 0
    // TODO, attempt to make the MAC be the same as Solaris
    { CIPHER_TYPE_AEAD, "CKM_AES_CCM", 0, "sun-ctr(aes)", "hmac(sha256)" },
#else
    { CIPHER_TYPE_AEAD, "CKM_AES_CCM", 0, "sun-ccm(aes)", NULL },
#endif
    { CIPHER_TYPE_AEAD, "CKM_AES_GCM", 0, "sun-gcm(aes)", NULL },
    { CIPHER_TYPE_BLK,  "CKM_AES_CTR", 0, "sun-ctr(aes)", NULL },
    { CIPHER_TYPE_MAC,  "CKM_SHA256_HMAC_GENERAL", 0, NULL, "hmac(sha256)" },
};

#define NUM_CIPHER_MAP (sizeof(cipher_map) / sizeof(cipher_map_t))





/*
 *
 * Convert Solaris RAW (single buffer) or UIO (multiple buffers) into
 * a dynamically allocated scatterlist.
 *
 * Returns total size of Solaris buffer(s), or 0 for failure.
 *
 * The scatterlist "linux_buffer" should be kfree()d by caller.
 *
 */
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

        *linux_buffer = kmalloc(sizeof(struct scatterlist) * 1,
                                GFP_KERNEL);
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
            printk("spl-crypto: mapping buffer %d to UIO->%d. %p len 0x%04lx: kmem_virt %d\n",
                   i, uio->uio_iovcnt, iov[i].iov_base, iov[i].iov_len,
                   kmem_virt(iov[i].iov_base));
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

    // Make sure we are to use iv
    if (!ccm_param || !ccm_param->nonce || !ccm_param->ulNonceSize) {
        memset(iv, 0, len);
        return;
    }

    // q = (uint8_t)((15 - nonceSize) & 0xFF);
    // cb[0] = 0x07 & (q-1);
    // cb[1..12] = supplied nonce
    // cb[13..14] = 0
    // cb[15] = 1;
    memset(iv, 0, len); // Make all bytes 0 first.
    iv[0] = (( 15-ccm_param->ulNonceSize-1 )&7);
    memcpy(&iv[1], ccm_param->nonce, ccm_param->ulNonceSize); // ~12 bytes

}



/*
 *
 * This is needed while the temporary fix to use sg_copy_from_buffer()
 * is in place.
 *
 */
#ifdef ZFS_COPYDST
int sg_nents(struct scatterlist *sg)
{
    int nents;
    for (nents = 0; sg; sg = sg_next(sg))
        nents++;
    return nents;
}
#endif


int crypto_mac(crypto_mechanism_t *mech, crypto_data_t *data,
               crypto_key_t *key, crypto_ctx_template_t tmpl, crypto_data_t *mac,
               crypto_call_req_t *cr)
{
    int ret = CRYPTO_FAILED;
    cipher_map_t *cm = NULL;
    struct scatterlist *linux_data = NULL;
    struct scatterlist *linux_hmac = NULL;
    size_t datalen, hmaclen;
    struct crypto_hash *htfm = NULL;
    struct hash_desc desc;

#if _KERNEL
    printk("crypto_mac\n");
#endif
    ASSERT(mech != NULL);

    if (mech->cm_type >= NUM_CIPHER_MAP) return CRYPTO_FAILED;
    cm = &cipher_map[ mech->cm_type ];

    if (!cm->hmac_name) return CRYPTO_FAILED;

    ASSERT(key->ck_format == CRYPTO_KEY_RAW);

    if (!(datalen = crypto_map_buffers(data, &linux_data)))
        goto out;
    if (!(hmaclen = crypto_map_buffers(data, &linux_hmac)))
        goto out;

    // Enough room in output?
    if (crypto_hash_digestsize(htfm) > hmaclen) goto out;

    htfm = crypto_alloc_hash(cm->hmac_name, 0, 0);
    if (!htfm || IS_ERR(htfm)) goto out;

    desc.tfm = htfm;
    desc.flags = 0;

    crypto_hash_setkey(htfm,
                       key->ck_data,
                       key->ck_length / 8);

    ret = crypto_hash_digest(&desc, linux_data, datalen,
                             sg_virt(linux_hmac)); // u8*, not scatterlist

    if (!ret)
        ret = CRYPTO_SUCCESS;

 out:
    if (htfm || !IS_ERR(htfm)) crypto_free_hash(htfm);
    if (linux_data) kfree(linux_data);
    if (linux_hmac) kfree(linux_hmac);
#ifdef ZFS_CRYPTO_VERBOSE
    printk("spl-crypto: mac returning %d\n", ret);
#endif
    return ret;
}



/*
 * Solaris crypto vs Linux crypto
 *
 * Translate the Solaris crypto API to Linux crypto API. This needs to be
 * expanded to handle more ciphers, and key lengths.
 *
 */
int crypto_encrypt_aead(crypto_mechanism_t *mech, crypto_data_t *plaintext,
                        crypto_key_t *key, crypto_ctx_template_t tmpl,
                        crypto_data_t *ciphertext,
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
    unsigned char *new_plain  = NULL;
    unsigned char *new_cipher = NULL;
    cipher_map_t *cm = NULL;

#ifdef ZFS_CRYPTO_VERBOSE
    printk("spl-crypto: encrypt enter: type %d\n", (int) mech->cm_type);
#endif

    ASSERT(mech != NULL);

    if (mech->cm_type >= NUM_CIPHER_MAP) return CRYPTO_FAILED;
    cm = &cipher_map[ mech->cm_type ];

#ifdef ZFS_CRYPTO_VERBOSE
    printk("spl-crypto: ciphermap '%s' -> '%s' in use\n",
           cm->solaris_name,
           cm->linux_name);
#endif

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

#ifdef ZFS_COPYDST
    // Temporarily, we will allocate a new linear buffer for the full
    // output, and call cipher. This is to avoid the scatterwalk panic.
    // after completion, call sg_copy_from_buffer() to copy the linear buffer
    // data back into the destination scatterlist. This does not panic.
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

    // This gets us a valid cipher,but the MAC diff from Solaris 'mac(sha256)'
    tfm = crypto_alloc_aead(cm->linux_name, 0, 0);

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
    aead_request_set_assoc(req, NULL, 0);

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

    // Copy back the linear buffer to the scatterlist.
#ifdef ZFS_CRYPTO_VERBOSE
    printk("spl-crypto: copy data back\n");
#endif
    if (linux_cipher) {
        kfree(linux_cipher);
        linux_cipher = NULL;
    }

    if (!(cryptlen = crypto_map_buffers(ciphertext, &linux_cipher)))
        return CRYPTO_FAILED;

#if 1
    sg_copy_from_buffer(linux_cipher, sg_nents(linux_cipher),
                        new_cipher, cryptlen);
#else
    scatterwalk_map_and_copy(new_cipher, linux_cipher, 0, cryptlen, 1);
#endif

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





int crypto_decrypt_aead(crypto_mechanism_t *mech, crypto_data_t *ciphertext,
                        crypto_key_t *key, crypto_ctx_template_t tmpl,
                        crypto_data_t *plaintext, crypto_call_req_t *cr)
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
    unsigned char *new_plain  = NULL;
    unsigned char *new_cipher = NULL;
    cipher_map_t *cm = NULL;

#ifdef ZFS_CRYPTO_VERBOSE
    printk("spl-crypto: decrypt enter: type %d\n", (int)mech->cm_type);
#endif

    ASSERT(mech != NULL);

    if (mech->cm_type >= NUM_CIPHER_MAP) return CRYPTO_FAILED;
    cm = &cipher_map[ mech->cm_type ];

#ifdef ZFS_CRYPTO_VERBOSE
    printk("spl-crypto: ciphermap '%s' -> '%s' in use\n",
           cm->solaris_name,
           cm->linux_name);
#endif

    ASSERT(key->ck_format == CRYPTO_KEY_RAW);

    // Use source len as cryptolen. If we are given two buffers here,
    // the cryptolen should be msglen + maclen. ie, 512 + 16, which
    // is what linux_decrypt expects to get
    if (!(plainlen = crypto_map_buffers(plaintext, &linux_plain)))
        return CRYPTO_FAILED;

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

    tfm = crypto_alloc_aead(cm->linux_name, 0, 0);
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
    aead_request_set_assoc(req, NULL, 0);

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

    case -EBADMSG: // Verify authenticate failed.
        cmn_err(CE_WARN, "spl-crypto: decrypt verify failed.");
        //ret = CRYPTO_SUCCESS;  // Fix me in future, should be failure.
        ret = CRYPTO_INVALID_MAC;
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

    if (linux_cipher) {
        kfree(linux_cipher);
        linux_cipher = NULL;
    }

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
    printk("spl-crypto: decrypt done. returning %d\n", ret);
#endif
    return ret;
#endif
    ASSERT(1==0);
    return CRYPTO_FAILED;
}


// *************************************************************************
// *************************************************************************
// *************************************************************************
// *************************************************************************
// *************************************************************************
// *************************************************************************
// *************************************************************************
// *************************************************************************


int crypto_encrypt_blk(crypto_mechanism_t *mech, crypto_data_t *plaintext,
                       crypto_key_t *key, crypto_ctx_template_t tmpl,
                       crypto_data_t *ciphertext, crypto_call_req_t *cr)
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
    cipher_map_t *cm = NULL;

#ifdef ZFS_CRYPTO_VERBOSE
    printk("spl-crypto: encrypt_blk\n");
#endif

    ASSERT(mech != NULL);

    if (mech->cm_type >= NUM_CIPHER_MAP) return CRYPTO_FAILED;
    cm = &cipher_map[ mech->cm_type ];

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
#ifdef ZFS_COPYDST

        // Allocate buffer to dst, total size.
    new_cipher = kmalloc(cryptlen, GFP_KERNEL);
    if (!new_cipher) goto out;
    sg_init_table(linux_cipher, 1 );
    sg_set_buf(&linux_cipher[0], new_cipher, cryptlen);
    printk("spl-crypto: using all new buffers\n");
#endif


    // What is the size of the MAC buffer?
    maclen = cryptlen - plainlen;

#ifdef ZFS_CRYPTO_VERBOSE
    printk("spl-crypto: buffers set, len 0x%04lx / 0x%04lx (mac %ld)\n",
           plainlen, cryptlen, maclen);
#endif

    // This gets us a valid cipher, but the MAC differs from Solaris 'mac(sha256)'
    tfm = crypto_alloc_ablkcipher(cm->linux_name, 0, 0);
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
#ifdef ZFS_COPYDST
    printk("spl-crypto: copy data back\n");
    kfree(linux_cipher);
    if (!(cryptlen = crypto_map_buffers(ciphertext, &linux_cipher)))
        return CRYPTO_FAILED;

    sg_copy_from_buffer(linux_cipher, sg_nents(linux_cipher),
                        new_cipher, cryptlen);
#endif


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



int crypto_decrypt_blk(crypto_mechanism_t *mech, crypto_data_t *ciphertext,
                       crypto_key_t *key, crypto_ctx_template_t tmpl,
                       crypto_data_t *plaintext, crypto_call_req_t *cr)
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
    cipher_map_t *cm = NULL;

#ifdef ZFS_CRYPTO_VERBOSE
    printk("spl-crypto: decrypt enter\n");
#endif

    ASSERT(mech != NULL);

    if (mech->cm_type >= NUM_CIPHER_MAP) return CRYPTO_FAILED;
    cm = &cipher_map[ mech->cm_type ];

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
#ifdef ZFS_COPYDST
    new_plain = kmalloc(plainlen, GFP_KERNEL);
    if (!new_plain) goto out;
    sg_init_table(linux_plain, 1 );
    sg_set_buf(&linux_plain[0], new_plain, plainlen);
    printk("spl-crypto: using all new buffers\n");
#endif

    maclen = cryptlen - plainlen;

#ifdef ZFS_CRYPTO_VERBOSE
    printk("spl-crypto: buffers set, len 0x%04lx / 0x%04lx (mac %ld)\n",
           plainlen, cryptlen, maclen);
#endif

    // This gets us a valid cipher, but the MAC differs from Solaris 'mac(sha256)'
    tfm = crypto_alloc_ablkcipher(cm->linux_name, 0, 0);
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

    case -EBADMSG: // Verify authenticate failed.
        cmn_err(CE_WARN, "spl-crypto: decrypt verify failed.");
        ret = CRYPTO_SUCCESS;
        break;

    default:
        cmn_err(CE_WARN, "spl-crypto: decrypt failed: %d", ret);
        break;
    }

#ifdef ZFS_COPYDST
    // Copy back
    printk("spl-crypto: copy data back\n");
    if (!(plainlen = crypto_map_buffers(plaintext, &linux_plain)))
        return CRYPTO_FAILED;

    sg_copy_from_buffer(linux_plain, sg_nents(linux_plain),
                        new_plain, plainlen);
#endif

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




int crypto_encrypt(crypto_mechanism_t *mech, crypto_data_t *plaintext,
                   crypto_key_t *key, crypto_ctx_template_t tmpl,
                   crypto_data_t *ciphertext, crypto_call_req_t *cr)
{
    cipher_map_t *cm = NULL;

    if (mech->cm_type >= NUM_CIPHER_MAP) return CRYPTO_FAILED;
    cm = &cipher_map[ mech->cm_type ];

    if (cm->type == CIPHER_TYPE_AEAD)
        return crypto_encrypt_aead(mech, plaintext, key, tmpl,
                                   ciphertext, cr);

    if (cm->type == CIPHER_TYPE_BLK)
        return crypto_encrypt_blk(mech, plaintext, key, tmpl,
                                  ciphertext, cr);

    return CRYPTO_FAILED;
}

int crypto_decrypt(crypto_mechanism_t *mech, crypto_data_t *ciphertext,
                   crypto_key_t *key, crypto_ctx_template_t tmpl,
                   crypto_data_t *plaintext, crypto_call_req_t *cr)
{
    cipher_map_t *cm = NULL;

    if (mech->cm_type >= NUM_CIPHER_MAP) return CRYPTO_FAILED;
    cm = &cipher_map[ mech->cm_type ];

    if (cm->type == CIPHER_TYPE_AEAD)
        return crypto_decrypt_aead(mech, ciphertext, key, tmpl,
                                   plaintext, cr);

    if (cm->type == CIPHER_TYPE_BLK)
        return crypto_decrypt_blk(mech, ciphertext, key, tmpl,
                                  plaintext, cr);

    return CRYPTO_FAILED;
}





int crypto_create_ctx_template(crypto_mechanism_t *mech,
    crypto_key_t *key, crypto_ctx_template_t *tmpl, int kmflag)
{
    return 0;
}

void crypto_destroy_ctx_template(crypto_ctx_template_t tmpl)
{
    return;
}


/*
 *
 * This function maps between Solaris cipher string, and Linux cipher string.
 * It is always used as 'early test' on cipher availability, so we include
 * testing the cipher here.
 *
 */
crypto_mech_type_t crypto_mech2id(crypto_mech_name_t name)
{
    int i;

    if (!name || !*name)
        return CRYPTO_MECH_INVALID;

#ifdef ZFS_CRYPTO_VERBOSE
#if _KERNEL
    printk("called crypto_mech2id '%s' (total %d)\n", name, (int)NUM_CIPHER_MAP);
#endif
#endif

    for (i = 0; i < NUM_CIPHER_MAP; i++) {

        if (cipher_map[i].solaris_name &&
            !strcmp(cipher_map[i].solaris_name, name)) {

            // Do we test the cipher?
            if (!cipher_map[i].power_on_test) {

                // Test it only once
                cipher_map[i].power_on_test = 1;

                if (cipher_map[i].type == CIPHER_TYPE_AEAD) {

                    /* AEAD cipher test */
                    struct crypto_aead  *tfm = NULL;
                    tfm = crypto_alloc_aead(cipher_map[i].linux_name, 0, 0);
                    if (!tfm || IS_ERR(tfm)) {
                        printk("spl-crypto: No such AEAD cipher '%s'.\nPlease ensure the correct kernel modules has been loaded,\nLinux name '%s'\n",
                               cipher_map[i].solaris_name,
                               cipher_map[i].linux_name);
                        return CRYPTO_MECH_INVALID;
                    }

                    crypto_free_aead(tfm);
                    printk("spl-crypto: Cipher test '%s' -> '%s' successful.\n",
                           cipher_map[i].solaris_name,
                           cipher_map[i].linux_name);


                    // Both linux_name and hmac_name set means BLKCIPHER
                } else if (cipher_map[i].type == CIPHER_TYPE_BLK) {

                    /* ablkcipher test */
                    struct crypto_ablkcipher *tfm = NULL;
                    tfm = crypto_alloc_ablkcipher(cipher_map[i].linux_name, 0, 0);
                    if (!tfm || IS_ERR(tfm)) {
                        printk("spl-crypto: No such blkcipher '%s'.\nPlease ensure the correct kernel modules has been loaded,\nLinux name '%s'\n",
                               cipher_map[i].solaris_name,
                               cipher_map[i].linux_name);
                        return CRYPTO_MECH_INVALID;
                    }
                    crypto_free_ablkcipher(tfm);

                    // linux_name = NULL, and hmac_name set means just MAC
                } else if (cipher_map[i].type == CIPHER_TYPE_MAC) {

                    struct crypto_hash *htfm = NULL;
                    htfm = crypto_alloc_hash(cipher_map[i].hmac_name, 0, 0);
                    if (!htfm || IS_ERR(htfm)) {
                        printk("spl-crypto: No such MAC '%s'.\nPlease ensure the correct kernel modules has been loaded,\nLinux name '%s'\n",
                               cipher_map[i].solaris_name,
                               cipher_map[i].hmac_name);
                        return CRYPTO_MECH_INVALID;
                    }
                    crypto_free_hash(htfm);

                    // Both are NULL is a failure.
                } else {
                    return CRYPTO_MECH_INVALID;
                }

            }

            return i; // Index into list.
        }
    } // for all cipher maps

    printk("spl-crypto: mac2id returning INVALID\n");
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




