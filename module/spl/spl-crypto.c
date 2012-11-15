#include <sys/crypto/api.h>
#include <sys/cmn_err.h>

#include <linux/scatterlist.h>
#include <linux/crypto.h>


int crypto_mac(crypto_mechanism_t *mech, crypto_data_t *data,
               crypto_key_t *key, crypto_ctx_template_t tmpl, crypto_data_t *mac,
               crypto_call_req_t *cr)
{
#if _KERNEL
    printk("crypto_mac\n");
#endif
    return 0;
}



int crypto_decryptX(crypto_mechanism_t *mech, crypto_data_t *ciphertext,
                   crypto_key_t *key, crypto_ctx_template_t tmpl,
                   crypto_data_t *plaintext, crypto_call_req_t *cr)
{
#if _KERNEL
    unsigned char *src;
    unsigned char *dst;
    size_t len = 0;
    int i;

    if (ciphertext->cd_format != CRYPTO_DATA_RAW) {
        printk("crypto_decrypt  cd_format is NOT RAW?! %d\n", ciphertext->cd_format);
        return -1;
    }

    if (plaintext && plaintext->cd_format != CRYPTO_DATA_RAW) {
        printk("crypto_decrypt  cd_format is NOT RAW?! %d\n", plaintext->cd_format);
        return -1;
    }

    src = (unsigned char *)ciphertext->cd_raw.iov_base;
    len = (size_t) ciphertext->cd_raw.iov_len;

    if (plaintext && plaintext->cd_raw.iov_base)
        dst = (unsigned char *)plaintext->cd_raw.iov_base;
    else
        dst = src;

    printk("crypto_decrypt (%p -> %p) 0x%04lx\n",
           src, dst, (unsigned long)len);

    for (i = 0; i < len; i++)
        //dst[i] = isalpha(src[i]) ? src[i]^0x20 : src[i];
        dst[i] = src[i];

    // Notify caller.
    if (cr && cr->cr_callback_func) {
        printk("   notifying caller\n");
        cr->cr_callback_func(cr->cr_callback_arg, cr->cr_reqid);
        return CRYPTO_QUEUED;
    }

#endif
    return CRYPTO_SUCCESS;
}

int crypto_decryptXXX(crypto_mechanism_t *mech, crypto_data_t *ciphertext,
    crypto_key_t *key, crypto_ctx_template_t tmpl, crypto_data_t *plaintext,
    crypto_call_req_t *cr)
{
#if _KERNEL
    unsigned char *src;
    unsigned char *dst;
    size_t len = 0;
    int i;
    unsigned int numiov = 0, curriov = 0, iovlen = 0;
    uio_t *srcuio = NULL;
    iovec_t *srciov = NULL;

    // Decrypt, we will get UIO -> RAW
    printk("crypto_decrypt  ciphertext cd_format %d, plaintext %d\n",
           ciphertext->cd_format, plaintext->cd_format);

    // DST is always RAW
    if (plaintext->cd_format != CRYPTO_DATA_RAW) {
        printk("crypto_decrypt  cd_format is NOT RAW?! %d\n", plaintext->cd_format);
        return CRYPTO_FAILED;
    }

    // SRC can be RAW, or UIO
    if ((plaintext->cd_format == CRYPTO_DATA_UIO) &&
        (plaintext->cd_uio->uio_segflg == UIO_USERSPACE)) {
        printk("crypto_decrypt  cipher cd_format is UIO?! segment is %s!!!\n",
               ciphertext->cd_uio->uio_segflg == UIO_USERSPACE ? "user" : "system");
        return CRYPTO_FAILED;
    }

    // We dont support MBLK at all
    if (plaintext->cd_format == CRYPTO_DATA_MBLK) {
        printk("crypto_decrypt  cipher cd_format is MBLK?!\n");
        return CRYPTO_FAILED;
    }

    // We do not handle callbacks (so far they've not been needed)
    if (cr != NULL) {
      printk("crypto_decrypt with callback request not supported\n");
      return CRYPTO_FAILED;
    }

    dst = (unsigned char *)plaintext->cd_raw.iov_base;
    len = (size_t) plaintext->cd_length;

    if (ciphertext && ciphertext->cd_raw.iov_base)
        src = (unsigned char *)ciphertext->cd_raw.iov_base;
    else
        src = dst;

    if (ciphertext->cd_format == CRYPTO_DATA_UIO) {
      srcuio = ciphertext->cd_uio;
      numiov = srcuio->uio_iovcnt;
      curriov = 0;
      iovlen = 0; // Forces read of first iov.
      srciov = srcuio->uio_iov;
      printk("crypto_decrypt: UIO :  with %u iovs: total 0x%04lx/0x%04lx\n",
             numiov,
             (unsigned long)len,
             (unsigned long)plaintext->cd_raw.iov_len);
    }

    if (numiov == 0) {
      printk("crypto_decrypt (%p -> %p) 0x%04lx/0x%04lx (offset 0x%04lx: numiov %u)\n",
	     src, dst,
             (unsigned long)len,
             (unsigned long)plaintext->cd_raw.iov_len,
             (unsigned long)plaintext->cd_offset,
             numiov);
    }

    for (i = 0; i < len; i++) {

        if (numiov && !iovlen) { // uses UIO, and ran out of space, move to next

            src = srciov[ curriov ].iov_base;
            iovlen = srciov[ curriov ].iov_len;

            printk("crypto_decrypt IOV (%p -> %p) curriov %u, iovlen 0x%04lx\n",
                   src, dst, curriov, (unsigned long)iovlen);

            curriov++; // Ready next.
            if (curriov >= numiov) { // out of dst space
                if (i < len) printk("crypto_decrypt ran outof dst space before src i=%d\n", i);
                break;
            }
        } // if numiov

        // ENCRYPT!
        dst[i] = isalpha(src[i]) ? src[i]^0x20 : src[i];
        // dst[i] = src[i];

        // Decrease UIO, if used
        if (iovlen) iovlen--;
    }

    printk("crypto_decrypt: done\n");
    return CRYPTO_SUCCESS;
#endif
    ASSERT(1==0);
    return CRYPTO_FAILED;
}


// So far, ZFS-crypto only uses 2 buffers. data + mac
#define SPL_CRYPTO_MAX_BUF 2


size_t crypto_map_buffers(crypto_data_t *solaris_buffer,
                       struct scatterlist linux_buffer[SPL_CRYPTO_MAX_BUF])
{
    uio_t *uio = NULL;
    iovec_t *iov = NULL;
    int i;
    size_t len = 0;

    // Setup SOURCE buffer(s)
    switch(solaris_buffer->cd_format) {
    case CRYPTO_DATA_RAW: // One buffer.
        sg_init_table(linux_buffer, 1 );
        sg_set_buf(&linux_buffer[0],
                   solaris_buffer->cd_raw.iov_base, // srcptr
                   solaris_buffer->cd_length);      // srclen
        printk("spl-crypto: mapping buffer to RAW->1 %p len 0x%04lx.\n",
               solaris_buffer->cd_raw.iov_base, solaris_buffer->cd_length);
        return solaris_buffer->cd_length;

    case CRYPTO_DATA_UIO: // Multiple buffers.
        uio = solaris_buffer->cd_uio;
        iov = uio->uio_iov;
        ASSERT( uio->uio_iovcnt <= SPL_CRYPTO_MAX_BUF );
        sg_init_table(linux_buffer, uio->uio_iovcnt );
        for (i = 0; i < uio->uio_iovcnt; i++) {
            sg_set_buf(&linux_buffer[i],
                        iov[i].iov_base,
                        iov[i].iov_len);
            printk("spl-crypto: mapping buffer %d to UIO->%d. %p len 0x%04lx\n",
                   i, uio->uio_iovcnt, iov[i].iov_base, iov[i].iov_len );
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

    printk("cipher_work_done called: %d\n", err);

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
    struct scatterlist linux_plain[SPL_CRYPTO_MAX_BUF];
    struct scatterlist linux_cipher[SPL_CRYPTO_MAX_BUF];
    size_t plainlen = 0, cryptlen = 0, maclen = 0;
    unsigned char iv[16];
    unsigned char assoc[16];
    struct scatterlist assoctext[1];

    printk("spl-crypto: enter\n");

    ASSERT(mech != NULL);

    // We don't use assoc, but it appears it needs to be supplied.
    memset(assoc, 0, sizeof(assoc));
    sg_init_one(&assoctext[0], assoc, sizeof(assoc));

    ASSERT(key->ck_format == CRYPTO_KEY_RAW);

    // Use source len as cryptolen.
    if (!(plainlen = crypto_map_buffers(plaintext, linux_plain)))
        return CRYPTO_FAILED;
    if (!(cryptlen = crypto_map_buffers(ciphertext, linux_cipher)))
        return CRYPTO_FAILED;

    // What is the size of the MAC buffer?
    maclen = cryptlen - plainlen;

    printk("spl-crypto: buffers set, len 0x%04lx / 0x%04lx (mac %ld)\n",
           plainlen, cryptlen, maclen);

    // This gets us a valid cipher, but the MAC differs from Solaris 'mac(sha256)'
    tfm = crypto_alloc_aead("ccm(aes)", 0, 0);
    if (IS_ERR(tfm)) return CRYPTO_FAILED;

    printk("spl-crypto: aead alloc OK\n");

    req = aead_request_alloc(tfm, GFP_KERNEL);
    if (!req) goto out;

    printk("spl-crypto: req alloc OK\n");

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

    printk("spl-crypto: calling encrypt(0x%04lx)\n", plainlen);

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

 out:
    if (req) aead_request_free(req);
    if (!IS_ERR(tfm)) crypto_free_aead(tfm);

    printk("spl-crypto: encrypt done: ret %d\n", ret);
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
    struct scatterlist linux_plain[SPL_CRYPTO_MAX_BUF];
    struct scatterlist linux_cipher[SPL_CRYPTO_MAX_BUF];
    size_t cryptlen = 0, plainlen = 0, maclen = 0;
    unsigned char iv[16];
    unsigned char assoc[16];
    struct scatterlist assoctext[1];

    printk("spl-crypto: decrypt enter\n");

    ASSERT(mech != NULL);

    // We don't use assoc, but it appears it needs to be supplied.
    memset(assoc, 0, sizeof(assoc));
    sg_init_one(&assoctext[0], assoc, sizeof(assoc));

    ASSERT(key->ck_format == CRYPTO_KEY_RAW);

    // Use source len as cryptolen. If we are given two buffers here,
    // the cryptolen should be msglen + maclen. ie, 512 + 16, which
    // is what linux_decrypt expects to get
    if (!(plainlen = crypto_map_buffers(plaintext, linux_plain)))
        return CRYPTO_FAILED;
    if (!(cryptlen = crypto_map_buffers(ciphertext, linux_cipher)))
        return CRYPTO_FAILED;

    maclen = cryptlen - plainlen;

    printk("spl-crypto: buffers set, len 0x%04lx / 0x%04lx (mac %ld)\n",
           plainlen, cryptlen, maclen);

    // This gets us a valid cipher, but the MAC differs from Solaris 'mac(sha256)'
    tfm = crypto_alloc_aead("ccm(aes)", 0, 0);
    if (IS_ERR(tfm)) return CRYPTO_FAILED;

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

    printk("spl-crypt: calling decrypt(0x%04lx / 0x%04lx maclen %ld)\n",
           plainlen, cryptlen, maclen);

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

 out:
    if (req) aead_request_free(req);
    if (!IS_ERR(tfm)) crypto_free_aead(tfm);

    printk("spl-crypto: decrypt done.\n");
    return ret;
#endif
    ASSERT(1==0);
    return CRYPTO_FAILED;
}








int crypto_encryptOLD(crypto_mechanism_t *mech, crypto_data_t *plaintext,
    crypto_key_t *key, crypto_ctx_template_t tmpl, crypto_data_t *ciphertext,
    crypto_call_req_t *cr)
{
#if _KERNEL
    unsigned char *src;
    unsigned char *dst;
    size_t len = 0;
    int i;
    unsigned int numiov = 0, curriov = 0, iovlen = 0;
    uio_t *dstuio = NULL;
    iovec_t *dstiov = NULL;

    // SOURCE is always RAW
    if (plaintext->cd_format != CRYPTO_DATA_RAW) {
        printk("crypto_encrypt  cd_format is NOT RAW?! %d\n", plaintext->cd_format);
        return CRYPTO_FAILED;
    }

    // DST can be RAW, or UIO
    if ((ciphertext->cd_format == CRYPTO_DATA_UIO) &&
        (ciphertext->cd_uio->uio_segflg == UIO_USERSPACE)) {
        printk("crypto_encrypt  cipher cd_format is UIO?! segment is %s!!!\n",
               ciphertext->cd_uio->uio_segflg == UIO_USERSPACE ? "user" : "system");
        return CRYPTO_FAILED;
    }

    // We dont support MBLK at all
    if (ciphertext->cd_format == CRYPTO_DATA_MBLK) {
        printk("crypto_encrypt  cipher cd_format is MBLK?!\n");
        return CRYPTO_FAILED;
    }

    // We do not handle callbacks (so far they've not been needed)
    if (cr != NULL) {
      printk("cyrpto_encrypt with callback request not supported\n");
      return CRYPTO_FAILED;
    }

    src = (unsigned char *)plaintext->cd_raw.iov_base;
    len = (size_t) plaintext->cd_length;

    if (ciphertext && ciphertext->cd_raw.iov_base)
        dst = (unsigned char *)ciphertext->cd_raw.iov_base;
    else
        dst = src;

    if (ciphertext->cd_format == CRYPTO_DATA_UIO) {
      dstuio = ciphertext->cd_uio;
      numiov = dstuio->uio_iovcnt;
      curriov = 0;
      iovlen = 0; // Forces read of first iov.
      dstiov = dstuio->uio_iov;
      printk("crypto_encrypt: UIO :  with %u iovs: total 0x%04lx/0x%04lx\n",
             numiov,
             (unsigned long)len,
             (unsigned long)plaintext->cd_raw.iov_len);
    }

    if (numiov == 0) {
      printk("crypto_encrypt (%p -> %p) 0x%04lx/0x%04lx (offset 0x%04lx: numiov %u)\n",
	     src, dst,
             (unsigned long)len,
             (unsigned long)plaintext->cd_raw.iov_len,
             (unsigned long)plaintext->cd_offset,
             numiov);
    }

    for (i = 0; i < len; i++) {

        if (numiov && !iovlen) { // uses UIO, and ran out of space, move to next

            dst = dstiov[ curriov ].iov_base;
            iovlen = dstiov[ curriov ].iov_len;

            printk("crypto_encrypt IOV (%p -> %p) curriov %u, iovlen 0x%04lx\n",
                   src, dst, curriov, (unsigned long)iovlen);

            curriov++; // Ready next.
            if (curriov >= numiov) { // out of dst space
                if (i < len) printk("crypto_encrypt ran outof dst space before src i=%d\n", i);
                break;
            }
        } // if numiov

        // ENCRYPT!
        dst[i] = isalpha(src[i]) ? src[i]^0x20 : src[i];
        //dst[i] = src[i];

        // Decrease UIO, if used
        if (iovlen) iovlen--;
    }

    printk("spl-crypto encrypt: done\n");
    return CRYPTO_SUCCESS;
#endif
    ASSERT(1==0);
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

crypto_mech_type_t crypto_mech2id(crypto_mech_name_t name)
{
    if (!name || !*name)
        return CRYPTO_MECH_INVALID;

#if _KERNEL
    printk("called crypto_mech2id '%s'\n", name);
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




