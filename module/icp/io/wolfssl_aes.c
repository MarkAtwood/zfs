// SPDX-License-Identifier: CDDL-1.0
/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or https://opensource.org/licenses/CDDL-1.0.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * CDDL HEADER END
 */
/*
 * Copyright (c) 2026, wolfSSL Inc. All rights reserved.
 *
 * wolfSSL-based AES-GCM/CCM provider for the OpenZFS ICP crypto framework.
 *
 * This file replaces aes.c when wolfSSL is enabled (HAVE_WOLFSSL).
 * It implements the same crypto_ops_t provider interface but delegates all
 * AES-GCM and AES-CCM operations to the wolfSSL kernel module
 * (libwolfssl.ko).
 */

#ifdef HAVE_WOLFSSL

#include <sys/zfs_context.h>
#include <sys/crypto/common.h>
#include <sys/crypto/impl.h>
#include <sys/crypto/spi.h>
#include <sys/crypto/icp.h>

/*
 * Include the ICP AES header for mechanism type enum and key size constants.
 * _AES_IMPL exposes the aes_mech_type_t enum (AES_CCM_MECH_INFO_TYPE,
 * AES_GCM_MECH_INFO_TYPE) which must match the values used by the KCF
 * mechanism table.
 */
#define	_AES_IMPL
#include <aes/aes_impl.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/aes.h>

/*
 * wolfSSL context template: a pre-initialized Aes object with key schedule.
 * Stored as the crypto_spi_ctx_template_t by create_ctx_template().
 *
 * The wolfSSL Aes struct is memcpy-safe: it contains only value types
 * (key schedule arrays, counters) and no self-referential pointers.
 */
typedef struct wolfssl_aes_tmpl {
	Aes		wt_aes;
	uint_t		wt_keylen;	/* key length in bytes */
	aes_mech_type_t	wt_mech;	/* mechanism that set the key */
} wolfssl_aes_tmpl_t;

/* ------------------------------------------------------------------ */
/*  Mechanism info table -- registered with KCF                       */
/* ------------------------------------------------------------------ */

static const crypto_mech_info_t aes_mech_info_tab[] = {
	{SUN_CKM_AES_CCM, AES_CCM_MECH_INFO_TYPE,
	    CRYPTO_FG_ENCRYPT_ATOMIC | CRYPTO_FG_DECRYPT_ATOMIC},
	{SUN_CKM_AES_GCM, AES_GCM_MECH_INFO_TYPE,
	    CRYPTO_FG_ENCRYPT_ATOMIC | CRYPTO_FG_DECRYPT_ATOMIC},
};

/* Forward declarations */
static int aes_encrypt_atomic(crypto_mechanism_t *, crypto_key_t *,
    crypto_data_t *, crypto_data_t *, crypto_spi_ctx_template_t);
static int aes_decrypt_atomic(crypto_mechanism_t *, crypto_key_t *,
    crypto_data_t *, crypto_data_t *, crypto_spi_ctx_template_t);
static int aes_create_ctx_template(crypto_mechanism_t *, crypto_key_t *,
    crypto_spi_ctx_template_t *, size_t *);
static int aes_free_context(crypto_ctx_t *);

static const crypto_cipher_ops_t aes_cipher_ops = {
	.encrypt_atomic = aes_encrypt_atomic,
	.decrypt_atomic = aes_decrypt_atomic
};

static const crypto_ctx_ops_t aes_ctx_ops = {
	.create_ctx_template = aes_create_ctx_template,
	.free_context = aes_free_context
};

static const crypto_ops_t aes_crypto_ops = {
	&aes_cipher_ops,
	NULL,
	&aes_ctx_ops,
};

static const crypto_provider_info_t aes_prov_info = {
	"AES Software Provider (wolfSSL)",
	&aes_crypto_ops,
	sizeof (aes_mech_info_tab) / sizeof (crypto_mech_info_t),
	aes_mech_info_tab
};

static crypto_kcf_provider_handle_t aes_prov_handle = 0;

/* ------------------------------------------------------------------ */
/*  Helper: validate key length                                       */
/* ------------------------------------------------------------------ */

static int
wolfssl_aes_check_key(crypto_key_t *key)
{
	if (key->ck_length < AES_MINBITS ||
	    key->ck_length > AES_MAXBITS)
		return (CRYPTO_KEY_SIZE_RANGE);

	/* Must be 128, 192, or 256 bits */
	if ((key->ck_length & 63) != 0)
		return (CRYPTO_KEY_SIZE_RANGE);

	return (CRYPTO_SUCCESS);
}

/* ------------------------------------------------------------------ */
/*  Helper: read crypto_data_t into a contiguous buffer               */
/* ------------------------------------------------------------------ */

/*
 * Copy 'len' bytes starting at cd_offset from a crypto_data_t into 'buf'.
 * Primarily used for CRYPTO_DATA_UIO linearization; RAW data is normally
 * accessed directly via the fast path in the encrypt/decrypt functions.
 */
static int
wolfssl_crypto_data_read(crypto_data_t *cd, uchar_t *buf, size_t len)
{
	switch (cd->cd_format) {
	case CRYPTO_DATA_RAW:
		memcpy(buf,
		    (uchar_t *)cd->cd_raw.iov_base + cd->cd_offset, len);
		return (CRYPTO_SUCCESS);

	case CRYPTO_DATA_UIO: {
		zfs_uio_t *uiop = cd->cd_uio;
		off_t offset = cd->cd_offset;
		size_t remaining = len;
		uint_t vec_idx = 0;

		if (zfs_uio_segflg(uiop) != UIO_SYSSPACE)
			return (CRYPTO_ARGUMENTS_BAD);

		offset = zfs_uio_index_at_offset(uiop, offset, &vec_idx);

		while (vec_idx < zfs_uio_iovcnt(uiop) && remaining > 0) {
			size_t cur = MIN(zfs_uio_iovlen(uiop, vec_idx) -
			    offset, remaining);
			memcpy(buf,
			    (uchar_t *)zfs_uio_iovbase(uiop, vec_idx) +
			    offset, cur);
			buf += cur;
			remaining -= cur;
			vec_idx++;
			offset = 0;
		}

		if (remaining > 0)
			return (CRYPTO_DATA_LEN_RANGE);
		return (CRYPTO_SUCCESS);
	}
	default:
		return (CRYPTO_ARGUMENTS_BAD);
	}
}

/* ------------------------------------------------------------------ */
/*  Helper: initialise a wolfSSL Aes object (from template or key)    */
/* ------------------------------------------------------------------ */

static int
wolfssl_aes_setup(crypto_key_t *key, aes_mech_type_t mech,
    crypto_spi_ctx_template_t tmpl, Aes **aes_out)
{
	Aes *aes;
	int ret;

	aes = (Aes *)kmem_alloc(sizeof (Aes), KM_SLEEP);

	if (tmpl != NULL) {
		wolfssl_aes_tmpl_t *t = (wolfssl_aes_tmpl_t *)tmpl;
		memcpy(aes, &t->wt_aes, sizeof (Aes));
	} else {
		uint_t keylen = CRYPTO_BITS2BYTES(key->ck_length);

		ret = wc_AesInit(aes, NULL, INVALID_DEVID);
		if (ret != 0) {
			kmem_free(aes, sizeof (Aes));
			return (CRYPTO_FAILED);
		}

		switch (mech) {
		case AES_GCM_MECH_INFO_TYPE:
			ret = wc_AesGcmSetKey(aes,
			    (const byte *)key->ck_data, keylen);
			break;
		case AES_CCM_MECH_INFO_TYPE:
			ret = wc_AesCcmSetKey(aes,
			    (const byte *)key->ck_data, keylen);
			break;
		default:
			wc_AesFree(aes);
			kmem_free(aes, sizeof (Aes));
			return (CRYPTO_MECHANISM_INVALID);
		}

		if (ret != 0) {
			wc_AesFree(aes);
			kmem_free(aes, sizeof (Aes));
			return (CRYPTO_KEY_SIZE_RANGE);
		}
	}

	*aes_out = aes;
	return (CRYPTO_SUCCESS);
}

static void
wolfssl_aes_teardown(Aes *aes)
{
	if (aes != NULL) {
		wc_AesFree(aes);
		memset(aes, 0, sizeof (Aes));
		kmem_free(aes, sizeof (Aes));
	}
}

/* ------------------------------------------------------------------ */
/*  KCF provider encrypt / decrypt entry points                       */
/* ------------------------------------------------------------------ */

/*
 * Encrypt plaintext using AES-GCM or AES-CCM via wolfSSL.
 *
 * Both modes share the same structure: extract IV/AAD/tag-length from
 * the mechanism parameters, encrypt the data, and append the auth tag.
 * The two wolfSSL calls (wc_AesGcmEncrypt / wc_AesCcmEncrypt) have
 * identical signatures, so only the dispatch differs.
 */
static int
aes_encrypt_atomic(crypto_mechanism_t *mechanism,
    crypto_key_t *key, crypto_data_t *plaintext, crypto_data_t *ciphertext,
    crypto_spi_ctx_template_t tmpl)
{
	Aes *aes = NULL;
	uchar_t *ptbuf = NULL, *ctbuf = NULL;
	uchar_t tag[AES_BLOCK_LEN];
	boolean_t pt_alloc = B_FALSE, ct_alloc = B_FALSE;
	const uchar_t *iv, *aad;
	size_t ptlen, ivlen, aadlen, taglen, need;
	int rv;

	ASSERT(ciphertext != NULL);

	ptlen = plaintext->cd_length;

	/* Extract mode-specific parameters into common locals */
	switch (mechanism->cm_type) {
	case AES_GCM_MECH_INFO_TYPE: {
		CK_AES_GCM_PARAMS *p;
		if (mechanism->cm_param == NULL ||
		    mechanism->cm_param_len != sizeof (CK_AES_GCM_PARAMS))
			return (CRYPTO_MECHANISM_PARAM_INVALID);
		p = (CK_AES_GCM_PARAMS *)(void *)mechanism->cm_param;
		iv = p->pIv;
		ivlen = p->ulIvLen;
		aad = p->pAAD;
		aadlen = p->ulAADLen;
		taglen = p->ulTagBits / 8;
		break;
	}
	case AES_CCM_MECH_INFO_TYPE: {
		CK_AES_CCM_PARAMS *p;
		if (mechanism->cm_param == NULL ||
		    mechanism->cm_param_len != sizeof (CK_AES_CCM_PARAMS))
			return (CRYPTO_MECHANISM_PARAM_INVALID);
		p = (CK_AES_CCM_PARAMS *)(void *)mechanism->cm_param;
		iv = p->nonce;
		ivlen = p->ulNonceSize;
		aad = p->authData;
		aadlen = p->ulAuthDataSize;
		taglen = p->ulMACSize;
		break;
	}
	default:
		return (CRYPTO_MECHANISM_INVALID);
	}

	need = ptlen + taglen;

	if (ciphertext->cd_length < need) {
		ciphertext->cd_length = need;
		return (CRYPTO_BUFFER_TOO_SMALL);
	}

	rv = wolfssl_aes_check_key(key);
	if (rv != CRYPTO_SUCCESS)
		return (rv);

	rv = wolfssl_aes_setup(key, mechanism->cm_type, tmpl, &aes);
	if (rv != CRYPTO_SUCCESS)
		return (rv);

	/* Input: use pointer directly for RAW, linearize for UIO */
	if (plaintext->cd_format == CRYPTO_DATA_RAW) {
		ptbuf = (uchar_t *)plaintext->cd_raw.iov_base +
		    plaintext->cd_offset;
	} else {
		ptbuf = (uchar_t *)vmem_alloc(ptlen, KM_SLEEP);
		pt_alloc = B_TRUE;
		rv = wolfssl_crypto_data_read(plaintext, ptbuf, ptlen);
		if (rv != CRYPTO_SUCCESS)
			goto out;
	}

	/* Output: encrypt directly into RAW buffer, temp buffer for UIO */
	if (ciphertext->cd_format == CRYPTO_DATA_RAW) {
		ctbuf = (uchar_t *)ciphertext->cd_raw.iov_base +
		    ciphertext->cd_offset;
	} else {
		ctbuf = (uchar_t *)vmem_alloc(ptlen, KM_SLEEP);
		ct_alloc = B_TRUE;
	}

	/* Dispatch to the appropriate wolfSSL encrypt function */
	{
		int ret;

		if (mechanism->cm_type == AES_GCM_MECH_INFO_TYPE)
			ret = wc_AesGcmEncrypt(aes, ctbuf, ptbuf, ptlen,
			    iv, ivlen, tag, taglen, aad, aadlen);
		else
			ret = wc_AesCcmEncrypt(aes, ctbuf, ptbuf, ptlen,
			    iv, ivlen, tag, taglen, aad, aadlen);

		if (ret != 0) {
			rv = CRYPTO_FAILED;
			goto out;
		}
	}

	/* Write output: append tag after ciphertext */
	if (!ct_alloc) {
		/*
		 * RAW: ciphertext is already in the output buffer.
		 * Just append the auth tag after it.
		 */
		memcpy(ctbuf + ptlen, tag, taglen);
		ciphertext->cd_length = need;
	} else {
		/*
		 * UIO: copy ciphertext and tag from temp buffers
		 * into the scatter-gather output.
		 */
		off_t saved_offset = ciphertext->cd_offset;

		rv = crypto_put_output_data(ctbuf, ciphertext, ptlen);
		if (rv == CRYPTO_SUCCESS) {
			ciphertext->cd_offset += ptlen;
			rv = crypto_put_output_data(tag, ciphertext, taglen);
		}
		if (rv == CRYPTO_SUCCESS) {
			ciphertext->cd_offset += taglen;
			ciphertext->cd_length =
			    ciphertext->cd_offset - saved_offset;
		}
		ciphertext->cd_offset = saved_offset;
	}

out:
	if (pt_alloc) {
		memset(ptbuf, 0, ptlen);
		vmem_free(ptbuf, ptlen);
	}
	if (ct_alloc)
		vmem_free(ctbuf, ptlen);
	wolfssl_aes_teardown(aes);
	return (rv);
}

/*
 * Decrypt ciphertext using AES-GCM or AES-CCM via wolfSSL.
 *
 * The plaintext output always goes through a temporary buffer so that
 * unauthenticated data is never exposed to the caller on auth failure.
 */
static int
aes_decrypt_atomic(crypto_mechanism_t *mechanism,
    crypto_key_t *key, crypto_data_t *ciphertext, crypto_data_t *plaintext,
    crypto_spi_ctx_template_t tmpl)
{
	Aes *aes = NULL;
	uchar_t *inbuf = NULL, *ptbuf = NULL;
	boolean_t in_alloc = B_FALSE;
	const uchar_t *iv, *aad;
	size_t ivlen, aadlen, taglen, ctlen, inlen, pt_need;
	int rv;

	ASSERT(plaintext != NULL);

	inlen = ciphertext->cd_length;

	/* Extract mode-specific parameters into common locals */
	switch (mechanism->cm_type) {
	case AES_GCM_MECH_INFO_TYPE: {
		CK_AES_GCM_PARAMS *p;
		if (mechanism->cm_param == NULL ||
		    mechanism->cm_param_len != sizeof (CK_AES_GCM_PARAMS))
			return (CRYPTO_MECHANISM_PARAM_INVALID);
		p = (CK_AES_GCM_PARAMS *)(void *)mechanism->cm_param;
		iv = p->pIv;
		ivlen = p->ulIvLen;
		aad = p->pAAD;
		aadlen = p->ulAADLen;
		taglen = p->ulTagBits / 8;
		pt_need = inlen - taglen;
		break;
	}
	case AES_CCM_MECH_INFO_TYPE: {
		CK_AES_CCM_PARAMS *p;
		if (mechanism->cm_param == NULL ||
		    mechanism->cm_param_len != sizeof (CK_AES_CCM_PARAMS))
			return (CRYPTO_MECHANISM_PARAM_INVALID);
		p = (CK_AES_CCM_PARAMS *)(void *)mechanism->cm_param;
		iv = p->nonce;
		ivlen = p->ulNonceSize;
		aad = p->authData;
		aadlen = p->ulAuthDataSize;
		taglen = p->ulMACSize;
		pt_need = p->ulDataSize;
		break;
	}
	default:
		return (CRYPTO_MECHANISM_INVALID);
	}

	if (inlen < taglen)
		return (CRYPTO_ENCRYPTED_DATA_LEN_RANGE);

	ctlen = inlen - taglen;

	if (plaintext->cd_length < pt_need) {
		plaintext->cd_length = pt_need;
		return (CRYPTO_BUFFER_TOO_SMALL);
	}

	rv = wolfssl_aes_check_key(key);
	if (rv != CRYPTO_SUCCESS)
		return (rv);

	rv = wolfssl_aes_setup(key, mechanism->cm_type, tmpl, &aes);
	if (rv != CRYPTO_SUCCESS)
		return (rv);

	/* Input: use pointer directly for RAW, linearize for UIO */
	if (ciphertext->cd_format == CRYPTO_DATA_RAW) {
		inbuf = (uchar_t *)ciphertext->cd_raw.iov_base +
		    ciphertext->cd_offset;
	} else {
		inbuf = (uchar_t *)vmem_alloc(inlen, KM_SLEEP);
		in_alloc = B_TRUE;
		rv = wolfssl_crypto_data_read(ciphertext, inbuf, inlen);
		if (rv != CRYPTO_SUCCESS)
			goto out;
	}

	/*
	 * Output: always use a temp buffer so unauthenticated plaintext
	 * is never exposed to the caller on auth failure.
	 */
	ptbuf = (uchar_t *)vmem_alloc(ctlen, KM_SLEEP);

	/* Dispatch to the appropriate wolfSSL decrypt function */
	{
		int ret;

		if (mechanism->cm_type == AES_GCM_MECH_INFO_TYPE)
			ret = wc_AesGcmDecrypt(aes, ptbuf, inbuf, ctlen,
			    iv, ivlen, inbuf + ctlen, taglen, aad, aadlen);
		else
			ret = wc_AesCcmDecrypt(aes, ptbuf, inbuf, ctlen,
			    iv, ivlen, inbuf + ctlen, taglen, aad, aadlen);

		if (ret != 0) {
			rv = CRYPTO_INVALID_MAC;
			goto out;
		}
	}

	/* Write authenticated plaintext to output */
	{
		off_t saved_offset = plaintext->cd_offset;

		rv = crypto_put_output_data(ptbuf, plaintext, ctlen);
		if (rv == CRYPTO_SUCCESS) {
			plaintext->cd_offset += ctlen;
			plaintext->cd_length =
			    plaintext->cd_offset - saved_offset;
		}
		plaintext->cd_offset = saved_offset;
	}

out:
	if (in_alloc)
		vmem_free(inbuf, inlen);
	if (ptbuf != NULL) {
		memset(ptbuf, 0, ctlen);
		vmem_free(ptbuf, ctlen);
	}
	wolfssl_aes_teardown(aes);
	return (rv);
}

/* ------------------------------------------------------------------ */
/*  KCF provider context template entry points                        */
/* ------------------------------------------------------------------ */

/*
 * Create a context template: pre-compute the AES key schedule so that
 * subsequent encrypt/decrypt calls can skip wc_Aes{Gcm,Ccm}SetKey().
 */
static int
aes_create_ctx_template(crypto_mechanism_t *mechanism, crypto_key_t *key,
    crypto_spi_ctx_template_t *tmpl, size_t *tmpl_size)
{
	wolfssl_aes_tmpl_t *t;
	uint_t keylen;
	int ret, rv;

	if (mechanism->cm_type != AES_CCM_MECH_INFO_TYPE &&
	    mechanism->cm_type != AES_GCM_MECH_INFO_TYPE)
		return (CRYPTO_MECHANISM_INVALID);

	rv = wolfssl_aes_check_key(key);
	if (rv != CRYPTO_SUCCESS)
		return (rv);

	keylen = CRYPTO_BITS2BYTES(key->ck_length);

	t = (wolfssl_aes_tmpl_t *)kmem_alloc(sizeof (*t), KM_SLEEP);
	memset(t, 0, sizeof (*t));

	ret = wc_AesInit(&t->wt_aes, NULL, INVALID_DEVID);
	if (ret != 0) {
		kmem_free(t, sizeof (*t));
		return (CRYPTO_FAILED);
	}

	switch (mechanism->cm_type) {
	case AES_GCM_MECH_INFO_TYPE:
		ret = wc_AesGcmSetKey(&t->wt_aes,
		    (const byte *)key->ck_data, keylen);
		break;
	case AES_CCM_MECH_INFO_TYPE:
		ret = wc_AesCcmSetKey(&t->wt_aes,
		    (const byte *)key->ck_data, keylen);
		break;
	default:
		wc_AesFree(&t->wt_aes);
		kmem_free(t, sizeof (*t));
		return (CRYPTO_MECHANISM_INVALID);
	}

	if (ret != 0) {
		wc_AesFree(&t->wt_aes);
		kmem_free(t, sizeof (*t));
		return (CRYPTO_KEY_SIZE_RANGE);
	}

	t->wt_keylen = keylen;
	t->wt_mech = (aes_mech_type_t)mechanism->cm_type;

	*tmpl = t;
	*tmpl_size = sizeof (*t);

	return (CRYPTO_SUCCESS);
}

static int
aes_free_context(crypto_ctx_t *ctx)
{
	wolfssl_aes_tmpl_t *t = (wolfssl_aes_tmpl_t *)ctx->cc_provider_private;

	if (t != NULL) {
		wc_AesFree(&t->wt_aes);
		memset(t, 0, sizeof (*t));
		kmem_free(t, sizeof (*t));
		ctx->cc_provider_private = NULL;
	}

	return (CRYPTO_SUCCESS);
}

/* ------------------------------------------------------------------ */
/*  Module init / fini                                                */
/* ------------------------------------------------------------------ */

int
aes_mod_init(void)
{
	if (crypto_register_provider(&aes_prov_info, &aes_prov_handle))
		return (EACCES);

	return (0);
}

int
aes_mod_fini(void)
{
	if (aes_prov_handle != 0) {
		if (crypto_unregister_provider(aes_prov_handle))
			return (EBUSY);

		aes_prov_handle = 0;
	}

	return (0);
}

#endif /* HAVE_WOLFSSL */
