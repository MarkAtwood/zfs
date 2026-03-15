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
 * wolfSSL-based SHA2 HMAC provider for the OpenZFS ICP crypto framework.
 *
 * This file replaces sha2_mod.c when wolfSSL is enabled, implementing
 * the crypto_mac_ops_t and crypto_ctx_ops_t provider interfaces using
 * wolfSSL kernel module HMAC APIs.
 *
 * Only SHA512-HMAC is registered.
 */

#ifdef HAVE_WOLFSSL

#include <sys/zfs_context.h>
#include <sys/crypto/common.h>
#include <sys/crypto/spi.h>
#include <sys/crypto/icp.h>
#include <sys/sha2.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/sha512.h>

/*
 * Context template: stores the raw key material so that mac_init can
 * quickly re-key a fresh Hmac without the caller having to pass the
 * key again.  We intentionally avoid copying wolfSSL internal Hmac
 * state, which may contain pointers or device-specific data.
 */
typedef struct sha2_hmac_tmpl {
	uint_t		ht_keylen;			/* bytes */
	uint8_t		ht_keybuf[SHA512_HMAC_BLOCK_SIZE];
} sha2_hmac_tmpl_t;

/*
 * Mechanism info structure passed to KCF during registration.
 */
static const crypto_mech_info_t sha2_mech_info_tab[] = {
	{SUN_CKM_SHA512_HMAC, SHA512_HMAC_MECH_INFO_TYPE,
	    CRYPTO_FG_MAC | CRYPTO_FG_MAC_ATOMIC},
};

/* Forward declarations */
static int sha2_mac_init(crypto_ctx_t *, crypto_mechanism_t *, crypto_key_t *,
    crypto_spi_ctx_template_t);
static int sha2_mac_update(crypto_ctx_t *, crypto_data_t *);
static int sha2_mac_final(crypto_ctx_t *, crypto_data_t *);
static int sha2_mac_atomic(crypto_mechanism_t *, crypto_key_t *,
    crypto_data_t *, crypto_data_t *, crypto_spi_ctx_template_t);
static int sha2_mac_verify_atomic(crypto_mechanism_t *, crypto_key_t *,
    crypto_data_t *, crypto_data_t *, crypto_spi_ctx_template_t);

static const crypto_mac_ops_t sha2_mac_ops = {
	.mac_init = sha2_mac_init,
	.mac = NULL,
	.mac_update = sha2_mac_update,
	.mac_final = sha2_mac_final,
	.mac_atomic = sha2_mac_atomic,
	.mac_verify_atomic = sha2_mac_verify_atomic
};

static int sha2_create_ctx_template(crypto_mechanism_t *, crypto_key_t *,
    crypto_spi_ctx_template_t *, size_t *);
static int sha2_free_context(crypto_ctx_t *);

static const crypto_ctx_ops_t sha2_ctx_ops = {
	.create_ctx_template = sha2_create_ctx_template,
	.free_context = sha2_free_context
};

static const crypto_ops_t sha2_crypto_ops = {
	NULL,
	&sha2_mac_ops,
	&sha2_ctx_ops,
};

static const crypto_provider_info_t sha2_prov_info = {
	"SHA2 Software Provider (wolfSSL)",
	&sha2_crypto_ops,
	sizeof (sha2_mech_info_tab) / sizeof (crypto_mech_info_t),
	sha2_mech_info_tab
};

static crypto_kcf_provider_handle_t sha2_prov_handle = 0;

/* ------------------------------------------------------------------ */
/*  Helpers                                                           */
/* ------------------------------------------------------------------ */

static Hmac *
wolfssl_hmac_alloc_and_key(const uint8_t *key, uint_t keylen, int *errp)
{
	Hmac *hmac;
	int ret;

	hmac = (Hmac *)kmem_alloc(sizeof (*hmac), KM_SLEEP);

	ret = wc_HmacInit(hmac, NULL, INVALID_DEVID);
	if (ret != 0) {
		kmem_free(hmac, sizeof (*hmac));
		*errp = CRYPTO_FAILED;
		return (NULL);
	}

	ret = wc_HmacSetKey(hmac, WC_SHA512, key, keylen);
	if (ret != 0) {
		wc_HmacFree(hmac);
		kmem_free(hmac, sizeof (*hmac));
		*errp = CRYPTO_FAILED;
		return (NULL);
	}

	*errp = CRYPTO_SUCCESS;
	return (hmac);
}

static void
wolfssl_hmac_free(Hmac *hmac)
{
	if (hmac != NULL) {
		wc_HmacFree(hmac);
		kmem_free(hmac, sizeof (*hmac));
	}
}

/*
 * Feed data from a crypto_data_t into an Hmac via wc_HmacUpdate.
 */
static int
wolfssl_hmac_update_cd(Hmac *hmac, crypto_data_t *data)
{
	switch (data->cd_format) {
	case CRYPTO_DATA_RAW:
		if (wc_HmacUpdate(hmac,
		    (const uint8_t *)data->cd_raw.iov_base + data->cd_offset,
		    data->cd_length) != 0)
			return (CRYPTO_FAILED);
		return (CRYPTO_SUCCESS);

	case CRYPTO_DATA_UIO: {
		off_t offset = data->cd_offset;
		size_t length = data->cd_length;
		uint_t vec_idx = 0;

		if (zfs_uio_segflg(data->cd_uio) != UIO_SYSSPACE)
			return (CRYPTO_ARGUMENTS_BAD);

		offset = zfs_uio_index_at_offset(data->cd_uio, offset,
		    &vec_idx);

		while (vec_idx < zfs_uio_iovcnt(data->cd_uio) && length > 0) {
			size_t cur_len = MIN(
			    zfs_uio_iovlen(data->cd_uio, vec_idx) - offset,
			    length);

			if (wc_HmacUpdate(hmac,
			    (const uint8_t *)zfs_uio_iovbase(data->cd_uio,
			    vec_idx) + offset,
			    cur_len) != 0)
				return (CRYPTO_FAILED);

			length -= cur_len;
			vec_idx++;
			offset = 0;
		}

		if (length > 0)
			return (CRYPTO_DATA_LEN_RANGE);
		return (CRYPTO_SUCCESS);
	}

	default:
		return (CRYPTO_ARGUMENTS_BAD);
	}
}

/*
 * Write a completed digest into a crypto_data_t.
 */
static int
wolfssl_hmac_digest_to_cd(const uint8_t *digest, uint32_t digest_len,
    crypto_data_t *out)
{
	switch (out->cd_format) {
	case CRYPTO_DATA_RAW:
		memcpy((uint8_t *)out->cd_raw.iov_base + out->cd_offset,
		    digest, digest_len);
		return (CRYPTO_SUCCESS);

	case CRYPTO_DATA_UIO: {
		off_t offset = out->cd_offset;
		uint_t vec_idx = 0;
		off_t scratch_offset = 0;
		size_t length = digest_len;

		if (zfs_uio_segflg(out->cd_uio) != UIO_SYSSPACE)
			return (CRYPTO_ARGUMENTS_BAD);

		offset = zfs_uio_index_at_offset(out->cd_uio, offset,
		    &vec_idx);

		while (vec_idx < zfs_uio_iovcnt(out->cd_uio) && length > 0) {
			size_t cur_len = MIN(
			    zfs_uio_iovlen(out->cd_uio, vec_idx) - offset,
			    length);

			memcpy(zfs_uio_iovbase(out->cd_uio, vec_idx) + offset,
			    digest + scratch_offset, cur_len);

			length -= cur_len;
			vec_idx++;
			scratch_offset += cur_len;
			offset = 0;
		}

		if (length > 0)
			return (CRYPTO_DATA_LEN_RANGE);
		return (CRYPTO_SUCCESS);
	}

	default:
		return (CRYPTO_ARGUMENTS_BAD);
	}
}

/*
 * Read digest_len bytes from a crypto_data_t into buf (for verify).
 */
static int
wolfssl_hmac_read_cd(crypto_data_t *cd, uint8_t *buf, uint32_t digest_len)
{
	switch (cd->cd_format) {
	case CRYPTO_DATA_RAW:
		memcpy(buf,
		    (const uint8_t *)cd->cd_raw.iov_base + cd->cd_offset,
		    digest_len);
		return (CRYPTO_SUCCESS);

	case CRYPTO_DATA_UIO: {
		off_t offset = cd->cd_offset;
		uint_t vec_idx = 0;
		off_t scratch_offset = 0;
		size_t length = digest_len;

		if (zfs_uio_segflg(cd->cd_uio) != UIO_SYSSPACE)
			return (CRYPTO_ARGUMENTS_BAD);

		offset = zfs_uio_index_at_offset(cd->cd_uio, offset, &vec_idx);

		while (vec_idx < zfs_uio_iovcnt(cd->cd_uio) && length > 0) {
			size_t cur_len = MIN(
			    zfs_uio_iovlen(cd->cd_uio, vec_idx) - offset,
			    length);

			memcpy(buf + scratch_offset,
			    zfs_uio_iovbase(cd->cd_uio, vec_idx) + offset,
			    cur_len);

			length -= cur_len;
			vec_idx++;
			scratch_offset += cur_len;
			offset = 0;
		}

		if (length > 0)
			return (CRYPTO_DATA_LEN_RANGE);
		return (CRYPTO_SUCCESS);
	}

	default:
		return (CRYPTO_ARGUMENTS_BAD);
	}
}

/* ------------------------------------------------------------------ */
/*  KCF software provider mac entry points                            */
/* ------------------------------------------------------------------ */

static int
sha2_mac_init(crypto_ctx_t *ctx, crypto_mechanism_t *mechanism,
    crypto_key_t *key, crypto_spi_ctx_template_t ctx_template)
{
	Hmac *hmac;
	int err;

	if (mechanism->cm_type != SHA512_HMAC_MECH_INFO_TYPE)
		return (CRYPTO_MECHANISM_INVALID);

	if (ctx_template != NULL) {
		sha2_hmac_tmpl_t *tmpl = (sha2_hmac_tmpl_t *)ctx_template;
		hmac = wolfssl_hmac_alloc_and_key(tmpl->ht_keybuf,
		    tmpl->ht_keylen, &err);
	} else {
		hmac = wolfssl_hmac_alloc_and_key(
		    (const uint8_t *)key->ck_data,
		    CRYPTO_BITS2BYTES(key->ck_length), &err);
	}

	if (hmac == NULL)
		return (err);

	ctx->cc_provider_private = hmac;
	return (CRYPTO_SUCCESS);
}

static int
sha2_mac_update(crypto_ctx_t *ctx, crypto_data_t *data)
{
	ASSERT(ctx->cc_provider_private != NULL);
	return (wolfssl_hmac_update_cd(
	    (Hmac *)ctx->cc_provider_private, data));
}

static int
sha2_mac_final(crypto_ctx_t *ctx, crypto_data_t *mac)
{
	Hmac *hmac;
	uint8_t digest[SHA512_DIGEST_LENGTH];
	int rv;

	ASSERT(ctx->cc_provider_private != NULL);
	hmac = (Hmac *)ctx->cc_provider_private;

	if (mac->cd_length < SHA512_DIGEST_LENGTH) {
		mac->cd_length = SHA512_DIGEST_LENGTH;
		return (CRYPTO_BUFFER_TOO_SMALL);
	}

	if (wc_HmacFinal(hmac, digest) != 0) {
		wolfssl_hmac_free(hmac);
		ctx->cc_provider_private = NULL;
		mac->cd_length = 0;
		return (CRYPTO_FAILED);
	}

	rv = wolfssl_hmac_digest_to_cd(digest, SHA512_DIGEST_LENGTH, mac);

	if (rv == CRYPTO_SUCCESS)
		mac->cd_length = SHA512_DIGEST_LENGTH;
	else
		mac->cd_length = 0;

	wolfssl_hmac_free(hmac);
	ctx->cc_provider_private = NULL;

	return (rv);
}

static int
sha2_mac_atomic(crypto_mechanism_t *mechanism,
    crypto_key_t *key, crypto_data_t *data, crypto_data_t *mac,
    crypto_spi_ctx_template_t ctx_template)
{
	Hmac *hmac;
	uint8_t digest[SHA512_DIGEST_LENGTH];
	int rv, err;

	if (mechanism->cm_type != SHA512_HMAC_MECH_INFO_TYPE)
		return (CRYPTO_MECHANISM_INVALID);

	if (ctx_template != NULL) {
		sha2_hmac_tmpl_t *tmpl = (sha2_hmac_tmpl_t *)ctx_template;
		hmac = wolfssl_hmac_alloc_and_key(tmpl->ht_keybuf,
		    tmpl->ht_keylen, &err);
	} else {
		hmac = wolfssl_hmac_alloc_and_key(
		    (const uint8_t *)key->ck_data,
		    CRYPTO_BITS2BYTES(key->ck_length), &err);
	}

	if (hmac == NULL)
		return (err);

	rv = wolfssl_hmac_update_cd(hmac, data);
	if (rv != CRYPTO_SUCCESS)
		goto bail;

	if (wc_HmacFinal(hmac, digest) != 0) {
		rv = CRYPTO_FAILED;
		goto bail;
	}

	rv = wolfssl_hmac_digest_to_cd(digest, SHA512_DIGEST_LENGTH, mac);
	if (rv == CRYPTO_SUCCESS) {
		mac->cd_length = SHA512_DIGEST_LENGTH;
		wolfssl_hmac_free(hmac);
		return (CRYPTO_SUCCESS);
	}

bail:
	wolfssl_hmac_free(hmac);
	mac->cd_length = 0;
	return (rv);
}

static int
sha2_mac_verify_atomic(crypto_mechanism_t *mechanism,
    crypto_key_t *key, crypto_data_t *data, crypto_data_t *mac,
    crypto_spi_ctx_template_t ctx_template)
{
	Hmac *hmac;
	uint8_t digest[SHA512_DIGEST_LENGTH];
	uint8_t expected[SHA512_DIGEST_LENGTH];
	int rv, err;

	if (mechanism->cm_type != SHA512_HMAC_MECH_INFO_TYPE)
		return (CRYPTO_MECHANISM_INVALID);

	if (mac->cd_length != SHA512_DIGEST_LENGTH)
		return (CRYPTO_INVALID_MAC);

	if (ctx_template != NULL) {
		sha2_hmac_tmpl_t *tmpl = (sha2_hmac_tmpl_t *)ctx_template;
		hmac = wolfssl_hmac_alloc_and_key(tmpl->ht_keybuf,
		    tmpl->ht_keylen, &err);
	} else {
		hmac = wolfssl_hmac_alloc_and_key(
		    (const uint8_t *)key->ck_data,
		    CRYPTO_BITS2BYTES(key->ck_length), &err);
	}

	if (hmac == NULL)
		return (err);

	rv = wolfssl_hmac_update_cd(hmac, data);
	if (rv != CRYPTO_SUCCESS) {
		wolfssl_hmac_free(hmac);
		return (rv);
	}

	if (wc_HmacFinal(hmac, digest) != 0) {
		wolfssl_hmac_free(hmac);
		return (CRYPTO_FAILED);
	}

	wolfssl_hmac_free(hmac);

	rv = wolfssl_hmac_read_cd(mac, expected, SHA512_DIGEST_LENGTH);
	if (rv != CRYPTO_SUCCESS)
		return (rv);

	if (memcmp(digest, expected, SHA512_DIGEST_LENGTH) != 0)
		return (CRYPTO_INVALID_MAC);

	return (CRYPTO_SUCCESS);
}

/* ------------------------------------------------------------------ */
/*  KCF software provider context management entry points             */
/* ------------------------------------------------------------------ */

static int
sha2_create_ctx_template(crypto_mechanism_t *mechanism, crypto_key_t *key,
    crypto_spi_ctx_template_t *ctx_template, size_t *ctx_template_size)
{
	sha2_hmac_tmpl_t *tmpl;
	uint_t keylen;

	if (mechanism->cm_type != SHA512_HMAC_MECH_INFO_TYPE)
		return (CRYPTO_MECHANISM_INVALID);

	keylen = CRYPTO_BITS2BYTES(key->ck_length);

	tmpl = kmem_alloc(sizeof (*tmpl), KM_SLEEP);
	memset(tmpl->ht_keybuf, 0, sizeof (tmpl->ht_keybuf));
	memcpy(tmpl->ht_keybuf, key->ck_data,
	    MIN(keylen, sizeof (tmpl->ht_keybuf)));
	tmpl->ht_keylen = keylen;

	*ctx_template = (crypto_spi_ctx_template_t)tmpl;
	*ctx_template_size = sizeof (*tmpl);

	return (CRYPTO_SUCCESS);
}

static int
sha2_free_context(crypto_ctx_t *ctx)
{
	if (ctx->cc_provider_private == NULL)
		return (CRYPTO_SUCCESS);

	wolfssl_hmac_free((Hmac *)ctx->cc_provider_private);
	ctx->cc_provider_private = NULL;

	return (CRYPTO_SUCCESS);
}

/* ------------------------------------------------------------------ */
/*  Module init / fini                                                */
/* ------------------------------------------------------------------ */

int
sha2_mod_init(void)
{
	int ret;

	if ((ret = crypto_register_provider(&sha2_prov_info,
	    &sha2_prov_handle)) != CRYPTO_SUCCESS)
		cmn_err(CE_WARN, "wolfssl sha2 _init: "
		    "crypto_register_provider() failed (0x%x)", ret);

	return (0);
}

int
sha2_mod_fini(void)
{
	int ret = 0;

	if (sha2_prov_handle != 0) {
		if ((ret = crypto_unregister_provider(sha2_prov_handle)) !=
		    CRYPTO_SUCCESS) {
			cmn_err(CE_WARN,
			    "wolfssl sha2 _fini: "
			    "crypto_unregister_provider() failed (0x%x)", ret);
			return (EBUSY);
		}
		sha2_prov_handle = 0;
	}

	return (ret);
}

#endif /* HAVE_WOLFSSL */
