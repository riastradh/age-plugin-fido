/* -*- Mode: C -*- */

/*-
 * Copyright (c) 2020 Taylor R. Campbell
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * Deterministic authenticated encryption with HMAC-SHA256 and ChaCha20
 * in SIV -- won't break any speed records but it'll serve for this
 * low-performance application, and everyone and their dog has the
 * parts lying around handy.
 *
 *       Given key, header, and payload, the 32-byte tag is
 *
 *               HMAC-SHA256(key, header || payload ||
 *                       le64(nbytes(header)) || le64(nbytes(payload)) || 0),
 *
 *       the derived 32-byte subkey is
 *
 *               HMAC-SHA256(key, tag || 1),
 *
 *       and the (unauthenticated) ciphertext is
 *
 *               payload ^ ChaCha20_subkey(0);
 *
 *       finally, the authenticated ciphertext is the concatenation
 *
 *               tag || (payload ^ ChaCha20_subkey(0)).
 *
 *       Decryption and verification are defined the obvious way.  The
 *       tag is a commitment to the key and the payload as long as
 *       HMAC-SHA256 is collision-resistant.
 */

#include "dae.h"

#include <string.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>

struct DAE_CTX {
	HMAC_CTX *hmac;
	EVP_CIPHER_CTX *cipher;
};

static void
dae_fini(struct DAE_CTX *D)
{

	if (D->cipher)
		EVP_CIPHER_CTX_free(D->cipher);
	if (D->hmac)
		HMAC_CTX_free(D->hmac);
}

static int
dae_init(struct DAE_CTX *D, const uint8_t key[static DAE_KEYBYTES])
{

	memset(D, 0, sizeof(*D));
	if ((D->hmac = HMAC_CTX_new()) == NULL)
		goto fail;
	if (!HMAC_Init_ex(D->hmac, key, DAE_KEYBYTES, EVP_sha256(), NULL))
		goto fail;
	if ((D->cipher = EVP_CIPHER_CTX_new()) == NULL)
		goto fail;

	return 1;

fail:	dae_fini(D);
	return 0;
}

static void
enc64le(void *buf, uint64_t x)
{
	uint8_t *p = buf;

	p[0] = x & 0xff;
	p[1] = (x >> 8) & 0xff;
	p[2] = (x >> 16) & 0xff;
	p[3] = (x >> 24) & 0xff;
	p[4] = (x >> 32) & 0xff;
	p[5] = (x >> 40) & 0xff;
	p[6] = (x >> 48) & 0xff;
	p[7] = (x >> 56) & 0xff;
}

static int
auth(uint8_t tag[static DAE_TAGBYTES],
    const uint8_t *h, size_t nh,
    const uint8_t *m, size_t nm,
    struct DAE_CTX *D)
{
	uint8_t len64[16];
	uint8_t ds = 0;		/* domain separation */
	int ok = 0;

	/* HMAC API takes size as int.  */
	if (nh > INT_MAX)
		goto out;
	if (nm > INT_MAX)
		goto out;

	if (!HMAC_Init_ex(D->hmac, NULL, 0, NULL, NULL))
		goto out;
	if (!HMAC_Update(D->hmac, h, (int)nh))
		goto out;
	if (!HMAC_Update(D->hmac, m, (int)nm))
		goto out;
	enc64le(&len64[0], nh);
	enc64le(&len64[8], nm);
	if (!HMAC_Update(D->hmac, len64, 16))
		goto out;
	if (!HMAC_Update(D->hmac, &ds, 1))
		goto out;
	if (!HMAC_Final(D->hmac, tag, NULL))
		goto out;

	/* Success!  */
	ok = 1;

out:	return ok;
}

static int
kdf(uint8_t subkey[static 32],
    const uint8_t tag[static DAE_TAGBYTES],
    struct DAE_CTX *D)
{
	uint8_t ds = 1;
	int ok = 0;

	if (!HMAC_Init_ex(D->hmac, NULL, 0, NULL, NULL))
		goto out;
	if (!HMAC_Update(D->hmac, tag, DAE_TAGBYTES))
		goto out;
	if (!HMAC_Update(D->hmac, &ds, 1))
		goto out;
	if (!HMAC_Final(D->hmac, subkey, NULL))
		goto out;

	/* Success!  */
	ok = 1;

out:	return ok;
}

static int
stream_xor(uint8_t *out, const uint8_t *in, size_t n,
    const uint8_t tag[DAE_TAGBYTES], struct DAE_CTX *D)
{
	static const uint8_t noncectr[16];
	uint8_t subkey[32];
	int outl;
	int ok = 0;

	/* EVP_CipherUpdate takes size as int.  */
	if (n > INT_MAX)
		goto out;

	if (!kdf(subkey, tag, D))
		goto out;
	if (!EVP_EncryptInit(D->cipher, EVP_chacha20(), subkey, noncectr))
		goto out;
	if (!EVP_CipherUpdate(D->cipher, out, &outl, in, (int)n))
		goto out;
	if (outl != (int)n)
		goto out;

	/* Success!  */
	ok = 1;

out:	OPENSSL_cleanse(subkey, sizeof(subkey));
	return ok;
}

int
dae_encrypt(uint8_t c[static DAE_TAGBYTES],
    const uint8_t *h, size_t nh,
    const uint8_t *m, size_t nm,
    const uint8_t key[static DAE_KEYBYTES])
{
	struct DAE_CTX ctx;
	size_t nc;
	int ok = 0;

	if (nm > SIZE_MAX - DAE_TAGBYTES)
		return 0;
	nc = nm + DAE_TAGBYTES;

	if (!dae_init(&ctx, key))
		goto out;
	if (!auth(c, h, nh, m, nm, &ctx))
		goto out;
	if (!stream_xor(c + DAE_TAGBYTES, m, nm, c, &ctx))
		goto out;

	/* Success!  */
	ok = 1;

out:	dae_fini(&ctx);
	if (!ok)
		OPENSSL_cleanse(c, nc);
	return ok;
}

int
dae_decrypt(uint8_t *m,
    const uint8_t *h, size_t nh,
    const uint8_t c[static DAE_TAGBYTES], size_t nc,
    const uint8_t key[static DAE_KEYBYTES])
{
	struct DAE_CTX ctx;
	uint8_t tag[DAE_TAGBYTES];
	size_t nm;
	int ok = 0;

	if (nc < DAE_TAGBYTES)
		return 0;
	nm = nc - DAE_TAGBYTES;

	if (!dae_init(&ctx, key))
		goto out;
	if (!stream_xor(m, c + DAE_TAGBYTES, nm, c, &ctx))
		goto out;
	if (!auth(tag, h, nh, m, nm, &ctx))
		goto out;
	if (CRYPTO_memcmp(c, tag, DAE_TAGBYTES) != 0)
		goto out;

	/* Success!  */
	ok = 1;

out:	dae_fini(&ctx);
	OPENSSL_cleanse(tag, sizeof(tag));
	if (!ok)
		OPENSSL_cleanse(m, nm);
	return ok;
}
