/*-
 * Copyright (c) 2021 Taylor R. Campbell
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
 * XXX TODO:
 *
 * - Report errors according to protocol, not with errx(1, "...").
 *
 * - Figure out how identities and recipient stanzas are supposed to
 *   match up in the key-unwrapping protocol.
 *
 * - Give feedback in the key-unwrapping protocol about when we need
 *   device interaction.
 *
 * - Consider supporting PINs for FIDO2 devices.
 *
 * - Read from all devices on system in parallel.
 *
 * - Handle uppercase bech32 properly.
 */

#define	_POSIX_C_SOURCE	200809L

#include <assert.h>
#include <ctype.h>		/* XXX variable-time toupper */
#include <err.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <fido.h>
#include <fidocrypt.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include "b64dec.h"
#include "b64write.h"
#include "bech32.h"
#include "ctassert.h"
#include "freadline.h"
#include "progname.h"
#include "reallocn.h"
#include "strprefix.h"

#define	arraycount(A)	(sizeof(A)/sizeof(*(A)))

#define	AGEFIDO_HRP	"age1fido"
#define	AGEFIDO_ID_HRP	"age-plugin-fido-"

static fido_dev_t *
opendev(const char *devpath)
{
	fido_dev_t *dev = NULL;
	int error;

	/* Create a fido dev representative.  */
	if ((dev = fido_dev_new()) == NULL)
		errx(1, "fido_dev_new");

	if (devpath) {
		/* If the user provided a device path, just open it.  */
		if ((error = fido_dev_open(dev, devpath)) != FIDO_OK)
			errx(1, "fido_dev_open: %s", fido_strerr(error));
	} else {
		/* None provided -- try the first one from the system.  */
		fido_dev_info_t *devlist = NULL;
		const fido_dev_info_t *devinfo;
		size_t ndevs = 0;

		if ((devlist = fido_dev_info_new(1)) == NULL)
			errx(1, "fido_dev_info_new");
		if ((error = fido_dev_info_manifest(devlist, 1, &ndevs))
		    != FIDO_OK)
			errx(1, "fido_dev_info_manifest: %s",
			    fido_strerr(error));
		if (ndevs < 1)
			errx(1, "no devices found");
		if ((devinfo = fido_dev_info_ptr(devlist, 0)) == NULL)
			errx(1, "fido_dev_info_ptr");
		if ((error = fido_dev_open(dev, fido_dev_info_path(devinfo)))
		    != FIDO_OK)
			errx(1, "fido_dev_open: %s", fido_strerr(error));
		fido_dev_info_free(&devlist, ndevs);
	}

	return dev;
}

struct keywrap {
	void *credential_id;
	size_t ncredential_id;
	void *ciphertext;
	size_t nciphertext;
};

static void
encap(struct keywrap *K, const void *cookie, size_t ncookie,
    const void *key, size_t nkey)
{
	char rp_id[BECH32_MAX + 1];
	uint8_t challenge[32];
	fido_dev_t *dev = NULL;
	fido_cred_t *cred = NULL;
	const void *credential_id;
	size_t ncredential_id;
	unsigned char *ciphertext = NULL;
	size_t nciphertext = 0;
	int n, error;

	/* Encode the relying party id.  */
	if ((n = bech32enc(rp_id, sizeof(rp_id),
		    AGEFIDO_HRP, strlen(AGEFIDO_HRP),
		    cookie, ncookie)) == -1)
		err(1, "bad cookie");

	/* Generate a challenge.  */
	if (RAND_bytes(challenge, sizeof(challenge)) != 1)
		errx(1, "RAND_bytes");

	/* Create the credential and set its parameters.  */
	if ((cred = fido_cred_new()) == NULL)
		errx(1, "fido_cred_new");
	if ((error = fido_cred_set_type(cred, COSE_ES256)) != FIDO_OK)
		errx(1, "fido_cred_set_type: %s", fido_strerr(error));
	if ((error = fido_cred_set_rp(cred, "hello", NULL)) != FIDO_OK)
		errx(1, "fido_cred_set_rp: %s", fido_strerr(error));
	if ((error = fido_cred_set_user(cred,
		    (const unsigned char *)"age", strlen("age"),
		    /*user_name*/"age(1)", /*displayname*/NULL, /*icon*/NULL))
	    != FIDO_OK)
		errx(1, "fido_cred_set_user: %s", fido_strerr(error));
	if ((error = fido_cred_set_clientdata_hash(cred,
		    challenge, sizeof(challenge))) != FIDO_OK)
		errx(1, "fido_cred_set_clientdata_hash: %s",
		    fido_strerr(error));

	/* Open a device.  */
	dev = opendev(NULL);

	/* Make the credential.  */
	if ((error = fido_dev_make_cred(dev, cred, NULL)) != FIDO_OK) {
		(void)fido_dev_cancel(dev);
		errx(1, "fido_dev_make_cred: %s", fido_strerr(error));
	}

	/* Close the device -- we're done with it now.  */
	fido_dev_close(dev);

	/* Get the credential id.  */
	if ((credential_id = fido_cred_id_ptr(cred)) == NULL ||
	    (ncredential_id = fido_cred_id_len(cred)) == 0)
		errx(1, "missingfido_cred_id");

	/* Verify the credential.  */
	if (fido_cred_x5c_ptr(cred) == NULL) {
		if ((error = fido_cred_verify_self(cred)) != FIDO_OK)
			errx(1, "fido_cred_verify_self: %s",
			    fido_strerr(error));
	} else {
		if ((error = fido_cred_verify(cred)) != FIDO_OK)
			errx(1, "fido_cred_verify: %s", fido_strerr(error));
	}

	/* Encrypt the key.  */
	if ((error = fido_cred_encrypt(cred, NULL, 0, key, nkey,
		    &ciphertext, &nciphertext)) != FIDO_OK)
		errx(1, "fido_cred_encrypt: %s", fido_strerr(error));

	/* Copy the credential id.  */
	if ((K->credential_id = malloc(ncredential_id)) == NULL)
		errx(1, "malloc");
	memcpy(K->credential_id, credential_id, ncredential_id);
	K->ncredential_id = ncredential_id;

	/* Return the ciphertext.  */
	K->ciphertext = ciphertext;
	K->nciphertext = nciphertext;

	/* Success!  */
	fido_cred_free(&cred);
	fido_dev_free(&dev);
	OPENSSL_cleanse(challenge, sizeof(challenge));
	OPENSSL_cleanse(rp_id, sizeof(rp_id));
}

static void
decap(const struct keywrap *K, const void *cookie, size_t ncookie,
    void **keyp, size_t *nkeyp)
{
	char rp_id[BECH32_MAX + 1];
	uint8_t challenge[32];
	fido_dev_t *dev = NULL;
	fido_assert_t *assertion = NULL;
	unsigned char *key;
	size_t nkey;
	int n, error;

	/* Encode the relying party id.  */
	if ((n = bech32enc(rp_id, sizeof(rp_id),
		    AGEFIDO_HRP, strlen(AGEFIDO_HRP),
		    cookie, ncookie)) == -1)
		err(1, "bad cookie");

	/* Generate a challenge.  */
	if (RAND_bytes(challenge, sizeof(challenge)) != 1)
		errx(1, "RAND_bytes");

	/* Create the assertion and set its parameters.  */
	if ((assertion = fido_assert_new()) == NULL)
		errx(1, "fido_assert_new");
	if ((error = fido_assert_set_rp(assertion, "hello")) != FIDO_OK)
		errx(1, "fido_assert_set_rp: %s", fido_strerr(error));
	if ((error = fido_assert_set_clientdata_hash(assertion,
		    challenge, sizeof(challenge))) != FIDO_OK)
		errx(1, "fido_assert_set_clientdata_hash: %s",
		    fido_strerr(error));
	if ((error = fido_assert_allow_cred(assertion, K->credential_id,
		    K->ncredential_id)) != FIDO_OK)
		errx(1, "fido_assert_allow_cred: %s", fido_strerr(error));

	/* Open a device.  */
	dev = opendev(NULL);

	/* Get an assertion response.  */
	if ((error = fido_dev_get_assert(dev, assertion, NULL)) != FIDO_OK) {
		(void)fido_dev_cancel(dev);
		errx(1, "fido_dev_get_assert: %s", fido_strerr(error));
	}

	/* Close the device -- we're done with it now.  */
	fido_dev_close(dev);

	/* Verify we got an assertion response.  */
	if (fido_assert_count(assertion) != 1)
		errx(1, "failed to get one assertion response");

	/*
	 * Verify and decrypt the ciphertext using the `key' derived
	 * from the assertion.
	 */
	if ((error = fido_assert_decrypt(assertion, 0,
		    K->ciphertext, K->nciphertext, &key, &nkey)) != FIDO_OK)
		errx(1, "fido_assert_decrypt: %s", fido_strerr(error));

	/* Success!  */
	*keyp = key;
	*nkeyp = nkey;
	fido_assert_free(&assertion);
	fido_dev_free(&dev);
	OPENSSL_cleanse(challenge, sizeof(challenge));
	OPENSSL_cleanse(rp_id, sizeof(rp_id));
}

static bool
eat(char **bufp, size_t *lenp, const char *prefix)
{

	if (strprefix(*bufp, *lenp, prefix) != 0)
		return false;
	*bufp += strlen(prefix);
	*lenp -= strlen(prefix);
	return true;
}

char buf[1024];

static void
read_b64_until_cmd(unsigned char **bufp, size_t *lenp, size_t *cmdlenp)
{
	EVP_ENCODE_CTX *ctx;
	size_t len;
	int n0, n;

	/* Initialize the output buffer to empty.  */
	*bufp = NULL;
	*lenp = 0;

	/* Create a base64-decoding context.  */
	if ((ctx = EVP_ENCODE_CTX_new()) == NULL)
		errx(1, "EVP_ENCODE_CTX_new");
	EVP_DecodeInit(ctx);

	/* Read lines until we get a `-> ' line.  */
	for (;;) {
		if (freadline(buf, sizeof buf, &len, stdin) == EOF)
			errx(1, "premature EOF");

		if (len == 0 || buf[len - 1] != '\n')
			errx(1, "invalid payload");

		/*
		 * If the line starts with `-> ', we're done -- break
		 * out of the loop and back into parsing the command in
		 * buf.
		 */
		if (strprefix(buf, len, "-> ") == 0)
			break;

		/*
		 * Otherwise, the line may encode up to
		 * (3/4)*sizeof(buf) bytes of data -- possibly fewer,
		 * considering base64 padding and whitespace.
		 *
		 * Compute an upper bound n0 on the number of bytes
		 * this might add, as an int because OpenSSL's
		 * EVP_DecodeUpdate deals only in int sizes; prove that
		 * the intermediate does not overflow int.
		 */
		CTASSERT(sizeof buf <= (INT_MAX - 4 + 1)/3);
		n0 = (3*len + 4 - 1)/4;

		/*
		 * Stop here if this would overflow the maximum key
		 * length.  We arbitrarily set 2048 bytes as the
		 * maximum -- this is plenty for, e.g., RSA-4096.
		 */
		CTASSERT((3*sizeof buf + 4 - 1)/4 < 2048);
		if (*lenp > (size_t)(2048 - n0))
			errx(1, "payload too long");

		/* Ensure there's enough space.  */
		if (reallocn(bufp, *lenp + n0, 1) == -1)
			err(1, "realloc");

		/* Decode the data and extend the buffer.  */
		if (EVP_DecodeUpdate(ctx, *bufp + *lenp, &n,
			(const unsigned char *)buf, len) == -1)
			errx(1, "invalid base64");
		assert(n >= 0);
		assert(n <= n0);
		*lenp += n;
	}

	if (EVP_DecodeFinal(ctx, *bufp + *lenp, &n) == -1)
		errx(1, "invalid base64");
	assert(n >= 0);
	*lenp += n;

	/* Done with the base64-decoding context.  */
	EVP_ENCODE_CTX_free(ctx);

	/* Return the command length we just read.  */
	*cmdlenp = len;
}

static void
do_keygen(void)
{
	uint8_t buf[32];
	char bech32[BECH32_MAX + 1];
	int n;

	if (RAND_bytes(buf, sizeof(buf)) != 1)
		errx(1, "RAND_bytes");

	/* Print the recipient.  */
	if (bech32enc(bech32, sizeof(bech32),
		AGEFIDO_HRP, strlen(AGEFIDO_HRP),
		buf, sizeof(buf)) == -1)
		errx(1, "bech32enc");
	printf("%s\n", bech32);

	/* Print the identity.  */
	if ((n = bech32enc(bech32, sizeof(bech32),
		    AGEFIDO_ID_HRP, strlen(AGEFIDO_ID_HRP),
		    buf, sizeof(buf))) == -1)
		errx(1, "bech32enc");
	while (n --> 0)
		bech32[n] = toupper(bech32[n]);	/* XXX variable-time */
	printf("%s\n", bech32);

	OPENSSL_cleanse(bech32, sizeof(bech32));
	OPENSSL_cleanse(buf, sizeof(buf));
}

static void
do_recipient(void)
{
	struct {
		char *bech32;
		unsigned char *buf;
	} recips[32];
	unsigned nrecips = 0;
	struct {
		unsigned char *buf;
		unsigned len;
	} keys[32];
	unsigned nkeys = 0;
	struct keywrap *keywraps;
	char *p;
	size_t n;
	unsigned i, j;

	/*
	 * Phase 1 [client, uni-directional]
	 */
	for (;;) {
		/* Read a line into buf.  */
		if (freadline(buf, sizeof buf, &n, stdin) == EOF)
			err(1, "read command");

parsecmd:	/* Parse the n-byte line in buf, including trailing LF.  */
		p = buf;

		/* Verify the line has form `-> ...\n' and back up over LF.  */
		if (!eat(&p, &n, "-> ") || n == 0 || p[n - 1] != '\n')
			errx(1, "bad command (n=%zu) %s", n, buf);

		/* NUL-terminate the line without LF.  */
		p[--n] = '\0';

		/* Dispatch on the command.  */
		if (eat(&p, &n, "add-recipient")) {
			/*
			 * Verify there's arguments after the command,
			 * separated by a space.
			 */
			if (n-- == 0 || *p++ != ' ')
				errx(1, "bad add-recipient command");

			/* Verify we haven't filled the recipient list.  */
			if (nrecips >= arraycount(recips))
				errx(1, "too many recipients");

			/* Copy the recipient and put it at the end.  */
			if ((recips[nrecips++].bech32 = strndup(p, n)) == NULL)
				err(1, "strndup");

		} else if (eat(&p, &n, "wrap-file-key")) {
			unsigned char *key;
			size_t keylen;

			/* Verify there are no arguments.  */
			if (n)
				errx(1, "bad wrap-file-key command");

			/* Verify we haven't filled the key list.  */
			if (nkeys >= arraycount(keys))
				errx(1, "too many keys");

			/*
			 * Read the key to wrap from the base64 body of
			 * the stanza.  This leaves the first `-> '
			 * line after the stanza in buf, or aborts if
			 * anything went wrong.
			 */
			read_b64_until_cmd(&key, &keylen, &n);

			/* Verify the key was nonempty.  */
			/* XXX Is this really a problem?  */
			if (key == NULL)
				errx(1, "empty key");

			/* Put the key at the end of the list.  */
			keys[nkeys].buf = key;
			keys[nkeys].len = keylen;
			nkeys++;

			/*
			 * We already have a command in the buffer --
			 * go back to parsing it.
			 */
			goto parsecmd;

		} else if (eat(&p, &n, "done")) {
			/* Verify there are no arguments.  */
			if (n)
				errx(1, "bad done command");

			/* Break out of this phase of the state machine.  */
			break;

		} else {
			errx(1, "unknown command");
		}
	}

	/* Verify that all the recipients are valid and decode.  */
	for (i = 0; i < nrecips; i++) {
		if (bech32dec_size(strlen(AGEFIDO_HRP),
			strlen(recips[i].bech32)) != 32)
			errx(1, "invalid recipient");
		if ((recips[i].buf = malloc(32)) == NULL)
			err(1, "malloc");
		if (bech32dec(recips[i].buf, 32,
			AGEFIDO_HRP, strlen(AGEFIDO_HRP),
			recips[i].bech32, strlen(recips[i].bech32)) == -1)
			errx(1, "invalid recipient");
	}

	CTASSERT(arraycount(recips) <= SIZE_MAX/arraycount(keys));
	if ((keywraps = calloc(nrecips*nkeys, sizeof(keywraps[0]))) == NULL)
		err(1, "calloc");
	for (i = 0; i < nrecips; i++) {
		for (j = 0; j < nkeys; j++) {
			encap(&keywraps[nrecips*i + j], recips[i].buf, 32,
			    keys[j].buf, keys[j].len);
		}
	}

	/*
	 * Phase 2 [plugin, uni-directional]
	 */
	for (i = 0; i < nrecips; i++) {
		SHA256_CTX ctx;
		unsigned char hash[32];

		/* Compute the recipient hash.  */
		SHA256_Init(&ctx);
		SHA256_Update(&ctx, "AGEFIDO1", 8);
		SHA256_Update(&ctx, recips[i].buf, 32);
		SHA256_Final(hash, &ctx);

		/* Print all the keys wrapped for this recipient.  */
		for (j = 0; j < nkeys; j++) {
			struct keywrap *K = &keywraps[nrecips*i + j];

			printf("-> recipient-stanza %d fido ", j);
			b64write(hash, 32, stdout, BIO_FLAGS_BASE64_NO_NL);
			printf(" ");
			b64write(K->credential_id, K->ncredential_id, stdout,
			    BIO_FLAGS_BASE64_NO_NL);
			printf("\n");
			b64write(K->ciphertext, K->nciphertext, stdout, 0);
		}
	}
	printf("-> done\n");
}

static void
do_identity(void)
{
	struct {
		char *bech32;
		unsigned char *buf;
		unsigned char *hash;
	} ids[32];
	unsigned nids = 0;
	struct {
		int file_index;
		char *hash_b64;
		char *credid_b64;
		unsigned char *buf;
		unsigned len;
	} *stanzas = NULL;
	size_t nstanzas = 0;
	char *p, *q;
	int file_index;
	size_t i, j, n;

	/*
	 * Phase 1 [client, uni-directional]
	 */
	for (;;) {
		/* Read a line into buf.  */
		if (freadline(buf, sizeof buf, &n, stdin) == EOF)
			err(1, "read command");

parsecmd:	/* Parse the n-byte line in buf, including trailing LF.  */
		p = buf;

		/* Verify the line has form `-> ...\n' and back up over LF.  */
		if (!eat(&p, &n, "-> ") || n == 0 || p[--n] != '\n')
			errx(1, "bad command");

		/* NUL-terminate the line without LF.  */
		p[n] = '\0';

		/* Dispatch on the command.  */
		if (eat(&p, &n, "add-identity")) {
			/*
			 * Verify there's arguments after the command,
			 * separated by a space.
			 */
			if (n-- == 0 || *p++ != ' ')
				errx(1, "bad add-recipient command");

			/* Verify we haven't filled the identity list.  */
			if (nids >= arraycount(ids))
				errx(1, "too many identities");

			/* Copy the identity and put it at the end.  */
			if ((ids[nids++].bech32 = strndup(p, n)) == NULL)
				err(1, "strndup");

		} else if (eat(&p, &n, "recipient-stanza")) {
			unsigned char *ciphertext;
			size_t clen;
			int m = -1;

			/* Allocate a stanza.  */
			if (reallocn(&stanzas, nstanzas + 1,
				sizeof(stanzas[0])) == -1)
				err(1, "realloc");

			/* Parse stanza number and verify type.  */
			sscanf(p, " %d fido %n", &stanzas[nstanzas].file_index,
			    &m);
			if (m == -1)
				/* XXX print, not err */
				errx(1, "invalid recipient");
			if (stanzas[nstanzas].file_index < 0)
				errx(1, "invalid file index");
			assert(m > 0);
			assert((size_t)m <= n);
			p += m;
			n -= m;

			if ((q = strchr(p, ' ')) == NULL)
				/* XXX print, not err */
				errx(1, "invalid recipient");
			*q++ = '\0';
			if ((stanzas[nstanzas].hash_b64 = strdup(p)) == NULL)
				err(1, "strdup");
			if ((stanzas[nstanzas].credid_b64 = strdup(q)) == NULL)
				err(1, "strdup");

			/*
			 * Read the ciphertext from the base64 body of
			 * the stanza.  This leaves the first `-> '
			 * line after the stanza in buf, or aborts if
			 * anything went wrong.
			 */
			read_b64_until_cmd(&ciphertext, &clen, &n);

			/* Verify the ciphertext was nonempty.  */
			if (ciphertext == NULL)
				errx(1, "empty ciphertext");

			/* Put the key at the end of the list.  */
			stanzas[nstanzas].buf = ciphertext;
			stanzas[nstanzas].len = clen;
			nstanzas++;

			/*
			 * We already have a command in the buffer --
			 * go back to parsing it.
			 */
			goto parsecmd;

		} else if (eat(&p, &n, "done")) {
			/* Verify there are no arguments.  */
			if (n)
				errx(1, "bad done command");

			/* Break out of this phase of the state machine.  */
			break;

		} else {
			/*
			 * Unknown stanza type.  Consume and ignore the
			 * stanza body until we hit `-> ' -- `Unknown
			 * stanza types MUST be ignored by the plugin.'
			 */
			while (freadline(buf, sizeof buf, &n, stdin) != EOF) {
				/* Verify the line ends with LF.  */
				if (n == 0 || buf[n - 1] != '\n')
					errx(1, "invalid payload");

				/* If it's a new command, back to the top.  */
				if (strprefix(buf, n, "-> ") == 0)
					goto parsecmd;
			}

			/* We only get here if freadline returned EOF.  */
			errx(1, "premature EOF");
		}
	}

	/* Verify that all the identities are valid, decode, and hash.  */
	for (i = 0; i < nids; i++) {
		SHA256_CTX ctx;

		if (bech32dec_size(strlen(AGEFIDO_ID_HRP),
			strlen(ids[i].bech32)) != 32)
			errx(1, "invalid identity 1 len=%d",
			    bech32dec_size(strlen(AGEFIDO_ID_HRP),
				strlen(ids[i].bech32)));
		if ((ids[i].buf = malloc(32)) == NULL ||
		    (ids[i].hash = malloc(32)) == NULL)
			err(1, "malloc");
		for (j = 0; j < strlen(ids[i].bech32); j++) /* XXX */
			ids[i].bech32[j] = tolower(ids[i].bech32[j]);
		if (bech32dec(ids[i].buf, 32,
			AGEFIDO_ID_HRP, strlen(AGEFIDO_ID_HRP),
			ids[i].bech32, strlen(ids[i].bech32)) == -1)
			errx(1, "invalid identity 2");

		SHA256_Init(&ctx);
		SHA256_Update(&ctx, "AGEFIDO1", 8);
		SHA256_Update(&ctx, ids[i].buf, 32);
		SHA256_Final(ids[i].hash, &ctx);
	}

	/*
	 * Phase 2 [plugin, bi-directional]
	 */
	for (file_index = -1, i = 0; i < nstanzas; i++) {
		struct keywrap keywrap, *K = &keywrap;
		void *hash;
		size_t hashlen;
		void *key;
		size_t nkey;

		/* Skip files we've already decapsulated.  */
		if (stanzas[i].file_index == file_index)
			continue;

		/* Decode the recipient hash.  */
		if (b64dec(stanzas[i].hash_b64, strlen(stanzas[i].hash_b64),
			&hash, &hashlen) == -1 ||
		    hashlen != 32)
			errx(1, "invalid recipient stanza");

		/* Find the matching identity.  */
		for (j = 0; j < nids; j++) {
			if (CRYPTO_memcmp(hash, ids[i].hash, 32) == 0)
				break;
		}
		if (j == nids)
			errx(1, "missing identity");

		/* Decode the base64 credential id.  */
		if (b64dec(stanzas[i].credid_b64,
			strlen(stanzas[i].credid_b64),
			&K->credential_id, &K->ncredential_id) == -1)
			errx(1, "invalid base64 123: %s",
			    stanzas[i].credid_b64);

		/* Decapsulate the key.  */
		K->ciphertext = stanzas[i].buf;
		K->nciphertext = stanzas[i].len;
		decap(K, ids[i].buf, 32, &key, &nkey);

		printf("-> file-key %d\n", stanzas[i].file_index);
		b64write(key, nkey, stdout, 0);
	}
	printf("-> done\n");
}

static void
usage(void)
{

	fprintf(stderr, "Usage: %s --age-plugin=<type>\n", getprogname());
	exit(1);
}

int
main(int argc, char **argv)
{

	setprogname(argv[0]);
	if (argc == 1)
		do_keygen();
	else if (argc != 2)
		usage();
	else if (strcmp(argv[1], "--age-plugin=recipient-v1") == 0)
		do_recipient();
	else if (strcmp(argv[1], "--age-plugin=identity-v1") == 0)
		do_identity();
	else
		usage();

	fflush(stdout);
	return ferror(stdout);
}
