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

#include "b64dec.h"

#include <assert.h>
#include <stddef.h>
#include <stdlib.h>

#include <openssl/evp.h>

/*
 * b64dec(in, inlen, &out, &outlen)
 *
 *	Decode base64 data from inlen bytes at in into a newly
 *	allocated buffer of outlen bytes at out.  Return 0 on success,
 *	-1 on failure.
 *
 *	XXX variable-time
 */
int
b64dec(const char *in, size_t inlen, void **outp, size_t *outlenp)
{
	EVP_ENCODE_CTX *ctx = NULL;
	void *out = NULL;
	int outlen, addendum;
	int error = -1;

	/* Create a base64-decoding context.  */
	if ((ctx = EVP_ENCODE_CTX_new()) == NULL)
		goto out;
	EVP_DecodeInit(ctx);

	/* Cheap overflow avoidance.  */
	if (inlen > SIZE_MAX/3 - 4 || inlen > INT_MAX)
		goto out;

	/*
	 * Allocate a buffer of the maximum size.  This may be larger
	 * than we need, owing to whitespace and padding.
	 */
	outlen = (int)(3*inlen + 4 - 1)/4;
	assert(outlen >= 0);
	if ((out = malloc((size_t)outlen)) == NULL)
		goto out;

	/* Decode and determine the actual length.  */
	if (EVP_DecodeUpdate(ctx, out, &outlen, (const unsigned char *)in,
		(int)inlen) == -1)
		goto out;
	assert(outlen >= 0);
	assert(outlen <= (int)(3*inlen + 4 - 1)/4);

	/* Flush buffer.  (XXX ???)  */
	if (EVP_DecodeFinal(ctx, out + outlen, &addendum) == -1)
		goto out;
	assert(addendum <= (int)(3*inlen + 4 - 1)/4 - outlen);
	outlen += addendum;

	/* Success!  */
	*outp = out;
	out = NULL;
	*outlenp = (size_t)outlen;
	error = 0;

out:	free(out);
	if (ctx)
		EVP_ENCODE_CTX_free(ctx);
	return error;
}
