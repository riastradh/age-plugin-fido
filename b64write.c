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

#include "b64write.h"

#include <stddef.h>
#include <stdio.h>

#include <openssl/bio.h>
#include <openssl/evp.h>

/*
 * b64write(buf, len, file, flags)
 *
 *	Write len bytes at buf base64-encoded to the specified file
 *	stream.  flags may be 0, to wrap the output lines, or
 *	BIO_FLAGS_BASE64_NO_NL, to create just base64 data without
 *	whitespace.  Return 0 on success, -1 on error.
 *
 *	XXX variable-time
 */
int
b64write(const void *buf, size_t len, FILE *file, int flags)
{
	BIO *bio_file = NULL, *bio_b64 = NULL;
	int error = -1;

	if (len > INT_MAX)
		goto out;

	if ((bio_file = BIO_new_fp(file, BIO_NOCLOSE)) == NULL)
		goto out;
	if ((bio_b64 = BIO_new(BIO_f_base64())) == NULL)
		goto out;
	BIO_set_flags(bio_b64, flags);
	BIO_push(bio_b64, bio_file);

	if (!BIO_write(bio_b64, buf, len))
		goto out;
	if (BIO_flush(bio_b64) != 1)	/* returns 0 _or_ -1 for failure */
		goto out;

	/* Success!  */
	error = 0;

out:	if (bio_b64)
		BIO_free(bio_b64);
	if (bio_file)
		BIO_free(bio_file);
	return error;
}
