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

#include "dae.h"

#include <err.h>
#include <stdint.h>
#include <stdio.h>

static const uint8_t key[DAE_KEYBYTES] = {
	0x00,0x01,0x02,0x03, 0x04,0x05,0x06,0x07,
	0x08,0x09,0x0a,0x0b, 0x0c,0x0d,0x0e,0x0f,
	0x10,0x11,0x12,0x13, 0x14,0x15,0x16,0x17,
	0x18,0x19,0x1a,0x1b, 0x1c,0x1d,0x1e,0x1f,
};

/* Note: No NUL terminator on these.  */

static const uint8_t header[9] = "The Raven";

static const uint8_t payload[126] =
    "Once upon a midnight dreary,\n"
    "  while I pondered, weak and weary,\n"
    "Over many a quaint and curious\n"
    "  volume of forgotten lore...\n";

int
main(void)
{
	uint8_t c[DAE_TAGBYTES + sizeof(payload)];
	uint8_t m[sizeof(payload)];
	unsigned i;

	if (!dae_encrypt(c, header, sizeof(header), payload, sizeof(payload),
		key))
		errx(1, "encrypt");
	printf("ciphertext:\n");
	for (i = 0; i < sizeof(c); i++)
		printf("%02hhx", c[i]);
	printf("\n");

	if (!dae_decrypt(m, header, sizeof(header), c, sizeof(c), key))
		errx(1, "encrypt");
	printf("plaintext:\n");
	for (i = 0; i < sizeof(m); i++)
		printf("%02hhx", m[i]);
	printf("\n");

	c[12] ^= 0x08;
	if (dae_decrypt(m, header, sizeof(header), c, sizeof(c), key))
		errx(1, "accepted forgery");

	return 0;
}
