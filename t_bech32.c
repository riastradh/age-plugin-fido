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

#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "bech32.h"

#define	arraycount(A)	(sizeof(A)/sizeof((A)[0]))

static const struct {
	const char *hrp;
	const char *bech32;
} V[] = {			/* valid */
	[0] = { .hrp = "a", .bech32 = "a12uel5l" },
	[1] = {
		.hrp =
		    "an83characterlonghumanreadablepartthatco"
		    "ntainsthenumber1andtheexcludedcharacters"
		    "bio",
		.bech32 =
		    "an83characterlonghumanreadablepartthatco"
		    "ntainsthenumber1andtheexcludedcharacters"
		    "bio1tt5tgs",
	},
	[2] = {
		.hrp =
		    "an84characterslonghumanreadablepartthatc"
		    "ontainsthenumber1andtheexcludedcharacter"
		    "sbio",
		.bech32 =
		    "an84characterslonghumanreadablepartthatc"
		    "ontainsthenumber1andtheexcludedcharacter"
		    "sbio1569pvx",
	},
	[3] = {
		.hrp = "1",
		.bech32 =
		    "11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"
		    "qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"
		    "qqqqc8247j",
	},
	[4] = {
		.hrp = "split",
		.bech32 =
		    "split1checkupstagehandshakeupstreamerran"
		    "terredcaperred2y9e3w",
	},
	[5] = { .hrp = "?", .bech32 = "?1ezyfcl" },
}, I[] = {			/* invalid */
	[0] = { .hrp = "\020", .bech32 = "\0201nwldj5" },
#if 0
	/*
	 * We skip these tests because it's the caller's responsibility
	 * to pass in a valid HRP; the API treats the HRP as a
	 * hard-coded part of the software logic, not as a variable
	 * field.
	 */
	[1] = { .hrp = "\177", .bech32 = "\177""1axkwrx" },
	[2] = { .hrp = "\200", .bech32 = "\200""1eym55h" },
#endif
	[3] = { .hrp = "pzry", .bech32 = "pzry9x0s0muk" },
	[4] = { .hrp = "", .bech32 = "1pzry9x0s0muk" },
	[5] = { .hrp = "x", .bech32 = "x1b4n0q5v" },
	[6] = { .hrp = "li", .bech32 = "li1dgmt3" },
	[7] = { .hrp = "de", .bech32 = "de1lg7wt\377" },
	[8] = { .hrp = "a", .bech32 = "A1G7SGD8" },
	[9] = { .hrp = "", .bech32 = "10a06t8" },
	[10] = { .hrp = "", .bech32 = "1qzzfhee" },
	[11] = {
		.hrp = "bc",
		.bech32 = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5",
	},
	[12] = {
		.hrp = "tb",
		.bech32 =
		    "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj"
		    "0gdcccefvpysxf3q0sL5k7",
	},
#if 0
	/*
	 * This one is not actually invalid but is incorrectly
	 * described as invalid in the spec.
	 */
	[13] = {
		.hrp = "bc",
		.bech32 = "bc1zw508d6qejxtdg4y5r3zarvaryvqyzf3du",
	},
#endif
	[14] = {
		.hrp = "tb",
		.bech32 =
		    "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj"
		    "0gdcccefvpysxf3pjxtptv",
	},
};

int
main(void)
{
	uint8_t payload[BECH32_PAYLOAD_MAX];
	char bech32[BECH32_MAX + 1];
	unsigned i;
	int n, m, j;

	/* Valid tests.  */
	for (i = 0; i < arraycount(V); i++) {
		/* Decode as is (lowercase).  */
		if ((n = bech32dec(payload, sizeof(payload),
			    V[i].hrp, strlen(V[i].hrp),
			    V[i].bech32, strlen(V[i].bech32))) == -1) {
			printf("valid %u decode fail\n", i);
			memset(payload, 0, sizeof(payload));
		} else {
			printf("valid %u decode ok (%d bytes)", i, n);
			for (j = 0; j < n; j++)
				printf(" %02hhx", payload[j]);
			printf("\n");
		}

		/* Map to uppercase and decode again.  */
		for (j = 0; j < (int)strlen(V[i].bech32); j++)
			bech32[j] = tolower((unsigned char)V[i].bech32[j]);
		bech32[j] = '\0';
		if ((n = bech32dec(payload, sizeof(payload),
			    V[i].hrp, strlen(V[i].hrp),
			    bech32, strlen(bech32))) == -1) {
			printf("valid %u decode fail\n", i);
			memset(payload, 0, sizeof(payload));
		} else {
			printf("valid %u decode ok (%d bytes)", i, n);
			for (j = 0; j < n; j++)
				printf(" %02hhx", payload[j]);
			printf("\n");
		}

		/* Encode as lowercase.  */
		if ((m = bech32enc(bech32, sizeof(bech32),
			    V[i].hrp, strlen(V[i].hrp), payload, n)) == -1) {
			printf("valid %u encode fail\n", i);
		} else {
			printf("valid %u encode ok (%d bytes) %s\n", i, m,
			    bech32);
		}

		/* Encode as uppercase.  */
		if ((m = bech32enc_upper(bech32, sizeof(bech32),
			    V[i].hrp, strlen(V[i].hrp), payload, n)) == -1) {
			printf("valid %u encode fail\n", i);
		} else {
			printf("valid %u encode ok (%d bytes) %s\n", i, m,
			    bech32);
		}
	}

	/* Invalid tests.  */
	for (i = 0; i < arraycount(I); i++) {
		if (I[i].bech32 == NULL)
			continue;
		printf("invalid %u decoded %d\n", i,
		    n = bech32dec(payload, sizeof(payload),
			I[i].hrp, strlen(I[i].hrp),
			I[i].bech32, strlen(I[i].bech32)));
		if (n == -1)
			continue;
		for (j = 0; j < n; j++)
			printf(" %02hhx", payload[j]);
		printf("\n");
	}

	return 0;
}
