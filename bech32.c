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
 * Bech32 encoding of octet strings, as used in Zcash, based on the
 * somewhat more complicated encoding of Bitcoin BIP 173 segwit
 * addresses.
 *
 *	Daira Hopwood, `Bech32 Format', Zcash Improvement Proposal, ZIP
 *	173, 2018-06-13.
 *	https://zips.z.cash/zip-0173
 */

#define	_POSIX_C_SOURCE	200809L

#include "bech32.h"

#include <assert.h>
#include <err.h>
#include <inttypes.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "ctassert.h"

#define	arraycount(A)	(sizeof(A)/sizeof(*(A)))

/*
 * bech32_tolower_8(out, in)
 *
 *	Convert eight 7-bit US-ASCII code points in[0], in[1], ...,
 *	in[7] to lowercase at out[0], out[1], ..., out[7] in constant
 *	time.  Returns -1 on error if any in[i] has the eighth bit set,
 *	or 0 on success.
 */
static int
bech32_tolower_8(char out[static 8], const char in[static 8])
{
	uint64_t x, y, error, mask;

	/*
	 * Load input.  byte order doesn't matter as long as it matches
	 * on input and output -- each byte is independent.
	 */
	memcpy(&x, in, 8);

	/*
	 * Input should be US-ASCII; take eighth bit as error
	 * indicator, and then set it to borrow from while we work on
	 * 7-bit units.
	 */
	error = x & UINT64_C(0x8080808080808080);
	y = x;
	x |= UINT64_C(0x8080808080808080);

	/*
	 * Borrow if less than `A' (0x41): clear eighth bit in each
	 * unit less than `A'.
	 */
	CTASSERT('A' == 0x41);
	mask = x - UINT64_C(0x4141414141414141);

	/*
	 * Borrow if not greater than `Z' (0x5a) and invert: clear
	 * eighth bit in each unit greater than `Z'.
	 */
	CTASSERT('Z' == 0x5a);
	mask &= ~(x - UINT64_C(0x5b5b5b5b5b5b5b5b));

	/*
	 * Clear all bits other than the borrow.  After this point, the
	 * eighth bit of each 8-bit unit is set iff that unit lies in
	 * US-ASCII A-Z.
	 */
	mask &= 0x8080808080808080;

	/* Shift 0x80 to 0x20 to get the case-changing bit mask.  */
	mask >>= 2;
	assert(mask == (mask & 0x2020202020202020));

	/* Change case.  */
	y ^= mask;

	/* Store output.  */
	memcpy(out, &y, 8);

	/*
	 * Map zero to 0, nonzero to -1.  In this case, all the nonzero
	 * bits will be at positions 7 mod 8, so shift them to 0 mod 8
	 * and then combine them all at 0.
	 */
	error >>= 7;
	error |= error >> 8;
	error |= error >> 16;
	error |= error >> 32;
	return -(error & 1);
}

/*
 * bech32_tolower(out, in, n)
 *
 *	Convert n 7-bit US-ASCII code points in[0], in[1], ..., in[n-1]
 *	to lowercase at out[0], out[1], ..., out[n-1] in constant time.
 *	Returns -1 on error if any in[i] has the eighth bit set, or 0
 *	on success.
 */
static int
bech32_tolower(char *out, const char *in, size_t n)
{
	int error = 0;

	for (; 8 <= n; out += 8, in += 8, n -= 8)
		error |= bech32_tolower_8(out, in);
	if (n) {
		char buf[8];

		memcpy(buf, in, n);
		memset(buf + n, 0, 8 - n);
		error |= bech32_tolower_8(buf, buf);
		memcpy(out, buf, n);
	}

	return error;
}

/*
 * bech32_toupper_8(out, in)
 *
 *	Convert eight 7-bit US-ASCII code points in[0], in[1], ...,
 *	in[7] to uppercase at out[0], out[1], ..., out[7] in constant
 *	time.  Returns -1 on error if any in[i] has the eighth bit set,
 *	or 0 on success.
 */
static int
bech32_toupper_8(char out[static 8], const char in[static 8])
{
	uint64_t x, y, error, mask;

	/*
	 * Load input.  byte order doesn't matter as long as it matches
	 * on input and output -- each byte is independent.
	 */
	memcpy(&x, in, 8);

	/*
	 * Input should be US-ASCII; take eighth bit as error
	 * indicator, and then set it to borrow from while we work on
	 * 7-bit units.
	 */
	error = x & UINT64_C(0x8080808080808080);
	y = x;
	x |= UINT64_C(0x8080808080808080);

	/*
	 * Borrow if less than `a' (0x61): clear eighth bit in each
	 * unit less than `a'.
	 */
	CTASSERT('a' == 0x61);
	mask = x - UINT64_C(0x6161616161616161);

	/*
	 * Borrow if not greater than `z' (0x7a) and invert: clear
	 * eighth bit in each unit greater than `z'.
	 */
	CTASSERT('z' == 0x7a);
	mask &= ~(x - UINT64_C(0x7b7b7b7b7b7b7b7b));

	/*
	 * Clear all bits other than the borrow.  After this point, the
	 * eighth bit of each 8-bit unit is set iff that unit lies in
	 * US-ASCII a-z.
	 */
	mask &= 0x8080808080808080;

	/* Shift 0x80 to 0x20 to get the case-changing bit mask.  */
	mask >>= 2;
	assert(mask == (mask & 0x2020202020202020));

	/* Change case.  */
	y ^= mask;

	/* Store output.  */
	memcpy(out, &y, 8);

	/*
	 * Map zero to 0, nonzero to -1.  In this case, all the nonzero
	 * bits will be at positions 7 mod 8, so shift them to 0 mod 8
	 * and then combine them all at 0.
	 */
	error >>= 7;
	error |= error >> 8;
	error |= error >> 16;
	error |= error >> 32;
	return -(error & 1);
}

/*
 * bech32_toupper(out, in, n)
 *
 *	Convert n 7-bit US-ASCII code points in[0], in[1], ..., in[n-1]
 *	to uppercase at out[0], out[1], ..., out[n-1] in constant time.
 *	Returns -1 on error if any in[i] has the eighth bit set, or 0
 *	on success.
 */
static int
bech32_toupper(char *out, const char *in, size_t n)
{
	int error = 0;

	for (; 8 <= n; out += 8, in += 8, n -= 8)
		error |= bech32_toupper_8(out, in);
	if (n) {
		char buf[8];

		memcpy(buf, in, n);
		memset(buf + n, 0, 8 - n);
		error |= bech32_toupper_8(buf, buf);
		memcpy(out, buf, n);
	}

	return error;
}

/*
 * Conservatively avoid overflow.  We can actually handle substantially
 * larger inputs since the expansion is only a factor of 8/5, but this
 * saves the trouble of avoiding size_t overflow in the intermediate
 * quantity 8*n.
 */
#define	BECH32_8TO5_SIZE_MAX	((SIZE_MAX - 4)/8)

/*
 * bech32_8to5_size(n)
 *
 *	Return the number of 5-bit groups needed to encode n 8-bit
 *	groups, rounded up to include zero padding if necessary.
 *
 *	n must be at most BECH32_8TO5_SIZE_MAX.
 */
static size_t
bech32_8to5_size(size_t n8)
{

	assert(n8 <= BECH32_8TO5_SIZE_MAX);
	return (8*n8 + 4)/5;
}

/*
 * bech32_8to5(d, nd, s, ns)
 *
 *	Convert 8-bit groups to 5-bit groups: read ns bytes from s and
 *	store up to nd bytes at d; nd must be at least (8*ns + 4)/5,
 *	and ns must be at most BECH32_8TO5_SIZE_MAX.  Use
 *	bech32_8to5_size(ns) to compute the number of 5-bit groups
 *	needed to encode ns 8-bit groups.
 */
static void
bech32_8to5(uint8_t *d, size_t nd, const uint8_t *s, size_t ns)
{

	assert(ns <= BECH32_8TO5_SIZE_MAX);
	assert(nd >= bech32_8to5_size(ns));

	while (5 <= ns) {
		d[0] =		             ((s[0] & 0370) >> 3);
		d[1] = ((s[0] & 007) << 2) | ((s[1] & 0300) >> 6);
		d[2] =                       ((s[1] & 0076) >> 1);
		d[3] = ((s[1] & 001) << 4) | ((s[2] & 0360) >> 4);
		d[4] = ((s[2] & 017) << 1) | ((s[3] & 0200) >> 7);
		d[5] =                       ((s[3] & 0174) >> 2);
		d[6] = ((s[3] & 003) << 3) | ((s[4] & 0340) >> 5);
		d[7] =  (s[4] & 037);

		d += 8, nd -= 8;
		s += 5, ns -= 5;
	}

	if (ns) {
		uint8_t s0, s1, s2, s3;

		assert(1 <= ns && ns <= 4);
		s0 = s[0];
		s1 = (ns <= 1? 0 : s[1]);
		s2 = (ns <= 2? 0 : s[2]);
		s3 = (ns <= 3? 0 : s[3]);

		assert(2 <= nd);
		d[0] =                     ((s0 & 0370) >> 3);
		d[1] = ((s0 & 007) << 2) | ((s1 & 0300) >> 6);
		if (ns <= 1)
			return;
		assert(4 <= nd);
		d[2] =                     ((s1 & 0076) >> 1);
		d[3] = ((s1 & 001) << 4) | ((s2 & 0360) >> 4);
		if (ns <= 2)
			return;
		assert(5 <= nd);
		d[4] = ((s2 & 017) << 1) | ((s3 & 0200) >> 7);
		if (ns <= 3)
			return;
		assert(7 <= nd);
		d[5] =                     ((s3 & 0174) >> 2);
		d[6] = ((s3 & 003) << 3);
	}
}

/* Conservatively avoid overflowas for BECH32_8TO5_SIZE_MAX.  */
#define	BECH32_5TO8_SIZE_MAX	(SIZE_MAX/5)

/*
 * bech32_5to8_size(n)
 *
 *	Return the number of 8-bit groups encoded by n 5-bit groups,
 *	which may include discarded padding.
 *
 *	n must be at most BECH32_5TO8_SIZE_MAX.
 */
static size_t
bech32_5to8_size(size_t n5)
{

	return (5*n5)/8;
}

/*
 * bech32_5to8(d, nd, s, ns)
 *
 *	Convert 5-bit groups to 8-bit groups: read ns bytes from s and
 *	store up to nd bytes at d; nd must be at least 5*ns/8, and ns
 *	must be at most BECH32_5TO8_SIZE_MAX.  Use bech32_5to8_size(ns)
 *	to compute the number of 8-bit groups encoded by ns 5-bit
 *	groups.
 *
 *	Returns zero if padding is correct, and some nonzero value if
 *	padding is invalid.
 */
static int
bech32_5to8(uint8_t *d, size_t nd, const uint8_t *s, size_t ns)
{

	assert(nd >= bech32_5to8_size(ns));

	/*
	 * ceiling(8*n/5) is always congruent to 0, 2, 4, 5, or 7
	 * modulo 8; other lengths are not allowed.
	 */
	switch (ns % 8) {
	case 1:
	case 3:
	case 6:
		return -1;
	}

	while (8 <= ns) {
		uint8_t s0 = s[0], s1 = s[1], s2 = s[2], s3 = s[3];
		uint8_t s4 = s[4], s5 = s[5], s6 = s[6], s7 = s[7];

		d[0] = (s0 & 037) << 3 | (s1 & 034) >> 2;
		d[1] = (s1 & 003) << 6 | s2 << 1 | (s3 & 020) >> 4;
		d[2] = (s3 & 017) << 4 | (s4 & 036) >> 1;
		d[3] = (s4 & 001) << 7 | s5 << 2 | (s6 & 030) >> 3;
		d[4] = (s6 & 007) << 5 | s7;

		d += 5, nd -= 5;
		s += 8, ns -= 8;
	}

	if (ns) {
		uint8_t s0, s1, s2, s3, s4, s5, s6;

		assert(1 <= ns && ns <= 7);
		s0 = s[0];
		s1 = (ns <= 2? 0 : s[1]);
		s2 = (ns <= 2? 0 : s[2]);
		s3 = (ns <= 4? 0 : s[3]);
		s4 = (ns <= 4? 0 : s[4]);
		s5 = (ns <= 5? 0 : s[5]);
		s6 = 0;

		assert(1 <= nd);
		d[0] = (s0 & 037) << 3 | (s1 & 034) >> 2;
		if (ns <= 2)
			return s1 & 003;
		assert(2 <= nd);
		d[1] = (s1 & 003) << 6 | s2 << 1 | (s3 & 020) >> 4;
		if (ns <= 4)
			return s3 & 017;
		assert(3 <= nd);
		d[2] = (s3 & 017) << 4 | (s4 & 036) >> 1;
		if (ns <= 5)
			return s4 & 001;
		assert(4 <= nd);
		d[3] = (s4 & 001) << 7 | s5 << 2 | (s6 & 030) >> 3;
	}

	return 0;
}

static uint8_t bech32tab[32] = {
	'q','p','z','r', 'y','9','x','8', /* 0..7 */
	'g','f','2','t', 'v','d','w','0', /* 8..15 */
	's','3','j','n', '5','4','k','h', /* 16..23 */
	'c','e','6','m', 'u','a','7','l', /* 24..31 */
};

/*
 * bech32_b2c_8(out, in)
 *
 *	Convert eight 5-bit groups from binary integer values in[0],
 *	in[1], ..., in[7] to characters out[0], out[1], ..., out[7] in
 *	the bech32 set, in constant time.
 *
 *	Caller is responsible for ensuring in[i] == in[i] & 0x1f.
 */
static void
bech32_b2c_8(char out[static 8], const uint8_t in[static 8])
{
	uint64_t out64 = 0;
	uint64_t in64;
	uint64_t i;

	/*
	 * We use 8 bits to store each unit: 7 bits for the data (5
	 * bits for each 5-bit input unit, 7 bits for each US-ASCII
	 * output unit), and 1 bit to borrow from in order to test for
	 * equality.
	 */

	/*
	 * Load input.  byte order doesn't matter as long as it matches
	 * on input and output -- each byte is independent.
	 */
	memcpy(&in64, in, 8);
	assert(in64 == (in64 & UINT64_C(0x1f1f1f1f1f1f1f1f)));

	for (i = 0; (i & 0x20) == 0; i += UINT64_C(0x0101010101010101)) {
		uint64_t m, c;

		/* Create masks: all ones if equal, all zeros if no.  */
		m = in64 ^ i;				/* zero if equal */
		assert(m == (m & UINT64_C(0x1f1f1f1f1f1f1f1f)));
		m |= UINT64_C(0x2020202020202020);	/* set high bit */
		m -= UINT64_C(0x0101010101010101);	/* borrow if zero */
		m &= UINT64_C(0x2020202020202020);	/* clear low bits */
		m >>= 5;				/* smear */
		assert(m == (m & UINT64_C(0x0101010101010101)));
		m |= m << 1;
		assert(m == (m & UINT64_C(0x0303030303030303)));
		m |= m << 2;
		assert(m == (m & UINT64_C(0x0f0f0f0f0f0f0f0f)));
		m |= m << 3;
		assert(m == (m & UINT64_C(0x7f7f7f7f7f7f7f7f)));

		/* Copy the table entry to all positions.  */
		c = bech32tab[i & 0x1f];
		c |= c << 8;
		c |= c << 16;
		c |= c << 32;
		assert(c == (c & UINT64_C(0x7f7f7f7f7f7f7f7f)));

		/* Conditional swap.  */
		out64 = (out64 & m) | (c & ~m);
		assert(out64 == (out64 & UINT64_C(0x7f7f7f7f7f7f7f7f)));
	}

	/* Store output.  */
	memcpy(out, &out64, 8);
}

/*
 * bech32_b2c(out, in, n)
 *
 *	Convert 5-bit groups from binary integer values in[0], in[1],
 *	..., in[n-1] to characters out[0], out[1], ..., out[n-1] in
 *	the bech32 set, in constant time.
 */
static void
bech32_b2c(char *out, const uint8_t *in, size_t n)
{

	while (8 <= n) {
		bech32_b2c_8(out, in);
		out += 8;
		in += 8;
		n -= 8;
	}

	if (n) {
		uint8_t buf[8];

		memcpy(buf, in, n);
		memset(buf + n, 0, 8 - n);
		bech32_b2c_8((char *)buf, buf);
		memcpy(out, buf, n);
	}
}

/*
 * bech32_c2b_8(out, in)
 *
 *	Convert eight 5-bit groups from characters in[0], in[1], ...,
 *	in[7] in the bech32 set to binary integer values out[0],
 *	out[1], ..., out[7], in constant time.
 *
 *	Returns 0 if the encoding is valid, -1 if invalid.
 */
static int
bech32_c2b_8(uint8_t out[static 8], const char in[static 8])
{
	uint64_t out64 = UINT64_C(0x8080808080808080); /* error indicators */
	uint64_t in64;
	uint64_t i;
	uint64_t error = 0;

	/*
	 * We use 8 bits to store each unit: 7 bits for the data (7
	 * bits for each US-ASCII input unit, 5 bits for each 5-bit
	 * output unit), and 1 bit to borrow from in order to test for
	 * equality.
	 */

	/*
	 * Load input.  Byte order doesn't matter as long as it matches
	 * on input and output -- each byte is independent.
	 */
	memcpy(&in64, in, 8);

	/*
	 * Input should be US-ASCII; take eighth bit as error
	 * indicator, and then clear it while we work on 7-bit units.
	 */
	error |= in64 & UINT64_C(0x8080808080808080);
	in64 &= ~UINT64_C(0x8080808080808080);

	for (i = 0; (i & 0x20) == 0; i += UINT64_C(0x0101010101010101)) {
		uint64_t m, c;

		/* Copy the table entry to all positions.  */
		c = bech32tab[i & 0x1f];
		c |= c << 8;
		c |= c << 16;
		c |= c << 32;
		assert(c == (c & UINT64_C(0x7f7f7f7f7f7f7f7f)));

		/* Create masks: all ones if equal, all zeros if not.  */
		m = in64 ^ c;				/* zero if equal */
		assert(m == (m & UINT64_C(0x7f7f7f7f7f7f7f7f)));
		m |= UINT64_C(0x8080808080808080);	/* set high bit */
		m -= UINT64_C(0x0101010101010101);	/* borrow if zero */
		m &= UINT64_C(0x8080808080808080);	/* clear low bits */
		m >>= 7;				/* smear */
		assert(m == (m & UINT64_C(0x0101010101010101)));
		m |= m << 1;
		assert(m == (m & UINT64_C(0x0303030303030303)));
		m |= m << 2;
		assert(m == (m & UINT64_C(0x0f0f0f0f0f0f0f0f)));
		m |= m << 4;

		/* Conditional swap.  */
		out64 = (out64 & m) | (i & ~m);
	}

	/*
	 * If any error indicators are still there in out64, report
	 * them as error.
	 */
	error |= out64 & UINT64_C(0x8080808080808080);

	/*
	 * Clear error indicators to avoid violating invariants
	 * downstream that assume only bits 0x1f are set.
	 */
	out64 &= UINT64_C(0x7f7f7f7f7f7f7f7f);

	/* Store output.  */
	memcpy(out, &out64, 8);

	/*
	 * Map zero to 0, nonzero to -1.  In this case, all the nonzero
	 * bits will be at positions 7 mod 8, so shift them to 0 mod 8
	 * and then combine them all at 0.
	 */
	error >>= 7;
	error |= error >> 8;
	error |= error >> 16;
	error |= error >> 32;
	return -(error & 1);
}

/*
 * bech32_c2b(out, in, n)
 *
 *	Convert 5-bit groups from characters in[0], in[1], ...,
 *	in[n-1]] in the bech32 set to binary integer values out[0],
 *	out[1], ..., out[n-1], in constant time.
 *
 *	Returns 0 if the encoding is valid, -1 if invalid.
 */
static int
bech32_c2b(uint8_t *out, const char *in, size_t n)
{
	int error = 0;

	while (8 <= n) {
		error |= bech32_c2b_8(out, in);
		out += 8;
		in += 8;
		n -= 8;
	}

	if (n) {
		uint8_t buf[8];

		memcpy(buf, in, n);
		memset(buf + n, 'q', 8 - n);
		error |= bech32_c2b_8(buf, (const char *)buf);
		memcpy(out, buf, n);
	}

	return error;
}

/*
 * bech32 checksum
 */

static inline uint32_t
bch_step(uint32_t c, uint8_t x)
{
	uint32_t b = c >> 25;

	assert(x == (x & 0x1f));

	c &= UINT32_C(0x01ffffff);
	c <<= 5;
	c ^= x;

	c ^= UINT32_C(0x3b6a57b2) & -(b & 1); b >>= 1;
	c ^= UINT32_C(0x26508e6d) & -(b & 1); b >>= 1;
	c ^= UINT32_C(0x1ea119fa) & -(b & 1); b >>= 1;
	c ^= UINT32_C(0x3d4233dd) & -(b & 1); b >>= 1;
	c ^= UINT32_C(0x2a1462b3) & -(b & 1); b >>= 1;

	return c;
}

static uint32_t
bch_hrp(uint32_t c, const uint8_t *x, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++)
		c = bch_step(c, x[i] >> 5);
	c = bch_step(c, 0);
	for (i = 0; i < n; i++)
		c = bch_step(c, x[i] & 0x1f);

	return c;
}

static uint32_t
bch_data(uint32_t c, const uint8_t *x, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++)
		c = bch_step(c, x[i]);

	return c;
}

static void
bech32_cksum(uint8_t ck[static 6], const void *hrp, size_t nhrp,
    const void *data, size_t ndata)
{
	uint32_t c = 1;
	unsigned i;

	c = bch_hrp(c, hrp, nhrp);
	c = bch_data(c, data, ndata);
	for (i = 0; i < 6; i++)
		c = bch_step(c, 0);
	c ^= 1;

	ck[0] = (c >> 25) & 0x1f;
	ck[1] = (c >> 20) & 0x1f;
	ck[2] = (c >> 15) & 0x1f;
	ck[3] = (c >> 10) & 0x1f;
	ck[4] = (c >> 5) & 0x1f;
	ck[5] = c & 0x1f;
}

static uint32_t
bech32_verify(const void *hrp, size_t nhrp,
    const void *datacksum, size_t ndatacksum)
{
	uint32_t c = 1;

	c = bch_hrp(c, hrp, nhrp);
	c = bch_data(c, datacksum, ndatacksum);

	return c - 1;
}

/*
 * bech32 format
 */

#define	BECH32_CKSUMLEN		6u

/* HRP (nonempty) || `1' || cksum */
#define	BECH32_MIN		(1u + 1u + BECH32_CKSUMLEN)

#define	BECH32_DATA_MAX		(BECH32_MAX - BECH32_MIN)

CTASSERT(BECH32_HRP_MAX == BECH32_MAX - 1 - BECH32_CKSUMLEN);
CTASSERT(BECH32_PAYLOAD_MAX == (5*(BECH32_MAX - BECH32_MIN))/8);
CTASSERT(BECH32_PAYLOAD_MAX <= BECH32_8TO5_SIZE_MAX);

/*
 * bech32enc_size(nhrp, npayload)
 *
 *	Returns the number of characters in the bech32 encoding for
 *	given HRP and payload lengths, which must be at most
 *	BECH32_HRP_MAX and BECH32_PAYLOAD_MAX.  The result is at most
 *	BECH32_MAX, and does not include space for a NUL terminator.
 */
int
bech32enc_size(size_t nhrp, size_t npayload)
{
	size_t nbech32;

	assert(nhrp <= BECH32_HRP_MAX);
	assert(npayload <= BECH32_PAYLOAD_MAX);

	nbech32 = nhrp + 1 + bech32_8to5_size(npayload) + BECH32_CKSUMLEN;

	return (nbech32 <= BECH32_MAX ? (int)nbech32 : -1);
}

/*
 * bech32dec_size(nhrp, nbech32)
 *
 *	Returns the number of bytes encoded in a bech32 string of
 *	nbech32 characters long, not including a NUL terminator, with
 *	an HRP of length nhrp.  nhrp must be at most BECH32_HRP_MAX,
 *	and nbech32 must be at most BECH32_MAX.  The result is at most
 *	BECH32_PAYLOAD_MAX.
 */
int
bech32dec_size(size_t nhrp, size_t nbech32)
{
	size_t npayload;

	assert(nhrp <= BECH32_HRP_MAX);
	assert(nbech32 <= BECH32_MAX);

	npayload = bech32_5to8_size(nbech32 - nhrp - 1 - BECH32_CKSUMLEN);

	return (npayload <= BECH32_PAYLOAD_MAX ? (int)npayload : -1);
}

/*
 * bech32enc(bech32, nbech32, hrp, nhrp, payload, npayload)
 *
 *	Encode the given nhrp-byte HRP and npayload-byte payload in the
 *	nbech32-byte buffer at bech32, and NUL-terminate the buffer.
 *	Return -1 on failure (if any of the sizes involved are
 *	invalid), or the number of bytes in the bech32 encoding,
 *	excluding the NUL terminator, on success.
 *
 *	Note: This encodes lowercase bech32.  Caller is responsible for
 *	specifying a lowercase HRP.
 *
 *	bech32enc runs in time independent of the values of hrp[0],
 *	hrp[1], ..., hrp[n - 1] and payload[0], payload[1], ...,
 *	payload[npayload - 1].  However, the timing does depend on the
 *	values of nhrp and npayload.
 */
int
bech32enc(char *bech32, size_t nbech32, const void *hrp, size_t nhrp,
    const void *payload, size_t npayload)
{
	uint8_t datacksum[BECH32_DATA_MAX + BECH32_CKSUMLEN];
	size_t ndata;

	if (nhrp == 0)
		return -1;
	if (nhrp > BECH32_HRP_MAX)
		return -1;
	if (npayload > BECH32_PAYLOAD_MAX)
		return -1;
	ndata = bech32_8to5_size(npayload);
	assert(ndata <= BECH32_DATA_MAX);
	CTASSERT(BECH32_DATA_MAX <= SIZE_MAX - 1 - BECH32_CKSUMLEN - 1);
	if (nbech32 < nhrp + 1 + ndata + BECH32_CKSUMLEN + 1)
		return -1;
	if (nhrp + 1 + ndata + BECH32_CKSUMLEN > BECH32_MAX)
		return -1;

	/* Copy the HRP and `1'.  */
	memcpy(bech32, hrp, nhrp);
	bech32[nhrp] = '1';

	/* Convert 8-bit groups to 5-bit groups in our temporary buffer.  */
	bech32_8to5(datacksum, ndata, payload, npayload);

	/* Compute the checksum.  */
	bech32_cksum(datacksum + ndata, hrp, nhrp, datacksum, ndata);
	assert(bech32_verify(hrp, nhrp, datacksum, ndata + BECH32_CKSUMLEN)
	    == 0);

	/* Encode 5-bit groups.  */
	bech32_b2c(bech32 + nhrp + 1, datacksum, ndata + BECH32_CKSUMLEN);

	/* NUL-terminate.  */
	bech32[nhrp + 1 + ndata + BECH32_CKSUMLEN] = '\0';

	/* Return the length of the output string, excluding NUL.  */
	assert(nhrp + 1 + ndata + BECH32_CKSUMLEN <= INT_MAX);
	return (int)(nhrp + 1 + ndata + BECH32_CKSUMLEN);
}

/*
 * bech32enc_upper(bech32, nbech32, hrp, nhrp, payload, npayload)
 *
 *	Encode the given nhrp-byte HRP and npayload-byte payload in the
 *	nbech32-byte buffer at bech32, and NUL-terminate the buffer.
 *	Return -1 on failure (if any of the sizes involved are
 *	invalid), or the number of bytes in the bech32 encoding,
 *	excluding the NUL terminator, on success.
 *
 *	Note: This encodes uppercase bech32.  Caller is responsible for
 *	specifying a _lowercase_ HRP, not an uppercase HRP.
 *
 *	bech32enc runs in time independent of the values of hrp[0],
 *	hrp[1], ..., hrp[n - 1] and payload[0], payload[1], ...,
 *	payload[npayload - 1].  However, the timing does depend on the
 *	values of nhrp and npayload.
 */
int
bech32enc_upper(char *bech32, size_t nbech32, const void *hrp, size_t nhrp,
    const void *payload, size_t npayload)
{
	int n;
	int error;

	n = bech32enc(bech32, nbech32, hrp, nhrp, payload, npayload);
	if (n == -1)
		return -1;
	assert(n >= 0);
	assert(bech32[n] == '\0');
	error = bech32_toupper(bech32, bech32, (size_t)n);
	(void)error;
	assert(error == 0);

	return n;
}

/*
 * bech32dec(payload, npayload, hrp, nhrp, bech32, nbech32)
 *
 *	Verify and decode the nbech32-byte string at bech32.  Return -1
 *	on failure (mismatched HRP, not all uppercase or all lowercase,
 *	wrong character set, bad checksum), or the number of bytes
 *	encoded by the bech32 string on success.
 *
 *	Note: Caller is responsible for specifying a valid lowercase
 *	HRP.
 *
 *	bech32dec runs in time independent of the values of hrp[0],
 *	hrp[1], ..., hrp[n - 1] and bech32[0], bech32[1], ...,
 *	bech32[nbech32 - 1].  However, the timing does depend on the
 *	values of nhrp and nbech32.
 */
int
bech32dec(void *payload, size_t npayload, const void *hrp, size_t nhrp,
    const char *bech32, size_t nbech32)
{
	char buf[BECH32_MAX + 1];
	uint8_t datacksum[BECH32_DATA_MAX + BECH32_CKSUMLEN];
	size_t i, ndata;
	int notupper, notlower, error = 0;

	if (nhrp == 0)		/* hrp must be nonempty */
		return -1;
	if (nbech32 < BECH32_MIN || nbech32 > BECH32_MAX)
		return -1;
	CTASSERT(BECH32_MIN >= BECH32_CKSUMLEN + 1);
	if (nbech32 - BECH32_CKSUMLEN - 1 < nhrp)
		return -1;

	/* Convert to uppercase and see whether it matches.  */
	error |= bech32_toupper(buf, bech32, nbech32);
	for (notupper = 0, i = 0; i < nbech32; i++)
		notupper |= bech32[i] ^ buf[i];

	/*
	 * Convert to lowercase and see whether it matches.  Leave the
	 * buffer as lowercase for subsequent processing.
	 */
	error |= bech32_tolower(buf, bech32, nbech32);
	for (notlower = 0, i = 0; i < nbech32; i++)
		notlower |= bech32[i] ^ buf[i];

	/* Map zero to 0, nonzero to -1.  */
	notupper = ~((notupper - 1) >> 8);
	notlower = ~((notlower - 1) >> 8);

	/* Error if notlower and notupper.  */
	error |= notupper & notlower;

	/* Verify that bech32 starts with hrp followed by `1'.  */
	for (i = 0; i < nhrp; i++)
		error |= buf[i] ^ ((const char *)hrp)[i];
	error |= buf[nhrp] ^ '1';

	/* Determine the length of the encoded data part.  */
	ndata = nbech32 - nhrp - 1 - BECH32_CKSUMLEN;
	if (npayload < bech32_5to8_size(ndata))
		return -1;

	/* Decode 5-bit groups.  */
	error |= bech32_c2b(datacksum, buf + nhrp + 1,
	    ndata + BECH32_CKSUMLEN);

	/* Verify the checksum.  */
	error |= bech32_verify(hrp, nhrp, datacksum, ndata + BECH32_CKSUMLEN);

	/* Convert 5-bit groups in our temporary buffer to 8-bit groups.  */
	error |= bech32_5to8(payload, npayload, datacksum, ndata);

	/* Map zero error to 0, nonzero error to 1.  */
	error |= error >> 1;
	error |= error >> 2;
	error |= error >> 4;
	error |= error >> 8;
	error |= error >> 16;
	error &= 1;

	/* Return -1 on error, true length of payload on success.  */
	return -error | bech32_5to8_size(ndata);
}
