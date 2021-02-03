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

#ifndef	CTASSERT_H
#define	CTASSERT_H

#if __STDC_VERSION__ >= 201112L
#include <assert.h>
#define	CTASSERT(x)	static_assert(x, #x)
#else
#ifdef __COUNTER__
#define	CTASSERT(x)		CTASSERT1(x, ctassert, __COUNTER__)
#else
#define	CONCAT(u,v)		u##v
#define	CTASSERT(x)		CTASSERT0(x, __INCLUDE_LEVEL__, __LINE__)
#define	CTASSERT0(x,u,v)	CTASSERT1(x, CONCAT(level_,u), CONCAT(line_,v))
#endif
#define	CTASSERT1(x,u,v)	CTASSERT2(x,u,v)
#define	CTASSERT2(x,u,v)						      \
	struct ctassert_##u##_##v {					      \
		unsigned int u##v : ((x) ? 1 : -1);			      \
	}
#endif

#endif	/* CTASSERT_H */
