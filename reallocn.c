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

#define	_POSIX_C_SOURCE	200809L

#include "reallocn.h"

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int
reallocn(void *p, size_t nelem, size_t elemsize)
{
	void *optr, *nptr;
	int saved_errno = errno;

	memcpy(&optr, p, sizeof(optr));
	if (nelem == 0 || elemsize == 0) {
		free(optr);
		nptr = NULL;
	} else {
		if (nelem > SIZE_MAX/elemsize) {
			errno = EOVERFLOW;
			return -1;
		}
		if ((nptr = realloc(optr, nelem * elemsize)) == NULL)
			return -1;
	}
	memcpy(p, &nptr, sizeof(nptr));

	errno = saved_errno;
	return 0;
}
