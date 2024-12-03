/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Authors: Simon Kuenzer <simon.kuenzer@neclab.eu>
 *
 * Copyright (c) 2019, NEC Laboratories Europe GmbH,
 *                     NEC Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <inttypes.h>
#include <string.h>
#include <errno.h>
#include <uk/alloc.h>
#include <uk/print.h>
#include <uk/syscall.h>
#include <uk/thread.h>
#include <uk/arch/limits.h>

#ifndef PAGES2BYTES
#define PAGES2BYTES(x) ((x) << __PAGE_SHIFT)
#endif

#define HEAP_PAGES CONFIG_APPELFLOADER_BRK_NBPAGES
#define HEAP_LEN   PAGES2BYTES(CONFIG_APPELFLOADER_BRK_NBPAGES)

extern __uk_tls __uptr _uk_brk_base;
extern __uk_tls __uptr _uk_brk_cur;
extern __uk_tls __uptr _uk_brk_zeroed;
extern __uk_tls __sz _uk_brk_len;

UK_LLSYSCALL_R_DEFINE(void *, brk, void *, addr)
{
	void *base = NULL;
	void *brk_cur = NULL;
	void *zeroed = NULL;
	intptr_t len = 0;

	//uk_pr_err("doing brk for thread 0x%lx @ 0x%lx\n", uk_thread_current(), addr);

	ukplat_tlsp_get();

	base = (void *)uk_thread_uktls_var(uk_thread_current(), _uk_brk_base);
	brk_cur = (void *)uk_thread_uktls_var(uk_thread_current(), _uk_brk_cur);
	zeroed = (void *)uk_thread_uktls_var(uk_thread_current(), _uk_brk_zeroed);
	len = (intptr_t)uk_thread_uktls_var(uk_thread_current(), _uk_brk_len);
#if 0
	uk_pr_err("base: 0x%lx\n", (long)base);
	uk_pr_err("cur: 0x%lx\n", (long)brk_cur);
	uk_pr_err("zeroed: 0x%lx\n", (long)zeroed);
	uk_pr_err("len: 0x%lx\n", (long)len);
#endif

	/* allocate brk context */
	if (!base) {
		base = uk_palloc(uk_alloc_get_default(), HEAP_PAGES);
		if (!base) {
			uk_pr_crit("Could not allocate memory for heap (%"PRIu64" KiB): Out of memory\n",
				   (uint64_t) HEAP_LEN / 1024);
			return ERR2PTR(-ENOMEM);
		}

		/* initialize brk_cur with start of allocated heap region */
		brk_cur = base;
		zeroed = base;
		len = 0;

		uk_pr_debug("New brk heap region: %p-%p\n",
			    base, base + HEAP_LEN);
	}

	UK_ASSERT(brk_cur != NULL);

	if (addr < base || addr >= (base + HEAP_LEN)) {
		uk_pr_debug("Outside of brk range, return current brk %p\n",
			    brk_cur);

		uk_thread_uktls_var(uk_thread_current(), _uk_brk_base) = base;
		uk_thread_uktls_var(uk_thread_current(), _uk_brk_cur) = brk_cur;
		uk_thread_uktls_var(uk_thread_current(), _uk_brk_zeroed) = zeroed;
		uk_thread_uktls_var(uk_thread_current(), _uk_brk_len) = len;

		return brk_cur;
	}

	/* Zero out requested memory (e.g., glibc requires) */
	if (addr > zeroed) {
		uk_pr_debug("zeroing %p-%p...\n", zeroed, addr);
		memset(zeroed, 0x0, (size_t) (addr - zeroed));
	}

	brk_cur = addr;
	zeroed = addr;
	len = addr - base;

	uk_thread_uktls_var(uk_thread_current(), _uk_brk_base) = base;
	uk_thread_uktls_var(uk_thread_current(), _uk_brk_cur) = brk_cur;
	uk_thread_uktls_var(uk_thread_current(), _uk_brk_zeroed) = zeroed;
	uk_thread_uktls_var(uk_thread_current(), _uk_brk_len) = len;

	uk_pr_debug("brk @ %p (brk heap region: %p-%p)\n", addr, base, base + HEAP_LEN);

	return addr;
}

#if LIBC_SYSCALLS
#include <unistd.h>
#include <uk/errptr.h>

int brk(void *addr)
{
	long ret;
	ret = uk_syscall_r_brk(addr);
	if (ret == 0) {
		errno = EFAULT;
		return -1;
	}
	if (PTRISERR(ret)) {
		errno = PTR2ERR(ret);
		return -1;
	}
	return 0;
}

void *sbrk(intptr_t inc)
{
	long ret;
	void *prev_base = base;

	if (!base) {
		/* Case when we do not have any memory allocated yet */
		if (inc > HEAP_LEN) {
			errno = ENOMEM;
			return (void *) -1;
		}
		ret = uk_syscall_r_brk(NULL);
	} else {
		/* We are increasing or reducing our range */
		ret = uk_syscall_r_brk((long)base + len + inc);
	}

	if (ret == 0) {
		errno = EFAULT;
		return (void *) -1;
	}
	if (PTRISERR(ret)) {
		errno = PTR2ERR(ret);
		return (void *) -1;
	}

	if (!prev_base)
		return base;
	return prev_base;
}
#endif /* LIBC_SYSCALLS */
