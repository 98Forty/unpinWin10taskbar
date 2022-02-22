# Copyright 2011-2012 pooler@litecoinpool.org
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.


#if defined(OPTIMIZED_SALSA) && defined(__x86_64__)

#if defined(__linux__) && defined(__ELF__)
	.section .note.GNU-stack,"",%progbits
#endif

#define scrypt_shuffle(src, so, dest, do) \
	movl	so+60(src), %r8d; \
	movl	so+44(src), %r9d; \
	movl	so+28(src), %r10d; \
	movl	so+12(src), %r11d; \
	movl	%r8d, do+12(dest); \
	movl	%r9d, do+28(dest); \
	movl	%r10d, do+44(dest); \
	movl	%r11d, do+60(dest); \
	movl	so+40(src), %r8d; \
	movl	so+8(src), %r9d; \
	movl	so+48(src), %r10d; \
	movl	so+16(src), %r11d; \
	movl	%r8d, do+8(dest); \
	movl	%r9d, do+40(dest); \
	movl	%r10d, do+16(dest); \
	movl	%r11d, do+48(dest); \
	movl	so+20(src), %r8d; \
	movl	so+4(src), %r9d; \
	movl	so+52(src), %r10d; \
	movl	so+36(src), %r11d; \
	movl	%r8d, do+4(dest); \
	movl	%r9d, do+20(dest); \
	movl	%r10d, do+36(dest); \
	movl	%r11d, do+52(dest); \
	movl	so+0(src), %r8d; \
	movl	so+24(src), %r9d; \
	movl	so+32(src), %r10d; \
	movl	so+56(src), %r11d; \
	movl	%r8d, do+0(dest); \
	movl	%r9d, do+24(dest); \
	movl	%r10d, do+32(dest); \
	movl	%r11d, do+56(dest); \


#define gen_salsa8_core_doubleround() \
	movq	72(%rsp), %r15; \
	leaq	(%r14, %rdx), %rbp; \
	roll	$7, %ebp; \
	xorq	%rbp, %r9; \
	leaq	(%rdi, %r15), %rbp; \
	roll	$7, %ebp; \
	xorq	%rbp, %r10; \
	leaq	(%rdx, %r9), %rbp; \
	roll	$9, %ebp; \
	xorq	%rbp, %r11; \
	leaq	(%r15, %r10), %rbp; \
	roll	$9, %ebp; \
	xorq	%rbp, %r13; \
	leaq	(%r9, %r11), %rbp; \
	roll	$13, %ebp; \
	xorq	%rbp, %r14; \
	leaq	(%r10, %r13), %rbp; \
	roll	$13, %ebp; \
	xorq	%rbp, %rdi; \
	leaq	(%r11, %r14), %rbp; \
	roll	$18, %ebp; \
	xorq	%rbp, %rdx; \
	leaq	(%r13, %rdi), %rbp; \
	roll	$18, %ebp; \
	xorq	%rbp, %r15; \
	movq	48(%rsp), %rbp; \
	movq	%r15, 72(%rsp); \
	leaq	(%rax, %rbp), %r15; \
	roll	$7, %r15d; \
	xorq	%r15, %rbx; \
	leaq	(%rbp, %rbx), %r15; \
	roll	$9, %r15d; \
	xorq	%r15, %rcx; \
	leaq	(%rbx, %rcx), %r15; \
	roll	$13, %r15d; \
	xorq	%r15, %rax; \
	leaq	(%rcx, %rax), %r15; \
	roll	$18, %r15d; \
	xorq	%r15, %rbp; \
	movq	88(%rsp), %r15; \
	movq	%rbp, 48(%rsp); \
	leaq	(%r12, %r15), %rbp; \
	roll	$7, %ebp; \
	xorq	%rbp, %rsi; \
	leaq	(%r15, %rsi), %rbp; \
	roll	$9, %ebp; \
	xorq	%rbp, %r8; \
	leaq	(%rsi, %r8), %rbp; \
	roll	$13, %ebp; \
	xorq	%rbp, %r12; \
	leaq	(%r8, %r12), %rbp; \
	roll	$18, %ebp; \
	xorq	%rbp, %r15; \
	movq	%r15, 88(%rsp); \
	movq	72(%rsp), %r15; \
	leaq	(%rsi, %rdx), %rbp; \
	roll	$7, %ebp; \
	xorq	%rbp, %rdi; \
	leaq	(%r9, %r15), %rbp; \
	roll	$7, %ebp; \
	xorq	%rbp, %rax; \
	leaq	(%rdx, %rdi), %rbp; \
	roll	$9, %ebp; \
	xorq	%rbp, %rcx; \
	leaq	(%r15, %rax), %rbp; \
	roll	$9, %ebp; \
	xorq	%rbp, %r8; \
	leaq	(%rdi, %rcx), %rbp; \
	roll	$13, %ebp; \
	xorq	%rbp, %rsi; \
	leaq	(%rax, %r8), %rbp; \
	roll	$13, %ebp; \
	xorq	%rbp, %r9; \
	leaq	(%rcx, %rsi), %rbp; \
	roll	$18, %ebp; \
	xorq	%rbp, %rdx; \
	leaq	(%r8, %r9), %rbp; \
	roll	$18, %ebp; \
	xorq	%rbp, %r15; \
	movq	48(%rsp), %rbp; \
	movq	%r15, 72(%rsp); \
	leaq	(%r10, %rbp), %r15; \
	roll	$7, %r15d; \
	xorq	%r15, %r12; \
	leaq	(%rbp, %r12), %r15; \
	roll	$9, %r15d; \
	xorq	%r15, %r11; \
	leaq	(%r12, %r11), %r15; \
	roll	$13, %r15d; \
	xorq	%r15, %r10; \
	leaq	(%r11, %r10), %r15; \
	roll	$18, %r15d; \
	xorq	%r15, %rbp; \
	movq	88(%rsp), %r15; \
	movq	%rbp, 48(%rsp); \
	leaq	(%rbx, %r15), %rbp; \
	roll	$7, %ebp; \
	xorq	%rbp, %r14; \
	leaq	(%r15, %r14), %rbp; \
	roll	$9, %ebp; \
	xorq	%rbp, %r13; \
	leaq	(%r14, %r13), %rbp; \
	roll	$13, %ebp; \
	xorq	%rbp, %rbx; \
	leaq	(%r13, %rbx), %rbp; \
	roll	$18, %ebp; \
	xorq	%rbp, %r15; \
	movq	%r15, 88(%rsp); \


	.text
	.align 32
gen_salsa8_core:
	# 0: %rdx, %rdi, %rcx, %rsi
	movq	8(%rsp), %rdi
	movq	%rdi, %rdx
	shrq	$32, %rdi
	movq	16(%rsp), %rsi
	movq	%rsi, %rcx
	shrq	$32, %rsi
	# 1: %r9, 72(%rsp), %rax, %r8
	movq	24(%rsp), %r8
	movq	%r8, %r9
	shrq	$32, %r8
	movq	%r8, 72(%rsp)
	movq	32(%rsp), %r8
	movq	%r8, %rax
	shrq	$32, %r8
	# 2: %r11, %r10, 48(%rsp), %r12
	movq	40(%rsp), %r10
	movq	%r10, %r11
	shrq	$32, %r10
	movq	48(%rsp), %r12
	#movq	%r12, %r13
	#movq	%r13, 48(%rsp)
	shrq	$32, %r12
	# 3: %r14, %r13, %rbx, 88(%rsp)
	movq	56(%rsp), %r13
	movq	%r13, %r14
	shrq	$32, %r13
	movq	64(%rsp), %r15
	movq	%r15, %rbx
	shrq	$32, %r15
	movq	%r15, 88(%rsp)

	gen_salsa8_core_doubleround()
	gen_salsa8_core_doubleround()
	gen_salsa8_core_doubleround()
	gen_salsa8_core_doubleround()

	movl	%edx, %edx
	shlq	$32, %rdi
	addq	%rdi, %rdx
	movd	%rdx, %xmm0

	movl	%ecx, %ecx
	shlq	$32, %rsi
	addq	%rsi, %rcx
	movd	%rcx, %xmm4

	movq	72(%rsp), %rdi
	movl	%r9d, %r9d
	shlq	$32, %rdi
	addq	%rdi, %r9
	movd	%r9, %xmm1

	movl	%eax, %eax
	shlq	$32, %r8
	addq	%r8, %rax
	movd	%rax, %xmm5

	movl	%r11d, %r11d
	shlq	$32, %r10
	addq	%r10, %r11
	movd	%r11, %xmm2

	movl	48(%rsp), %r8d
	shlq	$32, %r12
	addq	%r12, %r8
	movd	%r8, %xmm6

	movl	%r14d, %r14d
	shlq	$32, %r13
	addq	%r13, %r14
	movd	%r14, %xmm3

	movq	88(%rsp), %rdi
	movl	%ebx, %ebx
	shlq	$32, %rdi
	addq	%rdi, %rbx
	movd	%rbx, %xmm7

	punpcklqdq	%xmm4, %xmm0
	punpcklqdq	%xmm5, %xmm1
	punpcklqdq	%xmm6, %xmm2
	punpcklqdq	%xmm7, %xmm3

	#movq	%rdx, 8(%rsp)
	#movq	%rcx, 16(%rsp)
	#movq	%r9, 24(%rsp)
	#movq	%rax, 32(%rsp)
	#movq	%r11, 40(%rsp)
	#movq	%r8, 48(%rsp)
	#movq	%r14, 56(%rsp)
	#movq	%rbx, 64(%rsp)

	ret


	.text
	.align 32
	.globl scrypt_core
	.globl _scrypt_core
scrypt_core:
_scrypt_core:
	pushq	%rbx
	pushq	%rbp
	pushq	%