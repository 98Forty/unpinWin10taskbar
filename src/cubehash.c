/* $Id: cubehash.c 227 2010-06-16 17:28:38Z tp $ */
/*
 * CubeHash implementation.
 *
 * ==========================(LICENSE BEGIN)============================
 *
 * Copyright (c) 2007-2010  Projet RNRT SAPHIR
 * 
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 * 
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * ===========================(LICENSE END)=============================
 *
 * @author   Thomas Pornin <thomas.pornin@cryptolog.com>
 */

#include <stddef.h>
#include <string.h>
#include <limits.h>

#include "sph_cubehash.h"
#ifdef __cplusplus
extern "C"{
#endif

#if SPH_SMALL_FOOTPRINT && !defined SPH_SMALL_FOOTPRINT_CUBEHASH
#define SPH_SMALL_FOOTPRINT_CUBEHASH   1
#endif

/*
 * Some tests were conducted on an Intel Core2 Q6600 (32-bit and 64-bit
 * mode), a PowerPC G3, and a MIPS-compatible CPU (Broadcom BCM3302).
 * It appears that the optimal settings are:
 *  -- full unroll, no state copy on the "big" systems (x86, PowerPC)
 *  -- unroll to 4 or 8, state copy on the "small" system (MIPS)
 */

#if SPH_SMALL_FOOTPRINT_CUBEHASH

#if !defined SPH_CUBEHASH_UNROLL
#define SPH_CUBEHASH_UNROLL   4
#endif
#if !defined SPH_CUBEHASH_NOCOPY
#define SPH_CUBEHASH_NOCOPY   1
#endif

#else

#if !defined SPH_CUBEHASH_UNROLL
#define SPH_CUBEHASH_UNROLL   0
#endif
#if !defined SPH_CUBEHASH_NOCOPY
#define SPH_CUBEHASH_NOCOPY   0
#endif

#endif

#ifdef _MSC_VER
#pragma warning (disable: 4146)
#endif

static const sph_u32 IV224[] = {
	SPH_C32(0xB0FC8217), SPH_C32(0x1BEE1A90), SPH_C32(0x829E1A22),
	SPH_C32(0x6362C342), SPH_C32(0x24D91C30), SPH_C32(0x03A7AA24),
	SPH_C32(0xA63721C8), SPH_C32(0x85B0E2EF), SPH_C32(0xF35D13F3),
	SPH_C32(0x41DA807D), SPH_C32(0x21A70CA6), SPH_C32(0x1F4E9774),
	SPH_C32(0xB3E1C932), SPH_C32(0xEB0A79A8), SPH_C32(0xCDDAAA66),
	SPH_C32(0xE2F6ECAA), SPH_C32(0x0A713362), SPH_C32(0xAA3080E0),
	SPH_C32(0xD8F23A32), SPH_C32(0xCEF15E28), SPH_C32(0xDB086314),
	SPH_C32(0x7F709DF7), SPH_C32(0xACD228A4), SPH_C32(0x704D6ECE),
	SPH_C32(0xAA3EC95F), SPH_C32(0xE387C214), SPH_C32(0x3A6445FF),
	SPH_C32(0x9CAB81C3), SPH_C32(0xC73D4B98), SPH_C32(0xD277AEBE),
	SPH_C32(0xFD20151C), SPH_C32(0x00CB573E)
};

static const sph_u32 IV256[] = {
	SPH_C32(0xEA2BD4B4), SPH_C32(0xCCD6F29F), SPH_C32(0x63117E71),
	SPH_C32(0x35481EAE), SPH_C32(0x22512D5B), SPH_C32(0xE5D94E63),
	SPH_C32(0x7E624131), SPH_C32(0xF4CC12BE), SPH_C32(0xC2D0B696),
	SPH_C32(0x42AF2070), SPH_C32(0xD0720C35), SPH_C32(0x3361DA8C),
	SPH_C32(0x28CCECA4), SPH_C32(0x8EF8AD83), SPH_C32(0x4680AC00),
	SPH_C32(0x40E5FBAB), SPH_C32(0xD89041C3), SPH_C32(0x6107FBD5),
	SPH_C32(0x6C859D41), SPH_C32(0xF0B26679), SPH_C32(0x09392549),
	SPH_C32(0x5FA25603), SPH_C32(0x65C892FD), SPH_C32(0x93CB6285),
	SPH_C32(0x2AF2B5AE), SPH_C32(0x9E4B4E60), SPH_C32(0x774ABFDD),
	SPH_C32(0x85254725), SPH_C32(0x15815AEB), SPH_C32(0x4AB6AAD6),
	SPH_C32(0x9CDAF8AF), SPH_C32(0xD6032C0A)
};

static const sph_u32 IV384[] = {
	SPH_C32(0xE623087E), SPH_C32(0x04C00C87), SPH_C32(0x5EF46453),
	SPH_C32(0x69524B13), SPH_C32(0x1A05C7A9), SPH_C32(0x3528DF88),
	SPH_C32(0x6BDD01B5), SPH_C32(0x5057B792), SPH_C32(0x6AA7A922),
	SPH_C32(0x649C7EEE), SPH_C32(0xF426309F), SPH_C32(0xCB629052),
	SPH_C32(0xFC8E20ED), SPH_C32(0xB3482BAB), SPH_C32(0xF89E5E7E),
	SPH_C32(0xD83D4DE4), SPH_C32(0x44BFC10D), SPH_C32(0x5FC1E63D),
	SPH_C32(0x2104E6CB), SPH_C32(0x17958F7F), SPH_C32(0xDBEAEF70),
	SPH_C32(0xB4B97E1E), SPH_C32(0x32C195F6), SPH_C32(0x6184A8E4),
	SPH_C32(0x796C2543), SPH_C32(0x23DE176D), SPH_C32(0xD33BBAEC),
	SPH_C32(0x0C12E5D2), SPH_C32(0x4EB95A7B), SPH_C32(0x2D18BA01),
	SPH_C32(0x04EE475F), SPH_C32(0x1FC5F22E)
};

static const sph_u32 IV512[] = {
	SPH_C32(0x2AEA2A61), SPH_C32(0x50F494D4), SPH_C32(0x2D538B8B),
	SPH_C32(0x4167D83E), SPH_C32(0x3FEE2313), SPH_C32(0xC701CF8C),
	SPH_C32(0xCC39968E), SPH_C32(0x50AC5695), SPH_C32(0x4D42C787),
	SPH_C32(0xA647A8B3), SPH_C32(0x97CF0BEF), SPH_C32(0x825B4537),
	SPH_C32(0xEEF864D2), SPH_C32(0xF22090C4), SPH_C32(0xD0E5CD33),
	SPH_C32(0xA23911AE), SPH_C32(0xFCD398D9), SPH_C32(0x148FE485),
	SPH_C32(0x1B017BEF), SPH_C32(0xB6444532), SPH_C32(0x6A536159),
	SPH_C32(0x2FF5781C), SPH_C32(0x91FA7934), SPH_C32(0x0DBADEA9),
	SPH_C32(0xD65C8A2B), SPH_C32(0xA5A70E75), SPH_C32(0xB1C62456),
	SPH_C32(0xBC796576), SPH_C32(0x1921C8F7), SPH_C32(0xE7989AF1),
	SPH_C32(0x7795D246), SPH_C32(0xD43E3B44)
};

#define T32      SPH_T32
#define ROTL32   SPH_ROTL32

#if SPH_CUBEHASH_NOCOPY

#define DECL_STATE
#define READ_STATE(cc)
#define WRITE_STATE(cc)

#define x0   ((sc)->state[ 0])
#define x1   ((sc)->state[ 1])
#define x2   ((sc)->state[ 2])
#define x3   ((sc)->state[ 3])
#define x4   ((sc)->state[ 4])
#define x5   ((sc)->state[ 5])
#define x6   ((sc)->state[ 6])
#define x7   ((sc)->state[ 7])
#define x8   ((sc)->state[ 8])
#define x9   ((sc)->state[ 9])
#define xa   ((sc)->state[10])
#define xb   ((sc)->state[11])
#define xc   ((sc)->state[12])
#define xd   ((sc)->state[13])
#define xe   ((sc)->state[14])
#define xf   ((sc)->state[15])
#define xg   ((sc)->state[16])
#define xh   ((sc)->state[17])
#define xi   ((sc)->state[18])
#define xj   ((sc)->state[19])
#define xk   ((sc)->state[20])
#define xl   ((sc)->state[21])
#define xm   ((sc)->state[22])
#define xn   ((sc)->state[23])
#define xo   ((sc)->state[24])
#define xp   ((sc)->state[25])
#define xq   ((sc)->state[26])
#define xr   ((sc)->state[27])
#define xs   ((sc)->state[28])
#define xt   ((sc)->state[29])
#define xu   ((sc)->state[30])
#define xv   ((sc)->state[31])

#else

#define DECL_STATE \
	sph_u32 x0, x1, x2, x3, x4, x5, x6, x7; \
	sph_u32 x8, x9, xa, xb, xc, xd, xe, xf; \
	sph_u32 xg, xh, xi, xj, xk, xl, xm, xn; \
	sph_u32 xo, xp, xq, xr, xs, xt, xu, xv;

#define READ_STATE(cc)   do { \
		x0 = (cc)->state[ 0]; \
		x1 = (cc)->state[ 1]; \
		x2 = (cc)->state[ 2]; \
		x3 = (cc)->state[ 3]; \
		x4 = (cc)->state[ 4]; \
		x5 = (cc)->state[ 5]; \
		x6 = (cc)->state[ 6]; \
		x7 = (cc)->state[ 7]; \
		x8 = (cc)->state[ 8]; \
		x9 = (cc)->state[ 9]; \
		xa = (cc)->state[10]; \
		xb = (cc)->state[11]; \
		xc = (cc)->state[12]; \
		xd = (cc)->state[13]; \
		xe = (cc)->state[14]; \
		xf = (cc)->state[15]; \
		xg = (cc)->state[16]; \
		xh = (cc)->state[17]; \
		xi = (cc)->state[18]; \
		xj = (cc)->state[19]; \
		xk = (cc)->state[20]; \
		xl = (cc)->state[21]; \
		xm = (cc)->state[22]; \
		xn = (cc)->state[23]; \
		xo = (cc)->state[24]; \
		xp = (cc)->state[25]; \
		xq = (cc)->state[26]; \
		xr = (cc)->state[27]; \
		xs = (cc)->state[28]; \
		xt = (cc)->state[29]; \
		xu = (cc)->state[30]; \
		xv = (cc)->state[31]; \
	} while (0)

#define WRITE_STATE(cc)   do { \
		(cc)->state[ 0] = x0; \
		(cc)->state[ 1] = x1; \
		(cc)->state[ 2] = x2; \
		(cc)->state[ 3] = x3; \
		(cc)->state[ 4] = x4; \
		(cc)->state[ 5] = x5; \
		(cc)->state[ 6] = x6; \
		(cc)->state[ 7] = x7; \
		(cc)->state[ 8] = x8; \
		(cc)->state[ 9] = x9; \
		(cc)->state[10] = xa; \
		(cc)->state[11] = xb; \
		(cc)->state[12] = xc; \
		(cc)->state[13] = xd; \
		(cc)->state[14] = xe; \
		(cc)->state[15] = xf; \
		(cc)->state[16] = xg; \
		(cc)->state[17] = xh; \
		(cc)->state[18] = xi; \
		(cc)->state[19] = xj; \
		(cc)->state[20] = xk; \
		(cc)->state[21] = xl; \
		(cc)->state[22] = xm; \
		(cc)->state[23] = xn; \
		(cc)->state[24] = xo; \
		(cc)->state[25] = xp; \
		(cc)->state[26] = xq; \
		(cc)->state[27] = xr; \
		(cc)->state[28] = xs; \
		(cc)->state[29] = xt; \
		(cc)->state[30] = xu; \
		(cc)->state[31] = xv; \
	} while (0)

#endif

#define INPUT_BLOCK   do { \
		x0 ^= sph_dec32le_aligned(buf +  0); \
		x1 ^= sph_dec32le_aligned(buf +  4); \
		x2 ^= sph_dec32le_aligned(buf +  8); \
		x3 ^= sph_dec32le_aligned(buf + 12); \
		x4 ^= sph_dec32le_aligned(buf + 16); \
		x5 ^= sph_dec32le_aligned(buf + 20); \
		x6 ^= sph_dec32le_aligned(buf + 24); \
	