/* $Id: groestl.c 260 2011-07-21 01:02:38Z tp $ */
/*
 * Groestl implementation.
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

#include "sph_groestl.h"

#ifdef __cplusplus
extern "C"{
#endif

#if SPH_SMALL_FOOTPRINT && !defined SPH_SMALL_FOOTPRINT_GROESTL
#define SPH_SMALL_FOOTPRINT_GROESTL   1
#endif

/*
 * Apparently, the 32-bit-only version is not faster than the 64-bit
 * version unless using the "small footprint" code on a 32-bit machine.
 */
#if !defined SPH_GROESTL_64
#if SPH_SMALL_FOOTPRINT_GROESTL && !SPH_64_TRUE
#define SPH_GROESTL_64   0
#else
#define SPH_GROESTL_64   1
#endif
#endif

#if !SPH_64
#undef SPH_GROESTL_64
#endif

#ifdef _MSC_VER
#pragma warning (disable: 4146)
#endif

/*
 * The internal representation may use either big-endian or
 * little-endian. Using the platform default representation speeds up
 * encoding and decoding between bytes and the matrix columns.
 */

#undef USE_LE
#if SPH_GROESTL_LITTLE_ENDIAN
#define USE_LE   1
#elif SPH_GROESTL_BIG_ENDIAN
#define USE_LE   0
#elif SPH_LITTLE_ENDIAN
#define USE_LE   1
#endif

#if USE_LE

#define C32e(x)     ((SPH_C32(x) >> 24) \
                    | ((SPH_C32(x) >>  8) & SPH_C32(0x0000FF00)) \
                    | ((SPH_C32(x) <<  8) & SPH_C32(0x00FF0000)) \
                    | ((SPH_C32(x) << 24) & SPH_C32(0xFF000000)))
#define dec32e_aligned   sph_dec32le_aligned
#define enc32e           sph_enc32le
#define B32_0(x)    ((x) & 0xFF)
#define B32_1(x)    (((x) >> 8) & 0xFF)
#define B32_2(x)    (((x) >> 16) & 0xFF)
#define B32_3(x)    ((x) >> 24)

#define R32u(u, d)   SPH_T32(((u) << 16) | ((d) >> 16))
#define R32d(u, d)   SPH_T32(((u) >> 16) | ((d) << 16))

#define PC32up(j, r)   ((sph_u32)((j) + (r)))
#define PC32dn(j, r)   0
#define QC32up(j, r)   SPH_C32(0xFFFFFFFF)
#define QC32dn(j, r)   (((sph_u32)(r) << 24) ^ SPH_T32(~((sph_u32)(j) << 24)))

#if SPH_64
#define C64e(x)     ((SPH_C64(x) >> 56) \
                    | ((SPH_C64(x) >> 40) & SPH_C64(0x000000000000FF00)) \
                    | ((SPH_C64(x) >> 24) & SPH_C64(0x0000000000FF0000)) \
                    | ((SPH_C64(x) >>  8) & SPH_C64(0x00000000FF000000)) \
                    | ((SPH_C64(x) <<  8) & SPH_C64(0x000000FF00000000)) \
                    | ((SPH_C64(x) << 24) & SPH_C64(0x0000FF0000000000)) \
                    | ((SPH_C64(x) << 40) & SPH_C64(0x00FF000000000000)) \
                    | ((SPH_C64(x) << 56) & SPH_C64(0xFF00000000000000)))
#define dec64e_aligned   sph_dec64le_aligned
#define enc64e           sph_enc64le
#define B64_0(x)    ((x) & 0xFF)
#define B64_1(x)    (((x) >> 8) & 0xFF)
#define B64_2(x)    (((x) >> 16) & 0xFF)
#define B64_3(x)    (((x) >> 24) & 0xFF)
#define B64_4(x)    (((x) >> 32) & 0xFF)
#define B64_5(x)    (((x) >> 40) & 0xFF)
#define B64_6(x)    (((x) >> 48) & 0xFF)
#define B64_7(x)    ((x) >> 56)
#define R64         SPH_ROTL64
#define PC64(j, r)  ((sph_u64)((j) + (r)))
#define QC64(j, r)  (((sph_u64)(r) << 56) ^ SPH_T64(~((sph_u64)(j) << 56)))
#endif

#else

#define C32e(x)     SPH_C32(x)
#define dec32e_aligned   sph_dec32be_aligned
#define enc32e           sph_enc32be
#define B32_0(x)    ((x) >> 24)
#define B32_1(x)    (((x) >> 16) & 0xFF)
#define B32_2(x)    (((x) >> 8) & 0xFF)
#define B32_3(x)    ((x) & 0xFF)

#define R32u(u, d)   SPH_T32(((u) >> 16) | ((d) << 16))
#define R32d(u, d)   SPH_T32(((u) << 16) | ((d) >> 16))

#define PC32up(j, r)   ((sph_u32)((j) + (r)) << 24)
#define PC32dn(j, r)   0
#define QC32up(j, r)   SPH_C32(0xFFFFFFFF)
#define QC32dn(j, r)   ((sph_u32)(r) ^ SPH_T32(~(sph_u32)(j)))

#if SPH_64
#define C64e(x)     SPH_C64(x)
#define dec64e_aligned   sph_dec64be_aligned
#define enc64e           sph_enc64be
#define B64_0(x)    ((x) >> 56)
#define B64_1(x)    (((x) >> 48) & 0xFF)
#define B64_2(x)    (((x) >> 40) & 0xFF)
#define B64_3(x)    (((x) >> 32) & 0xFF)
#define B64_4(x)    (((x) >> 24) & 0xFF)
#define B64_5(x)    (((x) >> 16) & 0xFF)
#define B64_6(x)    (((x) >> 8) & 0xFF)
#define B64_7(x)    ((x) & 0xFF)
#define R64         SPH_ROTR64
#define PC64(j, r)  ((sph_u64)((j) + (r)) << 56)
#define QC64(j, r)  ((sph_u64)(r) ^ SPH_T64(~(sph_u64)(j)))
#endif

#endif

#if SPH_GROESTL_64

static const sph_u64 T0[] = {
	C64e(0xc632f4a5f497a5c6), C64e(0xf86f978497eb84f8),
	C64e(0xee5eb099b0c799ee), C64e(0xf67a8c8d8cf78df6),
	C64e(0xffe8170d17e50dff), C64e(0xd60adcbddcb7bdd6),
	C64e(0xde16c8b1c8a7b1de), C64e(0x916dfc54fc395491),
	C64e(0x6090f050f0c05060), C64e(0x0207050305040302),
	C64e(0xce2ee0a9e087a9ce), C64e(0x56d1877d87ac7d56),
	C64e(0xe7cc2b192bd519e7), C64e(0xb513a662a67162b5),
	C64e(0x4d7c31e6319ae64d), C64e(0xec59b59ab5c39aec),
	C64e(0x8f40cf45cf05458f), C64e(0x1fa3bc9dbc3e9d1f),
	C64e(0x8949c040c0094089), C64e(0xfa68928792ef87fa),
	C64e(0xefd03f153fc515ef), C64e(0xb29426eb267febb2),
	C64e(0x8ece40c94007c98e), C64e(0xfbe61d0b1ded0bfb),
	C64e(0x416e2fec2f82ec41), C64e(0xb31aa967a97d67b3),
	C64e(0x5f431cfd1cbefd5f), C64e(0x456025ea258aea45),
	C64e(0x23f9dabfda46bf23), C64e(0x535102f702a6f753),
	C64e(0xe445a196a1d396e4), C64e(0x9b76ed5bed2d5b9b),
	C64e(0x75285dc25deac275), C64e(0xe1c5241c24d91ce1),
	C64e(0x3dd4e9aee97aae3d), C64e(0x4cf2be6abe986a4c),
	C64e(0x6c82ee5aeed85a6c), C64e(0x7ebdc341c3fc417e),
	C64e(0xf5f3060206f102f5), C64e(0x8352d14fd11d4f83),
	C64e(0x688ce45ce4d05c68), C64e(0x515607f407a2f451),
	C64e(0xd18d5c345cb934d1), C64e(0xf9e1180818e908f9),
	C64e(0xe24cae93aedf93e2), C64e(0xab3e9573954d73ab),
	C64e(0x6297f553f5c45362), C64e(0x2a6b413f41543f2a),
	C64e(0x081c140c14100c08), C64e(0x9563f652f6315295),
	C64e(0x46e9af65af8c6546), C64e(0x9d7fe25ee2215e9d),
	C64e(0x3048782878602830), C64e(0x37cff8a1f86ea137),
	C64e(0x0a1b110f11140f0a), C64e(0x2febc4b5c45eb52f),
	C64e(0x0e151b091b1c090e), C64e(0x247e5a365a483624),
	C64e(0x1badb69bb6369b1b), C64e(0xdf98473d47a53ddf),
	C64e(0xcda76a266a8126cd), C64e(0x4ef5bb69bb9c694e),
	C64e(0x7f334ccd4cfecd7f), C64e(0xea50ba9fbacf9fea),
	C64e(0x123f2d1b2d241b12), C64e(0x1da4b99eb93a9e1d),
	C64e(0x58c49c749cb07458), C64e(0x3446722e72682e34),
	C64e(0x3641772d776c2d36), C64e(0xdc11cdb2cda3b2dc),
	C64e(0xb49d29ee2973eeb4), C64e(0x5b4d16fb16b6fb5b),
	C64e(0xa4a501f60153