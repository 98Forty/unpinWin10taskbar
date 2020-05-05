/* $Id: hamsi_helper.c 202 2010-05-31 15:46:48Z tp $ */
/*
 * Helper code for Hamsi (input block expansion). This code is
 * automatically generated and includes precomputed tables for
 * expansion code which handles 2 to 8 bits at a time.
 *
 * This file is included from hamsi.c, and is not meant to be compiled
 * independently.
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

#ifdef __cplusplus
extern "C"{
#endif

#if SPH_HAMSI_EXPAND_SMALL == 1

/* Note: this table lists bits within each byte from least
   siginificant to most significant. */
static const sph_u32 T256[32][8] = {
	{ SPH_C32(0x74951000), SPH_C32(0x5a2b467e), SPH_C32(0x88fd1d2b),
	  SPH_C32(0x1ee68292), SPH_C32(0xcba90000), SPH_C32(0x90273769),
	  SPH_C32(0xbbdcf407), SPH_C32(0xd0f4af61) },
	{ SPH_C32(0xcba90000), SPH_C32(0x90273769), SPH_C32(0xbbdcf407),
	  SPH_C32(0xd0f4af61), SPH_C32(0xbf3c1000), SPH_C32(0xca0c7117),
	  SPH_C32(0x3321e92c), SPH_C32(0xce122df3) },
	{ SPH_C32(0xe92a2000), SPH_C32(0xb4578cfc), SPH_C32(0x11fa3a57),
	  SPH_C32(0x3dc90524), SPH_C32(0x97530000), SPH_C32(0x204f6ed3),
	  SPH_C32(0x77b9e80f), SPH_C32(0xa1ec5ec1) },
	{ SPH_C32(0x97530000), SPH_C32(0x204f6ed3), SPH_C32(0x77b9e80f),
	  SPH_C32(0xa1ec5ec1), SPH_C32(0x7e792000), SPH_C32(0x9418e22f),
	  SPH_C32(0x6643d258), SPH_C32(0x9c255be5) },
	{ SPH_C32(0x121b4000), SPH_C32(0x5b17d9e8), SPH_C32(0x8dfacfab),
	  SPH_C32(0xce36cc72), SPH_C32(0xe6570000), SPH_C32(0x4bb33a25),
	  SPH_C32(0x848598ba), SPH_C32(0x1041003e) },
	{ SPH_C32(0xe6570000), SPH_C32(0x4bb33a25), SPH_C32(0x848598ba),
	  SPH_C32(0x1041003e), SPH_C32(0xf44c4000), SPH_C32(0x10a4e3cd),
	  SPH_C32(0x097f5711), SPH_C32(0xde77cc4c) },
	{ SPH_C32(0xe4788000), SPH_C32(0x859673c1), SPH_C32(0xb5fb2452),
	  SPH_C32(0x29cc5edf), SPH_C32(0x045f0000), SPH_C32(0x9c4a93c9),
	  SPH_C32(0x62fc79d0), SPH_C32(0x731ebdc2) },
	{ SPH_C32(0x045f0000), SPH_C32(0x9c4a93c9), SPH_C32(0x62fc79d0),
	  SPH_C32(0x731ebdc2), SPH_C32(0xe0278000), SPH_C32(0x19dce008),
	  SPH_C32(0xd7075d82), SPH_C32(0x5ad2e31d) },
	{ SPH_C32(0xb7a40100), SPH_C32(0x8a1f31d8), SPH_C32(0x8589d8ab),
	  SPH_C32(0xe6c46464), SPH_C32(0x734c0000), SPH_C32(0x956fa7d6),
	  SPH_C32(0xa29d1297), SPH_C32(0x6ee56854) },
	{ SPH_C32(0x734c0000), SPH_C32(0x956fa7d6), SPH_C32(0xa29d1297),
	  SPH_C32(0x6ee56854), SPH_C32(0xc4e80100), SPH_C32(0x1f70960e),
	  SPH_C32(0x2714ca3c), SPH_C32(0x88210c30) },
	{ SPH_C32(0xa7b80200), SPH_C32(0x1f128433), SPH_C32(0x60e5f9f2),
	  SPH_C32(0x9e147576), SPH_C32(0xee260000), SPH_C32(0x124b683e),
	  SPH_C32(0x80c2d68f), SPH_C32(0x3bf3ab2c) },
	{ SPH_C32(0xee260000), SPH_C32(0x124b683e), SPH_C32(0x80c2d68f),
	  SPH_C32(0x3bf3ab2c), SPH_C32(0x499e0200), SPH_C32(0x0d59ec0d),
	  SPH_C32(0xe0272f7d), SPH_C32(0xa5e7de5a) },
	{ SPH_C32(0x8f3e0400), SPH_C32(0x0d9dc877), SPH_C32(0x6fc548e1),
	  SPH_C32(0x898d2cd6), SPH_C32(0x14bd0000), SPH_C32(0x2fba37ff),
	  SPH_C32(0x6a72e5bb), SPH_C32(0x247febe6) },
	{ SPH_C32(0x14bd0000), SPH_C32(0x2fba37ff), SPH_C32(0x6a72e5bb),
	  SPH_C32(0x247febe6), SPH_C32(0x9b830400), SPH_C32(0x2227ff88),
	  SPH_C32(0x05b7ad5a), SPH_C32(0xadf2c730) },
	{ SPH_C32(0xde320800), SPH_C32(0x288350fe), SPH_C32(0x71852ac7),
	  SPH_C32(0xa6bf9f96), SPH_C32(0xe18b0000), SPH_C32(0x5459887d),
	  SPH_C32(0xbf1283d3), SPH_C32(0x1b666a73) },
	{ SPH_C32(0xe18b0000), SPH_C32(0x5459887d), SPH_C32(0xbf1283d3),
	  SPH_C32(0x1b666a73), SPH_C32(0x3fb90800), SPH_C32(0x7cdad883),
	  SPH_C32(0xce97a914), SPH_C32(0xbdd9f5e5) },
	{ SPH_C32(0x515c0010), SPH_C32(0x40f372fb), SPH_C32(0xfce72602),
	  SPH_C32(0x71575061), SPH_C32(0x2e390000), SPH_C32(0x64dd6689),
	  SPH_C32(0x3cd406fc), SPH_C32(0xb1f490bc) },
	{ SPH_C32(0x2e390000), SPH_C32(0x64dd6689), SPH_C32(0x3cd406fc),
	  SPH_C32(0xb1f490bc), SPH_C32(0x7f650010), SPH_C32(0x242e1472),
	  SPH_C32(0xc03320fe), SPH_C32(0xc0a3c0dd) },
	{ SPH_C32(0xa2b80020), SPH_C32(0x81e7e5f6), SPH_C32(0xf9ce4c04),
	  SPH_C32(0xe2afa0c0), SPH_C32(0x5c720000), SPH_C32(0xc9bacd12),
	  SPH_C32(0x79a90df9), SPH_C32(0x63e92178) },
	{ SPH_C32(0x5c720000), SPH_C32(0xc9bacd12), SPH_C32(0x79a90df9),
	  SPH_C32(0x63e92178), SPH_C32(0xfeca0020), SPH_C32(0x485d28e4),
	  SPH_C32(0x806741fd), SPH_C32(0x814681b8) },
	{ SPH_C32(0x4dce0040), SPH_C32(0x3b5bec7e), SPH_C32(0x36656ba8),
	  SPH_C32(0x23633a05), SPH_C32(0x78ab0000), SPH_C32(0xa0cd5a34),
	  SPH_C32(0x5d5ca0f7), SPH_C32(0x727784cb) },
	{ SPH_C32(0x78ab0000), SPH_C32(0xa0cd5a34), SPH_C32(0x5d5ca0f7),
	  SPH_C32(0x727784cb), SPH_C32(0x35650040), SPH_C32(0x9b96b64a),
	  SPH_C32(0x6b39cb5f), SPH_C32(0x5114bece) },
	{ SPH_C32(0x5bd20080), SPH_C32(0x450f18ec), SPH_C32(0xc2c46c55),
	  SPH_C32(0xf362b233), SPH_C32(0x39a60000), SPH_C32(0x4ab753eb),
	  SPH_C32(0xd14e094b), SPH_C32(0xb772b42b) },
	{ SPH_C32(0x39a60000), SPH_C32(0x4ab753eb), SPH_C32(0xd14e094b),
	  SPH_C32(0xb772b42b), SPH_C32(0x62740080), SPH_C32(0x0fb84b07),
	  SPH_C32(0x138a651e), SPH_C32(0x44100618) },
	{ SPH_C32(0xc04e0001), SPH_C32(0x33b9c010), SPH_C32(0xae0ebb05),
	  SPH_C32(0xb5a4c63b), SPH_C32(0xc8f10000), SPH_C32(0x0b2de782),
	  SPH_C32(0x6bf648a4), SPH_C32(0x539cbdbf) },
	{ SPH_C32(0xc8f10000), SPH_C32(0x0b2de782), SPH_C32(0x6bf648a4),
	  SPH_C32(0x539cbdbf), SPH_C32(0x08bf0001), SPH_C32(0x38942792),
	  SPH_C32(0xc5f8f3a1), SPH_C32(0xe6387b84) },
	{ SPH_C32(0x88230002), SPH_C32(0x5fe7a7b3), SPH_C32(0x99e585aa),
	  SPH_C32(0x8d75f7f1), SPH_C32(0x51ac0000), SPH_C32(0x25e30f14),
	  SPH_C32(0x79e22a4c), SPH_C32(0x1298bd46) },
	{ SPH_C32(0x51ac0000), SPH_C32(0x25e30f14), SPH_C32(0x79e22a4c),
	  SPH_C32(0x1298bd46), SPH_C32(0xd98f0002), SPH_C32(0x7a04a8a7),
	  SPH_C32(0xe007afe6), SPH_C32(0x9fed4ab7) },
	{ SPH_C32(0xd0080004), SPH_C32(0x8c768f77), SPH_C32(0x9dc5b050),
	  SPH_C32(0xaf4a29da), SPH_C32(0x6ba90000), SPH_C32(0x40ebf9aa),
	  SPH_C32(0x98321c3d), SPH_C32(0x76acc733) },
	{ SPH_C32(0x6ba90000), SPH_C32(0x40ebf9aa), SPH_C32(0x98321c3d),
	  SPH_C32(0x76acc733), SPH_C32(0xbba10004), SPH_C32(0xcc9d76dd),
	  SPH_C32(0x05f7ac6d), SPH_C32(0xd9e6eee9) },
	{ SPH_C32(0xa8ae0008), SPH_C32(0x2079397d), SPH_C32(0xfe739301),
	  SPH_C32(0xb8a92831), SPH_C32(0x171c0000), SPH_C32(0xb26e3344),
	  SPH_C32(0x9e6a837e), SPH_C32(0x58f8485f) },
	{ SPH_C32(0x171c0000), SPH_C32(0xb26e3344), SPH_C32(0x9e6a837e),
	  SPH_C32(0x58f8485f), SPH_C32(0xbfb20008), SPH_C32(0x92170a39),
	  SPH_C32(0x6019107f), SPH_C32(0xe051606e) }
};

#define INPUT_SMALL   do { \
		const sph_u32 *tp = &T256[0][0]; \
		unsigned u, v; \
		m0 = 0; \
		m1 = 0; \
		m2 = 0; \
		m3 = 0; \
		m4 = 0; \
		m5 = 0; \
		m6 = 0; \
		m7 = 0; \
		for (u = 0; u < 4; u ++) { \
			unsigned db = buf[u]; \
			for (v = 0; v < 8; v ++, db >>= 1) { \
				sph_u32 dm = SPH_T32(-(sph_u32)(db & 1)); \
				m0 ^= dm & *tp ++; \
				m1 ^= dm & *tp ++; \
				m2 ^= dm & *tp ++; \
				m3 ^= dm & *tp ++; \
				m4 ^= dm & *tp ++; \
				m5 ^= dm & *tp ++; \
				m6 ^= dm & *tp ++; \
				m7 ^= dm & *tp ++; \
			} \
		} \
	} while (0)

#endif

#if SPH_HAMSI_EXPAND_SMALL == 2

static const sph_u32 T256_0[4][8] = {
	{ SPH_C32(0x00000000), SPH_C32(0x00000000), SPH_C32(0x00000000),
	  SPH_C32(0x00000000), SPH_C32(0x00000000), SPH_C32(0x00000000),
	  SPH_C32(0x00000000), SPH_C32(0x00000000) },
	{ SPH_C32(0xe4788000), SPH_C32(0x859673c1), SPH_C32(0xb5fb2452),
	  SPH_C32(0x29cc5edf), SPH_C32(0x045f0000), SPH_C32(0x9c4a93c9),
	  SPH_C32(0x62fc79d0), SPH_C32(0x731ebdc2) },
	{ SPH_C32(0x045f0000), SPH_C32(0x9c4a93c9), SPH_C32(0x62fc79d0),
	  SPH_C32(0x731ebdc2), SPH_C32(0xe0278000), SPH_C32(0x19dce008),
	  SPH_C32(0xd7075d82), SPH_C32(0x5ad2e31d) },
	{ SPH_C32(0xe0278000), SPH_C32(0x19dce008), SPH_C32(0xd7075d82),
	  SPH_C32(0x5ad2e31d), SPH_C32(0xe4788000), SPH_C32(0x859673c1),
	  SPH_C32(0xb5fb2452), SPH_C32(0x29cc5edf) }
};

static const sph_u32 T256_2[4][8] = {
	{ SPH_C32(0x00000000), SPH_C32(0x00000000), SPH_C32(0x00000000),
	  SPH_C32(0x00000000), SPH_C32(0x00000000), SPH_C32(0x00000000),
	  SPH_C32(0x00000000), SPH_C32(0x00000000) },
	{ SPH_C32(0x121b4000), SPH_C32(0x5b17d9e8), SPH_C32(0x8dfacfab),
	  SPH_C32(0xce36cc72), SPH_C32(0xe6570000), SPH_C32(0x4bb33a25),
	  SPH_C32(0x848598ba), SPH_C32(0x1041003e) },
	{ SPH_C32(0xe6570000), SPH_C32(0x4bb33a25), SPH_C32(0x848598ba),
	  SPH_C32(0x1041003e), SPH_C32(0xf44c4000), SPH_C32(0x10a4e3cd),
	  SPH_C32(0x097f5711), SPH_C32(0xde77cc4c) },
	{ SPH_C32(0xf44c4000), SPH_C32(0x10a4e3cd), SPH_C32(0x097f5711),
	  SPH_C32(0xde77cc4c), SPH_C32(0x121b4000), SPH_C32(0x5b17d9e8),
	  SPH_C32(0x8dfacfab), SPH_C32(0xce36cc72) }
};

static const sph_u32 T256_4[4][8] = {
	{ SPH_C32(0x00000000), SPH_C32(0x00000000), SPH_C32(0x00000000),
	  SPH_C32(0x00000000), SPH_C32(0x00000000), SPH_C32(0x00000000),
	  SPH_C32(0x00000000), SPH_C32(0x00000000) },
	{ SPH_C32(0xe92a2000), SPH_C32(0xb4578cfc), SPH_C32(0x11fa3a57),
	  SPH_C32(0x3dc90524), SPH_C32(0x97530000), SPH_C32(0x204f6ed3),
	  SPH_C32(0x77b9e80f), SPH_C32(0xa1ec5ec1) },
	{ SPH_C32(0x97530000), SPH_C32(0x204f6ed3), SPH_C32(0x77b9e80f),
	  SPH_C32(0xa1ec5ec1), SPH_C32(0x7e792000), SPH_C32(0x9418e22f),
	  SPH_C32(0x6643d258), SPH_C32(0x9c255be5) },
	{ SPH_C32(0x7e792000), SPH_C32(0x9418e22f), SPH_C32(0x6643d258),
	  SPH_C32(0x9c255be5), SPH_C32(0xe92a2000), SPH_C32(0xb4578cfc),
	  SPH_C32(0x11fa3a57), SPH_C32(0x3dc90524) }
};

static const sph_u32 T256_6[4][8] = {
	{ SPH_C32(0x00000000), SPH_C32(0x00000000), SPH_C32(0x00000000),
	  SPH_C32(0x00000000), SPH_C32(0x00000000), SPH_C32(0x00000000),
	  SPH_C32(0x00000000), SPH_C32(0x00000000) },
	{ SPH_C32(0x74951000), SPH_C32(0x5a2b467e), SPH_C32(0x88fd1d2b),
	  SPH_C32(0x1ee68292), SPH_C32(0xcba90000), SPH_C32(0x90273769),
	  SPH_C32(0xbbdcf407), SPH_C32(0xd0f4af61) },
	{ SPH_C32(0xcba90000), SPH_C32(0x90273769), SPH_C32(0xbbdcf407),
	  SPH_C32(0xd0f4af61), SPH_C32(0xbf3c1000), SPH_C32(0xca0c7117),
	  SPH_C32(0x3321e92c), SPH_C32(0xce122df3) },
	{ SPH_C32(0xbf3c1000), SPH_C32(0xca0c7117), SPH_C32(0x3321e92c),
	  SPH_C32(0xce122df3), SPH_C32(0x74951000), SPH_C32(0x5a2b467e),
	  SPH_C32(0x88fd1d2b), SPH_C32(0x1ee68292) }
};

static const sph_u32 T256_8[4][8] = {
	{ SPH_C32(0x00000000), SPH_C32(0x00000000), SPH_C32(0x00000000),
	  SPH_C32(0x00000000), SPH_C32(0x00000000), SPH_C32(0x00000000),
	  SPH_C32(0x00000000), SPH_C32(0x00000000) },
	{ SPH_C32(0xde320800), SPH_C32(0x288350fe), SPH_C32(0x71852ac7),
	  SPH_C32(0xa6bf9f96), SPH_C32(0xe18b0000), SPH_C32(0x5459887d),
	  SPH_C32(0xbf1283d3), SPH_C32(0x1b666a73) },
	{ SPH_C32(0xe18b0000), SPH_C32(0x5459887d), SPH_C32(0xbf1283d3),
	  SPH_C32(0x1b666a73), SPH_C32(0x3fb90800), SPH_C32(0x7cdad883),
	  SPH_C32(0xce97a914), SPH_C32(0xbdd9f5e5) },
	{ SPH_C32(0x3fb90800), SPH_C32(0x7cdad883), SPH_C32(0xce97a914),
	  SPH_C32(0xbdd9f5e5), SPH_C32(0xde320800), SPH_C32(0x288350fe),
	  SPH_C32(0x71852ac7), SPH_C32(0xa6bf9f96) }
};

static const sph_u32 T256_10[4][8] = {
	{ SPH_C32(0x00000000), SPH_C32(0x00000000), SPH_C32(0x00000000),
	  SPH_C32(0x00000000), SPH_C32(0x00000000), SPH_C32(0x00000000),
	  SPH_C32(0x00000000), SPH_C32(0x00000000) },
	{ SPH_C32(0x8f3e0400), SPH_C32(0x0d9dc877), SPH_C32(0x6fc548e1),
	  SPH_C32(0x898d2cd6), SPH_C32(0x14bd0000), SPH_C32(0x2fba37ff),
	  SPH_C32(0x6a72e5bb), SPH_C32(0x247febe6) },
	{ SPH_C32(0x14bd0000), SPH_C32(0x2fba37ff), SPH_C32(0x6a72e5bb),
	  SPH_C32(0x247febe6), SPH_C32(0x9b830400), SPH_C32(0x2227ff88),
	  SPH_C32(0x05b7ad5a), SPH_C32(0xadf2c730) },
	{ SPH_C32(0x9b830400), SPH_C32(0x2227ff88), SPH_C32(0x05b7ad5a),
	  SPH_C32(0xadf2c730), SPH_C32(0x8f3e0400), SPH_C32(0x0d9dc877),
	  SPH_C32(0x6fc548e1), SPH_C32(0x898d2cd6) }
};

static const sph_u32 T256_12[4][8] = {
	{ SPH_C32(0x00000000), SPH_C32(0x00000000), SPH_C32(0x00000000),
	  SPH_C32(0x00000000), SPH_C32(0x00000000), SPH_C32(0x00000000),
	  SPH_C32(0x00000000), SPH_C32(0x00000000) },
	{ SPH_C32(0xa7b80200), SPH_C32(0x1f128433), SPH_C32(0x60e5f9f2),
	  SPH_C32(0x9e147576), SPH_C32(0xee260000), SPH_C32(0x124b683e),
	  SPH_C32(0x80c2d68f), SPH_C32(0x3bf3ab2c) },
	{ SPH_C32(0xee260000), SPH_C32(0x124b683e), SPH_C32(0x80c2d68f),
	  SPH_C32(0x3bf3ab2c), SPH_C32(0x499e0200), SPH_C32(0x0d59ec0d),
	  SPH_C32(0xe0272f7d), SPH_C32(0xa5e7de5a) },
	{ SPH_C32(0x499e0200), SPH_C32(0x0d59ec0d), SPH_C32(0xe0272f7d),
	  SPH_C32(0xa5e7de5a), SPH_C32(0xa7b80200), SPH_C32(0x1f128433),
	  SPH_C32(0x60e5f9f2), SPH_C32(0x9e147576) }
};

static const sph_u32 T256_14[4][8] = {
	{ SPH_C32(0x00000000), SPH_C32(0x00000000), SPH_C32(0x00000000),
	  SPH_C32(0x00000000), SPH_C32(0x00000000), SPH_C32(0x00000000),
	  SPH_C32(0x00000000), SPH_C32(0x00000000) },
	{ SPH_C32(0xb7a40100), SPH_C32(0x8a1f31d8), SPH_C32(0x8589d8ab),
	  SPH_C32(0xe6c46464), SPH_C32(0x734c0000), SPH_C32(0x956fa7d6),
	  SPH_C32(0xa29d1297), SPH_C32(0x6ee56854) },
	{ SPH_C32(0x734c0000), SPH_C32(0x956fa7d6), SPH_C32(0xa29d1297),
	  SPH_C32(0x6ee56854), SPH_C32(0xc4e80100), SPH_C32(0x1f70960e),
	  SPH_C32(0x2714ca3c), SPH_C32(0x88210c30) },
	{ SPH_C32(0xc4e80100), SPH_C32(0x1f70960e), SPH_C32(0x2714ca3c),
	  SPH_C32(0x88210c30), SPH_C32(0xb7a40100), SPH_C32(0x8a1f31d8),
	  SPH_C32(0x8589d8ab), SPH_C32(0xe6c46464) }
};

static const sph_u32 T256_16[4][8] = {
	{ SPH_C32(0x00000000), SPH_C32(0x00000000), SPH_C32(0x00000000),
	  SPH_C32(0x00000000), SPH_C32(0x00000000), SPH_C32(0x00000000),
	  SPH_C32(0x00000000), SPH_C32(0x00000000) },
	{ SPH_C32(0x5bd20080), SPH_C32(0x450f18ec), SPH_C32(0xc2c46c55),
	  SPH_C32(0xf362b233), SPH_C32(0x39a60000), SPH_C32(0x4ab753eb),
	  SPH_C32(0xd14e094b), SPH_C32(0xb772b42b) },
	{ SPH_C32(0x39a60000), SPH_C32(0x4ab753eb), SPH_C32(0xd14e094b),
	  SPH_C32(0xb772b42b), SPH_C32(0x62740080), SPH_C32(0x0fb84b07),
	  SPH_C32(0x138a651e), SPH_C32(0x44100618) },
	{ SPH_C32(0x62740080), SPH_C32(0x0fb84b07), SPH_C32(0x138a651e),
	  SPH_C32(0x44100618), SPH_C32(0x5bd20080), SPH_C32(0x450f18ec),
	  SPH_C32(0xc2c46c55), SPH_C32(0xf362b233) }
};

static const sph_u32 T256_18[4][8] = {
	{ SPH_C32(0x00000000), SPH_C32(0x00000000), SPH_C32(0x00000000),
	  SPH_C32(0x00000000), SPH_C32(0x00000000), SPH_C32(0x00000000),
	  SPH_C32(0x00000000), SPH_C32(0x00000000) },
	{ SPH_C32(0x4dce0040), SPH_C32(0x3b5bec7e), SPH_C32(0x36656ba8),
	  SPH_C32(0x23633a05), SPH_C32(0x78ab0000), SPH_C32(0xa0cd5a34),
	  SPH_C32(0x5d5ca0f7), SPH_C32(0x727784cb) },
	{ SPH_C32(0x78ab0000), SPH_C32(0xa0cd5a34), SPH_C32(0x5d5ca0f7),
	  SPH_C32(0x727784cb), SPH_C32(0x35650040), SPH_C32(0x9b96b64a),
	  SPH_C32(0x6b39cb5f), SPH_C32(0x5114bece) },
	{ SPH_C32(0x35650040), SPH_C32(0x9b96b64a), SPH_C32(0x6b39cb5f),
	  SPH_C32(0x5114bece), SPH_C32(0x4dce0040), SPH_C32(0x3b5bec7e),
	  SPH_C32(0x36656ba8), SPH_C32(0x23633a05) }
};

static const sph_u32 T256_20[4][8] = {
	{ SPH_C32(0x00000000), SPH_C32(0x00000000), SPH_C32(0x00000000),
	  SPH_C32(0x00000000), SPH_C32(0x00000000), SPH_C32(0x00000000),
	  SPH_C32(0x00000000), SPH_C32(0x00000000) },
	{ SPH_C32(0xa2b80020), SPH_C32(0x81e7e5f6), SPH_C32(0xf9ce4c04),
	  SPH_C32(0xe2afa0c0), SPH_C32(0x5c720000), SPH_C32(0xc9bacd12),
	  SPH_C32(0x79a90df9), SPH_C32(0x63e92178) },
	{ SPH_C32(0x5c720000), SPH_C32(0xc9bacd12), SPH_C32(0x79a90df9),
	  SPH_C32(0x63e92178), SPH_C32(0xfeca0020), SPH_C32(0x485d28e4),
	  SPH_C32(0x806741fd), SPH_C32(0x814681b8) },
	{ SPH_C32(0xfeca0020), SPH_C32(0x485d28e4), SPH_C32(0x806741fd),
	  SPH_C32(0x814681b8), SPH_C32(0xa2b80020), SPH_C32(0x81e7e5f6),
	  SPH_C32(0xf9ce4c04), SPH_C32(0xe2afa0c0) }
};

static const sph_u32 T256_22[4][8] = {
	{ SPH_C32(0x00000000), SPH_C32(0x00000000), SPH_C32(0x00000000),
	  SPH_C32(0x00000000), SPH_C32(0x00000000), SPH_C32(0x00000000),
	  SPH_C32(0x00000000), SPH_C32(0x00000000) },
	{ SPH_C32(0x515c0010), SPH_C32(0x40f372fb), SPH_C32(0xfce72602),
	  SPH_C32(0x71575061), SPH_C32(0x2e390000), SPH_C32(0x64dd6689),
	  SPH_C32(0x3cd406fc), SPH_C32(0xb1f490bc) },
	{ SPH_C32(0x2e390000), SPH_C32(0x64dd6689), SPH_C32(0x3cd406fc),
	  SPH_C32(0xb1f490bc), SPH_C32(0x7f650010), SPH_C32(0x242e1472),
	  SPH_C32(0xc03320fe), SPH_C32(0xc0a3c0dd) },
	{ SPH_C32(0x7f650010), SPH_C32(0x242e1472), SPH_C32(0xc03320fe),
	  SPH_C32(0xc0a3c0dd), SPH_C32(0x515c0010), SPH_C32(0x40f372fb),
	  SPH_C32(0xfce72602), SPH_C32(0x71575061) }
};

static const sph_u32 T256_24[4][8] = {
	{ SPH_C32(0x00000000), SPH_C32(0x00000000), SPH_C32(0x00000000),
	  SPH_C32(0x00000000), SPH_C32(0x00000000), SPH_C32(0x00000000),
	  SPH_C32(0x00000000), SPH_C32(0x00000000) },
	{ SPH_C32(0xa8ae0008), SPH_C32(0x2079397d), SPH_C32(0xfe739301),
	  SPH_C32(0xb8a92831), SPH_C32(0x171c0000), SPH_C32(0xb26e3344),
	  SPH_C32(0x9e6a837e), SPH_C32(0x58f8485f) },
	{ SPH_C32(0x171c0000), SPH_C32(0xb26e3344), SPH_C32(0x9e6a837e),
	  SPH_C32(0x58f8485f), SPH_C32(0xbfb20008), SPH_C32(0x92170a39),
	  SPH_C32(0x6019107f), SPH_C32(0xe051606e) },
	{ SPH_C32(0xbfb20008), SPH_C32(0x92170a39), SPH_C32(0x6019107f),
	  SPH_C32(0xe051606e), SPH_C32(0xa8ae0008), SPH_C32(0x2079397d),
	  SPH_C32(0xfe739301), SPH_C32(0xb8a92831) }
};

static const sph_u32 T256_26[4][8] = {
	{ SPH_C32(0x00000000), SPH_C32(0x00000000), SPH_C32(0x00000000),
	  SPH_C32(0x00000000), SPH_C32(0x00000000), SPH_C32(0x00000000),
	  SPH_C32(0x00000000), SPH_C32(0x00000000) },
	{ SPH_C32(0xd0080004), SPH_C32(0x8c768f77), SPH_C32(0x9dc5b050),
	  SPH_C32(0xaf4a29da), SPH_C32(0x6ba90000), SPH_C32(0x40ebf9aa),
	  SPH_C32(0x98321c3d), SPH_C32(0x76acc733) },
	{ SPH_C32(0x6ba90000), SPH_C32(0x40ebf9aa), SPH_C32(0x98321c3d),
	  SPH_C32(0x76acc733), SPH_C32(0xbba10004), SPH_C32(0xcc9d76dd),
	  SPH_C32(0x05f7ac6d), SPH_C32(0xd9e6eee9) },
	{ SPH_C32(0xbba10004), SPH_C32(0xcc9d76dd), SPH_C32(0x05f7ac6d),
	  SPH_C32(0xd9e6eee9), SPH_C32(0xd0080004), SPH_C32(0x8c768f77),
	  SPH_C32(0x9dc5b050), SPH_C32(0xaf4a29da) }
};

static const sph_u32 T256_28[4][8] = {
	{ SPH_C32(0x00000000), SPH_C32(0x00000000), SPH_C32(0x00000000),
	  SPH_C32(0x00000000), SPH_C32(0x00000000), SPH_C32(0x00000000),
	  SPH_C32(0x00000000), SPH_C32(0x00000000) },
	{ SPH_C32(0x88230002), SPH_C32(0x5fe7a7b3), SPH_C32(0x99e585aa),
	  SPH_C32(0x8d75f7f1), SPH_C32(0x51ac0000), SPH_C32(0x25e30f14),
	  SPH_C32(0x79e22a4c), SPH_C32(0x1298bd46) },
	{ SPH_C32(0x51ac0000), SPH_C32(0x25e30f14), SPH_C32(0x79e22a4c),
	  SPH_C32(0x1298bd46), SPH_C32(0xd98f0002), SPH_C32(0x7a04a8a7),
	  SPH_C32(0xe007afe6), SPH_C32(0x9fed4ab7) },
	{ SPH_C32(0xd98f0002), SPH_C32(0x7a04a8a7), SPH_C32(0xe007afe6),
	  SPH_C32(0x9fed4ab7), SPH_C32(0x88230002), SPH_C32(0x5fe7a7b3),
	  SPH_C32(0x99e585aa), SPH_C32(0x8d75f7f1) }
};

static const sph_u32 T256_30[4][8] = {
	{ SPH_C32(0x00000000), SPH_C32(0x00000000), SPH_C32(0x00000000),
	  SPH_C32(0x00000000), SPH_C32(0x00000000), SPH_C32(0x00000000),
	  SPH_C32(0x00000000), SPH_C32(0x00000000) },
	{ SPH_C32(0xc04e0001), SPH_C32(0x33b9c010), SPH_C32(0xae0ebb05),
	  SPH_C32(0xb5a4c63b), SPH_C32(0xc8f10000), SPH_C32(0x0b2de782),
	  SPH_C32(0x6bf648a4), SPH_C32(0x539cbdbf) },
	{ SPH_C32(0xc8f10000), SPH_C32(0x0b2de782), SPH_C32(0x6bf648a4),
	  SPH_C32(0x539cbdbf), SPH_C32(0x08bf0001), SPH_C32(0x38942792),
	  SPH_C32(0xc5f8f3a1), SPH_C32(0xe6387b84) },
	{ SPH_C32(0x08bf0001), SPH_C32(0x38942792), SPH_C32(0xc5f8f3a1),
	  SPH_C32(0xe6387b84), SPH_C32(0xc04e0001), SPH_C32(0x33b9c010),
	  SPH_C32(0xae0ebb05), SPH_C32(0xb5a4c63b) }
};

#define INPUT_SMALL   do { \
		unsigned acc = buf[0]; \
		const sph_u32 *rp; \
		rp = &T256_0[acc >> 6][0]; \
		m0 = rp[0]; \
		m1 = rp[1]; \
		m2 = rp[2]; \
		m3 = rp[3]; \
		m4 = rp[4]; \
		m5 = rp[5]; \
		m6 = rp[6]; \
		m7 = rp[7]; \
		rp = &T256_2[(acc >> 4) & 0x03][0]; \
		m0 ^= rp[0]; \
		m1 ^= rp[1]; \
		m2 ^= rp[2]; \
		m3 ^= rp[3]; \
		m4 ^= rp[4]; \
		m5 ^= rp[5]; \
		m6 ^= rp[6]; \
		m7 ^= rp[7]; \
		rp = &T256_4[(acc >> 2) & 0x03][0]; \
		m0 ^= rp[0]; \
		m1 ^= rp[1]; \
		m2 ^= rp[2]; \
		m3 ^= rp[3]; \
		m4 ^= rp[4]; \
		m5 ^= rp[5]; \
		m6 ^= rp[6]; \
		m7 ^= rp[7]; \
		rp = &T256_6[acc & 0x03][0]; \
		m0 ^= rp[0]; \
		m1 ^= rp[1]; \
		m2 ^= rp[2]; \
		m3 ^= rp[3]; \
		m4 ^= rp[4]; \
		m5 ^= rp[5]; \
		m6 ^= rp[6]; \
		m7 ^= rp[7]; \
		acc = buf[1]; \
		rp = &T256_8[acc >> 6][0]; \
		m0 ^= rp[0]; \
		m1 ^= rp[1]; \
		m2 ^= rp[2]; \
		m3 ^= rp[3]; \
		m4 ^= rp[4]; \
		m5 ^= rp[5]; \
		m6 ^= rp[6]; \
		m7 ^= rp[7]; \
		rp = &T256_10[(acc >> 4) & 0x03][0]; \
		m0 ^= rp[0]; \
		m1 ^= rp[1]; \
		m2 ^= rp[2]; \
		m3 ^= rp[3]; \
		m4 ^= rp[4]; \
		m5 ^= rp[5]; \
		m6 ^= rp[6]; \
		m7 ^= rp[7]; \
		rp = &T256_12[(acc >> 2) & 0x03][0]; \
		m0 ^= rp[0]; \
		m1 ^= rp[1]; \
		m2 ^= rp[2]; \
		m3 ^= rp[3]; \
		m4 ^= rp[4]; \
		m5 ^= rp[5]; \
		m6 ^= rp[6]; \
		m7 ^= rp[7]; \
		rp = &T256_14[acc & 0x03][0]; \
		m0 ^= rp[0]; \
		m1 ^= rp[1]; \
		m2 ^= rp[2]; \
		m3 ^= rp[3]; \
		m4 ^= rp[4]; \
		m5 ^= rp[5]; \
		m6 ^= rp[6]; \
		m7 ^= rp[7]; \
		acc = buf[2]; \
		rp = &T256_16[acc >> 6][0]; \
		m0 ^= rp[0]; \
		m1 ^= rp[1]; \
		m2 ^= rp[2]; \
		m3 ^= rp[3]; \
		m4 ^= rp[4]; \
		m5 ^= rp[5]; \
		m6 ^= rp[6]; \
		m7 ^= rp[7]; \
		rp = &T256_18[(acc >> 4) & 0x03][0]; \
		m0 ^= rp[0]; \
		m1 ^= rp[1]; \
		m2 ^= rp[2]; \
		m3 ^= rp[3]; \
		m4 ^= rp[4]; \
		m5 ^= rp[5]; \
		m6 ^= rp[6]; \
		m7 ^= rp[7]; \
		rp = &T256_20[(acc >> 2) & 0x03][0]; \
		m0 ^= rp[0]; \
		m1 ^= rp[1]; \
		m2 ^= rp[2]; \
		m3 ^= rp[3]; \
		m4 ^= rp[4]; \
		m5 ^= rp[5]; \
		m6 ^= rp[6]; \
		m7 ^= rp[7]; \
		rp = &T256_22[acc & 0x03][0]; \
		m0 ^= rp[0]; \
		m1 ^= rp[1]; \
		m2 ^= rp[2]; \
		m3 ^= rp[3]; \
		m4 ^= rp[4]; \
		m5 ^= rp[5]; \
		m6 ^= rp[6]; \
		m7 ^= rp[7]; \
		acc = buf[3]; \
		rp = &T256_24[acc >> 6][0]; \
		m0 ^= rp[0]; \
		m1 ^= rp[1]; \
		m2 ^= rp[2]; \
		m3 ^= rp[3]; \
		m4 ^= rp[4]; \
		m5 ^= rp[5]; \
		m6 ^= rp[6]; \
		m7 ^= rp[7]; \
		rp = &T256_26[(acc >> 4) & 0x03][0]; \
		m0 ^= rp[0]; \
		m1 ^= rp[1]; \
		m2 ^= rp[2]; \
		m3 ^= rp[3]; \
		m4 ^= rp[4]; \
		m5 ^= rp[5]; \
		m6 ^= rp[6]; \
		m7 ^= rp[7]; \
		rp = &T256_28[(acc >> 2) & 0x03][0]; \
		m0 ^= rp[0]; \
		m1 ^= rp[1]; \
		m2 ^= rp[2]; \
		m3 ^= rp[3]; \
		m4 ^= rp[4]; \
		m5 ^= rp[5]; \
		m6 ^= rp[6]; \
		m7 ^= rp[7]; \
		rp = &T256_30[acc & 0x03][0]; \
		m0 ^= rp[0]; \
		m1 ^= rp[1]; \
		m2 ^= rp[2]; \
		m3 ^= rp[3]; \
		m4 ^= rp[4]; \
		m5 ^= rp[5]; \
		m6 ^= rp[6]; \
		m7 ^= rp[7]; \
	} while (0)

#endif

#if SPH_HAMSI_EXPAND_SMALL == 3

static const sph_u32 T256_0[8][8] = {
	{ SPH_C32(0x00000000), SPH_C32(0x00000000), SPH_C32(0x00000000),
	  SPH_C32(0x00000000), SPH_C32(0x00000000), SPH_C32(0x00000000),
	  SPH_C32(0x00000000), SPH_C32(0x00000000) },
	{ SPH_C32(0xe6570000), SPH_C32(0x4bb33a25), SPH_C32(0x848598ba),
	  SPH_C32(0x1041003e), SPH_C32(0xf44c4000), SPH_C32(0x10a4e3cd),
	  SPH_C32(0x097f5711), SPH_C32(0xde77cc4c) },
	{ SPH_C32(0xe4788000), SPH_C32(0x859673c1), SPH_C32(0xb5fb2452),
	  SPH_C32(0x29cc5edf), SPH_C32(0x045f0000), SPH_C32(0x9c4a93c9),
	  SPH_C32(0x62fc79d0), SPH_C32(0x731ebdc2) },
	{ SPH_C32(0x022f8000), SPH_C32(0xce2549e4), SPH_C32(0x317ebce8),
	  SPH_C32(0x398d5ee1), SPH_C32(0xf0134000), SPH_C32(0x8cee7004),
	  SPH_C32(0x6b832ec1), SPH_C32(0xad69718e) },
	{ SPH_C32(0x045f0000), SPH_C32(0x9c4a93c9), SPH_C32(0x62fc79d0),
	  SPH_C32(0x731ebdc2), SPH_C32(0xe0278000), SPH_C32(0x19dce008),
	  SPH_C32(0xd7075d82), SPH_C32(0x5ad2e31d) },
	{ SPH_C32(0xe2080000), SPH_C32(0xd7f9a9ec), SPH_C32(0xe679e16a),
	  SPH_C32(0x635fbdfc), SPH_C32(0x146bc000), SPH_C32(0x097803c5),
	  SPH_C32(0xde780a93), SPH_C32(0x84a52f51) },
	{ SPH_C32(0xe0278000), SPH_C32(0x19dce008), SPH_C32(0xd7075d82),
	  SPH_C32(0x5ad2e31d), SPH_C32(0xe4788000), SPH_C32(0x859673c1),
	  SPH_C32(0xb5fb2452), SPH_C32(0x29cc5edf) },
	{ SPH_C32(0x06708000), SPH_C32(0x526fda2d), SPH_C32(0x5382c538),
	  SPH_C32(0x4a93e323), SPH_C32(0x1034c000), SPH_C32(0x9532900c),
	  SPH_C32(0xbc847343), SPH_C32(0xf7bb9293) }
};

static const sph_u32 T256_3[8][8] = {
	{ SPH_C32(0x00000000), SPH_C32(0x00000000), SPH_C32(0x00000000),
	  SPH_C32(0x00000000), SPH_C32(0x00000000), SPH_C32(0x00000000),
	  SPH_C32(0x00000000), SPH_C32(0x00000000) },
	{ SPH_C32(0xe92a2000), SPH_C32(0xb4578cfc), SPH_C32(0x11fa3a57),
	  SPH_C32(0x3dc90524), SPH_C32(0x97530000), SPH_C32(0x204f6ed3),
	  SPH_C32(0x77b9e80f), SPH_C32(0xa1ec5ec1) },
	{ SPH_C32(0x97530000), SPH_C32(0x204f6ed3), SPH_C32(0x77b9e80f),
	  SPH_C32(0xa1ec5ec1), SPH_C32(0x7e792000), SPH_C32(0x9418e22f),
	  SPH_C32(0x6643d258), SPH_C32(0x9c255be5) },
	{ SPH_C32(0x7e792000), SPH_C32(0x9418e22f), SPH_C32(0x6643d258),
	  SPH_C32(0x9c255be5), SPH_C32(0xe92a2000), SPH_C32(0xb4578cfc),
	  SPH_C32(0x11fa3a57), SPH_C32(0x3dc90524) },
	{ SPH_C32(0x121b4000), SPH_C32(0x5b17d9e8), SPH_C32(0x8dfacfab),
	  SPH_C32(0xce36cc72), SPH_C32(0xe6570000), SPH_C32(0x4bb33a25),
	  SPH_C32(0x848598ba), SPH_C32(0x1041003e) },
	{ SPH_C32(0xfb316000), SPH_C32(0xef405514), SPH_C32(0x9c00f5fc),
	  SPH_C32(0xf3ffc956), SPH_C32(0x71040000), SPH_C32(0x6bfc54f6),
	  SPH_C32(0xf33c70b5), SPH_C32(0xb1ad5eff) },
	{ SPH_C32(0x85484000), SPH_C32(0x7b58b73b), SPH_C32(0xfa4327a4),
	  SPH_C32(0x6fda92b3), SPH_C32(0x982e2000), SPH_C32(0xdfabd80a),
	  SPH_C32(0xe2c64ae2), SPH_C32(0x8c645bdb) },
	{ SPH_C32(0x6c626000), SPH_C32(0xcf0f3bc7), SPH_C32(0xebb91df3),
	  SPH_C32(0x52139797), SPH_C32(0x0f7d2000), SPH_C32(0xffe4b6d9),
	  SPH_C32(0x957fa2ed), SPH_C32(0x2d88051a) }
};

static const sph_u32 T256_6[8][8] = {
	{ SPH_C32(0x00000000), SPH_C32(0x00000000), SPH_C32(0x00000000),
	  SPH_C32(0x00000000), SPH_C32(0x00000000), SPH_C32(0x00000000),
	  SPH_C32(0x00000000), SPH_C32(0x00000000) },
	{ SPH_C32(0xe18b0000), SPH_C32(0x5459887d), SPH_C32(0xbf1283d3),
	  SPH_C32(0x1b666a73), SPH_C32(0x3fb90800), SPH_C32(0x7cdad883),
	  SPH_C32(0xce97a914), SPH_C32(0xbdd9f5e5) },
	{ SPH_C32(0x74951000), SPH_C32(0x5a2b467e), SPH_C32(0x88fd1d2b),
	  SPH_C32(0x1ee68292), SPH_C32(0xcba90000), SPH_C32(0x90273769),
	  SPH_C32(0xbbdcf407), SPH_C32(0xd0f4af61) },
	{ SPH_C32(0x951e1000), SPH_C32(0x0e72ce03), SPH_C32(0x37ef9ef8),
	  SPH_C32(0x0580e8e1), SPH_C32(0xf4100800), SPH_C32(0xecfdefea),
	  SPH_C32(0x754b5d13), SPH_C32(0x6d2d5a84) },
	{ SPH_C32(0xcba90000), SPH_C32(0x90273769), SPH_C32(0xbbdcf407),
	  SPH_C32(0xd0f4af61), SPH_C32(0xbf3c1000), SPH_C32(0xca0c7117),
	  SPH_C32(0x3321e92c), SPH_C32(0xce122df3) },
	{ SPH_C32(0x2a220000), SPH_C32(0xc47ebf14), SPH_C32(0x04ce77d4),
	  SPH_C32(0xcb92c512), SPH_C32(0x80851800), SPH_C32(0xb6d6a994),
	  SPH_C32(0xfdb64038), SPH_C32(0x73cbd816) },
	{ SPH_C32(0xbf3c1000), SPH_C32(0xca0c7117), SPH_C32(0x3321e92c),
	  SPH_C32(0xce122df3), SPH_C32(0x74951000), SPH_C32(0x5a2b467e),
	  SPH_C32(0x88fd1d2b), SPH_C32(0x1ee68292) },
	{ SPH_C32(0x5eb71000), SPH_C32(0x9e55f96a), SPH_C32(0x8c336aff),
	  SPH_C32(0xd5744780), SPH_C32(0x4b2c1800), SPH_C32(0x26f19efd),
	  SPH_C32(0x466ab43f), SPH_C32(0xa33f7777) }
};

static const sph_u32 T256_9[8][8] = {
	{ SPH_C32(0x00000000), SPH_C32(0x00000000), SPH_C32(0x00000000),
	  SPH_C32(0x00000000), SPH_C32(0x00000000), SPH_C32(0x00000000),
	  SPH_C32(0x00000000), SPH_C32(0x00000000) },
	{ SPH_C32(0x8f3e0400), SPH_C32(0x0d9dc877), SPH_C32(0x6fc548e1),
	  SPH_C32(0x898d2cd6), SPH_C32(0x14bd0000), SPH_C32(0x2fba37ff),
	  SPH_C32(0x6a72e5bb), SPH_C32(0x247febe6) },
	{ SPH_C32(0x14bd0000), SPH_C32(0x2fba37ff), SPH_C32(0x6a72e5bb),
	  SPH_C32(0x247febe6), SPH_C32(0x9b830400), SPH_C32(0x2227ff88),
	  SPH_C32(0x05b7ad5a), SPH_C32(0xadf2c730) },
	{ SPH_C32(0x9b830400), SPH_C32(0x2227ff88), SPH_C32(0x05b7ad5a),
	  SPH_C32(0xadf2c730), SPH_C32(0x8f3e0400), SPH_C32(0x0d9dc877),
	  SPH_C32(0x6fc548e1), SPH_C32(0x898d2cd6) },
	{ SPH_C32(0xde320800), SPH_C32(0x288350fe), SPH_C32(0x71852ac7),
	  SPH_C32(0xa6bf9f96), SPH_C32(0xe18b0000), SPH_C32(0x5459887d),
	  SPH_C32(0xbf1283d3), SPH_C32(0x1b666a73) },
	{ SPH_C32(0x510c0c00), SPH_C32(0x251e9889), SPH_C32(0x1e406226),
	  SPH_C32(0x2f32b340), SPH_C32(0xf5360000), SPH_C32(0x7be3bf82),
	  SPH_C32(0xd5606668), SPH_C32(0x3f198195) },
	{ SPH_C32(0xca8f0800), SPH_C32(0x07396701), SPH_C32(0x1bf7cf7c),
	  SPH_C32(0x82c07470), SPH_C32(0x7a080400), SPH_C32(0x767e77f5),
	  SPH_C32(0xbaa52e89), SPH_C32(0xb694ad43) },
	{ SPH_C32(0x45b10c00), SPH_C32(0x0aa4af76), SPH_C32(0x7432879d),
	  SPH_C32(0x0b4d58a6), SPH_C32(0x6eb50400), SPH_C32(0x59c4400a),
	  SPH_C32(0xd0d7cb32), SPH_C32(0x92eb46a5) }
};

static const sph_u32 T256_12[8][8] = {
	{ SPH_C32(0x00000000), SPH_C32(0x00000000), SPH_C32(0x00000000),
	  SPH_C32(0x00000000), SPH_C32(0x00000000), SPH_C32(0x00000000),
	  SPH_C32(0x00000000), SPH_C32(0x00000000) },
	{ SPH_C32(0x734c0000), SPH_C32(0x956fa7d6), SPH_C32(0xa29d1297),
	  SPH_C32(0x6ee56854), SPH_C32(0xc4e80100), SPH_C32(0x1f70960e),
	  SPH_C32(0x2714ca3c), SPH_C32(0x88210c30) },
	{ SPH_C32(0xa7b80200), SPH_C32(0x1f128433), SPH_C32(0x60e5f9f2),
	  SPH_C32(0x9e147576), SPH_C32(0xee260000), SPH_C32(0x124b683e),
	  SPH_C32(0x80c2d68f), SPH_C32(0x3bf3ab2c) },
	{ SPH_C32(0xd4f40200), SPH_C32(0x8a7d23e5), SPH_C32(0xc278eb65),
	  SPH_C32(0xf0f11d22), SPH_C32(0x2ace0100), SPH_C32(0x0d3bfe30),
	  SPH_C32(0xa7d61cb3), SPH_C32(0xb3d2a71c) },
	{ SPH_C32(0xee260000), SPH_C32(0x124b683e), SPH_C32(0x80c2d68f),
	  SPH_C32(0x3bf3ab2c), SPH_C32(0x499e0200), SPH_C32(0x0d59ec0d),
	  SPH_C32(0xe0272f7d), SPH_C32(0xa5e7de5a) },
	{ SPH_C32(0x9d6a0000), SPH_C32(0x8724cfe8), SPH_C32(0x225fc418),
	  SPH_C32(0x5516c378), SPH_C32(0x8d760300), SPH_C32(0x12297a03),
	  SPH_C32(0xc733e541), SPH_C32(0x2dc6d26a) },
	{ SPH_C32(0x499e0200), SPH_C32(0x0d59ec0d), SPH_C32(0xe0272f7d),
	  SPH_C32(0xa5e7de5a), SPH_C32(0xa7b80200), SPH_C32(0x1f128433),
	  SPH_C32(0x60e5f9f2), SPH_C32(0x9e147576) },
	{ SPH_C32(0x3ad20200), SPH_C32(0x98364bdb), SPH_C32(0x42ba3dea),
	  SPH_C32(0xcb02b60e), SPH_C32(0x63500300), SPH_C32(0x0062123d),
	  SPH_C32(0x47f133ce), SPH_C32(0x16357946) }
};

static const sph_u32 T256_15[8][8] = {
	{ SPH_C32(0x00000000), SPH_C32(0x00000000), SPH_C32(0x00000000),
	  SPH_C32(0x00000000), SPH_C32(0x00000000), SPH_C32(0x00000000),
	  SPH_C32(0x00000000), SPH_C32(0x00000000) },
	{ SPH_C32(0x5bd20080), SPH_C32(0x450f18ec), SPH_C32(0xc2c46c55),
	  SPH_C32(0xf362b233), SPH_C32(0x39a60000), SPH_C32(0x4ab753eb),
	  SPH_C32(0xd14e094b), SPH_C32(0xb772b42b) },
	{ SPH_C32(0x39a60000), SPH_C32(0x4ab753eb), SPH_C32(0xd14e094b),
	  SPH_C32(0xb772b42b), SPH_C32(0x62740080), SPH_C32(0x0fb84b07),
	  SPH_C32(0x138a651e), SPH_C32(0x44100618) },
	{ SPH_C32(0x62740080), SPH_C32(0x0fb84b07), SPH_C32(0x138a651e),
	  SPH_C32(0x44100618), SPH_C32(0x5bd20080), SPH_C32(0x450f18ec),
	  SPH_C32(0xc2c46c55), SPH_C32(0xf362b233) },
	{ SPH_C32(0xb7a40100), SPH_C32(0x8a1f31d8), SPH_C32(0x8589d8ab),
	  SPH_C32(0xe6c46464), SPH_C32(0x734c0000), SPH_C32(0x956fa7d6),
	  SPH_C32(0xa29d1297), SPH_C32(0x6ee56854) },
	{ SPH_C32(0xec760180), SPH_C32(0xcf102934), SPH_C32(0x474db4fe),
	  SPH_C32(0x15a6d657), SPH_C32(0x4aea0000), SPH_C32(0xdfd8f43d),
	  SPH_C32(0x73d31bdc), SPH_C32(0xd997dc7f) },
	{ SPH_C32(0x8e020100), SPH_C32(0xc0a86233), SPH_C32(0x54c7d1e0),
	  SPH_C32(0x51b6d04f), SPH_C32(0x11380080), SPH_C32(0x9ad7ecd1),
	  SPH_C32(0xb1177789), SPH_C32(0x2af56e4c) },
	{ SPH_C32(0xd5d00180), SPH_C32(0x85a77adf), SPH_C32(0x9603bdb5),
	  SPH_C32(0xa2d4627c), SPH_C32(0x289e0080), SPH_C32(0xd060bf3a),
	  SPH_C32(0x60597ec2), SPH_C32(0x9d87da67) }
};

static const sph_u32 T256_18[8][8] = {
	{ SPH_C32(0x00000000), SPH_C32(0x00000000), SPH_C32(0x00000000),
	  SPH_C32(0x00000000), SPH_C32(0x00000000), SPH_C32(0x00000000),
	  SPH_C32(0x00000000), SPH_C32(0x00000000) },
	{ SPH_C32(0x5c720000), SPH_C32(0xc9bacd12), SPH_C32(0x79a90df9),
	  SPH_C32(0x63e92178), SPH_C32(0xfeca0020), SPH_C32(0x485d28e4),
	  SPH_C32(0x806741fd), SPH_C32(0x814681b8) },
	{ SPH_C32(0x4dce0040), SPH_C32(0x3b5bec7e), SPH_C32(0x36656ba8),
	  SPH_C32(0x23633a05), SPH_C32(0x78ab0000), SPH_C32(0xa0cd5a34),
	  SPH_C32(0x5d5ca0f7), SPH_C32(0x727784cb) },
	{ SPH_C32(0x11bc0040), SPH_C32(0xf2e1216c), SPH_C32(0x4fcc6651),
	  SPH_C32(0x408a1b7d), SPH_C32(0x86610020), SPH_C32(0xe89072d0),
	  SPH_C32(0xdd3be10a), SPH_C32(0xf3310573) },
	{ SPH_C32(0x78ab0000), SPH_C32(0xa0cd5a34), SPH_C32(0x5d5ca0f7),
	  SPH_C32(0x727784cb), SPH_C32(0x35650040), SPH_C32(0x9b96b64a),
	  SPH_C32(0x6b39cb5f), SPH_C32(0x5114bece) },
	{ SPH_C32(0x24d90000), SPH_C32(0x69779726), SPH_C32(0x24f5ad0e),
	  SPH_C32(0x119ea5b3), SPH_C32(0xcbaf0060), SPH_C32(0xd3cb9eae),
	  SPH_C32(0xeb5e8aa2), SPH_C32(0xd0523f76) },
	{ SPH_C32(0x35650040), SPH_C32(0x9b96b64a), SPH_C32(0x6b39cb5f),
	  SPH_C32(0x5114bece), SPH_C32(0x4dce0040), SPH_C32(0x3b5bec7e),
	  SPH_C32(0x36656ba8), SPH_C32(0x23633a05) },
	{ SPH_C32(0x69170040), SPH_C32(0x522c7b58), SPH_C32(0x1290c6a6),
	  SPH_C32(0x32fd9fb6), SPH_C32(0xb3040060), SPH_C32(0x7306c49a),
	  SPH_C32(0xb6022a55), SPH_C32(0xa225bbbd) }
};

static const sph_u32 T256_21[8][8] = {
	{ SPH_C32(0x00000000), SPH_C32(0x00000000), SPH_C32(0x00000000),
	  SPH_C32(0x00000000), SPH_C32(0x00000000), SPH_C32(0x00000000),
	  SPH_C32(0x00000000), SPH_C32(0x00000000) },
	{ SPH_C32(0x515c0010), SPH_C32(0x40f372fb), SPH_C32(0xfce72602),
	  SPH_C32(0x71575061), SPH_C32(0x2e390000), SPH_C32(0x64dd6689),
	  SPH_C32(0x3cd406fc), SPH_C32(0xb1f490bc) },
	{ SPH_C32(0x2e390000), SPH_C32(0x64dd6689), SPH_C32(0x3cd406fc),
	  SPH_C32(0xb1f490bc), SPH_C32(0x7f650010), SPH_C32(0x242e1472),
	  SPH_C32(0xc03320fe), SPH_C32(0xc0a3c0dd) },
	{ SPH_C32(0x7f650010), SPH_C32(0x242e1472), SPH_C32(0xc03320fe),
	  SPH_C32(0xc0a3c0dd), SPH_C32(0x515c0010), SPH_C32(0x40f372fb),
	  SPH_C32(0xfce72602), SPH_C32(0x71575061) },
	{ SPH_C32(0xa2b80020), SPH_C32(0x81e7e5f6), SPH_C32(0xf9ce4c04),
	  SPH_C32(0xe2afa0c0), SPH_C32(0x5c720000), SPH_C32(0xc9bacd12),
	  SPH_C32(0x79a90df9), SPH_C32(0x63e92178) },
	{ SPH_C32(0xf3e40030), SPH_C32(0xc114970d), SPH_C32(0x05296a06),
	  SPH_C32(0x93f8f0a1), SPH_C32(0x724b0000), SPH_C32(0xad67ab9b),
	  SPH_C32(0x457d0b05), SPH_C32(0xd21db1c4) },
	{ SPH_C32(0x8c810020), SPH_C32(0xe53a837f), SPH_C32(0xc51a4af8),
	  SPH_C32(0x535b307c), SPH_C32(0x23170010), SPH_C32(0xed94d960),
	  SPH_C32(0xb99a2d07), SPH_C32(0xa34ae1a5) },
	{ SPH_C32(0xdddd0030), SPH_C32(0xa5c9f184), SPH_C32(0x39fd6cfa),
	  SPH_C32(0x220c601d), SPH_C32(0x0d2e0010), SPH_C32(0x8949bfe9),
	  SPH_C32(0x854e2bfb), SPH_C32(0x12be7119) }
};

static const sph_u32 T256_24[8][8] = {
	{ SPH_C32(0x00000000), SPH_C32(0x00000000), SPH_C32(0x00000000),
	  SPH_C32(0x00000000), SPH_C32(0x00000000), SPH_C32(0x00000000),
	  SPH_C32(0x00000000), SPH_C32(0x00000000) },
	{ SPH_C32(0x6ba90000), SPH_C32(0x40ebf9aa), SPH_C32(0x98321c3d),
	  SPH_C32(0x76acc733), SPH_C32(0xbba10004), SPH_C32(0xcc9d76dd),
	  SPH_C32(0x05f7ac6d), SPH_C32(0xd9e6eee9) },
	{ SPH_C32(0xa8ae0008), SPH_C32(0x2079397d), SPH_C32(0xfe739301),
	  SPH_C32(0xb8a92831), SPH_C32(0x171c0000), SPH_C32(0xb26e3344),
	  SPH_C32(0x9e6a837e), SPH_C32(0x58f8485f) },
	{ SPH_C32(0xc3070008), SPH_C32(0x6092c0d7), SPH_C32(0x66418f3c),
	  SPH_C32(0xce05ef02), SPH_C32(0xacbd0004), SPH_C32(0x7ef34599),
	  SPH_C32(0x9b9d2f13), SPH_C32(0x811ea6b6) },
	{ SPH_C32(0x171c0000), SPH_C32(0xb26e3344), SPH_C32(0x9e6a837e),
	  SPH_C32(0x58f8485f), SPH_C32(0xbfb20008), SPH_C32(0x92170a39),
	  SPH_C32(0x6019107f), SPH_C32(0xe051606e) },
	{ SPH_C32(0x7cb50000), SPH_C32(0xf285caee), SPH_C32(0x06589f43),
	  SPH_C32(0x2e548f6c), SPH_C32(0x0413000c), SPH_C32(0x5e8a7ce4),
	  SPH_C32(0x65eebc12), SPH_C32(0x39b78e87) },
	{ SPH_C32(0xbfb20008), SPH_C32(0x92170a39), SPH_C32(0x6019107f),
	  SPH_C32(0xe051606e), SPH_C32(0xa8ae0008), SPH_C32(0x2079397d),
	  SPH_C32(0xfe739301), SPH_C32(0xb8a92831) },
	{ SPH_C32(0xd41b0008), SPH_C32(0xd2fcf393), SPH_C32(0xf82b0c42),
	  SPH_C32(0x96fda75d), SPH_C32(0x130f000c), SPH_C32(0xece44fa0),
	  SPH_C32(0xfb843f6c), SPH_C32(0x614fc6d8) }
};

static const sph_u32 T256_27[8][8] = {
	{ SPH_C32(0x00000000), SPH_C32(0x00000000), SPH_C32(0x00000000),
	  SPH_C32(0x00000000), SPH_C32(0x00000000), SPH_C32(0x00000000),
	  SPH_C32(0x00000000), SPH_C32(0x00000000) },
	{ SPH_C32(0x88230002), SPH_C32(0x5fe7a7b3), SPH_C32(0x99e585aa),
	  SPH_C32(0x8d75f7f1), SPH_C32(0x51ac0000), SPH_C32(0x25e30f14),
	  SPH_C32(0x79e22a4c), SPH_C32(0x1298bd46) },
	{ SPH_C32(0x51ac0000), SPH_C32(0x25e30f14), SPH_C32(0x79e22a4c),
	  SPH_C32(0x1298bd46), SPH_C32(0xd98f0002), SPH_C32(0x7a04a8a7),
	  SPH_C32(0xe007afe6), SPH_C32(0x9fed4ab7) },
	{ SPH_C32(0xd98f0002), SPH_C32(0x7a04a8a7), SPH_C32(0xe007afe6),
	  SPH_C32(0x9fed4ab7), SPH_C32(0x88230002), SPH_C32(0x5fe7a7b3),
	  SPH_C32(0x99e585aa), SPH_C32(0x8d75f7f1) },
	{ SPH_C32(0xd0080004), SPH_C32(0x8c768f77), SPH_C32(0x9dc5b050),
	  SPH_C32(0xaf4a29da), SPH_C32(0x6ba90000), SPH_C32(0x40ebf9aa),
	  SPH_C32(0x98321c3d), SPH_C32(0x76acc733) },
	{ SPH_C32(0x582b0006), SPH_C32(0xd39128c4), SPH_C32(0x042035fa),
	  SPH_C32(0x223fde2b), SPH_C32(0x3a050000), SPH_C32(0x6508f6be),
	  SPH_C32(0xe1d03671), SPH_C32(0x64347a75) },
	{ SPH_C32(0x81a40004), SPH_C32(0xa9958063), SPH_C32(0xe4279a1c),
	  SPH_C32(0xbdd2949c), SPH_C32(0xb2260002), SPH_C32(0x3aef510d),
	  SPH_C32(0x7835b3db), SPH_C32(0xe9418d84) },
	{ SPH_C32(0x09870006), SPH_C32(0xf67227d0), SPH_C32(0x7dc21fb6),
	  SPH_C32(0x30a7636d), SPH_C32(0xe38a0002), SPH_C32(0x1f0c5e19),
	  SPH_C32(0x01d79997), SPH_C32(0xfbd930c2) }
};

static const sph_u32 T256_30[4][8] = {
	{ SPH_C32(0x00000000), SPH_C32(0x00000000), SPH_C32(0x00000000),
	  SPH_C32(0x00000000), SPH_C32(0x00000000), SPH_C32(0x00000000),
	  SPH_C32(0x00000000), SPH_C32(0x00000000) },
	{ SPH_C32(0xc04e0001), SPH_C32(0x33b9c010), SPH_C32(0xae0ebb05),
	  SPH_C32(0xb5a4c63b), SPH_C32(0xc8f10000), SPH_C32(0x0b2de782),
	  SPH_C32(0x6bf648a4), SPH_C32(0x539cbdbf) },
	{ SPH_C32(0xc8f10000), SPH_C32(0x0b2de782), SPH_C32(0x6bf648a4),
	  SPH_C32(0x539cbdbf), SPH_C32(0x08bf0001), SPH_C32(0x38942792),
	  SPH_C32(0xc5f8f3a1), SPH_C32(0xe6387b84) },
	{ SPH_C32(0x08bf0001), SPH_C32(0x38942792), SPH_C32(0xc5f8f3a1),
	  SPH_C32(0xe6387b84), SPH_C32(0xc04e0001), SPH_C32(0x33b9c010),
	  SPH_C32(0xae0ebb05), SPH_C32(0xb5a4c63b) }
};

#define INPUT_SMALL   do { \
		unsigned acc = buf[0]; \
		const sph_u32 *rp; \
		rp = &T256_0[acc >> 5][0]; \
		m0 = rp[0]; \
		m1 = rp[1]; \
		m2 = rp[2]; \
		m3 = rp[3]; \
		m4 = rp[4]; \
		m5 = rp[5]; \
		m6 = rp[6]; \
		m7 = rp[7]; \
		rp = &T256_3[(acc >> 2) & 0x07][0]; \
		m0 ^= rp[0]; \
		m1 ^= rp[1]; \
		m2 ^= rp[2]; \
		m3 ^= rp[3]; \
		m4 ^= rp[4]; \
		m5 ^= rp[5]; \
		m6 ^= rp[6]; \
		m7 ^= rp[7]; \
		acc = (acc << 8) | buf[1]; \
		rp = &T256_6[(acc >> 7) & 0x07][0]; \
		m0 ^= rp[0]; \
		m1 ^= rp[1]; \
		m2 ^= rp[2]; \
		m3 ^= rp[3]; \
		m4 ^= rp[4]; \
		m5 ^= rp[5]; \
		m6 ^= rp[6]; \
		m7 ^= rp[7]; \
		rp = &T256_9[(acc >> 4) & 0x07][0]; \
		m0 ^= rp[0]; \
		m1 ^= rp[1]; \
		m2 ^= rp[2]; \
		m3 ^= rp[3]; \
		m4 ^= rp[4]; \
		m5 ^= rp[5]; \
		m6 ^= rp[6]; \
		m7 ^= rp[7]; \
		rp = &T256_12[(acc >> 1) & 0x07][0]; \
		m0 ^= rp[0]; \
		m1 ^= rp[1]; \
		m2 ^= rp[2]; \
		m3 ^= rp[3]; \
		m4 ^= rp[4]; \
		m5 ^= rp[5]; \
		m6 ^= rp[6]; \
		m7 ^= rp[7]; \
		acc = (acc << 8) | buf[2]; \
		rp = &T256_15[(acc >> 6) & 0x07][0]; \
		m0 ^= rp[0]; \
		m1 ^= rp[1]; \
		m2 ^= rp[2]; \
		m3 ^= rp[3]; \
		m4 ^= rp[4]; \
		m5 ^= rp[5]; \
		m6 ^= rp[6]; \
		m7 ^= rp[7]; \
		rp = &T256_18[(acc >> 3) & 0x07][0]; \
		m0 ^= rp[0]; \
		m1 ^= rp[1]; \
		m2 ^= rp[2]; \
		m3 ^= rp[3]; \
		m4 ^= rp[4]; \
		m5 ^= rp[5]; \
		m6 ^= rp[6]; \
		m7 ^= rp[7]; \
		rp = &T256_21[acc & 0x07][0]; \
		m0 ^= rp[0]; \
		m1 ^= rp[1]; \
		m2 ^= rp[2]; \
		m3 ^= rp[3]; \
		m4 ^= rp[4]; \
		m5 ^= rp[5]; \
		m6 ^= rp[6]; \
		m7 ^= rp[7]; \
		acc = buf[3]; \
		rp = &T256_24[acc >> 5][0]; \
		m0 ^= rp[0]; \
		m1 ^= rp[1]; \
		m2 ^= rp[2]; \
		m3 ^= rp[3]; \
		m4 ^= rp[4]; \
		m5 ^= rp[5]; \
		m6 ^= rp[6]; \
		m7 ^= rp[7]; \
		rp = &T256_27[(acc >> 2) & 0x07][0]; \
		m0 ^= rp[0]; \
		m1 ^= rp[1]; \
		m2 ^= rp[2]; \
		m3 ^= rp[3]; \
		m4 ^= rp[4]; \
		m5 ^= rp[5]; \
		m6 ^= rp[6]; \
		m7 ^= rp[7]; \
		rp = &T256_30[acc & 0x03][0]; \
		m0 ^= rp[0]; \
		m1 ^= rp[1]; \
		m2 ^= rp[2]; \
		m3 ^= rp[3]; \
		m4 ^= rp[4]; \
		m5 ^= rp[5]; \
		m6 ^= rp[6]; \
		m7 ^= rp[7]; \
	} while (0)

#endif

#if SPH_HAMSI_EXPAND_SMALL == 4

static const sph_u32 T256_0[16][8] = {
	{ SPH_C32(0x00000000), SPH_C32(0x00000000), SPH_C32(0x00000000),
	  SPH_C32(0x00000000), SPH_C32(0x00000000), SPH_C32(0x00000000),
	  SPH_C32(0x00000000), SPH_C32(0x00000000) },
	{ SPH_C32(0x121b4000), SPH_C32(0x5b17d9e8), SPH_C32(0x8dfacfab),
	  SPH_C32(0xce36cc72), SPH_C32(0xe6570000), SPH_C32(0x4bb33a25),
	  SPH_C32(0x848598ba), SPH_C32(0x1041003e) },
	{ SPH_C32(0xe6570000), SPH_C32(0x4bb33a25), SPH_C32(0x848598ba),
	  SPH_C32(0x1041003e), SPH_C32(0xf44c4000), SPH_C32(0x10a4e3cd),
	  SPH_C32(0x097f5711), SPH_C32(0xde77cc4c) },
	{ SPH_C32(0xf44c4000), SPH_C32(0x10a4e3cd), SPH_C32(0x097f5711),
	  SPH_C32(0xde77cc4c), SPH_C32(0x121b4000), SPH_C32(0x5b17d9e8),
	  SPH_C32(0x8dfacfab), SPH_C32(0xce36cc72) },
	{ SPH_C32(0xe4788000), SPH_C32(0x859673c1), SPH_C32(0xb5fb2452),
	  SPH_C32(0x29cc5edf), SPH_C32(0x045f0000), SPH_C32(0x9c4a93c9),
	  SPH_C32(0x62fc79d0), SPH_C32(0x731ebdc2) },
	{ SPH_C32(0xf663c000), SPH_C32(0xde81aa29), SPH_C32(0x3801ebf9),
	  SPH_C32(0xe7fa92ad), SPH_C32(0xe2080000), SPH_C32(0xd7f9a9ec),
	  SPH_C32(0xe679e16a), SPH_C32(0x635fbdfc) },
	{ SPH_C32(0x022f8000), SPH_C32(0xce2549e4), SPH_C32(0x317ebce8),
	  SPH_C32(0x398d5ee1), SPH_C32(0xf0134000), SPH_C32(0x8cee7004),
	  SPH_C32(0x6b832ec1), SPH_C32(0xad69718e) },
	{ SPH_C32(0x1034c000), SPH_C32(0x9532900c), SPH_C32(0xbc847343),
	  SPH_C32(0xf7bb9293), SPH_C32(0x16444000), SPH_C32(0xc75d4a21),
	  SPH_C32(0xef06b67b), SPH_C32(0xbd2871b0) },
	{ SPH_C32(0x045f0000), SPH_C32(0x9c4a93c9), SPH_C32(0x62fc79d0),
	  SPH_C32(0x731ebdc2), SPH_C32(0xe0278000), SPH_C32(0x19dce008),
	  SPH_C32(0xd7075d82), SPH_C32(0x5ad2e31d) },
	{ SPH_C32(0x16444000), SPH_C32(0xc75d4a21), SPH_C32(0xef06b67b),
	  SPH_C32(0xbd2871b0), SPH_C32(0x06708000), SPH_C32(0x526fda2d),
	  SPH_C32(0x5382c538), SPH_C32(0x4a93e323) },
	{ SPH_C32(0xe2080000), SPH_C32(0xd7f9a9ec), SPH_C32(0xe679e16a),
	  SPH_C32(0x635fbdfc), SPH_C32(0x146bc000), SPH_C32(0x097803c5),
	  SPH_C32(0xde780a93), SPH_C32(0x84a52f51) },
	{ SPH_C32(0xf0134000), SPH_C32(0x8cee7004), SPH_C32(0x6b832ec1),
	  SPH_C32(0xad69718e), SPH_C32(0xf23cc000), SPH_C32(0x42cb39e0),
	  SPH_C32(0x5afd9229), SPH_C32(0x94e42f6f) },
	{ SPH_C32(0xe0278000), SPH_C32(0x19dce008), SPH_C32(0xd7075d82),
	  SPH_C32(0x5ad2e31d), SPH_C32(0xe4788000), SPH_C32(0x859673c1),
	  SPH_C32(0xb5fb2452), SPH_C32(0x29cc5edf) },
	{ SPH_C32(0xf23cc000), SPH_C32(0x42cb39e0), SPH_C32(0x5afd9229),
	  SPH_C32(0x94e42f6f), SPH_C32(0x022f8000), SPH_C32(0xce2549e4),
	  SPH_C32(0x317ebce8), SPH_C32(0x398d5ee1) },
	{ SPH_C32(0x06708000), SPH_C32(0x526fda2d), SPH_C32(0x5382c538),
	  SPH_C32(0x4a93e323), SPH_C32(0x1034c000), SPH_C32(0x9532900c),
	  SPH_C32(0xbc847343), SPH_C32(0xf7bb9293) },
	{ SPH_C32(0x146bc000), SPH_C32(0x097803c5), SPH_C32(0xde780a93),
	  SPH_C32(0x84a52f51), SPH_C32(0xf663c000), SPH_C32(0xde81aa29),
	  SPH_C32(0x3801ebf9), SPH_C32(0xe7fa92ad) }
};

static const sph_u32 T256_4[16][8] = {
	{ SPH_C32(0x00000000), SPH_C32(0x00000000), SPH_C32(0x00000000),
	  SPH_C32(0x00000000), SPH_C32(0x00000000), SPH_C32(0x00000000),
	  SPH_C32(0x00000000), SPH_C32(0x00000000) },
	{ SPH_C32(0x74951000), SPH_C32(0x5a2b467e), SPH_C32(0x88fd1d2b),
	  SPH_C32(0x1ee68292), SPH_C32(0xcba90000), SPH_C32(0x90273769),
	  SPH_C32(0xbbdcf407), SPH_C32(0xd0f4af61) },
	{ SPH_C32(0xcba90000), SPH_C32(0x90273769), SPH_C32(0xbbdcf407),
	  SPH_C32(0xd0f4af61), SPH_C32(0xbf3c1000), SPH_C32(0xca0c7117),
	  SPH_C32(0x3321e92c), SPH_C32(0xce122df3) },
	{ SPH_C32(0xbf3c1000), SPH_C32(0xca0c7117), SPH_C32(0x3321e92c),
	  SPH_C32(0xce122df3), SPH_C32(0x74951000), SPH_C32(0x5a2b467e),
	  SPH_C32(0x88fd1d2b), SPH_C32(0x1ee68292) },
	{ SPH_C32(0xe92a2000), SPH_C32(0xb4578cfc), SPH_C32(0x11fa3a57),
	  SPH_C32(0x3dc90524), SPH_C32(0x97530000), SPH_C32(0x204f6ed3),
	  SPH_C32(0x77b9e80f), SPH_C32(0xa1ec5ec1) },
	{ SPH_C32(0x9dbf3000), SPH_C32(0xee7cca82), SPH_C32(0x9907277c),
	  SPH_C32(0x232f87b6), SPH_C32(0x5cfa0000), SPH_C32(0xb06859ba),
	  SPH_C32(0xcc651c08), SPH_C32(0x7118f1a0) },
	{ SPH_C32(0x22832000), SPH_C32(0x2470bb95), SPH_C32(0xaa26ce50),
	  SPH_C32(0xed3daa45), SPH_C32(0x286f1000), SPH_C32(0xea431fc4),
	  SPH_C32(0x44980123), SPH_C32(0x6ffe7332) },
	{ SPH_C32(0x56163000), SPH_C32(0x7e5bfdeb), SPH_C32(0x22dbd37b),
	  SPH_C32(0xf3db28d7), SPH_C32(0xe3c61000), SPH_C32(0x7a6428ad),
	  SPH_C32(0xff44f524), SPH_C32(0xbf0adc53) },
	{ SPH_C32(0x97530000), SPH_C32(0x204f6ed3), SPH_C32(0x77b9e80f),
	  SPH_C32(0xa1ec5ec1), SPH_C32(0x7e792000), SPH_C32(0x9418e22f),
	  SPH_C32(0x6643d258), SPH_C32(0x9c255be5) },
	{ SPH_C32(0xe3c61000), SPH_C32(0x7a6428ad), SPH_C32(0xff44f524),
	  SPH_C32(0xbf0adc53), SPH_C32(0xb5d02000), SPH_C32(0x043fd546),
	  SPH_C32(0xdd9f265f), SPH_C32(0x4cd1f484) },
	{ SPH_C32(0x5cfa0000), SPH_C32(0xb06859ba), SPH_C32(0xcc651c08),
	  SPH_C32(0x7118f1a0), SPH_C32(0xc1453000), SPH_C32(0x5e149338),
	  SPH_C32(0x55623b74), SPH_C32(0x52377616) },
	{ SPH_C32(0x286f1000), SPH_C32(0xea431fc4), SPH_C32(0x44980123),
	  SPH_C32(0x6ffe7332), SPH_C32(0x0aec3000), SPH_C32(0xce33a451),
	  SPH_C32(0xeebecf73), SPH_C32(0x82c3d977) },
	{ SPH_C32(0x7e792000), SPH_C32(0x9418e22f), SPH_C32(0x6643d258),
	  SPH_C32(0x9c255be5), SPH_C32(0xe92a2000), SPH_C32(0xb4578cfc),
	  SPH_C32(0x11fa3a57), SPH_C32(0x3dc90524) },
	{ SPH_C32(0x0aec3000), SPH_C32(0xce33a451), SPH_C32(0xeebecf73),
	  SPH_C32(0x82c3d977), SPH_C32(0x22832000), SPH_C32(0x2470bb95),
	  SPH_C32(0xaa26ce50), SPH_C32(0xed3daa45) },
	{ SPH_C32(0xb5d02000), SPH_C32(0x043fd546), SPH_C32(0xdd9f265f),
	  SPH_C32(0x4cd1f484), SPH_C32(0x56163000), SPH_C32(0x7e5bfdeb),
	  SPH_C32(0x22dbd37b), SPH_C32(0xf3db28d7) },
	{ SPH_C32(0xc1453000), SPH_C32(0x5e149338), SPH_C32(0x55623b74),
	  SPH_C32(0x52377616), SPH_C32(0x9dbf3000), SPH_C32(0xee7cca82),
	  SPH_C32(0x9907277c), SPH_C32(0x232f87b6) }
};

static const sph_u32 T256_8[16][8] = {
	{ SPH_C32(0x00000000), SPH_C32(0x00000000), SPH_C32(0x00000000),
	  SPH_C32(0x00000000), SPH_C32(0x00000000), SPH_C32(0x00000000),
	  SPH_C32(0x00000000), SPH_C32(0x00000000) },
	{ SPH_C32(0x8f3e0400), SPH_C32(0x0d9dc877), SPH_C32(0x6fc548e1),
	  SPH_C32(0x898d2cd6), SPH_C32(0x14bd0000), SPH_C32(0x2fba37ff),
	  SPH_C32(0x6a72e5bb), SPH_C32(0x247febe6) },
	{ SPH_C32(0x14bd0000), SPH_C32(0x2fba37ff), SPH_C32(0x6a72e5bb),
	  SPH_C32(0x247febe6), SPH_C32(0x9b830400), SPH_C32(0x2227ff88),
	  SPH_C32(0x05b7ad5a), SPH_C32(0xadf2c730) },
	{ SPH_C32(0x9b830400), SPH_C32(0x2227ff88), SPH_C32(0x05b7ad5a),
	  SPH_C32(0xadf2c730), SPH_C32(0x8f3e0400), SPH_C32(0x0d9dc877),
	  SPH_C32(0x6fc548e1), SPH_C32(0x898d2cd6) },
	{ SPH_C32(0xde320800), SPH_C32(0x288350fe), SPH_C32(0x71852ac7),
	  SPH_C32(0xa6bf9f96), SPH_C32(0xe18b0000), SPH_C32(0x5459887d),
	  SPH_C32(0xbf1283d3), SPH_C32(0x1b666a73) },
	{ SPH_C32(0x510c0c00), SPH_C32(0x251e9889), SPH_C32(0x1e406226),
	  SPH_C32(0x2f32b340), SPH_C32(0xf5360000), SPH_C32(0x7be3bf82),
	  SPH_C32(0xd5606668), SPH_C32(0x3f198195) },
	{ SPH_C32(0xca8f0800), SPH_C32(0x07396701), SPH_C32(0x1bf7cf7c),
	  SPH_C32(0x82c07470), SPH_C32(0x7a080400), SPH_C32(0x767e77f5),
	  SPH_C32(0xbaa52e89), SPH_C32(0xb694ad43) },
	{ SPH_C32(0x45b10c00), SPH_C32(0x0aa4af76), SPH_C32(0x7432879d),
	  SPH_C32(0x0b4d58a6), SPH_C32(0x6eb50400), SPH_C32(0x59c4400a),
	  SPH_C32(0xd0d7cb32), SPH_C32(0x92eb46a5) },
	{ SPH_C32(0xe18b0000), SPH_C32(0x5459887d), SPH_C32(0xbf1283d3),
	  SPH_C32(0x1b666a73), SPH_C32(0x3fb90800), SPH_C32(0x7cdad883),
	  SPH_C32(0xce97a914), SPH_C32(0xbdd9f5e5) },
	{ SPH_C32(0x6eb50400), SPH_C32(0x59c4400a), SPH_C32(0xd0d7cb32),
	  SPH_C32(0x92eb46a5), SPH_C32(0x2b040800), SPH_C32(0x5360ef7c),
	  SPH_C32(0xa4e54caf), SPH_C32(0x99a61e03) },
	{ SPH_C32(0xf5360000), SPH_C32(0x7be3bf82), SPH_C32(0xd5606668),
	  SPH_C32(0x3f198195), SPH_C32(0xa43a0c00), SPH_C32(0x5efd270b),
	  SPH_C32(0xcb20044e), SPH_C32(0x102b32d5) },
	{ SPH_C32(0x7a080400), SPH_C32(0x767e77f5), SPH_C32(0xbaa52e89),
	  SPH_C32(0xb694ad43), SPH_C32(0xb0870c00), SPH_C32(0x714710f4),
	  SPH_C32(0xa152e1f5), SPH_C32(0x3454d933) },
	{ SPH_C32(0x3fb90800), SPH_C32(0x7cdad883), SPH_C32(0xce97a914),
	  SPH_C32(0xbdd9f5e5), SPH_C32(0xde320800), SPH_C32(0x288350fe),
	  SPH_C32(0x71852ac7), SPH_C32(0xa6bf9f96) },
	{ SPH_C32(0xb0870c00), SPH_C32(0x714710f4), SPH_C32(0xa152e1f5),
	  SPH_C32(0x3454d933), SPH_C32(0xca8f0800), SPH_C32(0x07396701),
	  SPH_C32(0x1bf7cf7c), SPH_C32(0x82c07470) },
	{ SPH_C32(0x2b040800), SPH_C32(0x5360ef7c), SPH_C32(0xa4e54caf),
	  SPH_C32(0x99a61e03), SPH_C32(0x45b10c00), SPH_C32(0x0aa4af76),
	  SPH_C32(0x7432879d), SPH_C32(0x0b4d58a6) },
	{ SPH_C32(0xa43a0c00), SPH_C32(0x5efd270b), SPH_C32(0xcb20044e),
	  SPH_C32(0x102b32d5), SPH_C32(0x510c0c00), SPH_C32(0x251e9889),
	  SPH_C32(0x1e406226), SPH_C32(0x2f32b340) }
};

static const sph_u32 T256_12[16][8] = {
	{ SPH_C32(0x00000000), SPH_C32(0x00000000), SPH_C32(0x00000000),
	  SPH_C32(0x00000000), SPH_C32(0x00000000), SPH_C32(0x00000000),
	  SPH_C32(0x00000000), SPH_C32(0x00000000) },
	{ SPH_C32(0xb7a40100), SPH_C32(0x8a1f31d8), SPH_C32(0x8589d8ab),
	  SPH_C32(0xe6c46464), SPH_C32(0x734c0000), SPH_C32(0x956fa7d6),
	  SPH_C32(0xa29d1297), SPH_C32(0x6ee56854) },
	{ SPH_C32(0x734c0000), SPH_C32(0x956fa7d6), SPH_C32(0xa29d1297),
	  SPH_C32(0x6ee56854), SPH_C32(0xc4e80100), SPH_C32(0x1f70960e),
	  SPH_C32(0x2714ca3c), SPH_C32(0x88210c30) },
	{ SPH_C32(0xc4e80100), SPH_C32(0x1f70960e), SPH_C32(0x2714ca3c),
	  SPH_C32(0x88210c30), SPH_C32(0xb7a40100), SPH_C32(0x8a1f31d8),
	  SPH_C32(0x8589d8ab), SPH_C32(0xe6c46464) },
	{ SPH_C32(0xa7b80200), SPH_C32(0x1f128433), SPH_C32(0x60e5f9f2),
	  SPH_C32(0x9e147576), SPH_C32(0xee260000), SPH_C32(0x124b683e),
	  SPH_C32(0x80c2d68f), SPH_C32(0x3bf3ab2c) },
	{ SPH_C32(0x101c0300), SPH_C32(0x950db5eb), SPH_C32(0xe56c2159),
	  SPH_C32(0x78d01112), SPH_C32(0x9d6a0000), SPH_C32(0x8724cfe8),
	  SPH_C32(0x225fc418), SPH_C32(0x5516c378) },
	{ SPH_C32(0xd4f40200), SPH_C32(0x8a7d23e5), SPH_C32(0xc278eb65),
	  SPH_C32(0xf0f11d22), SPH_C32(0x2ace0100), SPH_C32(0x0d3bfe30),
	  SPH_C32(0xa7d61cb3), SPH_C32(0xb3d2a71c) },
	{ SPH_C32(0x63500300), SPH_C32(0x0062123d), SPH_C32(0x47f133ce),
	  SPH_C32(0x16357946), SPH_C32(0x59820100), SPH_C32(0x985459e6),
	  SPH_C32(0x054b0e24), SPH_C32(0xdd37cf48) },
	{ SPH_C32(0xee260000), SPH_C32(0x124b683e), SPH_C32(0x80c2d68f),
	  SPH_C32(0x3bf3ab2c), SPH_C32(0x499e0200), SPH_C32(0x0d59ec0d),
	  SPH_C32(0xe0272f7d), SPH_C32(0xa5e7de5a) },
	{ SPH_C32(0x59820100), SPH_C32(0x985459e6), SPH_C32(0x054b0e24),
	  SPH_C32(0xdd37cf48), SPH_C32(0x3ad20200), SPH_C32(0x98364bdb),
	  SPH_C32(0x42ba3dea), SPH_C32(0xcb02b60e) },
	{ SPH_C32(0x9d6a0000), SPH_C32(0x8724cfe8), SPH_C32(0x225fc418),
	  SPH_C32(0x5516c378), SPH_C32(0x8d760300), SPH_C32(0x12297a03),
	  SPH_C32(0xc733e541), SPH_C32(0x2dc6d26a) },
	{ SPH_C32(0x2ace0100), SPH_C32(0x0d3bfe30), SPH_C32(0xa7d61cb3),
	  SPH_C32(0xb3d2a71c), SPH_C32(0xfe3a0300), SPH_C32(0x8746ddd5),
	  SPH_C32(0x65aef7d6), SPH_C32(0x4323ba3e) },
	{ SPH_C32(0x499e0200), SPH_C32(0x0d59ec0d), SPH_C32(0xe0272f7d),
	  SPH_C32(0xa5e7de5a), SPH_C32(0xa7b80200), SPH_C32(0x1f128433),
	  SPH_C32(0x60e5f9f2), SPH_C32(0x9e147576) },
	{ SPH_C32(0xfe3a0300), SPH_C32(0x8746ddd5), SPH_C32(0x65aef7d6),
	  SPH_C32(0x4323ba3e), SPH_C32(0xd4f40200), SPH_C32(0x8a7d23e5),
	  SPH_C32(0xc278eb65), SPH_C32(0xf0f11d22) },
	{ SPH_C32(0x3ad20200), SPH_C32(0x98364bdb), SPH_C32(0x42ba3dea),
	  SPH_C32(0xcb02b60e), SPH_C32(0x63500300), SPH_C32(0x0062123d),
	  SPH_C32(0x47f133ce), SPH_C32(0x16357946) },
	{ SPH_C32(0x8d760300), SPH_C32(0x12297a03), SPH_C32(0xc733e541),
	  SPH_C32(0x2dc6d26a), SPH_C32(0x101c0300), SPH_C32(0x950db5eb),
	  SPH_C32(0xe56c2159), SPH_C32(0x78d01112) }
};

static const sph_u32 T256_16[16][8] = {
	{ SPH_C32(0x00000000), SPH_C32(0x00000000), SPH_C32(0x00000000),
	  SPH_C32(0x00000000), SPH_C32(0x00000000), SPH_C32(0x00000000),
	  SPH_C32(0x00000000), SPH_C32(0x00000000) },
	{ SPH_C32(0x4dce0040), SPH_C32(0x3b5bec7e), SPH_C32(0x36656ba8),
	  SPH_C32(0x23633a05), SPH_C32(0x78ab0000), SPH_C32(0xa0cd5a34),
	  SPH_C32(0x5d5ca0f7), SPH_C32(0x727784cb) },
	{ SPH_C32(0x78ab0000), SPH_C32(0xa0cd5a34), SPH_C32(0x5d5ca0f7),
	  SPH_C32(0x727784cb), SPH_C32(0x35650040), SPH_C32(0x9b96b64a),
	  SPH_C32(0x6b39cb5f), SPH_C32(0x5114bece) },
	{ SPH_C32(0x35650040), SPH_C32(0x9b96b64a), SPH_C32(0x6b39cb5f),
	  SPH_C32(0x5114bece), SPH_C32(0x4dce0040), SPH_C32(0x3b5bec7e),
	  SPH_C32(0x36656ba8), SPH_C32(0x23633a05) },
	{ SPH_C32(0x5bd20080), SPH_C32(0x450f18ec), SPH_C32(0xc2c46c55),
	  SPH_C32(0xf362b233), SPH_C32(0x39a60000), SPH_C32(0x4ab753eb),
	  SPH_C32(0xd14e094b), SPH_C32(0xb772b42b) },
	{ SPH_C32(0x161c00c0), SPH_C32(0x7e54f492), SPH_C32(0xf4a107fd),
	  SPH_C32(0xd0018836), SPH_C32(0x410d0000), SPH_C32(0xea7a09df),
	  SPH_C32(0x8c12a9bc), SPH_C32(0xc50530e0) },
	{ SPH_C32(0x23790080), SPH_C32(0xe5c242d8), SPH_C32(0x9f98cca2),
	  SPH_C32(0x811536f8), SPH_C32(0x0cc30040), SPH_C32(0xd121e5a1),
	  SPH_C32(0xba77c214), SPH_C32(0xe6660ae5) },
	{ SPH_C32(0x6eb700c0), SPH_C32(0xde99aea6), SPH_C32(0xa9fda70a),
	  SPH_C32(0xa2760cfd), SPH_C32(0x74680040), SPH_C32(0x71ecbf95),
	  SPH_C32(0xe72b62e3), SPH_C32(0x94118e2e) },
	{ SPH_C32(0x39a60000), SPH_C32(0x4ab753eb), SPH_C32(0xd14e094b),
	  SPH_C32(0xb772b42b), SPH_C32(0x62740080), SPH_C32(0x0fb84b07),
	  SPH_C32(0x138a651e), SPH_C32(0x44100618) },
	{ SPH_C32(0x74680040), SPH_C32(0x71ecbf95), SPH_C32(0xe72b62e3),
	  SPH_C32(0x94118e2e), SPH_C32(0x1adf0080), SPH_C32(0xaf751133),
	  SPH_C32(0x4ed6c5e9), SPH_C32(0x366782d3) },
	{ SPH_C32(0x410d0000), SPH_C32(0xea7a09df), SPH_C32(0x8c12a9bc),
	  SPH_C32(0xc50530e0), SPH_C32(0x571100c0), SPH_C32(0x942efd4d),
	  SPH_C32(0x78b3ae41), SPH_C32(0x1504b8d6) },
	{ SPH_C32(0x0cc30040), SPH_C32(0xd121e5a1), SPH_C32(0xba77c214),
	  SPH_C32(0xe6660ae5), SPH_C32(0x2fba00c0), SPH_C32(0x34e3a779),
	  SPH_C32(0x25ef0eb6), SPH_C32(0x67733c1d) },
	{ SPH_C32(0x62740080), SPH_C32(0x0fb84b07), SPH_C32(0x138a651e),
	  SPH_C32(0x44100618), SPH_C32(0x5bd20080), SPH_C32(0x450f18ec),
	  SPH_C32(0xc2c46c55), SPH_C32(0xf362b233) },
	{ SPH_C32(0x2fba00c0), SPH_C32(0x34e3a779), SPH_C32(0x25ef0eb6),
	  SPH_C32(0x67733c1d), SPH_C32(0x23790080), SPH_C32(0xe5c242d8),
	  SPH_C32(0x9f98cca2), SPH_C32(0x811536f8) },
	{ SPH_C32(0x1adf0080), SPH_C32(0xaf751133), SPH_C32(0x4ed6c5e9),
	  SPH_C32(0x366782d3), SPH_C32(0x6eb700c0), SPH_C32(0xde99aea6),
	  SPH_C32(0xa9fda70a), SPH_C32(0xa2760cfd) },
	{ SPH_C32(0x571100c0), SPH_C32(0x942efd4d), SPH_C32(0x78b3ae41),
	  SPH_C32(0x1504b8d6), SPH_C32(0x161c00c0), SPH_C32(0x7e54f492),
	  SPH_C32(0xf4a107fd), SPH_C32(0xd0018836) }
};

static const sph_u32 T256_20[16][8] = {
	{ SPH_C32(0x00000000), SPH_C32(0x00000000), SPH_C32(0x00000000),
	  SPH_C32(0x00000000), SPH_C32(0x00000000), SPH_C32(0x00000000),
	  SPH_C32(0x00000000), SPH_C32(0x00000000) },
	{ SPH_C32(0x515c0010), SPH_C32(0x40f372fb), SPH_C32(0xfce72602),
	  SPH_C32(0x71575061), SPH_C32(0x2e390000), SPH_C32(0x64dd6689),
	  SPH_C32(0x3cd406fc), SPH_C32(0xb1f490bc) },
	{ SPH_C32(0x2e390000), SPH_C32(0x64dd6689), SPH_C32(0x3cd406fc),
	  SPH_C32(0xb1f490bc), SPH_C32(0x7f650010), SPH_C32(0x242e1472),
	  SPH_C32(0xc03320fe), SPH_C32(0xc0a3c0dd) },
	{ SPH_C32(0x7f650010), SPH_C32(0x242e1472), SPH_C32(0xc03320fe),
	  SPH_C32(0xc0a3c0dd), SPH_C32(0x515c0010), SPH_C32(0x40f372fb),
	  SPH_C32(0xfce72602), SPH_C32(0x71575061) },
	{ SPH_C32(0xa2b80020), SPH_C32(0x81e7e5f6), SPH_C32(0xf9ce4c04),
	  SPH_C32(0xe2afa0c0), SPH_C32(0x5c720000), SPH_C32(0xc9bacd12),
	  SPH_C32(0x79a90df9), SPH_C32(0x63e92178) },
	{ SPH_C32(0xf3e40030), SPH_C32(0xc114970d), SPH_C32(0x05296a06),
	  SPH_C32(0x93f8f0a1), SPH_C32(0x724b0000), SPH_C32(0xad67ab9b),
	  SPH_C32(0x457d0b05), SPH_C32(0xd21db1c4) },
	{ SPH_C32(0x8c810020), SPH_C32(0xe53a837f), SPH_C32(0xc51a4af8),
	  SPH_C32(0x535b307c), SPH_C32(0x23170010), SPH_C32(0xed94d960),
	  SPH_C32(0xb99a2d07), SPH_C32(0xa34ae1a5) },
	{ SPH_C32(0xdddd0030), SPH_C32(0xa5c9f184), SPH_C32(0x39fd6cfa),
	  SPH_C32(0x220c601d), SPH_C32(0x0d2e0010), SPH_C32(0x8949bfe9),
	  SPH_C32(0x854e2bfb), SPH_C32(0x12be7119) },
	{ SPH_C32(0x5c720000), SPH_C32(0xc9bacd12), SPH_C32(0x79a90df9),
	  SPH_C32(0x63e92178), SPH_C32(0xfeca0020), SPH_C32(0x485d28e4),
	  SPH_C32(0x806741fd), SPH_C32(0x814681b8) },
	{ SPH_C32(0x0d2e0010), SPH_C32(0x8949bfe9), SPH_C32(0x854e2bfb),
	  SPH_C32(0x12be7119), SPH_C32(0xd0f30020), SPH_C32(0x2c804e6d),
	  SPH_C32(0xbcb34701), SPH_C32(0x30b21104) },
	{ SPH_C32(0x724b0000), SPH_C32(0xad67ab9b), SPH_C32(0x457d0b05),
	  SPH_C32(0xd21db1c4), SPH_C32(0x81af0030), SPH_C32(0x6c733c96),
	  SPH_C32(0x40546103), SPH_C32(0x41e54165) },
	{ SPH_C32(0x23170010), SPH_C32(0xed94d960), SPH_C32(0xb99a2d07),
	  SPH_C32(0xa34ae1a5), SPH_C32(0xaf960030), SPH_C32(0x08ae5a1f),
	  SPH_C32(0x7c8067ff), SPH_C32(0xf011d1d9) },
	{ SPH_C32(0xfeca0020), SPH_C32(0x485d28e4), SPH_C32(0x806741fd),
	  SPH_C32(0x814681b8), SPH_C32(0xa2b80020), SPH_C32(0x81e7e5f6),
	  SPH_C32(0xf9ce4c04), SPH_C32(0xe2afa0c0) },
	{ SPH_C32(0xaf960030), SPH_C32(0x08ae5a1f), SPH_C32(0x7c8067ff),
	  SPH_C32(0xf011d1d9), SPH_C32(0x8c810020), SPH_C32(0xe53a837f),
	  SPH_C32(0xc51a4af8), SPH_C32(0x535b307c) },
	{ SPH_C32(0xd0f30020), SPH_C32(0x2c804e6d), SPH_C32(0xbcb34701),
	  SPH_C32(0x30b21104), SPH_C32(0xdddd0030), SPH_C32(0xa5c9f184),
	  SPH_C32(0x39fd6cfa), SPH_C32(0x220c601d) },
	{ SPH_C32(0x81af0030), SPH_C32(0x6c733c96), SPH_C32(0x40546103),
	  SPH_C32(0x41e54165), SPH_C32(0xf3e40030), SPH_C32(0xc114970d),
	  SPH_C32(0x05296a06), SPH_C32(0x93f8f0a1) }
};

static const sph_u32 T256_24[16][8] = {
	{ SPH_C32(0x00000000), SPH_C32(0x00000000), SPH_C32(0x00000000),
	  SPH_C32(0x00000000), SPH_C32(0x00000000), SPH_C32(0x00000000),
	  SPH_C32(0x00000000), SPH_C32(0x00000000) },
	{ SPH_C32(0xd0080004), SPH_C32(0x8c768f77), SPH_C32(0x9dc5b050),
	  SPH_C32(0xaf4a29da), SPH_C32(0x6ba90000), SPH_C32(0x40ebf9aa),
	  SPH_C32(0x98321c3d), SPH_C32(0x76acc733) },
	{ SPH_C32(0x6ba90000), SPH_C32(0x40ebf9aa), SPH_C32(0x98321c3d),
	  SPH_C32(0x76acc733), SPH_C32(0xbba10004), SPH_C32(0xcc9d76dd),
	  SPH_C32(0x05f7ac6d), SPH_C32(0xd9e6eee9) },
	{ SPH_C32(0xbba10004), SPH_C32(0xcc9d76dd), SPH_C32(0x05f7ac6d),
	  SPH_C32(0xd9e6eee9), SPH_C32(0xd0080004), SPH_C32(0x8c768f77),
	  SPH_C32(0x9dc5b050), SPH_C32(0xaf4a29da) },
	{ SPH_C32(0xa8ae0008), SPH_C32(0x2079397d), SPH_C32(0xfe739301),
	  SPH_C32(0xb8a92831), SPH_C32(0x171c0000), SPH_C32(0xb26e3344),
	  SPH_C32(0x9e6a837e), SPH_C32(0x58f8485f) },
	{ SPH_C32(0x78a6000c), SPH_C32(0xac0fb60a), SPH_C32(0x63b62351),
	  SPH_C32(0x17e301eb), SPH_C32(0x7cb50000), SPH_C32(0xf285caee),
	  SPH_C32(0x06589f43), SPH_C32(0x2e548f6c) },
	{ SPH_C32(0xc3070008), SPH_C32(0x6092c0d7), SPH_C32(0x66418f3c),
	  SPH_C32(0xce05ef02), SPH_C32(0xacbd0004), SPH_C32(0x7ef34599),
	  SPH_C32(0x9b9d2f13), SPH_C32(0x811ea6b6) },
	{ SPH_C32(0x130f000c), SPH_C32(0xece44fa0), SPH_C32(0xfb843f6c),
	  SPH_C32(0x614fc6d8), SPH_C32(0xc7140004), SPH_C32(0x3e18bc33),
	  SPH_C32(0x03af332e), SPH_C32(0xf7b26185) },
	{ SPH_C32(0x171c0000), SPH_C32(0xb26e3344), SPH_C32(0x9e6a837e),
	  SPH_C32(0x58f8485f), SPH_C32(0xbfb20008), SPH_C32(0x92170a39),
	  SPH_C32(0x6019107f), SPH_C32(0xe051606e) },
	{ SPH_C32(0xc7140004), SPH_C32(0x3e18bc33), SPH_C32(0x03af332e),
	  SPH_C32(0xf7b26185), SPH_C32(0xd41b0008), SPH_C32(0xd2fcf393),
	  SPH_C32(0xf82b0c42), SPH_C32(0x96fda75d) },
	{ SPH_C32(0x7cb50000), SPH_C32(0xf285caee), SPH_C32(0x06589f43),
	  SPH_C32(0x2e548f6c), SPH_C32(0x0413000c), SPH_C32(0x5e8a7ce4),
	  SPH_C32(0x65eebc12), SPH_C32(0x39b78e87) },
	{ SPH_C32(0xacbd0004), SPH_C32(0x7ef34599), SPH_C32(0x9b9d2f13),
	  SPH_C32(0x811ea6b6), SPH_C32(0x6fba000c), SPH_C32(0x1e61854e),
	  SPH_C32(0xfddca02f), SPH_C32(0x4f1b49b4) },
	{ SPH_C32(0xbfb20008), SPH_C32(0x92170a39), SPH_C32(0x6019107f),
	  SPH_C32(0xe051606e), SPH_C32(0xa8ae0008), SPH_C32(0x2079397d),
	  SPH_C32(0xfe739301), SPH_C32(0xb8a92831) },
	{ SPH_C32(0x6fba000c), SPH_C32(0x1e61854e), SPH_C32(0xfddca02f),
	  SPH_C32(0x4f1b49b4), SPH_C32(0xc3070008), SPH_C32(0x6092c0d7),
	  SPH_C32(0x66418f3c), SPH_C32(0xce05ef02) },
	{ SPH_C32(0xd41b0008), SPH_C32(0xd2fcf393), SPH_C32(0xf82b0c42),
	  SPH_C32(0x96fda75d), SPH_C32(0x130f000c), SPH_C32(0xece44fa0),
	  SPH_C32(0xfb843f6c), SPH_C32(0x614fc6d8) },
	{ SPH_C32(0x0413000c), SPH_C32(0x5e8a7ce4), SPH_C32(0x65eebc12),
	  SPH_C32(0x39b78e87), SPH_C32(0x78a6000c), SPH_C32(0xac0fb60a),
	  SPH_C32(0x63b62351), SPH_C32(0x17e301eb) }
};

static const sph_u32 T256_28[16][8] = {
	{ SPH_C32(0x00000000), SPH_C32(0x00000000), SPH_C32(0x00000000),
	  SPH_C32(0x00000000), SPH_C32(0x00000000), SPH_C32(0x00000000),
	  SPH_C32(0x00000000), SPH_C32(0x00000000) },
	{ SPH_C32(0xc04e0001), SPH_C32(0x33b9c010), SPH_C32(0xae0ebb05),
	  SPH_C32(0xb5a4c63b), SPH_C32(0xc8f10000), SPH_C32(0x0b2de782),
	  SPH_C32(0x6bf648a4), SPH_C32(0x539cbdbf) },
	{ SPH_C32(0xc8f10000), SPH_C32(0x0b2de782), SPH_C32(0x6bf648a4),
	  SPH_C32(0x539cbdbf), SPH_C32(0x08bf0001), SPH_C32(0x38942792),
	  SPH_C32(0xc5f8f3a1), SPH_C32(0xe6387b84) },
	{ SPH_C32(0x08bf0001), SPH_C32(0x38942792), SPH_C32(0xc5f8f3a1),
	  SPH_C32(0xe6387b84), SPH_C32(0xc04e0001), SPH_C32(0x33b9c010),
	  SPH_C32(0xae0ebb05), SPH_C32(0xb5a4c63b) },
	{ SPH_C32(0x88230002), SPH_C32(0x5fe7a7b3), SPH_C32(0x99e585aa),
	  SPH_C32(0x8d75f7f1), SPH_C32(0x51ac0000), SPH_C32(0x25e30f14),
	  SPH_C32(0x79e22a4c), SPH_C32(0x1298bd46) },
	{ SPH_C32(0x486d0003), SPH_C32(0x6c5e67a3), SPH_C32(0x37eb3eaf),
	  SPH_C32(0x38d131ca), SPH_C32(0x995d0000), SPH_C32(0x2ecee896),
	  SPH_C32(0x121462e8), SPH_C32(0x410400f9) },
	{ SPH_C32(0x40d20002), SPH_C32(0x54ca4031), SPH_C32(0xf213cd0e),
	  SPH_C32(0xdee94a4e), SPH_C32(0x59130001), SPH_C32(0x1d772886),
	  SPH_C32(0xbc1ad9ed), SPH_C32(0xf4a0c6c2) },
	{ SPH_C32(0x809c0003), SPH_C32(0x67738021), SPH_C32(0x5c1d760b),
	  SPH_C32(0x6b4d8c75), SPH_C32(0x91e20001), SPH_C32(0x165acf04),
	  SPH_C32(0xd7ec9149), SPH_C32(0xa73c7b7d) },
	{ SPH_C32(0x51ac0000), SPH_C32(0x25e30f14), SPH_C32(0x79e22a4c),
	  SPH_C32(0x1298bd46), SPH_C32(0xd98f0002), SPH_C32(0x7a04a8a7),
	  SPH_C32(0xe007afe6), SPH_C32(0x9fed4ab7) },
	{ SPH_C32(0x91e20001), SPH_C32(0x165acf04), SPH_C32(0xd7ec9149),
	  SPH_C32(0xa73c7b7d), SPH_C32(0x117e0002), SPH_C32(0x71294f25),
	  SPH_C32(0x8bf1e742), SPH_C32(0xcc71f708) },
	{ SPH_C32(0x995d0000), SPH_C32(0x2ecee896), SPH_C32(0x121462e8),
	  SPH_C32(0x410400f9), SPH_C32(0xd1300003), SPH_C32(0x42908f35),
	  SPH_C32(0x25ff5c47), SPH_C32(0x79d53133) },
	{ SPH_C32(0x59130001), SPH_C32(0x1d772886), SPH_C32(0xbc1ad9ed),
	  SPH_C32(0xf4a0c6c2), SPH_C32(0x19c10003), SPH_C32(0x49bd68b7),
	  SPH_C32(0x4e0914e3), SPH_C32(0x2a498c8c) },
	{ SPH_C32(0xd98f0002), SPH_C32(0x7a04a8a7), SPH_C32(0xe007afe6),
	  SPH_C32(0x9fed4ab7), SPH_C32(0x88230002), SPH_C32(0x5fe7a7b3),
	  SPH_C32(0x99e585aa), SPH_C32(0x8d75f7f1) },
	{ SPH_C32(0x19c10003), SPH_C32(0x49bd68b7), SPH_C32(0x4e0914e3),
	  SPH_C32(0x2a498c8c), SPH_C32(0x40d20002), SPH_C32(0x54ca4031),
	  SPH_C32(0xf213cd0e), SPH_C32(0xdee94a4e) },
	{ SPH_C32(0x117e0002), SPH_C32(0x71294f25), SPH_C32(0x8bf1e742),
	  SPH_C32(0xcc71f708), SPH_C32(0x809c0003), SPH_C32(0x67738021),
	  SPH_C32(0x5c1d760b), SPH_C32(0x6b4d8c75) },
	{ SPH_C32(0xd1300003), SPH_C32(0x42908f35), SPH_C32(0x25ff5c47),
	  SPH_C32(0x79d53133), SPH_C32(0x486d0003), SPH_C32(0x6c5e67a3),
	  SPH_C32(0x37eb3eaf), SPH_C32(0x38d131ca) }
};

#define INPUT_SMALL   do { \
		unsigned acc = buf[0]; \
		const sph_u32 *rp; \
		rp = &T256_0[acc >> 4][0]; \
		m0 = rp[0]; \
		m1 = rp[1]; \
		m2 = rp[2]; \
		m3 = rp[3]; \
		m4 = rp[4]; \
		m5 = rp[5]; \
		m6 = rp[6]; \
		m7 = rp[7]; \
		rp = &T256_4[acc & 0x0f][0]; \
		m0 ^= rp[0]; \
		m1 ^= rp[1]; \
		m2 ^= rp[2]; \
		m3 ^= rp[3]; \
		m4 ^= rp[4]; \
		m5 ^= rp[5]; \
		m6 ^= rp[6]; \
		m7 ^= rp[7]; \
		acc = buf[1]; \
		rp = &T256_8[acc >> 4][0]; \
		m0 ^= rp[0]; \
		m1 ^= rp[1]; \
		m2 ^= rp[2]; \
		m3 ^= rp[3]; \
		m4 ^= rp[4]; \
		m5 ^= rp[5]; \
		m6 ^= rp[6]; \
		m7 ^= rp[7]; \
		rp = &T256_12[acc & 0x0f][0]; \
		m0 ^= rp[0]; \
		m1 ^= rp[1]; \
		m2 ^= rp[2]; \
		m3 ^= rp[3]; \
		m4 ^= rp[4]; \
		m5 ^= rp[5]; \
		m6 ^= rp[6]; \
		m7 ^= rp[7]; \
		acc = buf[2]; \
		rp = &T256_16[acc >> 4][0]; \
		m0 ^= rp[0]; \
		m1 ^= rp[1]; \
		m2 ^= rp[2]; \
		m3 ^= rp[3]; \
		m4 ^= rp[4]; \
		m5 ^= rp[5]; \
		m6 ^= rp[6]; \
		m7 ^= rp[7]; \
		rp = &T256_20[acc & 0x0f][0]; \
		m0 ^= rp[0]; \
		m1 ^= rp[1]; \
		m2 ^= rp[2]; \
		m3 ^= rp[3]; \
		m4 ^= rp[4]; \
		m5 ^= rp[5]; \
		m6 ^= rp[6]; \
		m7 ^= rp[7]; \
		acc = buf[3]; \
		rp = &T256_24[acc >> 4][0]; \
		m0 ^= rp[0]; \
		m1 ^= rp[1]; \
		m2 ^= rp[2]; \
		m3 ^= rp[3]; \
		m4 ^= rp[4]; \
		m5 ^= rp[5]; \
		m6 ^= rp[6]; \
		m7 ^= rp[7]; \
		rp = &T256_28[acc & 0x0f][0]; \
		m0 ^= rp[0]; \
		m1 ^= rp[1]; \
		m2 ^= rp[2]; \
		m3 ^= rp[3]; \
		m4 ^= rp[4]; \
		m5 ^= rp[5]; \
		m6 ^= rp[6]; \
		m7 ^= rp[7]; \
	} while (0)

#endif

#if SPH_HAMSI_EXPAND_SMALL == 5

static const sph_u32 T256_0[32][8] = {
	{ SPH_C32(0x00000000), SPH_C32(0x00000000), SPH_C32(0x00000000),
	  SPH_C32(0x00000000), SPH_C32(0x00000000), SPH_C32(0x00000000),
	  SPH_C32(0x00000000), SPH_C32(0x00000000) },
	{ SPH_C32(0x97530000), SPH_C32(0x204f6ed3), SPH_C32(0x77b9e80f),
	  SPH_C32(0xa1ec5ec1), SPH_C32(0x7e792000), SPH_C32(0x9418e22f),
	  SPH_C32(0x6643d258), SPH_C32(0x9c255be5) },
	{ SPH_C32(0x121b4000), SPH_C32(0x5b17d9e8), SPH_C32(0x8dfacfab),
	  SPH_C32(0xce36cc72), SPH_C32(0xe6570000), SPH_C32(0x4bb33a25),
	  SPH_C32(0x848598ba), SPH_C32(0x1041003e) },
	{ SPH_C32(0x85484000), SPH_C32(0x7b58b73b), SPH_C32(0xfa4327a4),
	  SPH_C32(0x6fda92b3), SPH_C32(0x982e2000), SPH_C32(0xdfabd80a),
	  SPH_C32(0xe2c64ae2), SPH_C32(0x8c645bdb) },
	{ SPH_C32(0xe6570000), SPH_C32(0x4bb33a25), SPH_C32(0x848598ba),
	  SPH_C32(0x1041003e), SPH_C32(0xf44c4000), SPH_C32(0x10a4e3cd),
	  SPH_C32(0x097f5711), SPH_C32(0xde77cc4c) },
	{ SPH_C32(0x71040000), SPH_C32(0x6bfc54f6), SPH_C32(0xf33c70b5),
	  SPH_C32(0xb1ad5eff), SPH_C32(0x8a356000), SPH_C32(0x84bc01e2),
	  SPH_C32(0x6f3c8549), SPH_C32(0x425297a9) },
	{ SPH_C32(0xf44c4000), SPH_C32(0x10a4e3cd), SPH_C32(0x097f5711),
	  SPH_C32(0xde77cc4c), SPH_C32(0x121b4000), SPH_C32(0x5b17d9e8),
	  SPH_C32(0x8dfacfab), SPH_C32(0xce36cc72) },
	{ SPH_C32(0x631f4000), SPH_C32(0x30eb8d1e), SPH_C32(0x7ec6bf1e),
	  SPH_C32(0x7f9b928d), SPH_C32(0x6c626000), SPH_C32(0xcf0f3bc7),
	  SPH_C32(0xebb91df3), SPH_C32(0x52139797) },
	{ SPH_C32(0xe4788000), SPH_C32(0x859673c1), SPH_C32(0xb5fb2452),
	  SPH_C32(0x29cc5edf), SPH_C32(0x045f0000), SPH_C32(0x9c4a93c9),
	  SPH_C32(0x62fc79d0), SPH_C32(0x731ebdc2) },
	{ SPH_C32(0x732b8000), SPH_C32(0xa5d91d12), SPH_C32(0xc242cc5d),
	  SPH_C32(0x8820001e), SPH_C32(0x7a262000), SPH_C32(0x085271e6),
	  SPH_C32(0x04bfab88), SPH_C32(0xef3be627) },
	{ SPH_C32(0xf663c000), SPH_C32(0xde81aa29), SPH_C32(0x3801ebf9),
	  SPH_C32(0xe7fa92ad), SPH_C32(0xe2080000), SPH_C32(0xd7f9a9ec),
	  SPH_C32(0xe679e16a), SPH_C32(0x635fbdfc) },
	{ SPH_C32(0x6130c000), SPH_C32(0xfecec4fa), SPH_C32(0x4fb803f6),
	  SPH_C32(0x4616cc6c), SPH_C32(0x9c712000), SPH_C32(0x43e14bc3),
	  SPH_C32(0x803a3332), SPH_C32(0xff7ae619) },
	{ SPH_C32(0x022f8000), SPH_C32(0xce2549e4), SPH_C32(0x317ebce8),
	  SPH_C32(0x398d5ee1), SPH_C32(0xf0134000), SPH_C32(0x8cee7004),
	  SPH_C32(0x6b832ec1), SPH_C32(0xad69718e) },
	{ SPH_C32(0x957c8000), SPH_C32(0xee6a2737), SPH_C32(0x46c754e7),
	  SPH_C32(0x98610020), SPH_C32(0x8e6a6000), SPH_C32(0x18f6922b),
	  SPH_C32(0x0dc0fc99), SPH_C32(0x314c2a6b) },
	{ SPH_C32(0x1034c000), SPH_C32(0x9532900c), SPH_C32(0xbc847343),
	  SPH_C32(0xf7bb9293), SPH_C32(0x16444000), SPH_C32(0xc75d4a21),
	  SPH_C32(0xef06b67b), SPH_C32(0xbd2871b0) },
	{ SPH_C32(0x8767c000), SPH_C32(0xb57dfedf), SPH_C32(0xcb3d9b4c),
	  SPH_C32(0x5657cc52), SPH_C32(0x683d6000), SPH_C32(0x5345a80e),
	  SPH_C32(0x89456423), SPH_C32(0x210d2a55) },
	{ SPH_C32(0x045f0000), SPH_C32(0x9c4a93c9), SPH_C32(0x62fc79d0),
	  SPH_C32(0x731ebdc2), SPH_C32(0xe0278000), SPH_C32(0x19dce008),
	  SPH_C32(0xd7075d82), SPH_C32(0x5ad2e31d) },
	{ SPH_C32(0x930c0000), SPH_C32(0xbc05fd1a), SPH_C32(0x154591df),
	  SPH_C32(0xd2f2e303), SPH_C32(0x9e5ea000), SPH_C32(0x8dc40227),
	  SPH_C32(0xb1448fda), SPH_C32(0xc6f7b8f8) },
	{ SPH_C32(0x16444000), SPH_C32(0xc75d4a21), SPH_C32(0xef06b67b),
	  SPH_C32(0xbd2871b0), SPH_C32(0x06708000), SPH_C32(0x526fda2d),
	  SPH_C32(0x5382c538), SPH_C32(0x4a93e323) },
	{ SPH_C32(0x81174000), SPH_C32(0xe71224f2), SPH_C32(0x98bf5e74),
	  SPH_C32(0x1cc42f71), SPH_C32(0x7809a000), SPH_C32(0xc6773802),
	  SPH_C32(0x35c11760), SPH_C32(0xd6b6b8c6) },
	{ SPH_C32(0xe2080000), SPH_C32(0xd7f9a9ec), SPH_C32(0xe679e16a),
	  SPH_C32(0x635fbdfc), SPH_C32(0x146bc000), SPH_C32(0x097803c5),
	  SPH_C32(0xde780a93), SPH_C32(0x84a52f51) },
	{ SPH_C32(0x755b0000), SPH_C32(0xf7b6c73f), SPH_C32(0x91c00965),
	  SPH_C32(0xc2b3e33d), SPH_C32(0x6a12e000), SPH_C32(0x9d60e1ea),
	  SPH_C32(0xb83bd8cb), SPH_C32(0x188074b4) },
	{ SPH_C32(0xf0134000), SPH_C32(0x8cee7004), SPH_C32(0x6b832ec1),
	  SPH_C32(0xad69718e), SPH_C32(0xf23cc000), SPH_C32(0x42cb39e0),
	  SPH_C32(0x5afd9229), SPH_C32(0x94e42f6f) },
	{ SPH_C32(0x67404000), SPH_C32(0xaca11ed7), SPH_C32(0x1c3ac6ce),
	  SPH_C32(0x0c852f4f), SPH_C32(0x8c45e000), SPH_C32(0xd6d3dbcf),
	  SPH_C32(0x3cbe4071), SPH_C32(0x08c1748a) },
	{ SPH_C32(0xe0278000), SPH_C32(0x19dce008), SPH_C32(0xd7075d82),
	  SPH_C32(0x5ad2e31d), SPH_C32(0xe4788000), SPH_C32(0x859673c1),
	  SPH_C32(0xb5fb2452), SPH_C32(0x29cc5edf) },
	{ SPH_C32(0x77748000), SPH_C32(0x39938edb), SPH_C32(0xa0beb58d),
	  SPH_C32(0xfb3ebddc), SPH_C32(0x9a01a000), SPH_C32(0x118e91ee),
	  SPH_C32(0xd3b8f60a), SPH_C32(0xb5e9053a) },
	{ SPH_C32(0xf23cc000), SPH_C32(0x42cb39e0), SPH_C32(0x5afd9229),
	  SPH_C32(0x94e42f6f), SPH_C32(0x022f8000), SPH_C32(0xce2549e4),
	  SPH_C32(0x317ebce8), SPH_C32(0x398d5ee1) },
	{ SPH_C32(0x656fc000), SPH_C32(0x62845733), SPH_C32(0x2d447a26),
	  SPH_C32(0x350871ae), SPH_C32(0x7c56a000), SPH_C32(0x5a3dabcb),
	  SPH_C32(0x573d6eb0), SPH_C32(0xa5a80504) },
	{ SPH_C32(0x06708000), SPH_C32(0x526fda2d), SPH_C32(0x5382c538),
	  SPH_C32(0x4a93e323), SPH_C32(0x1034c000), SPH_C32(0x9532900c),
	  SPH_C32(0xbc847343), SPH_C32(0xf7bb9293) },
	{ SPH_C32(0x91238000), SPH_C32(0x7220b4fe), SPH_C32(0x243b2d37),
	  SPH_C32(0xeb7fbde2), SPH_C32(0x6e4de000), SPH_C32(0x012a7223),
	  SPH_C32(0xdac7a11b), SPH_C32(0x6b9ec976) },
	{ SPH_C32(0x146bc000), SPH_C32(0x097803c5), SPH_C32(0xde780a93),
	  SPH_C32(0x84a52f51), SPH_C32(0xf663c000), SPH_C32(0xde81aa29),
	  SPH_C32(0x3801ebf9), SPH_C32(0xe7fa92ad) },
	{ SPH_C32(0x8338c000), SPH_C32(0x29376d16), SPH_C32(0xa9c1e29c),
	  SPH_C32(0x25497190), SPH_C32(0x881ae000), SPH_C32(0x4a994806),
	  SPH_C32(0x5e4239a1), SPH_C32(0x7bdfc948) }
};

static const sph_u32 T256_5[32][8] = {
	{ SPH_C32(0x00000000), SPH_C32(0x00000000), SPH_C32(0x00000000),
	  SPH_C32(0x00000000), SPH_C32(0x00000000), SPH_C32(0x00000000),
	  SPH_C32(0x00000000), SPH_C32(0x00000000) },
	{ SPH_C32(0xde320800), SPH_C32(0x288350fe), SPH_C32(0x71852ac7),
	  SPH_C32(0xa6bf9f96), SPH_C32(0xe18b0000), SPH_C32(0x5459887d),
	  SPH_C32(0xbf1283d3), SPH_C32(0x1b666a73) },
	{ SPH_C32(0xe18b0000), SPH_C32(0x5459887d), SPH_C32(0xbf1283d3),
	  SPH_C32(0x1b666a73), SPH_C32(0x3fb90800), SPH_C32(0x7cdad883),
	  SPH_C32(0xce97a914), SPH_C32(0xbdd9f5e5) },
	{ SPH_C32(0x3fb90800), SPH_C32(0x7cdad883), SPH_C32(0xce97a914),
	  SPH_C32(0xbdd9f5e5), SPH_C32(0xde320800), SPH_C32(0x288350fe),
	  SPH_C32(0x71852ac7), SPH_C32(0xa6bf9f96) },
	{ SPH_C32(0x74951000), SPH_C32(0x5a2b467e), SPH_C32(0x88fd1d2b),
	  SPH_C32(0x1ee68292), SPH_C32(0xcba90000), SPH_C32(0x90273769),
	  SPH_C32(0xbbdcf407), SPH_C32(0xd0f4af61) },
	{ SPH_C32(0xaaa71800), SPH_C32(0x72a81680), SPH_C32(0xf97837ec),
	  SPH_C32(0xb8591d04), SPH_C32(0x2a220000), SPH_C32(0xc47ebf14),
	  SPH_C32(0x04ce77d4), SPH_C32(0xcb92c512) },
	{ SPH_C32(0x951e1000), SPH_C32(0x0e72ce03), SPH_C32(0x37ef9ef8),
	  SPH_C32(0x0580e8e1), SPH_C32(0xf4100800), SPH_C32(0xecfdefea),
	  SPH_C32(0x754b5d13), SPH_C32(0x6d2d5a84) },
	{ SPH_C32(0x4b2c1800), SPH_C32(0x26f19efd), SPH_C32(0x466ab43f),
	  SPH_C32(0xa33f7777), SPH_C32(0x159b0800), SPH_C32(0xb8a46797),
	  SPH_C32(0xca59dec0), SPH_C32(0x764b30f7) },
	{ SPH_C32(0xcba90000), SPH_C32(0x90273769), SPH_C32(0xbbdcf407),
	  SPH_C32(0xd0f4af61), SPH_C32(0xbf3c1000), SPH_C32(0xca0c7117),
	  SPH_C32(0x3321e92c), SPH_C32(0xce122df3) },
	{ SPH_C32(0x159b0800), SPH_C32(0xb8a46797), SPH_C32(0xca59dec0),
	  SPH_C32(0x764b30f7), SPH_C32(0x5eb71000), SPH_C32(0x9e55f96a),
	  SPH_C32(0x8c336aff), SPH_C32(0xd5744780) },
	{ SPH_C32(0x2a220000), SPH_C32(0xc47ebf14), SPH_C32(0x04ce77d4),
	  SPH_C32(0xcb92c512), SPH_C32(0x80851800), SPH_C32(0xb6d6a994),
	  SPH_C32(0xfdb64038), SPH_C32(0x73cbd816) },
	{ SPH_C32(0xf4100800), SPH_C32(0xecfdefea), SPH_C32(0x754b5d13),
	  SPH_C32(0x6d2d5a84), SPH_C32(0x610e1800), SPH_C32(0xe28f21e9),
	  SPH_C32(0x42a4c3eb), SPH_C32(0x68adb265) },
	{ SPH_C32(0xbf3c1000), SPH_C32(0xca0c7117), SPH_C32(0x3321e92c),
	  SPH_C32(0xce122df3), SPH_C32(0x74951000), SPH_C32(0x5a2b467e),
	  SPH_C32(0x88fd1d2b), SPH_C32(0x1ee68292) },
	{ SPH_C32(0x610e1800), SPH_C32(0xe28f21e9), SPH_C32(0x42a4c3eb),
	  SPH_C32(0x68adb265), SPH_C32(0x951e1000), SPH_C32(0x0e72ce03),
	  SPH_C32(0x37ef9ef8), SPH_C32(0x0580e8e1) },
	{ SPH_C32(0x5eb71000), SPH_C32(0x9e55f96a), SPH_C32(0x8c336aff),
	  SPH_C32(0xd5744780), SPH_C32(0x4b2c1800), SPH_C32(0x26f19efd),
	  SPH_C32(0x466ab43f), SPH_C32(0xa33f7777) },
	{ SPH_C32(0x80851800), SPH_C32(0xb6d6a994), SPH_C32(0xfdb64038),
	  SPH_C32(0x73cbd816), SPH_C32(0xaaa71800), SPH_C32(0x72a81680),
	  SPH_C32(0xf97837ec), SPH_C32(0xb8591d04) },
	{ SPH_C32(0xe92a2000), SPH_C32(0xb4578cfc), SPH_C32(0x11fa3a57),
	  SPH_C32(0x3dc90524), SPH_C32(0x97530000), SPH_C32(0x204f6ed3),
	  SPH_C32(0x77b9e80f), SPH_C32(0xa1ec5ec1) },
	{ SPH_C32(0x37182800), SPH_C32(0x9cd4dc02), SPH_C32(0x607f1090),
	  SPH_C32(0x9b769ab2), SPH_C32(0x76d80000), SPH_C32(0x7416e6ae),
	  SPH_C32(0xc8ab6bdc), SPH_C32(0xba8a34b2) },
	{ SPH_C32(0x08a12000), SPH_C32(0xe00e0481), SPH_C32(0xaee8b984),
	  SPH_C32(0x26af6f57), SPH_C32(0xa8ea0800), SPH_C32(0x5c95b650),
	  SPH_C32(0xb92e411b), SPH_C32(0x1c35ab24) },
	{ SPH_C32(0xd6932800), SPH_C32(0xc88d547f), SPH_C32(0xdf6d9343),
	  SPH_C32(0x8010f0c1), SPH_C32(0x49610800), SPH_C32(0x08cc3e2d),
	  SPH_C32(0x063cc2c8), SPH_C32(0x0753c157) },
	{ SPH_C32(0x9dbf3000), SPH_C32(0xee7cca82), SPH_C32(0x9907277c),
	  SPH_C32(0x232f87b6), SPH_C32(0x5cfa0000), SPH_C32(0xb06859ba),
	  SPH_C32(0xcc651c08), SPH_C32(0x7118f1a0) },
	{ SPH_C32(0x438d3800), SPH_C32(0xc6ff9a7c), SPH_C32(0xe8820dbb),
	  SPH_C32(0x85901820), SPH_C32(0xbd710000), SPH_C32(0xe431d1c7),
	  SPH_C32(0x73779fdb), SPH_C32(0x6a7e9bd3) },
	{ SPH_C32(0x7c343000), SPH_C32(0xba2542ff), SPH_C32(0x2615a4af),
	  SPH_C32(0x3849edc5), SPH_C32(0x63430800), SPH_C32(0xccb28139),
	  SPH_C32(0x02f2b51c), SPH_C32(0xccc10445) },
	{ SPH_C32(0xa2063800), SPH_C32(0x92a61201), SPH_C32(0x57908e68),
	  SPH_C32(0x9ef67253), SPH_C32(0x82c80800), SPH_C32(0x98eb0944),
	  SPH_C32(0xbde036cf), SPH_C32(0xd7a76e36) },
	{ SPH_C32(0x22832000), SPH_C32(0x2470bb95), SPH_C32(0xaa26ce50),
	  SPH_C32(0xed3daa45), SPH_C32(0x286f1000), SPH_C32(0xea431fc4),
	  SPH_C32(0x44980123), SPH_C32(0x6ffe7332) },
	{ SPH_C32(0xfcb12800), SPH_C32(0x0cf3eb6b), SPH_C32(0xdba3e497),
	  SPH_C32(0x4b8235d3), SPH_C32(0xc9e41000), SPH_C32(0xbe1a97b9),
	  SPH_C32(0xfb8a82f0), SPH_C32(0x74981941) },
	{ SPH_C32(0xc3082000), SPH_C32(0x702933e8), SPH_C32(0x15344d83),
	  SPH_C32(0xf65bc036), SPH_C32(0x17d61800), SPH_C32(0x9699c747),
	  SPH_C32(0x8a0fa837), SPH_C32(0xd22786d7) },
	{ SPH_C32(0x1d3a2800), SPH_C32(0x58aa6316), SPH_C32(0x64b16744),
	  SPH_C32(0x50e45fa0), SPH_C32(0xf65d1800), SPH_C32(0xc2c04f3a),
	  SPH_C32(0x351d2be4), SPH_C32(0xc941eca4) },
	{ SPH_C32(0x56163000), SPH_C32(0x7e5bfdeb), SPH_C32(0x22dbd37b),
	  SPH_C32(0xf3db28d7), SPH_C32(0xe3c61000), SPH_C32(0x7a6428ad),
	  SPH_C32(0xff44f524), SPH_C32(0xbf0adc53) },
	{ SPH_C32(0x88243800), SPH_C32(0x56d8ad15), SPH_C32(0x535ef9bc),
	  SPH_C32(0x5564b741), SPH_C32(0x024d1000), SPH_C32(0x2e3da0d0),
	  SPH_C32(0x405676f7), SPH_C32(0xa46cb620) },
	{ SPH_C32(0xb79d3000), SPH_C32(0x2a027596), SPH_C32(0x9dc950a8),
	  SPH_C32(0xe8bd42a4), SPH_C32(0xdc7f1800), SPH_C32(0x06bef02e),
	  SPH_C32(0x31d35c30), SPH_C32(0x02d329b6) },
	{ SPH_C32(0x69af3800), SPH_C32(0x02812568), SPH_C32(0xec4c7a6f),
	  SPH_C32(0x4e02dd32), SPH_C32(0x3df41800), SPH_C32(0x52e77853),
	  SPH_C32(0x8ec1dfe3), SPH_C32(0x19b543c5) }
};

static const sph_u32 T256_10[32][8] = {
	{ SPH_C32(0x00000000), SPH_C32(0x00000000), SPH_C32(0x00000000),
	  SPH_C32(0x00000000), SPH_C32(0x00000000), SPH_C32(0x00000000),
	  SPH_C32(0x00000000), SPH_C32(0x00000000) },
	{ SPH_C32(0x734c0000), SPH_C32(0x956fa7d6), SPH_C32(0xa29d1297),
	  SPH_C32(0x6ee56854), SPH_C32(0xc4e80100), SPH_C32(0x1f70960e),
	  SPH_C32(0x2714ca3c), SPH_C32(0x88210c30) },
	{ SPH_C32(0xa7b80200), SPH_C32(0x1f128433), SPH_C32(0x60e5f9f2),
	  SPH_C32(0x9e147576), SPH_C32(0xee260000), SPH_C32(0x124b683e),
	  SPH_C32(0x80c2d68f), SPH_C32(0x3bf3ab2c) },
	{ SPH_C32(0xd4f40200), SPH_C32(0x8a7d23e5), SPH_C32(0xc278eb65),
	  SPH_C32(0xf0f11d22), SPH_C32(0x2ace0100), SPH_C32(0x0d3bfe30),
	  SPH_C32(0xa7d61cb3), SPH_C32(0xb3d2a71c) },
	{ SPH_C32(0xee260000), SPH_C32(0x124b683e), SPH_C32(0x80c2d68f),
	  SPH_C32(0x3bf3ab2c), SPH_C32(0x499e0200), SPH_C32(0x0d59ec0d),
	  SPH_C32(0xe0272f7d), SPH_C32(0xa5e7de5a) },
	{ SPH_C32(0x9d6a0000), SPH_C32(0x8724cfe8), SPH_C32(0x225fc418),
	  SPH_C32(0x5516c378), SPH_C32(0x8d760300), SPH_C32(0x12297a03),
	  SPH_C32(0xc733e541), SPH_C32(0x2dc6d26a) },
	{ SPH_C32(0x499e0200), SPH_C32(0x0d59ec0d), SPH_C32(0xe0272f7d),
	  SPH_C32(0xa5e7de5a), SPH_C32(0xa7b80200), SPH_C32(0x1f128433),
	  SPH_C32(0x60e5f9f2), SPH_C32(0x9e147576) },
	{ SPH_C32(0x3ad20200), SPH_C32(0x98364bdb), SPH_C32(0x42ba3dea),
	  SPH_C32(0xcb02b60e), SPH_C32(0x63500300), SPH_C32(0x0062123d),
	  SPH_C32(0x47f133ce), SPH_C32(0x16357946) },
	{ SPH_C32(0x8f3e0400), SPH_C32(0x0d9dc877), SPH_C32(0x6fc548e1),
	  SPH_C32(0x898d2cd6), SPH_C32(0x14bd0000), SPH_C32(0x2fba37ff),
	  SPH_C32(0x6a72e5bb), SPH_C32(0x247febe6) },
	{ SPH_C32(0xfc720400), SPH_C32(0x98f26fa1), SPH_C32(0xcd585a76),
	  SPH_C32(0xe7684482), SPH_C32(0xd0550100), SPH_C32(0x30caa1f1),
	  SPH_C32(0x4d662f87), SPH_C32(0xac5ee7d6) },
	{ SPH_C32(0x28860600), SPH_C32(0x128f4c44), SPH_C32(0x0f20b113),
	  SPH_C32(0x179959a0), SPH_C32(0xfa9b0000), SPH_C32(0x3df15fc1),
	  SPH_C32(0xeab03334), SPH_C32(0x1f8c40ca) },
	{ SPH_C32(0x5bca0600), SPH_C32(0x87e0eb92), SPH_C32(0xadbda384),
	  SPH_C32(0x797c31f4), SPH_C32(0x3e730100), SPH_C32(0x2281c9cf),
	  SPH_C32(0xcda4f908), SPH_C32(0x97ad4cfa) },
	{ SPH_C32(0x61180400), SPH_C32(0x1fd6a049), SPH_C32(0xef079e6e),
	  SPH_C32(0xb27e87fa), SPH_C32(0x5d230200), SPH_C32(0x22e3dbf2),
	  SPH_C32(0x8a55cac6), SPH_C32(0x819835bc) },
	{ SPH_C32(0x12540400), SPH_C32(0x8ab9079f), SPH_C32(0x4d9a8cf9),
	  SPH_C32(0xdc9befae), SPH_C32(0x99cb0300), SPH_C32(0x3d934dfc),
	  SPH_C32(0xad4100fa), SPH_C32(0x09b9398c) },
	{ SPH_C32(0xc6a00600), SPH_C32(0x00c4247a), SPH_C32(0x8fe2679c),
	  SPH_C32(0x2c6af28c), SPH_C32(0xb3050200), SPH_C32(0x30a8b3cc),
	  SPH_C32(0x0a971c49), SPH_C32(0xba6b9e90) },
	{ SPH_C32(0xb5ec0600), SPH_C32(0x95ab83ac), SPH_C32(0x2d7f750b),
	  SPH_C32(0x428f9ad8), SPH_C32(0x77ed0300), SPH_C32(0x2fd825c2),
	  SPH_C32(0x2d83d675), SPH_C32(0x324a92a0) },
	{ SPH_C32(0x14bd0000), SPH_C32(0x2fba37ff), SPH_C32(0x6a72e5bb),
	  SPH_C32(0x247febe6), SPH_C32(0x9b830400), SPH_C32(0x2227ff88),
	  SPH_C32(0x05b7ad5a), SPH_C32(0xadf2c730) },
	{ SPH_C32(0x67f10000), SPH_C32(0xbad59029), SPH_C32(0xc8eff72c),
	  SPH_C32(0x4a9a83b2), SPH_C32(0x5f6b0500), SPH_C32(0x3d576986),
	  SPH_C32(0x22a36766), SPH_C32(0x25d3cb00) },
	{ SPH_C32(0xb3050200), SPH_C32(0x30a8b3cc), SPH_C32(0x0a971c49),
	  SPH_C32(0xba6b9e90), SPH_C32(0x75a50400), SPH_C32(0x306c97b6),
	  SPH_C32(0x85757bd5), SPH_C32(0x96016c1c) },
	{ SPH_C32(0xc0490200), SPH_C32(0xa5c7141a), SPH_C32(0xa80a0ede),
	  SPH_C32(0xd48ef6c4), SPH_C32(0xb14d0500), SPH_C32(0x2f1c01b8),
	  SPH_C32(0xa261b1e9), SPH_C32(0x1e20602c) },
	{ SPH_C32(0xfa9b0000), SPH_C32(0x3df15fc1), SPH_C32(0xeab03334),
	  SPH_C32(0x1f8c40ca), SPH_C32(0xd21d0600), SPH_C32(0x2f7e1385),
	  SPH_C32(0xe5908227), SPH_C32(0x0815196a) },
	{ SPH_C32(0x89d70000), SPH_C32(0xa89ef817), SPH_C32(0x482d21a3),
	  SPH_C32(0x7169289e), SPH_C32(0x16f50700), SPH_C32(0x300e858b),
	  SPH_C32(0xc284481b), SPH_C32(0x8034155a) },
	{ SPH_C32(0x5d230200), SPH_C32(0x22e3dbf2), SPH_C32(0x8a55cac6),
	  SPH_C32(0x819835bc), SPH_C32(0x3c3b0600), SPH_C32(0x3d357bbb),
	  SPH_C32(0x655254a8), SPH_C32(0x33e6b246) },
	{ SPH_C32(0x2e6f0200), SPH_C32(0xb78c7c24), SPH_C32(0x28c8d851),
	  SPH_C32(0xef7d5de8), SPH_C32(0xf8d30700), SPH_C32(0x2245edb5),
	  SPH_C32(0x42469e94), SPH_C32(0xbbc7be76) },
	{ SPH_C32(0x9b830400), SPH_C32(0x2227ff88), SPH_C32(0x05b7ad5a),
	  SPH_C32(0xadf2c730), SPH_C32(0x8f3e0400), SPH_C32(0x0d9dc877),
	  SPH_C32(0x6fc548e1), SPH_C32(0x898d2cd6) },
	{ SPH_C32(0xe8cf0400), SPH_C32(0xb748585e), SPH_C32(0xa72abfcd),
	  SPH_C32(0xc317af64), SPH_C32(0x4bd60500), SPH_C32(0x12ed5e79),
	  SPH_C32(0x48d182dd), SPH_C32(0x01ac20e6) },
	{ SPH_C32(0x3c3b0600), SPH_C32(0x3d357bbb), SPH_C32(0x655254a8),
	  SPH_C32(0x33e6b246), SPH_C32(0x61180400), SPH_C32(0x1fd6a049),
	  SPH_C32(0xef079e6e), SPH_C32(0xb27e87fa) },
	{ SPH_C32(0x4f770600), SPH_C32(0xa85adc6d), SPH_C32(0xc7cf463f),
	  SPH_C32(0x5d03da12), SPH_C32(0xa5f00500), SPH_C32(0x00a63647),
	  SPH_C32(0xc8135452), SPH_C32(0x3a5f8bca) },
	{ SPH_C32(0x75a50400), SPH_C32(0x306c97b6), SPH_C32(0x85757bd5),
	  SPH_C32(0x96016c1c), SPH_C32(0xc6a00600), SPH_C32(0x00c4247a),
	  SPH_C32(0x8fe2679c), SPH_C32(0x2c6af28c) },
	{ SPH_C32(0x06e90400), SPH_C32(0xa5033060), SPH_C32(0x27e86942),
	  SPH_C32(0xf8e40448), SPH_C32(0x02480700), SPH_C32(0x1fb4b274),
	  SPH_C32(0xa8f6ada0), SPH_C32(0xa44bfebc) },
	{ SPH_C32(0xd21d0600), SPH_C32(0x2f7e1385), SPH_C32(0xe5908227),
	  SPH_C32(0x0815196a), SPH_C32(0x28860600), SPH_C32(0x128f4c44),
	  SPH_C32(0x0f20b113), SPH_C32(0x179959a0) },
	{ SPH_C32(0xa1510600), SPH_C32(0xba11b453), SPH_C32(0x470d90b0),
	  SPH_C32(0x66f0713e), SPH_C32(0xec6e0700), SPH_C32(0x0dffda4a),
	  SPH_C32(0x28347b2f), SPH_C32(0x9fb85590) }
};

static const sph_u32 T256_15[32][8] = {
	{ SPH_C32(0x00000000), SPH_C32(0x00000000), SPH_C32(0x00000000),
	  SPH_C32(0x00000000), SPH_C32(0x00000000), SPH_C32(0x00000000),
	  SPH_C32(0x00000000), SPH_C32(0x00000000) },
	{ SPH_C32(0x4dce0040), SPH_C32(0x3b5bec7e), SPH_C32(0x36656ba8),
	  SPH_C32(0x23633a05), SPH_C32(0x78ab0000), SPH_C32(0xa0cd5a34),
	  SPH_C32(0x5d5ca0f7), SPH_C32(0x727784cb) },
	{ SPH_C32(0x78ab0000), SPH_C32(0xa0cd5a34), SPH_C32(0x5d5ca0f7),
	  SPH_C32(0x727784cb), SPH_C32(0x35650040), SPH_C32(0x9b96b64a),
	  SPH_C32(0x6b39cb5f), SPH_C32(0x5114bece) },
	{ SPH_C32(0x35650040), SPH_C32(0x9b96b64a), SPH_C32(0x6b39cb5f),
	  SPH_C32(0x5114bece), SPH_C32(0x4dce0040), SPH_C32(0x3b5bec7e),
	  SPH_C32(0x36656ba8), SPH_C32(0x23633a05) },
	{ SPH_C32(0x5bd20080), SPH_C32(0x450f18ec), SPH_C32(0xc2c46c55),
	  SPH_C32(0xf362b233), SPH_C32(0x39a60000), SPH_C32(0x4ab753eb),
	  SPH_C32(0xd14e094b), SPH_C32(0xb772b42b) },
	{ SPH_C32(0x161c00c0), SPH_C32(0x7e54f492), SPH_C32(0xf4a107fd),
	  SPH_C32(0xd0018836), SPH_C32(0x410d0000), SPH_C32(0xea7a09df),
	  SPH_C32(0x8c12a9bc), SPH_C32(0xc50530e0) },
	{ SPH_C32(0x23790080), SPH_C32(0xe5c242d8), SPH_C32(0x9f98cca2),
	  SPH_C32(0x811536f8), SPH_C32(0x0cc30040), SPH_C32(0xd121e5a1),
	  SPH_C32(0xba77c214), SPH_C32(0xe6660ae5) },
	{ SPH_C32(0x6eb700c0), SPH_C32(0xde99aea6), SPH_C32(0xa9fda70a),
	  SPH_C32(0xa2760cfd), SPH_C32(0x74680040), SPH_C32(0x71ecbf95),
	  SPH_C32(0xe72b62e3), SPH_C32(0x94118e2e) },
	{ SPH_C32(0x39a60000), SPH_C32(0x4ab753eb), SPH_C32(0xd14e094b),
	  SPH_C32(0xb772b42b), SPH_C32(0x62740080), SPH_C32(0x0fb84b07),
	  SPH_C32(0x138a651e), SPH_C32(0x44100618) },
	{ SPH_C32(0x74680040), SPH_C32(0x71ecbf95), SPH_C32(0xe72b62e3),
	  SPH_C32(0x94118e2e), SPH_C32(0x1adf0080), SPH_C32(0xaf751133),
	  SPH_C32(0x4ed6c5e9), SPH_C32(0x366782d3) },
	{ SPH_C32(0x410d0000), SPH_C32(0xea7a09df), SPH_C32(0x8c12a9bc),
	  SPH_C32(0xc50530e0), SPH_C32(0x571100c0), SPH_C32(0x942efd4d),
	  SPH_C32(0x78b3ae41), SPH_C32(0x1504b8d6) },
	{ SPH_C32(0x0cc30040), SPH_C32(0xd121e5a1), SPH_C32(0xba77c214),
	  SPH_C32(0xe6660ae5), SPH_C32(0x2fba00c0), SPH_C32(0x34e3a779),
	  SPH_C32(0x25ef0eb6), SPH_C32(0x67733c1d) },
	{ SPH_C32(0x62740080), SPH_C32(0x0fb84b07), SPH_C32(0x138a651e),
	  SPH_C32(0x44100618), SPH_C32(0x5bd20080), SPH_C32(0x450f18ec),
	  SPH_C32(0xc2c46c55), SPH_C32(0xf362b233) },
	{ SPH_C32(0x2fba00c0), SPH_C32(0x34e3a779), SPH_C32(0x25ef0eb6),
	  SPH_C32(0x67733c1d), SPH_C32(0x23790080), SPH_C32(0xe5c242d8),
	  SPH_C32(0x9f98cca2), SPH_C32(0x811536f8) },
	{ SPH_C32(0x1adf0080), SPH_C32(0xaf751133), SPH_C32(0x4ed6c5e9),
	  SPH_C32(0x366782d3), SPH_C32(0x6eb700c0), SPH_C32(0xde99aea6),
	  SPH_C32(0xa9fda70a), SPH_C32(0xa2760cfd) },
	{ SPH_C32(0x571100c0), SPH_C32(0x942efd4d), SPH_C32(0x78b3ae41),
	  SPH_C32(0x1504b8d6), SPH_C32(0x161c00c0), SPH_C32(0x7e54f492),
	  SPH_C32(0xf4a107fd), SPH_C32(0xd0018836) },
	{ SPH_C32(0xb7a40100), SPH_C32(0x8a1f31d8), SPH_C32(0x8589d8ab),
	  SPH_C32(0xe6c46464), SPH_C32(0x734c0000), SPH_C32(0x956fa7d6),
	  SPH_C32(0xa29d1297), SPH_C32(0x6ee56854) },
	{ SPH_C32(0xfa6a0140), SPH_C32(0xb144dda6), SPH_C32(0xb3ecb303),
	  SPH_C32(0xc5a75e61), SPH_C32(0x0be70000), SPH_C32(0x35a2fde2),
	  SPH_C32(0xffc1b260), SPH_C32(0x1c92ec9f) },
	{ SPH_C32(0xcf0f0100), SPH_C32(0x2ad26bec), SPH_C32(0xd8d5785c),
	  SPH_C32(0x94b3e0af), SPH_C32(0x46290040), SPH_C32(0x0ef9119c),
	  SPH_C32(0xc9a4d9c8), SPH_C32(0x3ff1d69a) },
	{ SPH_C32(0x82c10140), SPH_C32(0x11898792), SPH_C32(0xeeb013f4),
	  SPH_C32(0xb7d0daaa), SPH_C32(0x3e820040), SPH_C32(0xae344ba8),
	  SPH_C32(0x94f8793f), SPH_C32(0x4d865251) },
	{ SPH_C32(0xec760180), SPH_C32(0xcf102934), SPH_C32(0x474db4fe),
	  SPH_C32(0x15a6d657), SPH_C32(0x4aea0000), SPH_C32(0xdfd8f43d),
	  SPH_C32(0x73d31bdc), SPH_C32(0xd997dc7f) },
	{ SPH_C32(0xa1b801c0), SPH_C32(0xf44bc54a), SPH_C32(0x7128df56),
	  SPH_C32(0x36c5ec52), SPH_C32(0x32410000), SPH_C32(0x7f15ae09),
	  SPH_C32(0x2e8fbb2b), SPH_C32(0xabe058b4) },
	{ SPH_C32(0x94dd0180), SPH_C32(0x6fdd7300), SPH_C32(0x1a111409),
	  SPH_C32(0x67d1529c), SPH_C32(0x7f8f0040), SPH_C32(0x444e4277),
	  SPH_C32(0x18ead083), SPH_C32(0x888362b1) },
	{ SPH_C32(0xd91301c0), SPH_C32(0x54869f7e), SPH_C32(0x2c747fa1),
	  SPH_C32(0x44b26899), SPH_C32(0x07240040), SPH_C32(0xe4831843),
	  SPH_C32(0x45b67074), SPH_C32(0xfaf4e67a) },
	{ SPH_C32(0x8e020100), SPH_C32(0xc0a86233), SPH_C32(0x54c7d1e0),
	  SPH_C32(0x51b6d04f), SPH_C32(0x11380080), SPH_C32(0x9ad7ecd1),
	  SPH_C32(0xb1177789), SPH_C32(0x2af56e4c) },
	{ SPH_C32(0xc3cc0140), SPH_C32(0xfbf38e4d), SPH_C32(0x62a2ba48),
	  SPH_C32(0x72d5ea4a), SPH_C32(0x69930080), SPH_C32(0x3a1ab6e5),
	  SPH_C32(0xec4bd77e), SPH_C32(0x5882ea87) },
	{ SPH_C32(0xf6a90100), SPH_C32(0x60653807), SPH_C32(0x099b7117),
	  SPH_C32(0x23c15484), SPH_C32(0x245d00c0), SPH_C32(0x01415a9b),
	  SPH_C32(0xda2ebcd6), SPH_C32(0x7be1d082) },
	{ SPH_C32(0xbb670140), SPH_C32(0x5b3ed479), SPH_C32(0x3ffe1abf),
	  SPH_C32(0x00a26e81), SPH_C32(0x5cf600c0), SPH_C32(0xa18c00af),
	  SPH_C32(0x87721c21), SPH_C32(0x09965449) },
	{ SPH_C32(0xd5d00180), SPH_C32(0x85a77adf), SPH_C32(0x9603bdb5),
	  SPH_C32(0xa2d4627c), SPH_C32(0x289e0080), SPH_C32(0xd060bf3a),
	  SPH_C32(0x60597ec2), SPH_C32(0x9d87da67) },
	{ SPH_C32(0x981e01c0), SPH_C32(0xbefc96a1), SPH_C32(0xa066d61d),
	  SPH_C32(0x81b75879), SPH_C32(0x50350080), SPH_C32(0x70ade50e),
	  SPH_C32(0x3d05de35), SPH_C32(0xeff05eac) },
	{ SPH_C32(0xad7b0180), SPH_C32(0x256a20eb), SPH_C32(0xcb5f1d42),
	  SPH_C32(0xd0a3e6b7), SPH_C32(0x1dfb00c0), SPH_C32(0x4bf60970),
	  SPH_C32(0x0b60b59d), SPH_C32(0xcc9364a9) },
	{ SPH_C32(0xe0b501c0), SPH_C32(0x1e31cc95), SPH_C32(0xfd3a76ea),
	  SPH_C32(0xf3c0dcb2), SPH_C32(0x655000c0), SPH_C32(0xeb3b5344),
	  SPH_C32(0x563c156a), SPH_C32(0xbee4e062) }
};

static const sph_u32 T256_20[32][8] = {
	{ SPH_C32(0x00000000), SPH_C32(0x00000000), SPH_C32(0x00000000),
	  SPH_C32(0x00000000), SPH_C32(0x00000000), SPH_C32(0x00000000),
	  SPH_C32(0x00000000), SPH_C32(0x00000000) },
	{ SPH_C32(0x171c0000), SPH_C32(0xb26e3344), SPH_C32(0x9e6a837e),
	  SPH_C32(0x58f8485f), SPH_C32(0xbfb20008), SPH_C32(0x92170a39),
	  SPH_C32(0x6019107f), SPH_C32(0xe051606e) },
	{ SPH_C32(0x515c0010), SPH_C32(0x40f372fb), SPH_C32(0xfce72602),
	  SPH_C32(0x71575061), SPH_C32(0x2e390000), SPH_C32(0x64dd6689),
	  SPH_C32(0x3cd406fc), SPH_C32(0xb1f490bc) },
	{ SPH_C32(0x46400010), SPH_C32(0xf29d41bf), SPH_C32(0x628da57c),
	  SPH_C32(0x29af183e), SPH_C32(0x918b0008), SPH_C32(0xf6ca6cb0),
	  SPH_C32(0x5ccd1683), SPH_C32(0x51a5f0d2) },
	{ SPH_C32(0x2e390000), SPH_C32(0x64dd6689), SPH_C32(0x3cd406fc),
	  SPH_C32(0xb1f490bc), SPH_C32(0x7f650010), SPH_C32(0x242e1472),
	  SPH_C32(0xc03320fe), SPH_C32(0xc0a3c0dd) },
	{ SPH_C32(0x39250000), SPH_C32(0xd6b355cd), SPH_C32(0xa2be8582),
	  SPH_C32(0xe90cd8e3), SPH_C32(0xc0d70018), SPH_C32(0xb6391e4b),
	  SPH_C32(0xa02a3081), SPH_C32(0x20f2a0b3) },
	{ SPH_C32(0x7f650010), SPH_C32(0x242e1472), SPH_C32(0xc03320fe),
	  SPH_C32(0xc0a3c0dd), SPH_C32(0x515c0010), SPH_C32(0x40f372fb),
	  SPH_C32(0xfce72602), SPH_C32(0x71575061) },
	{ SPH_C32(0x68790010), SPH_C32(0x96402736), SPH_C32(0x5e59a380),
	  SPH_C32(0x985b8882), SPH_C32(0xeeee0018), SPH_C32(0xd2e478c2),
	  SPH_C32(0x9cfe367d), SPH_C32(0x9106300f) },
	{ SPH_C32(0xa2b80020), SPH_C32(0x81e7e5f6), SPH_C32(0xf9ce4c04),
	  SPH_C32(0xe2afa0c0), SPH_C32(0x5c720000), SPH_C32(0xc9bacd12),
	  SPH_C32(0x79a90df9), SPH_C32(0x63e92178) },
	{ SPH_C32(0xb5a40020), SPH_C32(0x3389d6b2), SPH_C32(0x67a4cf7a),
	  SPH_C32(0xba57e89f), SPH_C32(0xe3c00008), SPH_C32(0x5badc72b),
	  SPH_C32(0x19b01d86), SPH_C32(0x83b84116) },
	{ SPH_C32(0xf3e40030), SPH_C32(0xc114970d), SPH_C32(0x05296a06),
	  SPH_C32(0x93f8f0a1), SPH_C32(0x724b0000), SPH_C32(0xad67ab9b),
	  SPH_C32(0x457d0b05), SPH_C32(0xd21db1c4) },
	{ SPH_C32(0xe4f80030), SPH_C32(0x737aa449), SPH_C32(0x9b43e978),
	  SPH_C32(0xcb00b8fe), SPH_C32(0xcdf90008), SPH_C32(0x3f70a1a2),
	  SPH_C32(0x25641b7a), SPH_C32(0x324cd1aa) },
	{ SPH_C32(0x8c810020), SPH_C32(0xe53a837f), SPH_C32(0xc51a4af8),
	  SPH_C32(0x535b307c), SPH_C32(0x23170010), SPH_C32(0xed94d960),
	  SPH_C32(0xb99a2d07), SPH_C32(0xa34ae1a5) },
	{ SPH_C32(0x9b9d0020), SPH_C32(0x5754b03b), SPH_C32(0x5b70c986),
	  SPH_C32(0x0ba37823), SPH_C32(0x9ca50018), SPH_C32(0x7f83d359),
	  SPH_C32(0xd9833d78), SPH_C32(0x431b81cb) },
	{ SPH_C32(0xdddd0030), SPH_C32(0xa5c9f184), SPH_C32(0x39fd6cfa),
	  SPH_C32(0x220c601d), SPH_C32(0x0d2e0010), SPH_C32(0x8949bfe9),
	  SPH_C32(0x854e2bfb), SPH_C32(0x12be7119) },
	{ SPH_C32(0xcac10030), SPH_C32(0x17a7c2c0), SPH_C32(0xa797ef84),
	  SPH_C32(0x7af42842), SPH_C32(0xb29c0018), SPH_C32(0x1b5eb5d0),
	  SPH_C32(0xe5573b84), SPH_C32(0xf2ef1177) },
	{ SPH_C32(0x5c720000), SPH_C32(0xc9bacd12), SPH_C32(0x79a90df9),
	  SPH_C32(0x63e92178), SPH_C32(0xfeca0020), SPH_C32(0x485d28e4),
	  SPH_C32(0x806741fd), SPH_C32(0x814681b8) },
	{ SPH_C32(0x4b6e0000), SPH_C32(0x7bd4fe56), SPH_C32(0xe7c38e87),
	  SPH_C32(0x3b116927), SPH_C32(0x41780028), SPH_C32(0xda4a22dd),
	  SPH_C32(0xe07e5182), SPH_C32(0x6117e1d6) },
	{ SPH_C32(0x0d2e0010), SPH_C32(0x8949bfe9), SPH_C32(0x854e2bfb),
	  SPH_C32(0x12be7119), SPH_C32(0xd0f30020), SPH_C32(0x2c804e6d),
	  SPH_C32(0xbcb34701), SPH_C32(0x30b21104) },
	{ SPH_C32(0x1a320010), SPH_C32(0x3b278cad), SPH_C32(0x1b24a885),
	  SPH_C32(0x4a463946), SPH_C32(0x6f410028), SPH_C32(0xbe974454),
	  SPH_C32(0xdcaa577e), SPH_C32(0xd0e3716a) },
	{ SPH_C32(0x724b0000), SPH_C32(0xad67ab9b), SPH_C32(0x457d0b05),
	  SPH_C32(0xd21db1c4), SPH_C32(0x81af0030), SPH_C32(0x6c733c96),
	  SPH_C32(0x40546103), SPH_C32(0x41e54165) },
	{ SPH_C32(0x65570000), SPH_C32(0x1f0998df), SPH_C32(0xdb17887b),
	  SPH_C32(0x8ae5f99b), SPH_C32(0x3e1d0038), SPH_C32(0xfe6436af),
	  SPH_C32(0x204d717c), SPH_C32(0xa1b4210b) },
	{ SPH_C32(0x23170010), SPH_C32(0xed94d960), SPH_C32(0xb99a2d07),
	  SPH_C32(0xa34ae1a5), SPH_C32(0xaf960030), SPH_C32(0x08ae5a1f),
	  SPH_C32(0x7c8067ff), SPH_C32(0xf011d1d9) },
	{ SPH_C32(0x340b0010), SPH_C32(0x5ffaea24), SPH_C32(0x27f0ae79),
	  SPH_C32(0xfbb2a9fa), SPH_C32(0x10240038), SPH_C32(0x9ab95026),
	  SPH_C32(0x1c997780), SPH_C32(0x1040b1b7) },
	{ SPH_C32(0xfeca0020), SPH_C32(0x485d28e4), SPH_C32(0x806741fd),
	  SPH_C32(0x814681b8), SPH_C32(0xa2b80020), SPH_C32(0x81e7e5f6),
	  SPH_C32(0xf9ce4c04), SPH_C32(0xe2afa0c0) },
	{ SPH_C32(0xe9d60020), SPH_C32(0xfa331ba0), SPH_C32(0x1e0dc283),
	  SPH_C32(0xd9bec9e7), SPH_C32(0x1d0a0028), SPH_C32(0x13f0efcf),
	  SPH_C32(0x99d75c7b), SPH_C32(0x02fec0ae) },
	{ SPH_C32(0xaf960030), SPH_C32(0x08ae5a1f), SPH_C32(0x7c8067ff),
	  SPH_C32(0xf011d1d9), SPH_C32(0x8c810020), SPH_C32(0xe53a837f),
	  SPH_C32(0xc51a4af8), SPH_C32(0x535b307c) },
	{ SPH_C32(0xb88a0030), SPH_C32(0xbac0695b), SPH_C32(0xe2eae481),
	  SPH_C32(0xa8e99986), SPH_C32(0x33330028), SPH_C32(0x772d8946),
	  SPH_C32(0xa5035a87), SPH_C32(0xb30a5012) },
	{ SPH_C32(0xd0f30020), SPH_C32(0x2c804e6d), SPH_C32(0xbcb34701),
	  SPH_C32(0x30b21104), SPH_C32(0xdddd0030), SPH_C32(0xa5c9f184),
	  SPH_C32(0x39fd6cfa), SPH_C32(0x220c601d) },
	{ SPH_C32(0xc7ef0020), SPH_C32(0x9eee7d29), SPH_C32(0x22d9c47f),
	  SPH_C32(0x684a595b), SPH_C32(0x626f0038), SPH_C32(0x37defbbd),
	  SPH_C32(0x59e47c85), SPH_C32(0xc25d0073) },
	{ SPH_C32(0x81af0030), SPH_C32(0x6c733c96), SPH_C32(0x40546103),
	  SPH_C32(0x41e54165), SPH_C32(0xf3e40030), SPH_C32(0xc114970d),
	  SPH_C32(0x05296a06), SPH_C32(0x93f8f0a1) },
	{ SPH_C32(0x96b30030), SPH_C32(0xde1d0fd2), SPH_C32(0xde3ee27d),
	  SPH_C32(0x191d093a), SPH_C32(0x4c560038), SPH_C32(0x53039d34),
	  SPH_C32(0x65307a79), SPH_C32(0x73a990cf) }
};

static const sph_u32 T256_25[32][8] = {
	{ SPH_C32(0x00000000), SPH_C32(0x00000000), SPH_C32(0x00000000),
	  SPH_C32(0x00000000), SPH_C32(0x00000000), SPH_C32(0x00000000),
	  SPH_C32(0x00000000), SPH_C32(0x00000000) },
	{ SPH_C32(0x88230002), SPH_C32(0x5fe7a7b3), SPH_C32(0x99e585aa),
	  SPH_C32(0x8d75f7f1), SPH_C32(0x51ac0000), SPH_C32(0x25e30f14),
	  SPH_C32(0x79e22a4c), SPH_C32(0x1298bd46) },
	{ SPH_C32(0x51ac0000), SPH_C32(0x25e30f14), SPH_C32(0x79e22a4c),
	  SPH_C32(0x1298bd46), SPH_C32(0xd98f0002), SPH_C32(0x7a04a8a7),
	  SPH_C32(0xe007afe6), SPH_C32(0x9fed4ab7) },
	{ SPH_C32(0xd98f0002), SPH_C32(0x7a04a8a7), SPH_C32(0xe007afe6),
	  SPH_C32(0x9fed4ab7), SPH_C32(0x88230002), SPH_C32(0x5fe7a7b3),
	  SPH_C32(0x99e585aa), SPH_C32(0x8d75f7f1) },
	{ SPH_C32(0xd0080004), SPH_C32(0x8c768f77), SPH_C32(0x9dc5b050),
	  SPH_C32(0xaf4a29da), SPH_C32(0x6ba90000), SPH_C32(0x40ebf9aa),
	  SPH_C32(0x98321c3d), SPH_C32(0x76acc733) },
	{ SPH_C32(0x582b0006), SPH_C32(0xd39128c4), SPH_C32(0x042035fa),
	  SPH_C32(0x223fde2b), SPH_C32(0x3a050000), SPH_C32(0x6508f6be),
	  SPH_C32(0xe1d03671), SPH_C32(0x64347a75) },
	{ SPH_C32(0x81a40004), SPH_C32(0xa9958063), SPH_C32(0xe4279a1c),
	  SPH_C32(0xbdd2949c), SPH_C32(0xb2260002), SPH_C32(0x3aef510d),
	  SPH_C32(0x7835b3db), SPH_C32(0xe9418d84) },
	{ SPH_C32(0x09870006), SPH_C32(0xf67227d0), SPH_C32(0x7dc21fb6),
	  SPH_C32(0x30a7636d), SPH_C32(0xe38a0002), SPH_C32(0x1f0c5e19),
	  SPH_C32(0x01d79997), SPH_C32(0xfbd930c2) },
	{ SPH_C32(0x6ba90000), SPH_C32(0x40ebf9aa), SPH_C32(0x98321c3d),
	  SPH_C32(0x76acc733), SPH_C32(0xbba10004), SPH_C32(0xcc9d76dd),
	  SPH_C32(0x05f7ac6d), SPH_C32(0xd9e6eee9) },
	{ SPH_C32(0xe38a0002), SPH_C32(0x1f0c5e19), SPH_C32(0x01d79997),
	  SPH_C32(0xfbd930c2), SPH_C32(0xea0d0004), SPH_C32(0xe97e79c9),
	  SPH_C32(0x7c158621), SPH_C32(0xcb7e53af) },
	{ SPH_C32(0x3a050000), SPH_C32(0x6508f6be), SPH_C32(0xe1d03671),
	  SPH_C32(0x64347a75), SPH_C32(0x622e0006), SPH_C32(0xb699de7a),
	  SPH_C32(0xe5f0038b), SPH_C32(0x460ba45e) },
	{ SPH_C32(0xb2260002), SPH_C32(0x3aef510d), SPH_C32(0x7835b3db),
	  SPH_C32(0xe9418d84), SPH_C32(0x33820006), SPH_C32(0x937ad16e),
	  SPH_C32(0x9c1229c7), SPH_C32(0x54931918) },
	{ SPH_C32(0xbba10004), SPH_C32(0xcc9d76dd), SPH_C32(0x05f7ac6d),
	  SPH_C32(0xd9e6eee9), SPH_C32(0xd0080004), SPH_C32(0x8c768f77),
	  SPH_C32(0x9dc5b050), SPH_C32(0xaf4a29da) },
	{ SPH_C32(0x33820006), SPH_C32(0x937ad16e), SPH_C32(0x9c1229c7),
	  SPH_C32(0x54931918), SPH_C32(0x81a40004), SPH_C32(0xa9958063),
	  SPH_C32(0xe4279a1c), SPH_C32(0xbdd2949c) },
	{ SPH_C32(0xea0d0004), SPH_C32(0xe97e79c9), SPH_C32(0x7c158621),
	  SPH_C32(0xcb7e53af), SPH_C32(0x09870006), SPH_C32(0xf67227d0),
	  SPH_C32(0x7dc21fb6), SPH_C32(0x30a7636d) },
	{ SPH_C32(0x622e0006), SPH_C32(0xb699de7a), SPH_C32(0xe5f0038b),
	  SPH_C32(0x460ba45e), SPH_C32(0x582b0006), SPH_C32(0xd39128c4),
	  SPH_C32(0x042035fa), SPH_C32(0x223fde2b) },
	{ SPH_C32(0xa8ae0008), SPH_C32(0x2079397d), SPH_C32(0xfe739301),
	  SPH_C32(0xb8a92831), SPH_C32(0x171c0000), SPH_C32(0xb26e3344),
	  SPH_C32(0x9e6a837e), SPH_C32(0x58f8485f) },
	{ SPH_C32(0x208d000a), SPH_C32(0x7f9e9ece), SPH_C32(0x679616ab),
	  SPH_C32(0x35dcdfc0), SPH_C32(0x46b00000), SPH_C32(0x978d3c50),
	  SPH_C32(0xe788a932), SPH_C32(0x4a60f519) },
	{ SPH_C32(0xf9020008), SPH_C32(0x059a3669), SPH_C32(0x8791b94d),
	  SPH_C32(0xaa319577), SPH_C32(0xce930002), SPH_C32(0xc86a9be3),
	  SPH_C32(0x7e6d2c98), SPH_C32(0xc71502e8) },
	{ SPH_C32(0x7121000a), SPH_C32(0x5a7d91da), SPH_C32(0x1e743ce7),
	  SPH_C32(0x27446286), SPH_C32(0x9f3f0002), SPH_C32(0xed8994f7),
	  SPH_C32(0x078f06d4), SPH_C32(0xd58dbfae) },
	{ SPH_C32(0x78a6000c), SPH_C32(0xac0fb60a), SPH_C32(0x63b62351),
	  SPH_C32(0x17e301eb), SPH_C32(0x7cb50000), SPH_C32(0xf285caee),
	  SPH_C32(0x06589f43), SPH_C32(0x2e548f6c) },
	{ SPH_C32(0xf085000e), SPH_C32(0xf3e811b9), SPH_C32(0xfa53a6fb),
	  SPH_C32(0x9a96f61a), SPH_C32(0x2d190000), SPH_C32(0xd766c5fa),
	  SPH_C32(0x7fbab50f), SPH_C32(0x3ccc322a) },
	{ SPH_C32(0x290a000c), SPH_C32(0x89ecb91e), SPH_C32(0x1a54091d),
	  SPH_C32(0x057bbcad), SPH_C32(0xa53a0002), SPH_C32(0x88816249),
	  SPH_C32(0xe65f30a5), SPH_C32(0xb1b9c5db) },
	{ SPH_C32(0xa129000e), SPH_C32(0xd60b1ead), SPH_C32(0x83b18cb7),
	  SPH_C32(0x880e4b5c), SPH_C32(0xf4960002), SPH_C32(0xad626d5d),
	  SPH_C32(0x9fbd1ae9), SPH_C32(0xa321789d) },
	{ SPH_C32(0xc3070008), SPH_C32(0x6092c0d7), SPH_C32(0x66418f3c),
	  SPH_C32(0xce05ef02), SPH_C32(0xacbd0004), SPH_C32(0x7ef34599),
	  SPH_C32(0x9b9d2f13), SPH_C32(0x811ea6b6) },
	{ SPH_C32(0x4b24000a), SPH_C32(0x3f756764), SPH_C32(0xffa40a96),
	  SPH_C32(0x437018f3), SPH_C32(0xfd110004), SPH_C32(0x5b104a8d),
	  SPH_C32(0xe27f055f), SPH_C32(0x93861bf0) },
	{ SPH_C32(0x92ab0008), SPH_C32(0x4571cfc3), SPH_C32(0x1fa3a570),
	  SPH_C32(0xdc9d5244), SPH_C32(0x75320006), SPH_C32(0x04f7ed3e),
	  SPH_C32(0x7b9a80f5), SPH_C32(0x1ef3ec01) },
	{ SPH_C32(0x1a88000a), SPH_C32(0x1a966870), SPH_C32(0x864620da),
	  SPH_C32(0x51e8a5b5), SPH_C32(0x249e0006), SPH_C32(0x2114e22a),
	  SPH_C32(0x0278aab9), SPH_C32(0x0c6b5147) },
	{ SPH_C32(0x130f000c), SPH_C32(0xece44fa0), SPH_C32(0xfb843f6c),
	  SPH_C32(0x614fc6d8), SPH_C32(0xc7140004), SPH_C32(0x3e18bc33),
	  SPH_C32(0x03af332e), SPH_C32(0xf7b26185) },
	{ SPH_C32(0x9b2c000e), SPH_C32(0xb303e813), SPH_C32(0x6261bac6),
	  SPH_C32(0xec3a3129), SPH_C32(0x96b80004), SPH_C32(0x1bfbb327),
	  SPH_C32(0x7a4d1962), SPH_C32(0xe52adcc3) },
	{ SPH_C32(0x42a3000c), SPH_C32(0xc90740b4), SPH_C32(0x82661520),
	  SPH_C32(0x73d77b9e), SPH_C32(0x1e9b0006), SPH_C32(0x441c1494),
	  SPH_C32(0xe3a89cc8), SPH_C32(0x685f2b32) },
	{ SPH_C32(0xca80000e), SPH_C32(0x96e0e707), SPH_C32(0x1b83908a),
	  SPH_C32(0xfea28c6f), SPH_C32(0x4f370006), SPH_C32(0x61ff1b80),
	  SPH_C32(0x9a4ab684), SPH_C32(0x7ac79674) }
};

static const sph_u32 T256_30[4][8] = {
	{ SPH_C32(0x00000000), SPH_C32(0x00000000), SPH_C32(0x00000000),
	  SPH_C32(0x00000000), SPH_C32(0x00000000), SPH_C32(0x00000000),
	  SPH_C32(0x00000000), SPH_C32(0x00000000) },
	{ SPH_C32(0xc04e0001), SPH_C32(0x33b9c010), SPH_C32(0xae0ebb05),
	  SPH_C32(0xb5a4c63b), SPH_C32(0xc8f10000), SPH_C32(0x0b2de782),
	  SPH_C32(0x6bf648a4), SPH_C32(0x539cbdbf) },
	{ SPH_C32(0xc8f10000), SPH_C32(0x0b2de782), SPH_C32(0x6bf648a4),
	  SPH_C32(0x539cbdbf), SPH_C32(0x08bf0001), SPH_C32(0x38942792),
	  SPH_C32(0xc5f8f3a1), SPH_C32(0xe6387b84) },
	{ SPH_C32(0x08bf0001), SPH_C32(0x38942792), SPH_C32(0xc5f8f3a1),
	  SPH_C32(0xe6387b84), SPH_C32(0xc04e0001), SPH_C32(0x33b9c010),
	  SPH_C32(0xae0ebb05), SPH_C32(0xb5a4c63b) }
};

#define INPUT_SMALL   do { \
		unsigned acc = buf[0]; \
		const sph_u32 *rp; \
		rp = &T256_0[acc >> 3][0]; \
		m0 = rp[0]; \
		m1 = rp[1]; \
		m2 = rp[2]; \
		m3 = rp[3]; \
		m4 = rp[4]; \
		m5 = rp[5]; \
		m6 = rp[6]; \
		m7 = rp[7]; \
		acc = (acc << 8) | buf[1]; \
		rp = &T256_5[(acc >> 6) & 0x1f][0]; \
		m0 ^= rp[0]; \
		m1 ^= rp[1]; \
		m2 ^= rp[2]; \
		m3 ^= rp[3]; \
		m4 ^= rp[4]; \
		m5 ^= rp[5]; \
		m6 ^= rp[6]; \
		m7 ^= rp[7]; \
		rp = &T256_10[(acc >> 1) & 0x1f][0]; \
		m0 ^= rp[0]; \
		m1 ^= rp[1]; \
		m2 ^= rp[2]; \
		m3 ^= rp[3]; \
		m4 ^= rp[4]; \
		m5 ^= rp[5]; \
		m6 ^= rp[6]; \
		m7 ^= rp[7]; \
		acc = (acc << 8) | buf[2]; \
		rp = &T256_15[(acc >> 4) & 0x1f][0]; \
		m0 ^= rp[0]; \
		m1 ^= rp[1]; \
		m2 ^= rp[2]; \
		m3 ^= rp[3]; \
		m4 ^= rp[4]; \
		m5 ^= rp[5]; \
		m6 ^= rp[6]; \
		m7 ^= rp[7]; \
		acc = (acc << 8) | buf[3]; \
		rp = &T256_20[(acc >> 7) & 0x1f][0]; \
		m0 ^= rp[0]; \
		m1 ^= rp[1]; \
		m2 ^= rp[2]; \
		m3 ^= rp[3]; \
		m4 ^= rp[4]; \
		m5 ^= rp[5]; \
		m6 ^= rp[6]; \
		m7 ^= rp[7]; \
		rp = &T256_25[(acc >> 2) & 0x1f][0]; \
		m0 ^= rp[0]; \
		m1 ^= rp[1]; \
		m2 ^= rp[2]; \
		m3 ^= rp[3]; \
		m4 ^= rp[4]; \
		m5 ^= rp[5]; \
		m6 ^= rp[6]; \
		m7 ^= rp[7]; \
		rp = &T256_30[acc & 0x03][0]; \
		m0 ^= rp[0]; \
		m1 ^= rp[1]; \
		m2 ^= rp[2]; \
		m3 ^= rp[3]; \
		m4 ^= rp[4]; \
		m5 ^= rp[5]; \
		m6 ^= rp[6]; \
		m7 ^= rp[7]; \
	} while (0)

#endif

#if SPH_HAMSI_EXPAND_SMALL == 6

static const sph_u32 T256_0[64][8] = {
	{ SPH_C32(0x00000000), SPH_C32(0x00000000), SPH_C32(0x00000000),
	  SPH_C32(0x00000000), SPH_C32(0x00000000), SPH_C32(0x00000000),
	  SPH_C32(0x00000000), SPH_C32(0x00000000) },
	{ SPH_C32(0xe92a2000), SPH_C32(0xb4578cfc), SPH_C32(0x11fa3a57),
	  SPH_C32(0x3dc90524), SPH_C32(0x97530000), SPH_C32(0x204f6ed3),
	  SPH_C32(0x77b9e80f), SPH_C32(0xa1ec5ec1) },
	{ SPH_C32(0x97530000), SPH_C32(0x204f6ed3), SPH_C32(0x77b9e80f),
	  SPH_C32(0xa1ec5ec1), SPH_C32(0x7e792000), SPH_C32(0x9418e22f),
	  SPH_C32(0x6643d258), SPH_C32(0x9c255be5) },
	{ SPH_C32(0x7e792000), SPH_C32(0x9418e22f), SPH_C32(0x6643d258),
	  SPH_C32(0x9c255be5), SPH_C32(0xe92a2000), SPH_C32(0xb4578cfc),
	  SPH_C32(0x11fa3a57), SPH_C32(0x3dc90524) },
	{ SPH_C32(0x121b4000), SPH_C32(0x5b17d9e8), SPH_C32(0x8dfacfab),
	  SPH_C32(0xce36cc72), SPH_C32(0xe6570000), SPH_C32(0x4bb33a25),
	  SPH_C32(0x848598ba), SPH_C32(0x1041003e) },
	{ SPH_C32(0xfb316000), SPH_C32(0xef405514), SPH_C32(0x9c00f5fc),
	  SPH_C32(0xf3ffc956), SPH_C32(0x71040000), SPH_C32(0x6bfc54f6),
	  SPH_C32(0xf33c70b5), SPH_C32(0xb1ad5eff) },
	{ SPH_C32(0x85484000), SPH_C32(0x7b58b73b), SPH_C32(0xfa4327a4),
	  SPH_C32(0x6fda92b3), SPH_C32(0x982e2000), SPH_C32(0xdfabd80a),
	  SPH_C32(0xe2c64ae2), SPH_C32(0x8c645bdb) },
	{ SPH_C32(0x6c626000), SPH_C32(0xcf0f3bc7), SPH_C32(0xebb91df3),
	  SPH_C32(0x52139797), SPH_C32(0x0f7d2000), SPH_C32(0xffe4b6d9),
	  SPH_C32(0x957fa2ed), SPH_C32(0x2d88051a) },
	{ SPH_C32(0xe6570000), SPH_C32(0x4bb33a25), SPH_C32(0x848598ba),
	  SPH_C32(0x1041003e), SPH_C32(0xf44c4000), SPH_C32(0x10a4e3cd),
	  SPH_C32(0x097f5711), SPH_C32(0xde77cc4c) },
	{ SPH_C32(0x0f7d2000), SPH_C32(0xffe4b6d9), SPH_C32(0x957fa2ed),
	  SPH_C32(0x2d88051a), SPH_C32(0x631f4000), SPH_C32(0x30eb8d1e),
	  SPH_C32(0x7ec6bf1e), SPH_C32(0x7f9b928d) },
	{ SPH_C32(0x71040000), SPH_C32(0x6bfc54f6), SPH_C32(0xf33c70b5),
	  SPH_C32(0xb1ad5eff), SPH_C32(0x8a356000), SPH_C32(0x84bc01e2),
	  SPH_C32(0x6f3c8549), SPH_C32(0x425297a9) },
	{ SPH_C32(0x982e2000), SPH_C32(0xdfabd80a), SPH_C32(0xe2c64ae2),
	  SPH_C32(0x8c645bdb), SPH_C32(0x1d666000), SPH_C32(0xa4f36f31),
	  SPH_C32(0x18856d46), SPH_C32(0xe3bec968) },
	{ SPH_C32(0xf44c4000), SPH_C32(0x10a4e3cd), SPH_C32(0x097f5711),
	  SPH_C32(0xde77cc4c), SPH_C32(0x121b4000), SPH_C32(0x5b17d9e8),
	  SPH_C32(0x8dfacfab), SPH_C32(0xce36cc72) },
	{ SPH_C32(0x1d666000), SPH_C32(0xa4f36f31), SPH_C32(0x18856d46),
	  SPH_C32(0xe3bec968), SPH_C32(0x85484000), SPH_C32(0x7b58b73b),
	  SPH_C32(0xfa4327a4), SPH_C32(0x6fda92b3) },
	{ SPH_C32(0x631f4000), SPH_C32(0x30eb8d1e), SPH_C32(0x7ec6bf1e),
	  SPH_C32(0x7f9b928d), SPH_C32(0x6c626000), SPH_C32(0xcf0f3bc7),
	  SPH_C32(0xebb91df3), SPH_C32(0x52139797) },
	{ SPH_C32(0x8a356000), SPH_C32(0x84bc01e2), SPH_C32(0x6f3c8549),
	  SPH_C32(0x425297a9), SPH_C32(0xfb316000), SPH_C32(0xef405514),
	  SPH_C32(0x9c00f5fc), SPH_C32(0xf3ffc956) },
	{ SPH_C32(0xe4788000), SPH_C32(0x859673c1), SPH_C32(0xb5fb2452),
	  SPH_C32(0x29cc5edf), SPH_C32(0x045f0000), SPH_C32(0x9c4a93c9),
	  SPH_C32(0x62fc79d0), SPH_C32(0x731ebdc2) },
	{ SPH_C32(0x0d52a000), SPH_C32(0x31c1ff3d), SPH_C32(0xa4011e05),
	  SPH_C32(0x14055bfb), SPH_C32(0x930c0000), SPH_C32(0xbc05fd1a),
	  SPH_C32(0x154591df), SPH_C32(0xd2f2e303) },
	{ SPH_C32(0x732b8000), SPH_C32(0xa5d91d12), SPH_C32(0xc242cc5d),
	  SPH_C32(0x8820001e), SPH_C32(0x7a262000), SPH_C32(0x085271e6),
	  SPH_C32(0x04bfab88), SPH_C32(0xef3be627) },
	{ SPH_C32(0x9a01a000), SPH_C32(0x118e91ee), SPH_C32(0xd3b8f60a),
	  SPH_C32(0xb5e9053a), SPH_C32(0xed752000), SPH_C32(0x281d1f35),
	  SPH_C32(0x73064387), SPH_C32(0x4ed7b8e6) },
	{ SPH_C32(0xf663c000), SPH_C32(0xde81aa29), SPH_C32(0x3801ebf9),
	  SPH_C32(0xe7fa92ad), SPH_C32(0xe2080000), SPH_C32(0xd7f9a9ec),
	  SPH_C32(0xe679e16a), SPH_C32(0x635fbdfc) },
	{ SPH_C32(0x1f49e000), SPH_C32(0x6ad626d5), SPH_C32(0x29fbd1ae),
	  SPH_C32(0xda339789), SPH_C32(0x755b0000), SPH_C32(0xf7b6c73f),
	  SPH_C32(0x91c00965), SPH_C32(0xc2b3e33d) },
	{ SPH_C32(0x6130c000), SPH_C32(0xfecec4fa), SPH_C32(0x4fb803f6),
	  SPH_C32(0x4616cc6c), SPH_C32(0x9c712000), SPH_C32(0x43e14bc3),
	  SPH_C32(0x803a3332), SPH_C32(0xff7ae619) },
	{ SPH_C32(0x881ae000), SPH_C32(0x4a994806), SPH_C32(0x5e4239a1),
	  SPH_C32(0x7bdfc948), SPH_C32(0x0b222000), SPH_C32(0x63ae2510),
	  SPH_C32(0xf783db3d), SPH_C32(0x5e96b8d8) },
	{ SPH_C32(0x022f8000), SPH_C32(0xce2549e4), SPH_C32(0x317ebce8),
	  SPH_C32(0x398d5ee1), SPH_C32(0xf0134000), SPH_C32(0x8cee7004),
	  SPH_C32(0x6b832ec1), SPH_C32(0xad69718e) },
	{ SPH_C32(0xeb05a000), SPH_C32(0x7a72c518), SPH_C32(0x208486bf),
	  SPH_C32(0x04445bc5), SPH_C32(0x67404000), SPH_C32(0xaca11ed7),
	  SPH_C32(0x1c3ac6ce), SPH_C32(0x0c852f4f) },
	{ SPH_C32(0x957c8000), SPH_C32(0xee6a2737), SPH_C32(0x46c754e7),
	  SPH_C32(0x98610020), SPH_C32(0x8e6a6000), SPH_C32(0x18f6922b),
	  SPH_C32(0x0dc0fc99), SPH_C32(0x314c2a6b) },
	{ SPH_C32(0x7c56a000), SPH_C32(0x5a3dabcb), SPH_C32(0x573d6eb0),
	  SPH_C32(0xa5a80504), SPH_C32(0x19396000), SPH_C32(0x38b9fcf8),
	  SPH_C32(0x7a791496), SPH_C32(0x90a074aa) },
	{ SPH_C32(0x1034c000), SPH_C32(0x9532900c), SPH_C32(0xbc847343),
	  SPH_C32(0xf7bb9293), SPH_C32(0x16444000), SPH_C32(0xc75d4a21),
	  SPH_C32(0xef06b67b), SPH_C32(0xbd2871b0) },
	{ SPH_C32(0xf91ee000), SPH_C32(0x21651cf0), SPH_C32(0xad7e4914),
	  SPH_C32(0xca7297b7), SPH_C32(0x81174000), SPH_C32(0xe71224f2),
	  SPH_C32(0x98bf5e74), SPH_C32(0x1cc42f71) },
	{ SPH_C32(0x8767c000), SPH_C32(0xb57dfedf), SPH_C32(0xcb3d9b4c),
	  SPH_C32(0x5657cc52), SPH_C32(0x683d6000), SPH_C32(0x5345a80e),
	  SPH_C32(0x89456423), SPH_C32(0x210d2a55) },
	{ SPH_C32(0x6e4de000), SPH_C32(0x012a7223), SPH_C32(0xdac7a11b),
	  SPH_C32(0x6b9ec976), SPH_C32(0xff6e6000), SPH_C32(0x730ac6dd),
	  SPH_C32(0xfefc8c2c), SPH_C32(0x80e17494) },
	{ SPH_C32(0x045f0000), SPH_C32(0x9c4a93c9), SPH_C32(0x62fc79d0),
	  SPH_C32(0x731ebdc2), SPH_C32(0xe0278000), SPH_C32(0x19dce008),
	  SPH_C32(0xd7075d82), SPH_C32(0x5ad2e31d) },
	{ SPH_C32(0xed752000), SPH_C32(0x281d1f35), SPH_C32(0x73064387),
	  SPH_C32(0x4ed7b8e6), SPH_C32(0x77748000), SPH_C32(0x39938edb),
	  SPH_C32(0xa0beb58d), SPH_C32(0xfb3ebddc) },
	{ SPH_C32(0x930c0000), SPH_C32(0xbc05fd1a), SPH_C32(0x154591df),
	  SPH_C32(0xd2f2e303), SPH_C32(0x9e5ea000), SPH_C32(0x8dc40227),
	  SPH_C32(0xb1448fda), SPH_C32(0xc6f7b8f8) },
	{ SPH_C32(0x7a262000), SPH_C32(0x085271e6), SPH_C32(0x04bfab88),
	  SPH_C32(0xef3be627), SPH_C32(0x090da000), SPH_C32(0xad8b6cf4),
	  SPH_C32(0xc6fd67d5), SPH_C32(0x671be639) },
	{ SPH_C32(0x16444000), SPH_C32(0xc75d4a21), SPH_C32(0xef06b67b),
	  SPH_C32(0xbd2871b0), SPH_C32(0x06708000), SPH_C32(0x526fda2d),
	  SPH_C32(0x5382c538), SPH_C32(0x4a93e323) },
	{ SPH_C32(0xff6e6000), SPH_C32(0x730ac6dd), SPH_C32(0xfefc8c2c),
	  SPH_C32(0x80e17494), SPH_C32(0x91238000), SPH_C32(0x7220b4fe),
	  SPH_C32(0x243b2d37), SPH_C32(0xeb7fbde2) },
	{ SPH_C32(0x81174000), SPH_C32(0xe71224f2), SPH_C32(0x98bf5e74),
	  SPH_C32(0x1cc42f71), SPH_C32(0x7809a000), SPH_C32(0xc6773802),
	  SPH_C32(0x35c11760), SPH_C32(0xd6b6b8c6) },
	{ SPH_C32(0x683d6000), SPH_C32(0x5345a80e), SPH_C32(0x89456423),
	  SPH_C32(0x210d2a55), SPH_C32(0xef5aa000), SPH_C32(0xe63856d1),
	  SPH_C32(0x4278ff6f), SPH_C32(0x775ae607) },
	{ SPH_C32(0xe2080000), SPH_C32(0xd7f9a9ec), SPH_C32(0xe679e16a),
	  SPH_C32(0x635fbdfc), SPH_C32(0x146bc000), SPH_C32(0x097803c5),
	  SPH_C32(0xde780a93), SPH_C32(0x84a52f51) },
	{ SPH_C32(0x0b222000), SPH_C32(0x63ae2510), SPH_C32(0xf783db3d),
	  SPH_C32(0x5e96b8d8), SPH_C32(0x8338c000), SPH_C32(0x29376d16),
	  SPH_C32(0xa9c1e29c), SPH_C32(0x25497190) },
	{ SPH_C32(0x755b0000), SPH_C32(0xf7b6c73f), SPH_C32(0x91c00965),
	  SPH_C32(0xc2b3e33d), SPH_C32(0x6a12e000), SPH_C32(0x9d60e1ea),
	  SPH_C32(0xb83bd8cb), SPH_C32(0x188074b4) },
	{ SPH_C32(0x9c712000), SPH_C32(0x43e14bc3), SPH_C32(0x803a3332),
	  SPH_C32(0xff7ae619), SPH_C32(0xfd41e000), SPH_C32(0xbd2f8f39),
	  SPH_C32(0xcf8230c4), SPH_C32(0xb96c2a75) },
	{ SPH_C32(0xf0134000), SPH_C32(0x8cee7004), SPH_C32(0x6b832ec1),
	  SPH_C32(0xad69718e), SPH_C32(0xf23cc000), SPH_C32(0x42cb39e0),
	  SPH_C32(0x5afd9229), SPH_C32(0x94e42f6f) },
	{ SPH_C32(0x19396000), SPH_C32(0x38b9fcf8), SPH_C32(0x7a791496),
	  SPH_C32(0x90a074aa), SPH_C32(0x656fc000), SPH_C32(0x62845733),
	  SPH_C32(0x2d447a26), SPH_C32(0x350871ae) },
	{ SPH_C32(0x67404000), SPH_C32(0xaca11ed7), SPH_C32(0x1c3ac6ce),
	  SPH_C32(0x0c852f4f), SPH_C32(0x8c45e000), SPH_C32(0xd6d3dbcf),
	  SPH_C32(0x3cbe4071), SPH_C32(0x08c1748a) },
	{ SPH_C32(0x8e6a6000), SPH_C32(0x18f6922b), SPH_C32(0x0dc0fc99),
	  SPH_C32(0x314c2a6b), SPH_C32(0x1b16e000), SPH_C32(0xf69cb51c),
	  SPH_C32(0x4b07a87e), SPH_C32(0xa92d2a4b) },
	{ SPH_C32(0xe0278000), SPH_C32(0x19dce008), SPH_C32(0xd7075d82),
	  SPH_C32(0x5ad2e31d), SPH_C32(0xe4788000), SPH_C32(0x859673c1),
	  SPH_C32(0xb5fb2452), SPH_C32(0x29cc5edf) },
	{ SPH_C32(0x090da000), SPH_C32(0xad8b6cf4), SPH_C32(0xc6fd67d5),
	  SPH_C32(0x671be639), SPH_C32(0x732b8000), SPH_C32(0xa5d91d12),
	  SPH_C32(0xc242cc5d), SPH_C32(0x8820001e) },
	{ SPH_C32(0x77748000), SPH_C32(0x39938edb), SPH_C32(0xa0beb58d),
	  SPH_C32(0xfb3ebddc), SPH_C32(0x9a01a000), SPH_C32(0x118e91ee),
	  SPH_C32(0xd3b8f60a), SPH_C32(0xb5e9053a) },
	{ SPH_C32(0x9e5ea000), SPH_C32(0x8dc40227), SPH_C32(0xb1448fda),
	  SPH_C32(0xc6f7b8f8), SPH_C32(0x0d52a000), SPH_C32(0x31c1ff3d),
	  SPH_C32(0xa4011e05), SPH_C32(0x14055bfb) },
	{ SPH_C32(0xf23cc000), SPH_C32(0x42cb39e0), SPH_C32(0x5afd9229),
	  SPH_C32(0x94e42f6f), SPH_C32(0x022f8000), SPH_C32(0xce2549e4),
	  SPH_C32(0x317ebce8), SPH_C32(0x398d5ee1) },
	{ SPH_C32(0x1b16e000), SPH_C32(0xf69cb51c), SPH_C32(0x4b07a87e),
	  SPH_C32(0xa92d2a4b), SPH_C32(0x957c8000), SPH_C32(0xee6a2737),
	  SPH_C32(0x46c754e7), SPH_C32(0x98610020) },
	{ SPH_C32(0x656fc000), SPH_C32(0x62845733), SPH_C32(0x2d447a26),
	  SPH_C32(0x350871ae), SPH_C32(0x7c56a000), SPH_C32(0x5a3dabcb),
	  SPH_C32(0x573d6eb0), SPH_C32(0xa5a80504) },
	{ SPH_C32(0x8c45e000), SPH_C32(0xd6d3dbcf), SPH_C32(0x3cbe4071),
	  SPH_C32(0x08c1748a), SPH_C32(0xeb05a000), SPH_C32(0x7a72c518),
	  SPH_C32(0x208486bf), SPH_C32(0x04445bc5) },
	{ SPH_C32(0x06708000), SPH_C32(0x526fda2d), SPH_C32(0x5382c538),
	  SPH_C32(0x4a93e323), SPH_C32(0x1034c000), SPH_C32(0x9532900c),
	  SPH_C32(0xbc847343), SPH_C32(0xf7bb9293) },
	{ SPH_C32(0xef5aa000), SPH_C32(0xe63856d1), SPH_C32(0x4278ff6f),
	  SPH_C32(0x775ae607), SPH_C32(0x8767c000), SPH_C32(0xb57dfedf),
	  SPH_C32(0xcb3d9b4c), SPH_C32(0x5657cc52) },
	{ SPH_C32(0x91238000), SPH_C32(0x7220b4fe), SPH_C32(0x243b2d37),
	  SPH_C32(0xeb7fbde2), SPH_C32(0x6e4de000), SPH_C32(0x012a7223),
	  SPH_C32(0xdac7a11b), SPH_C32(0x6b9ec976) },
	{ SPH_C32(0x7809a000), SPH_C32(0xc6773802), SPH_C32(0x35c11760),
	  SPH_C32(0xd6b6b8c6), SPH_C32(0xf91ee000), SPH_C32(0x21651cf0),
	  SPH_C32(0xad7e4914), SPH_C32(0xca7297b7) },
	{ SPH_C32(0x146bc000), SPH_C32(0x097803c5), SPH_C32(0xde780a93),
	  SPH_C32(0x84a52f51), SPH_C32(0xf663c000), SPH_C32(0xde81aa29),
	  SPH_C32(0x3801ebf9), SPH_C32(0xe7fa92ad) },
	{ SPH_C32(0xfd41e000), SPH_C32(0xbd2f8f39), SPH_C32(0xcf8230c4),
	  SPH_C32(0xb96c2a75), SPH_C32(0x6130c000), SPH_C32(0xfecec4fa),
	  SPH_C32(0x4fb803f6), SPH_C32(0x4616cc6c) },
	{ SPH_C32(0x8338c000), SPH_C32(0x29376d16), SPH_C32(0xa9c1e29c),
	  SPH_C32(0x25497190), SPH_C32(0x881ae000), SPH_C32(0x4a994806),
	  SPH_C32(0x5e4239a1), SPH_C32(0x7bdfc948) },
	{ SPH_C32(0x6a12e000), SPH_C32(0x9d60e1ea), SPH_C32(0xb83bd8cb),
	  SPH_C32(0x188074b4), SPH_C32(0x1f49e000), SPH_C32(0x6ad626d5),
	  SPH_C32(0x29fbd1ae), SPH_C32(0xda339789) }
};

static const sph_u32 T256_6[64][8] = {
	{ SPH_C32(0x00000000), SPH_C32(0x00000000), SPH_C32(0x00000000),
	  SPH_C32(0x00000000), SPH_C32(0x00000000), SPH_C32(0x00000000),
	  SPH_C32(0x00000000), SPH_C32(0x00000000) },
	{ SPH_C32(0x8f3e0400), SPH_C32(0x0d9dc877), SPH_C32(0x6fc548e1),
	  SPH_C32(0x898d2cd6), SPH_C32(0x14bd0000), SPH_C32(0x2fba37ff),
	  SPH_C32(0x6a72e5bb), SPH_C32(0x247febe6) },
	{ SPH_C32(0x14bd0000), SPH_C32(0x2fba37ff), SPH_C32(0x6a72e5bb),
	  SPH_C32(0x247febe6), SPH_C32(0x9b830400), SPH_C32(0x2227ff88),
	  SPH_C32(0x05b7ad5a), SPH_C32(0xadf2c730) },
	{ SPH_C32(0x9b830400), SPH_C32(0x2227ff88), SPH_C32(0x05b7ad5a),
	  SPH_C32(0xadf2c730), SPH_C32(0x8f3e0400), SPH_C32(0x0d9dc877),
	  SPH_C32(0x6fc548e1), SPH_C32(0x898d2cd6) },
	{ SPH_C32(0xde320800), SPH_C32(0x288350fe), SPH_C32(0x71852ac7),
	  SPH_C32(0xa6bf9f96), SPH_C32(0xe18b0000), SPH_C32(0x5459887d),
	  SPH_C32(0xbf1283d3), SPH_C32(0x1b666a73) },
	{ SPH_C32(0x510c0c00), SPH_C32(0x251e9889), SPH_C32(0x1e406226),
	  SPH_C32(0x2f32b340), SPH_C32(0xf5360000), SPH_C32(0x7be3bf82),
	  SPH_C32(0xd5606668), SPH_C32(0x3f198195) },
	{ SPH_C32(0xca8f0800), SPH_C32(0x07396701), SPH_C32(0x1bf7cf7c),
	  SPH_C32(0x82c07470), SPH_C32(0x7a080400), SPH_C32(0x767e77f5),
	  SPH_C32(0xbaa52e89), SPH_C32(0xb694ad43) },
	{ SPH_C32(0x45b10c00), SPH_C32(0x0aa4af76), SPH_C32(0x7432879d),
	  SPH_C32(0x0b4d58a6), SPH_C32(0x6eb50400), SPH_C32(0x59c4400a),
	  SPH_C32(0xd0d7cb32), SPH_C32(0x92eb46a5) },
	{ SPH_C32(0xe18b0000), SPH_C32(0x5459887d), SPH_C32(0xbf1283d3),
	  SPH_C32(0x1b666a73), SPH_C32(0x3fb90800), SPH_C32(0x7cdad883),
	  SPH_C32(0xce97a914), SPH_C32(0xbdd9f5e5) },
	{ SPH_C32(0x6eb50400), SPH_C32(0x59c4400a), SPH_C32(0xd0d7cb32),
	  SPH_C32(0x92eb46a5), SPH_C32(0x2b040800), SPH_C32(0x5360ef7c),
	  SPH_C32(0xa4e54caf), SPH_C32(0x99a61e03) },
	{ SPH_C32(0xf5360000), SPH_C32(0x7be3bf82), SPH_C32(0xd5606668),
	  SPH_C32(0x3f198195), SPH_C32(0xa43a0c00), SPH_C32(0x5efd270b),
	  SPH_C32(0xcb20044e), SPH_C32(0x102b32d5) },
	{ SPH_C32(0x7a080400), SPH_C32(0x767e77f5), SPH_C32(0xbaa52e89),
	  SPH_C32(0xb694ad43), SPH_C32(0xb0870c00), SPH_C32(0x714710f4),
	  SPH_C32(0xa152e1f5), SPH_C32(0x3454d933) },
	{ SPH_C32(0x3fb90800), SPH_C32(0x7cdad883), SPH_C32(0xce97a914),
	  SPH_C32(0xbdd9f5e5), SPH_C32(0xde320800), SPH_C32(0x288350fe),
	  SPH_C32(0x71852ac7), SPH_C32(0xa6bf9f96) },
	{ SPH_C32(0xb0870c00), SPH_C32(0x714710f4), SPH_C32(0xa152e1f5),
	  SPH_C32(0x3454d933), SPH_C32(0xca8f0800), SPH_C32(0x07396701),
	  SPH_C32(0x1bf7cf7c), SPH_C32(0x82c07470) },
	{ SPH_C32(0x2b040800), SPH_C32(0x5360ef7c), SPH_C32(0xa4e54caf),
	  SPH_C32(0x99a61e03), SPH_C32(0x45b10c00), SPH_C32(0x0aa4af76),
	  SPH_C32(0x7432879d), SPH_C32(0x0b4d58a6) },
	{ SPH_C32(0xa43a0c00), SPH_C32(0x5efd270b), SPH_C32(0xcb20044e),
	  SPH_C32(0x102b32d5), SPH_C32(0x510c0c00), SPH_C32(0x251e9889),
	  SPH_C32(0x1e406226), SPH_C32(0x2f32b340) },
	{ SPH_C32(0x74951000), SPH_C32(0x5a2b467e), SPH_C32(0x88fd1d2b),
	  SPH_C32(0x1ee68292), SPH_C32(0xcba90000), SPH_C32(0x90273769),
	  SPH_C32(0xbbdcf407), SPH_C32(0xd0f4af61) },
	{ SPH_C32(0xfbab1400), SPH_C32(0x57b68e09), SPH_C32(0xe73855ca),
	  SPH_C32(0x976bae44), SPH_C32(0xdf140000), SPH_C32(0xbf9d0096),
	  SPH_C32(0xd1ae11bc), SPH_C32(0xf48b4487) },
	{ SPH_C32(0x60281000), SPH_C32(0x75917181), SPH_C32(0xe28ff890),
	  SPH_C32(0x3a996974), SPH_C32(0x502a0400), SPH_C32(0xb200c8e1),
	  SPH_C32(0xbe6b595d), SPH_C32(0x7d066851) },
	{ SPH_C32(0xef161400), SPH_C32(0x780cb9f6), SPH_C32(0x8d4ab071),
	  SPH_C32(0xb31445a2), SPH_C32(0x44970400), SPH_C32(0x9dbaff1e),
	  SPH_C32(0xd419bce6), SPH_C32(0x597983b7) },
	{ SPH_C32(0xaaa71800), SPH_C32(0x72a81680), SPH_C32(0xf97837ec),
	  SPH_C32(0xb8591d04), SPH_C32(0x2a220000), SPH_C32(0xc47ebf14),
	  SPH_C32(0x04ce77d4), SPH_C32(0xcb92c512) },
	{ SPH_C32(0x25991c00), SPH_C32(0x7f35def7), SPH_C32(0x96bd7f0d),
	  SPH_C32(0x31d431d2), SPH_C32(0x3e9f0000), SPH_C32(0xebc488eb),
	  SPH_C32(0x6ebc926f), SPH_C32(0xefed2ef4) },
	{ SPH_C32(0xbe1a1800), SPH_C32(0x5d12217f), SPH_C32(0x930ad257),
	  SPH_C32(0x9c26f6e2), SPH_C32(0xb1a10400), SPH_C32(0xe659409c),
	  SPH_C32(0x0179da8e), SPH_C32(0x66600222) },
	{ SPH_C32(0x31241c00), SPH_C32(0x508fe908), SPH_C32(0xfccf9ab6),
	  SPH_C32(0x15abda34), SPH_C32(0xa51c0400), SPH_C32(0xc9e37763),
	  SPH_C32(0x6b0b3f35), SPH_C32(0x421fe9c4) },
	{ SPH_C32(0x951e1000), SPH_C32(0x0e72ce03), SPH_C32(0x37ef9ef8),
	  SPH_C32(0x0580e8e1), SPH_C32(0xf4100800), SPH_C32(0xecfdefea),
	  SPH_C32(0x754b5d13), SPH_C32(0x6d2d5a84) },
	{ SPH_C32(0x1a201400), SPH_C32(0x03ef0674), SPH_C32(0x582ad619),
	  SPH_C32(0x8c0dc437), SPH_C32(0xe0ad0800), SPH_C32(0xc347d815),
	  SPH_C32(0x1f39b8a8), SPH_C32(0x4952b162) },
	{ SPH_C32(0x81a31000), SPH_C32(0x21c8f9fc), SPH_C32(0x5d9d7b43),
	  SPH_C32(0x21ff0307), SPH_C32(0x6f930c00), SPH_C32(0xceda1062),
	  SPH_C32(0x70fcf049), SPH_C32(0xc0df9db4) },
	{ SPH_C32(0x0e9d1400), SPH_C32(0x2c55318b), SPH_C32(0x325833a2),
	  SPH_C32(0xa8722fd1), SPH_C32(0x7b2e0c00), SPH_C32(0xe160279d),
	  SPH_C32(0x1a8e15f2), SPH_C32(0xe4a07652) },
	{ SPH_C32(0x4b2c1800), SPH_C32(0x26f19efd), SPH_C32(0x466ab43f),
	  SPH_C32(0xa33f7777), SPH_C32(0x159b0800), SPH_C32(0xb8a46797),
	  SPH_C32(0xca59dec0), SPH_C32(0x764b30f7) },
	{ SPH_C32(0xc4121c00), SPH_C32(0x2b6c568a), SPH_C32(0x29affcde),
	  SPH_C32(0x2ab25ba1), SPH_C32(0x01260800), SPH_C32(0x971e5068),
	  SPH_C32(0xa02b3b7b), SPH_C32(0x5234db11) },
	{ SPH_C32(0x5f911800), SPH_C32(0x094ba902), SPH_C32(0x2c185184),
	  SPH_C32(0x87409c91), SPH_C32(0x8e180c00), SPH_C32(0x9a83981f),
	  SPH_C32(0xcfee739a), SPH_C32(0xdbb9f7c7) },
	{ SPH_C32(0xd0af1c00), SPH_C32(0x04d66175), SPH_C32(0x43dd1965),
	  SPH_C32(0x0ecdb047), SPH_C32(0x9aa50c00), SPH_C32(0xb539afe0),
	  SPH_C32(0xa59c9621), SPH_C32(0xffc61c21) },
	{ SPH_C32(0xcba90000), SPH_C32(0x90273769), SPH_C32(0xbbdcf407),
	  SPH_C32(0xd0f4af61), SPH_C32(0xbf3c1000), SPH_C32(0xca0c7117),
	  SPH_C32(0x3321e92c), SPH_C32(0xce122df3) },
	{ SPH_C32(0x44970400), SPH_C32(0x9dbaff1e), SPH_C32(0xd419bce6),
	  SPH_C32(0x597983b7), SPH_C32(0xab811000), SPH_C32(0xe5b646e8),
	  SPH_C32(0x59530c97), SPH_C32(0xea6dc615) },
	{ SPH_C32(0xdf140000), SPH_C32(0xbf9d0096), SPH_C32(0xd1ae11bc),
	  SPH_C32(0xf48b4487), SPH_C32(0x24bf1400), SPH_C32(0xe82b8e9f),
	  SPH_C32(0x36964476), SPH_C32(0x63e0eac3) },
	{ SPH_C32(0x502a0400), SPH_C32(0xb200c8e1), SPH_C32(0xbe6b595d),
	  SPH_C32(0x7d066851), SPH_C32(0x30021400), SPH_C32(0xc791b960),
	  SPH_C32(0x5ce4a1cd), SPH_C32(0x479f0125) },
	{ SPH_C32(0x159b0800), SPH_C32(0xb8a46797), SPH_C32(0xca59dec0),
	  SPH_C32(0x764b30f7), SPH_C32(0x5eb71000), SPH_C32(0x9e55f96a),
	  SPH_C32(0x8c336aff), SPH_C32(0xd5744780) },
	{ SPH_C32(0x9aa50c00), SPH_C32(0xb539afe0), SPH_C32(0xa59c9621),
	  SPH_C32(0xffc61c21), SPH_C32(0x4a0a1000), SPH_C32(0xb1efce95),
	  SPH_C32(0xe6418f44), SPH_C32(0xf10bac66) },
	{ SPH_C32(0x01260800), SPH_C32(0x971e5068), SPH_C32(0xa02b3b7b),
	  SPH_C32(0x5234db11), SPH_C32(0xc5341400), SPH_C32(0xbc7206e2),
	  SPH_C32(0x8984c7a5), SPH_C32(0x788680b0) },
	{ SPH_C32(0x8e180c00), SPH_C32(0x9a83981f), SPH_C32(0xcfee739a),
	  SPH_C32(0xdbb9f7c7), SPH_C32(0xd1891400), SPH_C32(0x93c8311d),
	  SPH_C32(0xe3f6221e), SPH_C32(0x5cf96b56) },
	{ SPH_C32(0x2a220000), SPH_C32(0xc47ebf14), SPH_C32(0x04ce77d4),
	  SPH_C32(0xcb92c512), SPH_C32(0x80851800), SPH_C32(0xb6d6a994),
	  SPH_C32(0xfdb64038), SPH_C32(0x73cbd816) },
	{ SPH_C32(0xa51c0400), SPH_C32(0xc9e37763), SPH_C32(0x6b0b3f35),
	  SPH_C32(0x421fe9c4), SPH_C32(0x94381800), SPH_C32(0x996c9e6b),
	  SPH_C32(0x97c4a583), SPH_C32(0x57b433f0) },
	{ SPH_C32(0x3e9f0000), SPH_C32(0xebc488eb), SPH_C32(0x6ebc926f),
	  SPH_C32(0xefed2ef4), SPH_C32(0x1b061c00), SPH_C32(0x94f1561c),
	  SPH_C32(0xf801ed62), SPH_C32(0xde391f26) },
	{ SPH_C32(0xb1a10400), SPH_C32(0xe659409c), SPH_C32(0x0179da8e),
	  SPH_C32(0x66600222), SPH_C32(0x0fbb1c00), SPH_C32(0xbb4b61e3),
	  SPH_C32(0x927308d9), SPH_C32(0xfa46f4c0) },
	{ SPH_C32(0xf4100800), SPH_C32(0xecfdefea), SPH_C32(0x754b5d13),
	  SPH_C32(0x6d2d5a84), SPH_C32(0x610e1800), SPH_C32(0xe28f21e9),
	  SPH_C32(0x42a4c3eb), SPH_C32(0x68adb265) },
	{ SPH_C32(0x7b2e0c00), SPH_C32(0xe160279d), SPH_C32(0x1a8e15f2),
	  SPH_C32(0xe4a07652), SPH_C32(0x75b31800), SPH_C32(0xcd351616),
	  SPH_C32(0x28d62650), SPH_C32(0x4cd25983) },
	{ SPH_C32(0xe0ad0800), SPH_C32(0xc347d815), SPH_C32(0x1f39b8a8),
	  SPH_C32(0x4952b162), SPH_C32(0xfa8d1c00), SPH_C32(0xc0a8de61),
	  SPH_C32(0x47136eb1), SPH_C32(0xc55f7555) },
	{ SPH_C32(0x6f930c00), SPH_C32(0xceda1062), SPH_C32(0x70fcf049),
	  SPH_C32(0xc0df9db4), SPH_C32(0xee301c00), SPH_C32(0xef12e99e),
	  SPH_C32(0x2d618b0a), SPH_C32(0xe1209eb3) },
	{ SPH_C32(0xbf3c1000), SPH_C32(0xca0c7117), SPH_C32(0x3321e92c),
	  SPH_C32(0xce122df3), SPH_C32(0x74951000), SPH_C32(0x5a2b467e),
	  SPH_C32(0x88fd1d2b), SPH_C32(0x1ee68292) },
	{ SPH_C32(0x30021400), SPH_C32(0xc791b960), SPH_C32(0x5ce4a1cd),
	  SPH_C32(0x479f0125), SPH_C32(0x60281000), SPH_C32(0x75917181),
	  SPH_C32(0xe28ff890), SPH_C32(0x3a996974) },
	{ SPH_C32(0xab811000), SPH_C32(0xe5b646e8), SPH_C32(0x59530c97),
	  SPH_C32(0xea6dc615), SPH_C32(0xef161400), SPH_C32(0x780cb9f6),
	  SPH_C32(0x8d4ab071), SPH_C32(0xb31445a2) },
	{ SPH_C32(0x24bf1400), SPH_C32(0xe82b8e9f), SPH_C32(0x36964476),
	  SPH_C32(0x63e0eac3), SPH_C32(0xfbab1400), SPH_C32(0x57b68e09),
	  SPH_C32(0xe73855ca), SPH_C32(0x976bae44) },
	{ SPH_C32(0x610e1800), SPH_C32(0xe28f21e9), SPH_C32(0x42a4c3eb),
	  SPH_C32(0x68adb265), SPH_C32(0x951e1000), SPH_C32(0x0e72ce03),
	  SPH_C32(0x37ef9ef8), SPH_C32(0x0580e8e1) },
	{ SPH_C32(0xee301c00), SPH_C32(0xef12e99e), SPH_C32(0x2d618b0a),
	  SPH_C32(0xe1209eb3), SPH_C32(0x81a31000), SPH_C32(0x21c8f9fc),
	  SPH_C32(0x5d9d7b43), SPH_C32(0x21ff0307) },
	{ SPH_C32(0x75b31800), SPH_C32(0xcd351616), SPH_C32(0x28d62650),
	  SPH_C32(0x4cd25983), SPH_C32(0x0e9d1400), SPH_C32(0x2c55318b),
	  SPH_C32(0x325833a2), SPH_C32(0xa8722fd1) },
	{ SPH_C32(0xfa8d1c00), SPH_C32(0xc0a8de61), SPH_C32(0x47136eb1),
	  SPH_C32(0xc55f7555), SPH_C32(0x1a201400), SPH_C32(0x03ef0674),
	  SPH_C32(0x582ad619), SPH_C32(0x8c0dc437) },
	{ SPH_C32(0x5eb71000), SPH_C32(0x9e55f96a), SPH_C32(0x8c336aff),
	  SPH_C32(0xd5744780), SPH_C32(0x4b2c1800), SPH_C32(0x26f19efd),
	  SPH_C32(0x466ab43f), SPH_C32(0xa33f7777) },
	{ SPH_C32(0xd1891400), SPH_C32(0x93c8311d), SPH_C32(0xe3f6221e),
	  SPH_C32(0x5cf96b56), SPH_C32(0x5f911800), SPH_C32(0x094ba902),
	  SPH_C32(0x2c185184), SPH_C32(0x87409c91) },
	{ SPH_C32(0x4a0a1000), SPH_C32(0xb1efce95), SPH_C32(0xe6418f44),
	  SPH_C32(0xf10bac66), SPH_C32(0xd0af1c00), SPH_C32(0x04d66175),
	  SPH_C32(0x43dd1965), SPH_C32(0x0ecdb047) },
	{ SPH_C32(0xc5341400), SPH_C32(0xbc7206e2), SPH_C32(0x8984c7a5),
	  SPH_C32(0x788680b0), SPH_C32(0xc4121c00), SPH_C32(0x2b6c568a),
	  SPH_C32(0x29affcde), SPH_C32(0x2ab25ba1) },
	{ SPH_C32(0x80851800), SPH_C32(0xb6d6a994), SPH_C32(0xfdb64038),
	  SPH_C32(0x73cbd816), SPH_C32(0xaaa71800), SPH_C32(0x72a81680),
	  SPH_C32(0xf97837ec), SPH_C32(0xb8591d04) },
	{ SPH_C32(0x0fbb1c00), SPH_C32(0xbb4b61e3), SPH_C32(0x927308d9),
	  SPH_C32(0xfa46f4c0), SPH_C32(0xbe1a1800), SPH_C32(0x5d12217f),
	  SPH_C32(0x930ad257), SPH_C32(0x9c26f6e2) },
	{ SPH_C32(0x94381800), SPH_C32(0x996c9e6b), SPH_C32(0x97c4a583),
	  SPH_C32(0x57b433f0), SPH_C32(0x31241c00), SPH_C32(0x508fe908),
	  SPH_C32(0xfccf9ab6), SPH_C32(0x15abda34) },
	{ SPH_C32(0x1b061c00), SPH_C32(0x94f1561c), SPH_C32(0xf801ed62),
	  SPH_C32(0xde391f26), SPH_C32(0x25991c00), SPH_C32(0x7f35def7),
	  SPH_C32(0x96bd7f0d), SPH_C32(0x31d431d2) }
};

static const sph_u32 T256_12[64][8] = {
	{ SPH_C32(0x00000000), SPH_C32(0x00000000), SPH_C32(0x00000000),
	  SPH_C32(0x00000000), SPH_C32(0x00000000), SPH_C32(0x00000000),
	  SPH_C32(0x00000000), SPH_C32(0x00000000) },
	{ SPH_C32(0x5bd20080), SPH_C32(0x450f18ec), SPH_C32(0xc2c46c55),
	  SPH_C32(0xf362b233), SPH_C32(0x39a60000), SPH_C32(0x4ab753eb),
	  SPH_C32(0xd14e094b), SPH_C32(0xb772b42b) },
	{ SPH_C32(0x39a60000), SPH_C32(0x4ab753eb), SPH_C32(0xd14e094b),
	  SPH_C32(0xb772b42b), SPH_C32(0x62740080), SPH_C32(0x0fb84b07),
	  SPH_C32(0x138a651e), SPH_C32(0x44100618) },
	{ SPH_C32(0x62740080), SPH_C32(0x0fb84b07), SPH_C32(0x138a651e),
	  SPH_C32(0x44100618), SPH_C32(0x5bd20080), SPH_C32(0x450f18ec),
	  SPH_C32(0xc2c46c55), SPH_C32(0xf362b233) },
	{ SPH_C32(0xb7a40100), SPH_C32(0x8a1f31d8), SPH_C32(0x8589d8ab),
	  SPH_C32(0xe6c46464), SPH_C32(0x734c0000), SPH_C32(0x956fa7d6),
	  SPH_C32(0xa29d1297), SPH_C32(0x6ee56854) },
	{ SPH_C32(0xec760180), SPH_C32(0xcf102934), SPH_C32(0x474db4fe),
	  SPH_C32(0x15a6d657), SPH_C32(0x4aea0000), SPH_C32(0xdfd8f43d),
	  SPH_C32(0x73d31bdc), SPH_C32(0xd997dc7f) },
	{ SPH_C32(0x8e020100), SPH_C32(0xc0a86233), SPH_C32(0x54c7d1e0),
	  SPH_C32(0x51b6d04f), SPH_C32(0x11380080), SPH_C32(0x9ad7ecd1),
	  SPH_C32(0xb1177789), SPH_C32(0x2af56e4c) },
	{ SPH_C32(0xd5d00180), SPH_C32(0x85a77adf), SPH_C32(0x9603bdb5),
	  SPH_C32(0xa2d4627c), SPH_C32(0x289e0080), SPH_C32(0xd060bf3a),
	  SPH_C32(0x60597ec2), SPH_C32(0x9d87da67) },
	{ SPH_C32(0x734c0000), SPH_C32(0x956fa7d6), SPH_C32(0xa29d1297),
	  SPH_C32(0x6ee56854), SPH_C32(0xc4e80100), SPH_C32(0x1f70960e),
	  SPH_C32(0x2714ca3c), SPH_C32(0x88210c30) },
	{ SPH_C32(0x289e0080), SPH_C32(0xd060bf3a), SPH_C32(0x60597ec2),
	  SPH_C32(0x9d87da67), SPH_C32(0xfd4e0100), SPH_C32(0x55c7c5e5),
	  SPH_C32(0xf65ac377), SPH_C32(0x3f53b81b) },
	{ SPH_C32(0x4aea0000), SPH_C32(0xdfd8f43d), SPH_C32(0x73d31bdc),
	  SPH_C32(0xd997dc7f), SPH_C32(0xa69c0180), SPH_C32(0x10c8dd09),
	  SPH_C32(0x349eaf22), SPH_C32(0xcc310a28) },
	{ SPH_C32(0x11380080), SPH_C32(0x9ad7ecd1), SPH_C32(0xb1177789),
	  SPH_C32(0x2af56e4c), SPH_C32(0x9f3a0180), SPH_C32(0x5a7f8ee2),
	  SPH_C32(0xe5d0a669), SPH_C32(0x7b43be03) },
	{ SPH_C32(0xc4e80100), SPH_C32(0x1f70960e), SPH_C32(0x2714ca3c),
	  SPH_C32(0x88210c30), SPH_C32(0xb7a40100), SPH_C32(0x8a1f31d8),
	  SPH_C32(0x8589d8ab), SPH_C32(0xe6c46464) },
	{ SPH_C32(0x9f3a0180), SPH_C32(0x5a7f8ee2), SPH_C32(0xe5d0a669),
	  SPH_C32(0x7b43be03), SPH_C32(0x8e020100), SPH_C32(0xc0a86233),
	  SPH_C32(0x54c7d1e0), SPH_C32(0x51b6d04f) },
	{ SPH_C32(0xfd4e0100), SPH_C32(0x55c7c5e5), SPH_C32(0xf65ac377),
	  SPH_C32(0x3f53b81b), SPH_C32(0xd5d00180), SPH_C32(0x85a77adf),
	  SPH_C32(0x9603bdb5), SPH_C32(0xa2d4627c) },
	{ SPH_C32(0xa69c0180), SPH_C32(0x10c8dd09), SPH_C32(0x349eaf22),
	  SPH_C32(0xcc310a28), SPH_C32(0xec760180), SPH_C32(0xcf102934),
	  SPH_C32(0x474db4fe), SPH_C32(0x15a6d657) },
	{ SPH_C32(0xa7b80200), SPH_C32(0x1f128433), SPH_C32(0x60e5f9f2),
	  SPH_C32(0x9e147576), SPH_C32(0xee260000), SPH_C32(0x124b683e),
	  SPH_C32(0x80c2d68f), SPH_C32(0x3bf3ab2c) },
	{ SPH_C32(0xfc6a0280), SPH_C32(0x5a1d9cdf), SPH_C32(0xa22195a7),
	  SPH_C32(0x6d76c745), SPH_C32(0xd7800000), SPH_C32(0x58fc3bd5),
	  SPH_C32(0x518cdfc4), SPH_C32(0x8c811f07) },
	{ SPH_C32(0x9e1e0200), SPH_C32(0x55a5d7d8), SPH_C32(0xb1abf0b9),
	  SPH_C32(0x2966c15d), SPH_C32(0x8c520080), SPH_C32(0x1df32339),
	  SPH_C32(0x9348b391), SPH_C32(0x7fe3ad34) },
	{ SPH_C32(0xc5cc0280), SPH_C32(0x10aacf34), SPH_C32(0x736f9cec),
	  SPH_C32(0xda04736e), SPH_C32(0xb5f40080), SPH_C32(0x574470d2),
	  SPH_C32(0x4206bada), SPH_C32(0xc891191f) },
	{ SPH_C32(0x101c0300), SPH_C32(0x950db5eb), SPH_C32(0xe56c2159),
	  SPH_C32(0x78d01112), SPH_C32(0x9d6a0000), SPH_C32(0x8724cfe8),
	  SPH_C32(0x225fc418), SPH_C32(0x5516c378) },
	{ SPH_C32(0x4bce0380), SPH_C32(0xd002ad07), SPH_C32(0x27a84d0c),
	  SPH_C32(0x8bb2a321), SPH_C32(0xa4cc0000), SPH_C32(0xcd939c03),
	  SPH_C32(0xf311cd53), SPH_C32(0xe2647753) },
	{ SPH_C32(0x29ba0300), SPH_C32(0xdfbae600), SPH_C32(0x34222812),
	  SPH_C32(0xcfa2a539), SPH_C32(0xff1e0080), SPH_C32(0x889c84ef),
	  SPH_C32(0x31d5a106), SPH_C32(0x1106c560) },
	{ SPH_C32(0x72680380), SPH_C32(0x9ab5feec), SPH_C32(0xf6e64447),
	  SPH_C32(0x3cc0170a), SPH_C32(0xc6b80080), SPH_C32(0xc22bd704),
	  SPH_C32(0xe09ba84d), SPH_C32(0xa674714b) },
	{ SPH_C32(0xd4f40200), SPH_C32(0x8a7d23e5), SPH_C32(0xc278eb65),
	  SPH_C32(0xf0f11d22), SPH_C32(0x2ace0100), SPH_C32(0x0d3bfe30),
	  SPH_C32(0xa7d61cb3), SPH_C32(0xb3d2a71c) },
	{ SPH_C32(0x8f260280), SPH_C32(0xcf723b09), SPH_C32(0x00bc8730),
	  SPH_C32(0x0393af11), SPH_C32(0x13680100), SPH_C32(0x478caddb),
	  SPH_C32(0x769815f8), SPH_C32(0x04a01337) },
	{ SPH_C32(0xed520200), SPH_C32(0xc0ca700e), SPH_C32(0x1336e22e),
	  SPH_C32(0x4783a909), SPH_C32(0x48ba0180), SPH_C32(0x0283b537),
	  SPH_C32(0xb45c79ad), SPH_C32(0xf7c2a104) },
	{ SPH_C32(0xb6800280), SPH_C32(0x85c568e2), SPH_C32(0xd1f28e7b),
	  SPH_C32(0xb4e11b3a), SPH_C32(0x711c0180), SPH_C32(0x4834e6dc),
	  SPH_C32(0x651270e6), SPH_C32(0x40b0152f) },
	{ SPH_C32(0x63500300), SPH_C32(0x0062123d), SPH_C32(0x47f133ce),
	  SPH_C32(0x16357946), SPH_C32(0x59820100), SPH_C32(0x985459e6),
	  SPH_C32(0x054b0e24), SPH_C32(0xdd37cf48) },
	{ SPH_C32(0x38820380), SPH_C32(0x456d0ad1), SPH_C32(0x85355f9b),
	  SPH_C32(0xe557cb75), SPH_C32(0x60240100), SPH_C32(0xd2e30a0d),
	  SPH_C32(0xd405076f), SPH_C32(0x6a457b63) },
	{ SPH_C32(0x5af60300), SPH_C32(0x4ad541d6), SPH_C32(0x96bf3a85),
	  SPH_C32(0xa147cd6d), SPH_C32(0x3bf60180), SPH_C32(0x97ec12e1),
	  SPH_C32(0x16c16b3a), SPH_C32(0x9927c950) },
	{ SPH_C32(0x01240380), SPH_C32(0x0fda593a), SPH_C32(0x547b56d0),
	  SPH_C32(0x52257f5e), SPH_C32(0x02500180), SPH_C32(0xdd5b410a),
	  SPH_C32(0xc78f6271), SPH_C32(0x2e557d7b) },
	{ SPH_C32(0xee260000), SPH_C32(0x124b683e), SPH_C32(0x80c2d68f),
	  SPH_C32(0x3bf3ab2c), SPH_C32(0x499e0200), SPH_C32(0x0d59ec0d),
	  SPH_C32(0xe0272f7d), SPH_C32(0xa5e7de5a) },
	{ SPH_C32(0xb5f40080), SPH_C32(0x574470d2), SPH_C32(0x4206bada),
	  SPH_C32(0xc891191f), SPH_C32(0x70380200), SPH_C32(0x47eebfe6),
	  SPH_C32(0x31692636), SPH_C32(0x12956a71) },
	{ SPH_C32(0xd7800000), SPH_C32(0x58fc3bd5), SPH_C32(0x518cdfc4),
	  SPH_C32(0x8c811f07), SPH_C32(0x2bea0280), SPH_C32(0x02e1a70a),
	  SPH_C32(0xf3ad4a63), SPH_C32(0xe1f7d842) },
	{ SPH_C32(0x8c520080), SPH_C32(0x1df32339), SPH_C32(0x9348b391),
	  SPH_C32(0x7fe3ad34), SPH_C32(0x124c0280), SPH_C32(0x4856f4e1),
	  SPH_C32(0x22e34328), SPH_C32(0x56856c69) },
	{ SPH_C32(0x59820100), SPH_C32(0x985459e6), SPH_C32(0x054b0e24),
	  SPH_C32(0xdd37cf48), SPH_C32(0x3ad20200), SPH_C32(0x98364bdb),
	  SPH_C32(0x42ba3dea), SPH_C32(0xcb02b60e) },
	{ SPH_C32(0x02500180), SPH_C32(0xdd5b410a), SPH_C32(0xc78f6271),
	  SPH_C32(0x2e557d7b), SPH_C32(0x03740200), SPH_C32(0xd2811830),
	  SPH_C32(0x93f434a1), SPH_C32(0x7c700225) },
	{ SPH_C32(0x60240100), SPH_C32(0xd2e30a0d), SPH_C32(0xd405076f),
	  SPH_C32(0x6a457b63), SPH_C32(0x58a60280), SPH_C32(0x978e00dc),
	  SPH_C32(0x513058f4), SPH_C32(0x8f12b016) },
	{ SPH_C32(0x3bf60180), SPH_C32(0x97ec12e1), SPH_C32(0x16c16b3a),
	  SPH_C32(0x9927c950), SPH_C32(0x61000280), SPH_C32(0xdd395337),
	  SPH_C32(0x807e51bf), SPH_C32(0x3860043d) },
	{ SPH_C32(0x9d6a0000), SPH_C32(0x8724cfe8), SPH_C32(0x225fc418),
	  SPH_C32(0x5516c378), SPH_C32(0x8d760300), SPH_C32(0x12297a03),
	  SPH_C32(0xc733e541), SPH_C32(0x2dc6d26a) },
	{ SPH_C32(0xc6b80080), SPH_C32(0xc22bd704), SPH_C32(0xe09ba84d),
	  SPH_C32(0xa674714b), SPH_C32(0xb4d00300), SPH_C32(0x589e29e8),
	  SPH_C32(0x167dec0a), SPH_C32(0x9ab46641) },
	{ SPH_C32(0xa4cc0000), SPH_C32(0xcd939c03), SPH_C32(0xf311cd53),
	  SPH_C32(0xe2647753), SPH_C32(0xef020380), SPH_C32(0x1d913104),
	  SPH_C32(0xd4b9805f), SPH_C32(0x69d6d472) },
	{ SPH_C32(0xff1e0080), SPH_C32(0x889c84ef), SPH_C32(0x31d5a106),
	  SPH_C32(0x1106c560), SPH_C32(0xd6a40380), SPH_C32(0x572662ef),
	  SPH_C32(0x05f78914), SPH_C32(0xdea46059) },
	{ SPH_C32(0x2ace0100), SPH_C32(0x0d3bfe30), SPH_C32(0xa7d61cb3),
	  SPH_C32(0xb3d2a71c), SPH_C32(0xfe3a0300), SPH_C32(0x8746ddd5),
	  SPH_C32(0x65aef7d6), SPH_C32(0x4323ba3e) },
	{ SPH_C32(0x711c0180), SPH_C32(0x4834e6dc), SPH_C32(0x651270e6),
	  SPH_C32(0x40b0152f), SPH_C32(0xc79c0300), SPH_C32(0xcdf18e3e),
	  SPH_C32(0xb4e0fe9d), SPH_C32(0xf4510e15) },
	{ SPH_C32(0x13680100), SPH_C32(0x478caddb), SPH_C32(0x769815f8),
	  SPH_C32(0x04a01337), SPH_C32(0x9c4e0380), SPH_C32(0x88fe96d2),
	  SPH_C32(0x762492c8), SPH_C32(0x0733bc26) },
	{ SPH_C32(0x48ba0180), SPH_C32(0x0283b537), SPH_C32(0xb45c79ad),
	  SPH_C32(0xf7c2a104), SPH_C32(0xa5e80380), SPH_C32(0xc249c539),
	  SPH_C32(0xa76a9b83), SPH_C32(0xb041080d) },
	{ SPH_C32(0x499e0200), SPH_C32(0x0d59ec0d), SPH_C32(0xe0272f7d),
	  SPH_C32(0xa5e7de5a), SPH_C32(0xa7b80200), SPH_C32(0x1f128433),
	  SPH_C32(0x60e5f9f2), SPH_C32(0x9e147576) },
	{ SPH_C32(0x124c0280), SPH_C32(0x4856f4e1), SPH_C32(0x22e34328),
	  SPH_C32(0x56856c69), SPH_C32(0x9e1e0200), SPH_C32(0x55a5d7d8),
	  SPH_C32(0xb1abf0b9), SPH_C32(0x2966c15d) },
	{ SPH_C32(0x70380200), SPH_C32(0x47eebfe6), SPH_C32(0x31692636),
	  SPH_C32(0x12956a71), SPH_C32(0xc5cc0280), SPH_C32(0x10aacf34),
	  SPH_C32(0x736f9cec), SPH_C32(0xda04736e) },
	{ SPH_C32(0x2bea0280), SPH_C32(0x02e1a70a), SPH_C32(0xf3ad4a63),
	  SPH_C32(0xe1f7d842), SPH_C32(0xfc6a0280), SPH_C32(0x5a1d9cdf),
	  SPH_C32(0xa22195a7), SPH_C32(0x6d76c745) },
	{ SPH_C32(0xfe3a0300), SPH_C32(0x8746ddd5), SPH_C32(0x65aef7d6),
	  SPH_C32(0x4323ba3e), SPH_C32(0xd4f40200), SPH_C32(0x8a7d23e5),
	  SPH_C32(0xc278eb65), SPH_C32(0xf0f11d22) },
	{ SPH_C32(0xa5e80380), SPH_C32(0xc249c539), SPH_C32(0xa76a9b83),
	  SPH_C32(0xb041080d), SPH_C32(0xed520200), SPH_C32(0xc0ca700e),
	  SPH_C32(0x1336e22e), SPH_C32(0x4783a909) },
	{ SPH_C32(0xc79c0300), SPH_C32(0xcdf18e3e), SPH_C32(0xb4e0fe9d),
	  SPH_C32(0xf4510e15), SPH_C32(0xb6800280), SPH_C32(0x85c568e2),
	  SPH_C32(0xd1f28e7b), SPH_C32(0xb4e11b3a) },
	{ SPH_C32(0x9c4e0380), SPH_C32(0x88fe96d2), SPH_C32(0x762492c8),
	  SPH_C32(0x0733bc26), SPH_C32(0x8f260280), SPH_C32(0xcf723b09),
	  SPH_C32(0x00bc8730), SPH_C32(0x0393af11) },
	{ SPH_C32(0x3ad20200), SPH_C32(0x98364bdb), SPH_C32(0x42ba3dea),
	  SPH_C32(0xcb02b60e), SPH_C32(0x63500300), SPH_C32(0x0062123d),
	  SPH_C32(0x47f133ce), SPH_C32(0x16357946) },
	{ SPH_C32(0x61000280), SPH_C32(0xdd395337), SPH_C32(0x807e51bf),
	  SPH_C32(0x3860043d), SPH_C32(0x5af60300), SPH_C32(0x4ad541d6),
	  SPH_C32(0x96bf3a85), SPH_C32(0xa147cd6d) },
	{ SPH_C32(0x03740200), SPH_C32(0xd2811830), SPH_C32(0x93f434a1),
	  SPH_C32(0x7c700225), SPH_C32(0x01240380), SPH_C32(0x0fda593a),
	  SPH_C32(0x547b56d0), SPH_C32(0x52257f5e) },
	{ SPH_C32(0x58a60280), SPH_C32(0x978e00dc), SPH_C32(0x513058f4),
	  SPH_C32(0x8f12b016), SPH_C32(0x38820380), SPH_C32(0x456d0ad1),
	  SPH_C32(0x85355f9b), SPH_C32(0xe557cb75) },
	{ SPH_C32(0x8d760300), SPH_C32(0x12297a03), SPH_C32(0xc733e541),
	  SPH_C32(0x2dc6d26a), SPH_C32(0x101c0300), SPH_C32(0x950db5eb),
	  SPH_C32(0xe56c2159), SPH_C32(0x78d01112) },
	{ SPH_C32(0xd6a40380), SPH_C32(0x572662ef), SPH_C32(0x05f78914),
	  SPH_C32(0xdea46059), SPH_C32(0x29ba0300), SPH_C32(0xdfbae600),
	  SPH_C32(0x34222812), SPH_C32(0xcfa2a539) },
	{ SPH_C32(0xb4d00300), SPH_C32(0x589e29e8), SPH_C32(0x167dec0a),
	  SPH_C32(0x9ab46641), SPH_C32(0x72680380), SPH_C32(0x9ab5feec),
	  SPH_C32(0xf6e64447), SPH_C32(0x3cc0170a) },
	{ SPH_C32(0xef020380), SPH_C32(0x1d913104), SPH_C32(0xd4b9805f),
	  SPH_C32(0x69d6d472), SPH_C32(0x4bce0380), SPH_C32(0xd002ad07),
	  SPH_C32(0x27a84d0c), SPH_C32(0x8bb2a321) }
};

static const sph_u32 T256_18[64][8] = {
	{ SPH_C32(0x00000000), SPH_C32(0x00000000), SPH_C32(0x00000000),
	  SPH_C32(0x00000000), SPH_C32(0x00000000), SPH_C32(0x00000000),
	  SPH_C32(0x00000000), SPH_C32(0x00000000) },
	{ SPH_C32(0x515c0010), SPH_C32(0x40f372fb), SPH_C32(0xfce72602),
	  SPH_C32(0x71575061), SPH_C32(0x2e390000), SPH_C32(0x64dd6689),
	  SPH_C32(0x3cd406fc), SPH_C32(0xb1f490bc) },
	{ SPH_C32(0x2e390000), SPH_C32(0x64dd6689), SPH_C32(0x3cd406fc),
	  SPH_C32(0xb1f490bc), SPH_C32(0x7f650010), SPH_C32(0x242e1472),
	  SPH_C32(0xc03320fe), SPH_C32(0xc0a3c0dd) },
	{ SPH_C32(0x7f650010), SPH_C32(0x242e1472), SPH_C32(0xc03320fe),
	  SPH_C32(0xc0a3c0dd), SPH_C32(0x515c0010), SPH_C32(0x40f372fb),
	  SPH_C32(0xfce72602), SPH_C32(0x71575061) },
	{ SPH_C32(0xa2b80020), SPH_C32(0x81e7e5f6), SPH_C32(0xf9ce4c04),
	  SPH_C32(0xe2afa0c0), SPH_C32(0x5c720000), SPH_C32(0xc9bacd12),
	  SPH_C32(0x79a90df9), SPH_C32(0x63e92178) },
	{ SPH_C32(0xf3e40030), SPH_C32(0xc114970d), SPH_C32(0x05296a06),
	  SPH_C32(0x93f8f0a1), SPH_C32(0x724b0000), SPH_C32(0xad67ab9b),
	  SPH_C32(0x457d0b05), SPH_C32(0xd21db1c4) },
	{ SPH_C32(0x8c810020), SPH_C32(0xe53a837f), SPH_C32(0xc51a4af8),
	  SPH_C32(0x535b307c), SPH_C32(0x23170010), SPH_C32(0xed94d960),
	  SPH_C32(0xb99a2d07), SPH_C32(0xa34ae1a5) },
	{ SPH_C32(0xdddd0030), SPH_C32(0xa5c9f184), SPH_C32(0x39fd6cfa),
	  SPH_C32(0x220c601d), SPH_C32(0x0d2e0010), SPH_C32(0x8949bfe9),
	  SPH_C32(0x854e2bfb), SPH_C32(0x12be7119) },
	{ SPH_C32(0x5c720000), SPH_C32(0xc9bacd12), SPH_C32(0x79a90df9),
	  SPH_C32(0x63e92178), SPH_C32(0xfeca0020), SPH_C32(0x485d28e4),
	  SPH_C32(0x806741fd), SPH_C32(0x814681b8) },
	{ SPH_C32(0x0d2e0010), SPH_C32(0x8949bfe9), SPH_C32(0x854e2bfb),
	  SPH_C32(0x12be7119), SPH_C32(0xd0f30020), SPH_C32(0x2c804e6d),
	  SPH_C32(0xbcb34701), SPH_C32(0x30b21104) },
	{ SPH_C32(0x724b0000), SPH_C32(0xad67ab9b), SPH_C32(0x457d0b05),
	  SPH_C32(0xd21db1c4), SPH_C32(0x81af0030), SPH_C32(0x6c733c96),
	  SPH_C32(0x40546103), SPH_C32(0x41e54165) },
	{ SPH_C32(0x23170010), SPH_C32(0xed94d960), SPH_C32(0xb99a2d07),
	  SPH_C32(0xa34ae1a5), SPH_C32(0xaf960030), SPH_C32(0x08ae5a1f),
	  SPH_C32(0x7c8067ff), SPH_C32(0xf011d1d9) },
	{ SPH_C32(0xfeca0020), SPH_C32(0x485d28e4), SPH_C32(0x806741fd),
	  SPH_C32(0x814681b8), SPH_C32(0xa2b80020), SPH_C32(0x81e7e5f6),
	  SPH_C32(0xf9ce4c04), SPH_C32(0xe2afa0c0) },
	{ SPH_C32(0xaf960030), SPH_C32(0x08ae5a1f), SPH_C32(0x7c8067ff),
	  SPH_C32(0xf011d1d9), SPH_C32(0x8c810020), SPH_C32(0xe53a837f),
	  SPH_C32(0xc51a4af8), SPH_C32(0x535b307c) },
	{ SPH_C32(0xd0f30020), SPH_C32(0x2c804e6d), SPH_C32(0xbcb34701),
	  SPH_C32(0x30b21104), SPH_C32(0xdddd0030), SPH_C32(0xa5c9f184),
	  SPH_C32(0x39fd6cfa), SPH_C32(0x220c601d) },
	{ SPH_C32(0x81af0030), SPH_C32(0x6c733c96), SPH_C32(0x40546103),
	  SPH_C32(0x41e54165), SPH_C32(0xf3e40030), SPH_C32(0xc114970d),
	  SPH_C32(0x05296a06), SPH_C32(0x93f8f0a1) },
	{ SPH_C32(0x4dce0040), SPH_C32(0x3b5bec7e), SPH_C32(0x36656ba8),
	  SPH_C32(0x23633a05), SPH_C32(0x78ab0000), SPH_C32(0xa0cd5a34),
	  SPH_C32(0x5d5ca0f7), SPH_C32(0x727784cb) },
	{ SPH_C32(0x1c920050), SPH_C32(0x7ba89e85), SPH_C32(0xca824daa),
	  SPH_C32(0x52346a64), SPH_C32(0x56920000), SPH_C32(0xc4103cbd),
	  SPH_C32(0x6188a60b), SPH_C32(0xc3831477) },
	{ SPH_C32(0x63f70040), SPH_C32(0x5f868af7), SPH_C32(0x0ab16d54),
	  SPH_C32(0x9297aab9), SPH_C32(0x07ce0010), SPH_C32(0x84e34e46),
	  SPH_C32(0x9d6f8009), SPH_C32(0xb2d44416) },
	{ SPH_C32(0x32ab0050), SPH_C32(0x1f75f80c), SPH_C32(0xf6564b56),
	  SPH_C32(0xe3c0fad8), SPH_C32(0x29f70010), SPH_C32(0xe03e28cf),
	  SPH_C32(0xa1bb86f5), SPH_C32(0x0320d4aa) },
	{ SPH_C32(0xef760060), SPH_C32(0xbabc0988), SPH_C32(0xcfab27ac),
	  SPH_C32(0xc1cc9ac5), SPH_C32(0x24d90000), SPH_C32(0x69779726),
	  SPH_C32(0x24f5ad0e), SPH_C32(0x119ea5b3) },
	{ SPH_C32(0xbe2a0070), SPH_C32(0xfa4f7b73), SPH_C32(0x334c01ae),
	  SPH_C32(0xb09bcaa4), SPH_C32(0x0ae00000), SPH_C32(0x0daaf1af),
	  SPH_C32(0x1821abf2), SPH_C32(0xa06a350f) },
	{ SPH_C32(0xc14f0060), SPH_C32(0xde616f01), SPH_C32(0xf37f2150),
	  SPH_C32(0x70380a79), SPH_C32(0x5bbc0010), SPH_C32(0x4d598354),
	  SPH_C32(0xe4c68df0), SPH_C32(0xd13d656e) },
	{ SPH_C32(0x90130070), SPH_C32(0x9e921dfa), SPH_C32(0x0f980752),
	  SPH_C32(0x016f5a18), SPH_C32(0x75850010), SPH_C32(0x2984e5dd),
	  SPH_C32(0xd8128b0c), SPH_C32(0x60c9f5d2) },
	{ SPH_C32(0x11bc0040), SPH_C32(0xf2e1216c), SPH_C32(0x4fcc6651),
	  SPH_C32(0x408a1b7d), SPH_C32(0x86610020), SPH_C32(0xe89072d0),
	  SPH_C32(0xdd3be10a), SPH_C32(0xf3310573) },
	{ SPH_C32(0x40e00050), SPH_C32(0xb2125397), SPH_C32(0xb32b4053),
	  SPH_C32(0x31dd4b1c), SPH_C32(0xa8580020), SPH_C32(0x8c4d1459),
	  SPH_C32(0xe1efe7f6), SPH_C32(0x42c595cf) },
	{ SPH_C32(0x3f850040), SPH_C32(0x963c47e5), SPH_C32(0x731860ad),
	  SPH_C32(0xf17e8bc1), SPH_C32(0xf9040030), SPH_C32(0xccbe66a2),
	  SPH_C32(0x1d08c1f4), SPH_C32(0x3392c5ae) },
	{ SPH_C32(0x6ed90050), SPH_C32(0xd6cf351e), SPH_C32(0x8fff46af),
	  SPH_C32(0x8029dba0), SPH_C32(0xd73d0030), SPH_C32(0xa863002b),
	  SPH_C32(0x21dcc708), SPH_C32(0x82665512) },
	{ SPH_C32(0xb3040060), SPH_C32(0x7306c49a), SPH_C32(0xb6022a55),
	  SPH_C32(0xa225bbbd), SPH_C32(0xda130020), SPH_C32(0x212abfc2),
	  SPH_C32(0xa492ecf3), SPH_C32(0x90d8240b) },
	{ SPH_C32(0xe2580070), SPH_C32(0x33f5b661), SPH_C32(0x4ae50c57),
	  SPH_C32(0xd372ebdc), SPH_C32(0xf42a0020), SPH_C32(0x45f7d94b),
	  SPH_C32(0x9846ea0f), SPH_C32(0x212cb4b7) },
	{ SPH_C32(0x9d3d0060), SPH_C32(0x17dba213), SPH_C32(0x8ad62ca9),
	  SPH_C32(0x13d12b01), SPH_C32(0xa5760030), SPH_C32(0x0504abb0),
	  SPH_C32(0x64a1cc0d), SPH_C32(0x507be4d6) },
	{ SPH_C32(0xcc610070), SPH_C32(0x5728d0e8), SPH_C32(0x76310aab),
	  SPH_C32(0x62867b60), SPH_C32(0x8b4f0030), SPH_C32(0x61d9cd39),
	  SPH_C32(0x5875caf1), SPH_C32(0xe18f746a) },
	{ SPH_C32(0x78ab0000), SPH_C32(0xa0cd5a34), SPH_C32(0x5d5ca0f7),
	  SPH_C32(0x727784cb), SPH_C32(0x35650040), SPH_C32(0x9b96b64a),
	  SPH_C32(0x6b39cb5f), SPH_C32(0x5114bece) },
	{ SPH_C32(0x29f70010), SPH_C32(0xe03e28cf), SPH_C32(0xa1bb86f5),
	  SPH_C32(0x0320d4aa), SPH_C32(0x1b5c0040), SPH_C32(0xff4bd0c3),
	  SPH_C32(0x57edcda3), SPH_C32(0xe0e02e72) },
	{ SPH_C32(0x56920000), SPH_C32(0xc4103cbd), SPH_C32(0x6188a60b),
	  SPH_C32(0xc3831477), SPH_C32(0x4a000050), SPH_C32(0xbfb8a238),
	  SPH_C32(0xab0aeba1), SPH_C32(0x91b77e13) },
	{ SPH_C32(0x07ce0010), SPH_C32(0x84e34e46), SPH_C32(0x9d6f8009),
	  SPH_C32(0xb2d44416), SPH_C32(0x64390050), SPH_C32(0xdb65c4b1),
	  SPH_C32(0x97deed5d), SPH_C32(0x2043eeaf) },
	{ SPH_C32(0xda130020), SPH_C32(0x212abfc2), SPH_C32(0xa492ecf3),
	  SPH_C32(0x90d8240b), SPH_C32(0x69170040), SPH_C32(0x522c7b58),
	  SPH_C32(0x1290c6a6), SPH_C32(0x32fd9fb6) },
	{ SPH_C32(0x8b4f0030), SPH_C32(0x61d9cd39), SPH_C32(0x5875caf1),
	  SPH_C32(0xe18f746a), SPH_C32(0x472e0040), SPH_C32(0x36f11dd1),
	  SPH_C32(0x2e44c05a), SPH_C32(0x83090f0a) },
	{ SPH_C32(0xf42a0020), SPH_C32(0x45f7d94b), SPH_C32(0x9846ea0f),
	  SPH_C32(0x212cb4b7), SPH_C32(0x16720050), SPH_C32(0x76026f2a),
	  SPH_C32(0xd2a3e658), SPH_C32(0xf25e5f6b) },
	{ SPH_C32(0xa5760030), SPH_C32(0x0504abb0), SPH_C32(0x64a1cc0d),
	  SPH_C32(0x507be4d6), SPH_C32(0x384b0050), SPH_C32(0x12df09a3),
	  SPH_C32(0xee77e0a4), SPH_C32(0x43aacfd7) },
	{ SPH_C32(0x24d90000), SPH_C32(0x69779726), SPH_C32(0x24f5ad0e),
	  SPH_C32(0x119ea5b3), SPH_C32(0xcbaf0060), SPH_C32(0xd3cb9eae),
	  SPH_C32(0xeb5e8aa2), SPH_C32(0xd0523f76) },
	{ SPH_C32(0x75850010), SPH_C32(0x2984e5dd), SPH_C32(0xd8128b0c),
	  SPH_C32(0x60c9f5d2), SPH_C32(0xe5960060), SPH_C32(0xb716f827),
	  SPH_C32(0xd78a8c5e), SPH_C32(0x61a6afca) },
	{ SPH_C32(0x0ae00000), SPH_C32(0x0daaf1af), SPH_C32(0x1821abf2),
	  SPH_C32(0xa06a350f), SPH_C32(0xb4ca0070), SPH_C32(0xf7e58adc),
	  SPH_C32(0x2b6daa5c), SPH_C32(0x10f1ffab) },
	{ SPH_C32(0x5bbc0010), SPH_C32(0x4d598354), SPH_C32(0xe4c68df0),
	  SPH_C32(0xd13d656e), SPH_C32(0x9af30070), SPH_C32(0x9338ec55),
	  SPH_C32(0x17b9aca0), SPH_C32(0xa1056f17) },
	{ SPH_C32(0x86610020), SPH_C32(0xe89072d0), SPH_C32(0xdd3be10a),
	  SPH_C32(0xf3310573), SPH_C32(0x97dd0060), SPH_C32(0x1a7153bc),
	  SPH_C32(0x92f7875b), SPH_C32(0xb3bb1e0e) },
	{ SPH_C32(0xd73d0030), SPH_C32(0xa863002b), SPH_C32(0x21dcc708),
	  SPH_C32(0x82665512), SPH_C32(0xb9e40060), SPH_C32(0x7eac3535),
	  SPH_C32(0xae2381a7), SPH_C32(0x024f8eb2) },
	{ SPH_C32(0xa8580020), SPH_C32(0x8c4d1459), SPH_C32(0xe1efe7f6),
	  SPH_C32(0x42c595cf), SPH_C32(0xe8b80070), SPH_C32(0x3e5f47ce),
	  SPH_C32(0x52c4a7a5), SPH_C32(0x7318ded3) },
	{ SPH_C32(0xf9040030), SPH_C32(0xccbe66a2), SPH_C32(0x1d08c1f4),
	  SPH_C32(0x3392c5ae), SPH_C32(0xc6810070), SPH_C32(0x5a822147),
	  SPH_C32(0x6e10a159), SPH_C32(0xc2ec4e6f) },
	{ SPH_C32(0x35650040), SPH_C32(0x9b96b64a), SPH_C32(0x6b39cb5f),
	  SPH_C32(0x5114bece), SPH_C32(0x4dce0040), SPH_C32(0x3b5bec7e),
	  SPH_C32(0x36656ba8), SPH_C32(0x23633a05) },
	{ SPH_C32(0x64390050), SPH_C32(0xdb65c4b1), SPH_C32(0x97deed5d),
	  SPH_C32(0x2043eeaf), SPH_C32(0x63f70040), SPH_C32(0x5f868af7),
	  SPH_C32(0x0ab16d54), SPH_C32(0x9297aab9) },
	{ SPH_C32(0x1b5c0040), SPH_C32(0xff4bd0c3), SPH_C32(0x57edcda3),
	  SPH_C32(0xe0e02e72), SPH_C32(0x32ab0050), SPH_C32(0x1f75f80c),
	  SPH_C32(0xf6564b56), SPH_C32(0xe3c0fad8) },
	{ SPH_C32(0x4a000050), SPH_C32(0xbfb8a238), SPH_C32(0xab0aeba1),
	  SPH_C32(0x91b77e13), SPH_C32(0x1c920050), SPH_C32(0x7ba89e85),
	  SPH_C32(0xca824daa), SPH_C32(0x52346a64) },
	{ SPH_C32(0x97dd0060), SPH_C32(0x1a7153bc), SPH_C32(0x92f7875b),
	  SPH_C32(0xb3bb1e0e), SPH_C32(0x11bc0040), SPH_C32(0xf2e1216c),
	  SPH_C32(0x4fcc6651), SPH_C32(0x408a1b7d) },
	{ SPH_C32(0xc6810070), SPH_C32(0x5a822147), SPH_C32(0x6e10a159),
	  SPH_C32(0xc2ec4e6f), SPH_C32(0x3f850040), SPH_C32(0x963c47e5),
	  SPH_C32(0x731860ad), SPH_C32(0xf17e8bc1) },
	{ SPH_C32(0xb9e40060), SPH_C32(0x7eac3535), SPH_C32(0xae2381a7),
	  SPH_C32(0x024f8eb2), SPH_C32(0x6ed90050), SPH_C32(0xd6cf351e),
	  SPH_C32(0x8fff46af), SPH_C32(0x8029dba0) },
	{ SPH_C32(0xe8b80070), SPH_C32(0x3e5f47ce), SPH_C32(0x52c4a7a5),
	  SPH_C32(0x7318ded3), SPH_C32(0x40e00050), SPH_C32(0xb2125397),
	  SPH_C32(0xb32b4053), SPH_C32(0x31dd4b1c) },
	{ SPH_C32(0x69170040), SPH_C32(0x522c7b58), SPH_C32(0x1290c6a6),
	  SPH_C32(0x32fd9fb6), SPH_C32(0xb3040060), SPH_C32(0x7306c49a),
	  SPH_C32(0xb6022a55), SPH_C32(0xa225bbbd) },
	{ SPH_C32(0x384b0050), SPH_C32(0x12df09a3), SPH_C32(0xee77e0a4),
	  SPH_C32(0x43aacfd7), SPH_C32(0x9d3d0060), SPH_C32(0x17dba213),
	  SPH_C32(0x8ad62ca9), SPH_C32(0x13d12b01) },
	{ SPH_C32(0x472e0040), SPH_C32(0x36f11dd1), SPH_C32(0x2e44c05a),
	  SPH_C32(0x83090f0a), SPH_C32(0xcc610070), SPH_C32(0x5728d0e8),
	  SPH_C32(0x76310aab), SPH_C32(0x62867b60) },
	{ SPH_C32(0x16720050), SPH_C32(0x76026f2a), SPH_C32(0xd2a3e658),
	  SPH_C32(0xf25e5f6b), SPH_C32(0xe2580070), SPH_C32(0x33f5b661),
	  SPH_C32(0x4ae50c57), SPH_C32(0xd372ebdc) },
	{ SPH_C32(0xcbaf0060), SPH_C32(0xd3cb9eae), SPH_C32(0xeb5e8aa2),
	  SPH_C32(0xd0523f76), SPH_C32(0xef760060), SPH_C32(0xbabc0988),
	  SPH_C32(0xcfab27ac), SPH_C32(0xc1cc9ac5) },
	{ SPH_C32(0x9af30070), SPH_C32(0x9338ec55), SPH_C32(0x17b9aca0),
	  SPH_C32(0xa1056f17), SPH_C32(0xc14f0060), SPH_C32(0xde616f01),
	  SPH_C32(0xf37f2150), SPH_C32(0x70380a79) },
	{ SPH_C32(0xe5960060), SPH_C32(0xb716f827), SPH_C32(0xd78a8c5e),
	  SPH_C32(0x61a6afca), SPH_C32(0x90130070), SPH_C32(0x9e921dfa),
	  SPH_C32(0x0f980752), SPH_C32(0x016f5a18) },
	{ SPH_C32(0xb4ca0070), SPH_C32(0xf7e58adc), SPH_C32(0x2b6daa5c),
	  SPH_C32(0x10f1ffab), SPH_C32(0xbe2a0070), SPH_C32(0xfa4f7b73),
	  SPH_C32(0x334c01ae), SPH_C32(0xb09bcaa4) }
};

static const sph_u32 T256_24[64][8] = {
	{ SPH_C32(0x00000000), SPH_C32(0x00000000), SPH_C32(0x00000000),
	  SPH_C32(0x00000000), SPH_C32(0x00000000), SPH_C32(0x00000000),
	  SPH_C32(0x00000000), SPH_C32(0x00000000) },
	{ SPH_C32(0x88230002), SPH_C32(0x5fe7a7b3), SPH_C32(0x99e585aa),
	  SPH_C32(0x8d75f7f1), SPH_C32(0x51ac0000), SPH_C32(0x25e30f14),
	  SPH_C32(0x79e22a4c), SPH_C32(0x1298bd46) },
	{ SPH_C32(0x51ac0000), SPH_C32(0x25e30f14), SPH_C32(0x79e22a4c),
	  SPH_C32(0x1298bd46), SPH_C32(0xd98f0002), SPH_C32(0x7a04a8a7),
	  SPH_C32(0xe007afe6), SPH_C32(0x9fed4ab7) },
	{ SPH_C32(0xd98f0002), SPH_C32(0x7a04a8a7), SPH_C32(0xe007afe6),
	  SPH_C32(0x9fed4ab7), SPH_C32(0x88230002), SPH_C32(0x5fe7a7b3),
	  SPH_C32(0x99e585aa), SPH_C32(0x8d75f7f1) },
	{ SPH_C32(0xd0080004), SPH_C32(0x8c768f77), SPH_C32(0x9dc5b050),
	  SPH_C32(0xaf4a29da), SPH_C32(0x6ba90000), SPH_C32(0x40ebf9aa),
	  SPH_C32(0x98321c3d), SPH_C32(0x76acc733) },
	{ SPH_C32(0x582b0006), SPH_C32(0xd39128c4), SPH_C32(0x042035fa),
	  SPH_C32(0x223fde2b), SPH_C32(0x3a050000), SPH_C32(0x6508f6be),
	  SPH_C32(0xe1d03671), SPH_C32(0x64347a75) },
	{ SPH_C32(0x81a40004), SPH_C32(0xa9958063), SPH_C32(0xe4279a1c),
	  SPH_C32(0xbdd2949c), SPH_C32(0xb2260002), SPH_C32(0x3aef510d),
	  SPH_C32(0x7835b3db), SPH_C32(0xe9418d84) },
	{ SPH_C32(0x09870006), SPH_C32(0xf67227d0), SPH_C32(0x7dc21fb6),
	  SPH_C32(0x30a7636d), SPH_C32(0xe38a0002), SPH_C32(0x1f0c5e19),
	  SPH_C32(0x01d79997), SPH_C32(0xfbd930c2) },
	{ SPH_C32(0x6ba90000), SPH_C32(0x40ebf9aa), SPH_C32(0x98321c3d),
	  SPH_C32(0x76acc733), SPH_C32(0xbba10004), SPH_C32(0xcc9d76dd),
	  SPH_C32(0x05f7ac6d), SPH_C32(0xd9e6eee9) },
	{ SPH_C32(0xe38a0002), SPH_C32(0x1f0c5e19), SPH_C32(0x01d79997),
	  SPH_C32(0xfbd930c2), SPH_C32(0xea0d0004), SPH_C32(0xe97e79c9),
	  SPH_C32(0x7c158621), SPH_C32(0xcb7e53af) },
	{ SPH_C32(0x3a050000), SPH_C32(0x6508f6be), SPH_C32(0xe1d03671),
	  SPH_C32(0x64347a75), SPH_C32(0x622e0006), SPH_C32(0xb699de7a),
	  SPH_C32(0xe5f0038b), SPH_C32(0x460ba45e) },
	{ SPH_C32(0xb2260002), SPH_C32(0x3aef510d), SPH_C32(0x7835b3db),
	  SPH_C32(0xe9418d84), SPH_C32(0x33820006), SPH_C32(0x937ad16e),
	  SPH_C32(0x9c1229c7), SPH_C32(0x54931918) },
	{ SPH_C32(0xbba10004), SPH_C32(0xcc9d76dd), SPH_C32(0x05f7ac6d),
	  SPH_C32(0xd9e6eee9), SPH_C32(0xd0080004), SPH_C32(0x8c768f77),
	  SPH_C32(0x9dc5b050), SPH_C32(0xaf4a29da) },
	{ SPH_C32(0x33820006), SPH_C32(0x937ad16e), SPH_C32(0x9c1229c7),
	  SPH_C32(0x54931918), SPH_C32(0x81a40004), SPH_C32(0xa9958063),
	  SPH_C32(0xe4279a1c), SPH_C32(0xbdd2949c) },
	{ SPH_C32(0xea0d0004), SPH_C32(0xe97e79c9), SPH_C32(0x7c158621),
	  SPH_C32(0xcb7e53af), SPH_C32(0x09870006), SPH_C32(0xf67227d0),
	  SPH_C32(0x7dc21fb6), SPH_C32(0x30a7636d) },
	{ SPH_C32(0x622e0006), SPH_C32(0xb699de7a), SPH_C32(0xe5f0038b),
	  SPH_C32(0x460ba45e), SPH_C32(0x582b0006), SPH_C32(0xd39128c4),
	  SPH_C32(0x042035fa), SPH_C32(0x223fde2b) },
	{ SPH_C32(0xa8ae0008), SPH_C32(0x2079397d), SPH_C32(0xfe739301),
	  SPH_C32(0xb8a92831), SPH_C32(0x171c0000), SPH_C32(0xb26e3344),
	  SPH_C32(0x9e6a837e), SPH_C32(0x58f8485f) },
	{ SPH_C32(0x208d000a), SPH_C32(0x7f9e9ece), SPH_C32(0x679616ab),
	  SPH_C32(0x35dcdfc0), SPH_C32(0x46b00000), SPH_C32(0x978d3c50),
	  SPH_C32(0xe788a932), SPH_C32(0x4a60f519) },
	{ SPH_C32(0xf9020008), SPH_C32(0x059a3669), SPH_C32(0x8791b94d),
	  SPH_C32(0xaa319577), SPH_C32(0xce930002), SPH_C32(0xc86a9be3),
	  SPH_C32(0x7e6d2c98), SPH_C32(0xc71502e8) },
	{ SPH_C32(0x7121000a), SPH_C32(0x5a7d91da), SPH_C32(0x1e743ce7),
	  SPH_C32(0x27446286), SPH_C32(0x9f3f0002), SPH_C32(0xed8994f7),
	  SPH_C32(0x078f06d4), SPH_C32(0xd58dbfae) },
	{ SPH_C32(0x78a6000c), SPH_C32(0xac0fb60a), SPH_C32(0x63b62351),
	  SPH_C32(0x17e301eb), SPH_C32(0x7cb50000), SPH_C32(0xf285caee),
	  SPH_C32(0x06589f43), SPH_C32(0x2e548f6c) },
	{ SPH_C32(0xf085000e), SPH_C32(0xf3e811b9), SPH_C32(0xfa53a6fb),
	  SPH_C32(0x9a96f61a), SPH_C32(0x2d190000), SPH_C32(0xd766c5fa),
	  SPH_C32(0x7fbab50f), SPH_C32(0x3ccc322a) },
	{ SPH_C32(0x290a000c), SPH_C32(0x89ecb91e), SPH_C32(0x1a54091d),
	  SPH_C32(0x057bbcad), SPH_C32(0xa53a0002), SPH_C32(0x88816249),
	  SPH_C32(0xe65f30a5), SPH_C32(0xb1b9c5db) },
	{ SPH_C32(0xa129000e), SPH_C32(0xd60b1ead), SPH_C32(0x83b18cb7),
	  SPH_C32(0x880e4b5c), SPH_C32(0xf4960002), SPH_C32(0xad626d5d),
	  SPH_C32(0x9fbd1ae9), SPH_C32(0xa321789d) },
	{ SPH_C32(0xc3070008), SPH_C32(0x6092c0d7), SPH_C32(0x66418f3c),
	  SPH_C32(0xce05ef02), SPH_C32(0xacbd0004), SPH_C32(0x7ef34599),
	  SPH_C32(0x9b9d2f13), SPH_C32(0x811ea6b6) },
	{ SPH_C32(0x4b24000a), SPH_C32(0x3f756764), SPH_C32(0xffa40a96),
	  SPH_C32(0x437018f3), SPH_C32(0xfd110004), SPH_C32(0x5b104a8d),
	  SPH_C32(0xe27f055f), SPH_C32(0x93861bf0) },
	{ SPH_C32(0x92ab0008), SPH_C32(0x4571cfc3), SPH_C32(0x1fa3a570),
	  SPH_C32(0xdc9d5244), SPH_C32(0x75320006), SPH_C32(0x04f7ed3e),
	  SPH_C32(0x7b9a80f5), SPH_C32(0x1ef3ec01) },
	{ SPH_C32(0x1a88000a), SPH_C32(0x1a966870), SPH_C32(0x864620da),
	  SPH_C32(0x51e8a5b5), SPH_C32(0x249e0006), SPH_C32(0x2114e22a),
	  SPH_C32(0x0278aab9), SPH_C32(0x0c6b5147) },
	{ SPH_C32(0x130f000c), SPH_C32(0xece44fa0), SPH_C32(0xfb843f6c),
	  SPH_C32(0x614fc6d8), SPH_C32(0xc7140004), SPH_C32(0x3e18bc33),
	  SPH_C32(0x03af332e), SPH_C32(0xf7b26185) },
	{ SPH_C32(0x9b2c000e), SPH_C32(0xb303e813), SPH_C32(0x6261bac6),
	  SPH_C32(0xec3a3129), SPH_C32(0x96b80004), SPH_C32(0x1bfbb327),
	  SPH_C32(0x7a4d1962), SPH_C32(0xe52adcc3) },
	{ SPH_C32(0x42a3000c), SPH_C32(0xc90740b4), SPH_C32(0x82661520),
	  SPH_C32(0x73d77b9e), SPH_C32(0x1e9b0006), SPH_C32(0x441c1494),
	  SPH_C32(0xe3a89cc8), SPH_C32(0x685f2b32) },
	{ SPH_C32(0xca80000e), SPH_C32(0x96e0e707), SPH_C32(0x1b83908a),
	  SPH_C32(0xfea28c6f), SPH_C32(0x4f370006), SPH_C32(0x61ff1b80),
	  SPH_C32(0x9a4ab684), SPH_C32(0x7ac79674) },
	{ SPH_C32(0x171c0000), SPH_C32(0xb26e3344), SPH_C32(0x9e6a837e),
	  SPH_C32(0x58f8485f), SPH_C32(0xbfb20008), SPH_C32(0x92170a39),
	  SPH_C32(0x6019107f), SPH_C32(0xe051606e) },
	{ SPH_C32(0x9f3f0002), SPH_C32(0xed8994f7), SPH_C32(0x078f06d4),
	  SPH_C32(0xd58dbfae), SPH_C32(0xee1e0008), SPH_C32(0xb7f4052d),
	  SPH_C32(0x19fb3a33), SPH_C32(0xf2c9dd28) },
	{ SPH_C32(0x46b00000), SPH_C32(0x978d3c50), SPH_C32(0xe788a932),
	  SPH_C32(0x4a60f519), SPH_C32(0x663d000a), SPH_C32(0xe813a29e),
	  SPH_C32(0x801ebf99), SPH_C32(0x7fbc2ad9) },
	{ SPH_C32(0xce930002), SPH_C32(0xc86a9be3), SPH_C32(0x7e6d2c98),
	  SPH_C32(0xc71502e8), SPH_C32(0x3791000a), SPH_C32(0xcdf0ad8a),
	  SPH_C32(0xf9fc95d5), SPH_C32(0x6d24979f) },
	{ SPH_C32(0xc7140004), SPH_C32(0x3e18bc33), SPH_C32(0x03af332e),
	  SPH_C32(0xf7b26185), SPH_C32(0xd41b0008), SPH_C32(0xd2fcf393),
	  SPH_C32(0xf82b0c42), SPH_C32(0x96fda75d) },
	{ SPH_C32(0x4f370006)