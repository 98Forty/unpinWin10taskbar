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
	{ SPH_C32(0xc3cc0140), SPH_C32(0xfbf38e4d), SPH_C32(0x62a