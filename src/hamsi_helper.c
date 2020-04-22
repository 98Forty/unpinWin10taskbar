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
	  SPH_C32(0x6ee56854), SP