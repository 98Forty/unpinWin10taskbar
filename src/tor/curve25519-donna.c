/* Copyright 2008, Google Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *     * Neither the name of Google Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * curve25519-donna: Curve25519 elliptic curve, public key function
 *
 * http://code.google.com/p/curve25519-donna/
 *
 * Adam Langley <agl@imperialviolet.org>
 *
 * Derived from public domain C code by Daniel J. Bernstein <djb@cr.yp.to>
 *
 * More information about curve25519 can be found here
 *   http://cr.yp.to/ecdh.html
 *
 * djb's sample implementation of curve25519 is written in a special assembly
 * language called qhasm and uses the floating point registers.
 *
 * This is, almost, a clean room reimplementation from the curve25519 paper. It
 * uses many of the tricks described therein. Only the crecip function is taken
 * from the sample implementation.
 */

#include "orconfig.h"

#include <string.h>
#include "torint.h"

typedef uint8_t u8;
typedef int32_t s32;
typedef int64_t limb;

/* Field element representation:
 *
 * Field elements are written as an array of signed, 64-bit limbs, least
 * significant first. The value of the field element is:
 *   x[0] + 2^26·x[1] + x^51·x[2] + 2^102·x[3] + ...
 *
 * i.e. the limbs are 26, 25, 26, 25, ... bits wide.
 */

/* Sum two numbers: output += in */
static void fsum(limb *output, const limb *in) {
  unsigned i;
  for (i = 0; i < 10; i += 2) {
    output[0+i] = (output[0+i] + in[0+i]);
    output[1+i] = (output[1+i] + in[1+i]);
  }
}

/* Find the difference of two numbers: output = in - output
 * (note the order of the arguments!)
 */
static void fdifference(limb *output, const limb *in) {
  unsigned i;
  for (i = 0; i < 10; ++i) {
    output[i] = (in[i] - output[i]);
  }
}

/* Multiply a number by a scalar: output = in * scalar */
static void fscalar_product(limb *output, const limb *in, const limb scalar) {
  unsigned i;
  for (i = 0; i < 10; ++i) {
    output[i] = in[i] * scalar;
  }
}

/* Multiply two numbers: output = in2 * in
 *
 * output must be distinct to both inputs. The inputs are reduced coefficient
 * form, the output is not.
 */
static void fproduct(limb *output, const limb *in2, const limb *in) {
  output[0] =       ((limb) ((s32) in2[0])) * ((s32) in[0]);
  output[1] =       ((limb) ((s32) in2[0])) * ((s32) in[1]) +
                    ((limb) ((s32) in2[1])) * ((s32) in[0]);
  output[2] =  2 *  ((limb) ((s32) in2[1])) * ((s32) in[1]) +
                    ((limb) ((s32) in2[0])) * ((s32) in[2]) +
                    ((limb) ((s32) in2[2])) * ((s32) in[0]);
  output[3] =       ((limb) ((s32) in2[1])) * ((s32) in[2]) +
                    ((limb) ((s32) in2[2])) * ((s32) in[1]) +
                    ((limb) ((s32) in2[0])) * ((s32) in[3]) +
                    ((limb) ((s32) in2[3])) * ((s32) in[0]);
  output[4] =       ((limb) ((s32) in2[2])) * ((s32) in[2]) +
               2 * (((limb) ((s32) in2[1])) * ((s32) in[3]) +
                    ((limb) ((s32) in2[3])) * ((s32) in[1])) +
                    ((limb) ((s32) in2[0])) * ((s32) in[4]) +
                    ((limb) ((s32) in2[4])) * ((s32) in[0]);
  output[5] =       ((limb) ((s32) in2[2])) * ((s32) in[3]) +
                    ((limb) ((s32) in2[3])) * ((s32) in[2]) +
                    ((limb) ((s32) in2[1])) * ((s32) in[4]) +
                    ((limb) ((s32) in2[4])) * ((s32) in[1]) +
                    ((limb) ((s32) in2[0])) * ((s32) in[5]) +
                    ((limb) ((s32) in2[5])) * ((s32) in[0]);
  output[6] =  2 * (((limb) ((s32) in2[3])) * ((s32) in[3]) +
                    ((limb) ((s32) in2[1])) * ((s32) in[5]) +
                    ((limb) ((s32) in2[5])) * ((s32) in[1])) +
                    ((limb) ((s32) in2[2])) * ((s32) in[4]) +
                    ((limb) ((s32) in2[4])) * ((s32) in[2]) +
                    ((limb) ((s32) in2[0])) * ((s32) in[6]) +
                    ((limb) ((s32) in2[6])) * ((s32) in[0]);
  output[7] =       ((limb) ((s32) in2[3])) * ((s32) in[4]) +
                    ((limb) ((s32) in2[4])) * ((s32) in[3]) +
                    ((limb) ((s32) in2[2])) * ((s32) in[5]) +
                    ((limb) ((s32) in2[5])) * ((s32) in[2]) +
                    ((limb) ((s32) in2[1])) * ((s32) in[6]) +
                    ((limb) ((s32) in2[6])) * ((s32) in[1]) +
                    ((limb) ((s32) in2[0])) * ((s32) in[7]) +
                    ((limb) ((s32) in2[7])) * ((s32) in[0]);
  output[8] =       ((limb) ((s32) in2[4])) * ((s32) in[4]) +
               2 * (((limb) ((s32) in2[3])) * ((s32) in[5]) +
                    ((limb) ((s32) in2[5])) * ((s32) in[3]) +
                    ((limb) ((s32) in2[1])) * ((s32) in[7]) +
                    ((limb) ((s32) in2[7])) * ((s32) in[1])) +
                    ((limb) ((s32) in2[2])) * (