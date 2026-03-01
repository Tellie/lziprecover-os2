/* Functions to compute MD5 message digest of memory blocks according to the
   definition of MD5 in RFC 1321 from April 1992.
   Copyright (C) 2020-2026 Antonio Diaz Diaz.

   This library is free software. Redistribution and use in source and
   binary forms, with or without modification, are permitted provided
   that the following conditions are met:

   1. Redistributions of source code must retain the above copyright
   notice, this list of conditions, and the following disclaimer.

   2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions, and the following disclaimer in the
   documentation and/or other materials provided with the distribution.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
*/

#define _FILE_OFFSET_BITS 64

#include <cstring>
#include <stdint.h>

#include "md5.h"


namespace {

/* These are the four functions used in the four steps of the MD5 algorithm
   as defined in RFC 1321. */
#define F(x, y, z) ((x & y) | (~x & z))
#define G(x, y, z) ((x & z) | (y & ~z))
#define H(x, y, z) (x ^ y ^ z)
#define I(x, y, z) (y ^ (x | ~z))

/* Rotate x left n bits.
   It is unfortunate that C++ does not provide an operator for rotation.
   Hope the compiler is smart enough. */
#define ROTATE_LEFT(x, n) (x = (x << n) | (x >> (32 - n)))

// FF, GG, HH, and II transformations for rounds 1, 2, 3, and 4.
#define FF(a, b, c, d, x, s, ac) \
  { a += F(b, c, d) + x + ac; ROTATE_LEFT(a, s); a += b; }
#define GG(a, b, c, d, x, s, ac) \
  { a += G(b, c, d) + x + ac; ROTATE_LEFT(a, s); a += b; }
#define HH(a, b, c, d, x, s, ac) \
  { a += H(b, c, d) + x + ac; ROTATE_LEFT(a, s); a += b; }
#define II(a, b, c, d, x, s, ac) \
  { a += I(b, c, d) + x + ac; ROTATE_LEFT(a, s); a += b; }

} // end namespace


void MD5SUM::md5_process_block( const uint8_t block[64] )
  {
  uint32_t a = state[0], b = state[1], c = state[2], d = state[3], x[16];

  for( int i = 0, j = 0; i < 16; ++i, j += 4 )	// fill x in little endian
    x[i] = block[j] | (block[j+1] << 8) | (block[j+2] << 16) | (block[j+3] << 24);

  /* Round 1 */
  FF (a, b, c, d, x[ 0],  7, 0xD76AA478);	//  1
  FF (d, a, b, c, x[ 1], 12, 0xE8C7B756);	//  2
  FF (c, d, a, b, x[ 2], 17, 0x242070DB);	//  3
  FF (b, c, d, a, x[ 3], 22, 0xC1BDCEEE);	//  4
  FF (a, b, c, d, x[ 4],  7, 0xF57C0FAF);	//  5
  FF (d, a, b, c, x[ 5], 12, 0x4787C62A);	//  6
  FF (c, d, a, b, x[ 6], 17, 0xA8304613);	//  7
  FF (b, c, d, a, x[ 7], 22, 0xFD469501);	//  8
  FF (a, b, c, d, x[ 8],  7, 0x698098D8);	//  9
  FF (d, a, b, c, x[ 9], 12, 0x8B44F7AF);	// 10
  FF (c, d, a, b, x[10], 17, 0xFFFF5BB1);	// 11
  FF (b, c, d, a, x[11], 22, 0x895CD7BE);	// 12
  FF (a, b, c, d, x[12],  7, 0x6B901122);	// 13
  FF (d, a, b, c, x[13], 12, 0xFD987193);	// 14
  FF (c, d, a, b, x[14], 17, 0xA679438E);	// 15
  FF (b, c, d, a, x[15], 22, 0x49B40821);	// 16

  /* Round 2 */
  GG (a, b, c, d, x[ 1],  5, 0xF61E2562);	// 17
  GG (d, a, b, c, x[ 6],  9, 0xC040B340);	// 18
  GG (c, d, a, b, x[11], 14, 0x265E5A51);	// 19
  GG (b, c, d, a, x[ 0], 20, 0xE9B6C7AA);	// 20
  GG (a, b, c, d, x[ 5],  5, 0xD62F105D);	// 21
  GG (d, a, b, c, x[10],  9, 0x02441453);	// 22
  GG (c, d, a, b, x[15], 14, 0xD8A1E681);	// 23
  GG (b, c, d, a, x[ 4], 20, 0xE7D3FBC8);	// 24
  GG (a, b, c, d, x[ 9],  5, 0x21E1CDE6);	// 25
  GG (d, a, b, c, x[14],  9, 0xC33707D6);	// 26
  GG (c, d, a, b, x[ 3], 14, 0xF4D50D87);	// 27
  GG (b, c, d, a, x[ 8], 20, 0x455A14ED);	// 28
  GG (a, b, c, d, x[13],  5, 0xA9E3E905);	// 29
  GG (d, a, b, c, x[ 2],  9, 0xFCEFA3F8);	// 30
  GG (c, d, a, b, x[ 7], 14, 0x676F02D9);	// 31
  GG (b, c, d, a, x[12], 20, 0x8D2A4C8A);	// 32

  /* Round 3 */
  HH (a, b, c, d, x[ 5],  4, 0xFFFA3942);	// 33
  HH (d, a, b, c, x[ 8], 11, 0x8771F681);	// 34
  HH (c, d, a, b, x[11], 16, 0x6D9D6122);	// 35
  HH (b, c, d, a, x[14], 23, 0xFDE5380C);	// 36
  HH (a, b, c, d, x[ 1],  4, 0xA4BEEA44);	// 37
  HH (d, a, b, c, x[ 4], 11, 0x4BDECFA9);	// 38
  HH (c, d, a, b, x[ 7], 16, 0xF6BB4B60);	// 39
  HH (b, c, d, a, x[10], 23, 0xBEBFBC70);	// 40
  HH (a, b, c, d, x[13],  4, 0x289B7EC6);	// 41
  HH (d, a, b, c, x[ 0], 11, 0xEAA127FA);	// 42
  HH (c, d, a, b, x[ 3], 16, 0xD4EF3085);	// 43
  HH (b, c, d, a, x[ 6], 23, 0x04881D05);	// 44
  HH (a, b, c, d, x[ 9],  4, 0xD9D4D039);	// 45
  HH (d, a, b, c, x[12], 11, 0xE6DB99E5);	// 46
  HH (c, d, a, b, x[15], 16, 0x1FA27CF8);	// 47
  HH (b, c, d, a, x[ 2], 23, 0xC4AC5665);	// 48

  /* Round 4 */
  II (a, b, c, d, x[ 0],  6, 0xF4292244);	// 49
  II (d, a, b, c, x[ 7], 10, 0x432AFF97);	// 50
  II (c, d, a, b, x[14], 15, 0xAB9423A7);	// 51
  II (b, c, d, a, x[ 5], 21, 0xFC93A039);	// 52
  II (a, b, c, d, x[12],  6, 0x655B59C3);	// 53
  II (d, a, b, c, x[ 3], 10, 0x8F0CCC92);	// 54
  II (c, d, a, b, x[10], 15, 0xFFEFF47D);	// 55
  II (b, c, d, a, x[ 1], 21, 0x85845DD1);	// 56
  II (a, b, c, d, x[ 8],  6, 0x6FA87E4F);	// 57
  II (d, a, b, c, x[15], 10, 0xFE2CE6E0);	// 58
  II (c, d, a, b, x[ 6], 15, 0xA3014314);	// 59
  II (b, c, d, a, x[13], 21, 0x4E0811A1);	// 60
  II (a, b, c, d, x[ 4],  6, 0xF7537E82);	// 61
  II (d, a, b, c, x[11], 10, 0xBD3AF235);	// 62
  II (c, d, a, b, x[ 2], 15, 0x2AD7D2BB);	// 63
  II (b, c, d, a, x[ 9], 21, 0xEB86D391);	// 64

  // add the processed values to the context
  state[0] += a; state[1] += b; state[2] += c; state[3] += d;
  }


/* Update the context for the next 'len' bytes of 'buffer'.
   'len' does not need to be a multiple of 64.
*/
void MD5SUM::md5_update( const uint8_t * const buffer, const unsigned long len )
  {
  unsigned index = count & 0x3F;	// data length in bytes mod 64
  count += len;				// update data length
  const unsigned rest = 64 - index;
  unsigned long i;

  if( len >= rest )			// process as many bytes as possible
    {
    std::memcpy( ibuf + index, buffer, rest );
    md5_process_block( ibuf );
    for( i = rest; i + 63 < len; i += 64 )
      md5_process_block( buffer + i );
    index = 0;
    }
  else i = 0;

  std::memcpy( ibuf + index, buffer + i, len - i );	// save remaining input
  }


// finish computation and return the digest
void MD5SUM::md5_finish( md5_type & digest )
  {
  uint8_t padding[64] = {
    0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    };
  uint8_t bits[8];
  uint64_t c = count << 3;		// save data length in bits
  for( int i = 0; i <= 7; ++i ) { bits[i] = (uint8_t)c; c >>= 8; }

  const unsigned index = count & 0x3F;	// data length in bytes mod 64
  const unsigned len = (index < 56) ? (56 - index) : (120 - index);
  md5_update( padding, len );		// pad to 56 mod 64
  md5_update( bits, 8 );		// append data length in bits

  for( int i = 0, j = 0; i < 4; ++i, j += 4 )	// store state in digest
    {
    digest[j  ] = (uint8_t)state[i];
    digest[j+1] = (uint8_t)(state[i] >>  8);
    digest[j+2] = (uint8_t)(state[i] >> 16);
    digest[j+3] = (uint8_t)(state[i] >> 24);
    }
  }


void compute_md5( const uint8_t * const buffer, const unsigned long len,
                  md5_type & digest )
  {
  MD5SUM md5sum;
  if( len > 0 ) md5sum.md5_update( buffer, len );
  md5sum.md5_finish( digest );
  }


bool check_md5( const uint8_t * const buffer, const unsigned long len,
                const md5_type & digest )
  {
  md5_type new_digest;
  compute_md5( buffer, len, new_digest );
  return digest == new_digest;
  }
