/* Lziprecover - Data recovery tool
   Copyright (C) 2023-2026 Antonio Diaz Diaz.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 2 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#define _FILE_OFFSET_BITS 64

#include <cstdio>
#include <cstring>
#include <list>
#include <string>
#include <vector>
#include <stdint.h>
#include <unistd.h>	// STDERR_FILENO

#include "lzip.h"
#include "md5.h"
#include "fec.h"

namespace {

const uint16_t u16_one = 1;
const bool little_endian = *(const uint8_t *)&u16_one == 1;
inline uint16_t swap_bytes( const uint16_t a )
  { return ( a >> 8 ) | ( a << 8 ); }

struct Galois16_table		// addition/subtraction is exclusive or
  {
  enum { size = 1 << 16, poly = 0x1100B };	// generator polynomial
  uint16_t * log, * ilog, * mul_tables;

  Galois16_table() : log( 0 ), ilog( 0 ), mul_tables( 0 ) {}
  ~Galois16_table() { delete[] mul_tables; delete[] ilog; delete[] log; }

  void init()	// fill log, inverse log, and multiplication tables
    {
    if( log ) return;
    log = new uint16_t[size]; ilog = new uint16_t[size];
    mul_tables = new uint16_t[3 * 256 * 256];		// LL, LH, HH
    for( unsigned b = 1, i = 0; i < size - 1; ++i )
      {
      log[b] = i;
      ilog[i] = b;
      b <<= 1;
      if( b & size ) b ^= poly;
      }
    log[0] = size - 1;	// log(0) is not defined, so use a special value
    ilog[size-1] = 1;

    uint16_t * p = mul_tables;
    for( int i = 0; i < 16; i += 8 )
      for( int j = i; j < 16; j += 8 )
        for( int a = 0; a < 256 << i; a += 1 << i )
          for( int b = 0; b < 256 << j; b += 1 << j )
            *p++ = mul( a, b );
    }

  uint16_t mul( const uint16_t a, const uint16_t b ) const
    {
    if( a == 0 || b == 0 ) return 0;
    const unsigned sum = log[a] + log[b];
    return ( sum >= size - 1 ) ? ilog[sum-(size-1)] : ilog[sum];
    }

  uint16_t inverse( const uint16_t a ) const { return ilog[size-1-log[a]]; }
  } gf;


inline bool check_element( const uint16_t * const A, const uint16_t * const B,
                    const unsigned k, const unsigned row, const unsigned col )
  {
  const uint16_t * pa = A + row * k;
  const uint16_t * pb = B + col;
  uint16_t sum = 0;
  for( unsigned i = 0; i < k; ++i, ++pa, pb += k )
    sum ^= gf.mul( *pa, *pb );
  return sum == ( row == col );
  }

/* Check that A * B = I (A, B, I are square matrices of size k * k).
   Check just the diagonals for matrices larger than 1024 x 1024. */
bool check_inverse( const uint16_t * const A, const uint16_t * const B,
                    const unsigned k )
  {
  const bool print = verbosity >= 1 && k > max_k8 && isatty( STDERR_FILENO );
  for( unsigned row = 0; row < k; ++row )	// multiply A * B
    {
    if( k <= 1024 )
      for( unsigned col = 0; col < k; ++col )
        { if( !check_element( A, B, k, row, col ) )
            { if( print && row ) std::fputc( '\n', stderr ); return false; } }
    else
      if( !check_element( A, B, k, row, row ) ||
          !check_element( A, B, k, row, k - 1 - row ) )
        { if( print && row ) std::fputc( '\n', stderr ); return false; }
    if( print ) std::fprintf( stderr, "\r%5u rows checked \r", row + 1 );
    }
  return true;
  }


/* Invert in place a matrix of size k * k.
   This is like Gaussian elimination with a virtual identity matrix:
   A --some_changes--> I, I --same_changes--> A^-1
   Galois arithmetic is exact. Swapping rows or columns is not needed. */
bool invert_matrix( uint16_t * const matrix, const unsigned k )
  {
  const bool print = verbosity >= 1 && k > max_k8 && isatty( STDERR_FILENO );
  for( unsigned row = 0; row < k; ++row )
    {
    uint16_t * const pivot_row = matrix + row * k;
    uint16_t pivot = pivot_row[row];
    if( pivot == 0 )
      { if( print && row ) std::fputc( '\n', stderr ); return false; }
    if( pivot != 1 )				// scale the pivot_row
      {
      pivot = gf.inverse( pivot );
      pivot_row[row] = 1;
      for( unsigned col = 0; col < k; ++col )
        pivot_row[col] = gf.mul( pivot_row[col], pivot );
      }
    // subtract pivot_row from the other rows
    for( unsigned row2 = 0; row2 < k; ++row2 )
      if( row2 != row )
        {
        uint16_t * const dst_row = matrix + row2 * k;
        const uint16_t c = dst_row[row]; dst_row[row] = 0;
        for( unsigned col = 0; col < k; ++col )
          dst_row[col] ^= gf.mul( pivot_row[col], c );
        }
    if( print ) std::fprintf( stderr, "\r%5u rows inverted\r", row + 1 );
    }
  return true;
  }


// create dec_matrix containing only the rows needed and invert it in place
const uint16_t * init_dec_matrix( const std::vector< unsigned > & bb_vector,
                                  const std::vector< unsigned > & fbn_vector )
  {
  const unsigned bad_blocks = bb_vector.size();
  uint16_t * const dec_matrix = new uint16_t[bad_blocks * bad_blocks];

  // one row for each missing data block
  for( unsigned row = 0; row < bad_blocks; ++row )
    {
    uint16_t * const dec_row = dec_matrix + row * bad_blocks;
    const unsigned fbn = fbn_vector[row] | 0x8000;
    for( unsigned col = 0; col < bad_blocks; ++col )
      dec_row[col] = gf.inverse( fbn ^ bb_vector[col] );
    }
  if( !invert_matrix( dec_matrix, bad_blocks ) )
    internal_error( "GF(2^16) matrix not invertible." );
  return dec_matrix;
  }


/* compute dst[] += c * src[]
   treat the buffers as arrays of pairs of 16-bit Galois values */
inline void mul_add( const uint8_t * const src, uint8_t * const dst,
                     const unsigned long fbs, const uint16_t c )
  {
  if( c == 0 ) return;				// nothing to add
  const int cl = c & 0xFF;	// split factor c into low and high bytes
  const int ch = c >> 8;
  // pointers to the four multiplication tables (c.low/high * src.low/high)
  const uint16_t * LL = &gf.mul_tables[cl * 256];
  const uint16_t * LH = &gf.mul_tables[65536 + cl * 256];
  const uint16_t * HL = &gf.mul_tables[65536 + ch];		// step 256
  const uint16_t * HH = &gf.mul_tables[131072 + ch * 256];
  uint16_t L[256];		// extract the two tables for factor c
  uint16_t H[256];

  if( little_endian )
    for( int i = 0; i < 256; ++i )
      { L[i] = *LL++ ^ *HL; HL+=256; H[i] = *LH++ ^ *HH++; }
  else	// big endian
    for( int i = 0; i < 256; ++i )
      { H[i] = swap_bytes( *LL++ ^ *HL ); HL+=256;
        L[i] = swap_bytes( *LH++ ^ *HH++ ); }

  const uint32_t * const src32 = (const uint32_t *)src;
  uint32_t * const dst32 = (uint32_t *)dst;

  for( unsigned long i = 0; i < fbs / 4; ++i )
    { const uint32_t s = src32[i];
      dst32[i] ^= L[s & 0xFF] ^ H[s >> 8 & 0xFF] ^
                  L[s >> 16 & 0xFF] << 16 ^ H[s >> 24] << 16; }
  }

} // end namespace


void gf16_init() { gf.init(); }

bool gf16_check( const std::vector< unsigned > & fbn_vector, const unsigned k )
  {
  if( k == 0 ) return true;
  gf.init();
  bool good = true;
  for( unsigned a = 1; a < gf.size; ++a )
    if( gf.mul( a, gf.inverse( a ) ) != 1 )
      { good = false;
        std::fprintf( stderr, "%u * ( 1/%u ) != 1 in GF(2^16)\n", a, a ); }
  uint16_t * const enc_matrix = new uint16_t[k * k];
  uint16_t * const dec_matrix = new uint16_t[k * k];
  const bool random = fbn_vector.size() == k;
  for( unsigned row = 0; row < k; ++row )
    {
    const unsigned fbn = ( random ? fbn_vector[row] : row ) | 0x8000;
    uint16_t * const enc_row = enc_matrix + row * k;
    for( unsigned col = 0; col < k; ++col )
      enc_row[col] = gf.inverse( fbn ^ col );
    }
  std::memcpy( dec_matrix, enc_matrix, k * k * sizeof (uint16_t) );
  if( !invert_matrix( dec_matrix, k ) )
    { good = false; show_error( "GF(2^16) matrix not invertible." ); }
  else if( !check_inverse( enc_matrix, dec_matrix, k ) )
    { good = false; show_error( "GF(2^16) matrix A * A^-1 != I" ); }
  delete[] dec_matrix;
  delete[] enc_matrix;
  return good;
  }


void rs16_encode( const uint8_t * const buffer, const uint8_t * const lastbuf,
                  uint8_t * const fec_block, const unsigned long fbs,
                  const unsigned fbn, const unsigned k )
  {
  if( !gf.log ) internal_error( "GF(2^16) tables not initialized." );
  /* The encode matrix is a Hilbert matrix of size k * k with one row per
     fec block and one column per data block.
     The value of each element is computed on the fly with inverse. */
  const unsigned row = fbn | 0x8000;
  std::memset( fec_block, 0, fbs );
  for( unsigned col = 0; col < k; ++col )
    {
    const uint8_t * const src =
      ( col < k - (lastbuf != 0) ) ? buffer + col * fbs : lastbuf;
    mul_add( src, fec_block, fbs, gf.inverse( row ^ col ) );
    }
  }


void rs16_decode( const uint8_t * const buffer, const uint8_t * const lastbuf,
                  const std::vector< unsigned > & bb_vector,
                  const std::vector< unsigned > & fbn_vector,
                  uint8_t * const fecbuf, uint8_t * const dstbuf,
                  const unsigned long fbs, const unsigned k )
  {
  gf.init();
  const unsigned bad_blocks = bb_vector.size();
  for( unsigned col = 0, bi = 0; col < k; ++col )	// reduce
    {
    if( bi < bad_blocks && col == bb_vector[bi] ) { ++bi; continue; }
    const uint8_t * const src =
      ( col < k - (lastbuf != 0) ) ? buffer + col * fbs : lastbuf;
    for( unsigned row = 0; row < bad_blocks; ++row )
      {
      const unsigned fbn = fbn_vector[row] | 0x8000;
      mul_add( src, fecbuf + row * fbs, fbs, gf.inverse( fbn ^ col ) );
      }
    }
  const uint16_t * const dec_matrix = init_dec_matrix( bb_vector, fbn_vector );
  for( unsigned col = 0; col < bad_blocks; ++col )	// solve
    {
    uint8_t * const dst = dstbuf + col * fbs;
    std::memset( dst, 0, fbs );
    const uint16_t * const dec_row = dec_matrix + col * bad_blocks;
    for( unsigned row = 0; row < bad_blocks; ++row )
      mul_add( fecbuf + row * fbs, dst, fbs, dec_row[row] );
    }
  delete[] dec_matrix;
  }
