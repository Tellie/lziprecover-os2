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

#include "lzip.h"
#include "md5.h"
#include "fec.h"

namespace {

struct Galois8_table		// addition/subtraction is exclusive or
  {
  enum { size = 1 << 8, poly = 0x11D };		// generator polynomial
  uint8_t * log, * ilog, * mul_table;

  Galois8_table() : log( 0 ), ilog( 0 ), mul_table( 0 ) {}
  ~Galois8_table() { delete[] mul_table; delete[] ilog; delete[] log; }

  void init()	// fill log, inverse log, and multiplication tables
    {
    if( log ) return;
    log = new uint8_t[size]; ilog = new uint8_t[size];
    mul_table = new uint8_t[size * size];
    for( unsigned b = 1, i = 0; i < size - 1; ++i )
      {
      log[b] = i;
      ilog[i] = b;
      b <<= 1;
      if( b & size ) b ^= poly;
      }
    log[0] = size - 1;	// log(0) is not defined, so use a special value
    ilog[size-1] = 1;

    for( int i = 1; i < size; ++i )
      {
      uint8_t * const mul_row = mul_table + i * size;
      for( int j = 1; j < size; ++j )
        mul_row[j] = ilog[(log[i] + log[j]) % (size-1)];
      }
    for( int i = 0; i < size; ++i )
      mul_table[0 * size + i] = mul_table[i * size + 0] = 0;
    }

  uint8_t inverse( const uint8_t a ) const { return ilog[size-1-log[a]]; }
  } gf;


// check that A * B = I (A, B, I are square matrices of size k * k)
bool check_inverse( const uint8_t * const A, const uint8_t * const B,
                    const unsigned k )
  {
  for( unsigned row = 0; row < k; ++row )	// multiply A * B
    for( unsigned col = 0; col < k; ++col )
      {
      const uint8_t * pa = A + row * k;
      const uint8_t * pb = B + col;
      uint8_t sum = 0;
      for( unsigned i = 0; i < k; ++i, ++pa, pb += k )
        sum ^= gf.mul_table[*pa * gf.size + *pb];
      if( sum != ( row == col ) ) return false;
      }
  return true;
  }


/* Invert in place a matrix of size k * k.
   This is like Gaussian elimination with a virtual identity matrix:
   A --some_changes--> I, I --same_changes--> A^-1
   Galois arithmetic is exact. Swapping rows or columns is not needed. */
bool invert_matrix( uint8_t * const matrix, const unsigned k )
  {
  for( unsigned row = 0; row < k; ++row )
    {
    uint8_t * const pivot_row = matrix + row * k;
    const uint8_t pivot = pivot_row[row];
    if( pivot == 0 ) return false;
    if( pivot != 1 )				// scale the pivot_row
      {
      const uint8_t * const mul_row =
        gf.mul_table + gf.inverse( pivot ) * gf.size;
      pivot_row[row] = 1;
      for( unsigned col = 0; col < k; ++col )
        pivot_row[col] = mul_row[pivot_row[col]];
      }
    // subtract pivot_row from the other rows
    for( unsigned row2 = 0; row2 < k; ++row2 )
      if( row2 != row )
        {
        uint8_t * const dst_row = matrix + row2 * k;
        const uint8_t c = dst_row[row]; dst_row[row] = 0;
        const uint8_t * const mul_row = gf.mul_table + c * gf.size;
        for( unsigned col = 0; col < k; ++col )
          dst_row[col] ^= mul_row[pivot_row[col]];
        }
    }
  return true;
  }


// create dec_matrix containing only the rows needed and invert it in place
const uint8_t * init_dec_matrix( const std::vector< unsigned > & bb_vector,
                                 const std::vector< unsigned > & fbn_vector )
  {
  const unsigned bad_blocks = bb_vector.size();
  uint8_t * const dec_matrix = new uint8_t[bad_blocks * bad_blocks];

  // one row for each missing data block
  for( unsigned row = 0; row < bad_blocks; ++row )
    {
    uint8_t * const dec_row = dec_matrix + row * bad_blocks;
    const unsigned fbn = fbn_vector[row] | 0x80;
    for( unsigned col = 0; col < bad_blocks; ++col )
      dec_row[col] = gf.inverse( fbn ^ bb_vector[col] );
    }
  if( !invert_matrix( dec_matrix, bad_blocks ) )
    internal_error( "GF(2^8) matrix not invertible." );
  return dec_matrix;
  }


/* compute dst[] += c * src[]
   treat the buffers as arrays of quadruples of 8-bit Galois values */
inline void mul_add( const uint8_t * const src, uint8_t * const dst,
                     const unsigned long fbs, const uint8_t c )
  {
  if( c == 0 ) return;				// nothing to add
  const uint8_t * const mul_row = gf.mul_table + c * gf.size;
  const uint32_t * const src32 = (const uint32_t *)src;
  uint32_t * const dst32 = (uint32_t *)dst;

  for( unsigned long i = 0; i < fbs / 4; ++i )
    { const uint32_t s = src32[i];
      dst32[i] ^= mul_row[s & 0xFF] ^ mul_row[s >> 8 & 0xFF] << 8 ^
                  mul_row[s >> 16 & 0xFF] << 16 ^ mul_row[s >> 24] << 24; }
  }

} // end namespace


void gf8_init() { gf.init(); }

bool gf8_check( const std::vector< unsigned > & fbn_vector, const unsigned k )
  {
  if( k == 0 ) return true;
  gf.init();
  bool good = true;
  for( unsigned a = 1; a < gf.size; ++a )
    if( gf.mul_table[a * gf.size + gf.inverse( a )] != 1 )
      { good = false;
        std::fprintf( stderr, "%u * ( 1/%u ) != 1 in GF(2^8)\n", a, a ); }
  uint8_t * const enc_matrix = new uint8_t[k * k];
  uint8_t * const dec_matrix = new uint8_t[k * k];
  const bool random = fbn_vector.size() == k;
  for( unsigned row = 0; row < k; ++row )
    {
    const unsigned fbn = ( random ? fbn_vector[row] : row ) | 0x80;
    uint8_t * const enc_row = enc_matrix + row * k;
    for( unsigned col = 0; col < k; ++col )
      enc_row[col] = gf.inverse( fbn ^ col );
    }
  std::memcpy( dec_matrix, enc_matrix, k * k );
  if( !invert_matrix( dec_matrix, k ) )
    { good = false; show_error( "GF(2^8) matrix not invertible." ); }
  else if( !check_inverse( enc_matrix, dec_matrix, k ) )
    { good = false; show_error( "GF(2^8) matrix A * A^-1 != I" ); }
  delete[] dec_matrix;
  delete[] enc_matrix;
  return good;
  }


void rs8_encode( const uint8_t * const buffer, const uint8_t * const lastbuf,
                 uint8_t * const fec_block, const unsigned long fbs,
                 const unsigned fbn, const unsigned k )
  {
  if( !gf.log ) internal_error( "GF(2^8) tables not initialized." );
  /* The encode matrix is a Hilbert matrix of size k * k with one row per
     fec block and one column per data block.
     The value of each element is computed on the fly with inverse. */
  const unsigned row = fbn | 0x80;
  std::memset( fec_block, 0, fbs );
  for( unsigned col = 0; col < k; ++col )
    {
    const uint8_t * const src =
      ( col < k - (lastbuf != 0) ) ? buffer + col * fbs : lastbuf;
    mul_add( src, fec_block, fbs, gf.inverse( row ^ col ) );
    }
  }


void rs8_decode( const uint8_t * const buffer, const uint8_t * const lastbuf,
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
      const unsigned fbn = fbn_vector[row] | 0x80;
      mul_add( src, fecbuf + row * fbs, fbs, gf.inverse( fbn ^ col ) );
      }
    }
  const uint8_t * const dec_matrix = init_dec_matrix( bb_vector, fbn_vector );
  for( unsigned col = 0; col < bad_blocks; ++col )	// solve
    {
    uint8_t * const dst = dstbuf + col * fbs;
    std::memset( dst, 0, fbs );
    const uint8_t * const dec_row = dec_matrix + col * bad_blocks;
    for( unsigned row = 0; row < bad_blocks; ++row )
      mul_add( fecbuf + row * fbs, dst, fbs, dec_row[row] );
    }
  delete[] dec_matrix;
  }
