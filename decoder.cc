/* Lziprecover - Data recovery tool
   Copyright (C) 2009-2026 Antonio Diaz Diaz.

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

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <stdint.h>
#include <unistd.h>

#include "lzip.h"
#include "decoder.h"


const CRC32 crc32;


/* Return the number of bytes really read.
   If (value returned < size) and (errno == 0), means EOF was reached.
*/
long readblock( const int fd, uint8_t * const buf, const long size )
  {
  long sz = 0;
  errno = 0;
  while( sz < size )
    {
    const long n = read( fd, buf + sz, size - sz );
    if( n > 0 ) sz += n;
    else if( n == 0 ) break;				// EOF
    else if( errno != EINTR ) break;
    errno = 0;
    }
  return sz;
  }


/* Return the number of bytes really written.
   If (value returned < size), it is always an error.
*/
long writeblock( const int fd, const uint8_t * const buf, const long size )
  {
  long sz = 0;
  errno = 0;
  while( sz < size )
    {
    const long n = write( fd, buf + sz, size - sz );
    if( n > 0 ) sz += n;
    else if( n < 0 && errno != EINTR ) break;
    errno = 0;
    }
  return sz;
  }


bool Range_decoder::read_block()
  {
  if( !at_stream_end )
    {
    stream_pos = readblock( infd, buffer, buffer_size );
    if( stream_pos != buffer_size && errno ) throw Error( rd_err_msg );
    at_stream_end = stream_pos < buffer_size;
    partial_member_pos += pos;
    pos = 0;
    show_dprogress();
    }
  return pos < stream_pos;
  }


void LZ_decoder::flush_data()
  {
  if( pos > stream_pos )
    {
    const int size = pos - stream_pos;
    crc32.update_buf( crc_, buffer + stream_pos, size );
    if( outfd >= 0 )
      {
      const unsigned long long sp = stream_position();
      const long long i = positive_diff( outskip, sp );
      const long long s =
        std::min( positive_diff( outend, sp ), (unsigned long long)size ) - i;
      if( s > 0 && writeblock( outfd, buffer + stream_pos + i, s ) != s )
        throw Error( wr_err_msg );
      }
    if( pos >= dictionary_size )
      { partial_data_pos += pos; pos = 0; pos_wrapped = true; }
    stream_pos = pos;
    }
  }


bool LZ_decoder::check_trailer( const Pretty_print & pp ) const
  {
  Lzip_trailer trailer;
  int size = rdec.read_data( trailer.data, trailer.size );
  bool error = false;

  if( size < trailer.size )
    {
    error = true;
    if( verbosity >= 0 )
      { pp();
        std::fprintf( stderr, "Trailer truncated at trailer position %d;"
                              " some checks may fail.\n", size ); }
    while( size < trailer.size ) trailer.data[size++] = 0;
    }

  const unsigned td_crc = trailer.data_crc();
  if( td_crc != crc() )
    {
    error = true;
    if( verbosity >= 0 )
      { pp();
        std::fprintf( stderr, "CRC mismatch; stored %08X, computed %08X\n",
                      td_crc, crc() ); }
    }
  const unsigned long long data_size = data_position();
  const unsigned long long td_size = trailer.data_size();
  if( td_size != data_size )
    {
    error = true;
    if( verbosity >= 0 )
      { pp();
        std::fprintf( stderr, "Data size mismatch; stored %s (0x%llX), computed %s (0x%llX)\n",
                      format_num3( td_size ), td_size,
                      format_num3( data_size ), data_size ); }
    }
  const unsigned long long member_size = rdec.member_position();
  const unsigned long long tm_size = trailer.member_size();
  if( tm_size != member_size )
    {
    error = true;
    if( verbosity >= 0 )
      { pp();
        std::fprintf( stderr, "Member size mismatch; stored %s (0x%llX), computed %s (0x%llX)\n",
                      format_num3( tm_size ), tm_size,
                      format_num3( member_size ), member_size ); }
    }
  if( error ) return false;
  if( verbosity >= 2 )
    {
    if( verbosity >= 4 ) show_header( dictionary_size );
    if( verbosity >= 3 && data_size > 0 && member_size > 0 )
      std::fprintf( stderr, "%6.3f:1, %5.2f%% ratio, %5.2f%% saved, ",
                    (double)data_size / member_size,
                    ( 100.0 * member_size ) / data_size,
                    100.0 - ( ( 100.0 * member_size ) / data_size ) );
    if( verbosity >= 4 ) std::fprintf( stderr, "CRC %08X, ", td_crc );
    std::fprintf( stderr, "%11s out, %10s in. ",
                  format_num3( data_size ), format_num3( member_size ) );
    }
  if( rdec.get_code() != 0 && verbosity >= 1 )
    {			// corruption in the last 4 bytes of the EOS marker
    pp();
    std::fprintf( stderr, "Range decoder final code is %08X\n", rdec.get_code() );
    }
  return true;
  }


/* Return value: 0 = OK, 1 = decoder error, 2 = unexpected EOF,
                 3 = trailer error, 4 = unknown marker found,
                 5 = nonzero first LZMA byte found. */
int LZ_decoder::decode_member( const Pretty_print & pp,
                               const bool ignore_nonzero )
  {
  Bit_model bm_literal[1<<literal_context_bits][0x300];
  Bit_model bm_match[State::states][pos_states];
  Bit_model bm_rep[State::states];
  Bit_model bm_rep0[State::states];
  Bit_model bm_rep1[State::states];
  Bit_model bm_rep2[State::states];
  Bit_model bm_len[State::states][pos_states];
  Bit_model bm_dis_slot[len_states][1<<dis_slot_bits];
  Bit_model bm_dis[modeled_distances-end_dis_model+1];
  Bit_model bm_align[dis_align_size];
  Len_model match_len_model;
  Len_model rep_len_model;
  unsigned dis0 = 0;		// dis[0-3] latest four distances
  unsigned dis1 = 0;		// used for efficient coding of
  unsigned dis2 = 0;		// repeated distances
  unsigned dis3 = 0;
  State state;

  if( !rdec.load( ignore_nonzero ) ) return 5;
  while( !rdec.finished() )
    {
    const int pos_state = data_position() & pos_state_mask;
    if( rdec.decode_bit( bm_match[state()][pos_state] ) == 0 )	// 1st bit
      {
      // literal byte
      Bit_model * const bm = bm_literal[get_lit_state(peek_prev())];
      if( state.is_char_set_char() )
        put_byte( rdec.decode_tree8( bm ) );
      else
        put_byte( rdec.decode_matched( bm, peek( dis0 ) ) );
      continue;
      }
    // match or repeated match
    int len;
    if( rdec.decode_bit( bm_rep[state()] ) != 0 )		// 2nd bit
      {
      if( rdec.decode_bit( bm_rep0[state()] ) == 0 )		// 3rd bit
        {
        if( rdec.decode_bit( bm_len[state()][pos_state] ) == 0 ) // 4th bit
          { state.set_shortrep(); put_byte( peek( dis0 ) ); continue; }
        }
      else
        {
        unsigned distance;
        if( rdec.decode_bit( bm_rep1[state()] ) == 0 )		// 4th bit
          distance = dis1;
        else
          {
          if( rdec.decode_bit( bm_rep2[state()] ) == 0 )	// 5th bit
            distance = dis2;
          else
            { distance = dis3; dis3 = dis2; }
          dis2 = dis1;
          }
        dis1 = dis0;
        dis0 = distance;
        }
      state.set_rep();
      len = rdec.decode_len( rep_len_model, pos_state );
      }
    else					// match
      {
      dis3 = dis2; dis2 = dis1; dis1 = dis0;
      len = rdec.decode_len( match_len_model, pos_state );
      dis0 = rdec.decode_tree6( bm_dis_slot[get_len_state(len)] );
      if( dis0 >= start_dis_model )
        {
        const unsigned dis_slot = dis0;
        const int direct_bits = ( dis_slot >> 1 ) - 1;
        dis0 = ( 2 | ( dis_slot & 1 ) ) << direct_bits;
        if( dis_slot < end_dis_model )
          dis0 += rdec.decode_tree_reversed( bm_dis + ( dis0 - dis_slot ),
                                             direct_bits );
        else
          {
          dis0 += rdec.decode( direct_bits - dis_align_bits ) << dis_align_bits;
          dis0 += rdec.decode_tree_reversed4( bm_align );
          if( dis0 == 0xFFFFFFFFU )		// marker found
            {
            rdec.normalize();
            flush_data();
            if( len == min_match_len )		// End Of Stream marker
              return check_trailer( pp ) ? 0 : 3;
            if( verbosity >= 0 ) { pp();
              std::fprintf( stderr, "Unsupported marker code '%d'\n", len ); }
            return 4;
            }
          }
        }
      if( dis0 >= dictionary_size || ( dis0 >= pos && !pos_wrapped ) )
        { flush_data(); return 1; }
      state.set_match();
      }
    copy_block( dis0, len );
    }
  flush_data();
  return 2;
  }
