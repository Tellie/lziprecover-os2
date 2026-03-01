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
#include <climits>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <stdint.h>
#include <unistd.h>

#include "lzip.h"
#include "md5.h"
#include "mtester.h"


namespace {

const char * format_byte( const uint8_t byte )
  {
  enum { buffers = 8, bufsize = 16 };
  static char buffer[buffers][bufsize];	// circle of buffers for printf
  static int current = 0;
  char * const buf = buffer[current++]; current %= buffers;
  if( ( byte >= 0x20 && byte <= 0x7E ) || byte >= 0xA0 )
    snprintf( buf, bufsize, "'%c' (0x%02X)", byte, byte );
  else
    snprintf( buf, bufsize, "    (0x%02X)", byte );
  return buf;
  }

void print_byte_pos( FILE * const f, unsigned long long byte_pos )
  { if( byte_pos ) std::fprintf( f, "byte %s\n", format_num3( byte_pos ) ); }

} // end namespace


void LZ_mtester::print_block( const int len )
  {
  std::fputs( " \"", stdout );
  for( int i = len - 1; i >= 0; --i )
    {
    uint8_t byte = peek( i );
    if( byte < 0x20 || ( byte > 0x7E && byte < 0xA0 ) ) byte = '.';
    std::fputc( byte, stdout );
    }
  std::fputs( "\"\n", stdout );
  }


void LZ_mtester::duplicate_buffer( uint8_t * const buffer2 )
  {
  if( data_position() > 0 )
    std::memcpy( buffer2, buffer, std::min( data_position(),
                                    (unsigned long long)dictionary_size ) );
  else buffer2[dictionary_size-1] = 0;		// prev_byte of first byte
  buffer = buffer2;
  buffer_is_external = true;
  }


void LZ_mtester::flush_data()
  {
  if( pos > stream_pos )
    {
    const int size = pos - stream_pos;
    crc32.update_buf( crc_, buffer + stream_pos, size );
    if( md5sum ) md5sum->md5_update( buffer + stream_pos, size );
    if( outfd >= 0 && writeblock( outfd, buffer + stream_pos, size ) != size )
      throw Error( wr_err_msg );
    if( pos >= dictionary_size )
      { partial_data_pos += pos; pos = 0; pos_wrapped = true; }
    stream_pos = pos;
    }
  }


bool LZ_mtester::check_trailer( FILE * const f, unsigned long long byte_pos )
  {
  const Lzip_trailer * const trailer = rdec.get_trailer();
  if( !trailer )
    {
    if( verbosity >= 0 && f )
      { print_byte_pos( f, byte_pos ); byte_pos = 0;
        std::fputs( "Can't get trailer.\n", f ); }
    return false;
    }
  bool error = false;

  const unsigned td_crc = trailer->data_crc();
  if( td_crc != crc() )
    {
    error = true;
    if( verbosity >= 0 && f )
      { print_byte_pos( f, byte_pos ); byte_pos = 0;
        std::fprintf( f, "CRC mismatch; stored %08X, computed %08X\n",
                      td_crc, crc() ); }
    }
  const unsigned long long data_size = data_position();
  const unsigned long long td_size = trailer->data_size();
  if( td_size != data_size )
    {
    error = true;
    if( verbosity >= 0 && f )
      { print_byte_pos( f, byte_pos ); byte_pos = 0;
        std::fprintf( f, "Data size mismatch; stored %s (0x%llX), computed %s (0x%llX)\n",
                      format_num3( td_size ), td_size,
                      format_num3( data_size ), data_size ); }
    }
  const unsigned long member_size = rdec.member_position();
  const unsigned long long tm_size = trailer->member_size();
  if( tm_size != member_size )
    {
    error = true;
    if( verbosity >= 0 && f )
      { print_byte_pos( f, byte_pos ); byte_pos = 0;
        std::fprintf( f, "Member size mismatch; stored %s (0x%llX), computed %s (0x%lX)\n",
                      format_num3( tm_size ), tm_size,
                      format_num3( member_size ), member_size ); }
    }
  return !error;
  }


/* Return value: 0 = OK, 1 = decoder error, 2 = unexpected EOF,
                 3 = trailer error, 4 = unknown marker found,
                 -1 = pos_limit reached. */
int LZ_mtester::test_member( const unsigned long mpos_limit,
                             const unsigned long long dpos_limit,
                             FILE * const f, const unsigned long long byte_pos )
  {
  if( mpos_limit < Lzip_header::size + 5 ) return -1;
  if( member_position() == Lzip_header::size && !rdec.load() ) return 1;
  while( !rdec.finished() )
    {
    if( member_position() >= mpos_limit || data_position() >= dpos_limit )
      { flush_data(); return -1; }
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
              return check_trailer( f, byte_pos ) ? 0 : 3;
            if( verbosity >= 0 && f )
              { print_byte_pos( f, byte_pos );
                std::fprintf( f, "Unsupported marker code '%d'\n", len ); }
            return 4;
            }
          }
        }
      if( dis0 > max_dis0 ) max_dis0 = dis0;
      if( dis0 >= dictionary_size || ( dis0 >= pos && !pos_wrapped ) )
        { if( outfd >= 0 ) { flush_data(); } return 1; }
      state.set_match();
      }
    copy_block( dis0, len );
    }
  if( outfd >= 0 ) flush_data();	// else no need to flush if error
  return 2;
  }


/* Return value: 0 = OK, 1 = decoder error, 2 = unexpected EOF,
                 3 = trailer error, 4 = unknown marker found. */
int LZ_mtester::debug_decode_member( const bool show_packets )
  {
  if( !rdec.load() ) return 1;
  unsigned old_tmpos = member_position();	// truncated member position
  while( !rdec.finished() )
    {
    const unsigned long long dp = data_position();
    const unsigned long long mp = member_position() - 4;
    const unsigned tmpos = member_position();
    set_max_packet( tmpos - old_tmpos, mp );
    old_tmpos = tmpos;
    ++total_packets_;
    const int pos_state = data_position() & pos_state_mask;
    if( rdec.decode_bit( bm_match[state()][pos_state] ) == 0 )	// 1st bit
      {
      // literal byte
      Bit_model * const bm = bm_literal[get_lit_state(peek_prev())];
      if( state.is_char_set_char() )
        {
        const uint8_t cur_byte = rdec.decode_tree8( bm );
        put_byte( cur_byte );
        if( show_packets )
          std::printf( "%6s %6s  literal %s\n", format_num3( mp ),
                       format_num3( dp ), format_byte( cur_byte ) );
        }
      else
        {
        const uint8_t match_byte = peek( dis0 );
        const uint8_t cur_byte = rdec.decode_matched( bm, match_byte );
        put_byte( cur_byte );
        if( show_packets )
          std::printf( "%6s %6s  literal %s, match byte [%s] %s\n",
                       format_num3( mp ), format_num3( dp ),
                       format_byte( cur_byte ), format_num3( dp, dis0 + 1 ),
                       format_byte( match_byte ) );
        }
      continue;
      }
    // match or repeated match
    int len;
    if( rdec.decode_bit( bm_rep[state()] ) != 0 )		// 2nd bit
      {
      int rep = 0;
      if( rdec.decode_bit( bm_rep0[state()] ) == 0 )		// 3rd bit
        {
        if( rdec.decode_bit( bm_len[state()][pos_state] ) == 0 ) // 4th bit
          {
          if( show_packets )
            std::printf( "%6s %6s shortrep %s (%s) [%s]\n", format_num3( mp ),
                         format_num3( dp ), format_byte( peek( dis0 ) ),
                         format_num3( dis0 + 1 ), format_num3( dp, dis0 + 1 ) );
          state.set_shortrep(); put_byte( peek( dis0 ) ); continue;
          }
        }
      else
        {
        unsigned distance;
        if( rdec.decode_bit( bm_rep1[state()] ) == 0 )		// 4th bit
          { distance = dis1; rep = 1; }
        else
          {
          if( rdec.decode_bit( bm_rep2[state()] ) == 0 )	// 5th bit
            { distance = dis2; rep = 2; }
          else
            { distance = dis3; dis3 = dis2; rep = 3; }
          dis2 = dis1;
          }
        dis1 = dis0;
        dis0 = distance;
        }
      state.set_rep();
      len = rdec.decode_len( rep_len_model, pos_state );
      if( show_packets )
        std::printf( "%6s %6s  rep%c (%s,%3u) [%s]", format_num3( mp ),
                     format_num3( dp ), rep + '0', format_num3( dis0 + 1 ),
                     len, format_num3( dp, dis0 + 1 ) );
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
            const unsigned tmpos = member_position();
            set_max_marker( tmpos - old_tmpos );
            old_tmpos = tmpos;
            if( show_packets ) std::printf( "%6s %6s  marker code '%d'\n",
                               format_num3( mp ), format_num3( dp ), len );
            if( len == min_match_len )		// End Of Stream marker
              {
              if( show_packets ) std::printf( "%6s %6s  member trailer\n",
                                 format_num3( member_position() ),
                                 format_num3( data_position() ) );
              return check_trailer( show_packets ? stdout : 0 ) ? 0 : 3;
              }
            return 4;
            }
          }
        }
      if( dis0 > max_dis0 ) { max_dis0 = dis0; max_dis0_pos = mp; }
      if( show_packets )
        std::printf( "%6s %6s  match (%s,%3u) [%s]", format_num3( mp ),
                     format_num3( dp ), format_num3( dis0 + 1 ), len,
                     format_num3( dp, dis0 + 1 ) );
      if( dis0 >= dictionary_size || ( dis0 >= pos && !pos_wrapped ) )
        { flush_data(); if( show_packets ) std::fputc( '\n', stdout );
          return 1; }
      state.set_match();
      }
    copy_block( dis0, len );
    if( show_packets ) print_block( len );
    }
  flush_data();
  return 2;
  }
