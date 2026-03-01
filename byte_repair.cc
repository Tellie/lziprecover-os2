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
#include <sys/stat.h>

#include "lzip.h"
#include "mtester.h"
#include "lzip_index.h"


namespace {

bool pending_newline = false;

void print_pending_newline( const char terminator )
  { if( pending_newline && terminator != '\n' ) std::fputc( '\n', stdout );
    pending_newline = false; }


bool gross_damage( const uint8_t * const mbuffer, const long msize )
  {
  enum { maxlen = 7 };		// max number of consecutive identical bytes
  long i = Lzip_header::size;
  const long end = msize - Lzip_trailer::size - maxlen;
  while( i < end )
    {
    const uint8_t byte = mbuffer[i];
    int len = 0;			// does not count the first byte
    while( mbuffer[++i] == byte ) if( ++len >= maxlen ) return true;
    }
  return false;
  }


// Return value: 0 = errors remain, 6 = repaired pos
int repair_nonzero( uint8_t * const mbuffer, const long msize )
  {
  mbuffer[6] = 0;
  const Lzip_header & header = *(Lzip_header *)mbuffer;
  const unsigned dictionary_size = header.dictionary_size();
  if( !isvalid_ds( dictionary_size ) ) return 0;
  LZ_mtester mtester( mbuffer, msize, dictionary_size );
  if( mtester.test_member() == 0 ) return 6;
  return 0;
  }


// Return value: 0 = no change, 5 = repaired pos
int repair_dictionary_size( uint8_t * const mbuffer, const long msize )
  {
  Lzip_header & header = *(Lzip_header *)mbuffer;
  unsigned dictionary_size = header.dictionary_size();
  const Lzip_trailer & trailer =
    *(const Lzip_trailer *)( mbuffer + msize - trailer.size );
  const unsigned long long data_size = trailer.data_size();
  const bool valid_ds = isvalid_ds( dictionary_size );
  if( valid_ds && dictionary_size >= data_size ) return 0;	// can't be bad

  const unsigned long long dict_size_9 = 1 << 25;	// dict size of opt -9
  if( !valid_ds || dictionary_size < dict_size_9 )
    {
    dictionary_size = std::min( data_size, dict_size_9 );
    if( dictionary_size < min_dictionary_size )
      dictionary_size = min_dictionary_size;
    LZ_mtester mtester( mbuffer, msize, dictionary_size );
    const int result = mtester.test_member();
    if( result == 0 )
      { header.dictionary_size( dictionary_size ); return 5; }	// fix DS
    if( result != 1 || mtester.max_distance() <= dictionary_size ||
        mtester.max_distance() > max_dictionary_size ) return 0;
    }
  if( data_size > dict_size_9 )
    {
    dictionary_size =
      std::min( data_size, (unsigned long long)max_dictionary_size );
    LZ_mtester mtester( mbuffer, msize, dictionary_size );
    if( mtester.test_member() == 0 )
      { header.dictionary_size( dictionary_size ); return 5; }	// fix DS
    }
  return 0;
  }


const LZ_mtester * prepare_master( const uint8_t * const buffer,
                                   const long buffer_size,
                                   const unsigned long pos_limit,
                                   const unsigned dictionary_size )
  {
  LZ_mtester * const master =
    new LZ_mtester( buffer, buffer_size, dictionary_size );
  if( master->test_member( pos_limit ) == -1 ) return master;
  delete master;
  return 0;
  }


bool test_member_rest( const LZ_mtester & master, uint8_t * const buffer2,
                       long * const failure_posp = 0 )
  {
  LZ_mtester mtester( master );		// tester with external buffer
  mtester.duplicate_buffer( buffer2 );
  if( mtester.test_member() == 0 && mtester.finished() ) return true;
  if( failure_posp ) *failure_posp = mtester.member_position();
  return false;
  }


// Return value: -1 = master failed, 0 = begin reached, > 0 = repaired pos
long repair_member( uint8_t * const mbuffer, const long long mpos,
                    const long msize, const long begin, const long end,
                    const unsigned dictionary_size, const char terminator )
  {
  uint8_t * const buffer2 = new uint8_t[dictionary_size];
  for( long pos = end; pos >= begin && pos > end - 50000; )
    {
    const long min_pos = std::max( begin, pos - 100 );
    const unsigned long pos_limit = std::max( min_pos - 16, 0L );
    const LZ_mtester * master =
      prepare_master( mbuffer, msize, pos_limit, dictionary_size );
    if( !master ) { delete[] buffer2; return -1; }
    for( ; pos >= min_pos; --pos )
      {
      if( verbosity >= 2 )
        {
        std::printf( "  Trying position %s %c",
                     format_num3( mpos + pos ), terminator );
        std::fflush( stdout ); pending_newline = true;
        }
      for( int j = 0; j < 255; ++j )
        {
        ++mbuffer[pos];
        if( test_member_rest( *master, buffer2 ) )
          { delete master; delete[] buffer2; return pos; }
        }
      ++mbuffer[pos];
      }
    delete master;
    }
  delete[] buffer2;
  return 0;
  }

} // end namespace


bool safe_seek( const int fd, const long long pos,
                const std::string & filename )
  {
  if( lseek( fd, pos, SEEK_SET ) == pos ) return true;
  show_file_error( filename.c_str(), "Seek error", errno );
  return false;
  }


long seek_write( const int fd, const uint8_t * const buf, const long size,
                 const long long pos )
  {
  if( lseek( fd, pos, SEEK_SET ) == pos )
    return writeblock( fd, buf, size );
  return 0;
  }


uint8_t * read_member( const int infd, const long long mpos,
                       const long long msize, const std::string & filename )
  {
  if( msize <= 0 || msize > LONG_MAX )
    { show_file_error( filename.c_str(),
        "Input file contains member larger than LONG_MAX." ); return 0; }
  if( !safe_seek( infd, mpos, filename ) ) return 0;
  uint8_t * const buffer = new uint8_t[msize];

  if( readblock( infd, buffer, msize ) != msize )
    { show_file_error( filename.c_str(), rd_err_msg, errno );
      delete[] buffer; return 0; }
  return buffer;
  }


int byte_repair( const std::string & input_filename,
                 const std::string & default_output_filename,
                 const Cl_options & cl_opts,
                 const char terminator, const bool force )
  {
  const char * const filename = input_filename.c_str();
  struct stat in_stats;
  const int infd = open_instream( filename, &in_stats, false, true );
  if( infd < 0 ) return 1;

  const Lzip_index lzip_index( infd, cl_opts, true );
  if( lzip_index.retval() != 0 )
    { show_file_error( filename, lzip_index.error().c_str() );
      return lzip_index.retval(); }

  const bool to_file = default_output_filename.size();
  output_filename =
    to_file ? default_output_filename : insert_fixed( input_filename );
  if( !force && output_file_exists() ) return 1;
  outfd = -1;
  for( long i = 0; i < lzip_index.members(); ++i )
    {
    const long long mpos = lzip_index.mblock( i ).pos();
    const long long msize = lzip_index.mblock( i ).size();
    if( !safe_seek( infd, mpos, filename ) ) cleanup_and_fail( 1 );
    long long failure_pos = 0;
    bool nonzero = false;
    const int ret = test_member_from_file( infd, msize, &failure_pos, &nonzero );
    if( ret == 0 && !nonzero ) continue;
    if( ret != 0 && failure_pos < Lzip_header::size )		// End Of File
      { show_error( "Can't repair error in input file." );
        cleanup_and_fail( 2 ); }
    if( failure_pos >= msize - 8 ) failure_pos = msize - 8 - 1;

    if( verbosity >= 2 )		// damaged member found
      {
      std::printf( "Repairing member %s of %s  (failure pos = %s)\n",
                   format_num3( i + 1 ), format_num3( lzip_index.members() ),
                   format_num3( mpos + failure_pos ) );
      std::fflush( stdout );
      }
    uint8_t * const mbuffer = read_member( infd, mpos, msize, input_filename );
    if( !mbuffer ) cleanup_and_fail( 1 );
    const Lzip_header & header = *(const Lzip_header *)mbuffer;
    const unsigned dictionary_size = header.dictionary_size();
    long pos = 0;
    if( !nonzero && mbuffer[6] != 0 ) nonzero = true;		// bad DS
    if( !gross_damage( mbuffer, msize ) )
      {
      if( nonzero ) pos = repair_nonzero( mbuffer, msize );
      if( pos == 0 )
        pos = repair_dictionary_size( mbuffer, msize );
      if( pos == 0 )
        pos = repair_member( mbuffer, mpos, msize, header.size + 1,
                             header.size + 6, dictionary_size, terminator );
      if( pos == 0 )
        pos = repair_member( mbuffer, mpos, msize, header.size + 7,
                             failure_pos, dictionary_size, terminator );
      print_pending_newline( terminator );
      }
    if( pos < 0 )
      { show_error( "Can't prepare master." ); cleanup_and_fail( 1 ); }
    if( pos > 0 )
      {
      if( outfd < 0 )		// first damaged member repaired
        {
        if( !safe_seek( infd, 0, filename ) ) return 1;
        set_signal_handler();
        if( !open_outstream( true, true, false, true, to_file ) ) return 1;
        if( !copy_file( infd, outfd, input_filename, output_filename ) )
          cleanup_and_fail( 1 );		// copy whole file
        }
      if( ( nonzero && pos != 6 &&
            seek_write( outfd, mbuffer + 6, 1, mpos + 6 ) != 1 ) ||
          seek_write( outfd, mbuffer + pos, 1, mpos + pos ) != 1 )
        { show_file_error( printable_name( output_filename, false ),
            wr_err_msg, errno ); cleanup_and_fail( 1 ); }
      }
    delete[] mbuffer;
    if( pos == 0 )
      {
      show_error( "Can't repair input file. Error is probably larger than 1 byte." );
      cleanup_and_fail( 2 );
      }
    }

  if( outfd < 0 )
    {
    if( verbosity >= 1 )
      std::fputs( "Input file has no errors. Recovery is not needed.\n", stdout );
    return 0;
    }
  if( !close_outstream( &in_stats ) ) return 1;
  if( verbosity >= 1 )
    std::printf( "Repaired copy of '%s' written to '%s'\n",
                 filename, output_filename.c_str() );
  return 0;
  }


int debug_delay( const std::string & input_filename,
                 const Cl_options & cl_opts, Block range,
                 const char terminator )
  {
  const char * const filename = input_filename.c_str();
  struct stat in_stats;				// not used
  const int infd = open_instream( filename, &in_stats, false, true );
  if( infd < 0 ) return 1;

  const Lzip_index lzip_index( infd, cl_opts );
  if( lzip_index.retval() != 0 )
    { show_file_error( filename, lzip_index.error().c_str() );
      return lzip_index.retval(); }

  if( range.end() > lzip_index.cdata_size() )
    range.size( std::max( 0LL, lzip_index.cdata_size() - range.pos() ) );
  if( range.size() <= 0 )
    { show_file_error( filename, "Nothing to do; range is empty." ); return 0; }

  for( long i = 0; i < lzip_index.members(); ++i )
    {
    const Block & mb = lzip_index.mblock( i );
    if( !range.overlaps( mb ) ) continue;
    const long long mpos = lzip_index.mblock( i ).pos();
    const long long msize = lzip_index.mblock( i ).size();
    const unsigned dictionary_size = lzip_index.dictionary_size( i );
    if( verbosity >= 2 )
      {
      std::printf( "Finding max delay in member %s of %s  (mpos = %s, msize = %s)\n",
                   format_num3( i + 1 ), format_num3( lzip_index.members() ),
                   format_num3( mpos ), format_num3( msize ) );
      std::fflush( stdout );
      }
    uint8_t * const mbuffer = read_member( infd, mpos, msize, input_filename );
    if( !mbuffer ) return 1;
    uint8_t * const buffer2 = new uint8_t[dictionary_size];
    long pos = std::max( range.pos() - mpos, Lzip_header::size + 1LL );
    const long end = std::min( range.end() - mpos, msize );
    long max_delay = 0;
    while( pos < end )
      {
      const unsigned long pos_limit = std::max( pos - 16, 0L );
      const LZ_mtester * master =
        prepare_master( mbuffer, msize, pos_limit, dictionary_size );
      if( !master ) { show_error( "Can't prepare master." );
                      delete[] buffer2; delete[] mbuffer; return 1; }
      const long partial_end = std::min( pos + 100, end );
      for( ; pos < partial_end; ++pos )
        {
        if( verbosity >= 2 )
          {
          std::printf( "  Delays at position %s %c",
                       format_num3( mpos + pos ), terminator );
          std::fflush( stdout ); pending_newline = true;
          }
        int value = -1;
        for( int j = 0; j < 256; ++j )
          {
          ++mbuffer[pos];
          if( j == 255 ) break;
          long failure_pos = 0;
          if( test_member_rest( *master, buffer2, &failure_pos ) ) continue;
          const long delay = failure_pos - pos;
          if( delay > max_delay ) { max_delay = delay; value = mbuffer[pos]; }
          }
        if( value >= 0 && verbosity >= 2 )
          {
          std::printf( "  New max delay %s at position %s (0x%02X)\n",
               format_num3( max_delay ), format_num3( mpos + pos ), value );
          std::fflush( stdout ); pending_newline = false;
          }
        if( pos + max_delay >= msize ) { pos = end; break; }
        }
      delete master;
      }
    delete[] buffer2;
    delete[] mbuffer;
    print_pending_newline( terminator );
    }

  if( verbosity >= 1 ) std::fputs( "Done.\n", stdout );
  return 0;
  }


int debug_byte_repair( const std::string & input_filename,
                       const Cl_options & cl_opts, const Bad_byte & bad_byte,
                       const char terminator )
  {
  const char * const filename = input_filename.c_str();
  struct stat in_stats;				// not used
  const int infd = open_instream( filename, &in_stats, false, true );
  if( infd < 0 ) return 1;

  const Lzip_index lzip_index( infd, cl_opts );
  if( lzip_index.retval() != 0 )
    { show_file_error( filename, lzip_index.error().c_str() );
      return lzip_index.retval(); }

  long idx = 0;
  for( ; idx < lzip_index.members(); ++idx )
    if( lzip_index.mblock( idx ).includes( bad_byte.pos ) ) break;
  if( idx >= lzip_index.members() )
    { show_file_error( filename, "Nothing to do; byte is beyond EOF." );
      return 0; }

  const long long mpos = lzip_index.mblock( idx ).pos();
  const long long msize = lzip_index.mblock( idx ).size();
  {
  long long failure_pos = 0;
  if( !safe_seek( infd, mpos, input_filename ) ) return 1;
  if( test_member_from_file( infd, msize, &failure_pos ) != 0 )
    {
    if( verbosity >= 0 )
      std::fprintf( stderr, "Member %s of %s already damaged  (failure pos = %s)\n",
                    format_num3( idx + 1 ), format_num3( lzip_index.members() ),
                    format_num3( mpos + failure_pos ) );
    return 2;
    }
  }
  uint8_t * const mbuffer = read_member( infd, mpos, msize, input_filename );
  if( !mbuffer ) return 1;
  const Lzip_header & header = *(const Lzip_header *)mbuffer;
  const unsigned dictionary_size = header.dictionary_size();
  const long long bad_pos = bad_byte.pos - mpos;
  const uint8_t good_value = mbuffer[bad_pos];
  const uint8_t bad_value = bad_byte( good_value );
  mbuffer[bad_pos] = bad_value;
  long failure_pos = 5;
  if( bad_pos != 5 || isvalid_ds( header.dictionary_size() ) )
    {
    LZ_mtester mtester( mbuffer, msize, header.dictionary_size() );
    if( mtester.test_member() == 0 && mtester.finished() )
      {
      if( verbosity >= 1 )
        std::fputs( "Member decompressed with no errors.\n", stdout );
      delete[] mbuffer;
      return 0;
      }
    failure_pos = mtester.member_position();
    }
  if( verbosity >= 2 )
    {
    std::printf( "Test repairing member %s of %s  (mpos = %s, msize = %s)\n"
                 "  (damage pos = %s (0x%02X->0x%02X), failure pos = %s, delay = %s )\n",
                 format_num3( idx + 1 ), format_num3( lzip_index.members() ),
                 format_num3( mpos ), format_num3( msize ),
                 format_num3( bad_byte.pos ), good_value, bad_value,
                 format_num3( mpos + failure_pos ),
                 format_num3( mpos + failure_pos - bad_byte.pos ) );
    std::fflush( stdout );
    }
  if( failure_pos >= msize ) failure_pos = msize - 1;
  long pos = repair_dictionary_size( mbuffer, msize );
  if( pos == 0 )
    if( mbuffer[6] != 0 ) pos = repair_nonzero( mbuffer, msize );
  if( pos == 0 )
    pos = repair_member( mbuffer, mpos, msize, header.size + 1,
                         header.size + 6, dictionary_size, terminator );
  if( pos == 0 )
    pos = repair_member( mbuffer, mpos, msize, header.size + 7,
                         failure_pos, dictionary_size, terminator );
  print_pending_newline( terminator );
  delete[] mbuffer;
  if( pos < 0 ) { show_error( "Can't prepare master." ); return 1; }
  if( pos == 0 ) internal_error( "can't repair input file." );
  if( verbosity >= 1 ) std::fputs( "Member repaired successfully.\n", stdout );
  return 0;
  }


/* If show_packets is true, print to stdout descriptions of the decoded LZMA
   packets. Print also some global values; total number of packets in
   member, max distance (dis0) and its position in member, max LZMA packet
   size in each member and the positions in member of these packets.
   (Packet sizes are a fractionary number of bytes. The packet and marker
   sizes shown by option -X are the number of extra bytes required to decode
   the packet, not counting the data present in the range decoder before and
   after the decoding.
   if bad_byte.pos >= cdata_size, bad_byte is ignored.
*/
int debug_decompress( const std::string & input_filename,
                      const Cl_options & cl_opts, const Bad_byte & bad_byte,
                      const bool show_packets )
  {
  const char * const filename = input_filename.c_str();
  struct stat in_stats;
  const int infd = open_instream( filename, &in_stats, false, true );
  if( infd < 0 ) return 1;

  const Lzip_index lzip_index( infd, cl_opts );
  if( lzip_index.retval() != 0 )
    { show_file_error( filename, lzip_index.error().c_str() );
      return lzip_index.retval(); }

  outfd = show_packets ? -1 : STDOUT_FILENO;
  int retval = 0;
  for( long i = 0; i < lzip_index.members(); ++i )
    {
    const long long dpos = lzip_index.dblock( i ).pos();
    const long long mpos = lzip_index.mblock( i ).pos();
    const long long msize = lzip_index.mblock( i ).size();
    const unsigned dictionary_size = lzip_index.dictionary_size( i );
    if( verbosity >= 1 && show_packets )
      std::printf( "Decoding LZMA packets in member %s of %s "
                   "(mpos = %s, msize = %s, dpos = %s)\n  ipos   opos\n",
                   format_num3( i + 1 ), format_num3( lzip_index.members() ),
                   format_num3( mpos ), format_num3( msize ),
                   format_num3( dpos ) );
    if( !isvalid_ds( dictionary_size ) )
      { show_error( bad_dict_msg ); retval = 2; break; }
    uint8_t * const mbuffer = read_member( infd, mpos, msize, input_filename );
    if( !mbuffer ) { retval = 1; break; }
    if( bad_byte.pos >= 0 && lzip_index.mblock( i ).includes( bad_byte.pos ) )
      {
      const uint8_t good_value = mbuffer[bad_byte.pos-mpos];
      const uint8_t bad_value = bad_byte( good_value );
      mbuffer[bad_byte.pos-mpos] = bad_value;
      if( verbosity >= 1 && show_packets )
        std::printf( "Byte at pos %s changed from 0x%02X to 0x%02X\n",
                     format_num3( bad_byte.pos ), good_value, bad_value );
      }
    LZ_mtester mtester( mbuffer, msize, dictionary_size, outfd );
    const int result = mtester.debug_decode_member( show_packets );
    delete[] mbuffer;
    if( show_packets )
      {
      const std::vector< unsigned long long > & mppv = mtester.max_packet_posv();
      const unsigned mpackets = mppv.size();
      std::printf( "Total packets in member = %s\n",
                    format_num3( mtester.total_packets() ) );
      if( mtester.max_distance_pos() )
        std::printf( "Max distance in any match = %s at input position %s\n",
                      format_num3( mtester.max_distance() ),
                      format_num3( mtester.max_distance_pos() ) );
      if( mtester.max_marker_size() )
        std::printf( "Max marker size found = %u\n", mtester.max_marker_size() );
      std::printf( "Max packet size found = %u (%u packets)%s",
                    mtester.max_packet_size(), mpackets,
                    mpackets ? " at input positions" : "" );
      for( unsigned i = 0; i < mpackets; ++i )
        std::printf( " %s", format_num3( mppv[i] ) );
      std::fputc( '\n', stdout );
      }
    if( result != 0 )
      {
      if( verbosity >= 0 && result <= 2 && show_packets )
        std::printf( "%s at pos %s\n", ( result == 2 ) ?
                     "File ends unexpectedly" : "Decoder error",
                     format_num3( mpos + mtester.member_position() ) );
      retval = 2;
      if( result != 3 || !mtester.finished() || mtester.data_position() !=
          (unsigned long long)lzip_index.dblock( i ).size() ) break;
      }
    if( i + 1 < lzip_index.members() && show_packets )
      std::fputc( '\n', stdout );
    }

  if( !close_outstream( &in_stats ) && retval == 0 ) retval = 1;
  return retval;
  }
