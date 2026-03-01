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
#include <new>
#include <string>
#include <vector>
#include <stdint.h>
#include <unistd.h>

#include "lzip.h"
#include "mtester.h"


namespace {

/* Return the address of a malloc'd buffer containing the file data and
   the file size in '*file_sizep'. The buffer is at least 20 bytes larger.
   In case of error, return 0 and do not modify '*file_sizep'.
*/
uint8_t * read_file( const int infd, long * const file_sizep,
                     const char * const filename )
  {
  long buffer_size = 65536;
  uint8_t * buffer = (uint8_t *)std::malloc( buffer_size );
  if( !buffer ) throw std::bad_alloc();

  long file_size = readblock( infd, buffer, buffer_size - 20 );
  while( file_size >= buffer_size - 20 && !errno )
    {
    if( buffer_size >= LONG_MAX )
      { show_file_error( filename, large_file_msg );
        std::free( buffer ); return 0; }
    buffer_size = (buffer_size <= LONG_MAX / 2) ? 2 * buffer_size : LONG_MAX;
    uint8_t * const tmp = (uint8_t *)std::realloc( buffer, buffer_size );
    if( !tmp ) { std::free( buffer ); throw std::bad_alloc(); }
    buffer = tmp;
    file_size +=
      readblock( infd, buffer + file_size, buffer_size - 20 - file_size );
    }
  if( errno )
    {
    show_file_error( filename, rd_err_msg, errno );
    std::free( buffer ); return 0;
    }
  *file_sizep = file_size;
  return buffer;
  }


bool validate_ds( unsigned * const dictionary_size )
  {
  if( *dictionary_size < min_dictionary_size )
    { *dictionary_size = min_dictionary_size; return false; }
  if( *dictionary_size > max_dictionary_size )
    { *dictionary_size = max_dictionary_size; return false; }
  return true;
  }

} // end namespace


int alone_to_lz( const int infd, const Pretty_print & pp )
  {
  enum { lzma_header_size = 13, offset = lzma_header_size - Lzip_header::size };
  long file_size = 0;
  uint8_t * const buffer = read_file( infd, &file_size, pp.name() );
  if( !buffer ) return 1;
  if( file_size < lzma_header_size )
    { show_file_error( pp.name(), short_file_msg );
      std::free( buffer ); return 2; }

  if( buffer[0] != 93 )			// (45 * 2) + (9 * 0) + 3
    {
    const Lzip_header & header = *(const Lzip_header *)buffer;
    if( header.check() )
      show_file_error( pp.name(), "Input file is already in lzip format." );
    else
      show_file_error( pp.name(), "Input file has non-default LZMA properties." );
    std::free( buffer ); return 2;
    }
  for( int i = 5; i < lzma_header_size; ++i ) if( buffer[i] != 0xFF )
    { show_file_error( pp.name(), "Input file is non-streamed." );
      std::free( buffer ); return 2; }

  if( verbosity >= 1 ) pp();
  unsigned dictionary_size = 0;
  for( int i = 4; i > 0; --i )
    { dictionary_size <<= 8; dictionary_size += buffer[i]; }
  const unsigned orig_dictionary_size = dictionary_size;
  validate_ds( &dictionary_size );
  Lzip_header & header = *(Lzip_header *)( buffer + offset );
  header.set_magic();
  header.dictionary_size( dictionary_size );
  buffer[lzma_header_size] = 0;			// reset first LZMA byte
  for( int i = 0; i < Lzip_trailer::size; ++i ) buffer[file_size++] = 0;
  const long lzip_size = file_size - offset;
  // compute and fill trailer
  {
  LZ_mtester mtester( buffer + offset, lzip_size, dictionary_size );
  const int result = mtester.test_member();
  if( result == 1 && orig_dictionary_size > max_dictionary_size )
    { pp( "dictionary size is too large" ); std::free( buffer ); return 2; }
  if( result != 3 || !mtester.finished() )
    { pp( "file is corrupt" ); std::free( buffer ); return 2; }
  if( mtester.max_distance() < dictionary_size &&
      dictionary_size > min_dictionary_size )
    {
    dictionary_size =
      std::max( mtester.max_distance(), (unsigned)min_dictionary_size );
    header.dictionary_size( dictionary_size );
    }
  Lzip_trailer & trailer =
    *(Lzip_trailer *)( buffer + file_size - trailer.size );
  trailer.data_crc( mtester.crc() );
  trailer.data_size( mtester.data_position() );
  trailer.member_size( mtester.member_position() );
  }
  // check converted member
  LZ_mtester mtester( buffer + offset, lzip_size, dictionary_size );
  if( mtester.test_member() != 0 || !mtester.finished() )
    { pp( "conversion failed" ); std::free( buffer ); return 2; }
  if( writeblock( outfd, buffer + offset, lzip_size ) != lzip_size )
    {
    show_file_error( printable_name( output_filename, false ), wr_err_msg,
      errno ); std::free( buffer ); return 1;
    }
  std::free( buffer );
  if( verbosity >= 1 ) std::fputs( "done\n", stderr );
  return 0;
  }
