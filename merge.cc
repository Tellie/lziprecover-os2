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
#include "decoder.h"
#include "lzip_index.h"


Block Block::split( const long long pos )
  {
  if( pos > pos_ && pos < end() )
    {
    const Block b( pos_, pos - pos_ );
    pos_ = pos; size_ -= b.size_;
    return b;
    }
  return Block( 0, 0 );
  }

namespace {

bool pending_newline = false;

void print_pending_newline( const char terminator )
  { if( pending_newline && terminator != '\n' ) std::fputc( '\n', stdout );
    pending_newline = false; }


bool file_crc( uint32_t & crc, const int infd, const char * const filename )
  {
  const int buffer_size = 65536;
  crc = 0xFFFFFFFFU;
  uint8_t * const buffer = new uint8_t[buffer_size];
  bool error = false;

  while( true )
    {
    const int rd = readblock( infd, buffer, buffer_size );
    if( rd != buffer_size && errno )
      { show_file_error( filename, rd_err_msg, errno );
        error = true; break; }
    if( rd > 0 )
      crc32.update_buf( crc, buffer, rd );
    if( rd < buffer_size ) break;			// EOF
    }
  delete[] buffer;
  crc ^= 0xFFFFFFFFU;
  return !error;
  }


// Add 'bv' to 'block_vector' splitting blocks as needed to keep all the
// edges (pos and end of every block).
// 'block_vector' contains the result. 'bv' is destroyed.
void combine( std::vector< Block > & block_vector, std::vector< Block > & bv )
  {
  if( block_vector.empty() ) { block_vector.swap( bv ); return; }
  unsigned i1 = 0, i2 = 0;
  while( i1 < block_vector.size() && i2 < bv.size() )
    {
    Block & b1 = block_vector[i1];
    Block & b2 = bv[i2];
    if( b1.overlaps( b2 ) )
      {
      if( b1 < b2 )
        {
        Block b = b1.split( b2.pos() );
        block_vector.insert( block_vector.begin() + i1, b ); ++i1;
        }
      else if( b2 < b1 )
        {
        Block b( b2.pos(), b1.pos() - b2.pos() );
        b2.split( b1.pos() );
        block_vector.insert( block_vector.begin() + i1, b ); ++i1;
        }
      else if( b1.end() < b2.end() ) { b2.split( b1.end() ); ++i1; }
      else if( b2.end() < b1.end() )
        {
        Block b = b1.split( b2.end() );
        block_vector.insert( block_vector.begin() + i1, b ); ++i1; ++i2;
        }
      else { ++i1; ++i2; }		// blocks are identical
      }
    else if( b1 < b2 ) ++i1;
    else { block_vector.insert( block_vector.begin() + i1, b2 ); ++i1; ++i2; }
    }
  if( i2 < bv.size() )				// tail copy
    block_vector.insert( block_vector.end(), bv.begin() + i2, bv.end() );
  }


// positions in 'block_vector' are absolute file positions.
// blocks in 'block_vector' are ascending and don't overlap.
bool diff_member( const long long mpos, const long long msize,
                  const std::vector< std::string > & filenames,
                  const std::vector< int > & infd_vector,
                  std::vector< Block > & block_vector,
                  std::vector< int > & color_vector )
  {
  const int files = infd_vector.size();
  const int buffer_size = 65536;
  uint8_t * const buffer1 = new uint8_t[buffer_size];
  uint8_t * const buffer2 = new uint8_t[buffer_size];
  int next_color = 1;

  bool error = false;
  for( int i1 = 0; i1 < files && !error; ++i1 )
    {
    for( int i2 = i1 + 1; i2 < files && !error; ++i2 )
      {
      if( color_vector[i1] != 0 && color_vector[i1] == color_vector[i2] )
        continue;
      std::vector< Block > bv;
      long long partial_pos = 0;
      const int fd1 = infd_vector[i1], fd2 = infd_vector[i2];
      int begin = -1;			// begin of block. -1 means no block
      bool prev_equal = true;
      if( !safe_seek( fd1, mpos, filenames[i1] ) ||
          !safe_seek( fd2, mpos, filenames[i2] ) ) { error = true; break; }

      while( partial_pos < msize )
        {
        const int size = std::min( (long long)buffer_size, msize - partial_pos );
        const int rd = readblock( fd1, buffer1, size );
        if( rd != size && errno )
          { show_file_error( filenames[i1].c_str(), rd_err_msg, errno );
            error = true; break; }
        if( rd > 0 )
          {
          if( readblock( fd2, buffer2, rd ) != rd )
            { show_file_error( filenames[i2].c_str(), rd_err_msg, errno );
              error = true; break; }
          for( int i = 0; i < rd; ++i )
            {
            if( buffer1[i] != buffer2[i] )
              {
              prev_equal = false;
              if( begin < 0 ) begin = partial_pos + i;	// begin block
              }
            else if( !prev_equal ) prev_equal = true;
            else if( begin >= 0 )			// end block
              {
              Block b( mpos + begin, partial_pos + i - 1 - begin );
              begin = -1;
              bv.push_back( b );
              }
            }
          partial_pos += rd;
          }
        if( rd < buffer_size ) break;			// EOF
        }
      if( begin >= 0 )					// finish last block
        {
        Block b( mpos + begin, partial_pos - prev_equal - begin );
        bv.push_back( b );
        }
      if( bv.empty() )		// members are identical, set to same color
        {
        if( color_vector[i1] == 0 )
          {
          if( color_vector[i2] != 0 ) color_vector[i1] = color_vector[i2];
          else color_vector[i1] = color_vector[i2] = next_color++;
          }
        else if( color_vector[i2] == 0 ) color_vector[i2] = color_vector[i1];
        else internal_error( "different colors assigned to identical members." );
        }
      combine( block_vector, bv );
      }
    if( color_vector[i1] == 0 ) color_vector[i1] = next_color++;
    }
  delete[] buffer2; delete[] buffer1;
  return !error;
  }


long ipow( const unsigned base, const unsigned exponent )
  {
  unsigned long result = 1;
  for( unsigned i = 0; i < exponent; ++i )
    {
    if( LONG_MAX / result >= base ) result *= base;
    else { result = LONG_MAX; break; }
    }
  return result;
  }


int open_input_files( const std::vector< std::string > & filenames,
                      std::vector< int > & infd_vector,
                      const Cl_options & cl_opts, Lzip_index & lzip_index,
                      struct stat * const in_statsp )
  {
  const int files = filenames.size();
  for( int i = 0; i + 1 < files; ++i )
    for( int j = i + 1; j < files; ++j )
      if( filenames[i] == filenames[j] )
        { show_file_error( filenames[i].c_str(), "Input file given twice." );
          return 2; }
  {
  std::vector< uint32_t > crc_vector( files );
  for( int i = 0; i < files; ++i )
    {
    struct stat in_stats;				// not used
    infd_vector[i] = open_instream( filenames[i].c_str(),
                     ( i == 0 ) ? in_statsp : &in_stats, false, true );
    if( infd_vector[i] < 0 ) return 1;
    if( !file_crc( crc_vector[i], infd_vector[i], filenames[i].c_str() ) )
      return 1;
    for( int j = 0; j < i; ++j )
      if( crc_vector[i] == crc_vector[j] )
        { show_2file_error( "Input files", filenames[j].c_str(),
            filenames[i].c_str(), "are identical." ); return 2; }
    }
  }

  long long insize = 0;
  int good_i = -1;
  for( int i = 0; i < files; ++i )
    {
    long long tmp;
    const Lzip_index li( infd_vector[i], cl_opts, true );
    if( li.retval() == 0 )		// file format is intact
      {
      if( good_i < 0 ) { good_i = i; lzip_index = li; }
      else if( lzip_index != li )
        { show_2file_error( "Input files", filenames[good_i].c_str(),
            filenames[i].c_str(), "are different." ); return 2; }
      tmp = lzip_index.file_size();
      }
    else				// file format is damaged
      {
      tmp = lseek( infd_vector[i], 0, SEEK_END );
      if( tmp < 0 )
        {
        show_file_error( filenames[i].c_str(), seek_msg, errno );
        return 1;
        }
      }
    if( tmp < min_member_size )
      { show_file_error( filenames[i].c_str(), short_file_msg ); return 2; }
    if( i == 0 ) insize = tmp;
    else if( insize != tmp )
      { show_2file_error( "Sizes of input files", filenames[0].c_str(),
          filenames[i].c_str(), "are different." ); return 2; }
    }

  if( lzip_index.retval() != 0 )
    {
    const Lzip_index li( infd_vector, insize );
    if( li.retval() == 0 )		// file format could be recovered
      lzip_index = li;
    else
      { show_error( "Format damaged in all input files." ); return 2; }
    }

  for( int i = 0; i < files; ++i )
    {
    const int infd = infd_vector[i];
    bool error = false;
    for( long j = 0; j < lzip_index.members(); ++j )
      {
      const long long mpos = lzip_index.mblock( j ).pos();
      const long long msize = lzip_index.mblock( j ).size();
      if( !safe_seek( infd, mpos, filenames[i] ) ) return 1;
      if( test_member_from_file( infd, msize ) != 0 ) { error = true; break; }
      }
    if( !error )
      {
      if( verbosity >= 1 )
        std::printf( "Input file '%s' has no errors. Recovery is not needed.\n",
                     filenames[i].c_str() );
      return 0;
      }
    }
  return -1;
  }


void maybe_cluster_blocks( std::vector< Block > & block_vector )
  {
  const unsigned long old_size = block_vector.size();
  if( old_size <= 16 ) return;
  do {
    int min_gap = INT_MAX;
    bool same = true;			// all gaps have the same size
    for( unsigned i = 1; i < block_vector.size(); ++i )
      {
      const long long gap = block_vector[i].pos() - block_vector[i-1].end();
      if( gap < min_gap )
        { if( min_gap < INT_MAX ) same = false; min_gap = gap; }
      else if( gap != min_gap ) same = false;
      }
    if( min_gap >= INT_MAX || same ) break;
    for( unsigned i = block_vector.size() - 1; i > 0; --i )
      {
      const long long gap = block_vector[i].pos() - block_vector[i-1].end();
      if( gap == min_gap )
        {
        block_vector[i-1].size( block_vector[i-1].size() + gap +
                                block_vector[i].size() );
        block_vector.erase( block_vector.begin() + i );
        }
      }
    } while( block_vector.size() > 16 );
  if( verbosity >= 1 && old_size > block_vector.size() )
    std::printf( "  %s errors have been grouped in %s clusters.\n",
                 format_num3( old_size ), format_num3( block_vector.size() ) );
  }


bool color_done( const std::vector< int > & color_vector, const int i )
  {
  for( int j = i - 1; j >= 0; --j )
    if( color_vector[j] == color_vector[i] ) return true;
  return false;
  }


// try dividing blocks in 2 color groups at every gap
bool try_merge_member2( const std::vector< std::string > & filenames,
                        const long long mpos, const long long msize,
                        const std::vector< Block > & block_vector,
                        const std::vector< int > & color_vector,
                        const std::vector< int > & infd_vector,
                        const char terminator )
  {
  const int blocks = block_vector.size();
  const int files = infd_vector.size();
  const int variations = files * ( files - 1 );

  for( int i1 = 0; i1 < files; ++i1 )
    for( int i2 = 0; i2 < files; ++i2 )
      {
      if( i1 == i2 || color_vector[i1] == color_vector[i2] ||
          color_done( color_vector, i1 ) ) continue;
      for( int bi = 0; bi < blocks; ++bi )
        if( !safe_seek( infd_vector[i2], block_vector[bi].pos(), filenames[i2] ) ||
            !safe_seek( outfd, block_vector[bi].pos(), output_filename ) ||
            !copy_file( infd_vector[i2], outfd, filenames[i2], output_filename,
                        block_vector[bi].size() ) ) cleanup_and_fail( 1 );
      const int infd = infd_vector[i1];
      const int var = ( i1 * ( files - 1 ) ) + i2 - ( i2 > i1 ) + 1;
      for( int bi = 0; bi + 1 < blocks; ++bi )
        {
        if( verbosity >= 2 )
          {
          std::printf( "  Trying variation %d of %d, block %d        %c",
                       var, variations, bi + 1, terminator );
          std::fflush( stdout ); pending_newline = true;
          }
        if( !safe_seek( infd, block_vector[bi].pos(), filenames[i1] ) ||
            !safe_seek( outfd, block_vector[bi].pos(), output_filename ) ||
            !copy_file( infd, outfd, filenames[i1], output_filename,
                        block_vector[bi].size() ) ||
            !safe_seek( outfd, mpos, output_filename ) )
          cleanup_and_fail( 1 );
        long long failure_pos = 0;
        if( test_member_from_file( outfd, msize, &failure_pos ) == 0 )
          return true;
        if( mpos + failure_pos < block_vector[bi].end() ) break;
        }
      }
  return false;
  }


// merge block by block
bool try_merge_member( const std::vector< std::string > & filenames,
                       const long long mpos, const long long msize,
                       const std::vector< Block > & block_vector,
                       const std::vector< int > & color_vector,
                       const std::vector< int > & infd_vector,
                       const char terminator )
  {
  const int blocks = block_vector.size();
  const int files = infd_vector.size();
  const long variations = ipow( files, blocks );
  if( variations >= LONG_MAX )
    {
    if( files > 2 )
      show_error( "Too many damaged blocks. Try merging fewer files." );
    else
      show_error( "Too many damaged blocks. Merging is not possible." );
    cleanup_and_fail( 2 );
    }
  int bi = 0;					// block index
  std::vector< int > file_idx( blocks, 0 );	// file to read each block from

  while( bi >= 0 )
    {
    if( verbosity >= 2 )
      {
      long var = 0;
      for( int i = 0; i < blocks; ++i ) var = var * files + file_idx[i];
      std::printf( "  Trying variation %s of %s %c", format_num3( var + 1 ),
                   format_num3( variations ), terminator );
      std::fflush( stdout ); pending_newline = true;
      }
    while( bi < blocks )
      {
      const int infd = infd_vector[file_idx[bi]];
      if( !safe_seek( infd, block_vector[bi].pos(), filenames[file_idx[bi]] ) ||
          !safe_seek( outfd, block_vector[bi].pos(), output_filename ) ||
          !copy_file( infd, outfd, filenames[file_idx[bi]], output_filename,
                      block_vector[bi].size() ) ) cleanup_and_fail( 1 );
      ++bi;
      }
    if( !safe_seek( outfd, mpos, output_filename ) ) cleanup_and_fail( 1 );
    long long failure_pos = 0;
    if( test_member_from_file( outfd, msize, &failure_pos ) == 0 ) return true;
    while( bi > 0 && mpos + failure_pos < block_vector[bi-1].pos() ) --bi;
    while( --bi >= 0 )
      {
      while( ++file_idx[bi] < files &&
             color_done( color_vector, file_idx[bi] ) );
      if( file_idx[bi] < files ) break;
      file_idx[bi] = 0;
      }
    }
  return false;
  }


// merge a single block split at every possible position
bool try_merge_member1( const std::vector< std::string > & filenames,
                        const long long mpos, const long long msize,
                        const std::vector< Block > & block_vector,
                        const std::vector< int > & color_vector,
                        const std::vector< int > & infd_vector,
                        const char terminator )
  {
  if( block_vector.size() != 1 || block_vector[0].size() <= 1 ) return false;
  const long long pos = block_vector[0].pos();
  const long long size = block_vector[0].size();
  const int files = infd_vector.size();
  const int variations = files * ( files - 1 );
  uint8_t byte;

  for( int i1 = 0; i1 < files; ++i1 )
    for( int i2 = 0; i2 < files; ++i2 )
      {
      if( i1 == i2 || color_vector[i1] == color_vector[i2] ||
          color_done( color_vector, i1 ) ) continue;
      if( !safe_seek( infd_vector[i1], pos, filenames[i1] ) ||
          !safe_seek( infd_vector[i2], pos, filenames[i2] ) ||
          !safe_seek( outfd, pos, output_filename ) ||
          !copy_file( infd_vector[i2], outfd, filenames[i2], output_filename,
                      size ) ) cleanup_and_fail( 1 );
      const int infd = infd_vector[i1];
      const int var = ( i1 * ( files - 1 ) ) + i2 - ( i2 > i1 ) + 1;
      for( long long i = 0; i + 1 < size; ++i )
        {
        if( verbosity >= 2 )
          {
          std::printf( "  Trying variation %d of %d, position %s        %c",
                       var, variations, format_num3( pos + i ), terminator );
          std::fflush( stdout ); pending_newline = true;
          }
        if( !safe_seek( outfd, pos + i, output_filename ) ||
            readblock( infd, &byte, 1 ) != 1 ||
            writeblock( outfd, &byte, 1 ) != 1 ||
            !safe_seek( outfd, mpos, output_filename ) )
          cleanup_and_fail( 1 );
        long long failure_pos = 0;
        if( test_member_from_file( outfd, msize, &failure_pos ) == 0 )
          return true;
        if( mpos + failure_pos <= pos + i ) break;
        }
      }
  return false;
  }

} // end namespace


/* infd and outfd can refer to the same file if copying to a lower file
   position or if source and destination blocks don't overlap.
   max_size < 0 means no size limit. */
bool copy_file( const int infd, const int outfd, const std::string & iname,
                const std::string & oname, const long long max_size )
  {
  const long long buffer_size = 65536;
  // remaining number of bytes to copy
  long long rest = (max_size >= 0) ? max_size : buffer_size;
  long long copied_size = 0;
  uint8_t * const buffer = new uint8_t[buffer_size];
  bool error = false;

  while( rest > 0 )
    {
    const int size = std::min( buffer_size, rest );
    if( max_size >= 0 ) rest -= size;
    const int rd = readblock( infd, buffer, size );
    if( rd != size && errno )
      { show_file_error( printable_name( iname ), rd_err_msg, errno );
        error = true; break; }
    if( rd > 0 )
      {
      const int wr = writeblock( outfd, buffer, rd );
      if( wr != rd )
        { show_file_error( printable_name( oname, false ), wr_err_msg, errno );
          error = true; break; }
      copied_size += rd;
      }
    if( rd < size ) break;				// EOF
    }
  delete[] buffer;
  if( !error && max_size >= 0 && copied_size != max_size )
    { show_file_error( printable_name( iname ), "Input file ends unexpectedly." );
      error = true; }
  return !error;
  }


/* Return value: 0 = OK, 1 = bad msize, 2 = data error.
   'failure_pos' is relative to the beginning of the member. */
int test_member_from_file( const int infd, const unsigned long long msize,
                       long long * const failure_posp, bool * const nonzerop )
  {
  Range_decoder rdec( infd );
  Lzip_header header;
  rdec.read_data( header.data, header.size );
  const unsigned dictionary_size = header.dictionary_size();
  bool done = false;
  if( !rdec.finished() && header.check_magic() &&
      header.check_version() && isvalid_ds( dictionary_size ) )
    {
    LZ_decoder decoder( rdec, dictionary_size, -1 );
    const int saved_verbosity = verbosity;
    verbosity = -1;				// suppress all messages
    done = decoder.decode_member() == 0;
    verbosity = saved_verbosity;		// restore verbosity level
    if( nonzerop ) *nonzerop = rdec.nonzero();
    if( done && rdec.member_position() == msize ) return 0;
    }
  if( failure_posp ) *failure_posp = rdec.member_position();
  return done ? 1 : 2;
  }


int merge_files( const std::vector< std::string > & filenames,
                 const std::string & default_output_filename,
                 const Cl_options & cl_opts, const char terminator,
                 const bool force )
  {
  const int files = filenames.size();
  std::vector< int > infd_vector( files );
  Lzip_index lzip_index;
  struct stat in_stats;
  const int retval =
    open_input_files( filenames, infd_vector, cl_opts, lzip_index, &in_stats );
  if( retval >= 0 ) return retval;
  if( !safe_seek( infd_vector[0], 0, filenames[0] ) ) return 1;

  const bool to_file = default_output_filename.size();
  output_filename =
    to_file ? default_output_filename : insert_fixed( filenames[0] );
  set_signal_handler();
  if( !open_outstream( force, true, true, false, to_file ) ) return 1;
  if( !copy_file( infd_vector[0], outfd, filenames[0], output_filename ) )
    cleanup_and_fail( 1 );			// copy whole file

  for( long j = 0; j < lzip_index.members(); ++j )
    {
    const long long mpos = lzip_index.mblock( j ).pos();
    const long long msize = lzip_index.mblock( j ).size();
    // vector of data blocks differing among the copies of the current member
    std::vector< Block > block_vector;
    // different color means members are different
    std::vector< int > color_vector( files, 0 );
    if( !diff_member( mpos, msize, filenames, infd_vector, block_vector,
        color_vector ) || !safe_seek( outfd, mpos, output_filename ) )
      cleanup_and_fail( 1 );

    if( block_vector.empty() )
      {
      if( lzip_index.members() > 1 && test_member_from_file( outfd, msize ) == 0 )
        continue;
      if( verbosity >= 0 )
        std::fprintf( stderr, "Member %s is damaged and identical in all files."
                      " Merging is not possible.\n", format_num3( j + 1 ) );
      cleanup_and_fail( 2 );
      }

    if( verbosity >= 2 )
      {
      std::printf( "Merging member %s of %s  (%s %s)\n",
                   format_num3( j + 1 ), format_num3( lzip_index.members() ),
                   format_num3( block_vector.size() ),
                   ( block_vector.size() == 1 ) ? "error" : "errors" );
      std::fflush( stdout );
      }

    bool done = false;
    if( block_vector.size() > 1 )
      {
      maybe_cluster_blocks( block_vector );
      done = try_merge_member2( filenames, mpos, msize, block_vector,
                                color_vector, infd_vector, terminator );
      print_pending_newline( terminator );
      }
    // With just one member and one differing block the merge can't succeed.
    if( !done && ( lzip_index.members() > 1 || block_vector.size() > 1 ) )
      {
      done = try_merge_member( filenames, mpos, msize, block_vector,
                               color_vector, infd_vector, terminator );
      print_pending_newline( terminator );
      }
    if( !done )
      {
      done = try_merge_member1( filenames, mpos, msize, block_vector,
                                color_vector, infd_vector, terminator );
      print_pending_newline( terminator );
      }
    if( !done )
      {
      if( verbosity >= 3 )
        for( unsigned i = 0; i < block_vector.size(); ++i )
          std::fprintf( stderr, "area %2u from position %6s to %6s\n", i + 1,
                        format_num3( block_vector[i].pos() ),
                        format_num3( block_vector[i].end() - 1 ) );
      show_error( "Some error areas overlap. Merging is not possible." );
      cleanup_and_fail( 2 );
      }
    }

  if( !close_outstream( &in_stats ) ) return 1;
  if( verbosity >= 1 )
    std::fputs( "Input files merged successfully.\n", stdout );
  return 0;
  }
