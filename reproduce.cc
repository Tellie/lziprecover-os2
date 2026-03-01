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
#include <csignal>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <stdint.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include "lzip.h"
#include "md5.h"
#include "mtester.h"
#include "lzip_index.h"


namespace {

const char * const large_member_msg =
                   "Input file contains member too large for mmap.";
const char * final_msg = 0;

bool pending_newline = false;

void print_pending_newline( const char terminator )
  { if( pending_newline && terminator != '\n' ) std::fputc( '\n', stdout );
    pending_newline = false; }

int fatal_retval = 0;

int fatal( const int retval )
  { if( fatal_retval == 0 ) fatal_retval = retval; return retval; }

/* Detect bursts of identical bytes in member.
   Return the position of the damaged area in the member, or -1 if error. */
long bursted_pos( const uint8_t * const mbuffer, const long msize,
                  const char * const input_filename,
                  long * const sizep, uint8_t * const valuep = 0 )
  {
  enum { minlen = 8 };		// min number of consecutive identical bytes
  long i = Lzip_header::size;
  const long end = msize - minlen;
  long begin = -1;
  long size = 0;
  uint8_t value = 0;
  while( i < end )	// leave i pointing to the first differing byte
    {
    const uint8_t byte = mbuffer[i++];
    if( mbuffer[i] == byte )
      {
      const long pos = i - 1;
      ++i;
      while( i < msize && mbuffer[i] == byte ) ++i;
      if( i - pos >= minlen )
        { if( size <= 0 ) { begin = pos; value = byte; }
          size = i - begin; }
      }
    }
  if( begin < 0 || size <= 0 )
    { show_file_error( input_filename, "Can't locate damaged area." );
      return -1; }
  *sizep = size;
  if( valuep ) *valuep = value;
  return begin;
  }


const LZ_mtester * prepare_master2( const uint8_t * const mbuffer,
                                    const long msize, const long begin,
                                    const unsigned dictionary_size )
  {
  long pos_limit = std::max( begin - 16, (long)Lzip_header::size );
  LZ_mtester * master = new LZ_mtester( mbuffer, msize, dictionary_size );
  if( master->test_member( pos_limit ) != -1 ||
      master->member_position() > (unsigned long)begin )
    { delete master; return 0; }
  // decompress as much data as possible without surpassing begin
  while( pos_limit < begin && master->test_member( pos_limit + 1 ) == -1 &&
         master->member_position() <= (unsigned long)begin )
    ++pos_limit;
  delete master;
  master = new LZ_mtester( mbuffer, msize, dictionary_size );
  if( master->test_member( pos_limit ) == -1 &&
      master->member_position() <= (unsigned long)begin ) return master;
  delete master;
  return 0;
  }


/* Locate in the reference file (rbuf) the truncated data in the dictionary.
   The reference file must match from the last byte decoded back to the
   beginning of the file or to the beginning of the dictionary.
   Choose the match nearest to the beginning of the file.
   As a fallback, locate the longest partial match at least 512 bytes long.
   Return the offset in file of the first undecoded byte, or -1 if no match. */
long match_file( const LZ_mtester & master, const uint8_t * const rbuf,
                 const long rsize, const char * const reference_filename )
  {
  const uint8_t * prev_buffer;
  int dec_size, prev_size;
  const uint8_t * const dec_buffer =
    master.get_buffers( &prev_buffer, &dec_size, &prev_size );
  if( dec_size < 4 )
    { if( verbosity >= 1 )
        { std::printf( "'%s' can't match: not enough data in dictionary.\n",
                       reference_filename ); pending_newline = false; }
      return -1; }
  long offset = -1;	// offset in file of the first undecoded byte
  bool multiple = false;
  const uint8_t last_byte = dec_buffer[dec_size-1];
  for( long i = rsize - 1; i >= 3; --i )	// match at least 4 bytes at bof
    if( rbuf[i] == last_byte )
      {
      // compare file with the two parts of the dictionary
      int len = std::min( (long)dec_size - 1, i );
      if( std::memcmp( rbuf + i - len, dec_buffer + dec_size - 1 - len, len ) == 0 )
        {
        int len2 = std::min( (long)prev_size, i - len );
        if( len2 <= 0 || !prev_buffer ||
            std::memcmp( rbuf + i - len - len2,
                         prev_buffer + prev_size - len2, len2 ) == 0 )
          {
          if( offset >= 0 ) multiple = true;
          offset = i + 1;
          i -= len + len2;
          }
        }
      }
  if( offset >= 0 )
    {
    if( multiple && verbosity >= 1 )
      { std::printf( "warning: %s: Multiple matches. Using match at offset %s\n",
                     reference_filename, format_num3( offset ) );
        std::fflush( stdout ); }
    if( !multiple && verbosity >= 2 )
      { std::printf( "%s: Match found at offset %s\n", reference_filename,
                     format_num3( offset ) ); std::fflush( stdout ); }
    return offset;
    }
  int maxlen = 0;		// choose longest match in reference file
  for( long i = rsize - 1; i >= 0; --i )
    if( rbuf[i] == last_byte )
      {
      // compare file with the two parts of the dictionary
      const int size1 = std::min( (long)dec_size, i + 1 );
      int len = 1;
      while( len < size1 && rbuf[i-len] == dec_buffer[dec_size-len-1] ) ++len;
      if( len == size1 )
        {
        int size2 = std::min( (long)prev_size, i + 1 - size1 );
        while( len < size1 + size2 &&
               rbuf[i-len] == prev_buffer[prev_size+size1-len] ) ++len;
        }
      if( len > maxlen ) { maxlen = len; offset = i + 1; i -= len; }
      }
  if( maxlen >= 512 && offset >= 0 )
    {
    if( verbosity >= 1 )
      { std::printf( "warning: %s: Partial match found at offset %s, len %s."
                     " Reference data may be mixed with other data.\n",
                     reference_filename, format_num3( offset ),
                     format_num3( maxlen ) );
        std::fflush( stdout ); }
    return offset;
    }
  if( verbosity >= 1 )
    { std::printf( "'%s' does not match with decoded data.\n",
                   reference_filename ); pending_newline = false; }
  return -1;
  }


void show_close_error( const char * const prog_name = "data feeder" )
  {
  if( verbosity >= 0 )
    std::fprintf( stderr, "%s: Error closing output of %s: %s\n",
                  program_name, prog_name, std::strerror( errno ) );
  }


void show_exec_error( const char * const prog_name )
  {
  if( verbosity >= 0 )
    std::fprintf( stderr, "%s: Can't exec '%s': %s\n",
                  program_name, prog_name, std::strerror( errno ) );
  }


void show_fork_error( const char * const prog_name )
  {
  if( verbosity >= 0 )
    std::fprintf( stderr, "%s: Can't fork '%s': %s\n",
                  program_name, prog_name, std::strerror( errno ) );
  }


/* Return -1 if child not terminated, 1 in case of error, or exit status of
   child process 'pid'.
*/
int child_status( const pid_t pid, const char * const name )
  {
  int status;
  while( true )
    {
    const int tmp = waitpid( pid, &status, WNOHANG );
    if( tmp == -1 && errno != EINTR )
      {
      if( verbosity >= 0 )
        std::fprintf( stderr, "%s: Error checking status of '%s': %s\n",
                      program_name, name, std::strerror( errno ) );
      return 1;
      }
    if( tmp == 0 ) return -1;			// child not terminated
    if( tmp == pid ) break;			// child terminated
    }
  if( WIFEXITED( status ) ) return WEXITSTATUS( status );
  return 1;
  }


// Return exit status of child process 'pid', or 1 in case of error.
//
int wait_for_child( const pid_t pid, const char * const name )
  {
  int status;
  while( waitpid( pid, &status, 0 ) == -1 )
    {
    if( errno != EINTR )
      {
      if( verbosity >= 0 )
        std::fprintf( stderr, "%s: Error waiting termination of '%s': %s\n",
                      program_name, name, std::strerror( errno ) );
      return 1;
      }
    }
  if( WIFEXITED( status ) ) return WEXITSTATUS( status );
  return 1;
  }


bool good_status( const pid_t pid, const char * const name, const bool finished )
  {
  bool error = false;
  if( pid )
    {
    if( !finished )
      {
      const int tmp = child_status( pid, name );
      if( tmp < 0 )				// child not terminated
        { kill( pid, SIGTERM ); wait_for_child( pid, name ); }
      else if( tmp != 0 ) error = true;		// child status != 0
      }
    else
      if( wait_for_child( pid, name ) != 0 ) error = true;
    if( error )
      {
      if( verbosity >= 0 )
        std::fprintf( stderr, "%s: %s: Child terminated with error status.\n",
                      program_name, name );
      return false;
      }
    }
  return !error;
  }


/* Feed to lzip through 'ofd' the data decompressed up to 'good_dsize'
   (master->data_position) followed by the reference data from byte at
   offset 'offset' of reference file, up to a total of 'dsize' bytes. */
bool feed_data( uint8_t * const mbuffer, const long msize,
                const long long dsize, const unsigned long long good_dsize,
                const uint8_t * const rbuf, const long rsize,
                const long offset, const unsigned dictionary_size,
                const int ofd )
  {
  LZ_mtester mtester( mbuffer, msize, dictionary_size, ofd );
  if( mtester.test_member( LONG_MAX, good_dsize ) != -1 ||
      good_dsize != mtester.data_position() )
    { show_error( "Error decompressing prefix data for compressor." );
      return false; }
  // limit reference data to remaining decompressed data in member
  const long size =
    std::min( (unsigned long long)rsize - offset, dsize - good_dsize );
  if( writeblock( ofd, rbuf + offset, size ) != size )
    { show_error( "Error writing reference data to compressor", errno );
      return false; }
  return true;
  }


/* Try to reproduce the zeroed sector.
   Return value: -1 = failure, 0 = success, > 0 = fatal error. */
int try_reproduce( uint8_t * const mbuffer, const long msize,
                   const long long dsize, const unsigned long long good_dsize,
                   const long begin, const long end,
                   const uint8_t * const rbuf, const long rsize,
                   const long offset, const unsigned dictionary_size,
                   const char ** const lzip_argv, MD5SUM * const md5sump,
                   const char terminator, const bool auto0 = false )
  {
  int fda[2];				// pipe to compressor
  int fda2[2];				// pipe from compressor
  if( pipe( fda ) < 0 || pipe( fda2 ) < 0 )
    { show_error( "Can't create pipe", errno ); return fatal( 1 ); }
  const pid_t pid = fork();
  if( pid == 0 )			// child 1 (compressor feeder)
    {
    if( close( fda[0] ) != 0 ||
        close( fda2[0] ) != 0 || close( fda2[1] ) != 0 ||
        !feed_data( mbuffer, msize, dsize, good_dsize, rbuf, rsize, offset,
                    dictionary_size, fda[1] ) )
      { close( fda[1] ); _exit( 2 ); }
    if( close( fda[1] ) != 0 )
      { show_close_error(); _exit( 2 ); }
    _exit( 0 );
    }
  if( pid < 0 )			// parent
    { show_fork_error( "data feeder" ); return fatal( 1 ); }

  const pid_t pid2 = fork();
  if( pid2 == 0 )			// child 2 (compressor)
    {
    if( dup2( fda[0], STDIN_FILENO ) >= 0 &&
        dup2( fda2[1], STDOUT_FILENO ) >= 0 &&
        close( fda[0] ) == 0 && close( fda[1] ) == 0 &&
        close( fda2[0] ) == 0 && close( fda2[1] ) == 0 )
      execvp( lzip_argv[0], (char **)lzip_argv );
    show_exec_error( lzip_argv[0] );
    _exit( 2 );
    }
  if( pid2 < 0 )			// parent
    { show_fork_error( lzip_argv[0] ); return fatal( 1 ); }

  close( fda[0] ); close( fda[1] ); close( fda2[1] );
  const long xend = std::min( end + 4, msize );
  int retval = 0;				// -1 = mismatch
  bool first_post = true;
  bool same_ds = true;				// reproduced DS == header DS
  bool tail_mismatch = false;			// mismatch after end
  for( long i = 0; i < xend; )
    {
    enum { buffer_size = 16384 };		// 65536 makes it slower
    uint8_t buffer[buffer_size];
    if( verbosity >= 2 && i >= 65536 && terminator )
      {
      if( first_post )
        { first_post = false; print_pending_newline( terminator ); }
      std::printf( "  Reproducing position %s %c", format_num3( i ), terminator );
      std::fflush( stdout ); pending_newline = true;
      }
    const int rd = readblock( fda2[0], buffer, buffer_size );
    // not enough reference data to fill zeroed sector at this level
    if( rd <= 0 ) { if( i < end ) retval = -1; break; }
    int j = 0;
    /* Compare reproduced bytes with data in mbuffer.
       Do not fail because of a mismatch beyond the end of the zeroed sector
       to prevent the reproduction from failing because of the reference file
       just covering the zeroed sector. */
    for( ; j < rd && i < begin; ++j, ++i )
      if( mbuffer[i] != buffer[j] )			// mismatch
        {
        if( i != 5 ) { retval = -1; goto done; }	// ignore different DS
        const Lzip_header * header = (const Lzip_header *)buffer;
        if( header->dictionary_size() != dictionary_size ) same_ds = false;
        }
    // copy reproduced bytes into zeroed sector of mbuffer
    for( ; j < rd && i < end; ++j, ++i ) mbuffer[i] = buffer[j];
    for( ; j < rd && i < xend; ++j, ++i )
      if( mbuffer[i] != buffer[j] ) { tail_mismatch = true; goto done; }
    }
done:
  if( !first_post && terminator ) print_pending_newline( terminator );
  if( close( fda2[0] ) != 0 ) { show_close_error( "compressor" ); retval = 1; }
  if( !good_status( pid, "data feeder", false ) ||
      !good_status( pid2, lzip_argv[0], false ) ) retval = auto0 ? -1 : 1;
  if( retval == 0 )		// test whole member after reproduction
    {
    if( md5sump ) md5sump->reset();
    LZ_mtester mtester( mbuffer, msize, dictionary_size, -1, md5sump );
    if( mtester.test_member() != 0 || !mtester.finished() )
      {
      if( verbosity >= 2 && same_ds && begin >= 4096 && terminator )
        {
        if( !tail_mismatch )
          final_msg = "  Zeroed sector reproduced, but CRC does not match."
                      " (Multiple damages in file?).\n";
        else if( !final_msg )
          final_msg = "  Zeroed sector reproduced, but data after it does not"
                      " match. (Maybe wrong reference data or lzip version).\n";
        }
      retval = -1;		// incorrect reproduction of zeroed sector
      }
    }
  return retval;
  }


// Return value: -1 = master failed, 0 = success, > 0 = failure
int reproduce_member( uint8_t * const mbuffer, const long msize,
                      const long long dsize, const char * const lzip_name,
                      const char * const reference_filename, const long begin,
                      const long size, const int lzip_level,
                      MD5SUM * const md5sump, const char terminator )
  {
  struct stat st;
  const int rfd = open_instream( reference_filename, &st, false, true );
  if( rfd < 0 ) return fatal( 1 );
  if( !fits_in_size_t( st.st_size ) )		// mmap uses size_t
    { show_file_error( reference_filename, "Reference file is too large for mmap." );
      close( rfd ); return fatal( 1 ); }
  const long rsize = st.st_size;
  const uint8_t * const rbuf =
    (const uint8_t *)mmap( 0, rsize, PROT_READ, MAP_PRIVATE, rfd, 0 );
  close( rfd );
  if( rbuf == MAP_FAILED )
    { show_file_error( reference_filename, mmap_msg, errno );
      return fatal( 1 ); }

  const Lzip_header & header = *(const Lzip_header *)mbuffer;
  const unsigned dictionary_size = header.dictionary_size();
  const LZ_mtester * const master =
    prepare_master2( mbuffer, msize, begin, dictionary_size );
  if( !master ) return -1;
  if( verbosity >= 2 )
    {
    std::printf( "  (master mpos = %s, dpos = %s)\n",
                 format_num3( master->member_position() ),
                 format_num3( master->data_position() ) );
    std::fflush( stdout );
    }

  const long offset = match_file( *master, rbuf, rsize, reference_filename );
  if( offset < 0 ) { delete master; return 2; }		// no match
  /* Reference data from offset must be at least as large as zeroed sector
     minus member trailer if trailer is inside the zeroed sector. */
  const int t = (begin + size >= msize) ? 16 + Lzip_trailer::size : 0;
  if( rsize - offset < size - t )
    { show_file_error( reference_filename, "Not enough reference data after match." );
      delete master; return 2; }

  const unsigned long long good_dsize = master->data_position();
  const long end = begin + size;
  char level_str[8] = "-0";	// compression level or match length limit
  char dict_str[16];
  snprintf( dict_str, sizeof dict_str, "-s%u", dictionary_size );
  const char * lzip0_argv[3] = { lzip_name, "-0", 0 };
  const char * lzip_argv[4] = { lzip_name, level_str, dict_str, 0 };
  if( lzip_level >= 0 )
    for( unsigned char level = '0'; level <= '9'; ++level )
      {
      if( std::isdigit( lzip_level ) && level != lzip_level ) continue;
      level_str[1] = level;
      if( verbosity >= 1 && terminator )
        {
        std::printf( "Trying level %s %c", level_str, terminator );
        std::fflush( stdout ); pending_newline = true;
        }
      const bool level0 = level == '0';
      const bool auto0 = level0 && lzip_level != '0';
      int ret = try_reproduce( mbuffer, msize, dsize, good_dsize, begin, end,
                               rbuf, rsize, offset, dictionary_size,
                level0 ? lzip0_argv : lzip_argv, md5sump, terminator, auto0 );
      if( ret >= 0 )
        { delete master; munmap( (void *)rbuf, rsize ); return ret; }
      }
  if( lzip_level <= 0 )
    {
    for( int len = min_match_len_limit; len <= max_match_len; ++len )
      {
      if( lzip_level < -1 && -lzip_level != len ) continue;
      snprintf( level_str, sizeof level_str, "-m%u", len );
      if( verbosity >= 1 && terminator )
        {
        std::printf( "Trying match length limit %d %c", len, terminator );
        std::fflush( stdout ); pending_newline = true;
        }
      int ret = try_reproduce( mbuffer, msize, dsize, good_dsize, begin, end,
                               rbuf, rsize, offset, dictionary_size,
                               lzip_argv, md5sump, terminator );
      if( ret >= 0 )
        { delete master; munmap( (void *)rbuf, rsize ); return ret; }
      }
    }
  delete master;
  munmap( (void *)rbuf, rsize );
  return 2;
  }

} // end namespace


int reproduce_file( const std::string & input_filename,
                    const std::string & default_output_filename,
                    const char * const lzip_name,
                    const char * const reference_filename,
                    const Cl_options & cl_opts, const int lzip_level,
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
  unsigned errors = 0;
  const long page_size = std::max( 1L, sysconf( _SC_PAGESIZE ) );
  for( long i = 0; i < lzip_index.members(); ++i )
    {
    const long long dsize = lzip_index.dblock( i ).size();
    const long long mpos = lzip_index.mblock( i ).pos();
    const long long msize = lzip_index.mblock( i ).size();
    if( verbosity >= 1 && lzip_index.members() > 1 )
      {
      std::printf( "Testing member %s of %s %c", format_num3( i + 1 ),
                   format_num3( lzip_index.members() ), terminator );
      std::fflush( stdout ); pending_newline = true;
      }
    if( !safe_seek( infd, mpos, input_filename ) ) return 1;
    long long failure_pos = 0;
    if( test_member_from_file( infd, msize, &failure_pos ) == 0 )
      continue;				// member is not damaged
    print_pending_newline( terminator );
    if( ++errors > 1 ) break;	// only one member can be reproduced
    if( failure_pos < Lzip_header::size )		// End Of File
      { show_file_error( filename, "Unexpected end of file." ); return 2; }
    if( !fits_in_size_t( msize + page_size ) )		// mmap uses size_t
      { show_file_error( filename, large_member_msg ); return 1; }

    // without mmap, 3 times more memory are required because of fork
    const long mpos_rem = mpos % page_size;
    uint8_t * const mbuffer_base = (uint8_t *)mmap( 0, msize + mpos_rem,
              PROT_READ | PROT_WRITE, MAP_PRIVATE, infd, mpos - mpos_rem );
    if( mbuffer_base == MAP_FAILED )
      { show_file_error( filename, mmap_msg, errno ); return 1; }
    uint8_t * const mbuffer = mbuffer_base + mpos_rem;
    long size = 0;
    uint8_t value = 0;
    const long begin = bursted_pos( mbuffer, msize, filename, &size, &value );
    if( begin < 0 ) return 2;
    if( failure_pos < begin )
      { show_file_error( filename, "Data error found before damaged area." );
        return 2; }
    if( verbosity >= 1 )
      {
      std::printf( "Reproducing bad area in member %s of %s\n"
                   "  (begin = %s, size = %s, value = 0x%02X)\n",
                   format_num3( i + 1 ), format_num3( lzip_index.members() ),
                   format_num3( begin ), format_num3( size ), value );
      std::fflush( stdout );
      }
    const int ret = reproduce_member( mbuffer, msize, dsize, lzip_name,
                  reference_filename, begin, size, lzip_level, 0, terminator );
    if( ret <= 0 ) print_pending_newline( terminator );
    if( ret < 0 ) { show_error( "Can't prepare master." ); return 1; }
    if( ret == 0 )
      {
      if( outfd < 0 )			// first damaged member reproduced
        {
        if( !safe_seek( infd, 0, input_filename ) ) return 1;
        set_signal_handler();
        if( !open_outstream( true, true, false, true, to_file ) ) return 1;
        if( !copy_file( infd, outfd, input_filename, output_filename ) )
          cleanup_and_fail( 1 );		// copy whole file
        }
      if( seek_write( outfd, mbuffer + begin, size, mpos + begin ) != size )
        { show_file_error( output_filename.c_str(), "Error writing file", errno );
          cleanup_and_fail( 1 ); }
      if( verbosity >= 1 )
        std::fputs( "Member reproduced successfully.\n", stdout );
      }
    munmap( mbuffer_base, msize + mpos_rem );
    if( ret > 0 )
      {
      if( final_msg )
        { std::fputs( final_msg, stdout ); std::fflush( stdout ); }
      show_file_error( filename, "Unable to reproduce member." ); return ret;
      }
    }

  if( outfd < 0 )
    {
    if( verbosity >= 1 )
      std::printf( "Input file '%s' has no errors. Recovery is not needed.\n",
                   filename );
    return 0;
    }
  if( !close_outstream( &in_stats ) ) return 1;
  if( verbosity >= 0 )
    {
    if( errors > 1 )
      std::fputs( "One member reproduced."
                  " Copy of input file still contains errors.\n", stdout );
    else
      std::printf( "Repaired copy of '%s' written to '%s'\n",
                   filename, output_filename.c_str() );
    }
  return 0;
  }


/* Passes a 0 terminator to other functions to prevent intramember feedback.
   Exits only in case of fatal error. (reference file too large, etc). */
int debug_reproduce_file( const std::string & input_filename,
                          const char * const lzip_name,
                          const char * const reference_filename,
                          const Cl_options & cl_opts, const Block & range,
                          const int sector_size, const int lzip_level )
  {
  const char * const filename = input_filename.c_str();
  struct stat in_stats;				// not used
  const int infd = open_instream( filename, &in_stats, false, true );
  if( infd < 0 ) return 1;

  const Lzip_index lzip_index( infd, cl_opts );
  if( lzip_index.retval() != 0 )
    { show_file_error( filename, lzip_index.error().c_str() );
      return lzip_index.retval(); }

  const long long cdata_size = lzip_index.cdata_size();
  if( range.pos() >= cdata_size )
    { show_file_error( filename, "Range is beyond end of last member." );
      return 1; }

  const long page_size = std::max( 1L, sysconf( _SC_PAGESIZE ) );
  const long long positions_to_test =
    ( ( std::min( range.size(), cdata_size - range.pos() ) ) +
      sector_size - 9 ) / sector_size;
  unsigned long positions = 0, successes = 0, failed_comparisons = 0,
                alternative_reproductions = 0;
  const bool pct_enabled = cdata_size > sector_size &&
                           isatty( STDERR_FILENO ) && !isatty( STDOUT_FILENO );
  for( long i = 0; i < lzip_index.members(); ++i )
    {
    const long long mpos = lzip_index.mblock( i ).pos();
    const long long msize = lzip_index.mblock( i ).size();
    if( !range.overlaps( mpos, msize ) ) continue;
    if( !fits_in_size_t( msize + page_size ) )		// mmap uses size_t
      { show_file_error( filename, large_member_msg ); return 1; }
    const long long dsize = lzip_index.dblock( i ).size();
    const unsigned dictionary_size = lzip_index.dictionary_size( i );

    // md5sums of original not damaged member (compressed and decompressed)
    md5_type md5_digest_c, md5_digest_d;
    bool md5_valid = false;
    const long long rm_end = std::min( range.end(), mpos + msize );
    for( long long sector_pos = std::max( range.pos(), mpos );
         sector_pos + 8 <= rm_end; sector_pos += sector_size )
      {
      // without mmap, 3 times more memory are required because of fork
      const long mpos_rem = mpos % page_size;
      uint8_t * const mbuffer_base = (uint8_t *)mmap( 0, msize + mpos_rem,
                PROT_READ | PROT_WRITE, MAP_PRIVATE, infd, mpos - mpos_rem );
      if( mbuffer_base == MAP_FAILED )
        { show_file_error( filename, mmap_msg, errno ); return 1; }
      uint8_t * const mbuffer = mbuffer_base + mpos_rem;
      if( !md5_valid )
        {
        if( verbosity >= 0 )	// give a clue of the range being tested
          { std::printf( "Reproducing:    %s\nReference file: %s\nTesting "
                         "sectors of size %s at file positions %s to %s\n",
                         filename, reference_filename,
                         format_num3( std::min( (long long)sector_size,
                         rm_end - sector_pos ) ), format_num3( sector_pos ),
                         format_num3( rm_end - 1 ) ); std::fflush( stdout ); }
        md5_valid = true; compute_md5( mbuffer, msize, md5_digest_c );
        MD5SUM md5sum;
        LZ_mtester mtester( mbuffer, msize, dictionary_size, -1, &md5sum );
        if( mtester.test_member() != 0 || !mtester.finished() )
          {
          if( verbosity >= 0 )
            { std::printf( "Member %s of %s already damaged (failure pos = %s)\n",
                           format_num3( i + 1 ), format_num3( lzip_index.members() ),
                           format_num3( mpos + mtester.member_position() ) );
              std::fflush( stdout ); }
          munmap( mbuffer_base, msize + mpos_rem ); break;
          }
        md5sum.md5_finish( md5_digest_d );
        }
      ++positions;
      const int sector_sz =
        std::min( (long long)sector_size, rm_end - sector_pos );
      // set mbuffer[sector] to 0
      std::memset( mbuffer + ( sector_pos - mpos ), 0, sector_sz );
      long size = 0;
      const long begin = bursted_pos( mbuffer, msize, filename, &size );
      if( begin < 0 ) return 2;
      MD5SUM md5sum;
      const int ret = reproduce_member( mbuffer, msize, dsize, lzip_name,
                    reference_filename, begin, size, lzip_level, &md5sum, 0 );
      if( ret < 0 ) { show_error( "Can't prepare master." ); return 1; }
      if( ret == 0 )
        {
        ++successes;
        md5_type new_digest;
        md5sum.md5_finish( new_digest );
        if( md5_digest_d != new_digest )
          {
          ++failed_comparisons;
          if( verbosity >= 0 ) std::printf( "Comparison failed at pos %s\n",
                               format_num3( sector_pos ) );
          }
        else if( !check_md5( mbuffer, msize, md5_digest_c ) )
          {
          ++alternative_reproductions;
          if( verbosity >= 0 ) std::printf( "Alternative reproduction at pos %s\n",
                               format_num3( sector_pos ) );
          }
        else if( verbosity >= 0 )
          std::printf( "Reproduction succeeded at pos %s\n",
                       format_num3( sector_pos ) );
        }
      else if( verbosity >= 0 )				// ret > 0
        std::printf( "Unable to reproduce at pos %s\n",
                     format_num3( sector_pos ) );
      if( verbosity >= 0 )
        {
        std::fflush( stdout );				// flush result line
        if( pct_enabled )				// show feedback
          std::fprintf( stderr, "\r%s sectors  %s successes  %s failcomp  "
                        "%s altrep  %3u%% done\r",
                        format_num3( positions ), format_num3( successes ),
                        format_num3( failed_comparisons ),
                        format_num3( alternative_reproductions ),
                        (unsigned)( ( positions * 100.0 ) / positions_to_test ) );
        }
      munmap( mbuffer_base, msize + mpos_rem );
      if( fatal_retval ) goto done;
      }
    }
done:
  if( verbosity >= 0 )
    {
    std::printf( "\n%11s sectors tested"
                 "\n%11s reproductions returned with zero status",
                 format_num3( positions ), format_num3( successes ) );
    if( successes > 0 )
      {
      if( failed_comparisons > 0 )
        std::printf( ", of which\n%11s comparisons failed\n",
                     format_num3( failed_comparisons ) );
      else std::fputs( "\n            all comparisons passed\n", stdout );
      if( alternative_reproductions > 0 )
        std::printf( "%11s alternative reproductions found\n",
                     format_num3( alternative_reproductions ) );
      }
    else std::fputc( '\n', stdout );
    if( fatal_retval )
      std::fputs( "Exiting because of a fatal error\n", stdout );
    }
  return fatal_retval;
  }
