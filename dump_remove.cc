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
#include <cstring>
#include <string>
#include <vector>
#include <stdint.h>
#include <unistd.h>
#include <utime.h>
#include <sys/stat.h>

#include "lzip.h"
#include "lzip_index.h"


namespace {

const char * const pdate_msg = "warning: can't preserve file date";


/* Return the address of a malloc'd buffer containing the file data and
   the file size in '*file_sizep'.
   If the data contain zero and nonzero bytes, insert them in a tdatabox.
   In case of error, return 0 and do not modify '*file_sizep'.
*/
const uint8_t * read_file( const std::string & name, long * const file_sizep,
                           uint8_t ** base_bufferp )
  {
  struct stat in_stats;					// not used
  const char * const filename = printable_name( name );
  const int infd = (name == "-") ?
    STDIN_FILENO : open_instream( name.c_str(), &in_stats, false );
  if( infd < 0 ) return 0;
  long buffer_size = 65536;
  uint8_t * buffer = (uint8_t *)std::malloc( buffer_size );
  if( !buffer )
    { show_file_error( filename, mem_msg ); close( infd ); return 0; }
  std::memcpy( buffer, box_magic, 8 );
  long file_size = readblock( infd, buffer + 8, buffer_size - min_box_size ) + 8;
  while( file_size >= buffer_size - 8 && !errno )
    {
    if( buffer_size >= LONG_MAX ) { show_file_error( filename, large_file_msg );
      std::free( buffer ); close( infd ); return 0; }
    buffer_size = (buffer_size <= LONG_MAX / 2) ? 2 * buffer_size : LONG_MAX;
    uint8_t * const tmp = (uint8_t *)std::realloc( buffer, buffer_size );
    if( !tmp ) { show_file_error( filename, mem_msg ); std::free( buffer );
                 close( infd ); return 0; }
    buffer = tmp;
    file_size +=
      readblock( infd, buffer + file_size, buffer_size - 8 - file_size );
    }
  if( errno )
    { show_file_error( filename, rd_err_msg, errno );
      std::free( buffer ); close( infd ); return 0; }
  if( close( infd ) != 0 )
    { show_file_error( filename, "Error closing input file", errno );
      std::free( buffer ); return 0; }
  if( file_size <= 8 )
    { show_file_error( filename, empty_file_msg );
      std::free( buffer ); return 0; }
  *base_bufferp = buffer;
  bool boxed = false;
  if( buffer[8] == 0 )
    { for( long i = 9; i < file_size; ++i ) if( buffer[i] != 0 )
        { boxed = true; break; } }
  else if( file_size > 9 && std::memchr( buffer + 9, 0, file_size - 9 ) != 0 )
    boxed = true;
  if( boxed )
    { Box_trailer & trailer = *(Box_trailer *)( buffer + file_size );
      file_size += 8; trailer.box_size( file_size ); }
  else { buffer += 8; file_size -= 8; }	// don't free this displaced buffer
  *file_sizep = file_size;
  return buffer;
  }

} // end namespace


int append_tdata( const std::vector< std::string > & filenames,
                  const std::string & append_filename,
                  const Cl_options & cl_opts, const bool force )
  {
  uint8_t * base_buffer = 0;
  long append_size = 0;
  const uint8_t * const buffer =
    read_file( append_filename, &append_size, &base_buffer );
  if( !buffer ) return 1;
  int retval = 0;
  bool stdout_used = false;
  for( unsigned i = 0; i < filenames.size(); ++i )
    {
    const bool is_stdout = filenames[i] == "-";
    if( is_stdout ) { if( stdout_used ) continue; else stdout_used = true; }
    const char * const filename = is_stdout ? "(stdout)" : filenames[i].c_str();
    struct stat in_stats;				// not used
    const int fd = is_stdout ?
      STDOUT_FILENO : open_truncable_stream( filename, &in_stats );
    if( fd < 0 ) { set_retval( retval, 1 ); continue; }

    if( is_stdout )
      {
      if( writeblock( fd, buffer, append_size ) != append_size )
        { show_file_error( filename, wr_err_msg, errno );
          set_retval( retval, 1 ); break; }
      }
    else
      {
      const Lzip_index lzip_index( fd, cl_opts );
      if( lzip_index.retval() != 0 )
        {
        show_file_error( filename, lzip_index.error().c_str() );
        set_retval( retval, lzip_index.retval() );
        close( fd );
        continue;
        }
      const long long append_pos = lzip_index.cdata_size();
      const long long file_size = lzip_index.file_size();
      if( append_pos < file_size )
        {
        if( !force )
          { show_file_error( filename, "File already has trailing data. "
              "Use '--force' to overwrite existing trailing data." );
            set_retval( retval, 1 ); close( fd ); break; }
        int result;
        do result = ftruncate( fd, append_pos );
          while( result != 0 && errno == EINTR );
        if( result != 0 )
          { show_file_error( filename, "Can't truncate file", errno );
            set_retval( retval, 1 ); close( fd ); break; }
        }
      if( seek_write( fd, buffer, append_size, append_pos ) != append_size )
        { show_file_error( filename, wr_err_msg, errno );
          set_retval( retval, 1 ); close( fd ); break; }
      if( close( fd ) != 0 )
        { show_file_error( filename, "Error closing file", errno );
          set_retval( retval, 1 ); break; }
      }
    }
  std::free( base_buffer );
  if( stdout_used && close( STDOUT_FILENO ) != 0 )
    { show_error( "Error closing stdout", errno ); set_retval( retval, 1 ); }
  return retval;
  }


/* If strip is false, dump to outfd members/gaps/tdata in member_list.
   If strip is true, dump to outfd members/gaps/tdata not in member_list.
   Remove databox header and trailer when dumping boxed tdata alone. */
int dump_members( const std::vector< std::string > & filenames,
                  const std::string & default_output_filename,
                  const Cl_options & cl_opts, const Member_list & member_list,
                  const bool force, const bool strip, const bool to_stdout )
  {
  if( to_stdout || default_output_filename.empty() ) outfd = STDOUT_FILENO;
  else
    {
    output_filename = default_output_filename;
    set_signal_handler();
    if( !open_outstream( force, false, false, false ) ) return 1;
    }
  const bool dump_tdata_alone = !strip && member_list.tdata &&
    !member_list.damaged && !member_list.empty && !member_list.range();
  if( !dump_tdata_alone && !check_tty_out() ) return 1;
  unsigned long long copied_size = 0, stripped_size = 0;
  unsigned long long copied_tsize = 0, stripped_tsize = 0;
  unsigned long members = 0, smembers = 0;
  unsigned files = 0, tfiles = 0;
  int retval = 0;
  bool stdin_used = false;
  for( unsigned i = 0; i < filenames.size(); ++i )
    {
    const bool from_stdin = filenames[i] == "-";
    if( from_stdin ) { if( stdin_used ) continue; else stdin_used = true; }
    const char * const input_filename =
      from_stdin ? "(stdin)" : filenames[i].c_str();
    struct stat in_stats;				// not used
    const int infd = from_stdin ? STDIN_FILENO :
      open_instream( input_filename, &in_stats, false, true );
    if( infd < 0 ) { set_retval( retval, 1 ); continue; }

    const Lzip_index lzip_index( infd, cl_opts, cl_opts.ignore_errors,
                                 cl_opts.ignore_errors );
    if( lzip_index.retval() != 0 )
      {
      show_file_error( input_filename, lzip_index.error().c_str() );
      set_retval( retval, lzip_index.retval() );
      close( infd );
      continue;
      }
    if( !safe_seek( infd, 0, input_filename ) ) cleanup_and_fail( 1 );
    const long blocks = lzip_index.blocks( false );	// not counting tdata
    long long stream_pos = 0;		// first pos not yet read from file
    long gaps = 0;
    const unsigned long prev_members = members, prev_smembers = smembers;
    const unsigned long long prev_stripped_size = stripped_size;
    for( long j = 0; j < lzip_index.members(); ++j )	// copy members and gaps
      {
      const Block & mb = lzip_index.mblock( j );
      if( mb.pos() > stream_pos )				// gap
        {
        const bool in = member_list.damaged ||
                        member_list.includes( j + gaps, blocks );
        if( in == !strip )
          {
          if( !safe_seek( infd, stream_pos, input_filename ) ||
              !copy_file( infd, outfd, filenames[i], output_filename,
                          mb.pos() - stream_pos ) ) cleanup_and_fail( 1 );
          copied_size += mb.pos() - stream_pos; ++members;
          }
        else { stripped_size += mb.pos() - stream_pos; ++smembers; }
        ++gaps;
        }
      bool in = member_list.includes( j + gaps, blocks );	// member
      if( !in && member_list.empty && lzip_index.dblock( j ).size() == 0 )
        in = true;
      if( !in && member_list.damaged )
        {
        if( !safe_seek( infd, mb.pos(), input_filename ) ) cleanup_and_fail( 1 );
        in = test_member_from_file( infd, mb.size() ) != 0;	// damaged
        }
      if( in == !strip )
        {
        if( !safe_seek( infd, mb.pos(), input_filename ) ||
            !copy_file( infd, outfd, filenames[i], output_filename,
                        mb.size() ) ) cleanup_and_fail( 1 );
        copied_size += mb.size(); ++members;
        }
      else { stripped_size += mb.size(); ++smembers; }
      stream_pos = mb.end();
      }
    if( strip && members == prev_members )	// all members were stripped
      { if( verbosity >= 1 )
          show_file_error( input_filename, "All members stripped, skipping." );
        stripped_size = prev_stripped_size; smembers = prev_smembers;
        close( infd ); continue; }
    if( ( !strip && members > prev_members ) ||
        ( strip && smembers > prev_smembers ) ) ++files;
    // copy trailing data
    unsigned long long cdata_size = lzip_index.cdata_size();
    long long tdata_size = lzip_index.file_size() - cdata_size;
    if( member_list.tdata == !strip && tdata_size > 0 &&
        ( !strip || i + 1 >= filenames.size() ) )	// strip all but last
      {
      if( dump_tdata_alone && lzip_index.boxed_tdata() )
        { cdata_size += 8; tdata_size -= min_box_size; }  // remove databox
      if( !safe_seek( infd, cdata_size, input_filename ) ||
          !copy_file( infd, outfd, filenames[i], output_filename,
                      tdata_size ) ) cleanup_and_fail( 1 );
      copied_tsize += tdata_size;
      }
    else if( tdata_size > 0 ) { stripped_tsize += tdata_size; ++tfiles; }
    close( infd );
    }
  if( !close_outstream( 0 ) ) set_retval( retval, 1 );
  if( verbosity >= 1 )
    {
    if( !strip )
      {
      if( member_list.damaged || member_list.empty || member_list.range() )
        std::fprintf( stderr, "%s bytes dumped from %s %s from %u %s.\n",
                      format_num3( copied_size ), format_num3( members ),
                      ( members == 1 ) ? "member" : "members",
                      files, ( files == 1 ) ? "file" : "files" );
      if( member_list.tdata )
        std::fprintf( stderr, "%s trailing bytes dumped.\n",
                      format_num3( copied_tsize ) );
      }
    else
      {
      if( member_list.damaged || member_list.empty || member_list.range() )
        std::fprintf( stderr, "%s bytes stripped from %s %s from %u %s.\n",
                      format_num3( stripped_size ), format_num3( smembers ),
                      ( smembers == 1 ) ? "member" : "members",
                      files, ( files == 1 ) ? "file" : "files" );
      if( member_list.tdata )
        std::fprintf( stderr, "%s trailing bytes stripped from %u %s.\n",
                      format_num3( stripped_tsize ),
                      tfiles, ( tfiles == 1 ) ? "file" : "files" );
      }
    }
  return retval;
  }


/* Remove members, tdata from files in place by opening two descriptors for
   each file. */
int remove_members( const std::vector< std::string > & filenames,
                  const Cl_options & cl_opts, const Member_list & member_list )
  {
  unsigned long long removed_size = 0, removed_tsize = 0;
  unsigned long members = 0;
  unsigned files = 0, tfiles = 0;
  int retval = 0;
  for( unsigned i = 0; i < filenames.size(); ++i )
    {
    const char * const filename = filenames[i].c_str();
    struct stat in_stats, dummy_stats;
    const int infd = open_instream( filename, &in_stats, false, true );
    if( infd < 0 ) { set_retval( retval, 1 ); continue; }

    const Lzip_index lzip_index( infd, cl_opts, cl_opts.ignore_errors,
                                 cl_opts.ignore_errors );
    if( lzip_index.retval() != 0 )
      {
      show_file_error( filename, lzip_index.error().c_str() );
      set_retval( retval, lzip_index.retval() );
      close( infd );
      continue;
      }
    const int fd = open_truncable_stream( filename, &dummy_stats );
    if( fd < 0 ) { close( infd ); set_retval( retval, 1 ); continue; }

    if( !safe_seek( infd, 0, filename ) ) return 1;
    const long blocks = lzip_index.blocks( false );	// not counting tdata
    long long stream_pos = 0;		// first pos not yet written to file
    long gaps = 0;
    bool error = false;
    const unsigned long prev_members = members;
    for( long j = 0; j < lzip_index.members(); ++j )	// copy members and gaps
      {
      const Block & mb = lzip_index.mblock( j );
      const long long prev_end = (j > 0) ? lzip_index.mblock(j - 1).end() : 0;
      if( mb.pos() > prev_end )					// gap
        {
        if( !member_list.damaged && !member_list.includes( j + gaps, blocks ) )
          {
          if( stream_pos != prev_end &&
              ( !safe_seek( infd, prev_end, filename ) ||
                !safe_seek( fd, stream_pos, filename ) ||
                !copy_file( infd, fd, filenames[i], filenames[i],
                            mb.pos() - prev_end ) ) )
            { error = true; set_retval( retval, 1 ); break; }
          stream_pos += mb.pos() - prev_end;
          }
        else ++members;
        ++gaps;
        }
      bool in = member_list.includes( j + gaps, blocks );	// member
      if( !in && member_list.empty && lzip_index.dblock( j ).size() == 0 )
        in = true;
      if( !in && member_list.damaged )
        {
        if( !safe_seek( infd, mb.pos(), filename ) )
          { error = true; set_retval( retval, 1 ); break; }
        in = test_member_from_file( infd, mb.size() ) != 0;	// damaged
        }
      if( !in )
        {
        if( stream_pos != mb.pos() &&
            ( !safe_seek( infd, mb.pos(), filename ) ||
              !safe_seek( fd, stream_pos, filename ) ||
              !copy_file( infd, fd, filenames[i], filenames[i], mb.size() ) ) )
          { error = true; set_retval( retval, 1 ); break; }
        stream_pos += mb.size();
        }
      else ++members;
      }
    if( error ) { close( fd ); close( infd ); break; }
    if( stream_pos == 0 )			// all members were removed
      { show_file_error( filename, "All members would be removed, skipping." );
        close( fd ); close( infd ); set_retval( retval, 2 );
        members = prev_members; continue; }
    const long long cdata_size = lzip_index.cdata_size();
    if( cdata_size > stream_pos )
      { removed_size += cdata_size - stream_pos; ++files; }
    const long long file_size = lzip_index.file_size();
    const long long tdata_size = file_size - cdata_size;
    if( tdata_size > 0 )
      {
      if( !member_list.tdata )	// copy trailing data
        {
        if( stream_pos != cdata_size &&
            ( !safe_seek( infd, cdata_size, filename ) ||
              !safe_seek( fd, stream_pos, filename ) ||
              !copy_file( infd, fd, filenames[i], filenames[i], tdata_size ) ) )
          { close( fd ); close( infd ); set_retval( retval, 1 ); break; }
        stream_pos += tdata_size;
        }
      else { removed_tsize += tdata_size; ++tfiles; }
      }
    if( stream_pos >= file_size )		// no members were removed
      { close( fd ); close( infd ); continue; }
    int result;
    do result = ftruncate( fd, stream_pos );
      while( result != 0 && errno == EINTR );
    if( result != 0 )
      {
      show_file_error( filename, "Can't truncate file", errno );
      close( fd ); close( infd ); set_retval( retval, 1 ); break;
      }
    if( close( fd ) != 0 || close( infd ) != 0 )
      {
      show_file_error( filename, "Error closing file", errno );
      set_retval( retval, 1 ); break;
      }
    struct utimbuf t;
    t.actime = in_stats.st_atime;
    t.modtime = in_stats.st_mtime;
    if( utime( filename, &t ) != 0 && verbosity >= 1 )
      show_file_error( filename, pdate_msg, errno );
    }
  if( verbosity >= 1 )
    {
    if( member_list.damaged || member_list.empty || member_list.range() )
      std::fprintf( stderr, "%s bytes removed from %s %s from %u %s.\n",
                    format_num3( removed_size ), format_num3( members ),
                    ( members == 1 ) ? "member" : "members",
                    files, ( files == 1 ) ? "file" : "files" );
    if( member_list.tdata )
      std::fprintf( stderr, "%s trailing bytes removed from %u %s.\n",
                    format_num3( removed_tsize ),
                    tfiles, ( tfiles == 1 ) ? "file" : "files" );
    }
  return retval;
  }


/* Set to zero in place the first LZMA byte of each member in each file by
   opening one rw descriptor for each file. */
int nonzero_repair( const std::vector< std::string > & filenames,
                    const Cl_options & cl_opts )
  {
  unsigned long cleared_members = 0;
  unsigned files = 0;
  int retval = 0;
  for( unsigned i = 0; i < filenames.size(); ++i )
    {
    const char * const filename = filenames[i].c_str();
    struct stat in_stats;
    const int fd = open_truncable_stream( filename, &in_stats );
    if( fd < 0 ) { set_retval( retval, 1 ); continue; }

    const Lzip_index lzip_index( fd, cl_opts, true, cl_opts.ignore_errors );
    if( lzip_index.retval() != 0 )
      {
      show_file_error( filename, lzip_index.error().c_str() );
      set_retval( retval, lzip_index.retval() );
      close( fd );
      continue;
      }

    enum { bufsize = Lzip_header::size + 1 };
    uint8_t header_buf[bufsize];
    const uint8_t * const p = header_buf;	// keep gcc 6.1.0 quiet
    const Lzip_header & header = *(const Lzip_header *)p;
    uint8_t * const mark = header_buf + header.size;
    bool write_attempted = false;
    for( long j = 0; j < lzip_index.members(); ++j )	// clear the members
      {
      const Block & mb = lzip_index.mblock( j );
      if( seek_read( fd, header_buf, bufsize, mb.pos() ) != bufsize )
        { show_file_error( filename, "Error reading member header", errno );
          set_retval( retval, 1 ); break; }
      if( !header.check( true ) )
        { show_file_error( filename, "Member header became corrupt as we read it." );
          set_retval( retval, 2 ); break; }
      if( *mark == 0 ) continue;
      *mark = 0; write_attempted = true;
      if( seek_write( fd, mark, 1, mb.pos() + header.size ) != 1 )
        { show_file_error( filename, "Error writing to file", errno );
          set_retval( retval, 1 ); break; }
      ++cleared_members;
      }
    if( close( fd ) != 0 )
      {
      show_file_error( filename, "Error closing file", errno );
      set_retval( retval, 1 ); break;
      }
    if( write_attempted )
      {
      struct utimbuf t;
      t.actime = in_stats.st_atime;
      t.modtime = in_stats.st_mtime;
      if( utime( filename, &t ) != 0 && verbosity >= 1 )
        show_file_error( filename, pdate_msg, errno );
      ++files;
      }
    }
  if( verbosity >= 1 )
    std::fprintf( stderr, "%s %s cleared in %u %s.\n",
                  format_num3( cleared_members ),
                  ( cleared_members == 1 ) ? "member" : "members",
                  files, ( files == 1 ) ? "file" : "files" );
  return retval;
  }
