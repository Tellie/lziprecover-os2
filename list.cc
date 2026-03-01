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

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <stdint.h>
#include <unistd.h>
#include <sys/stat.h>

#include "lzip.h"
#include "lzip_index.h"


namespace {

void list_line( const unsigned long long uncomp_size,
                const unsigned long long comp_size,
                const char * const input_filename )
  {
  if( uncomp_size > 0 )
    std::printf( "%14s %14s %6.2f%%  %s\n",
                 format_num3( uncomp_size ), format_num3( comp_size ),
                 100.0 - ( ( 100.0 * comp_size ) / uncomp_size ),
                 input_filename );
  else
    std::printf( "%14llu %14llu   -INF%%  %s\n", uncomp_size, comp_size,
                 input_filename );
  }

} // end namespace


int list_files( const std::vector< std::string > & filenames,
                const Cl_options & cl_opts )
  {
  unsigned long long total_comp = 0, total_uncomp = 0;
  unsigned files = 0;
  int retval = 0;
  bool first_post = true;
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
    close( infd );
    if( lzip_index.retval() != 0 )
      {
      show_file_error( input_filename, lzip_index.error().c_str() );
      set_retval( retval, lzip_index.retval() );
      continue;
      }
    const bool multi_empty =
      !from_stdin && !cl_opts.ignore_errors && lzip_index.multi_empty();
    if( multi_empty ) set_retval( retval, 2 );
    if( verbosity < 0 ) continue;
    const unsigned long long udata_size = lzip_index.udata_size();
    const unsigned long long cdata_size = lzip_index.cdata_size();
    const unsigned long long tdata_size = lzip_index.file_size() - cdata_size;
    total_comp += cdata_size; total_uncomp += udata_size; ++files;
    const long members = lzip_index.members();
    if( first_post )
      {
      first_post = false;
      if( verbosity >= 1 ) std::fputs( "   dict    memb  ", stdout );
      std::fputs( "  uncompressed     compressed   saved  name\n", stdout );
      }
    if( multi_empty ) { std::fflush( stdout );
      show_file_error( input_filename, empty_member_msg ); }
    if( verbosity >= 1 )
      std::printf( "%s %5lu%s ", format_ds( lzip_index.dictionary_size() ),
                   members, tdata_size ? "+t" : "  " );
    list_line( udata_size, cdata_size, input_filename );

    if( verbosity >= 2 && ( members > 1 || tdata_size > 0 ||
        ( members == 1 && lzip_index.mblock( 0 ).pos() > 0 ) ) )
      {
      std::fputs( " member      data_pos      data_size     member_pos    member_size\n", stdout );
      long long prev_end = 0;
      for( long j = 0, gaps = 0; j < members; ++j )
        {
        const Block & db = lzip_index.dblock( j );
        const Block & mb = lzip_index.mblock( j );
        if( mb.pos() > prev_end )
          { std::printf( "   gap              -              - %14s %14s\n",
                         format_num3( prev_end ),
                         format_num3( mb.pos() - prev_end ) ); ++gaps; }
        std::printf( "%6s %14s %14s %14s %14s\n", format_num3( j + gaps + 1 ),
                     format_num3( db.pos() ), format_num3( db.size() ),
                     format_num3( mb.pos() ), format_num3( mb.size() ) );
        prev_end = mb.end();
        }
      if( tdata_size > 0 ) std::printf( " tdata %44s %14s\n",
        format_num3( cdata_size ), format_num3( tdata_size ) );
      if( i + 1 < filenames.size() || files > 1 ) std::fputc( '\n', stdout );
      first_post = true;	// reprint heading after list of members
      }
    std::fflush( stdout );
    if( std::ferror( stdout ) ) break;
    }
  if( verbosity >= 0 && files > 1 && !std::ferror( stdout ) )
    {
    if( verbosity >= 2 && first_post )
      std::fputs( "                   uncompressed     compressed   saved\n", stdout );
    if( verbosity >= 1 ) std::fputs( "                 ", stdout );
    list_line( total_uncomp, total_comp, "(totals)" );
    std::fflush( stdout );
    }
  if( verbosity >= 0 && ( std::ferror( stdout ) || std::fclose( stdout ) != 0 ) )
    { show_file_error( "(stdout)", wr_err_msg, errno );
      set_retval( retval, 1 ); }
  return retval;
  }
