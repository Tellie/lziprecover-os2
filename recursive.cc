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

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <list>
#include <string>
#include <vector>
#include <dirent.h>
#include <stdint.h>
#include <sys/stat.h>

#include "lzip.h"
#include "md5.h"
#include "fec.h"

namespace {

// Return true if full_name is a regular file or (a link to) a directory.
bool test_full_name( const std::string & full_name, const struct stat * stp,
                     const bool follow )
  {
  struct stat st, st2;
  if( ( follow && stat( full_name.c_str(), &st ) != 0 ) ||
      ( !follow && lstat( full_name.c_str(), &st ) != 0 ) ) return false;
  if( S_ISREG( st.st_mode ) ) return true;
  if( !S_ISDIR( st.st_mode ) ) return false;

  std::string prev_dir( full_name );
  bool loop = stp && st.st_ino == stp->st_ino && st.st_dev == stp->st_dev;
  if( !loop )
    for( unsigned i = prev_dir.size(); i > 1; )
      {
      while( i > 0 && prev_dir[i-1] != '/' ) --i;
      if( i == 0 ) break;
      if( i > 1 ) --i;		// remove trailing slash except at root dir
      prev_dir.resize( i );
      if( stat( prev_dir.c_str(), &st2 ) != 0 || !S_ISDIR( st2.st_mode ) ||
          ( st.st_ino == st2.st_ino && st.st_dev == st2.st_dev ) )
        { loop = true; break; }
      }
  if( loop )			// full_name already visited or above tree
    show_file_error( full_name.c_str(), "warning: recursive directory loop." );
  return !loop;			// (link to) directory
  }


bool ignore_name( const std::string & name )
  {
  if( name == "." || name == ".." || name == "fec" || name == "FEC" ||
      has_fec_extension( name ) ) return true;
  return name.size() > 3 && name.compare( name.size() - 3, 3, "fec" ) == 0 &&
         ( name.end()[-4] == '-' || name.end()[-4] == '.' ||
           name.end()[-4] == '_' );
  }

} // end namespace


/* Return in input_filename the next file name. ('-' is a valid file name).
   Ignore recursively found files and directories named "fec" or "*[-._]fec".
   Set 'retval' to 1 if a directory fails to open. */
bool next_filename( std::list< std::string > & filelist,
                    std::string & input_filename, int & retval,
                    const char recursive )
  {
  while( !filelist.empty() )
    {
    input_filename = filelist.front();
    filelist.pop_front();
    struct stat st;
    if( stat( input_filename.c_str(), &st ) == 0 && S_ISDIR( st.st_mode ) )
      {
      if( recursive )
        {
        DIR * const dirp = opendir( input_filename.c_str() );
        if( !dirp )
          {
          show_file_error( input_filename.c_str(), "Can't open directory", errno );
          if( retval == 0 ) { retval = 1; } continue;
          }
        for( unsigned i = input_filename.size();
             i > 1 && input_filename[i-1] == '/'; --i )
          input_filename.resize( i - 1 );	// remove trailing slashes
        struct stat stdot, *stdotp = 0;
        if( input_filename[0] != '/' )		// relative file name
          {
          if( input_filename == "." ) input_filename.clear();
          if( stat( ".", &stdot ) == 0 && S_ISDIR( stdot.st_mode ) )
            stdotp = &stdot;
          }
        if( input_filename.size() && input_filename != "/" )
          input_filename += '/';
        std::list< std::string > tmp_list;
        while( true )
          {
          const struct dirent * const entryp = readdir( dirp );
          if( !entryp ) { closedir( dirp ); break; }
          const std::string tmp_name( entryp->d_name );
          if( ignore_name( tmp_name ) ) continue;
          const std::string full_name( input_filename + tmp_name );
          if( test_full_name( full_name, stdotp, recursive == 2 ) )
            tmp_list.push_back( full_name );
          }
        filelist.splice( filelist.begin(), tmp_list );
        }
      continue;
      }
    return true;
    }
  input_filename.clear();
  return false;
  }
