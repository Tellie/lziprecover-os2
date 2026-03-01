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

class Lzip_index
  {
  struct Member
    {
    Block dblock, mblock;		// data block, member block
    unsigned dictionary_size;

    Member( const long long dpos, const long long dsize,
            const long long mpos, const long long msize,
            const unsigned dict_size )
      : dblock( dpos, dsize ), mblock( mpos, msize ),
        dictionary_size( dict_size ) {}

    bool operator==( const Member & m ) const { return mblock == m.mblock; }
    bool operator!=( const Member & m ) const { return mblock != m.mblock; }
    };

  // member_vector only contains members with a valid header.
  // Garbage between members is represented by gaps between mblocks.
  std::vector< Member > member_vector;
  std::string error_;
  long long insize;
  int retval_;
  unsigned dictionary_size_;	// largest dictionary size in the file
  bool boxed_tdata_;		// all tdata is inside a single box
  bool good_magic_;		// good magic in first header

  bool check_header( const Lzip_header & header, const bool first,
                     const bool ignore_bad_ds );
  void set_errno_error( const char * const msg );
  void set_num_error( const char * const msg, unsigned long long num );
  bool read_header( const int fd, Lzip_header & header, const long long pos );
  bool read_trailer( const int fd, Lzip_trailer & trailer,
                     const long long pos );
  bool skip_gap( const int fd, unsigned long long & pos,
                 const Cl_options & cl_opts,
                 const bool ignore_bad_ds, const bool ignore_gaps );

public:
  Lzip_index()
    : error_( "No index" ), insize( 0 ), retval_( 2 ), dictionary_size_( 0 ) {}
  Lzip_index( const int infd, const Cl_options & cl_opts,
              const bool ignore_bad_ds = false, const bool ignore_gaps = false,
              const long long max_pos = 0 );
  Lzip_index( const std::vector< int > & infd_vector, const long long fsize );

  long members() const { return member_vector.size(); }
  long blocks( const bool count_tdata ) const;	// members + gaps [+ tdata]
  const std::string & error() const { return error_; }
  int retval() const { return retval_; }
  unsigned dictionary_size() const { return dictionary_size_; }
  bool boxed_tdata() const { return boxed_tdata_; }
  bool good_magic() const { return good_magic_; }

  bool multi_empty() const	// multimember file with empty member(s)
    {
    if( member_vector.size() > 1 )
      for( unsigned long i = 0; i < member_vector.size(); ++i )
        if( member_vector[i].dblock.size() == 0 ) return true;
    return false;
    }

  bool operator==( const Lzip_index & li ) const
    {
    if( retval_ || li.retval_ || insize != li.insize ||
        member_vector.size() != li.member_vector.size() ) return false;
    for( unsigned long i = 0; i < member_vector.size(); ++i )
      if( member_vector[i] != li.member_vector[i] ) return false;
    return true;
    }
  bool operator!=( const Lzip_index & li ) const { return !( *this == li ); }

  long long udata_size() const
    { if( member_vector.empty() ) return 0;
      return member_vector.back().dblock.end(); }

  long long cdata_size() const
    { if( member_vector.empty() ) return 0;
      return member_vector.back().mblock.end(); }

  // total size including trailing data (if any)
  long long file_size() const
    { if( insize >= 0 ) return insize; else return 0; }

  const Block & dblock( const long i ) const
    { return member_vector[i].dblock; }
  const Block & mblock( const long i ) const
    { return member_vector[i].mblock; }
  unsigned dictionary_size( const long i ) const
    { return member_vector[i].dictionary_size; }
  };

//const uint8_t box_magic[8] = { 0x54, 0x44, 0x41, 0x54, 0x41, 0x42, 0x4F, 0x58 };
const uint8_t box_magic[8] = { 'T', 'D', 'A', 'T', 'A', 'B', 'O', 'X' };
enum { min_box_size = 16 };

struct Box_trailer
  {
  uint8_t data[8];		// box size including magic and trailer

  unsigned long long box_size() const
    {
    unsigned long long tmp = 0;
    for( int i = 7; i >= 0; --i ) { tmp <<= 8; tmp += data[i]; }
    return tmp;
    }

  void box_size( unsigned long long sz )
    { for( int i = 0; i <= 7; ++i ) { data[i] = (uint8_t)sz; sz >>= 8; } }
  };

int seek_read( const int fd, uint8_t * const buf, const int size,
               const long long pos );
// return <0 if error
long long skip_box( const int infd, long long pos, long long * box_sizep = 0 );
