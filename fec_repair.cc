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

#include <algorithm>
#include <cerrno>
#include <climits>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <new>
#include <list>
#include <string>
#include <vector>
#include <stdint.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include "lzip.h"
#include "md5.h"
#include "fec.h"


namespace {

void show_diag_msg( const std::string & input_filename, const char * const msg,
                    const bool debug = false )
  {
  if( verbosity >= ( debug ? 0 : 1 ) ) std::fprintf( stderr, "%s\n", msg );
  else show_file_error( input_filename.c_str(), msg );
  }


bool has_lz_extension( const std::string & name )
  {
  return ( name.size() > 3 &&
           name.compare( name.size() - 3, 3, ".lz" ) == 0 ) ||
         ( name.size() > 4 &&
           name.compare( name.size() - 4, 4, ".tlz" ) == 0 );
  }

bool has_fec_extension2( const std::string & name )
  {
  if( !has_fec_extension( name ) ) return false;
  if( verbosity >= 0 )
    std::fprintf( stderr, "%s: %s: Input file has '%s' suffix, ignored.\n",
                  program_name, name.c_str(), fec_extension );
  return true;
  }


const char * bad_fec_version( const unsigned version )
  {
  static char buf[80];
  snprintf( buf, sizeof buf, "Version %u fec format not supported.", version );
  return buf;
  }

// Return false if truncation removed all blocks.
bool truncate_block_vector( std::vector< Block > & block_vector,
                            const long long end )
  {
  unsigned i = block_vector.size();
  while( i > 0 && block_vector[i-1].pos() >= end ) --i;
  if( i == 0 ) { block_vector.clear(); return false; }
  Block & b = block_vector[i-1];
  if( b.includes( end ) ) b.size( end - b.pos() );
  if( i < block_vector.size() )
    block_vector.erase( block_vector.begin() + i, block_vector.end() );
  return true;
  }


class Fec_index
  {
  const uint8_t * fecdata_;
  const le32 * crc_array_;		// images allocated in fecdata
  const le32 * crcc_array_;
  std::vector< Fec_packet > fec_vector;	// fec blocks
  std::string error_;
  unsigned long fecdata_size_;		// size of fec file
  unsigned long fec_net_size_;		// size of packets (not file size)
  unsigned long fec_block_size_;	// from chksum/fec packets
  unsigned long prodata_size_;		// from chksum packets
  md5_type prodata_md5_;		// from chksum packets
  int retval_;				// 0 = OK, 1 = error, 2 = fatal error
  bool gf16_;
  const bool is_lz_;			// used by find_bad_blocks
  bool mmapped;

  bool read_fecfile( const std::string & fec_filename );
  bool parse_packet( const Chksum_packet & chksum_packet,
                     const bool ignore_errors );

public:
  Fec_index( const std::string & fec_filename,
             const bool ignore_errors = false, const bool is_lz = false );
  ~Fec_index() { if( mmapped ) munmap( (void *)fecdata_, fecdata_size_ );
                 else std::free( (void *)fecdata_ ); }

  const std::string & error() const { return error_; }
  int retval() const { return retval_; }
  void show_error( const std::string & fec_filename ) const
    { if( error_.size() )
        show_file_error( printable_name( fec_filename ), error_.c_str() ); }
  void show_fec_data( const std::string & input_filename,
                      const std::string & fec_filename, FILE * const f ) const;

  unsigned long fec_block_size() const { return fec_block_size_; }
  unsigned fec_blocks() const { return fec_vector.size(); }
  unsigned long fec_bytes() const { return fec_blocks() * fec_block_size_; }
  const uint8_t * fec_block( const unsigned i ) const
    { return fec_vector[i].fec_block(); }
  unsigned fbn( const unsigned i ) const
    { return fec_vector[i].fec_block_number(); }
  bool gf16() const { return gf16_; }

  const uint8_t * fecdata() const { return fecdata_; }
  unsigned long fecdata_size() const { return fecdata_size_; }
  unsigned long prodata_size() const { return prodata_size_; }
  const md5_type & prodata_md5() const { return prodata_md5_; }
  unsigned prodata_blocks() const
    { return ceil_divide( prodata_size_, fec_block_size_ ); }
  bool is_lz() const { return is_lz_; }

  bool has_array() const { return crc_array() != 0 || crcc_array() != 0; }
  const le32 * crc_array() const { return crc_array_; }
  const le32 * crcc_array() const { return crcc_array_; }

  unsigned long block_pos( const unsigned i ) const
    { return i * fec_block_size_; }

  unsigned long block_size( const unsigned i ) const
    {
    const unsigned long pos = i * fec_block_size_;
    if( pos >= prodata_size_ ) return 0;
    return std::min( fec_block_size_, prodata_size_ - pos );
    }

  unsigned long block_end( const unsigned i ) const
    { return std::min( ( i + 1 ) * fec_block_size_, prodata_size_ ); }

  bool prodata_match( const std::string & input_filename,
                      const md5_type & computed_prodata_md5,
                      const bool debug = true ) const
    {
    if( prodata_md5_ == computed_prodata_md5 ) return true;
    show_diag_msg( input_filename,
                   "MD5 mismatch between protected data and fec data.", debug );
    return false;
    }
  };


bool Fec_index::read_fecfile( const std::string & fec_filename )
  {
  struct stat in_stats;					// not used
  const int infd = (fec_filename == "-") ?
    STDIN_FILENO : open_instream( fec_filename.c_str(), &in_stats, false );
  if( infd < 0 ) return false;
  {
  const long long file_size = lseek( infd, 0, SEEK_END );
  if( file_size > 0 )
    {
    if( !fits_in_size_t( file_size ) )
      { error_ = large_file_msg; close( infd ); return false; }
    const uint8_t * buffer = (const uint8_t *)
      mmap( 0, file_size, PROT_READ, MAP_PRIVATE, infd, 0 );
    if( buffer && buffer != MAP_FAILED )
      { fecdata_ = buffer; fecdata_size_ = file_size; mmapped = true;
        close( infd ); return true; }
    }
  if( file_size >= 0 ) safe_seek( infd, 0, fec_filename );
  }
  long buffer_size = 65536;
  uint8_t * buffer = (uint8_t *)std::malloc( buffer_size );
  if( !buffer ) { error_ = mem_msg; close( infd ); return false; }
  long file_size = readblock( infd, buffer, buffer_size );
  if( file_size >= buffer_size && !errno && !check_fec_magic( buffer ) )
    { fecdata_ = buffer; fecdata_size_ = fec_magic_l; return true; }
  while( file_size >= buffer_size && !errno )
    {
    if( buffer_size >= LONG_MAX ) { error_ = large_file_msg;
      std::free( buffer ); close( infd ); return false; }
    buffer_size = (buffer_size <= LONG_MAX / 2) ? 2 * buffer_size : LONG_MAX;
    uint8_t * const tmp = (uint8_t *)std::realloc( buffer, buffer_size );
    if( !tmp )
      { error_ = mem_msg; std::free( buffer ); close( infd ); return false; }
    buffer = tmp;
    file_size += readblock( infd, buffer + file_size, buffer_size - file_size );
    }
  if( errno )
    { error_ = rd_err_msg; error_ += ": "; error_ += std::strerror( errno );
      std::free( buffer ); close( infd ); return false; }
  if( close( infd ) != 0 )
    { error_ = "Error closing input file: "; error_ += std::strerror( errno );
      std::free( buffer ); return false; }
  fecdata_ = buffer;
  fecdata_size_ = file_size;
  return true;
  }


bool Fec_index::parse_packet( const Chksum_packet & chksum_packet,
                              const bool ignore_errors )
  {
  const unsigned long long prodata_size = chksum_packet.prodata_size();
  if( prodata_size_ <= 0 )			// first chksum packet
    {
    if( !fits_in_size_t( prodata_size ) )
      { error_ = large_file_msg; retval_ = 1; return false; }
    prodata_size_ = prodata_size;
    prodata_md5_ = chksum_packet.prodata_md5();
    gf16_ = chksum_packet.gf16();
    }
  else
    {
    if( prodata_size_ != prodata_size )
      { error_ = "Contradictory protected data size in chksum packet.";
        retval_ = 2; return false; }
    if( prodata_md5_ != chksum_packet.prodata_md5() )
      { error_ = "Contradictory protected data MD5 in chksum packet.";
        retval_ = 2; return false; }
    if( gf16_ != chksum_packet.gf16() )
      { error_ = "Contradictory Galois Field size in chksum packet.";
        retval_ = 2; return false; }
    }
  if( !isvalid_fbs( fec_block_size_ ) )
    fec_block_size_ = chksum_packet.fec_block_size();
  else if( fec_block_size_ != chksum_packet.fec_block_size() )
    { error_ = "Contradictory fec_block_size in chksum packet.";
      retval_ = 2; return false; }
  if( !chksum_packet.check_payload_crc() )		// corrupt array
    { if( ignore_errors ) return true;
      error_ = "Corrupt CRC array in chksum packet."; retval_ = 2; return false; }
  if( !chksum_packet.is_crc_c() )
    {
    if( !crc_array_ ) crc_array_ = chksum_packet.crc_array();
    else { error_ = "More than one CRC32 array found.";
           retval_ = 2; return false; }
    }
  else if( !crcc_array_ ) crcc_array_ = chksum_packet.crc_array();
  else { error_ = "More than one CRC32-C array found.";
         retval_ = 2; return false; }
  return true;
  }


Fec_index::Fec_index( const std::string & fec_filename,
                      const bool ignore_errors, const bool is_lz )
  : fecdata_( 0 ), crc_array_( 0 ), crcc_array_( 0 ), fecdata_size_( 0 ),
    fec_net_size_( 0 ), fec_block_size_( 0 ), prodata_size_( 0 ),
    retval_( 0 ), gf16_( false ), is_lz_( is_lz ), mmapped( false )
  {
  if( !read_fecfile( fec_filename ) || !fecdata_ ) { retval_ = 1; return; }
  if( fecdata_size_ <= 0 )
    { error_ = "Fec file is empty."; retval_ = 2; return; }
  if( fecdata_size_ >= fec_magic_l && !check_fec_magic( fecdata_ ) )
    { error_ = "Bad magic number (file is not fec data)."; retval_ = 2; return; }
  if( fecdata_size_ < Chksum_packet::min_packet_size() )
    { error_ = "Fec file is too short."; retval_ = 2; return; }
  if( !Chksum_packet::check_version( fecdata_ ) )
    { error_ = bad_fec_version( Chksum_packet::version( fecdata_ ) );
      retval_ = 2; return; }

  /* Parse packets. pos usually points to a packet header, except when
     skipping a corrupt packet. */
  for( unsigned long pos = 0; pos < fecdata_size_; )
    {
    unsigned long image_size =
      Chksum_packet::check_image( fecdata_ + pos, fecdata_size_ - pos );
    if( image_size > 2 )
      {
      if( !parse_packet( Chksum_packet( fecdata_ + pos ), ignore_errors ) )
        return;
      fec_net_size_ += image_size; pos += image_size; continue;
      }
    if( image_size != 0 && ignore_errors ) { ++pos; continue; }
    if( image_size == 1 )
      { error_ = "Wrong size in chksum packet."; retval_ = 2; return; }
    if( image_size == 2 )
      { error_ = "Wrong CRC in chksum packet."; retval_ = 2; return; }

    image_size = Fec_packet::check_image( fecdata_ + pos, fecdata_size_ - pos );
    if( image_size > 2 )
      {
      const Fec_packet fec_packet( fecdata_ + pos );
      if( !isvalid_fbs( fec_block_size_ ) )
        fec_block_size_ = fec_packet.fec_block_size();
      else if( fec_block_size_ != fec_packet.fec_block_size() )
        { error_ = "Contradictory fec_block_size in fec packet.";
          retval_ = 2; return; }
      fec_vector.push_back( fec_packet );
      fec_net_size_ += image_size; pos += image_size; continue;
      }
    if( image_size != 0 && ignore_errors ) { ++pos; continue; }
    if( image_size == 1 )
      { error_ = "Wrong size in fec packet."; retval_ = 2; return; }
    if( image_size == 2 )
      { error_ = "Wrong CRC in fec packet."; retval_ = 2; return; }

    if( ignore_errors )
      { while( ++pos < fecdata_size_ && fecdata_[pos] != fec_magic[0] ) {}
        continue; }
    error_ = "Unknown packet type = ";		// unknown or corrupt packet
    const int size = std::min( (unsigned long)fec_magic_l, fecdata_size_ - pos );
    format_trailing_bytes( fecdata_ + pos, size, error_ );
    retval_ = 2; return;
    }
  if( prodata_size_ <= 0 )
    { error_ = "No valid chksum packets found."; retval_ = 2; return; }
  if( fec_blocks() <= 0 && !ignore_errors )
    { error_ = "No valid fec packets found."; retval_ = 2; return; }
  if( !has_array() && !ignore_errors )
    { error_ = "No valid CRC arrays found."; retval_ = 2; return; }
  if( fec_blocks() > prodata_blocks() )
    { error_ = "Too many fec packets found. (More than data blocks)";
      retval_ = 2; return; }
  if( !isvalid_fbs( fec_block_size_ ) )
    internal_error( "fec_block_size not found." );
  // check that fbn < max_k in each fec packet
  const unsigned max_k = gf16_ ? max_k16 : max_k8;
  std::vector< bool > bv( max_k );
  for( unsigned i = 0; i < fec_blocks(); ++i )
    {
    const unsigned fbn = fec_vector[i].fec_block_number();
    if( fbn >= max_k )
      { error_ = "Invalid fec_block_number in fec packet.";
        retval_ = 2; return; }
    if( bv[fbn] )
      { error_ = "Same fec_block_number in two fec packets.";
        retval_ = 2; return; }
    bv[fbn] = true;
    }
  }


void Fec_index::show_fec_data( const std::string & input_filename,
                      const std::string & fec_filename, FILE * const f ) const
  {
  const unsigned long fec_bytes_ = fec_bytes();
  const double spercent = ( 100.0 * fec_net_size_ ) / prodata_size_;
  const double fpercent = ( 100.0 * fec_bytes_ ) / prodata_size_;
  if( input_filename.size() )
    std::fprintf( f, "Protected file: '%s'\n", input_filename.c_str() );
  std::fprintf( f, "Protected size: %11s   Block size: %5s   Data blocks: %s\n"
                "      Fec file: '%s'\n"
                "      Fec size: %11s  %6.2f%%    Fec blocks: %u\n"
                "     Fec bytes: %11s  %6.2f%%   Fec numbers:",
                format_num3( prodata_size_ ), format_num3( fec_block_size_ ),
                format_num3( prodata_blocks() ), printable_name( fec_filename ),
                format_num3( fec_net_size_ ), spercent, fec_blocks(),
                format_num3( fec_bytes_ ), fpercent );
  for( unsigned i = 0; i < fec_blocks(); ++i )	// print ranges of fbn's
    {
    std::fprintf( f, " %u", fbn( i ) );
    const unsigned j = i;
    while( i + 1 < fec_blocks() && fbn( i + 1 ) == fbn( i ) + 1 ) ++i;
    if( i > j ) std::fprintf( f, "%c%u", ( i == j + 1 ) ? ' ' : '-', fbn( i ) );
    }
  std::fprintf( f, "\n      Features: GF(2^%s)%s%s\n", gf16_ ? "16" : "8",
                crc_array_ ? " CRC32" : "", crcc_array_ ? " CRC32-C" : "" );
  std::fflush( f );
  }


class Bad_block_index
  {
  const Fec_index & fec_index;
  const CRC32 crc32c;
  // list of prodata blocks with a mismatched CRC32 or CRC32-C
  std::vector< unsigned > bb_vector_;		// index of each bad block

  bool bursted_data_block( const uint8_t * const prodata,
                   const unsigned long mmapped_size, const unsigned i ) const;

public:
  Bad_block_index( const Fec_index & fec_index_, const uint8_t * const prodata,
                   md5_type & computed_prodata_md5,
                   const unsigned long mmapped_size )
    : fec_index( fec_index_ ), crc32c( true )
    { find_bad_blocks( prodata, computed_prodata_md5, mmapped_size ); }
  Bad_block_index( const Fec_index & fec_index_,
                   const std::vector< Block > & range_vector )
    : fec_index( fec_index_ ), crc32c( true ) { set_bad_blocks( range_vector ); }

  unsigned bad_blocks() const { return bb_vector_.size(); }
  const std::vector< unsigned > & bb_vector() const { return bb_vector_; }

  void find_bad_blocks( const uint8_t * const prodata,
                        md5_type & computed_prodata_md5,
                        const unsigned long mmapped_size );

  unsigned long first_bad_pos() const
    {
    if( bb_vector_.empty() ) return 0;
    return fec_index.block_pos( bb_vector_.front() );
    }

  unsigned long last_bad_pos() const
    {
    if( bb_vector_.empty() ) return 0;
    return fec_index.block_end( bb_vector_.back() ) - 1;
    }

  unsigned long bad_span() const
    {
    if( bb_vector_.empty() ) return 0;
    return last_bad_pos() + 1 - first_bad_pos();
    }

  unsigned long bad_data_bytes() const
    {
    if( bb_vector_.empty() ) return 0;
    return ( bb_vector_.size() - 1 ) * fec_index.fec_block_size() +
           fec_index.block_size( bb_vector_.back() );
    }

  // clusters must not overlap
  void set_bad_blocks( const std::vector< unsigned > & cluster_vector,
                       const unsigned cluster_size )
    {
    bb_vector_.clear();
    const unsigned blocks = fec_index.prodata_blocks();
    for( unsigned i = 0; i < cluster_vector.size(); ++i )
      {
      const unsigned idx = cluster_vector[i];
      for( unsigned j = 0; j < cluster_size && idx + j < blocks; ++j )
        bb_vector_.push_back( idx + j );
      }
    }

  // ranges must be sorted and must not overlap
  void set_bad_blocks( const std::vector< Block > & range_vector )
    {
    bb_vector_.clear();
    const unsigned long fbs = fec_index.fec_block_size();
    const unsigned blocks = fec_index.prodata_blocks();
    for( unsigned i = 0; i < range_vector.size(); ++i )
      {
      unsigned i1 = range_vector[i].pos() / fbs;
      const unsigned i2 = ( range_vector[i].end() - 1 ) / fbs;
      if( bb_vector_.size() ) i1 = std::max( i1, bb_vector_.back() + 1 );
      for( ; i1 <= i2 && i1 < blocks; ++i1 )
        bb_vector_.push_back( i1 );
      }
    }

  void set_bad_blocks( const long pos, const long size )
    {
    bb_vector_.clear();
    const unsigned long fbs = fec_index.fec_block_size();
    const unsigned blocks = fec_index.prodata_blocks();
    unsigned i1 = pos / fbs;
    const unsigned i2 = ( pos + size - 1 ) / fbs;
    for( ; i1 <= i2 && i1 < blocks; ++i1 ) bb_vector_.push_back( i1 );
    }
  };


// detect bursts of identical bytes in lzip protected file
bool Bad_block_index::bursted_data_block( const uint8_t * const prodata,
                   const unsigned long mmapped_size, const unsigned i ) const
  {
  enum { minlen = 8 };		// min number of consecutive identical bytes
  unsigned long pos = fec_index.block_pos( i );
  if( pos >= minlen / 2 ) pos -= minlen / 2;
  const unsigned long end =
    std::min( fec_index.block_end( i ) + minlen / 2, mmapped_size );
  unsigned count = 0;
  for( unsigned long j = pos + 1; j < end; ++j )
    {
    if( prodata[j] != prodata[j-1] ) count = 0;
    else if( ++count >= minlen - 1 ) return true;
    }
  return false;
  }

void Bad_block_index::find_bad_blocks( const uint8_t * const prodata,
                        md5_type & computed_prodata_md5,
                        const unsigned long mmapped_size )
  {
  bb_vector_.clear();
  MD5SUM md5sum;
  const unsigned long prodata_size = fec_index.prodata_size();
  const unsigned prodata_blocks = fec_index.prodata_blocks();
  const unsigned long fbs = fec_index.fec_block_size();
  const bool full = mmapped_size >= prodata_size;
  const unsigned available_blocks = full ? prodata_blocks : mmapped_size / fbs;
  const unsigned blocks = std::min( available_blocks, prodata_blocks );
  for( unsigned i = 0; i < blocks; ++i )
    {
    const unsigned long pos = fec_index.block_pos( i );
    const unsigned long size = fec_index.block_size( i );
    if( full ) md5sum.md5_update( prodata + pos, size );
    if( fec_index.has_array() )
      { if( ( fec_index.crc_array() && fec_index.crc_array()[i].val() !=
              crc32.compute_crc( prodata + pos, size ) ) ||
            ( fec_index.crcc_array() && fec_index.crcc_array()[i].val() !=
              crc32c.compute_crc( prodata + pos, size ) ) )
          bb_vector_.push_back( i ); }
    else if( fec_index.is_lz() && bursted_data_block( prodata, mmapped_size, i ) )
      bb_vector_.push_back( i );
    }
  if( full ) md5sum.md5_finish( computed_prodata_md5 );
  for( unsigned i = blocks; i < prodata_blocks; ++i )	// truncated file
    bb_vector_.push_back( i );
  }


long next_pct_pos( const long last_pos, const int pct )
  {
  if( pct <= 0 ) return 0;
  return std::min( last_pos, (long)( last_pos / ( 100.0 / pct ) ) );
  }


bool check_md5_2( const uint8_t * const prodata, const uint8_t * const dstbuf,
                  const std::vector< unsigned > & bb_vector,
                  const unsigned long prodata_size, const unsigned long fbs,
                  const md5_type & digest )
  {
  MD5SUM md5sum;
  md5_type new_digest;
  const unsigned prodata_blocks = ceil_divide( prodata_size, fbs );
  const unsigned bad_blocks = bb_vector.size();
  for( unsigned col = 0, bi = 0; col < prodata_blocks; ++col )
    {
    const uint8_t * src;
    if( bi < bad_blocks && col == bb_vector[bi] )
      { src = dstbuf + bi * fbs; ++bi; }		// repaired block
    else src = prodata + col * fbs;			// good block
    const unsigned long size =
      ( col < prodata_blocks - 1 ) ? fbs : ( prodata_size - 1 ) % fbs + 1;
    md5sum.md5_update( src, size );
    }
  md5sum.md5_finish( new_digest );
  return digest == new_digest;
  }


// if successful, return a buffer with the repaired blocks
const uint8_t * repair_prodata( const Fec_index & fec_index,
                                const Bad_block_index & bb_index,
                                const uint8_t * const prodata )
  {
  const unsigned bad_blocks = bb_index.bad_blocks();
  if( bad_blocks == 0 ) return 0;			// nothing to repair
  const unsigned fec_blocks = fec_index.fec_blocks();
  if( bad_blocks > fec_blocks )
    {
    if( verbosity >= 0 )
      std::fprintf( stderr, "Too many damaged blocks (%u).\n  Can't repair "
                    "file if it contains more than %u damaged blocks.\n",
                    bad_blocks, fec_blocks );
    return 0;
    }

  const std::vector< unsigned > & bb_vector = bb_index.bb_vector();
  std::vector< unsigned > fbn_vector;
  const unsigned long fbs = fec_index.fec_block_size();
  // copy fec blocks into fecbuf where reduction will be performed
  uint8_t * const fecbuf = new uint8_t[bad_blocks * fbs];
  for( unsigned bi = 0; bi < bad_blocks; ++bi )
    {
    fbn_vector.push_back( fec_index.fbn( bi ) );
    std::memcpy( fecbuf + bi * fbs, fec_index.fec_block( bi ), fbs );
    }
  const unsigned prodata_blocks = fec_index.prodata_blocks();
  const unsigned long prodata_size = fec_index.prodata_size();
  const bool last_is_missing = bb_vector.back() == prodata_blocks - 1;
  // last incomplete data block padded to fbs
  uint8_t * const lastbuf =
    set_lastbuf( prodata, prodata_size, fbs, last_is_missing );
  uint8_t * const dstbuf = new uint8_t[bad_blocks * fbs];
  fec_index.gf16() ?
    rs16_decode( prodata, lastbuf, bb_vector, fbn_vector, fecbuf, dstbuf, fbs,
                 prodata_blocks ) :
    rs8_decode( prodata, lastbuf, bb_vector, fbn_vector, fecbuf, dstbuf, fbs,
                prodata_blocks );
  if( lastbuf ) delete[] lastbuf;
  delete[] fecbuf;
  return dstbuf;
  }


bool check_prodata( const Fec_index & fec_index,
                    const Bad_block_index & bb_index,
                    const std::string & input_filename,
                    const std::string & fec_filename,
                    const md5_type & computed_prodata_md5,
                    const long long size_dif = 0,
                    const bool debug = true, const bool repair = false )
  {
  FILE * const f = debug ? stdout : stderr;
  if( verbosity >= ( debug ? 0 : 1 ) )
    fec_index.show_fec_data( input_filename, fec_filename, f );
  if( size_dif && verbosity >= 0 )
    std::fprintf( stderr, "Protected file is %s bytes %s.\n",
                  format_num3( llabs( size_dif ) ), ( size_dif > 0 ) ?
                  "larger than expected; maybe contains extra data" :
                  "smaller than expected; maybe is truncated" );
  const unsigned bad_blocks = bb_index.bad_blocks();
  const bool mismatch = size_dif < 0 || bad_blocks ||
    !fec_index.prodata_match( input_filename, computed_prodata_md5, debug );
  if( bad_blocks )
    {
    if( verbosity >= ( debug ? 0 : 1 ) )
      { std::fprintf( f, "Block mismatches: %u (%s bytes) spanning %s bytes "
                      "[%s,%s]\n", bad_blocks,
                      format_num3( bb_index.bad_data_bytes() ),
                      format_num3( bb_index.bad_span() ),
                      format_num3( bb_index.first_bad_pos() ),
                      format_num3( bb_index.last_bad_pos() ) );
        std::fflush( f ); }
    return false;
    }
  if( mismatch ) return false;
  if( verbosity >= 1 || ( verbosity >= 0 && size_dif > 0 ) )
    std::fprintf( f, "Protected data checked successfully.%s%s\n",
              repair ? " Repair not needed." : "",
              (repair && size_dif > 0) ? "\nJust removing extra data." : "" );
  return true;
  }


void print_blocks( const std::vector< unsigned > & pos_vector,
                   const char * const msg, const unsigned cblock_size )
  {
  std::fputs( ( pos_vector.size() == 1 ) ? "block" : "blocks", stdout );
  for( unsigned i = 0; i < pos_vector.size(); ++i )
    std::printf( " %2u", pos_vector[i] / cblock_size );
  std::fputs( msg, stdout );
  }


// replace dirname with destdir in name and write result to outname
void replace_dirname( const std::string & name, const std::string & destdir,
                      std::string & outname )
  {
  unsigned i = name.size();	// size of dirname to be replaced by destdir
  while( i > 0 && name[i-1] != '/' ) --i;	// point i to basename
  outname = destdir;
  outname.append( name, i, name.size() - i );	// append basename
  }


const Fec_index * fec_d_init( const std::string & input_filename,
          const std::string & cl_fec_filename, std::string & fec_filename,
          const uint8_t ** prodatap )
  {
  if( input_filename == "-" ) { prot_stdin(); return 0; }
  if( has_fec_extension2( input_filename ) ) return 0;
  const bool from_dir = cl_fec_filename.size() &&
                        cl_fec_filename.end()[-1] == '/';

  if( cl_fec_filename.size() && !from_dir )		// file or stdin
    fec_filename = cl_fec_filename;
  else						// read fec data from file.fec
    {
    if( from_dir )
      replace_dirname( input_filename, cl_fec_filename, fec_filename );
    else fec_filename = input_filename;
    fec_filename += fec_extension;
    }
  const Fec_index * const fec_indexp = new Fec_index( fec_filename );
  if( fec_indexp->retval() != 0 )
    { fec_indexp->show_error( fec_filename ); delete fec_indexp; return 0; }

  struct stat in_stats;					// not used
  const char * const input_filenamep = input_filename.c_str();
  const int infd = open_instream( input_filenamep, &in_stats, false, true );
  if( infd < 0 ) { delete fec_indexp; return 0; }
  const long prodata_size = fec_indexp->prodata_size();
  const long long file_size = lseek( infd, 0, SEEK_END );
  if( prodata_size != file_size )
    { show_file_error( input_filenamep,
                       "Size mismatch between protected data and fec data." );
      close( infd ); delete fec_indexp; return 0; }
  *prodatap = (const uint8_t *)
    mmap( 0, prodata_size, PROT_READ, MAP_PRIVATE, infd, 0 );
  close( infd );
  if( *prodatap == MAP_FAILED )
    { show_file_error( input_filenamep, mmap_msg, errno );
      delete fec_indexp; return 0; }
  return fec_indexp;
  }

} // end namespace


/* Check that no variable read from packet overflows unsigned long.
   0 = bad magic, 1 = bad size, 2 = bad crc, else return packet size. */
unsigned Chksum_packet::check_image( const uint8_t * const image_buffer,
                                     const unsigned long max_size )
  {
  if( max_size < min_packet_size() || !check_fec_magic( image_buffer ) )
    return 0;
  if( get_le( image_buffer + header_crc_o, crc32_l ) !=
      compute_header_crc( image_buffer ) ) return 2;
  if( !check_version( image_buffer ) || !check_flags( image_buffer ) ) return 2;
  const Chksum_packet chksum_packet( image_buffer );
  const unsigned long long prodata_size = chksum_packet.prodata_size();
  const unsigned long long fbs = chksum_packet.fec_block_size();
  if( prodata_size > max_prodata_size || !isvalid_fbs( fbs ) ) return 1;
  const unsigned long long image_size =
    chksum_packet.packet_size( prodata_size, fbs );
  const unsigned elsize = sizeof chksum_packet.crc_array()[0];
  const unsigned max_k = chksum_packet.gf16() ? max_k16 : max_k8;
  if( image_size < min_packet_size() || image_size > max_size ||
      image_size > header_size + max_k * elsize + trailer_size ) return 1;
  const unsigned paysize = image_size - header_size - trailer_size;
  const unsigned long long prodata_blocks =
    chksum_packet.prodata_blocks( prodata_size, fbs );
  if( paysize % elsize != 0 || paysize / elsize != prodata_blocks ||
      prodata_blocks <= 0 || prodata_blocks > max_k ) return 1;
  if( !fits_in_size_t( prodata_size ) || !fits_in_size_t( fbs ) )
    throw std::bad_alloc();
  return image_size;
  }


/* Check that no variable read from packet overflows unsigned long.
   0 = bad magic, 1 = bad size, 2 = bad crc, else return packet size. */
unsigned long Fec_packet::check_image( const uint8_t * const image_buffer,
                                       const unsigned long max_size )
  {
  if( max_size < min_packet_size() ||
      std::memcmp( image_buffer, fec_packet_magic, fec_magic_l ) != 0 )
    return 0;
  if( get_le( image_buffer + header_crc_o, crc32_l ) !=
      compute_header_crc( image_buffer ) ) return 2;
  const Fec_packet fec_packet( image_buffer );
  const unsigned long long fbs = fec_packet.fec_block_size();
  const unsigned long long image_size = fec_packet.packet_size( fbs );
  if( !isvalid_fbs( fbs ) || image_size < min_packet_size() ||
      image_size > max_size ) return 1;
  const unsigned long payload_crc_o = fec_block_o + fbs;
  const unsigned payload_crc = get_le( image_buffer + payload_crc_o, crc32_l );
  if( crc32.compute_crc( image_buffer + fec_block_o, fbs ) != payload_crc )
    return 2;
  if( !fits_in_size_t( fbs ) ) throw std::bad_alloc();
  return image_size;
  }


int fec_test( const std::vector< std::string > & filenames,
              const std::string & cl_fec_filename,
              const std::string & default_output_filename,
              const char recursive, const bool force, const bool ignore_errors,
              const bool repair, const bool to_stdout )
  {
  const bool to_file = !to_stdout && default_output_filename.size();
  if( repair && ( to_stdout || to_file ) && filenames.size() != 1 )
    { show_error( "You must specify exactly 1 protected file "
                  "when redirecting repaired data." ); return 1; }
  if( repair && ( to_stdout || to_file ) && recursive )
    { show_error( "Can't redirect repaired data in recursive mode." ); return 1; }
  if( to_stdout ) { outfd = STDOUT_FILENO; if( !check_tty_out() ) return 1; }
  else outfd = -1;
  const bool to_fixed = !to_stdout && !to_file;
  const bool from_dir = cl_fec_filename.size() &&
                        cl_fec_filename.end()[-1] == '/';
  int retval = 0;
  for( unsigned i = 0; i < filenames.size(); ++i )
    {
    if( filenames[i] == "-" )
      { prot_stdin(); set_retval( retval, 1 ); continue; }
    std::string srcdir;		// dirname to be replaced by cl_fec_filename
    if( from_dir ) extract_dirname( filenames[i], srcdir );
    std::list< std::string > filelist( 1U, filenames[i] );
    std::string input_filename;
    while( next_filename( filelist, input_filename, retval, recursive ) )
      {
      if( has_fec_extension2( input_filename ) )
        { set_retval( retval, 1 ); continue; }
      // read fec data from cl_fec_filename or file.fec
      std::string fec_filename;
      if( cl_fec_filename.size() && !from_dir )	// file or stdin
        {
        if( filenames.size() != 1 || recursive )
          { show_error( "You must specify exactly 1 protected file "
                        "when reading 1 fec file." ); return 1; }
        fec_filename = cl_fec_filename;
        }
      else { if( !from_dir ) fec_filename = input_filename;
             else replace_dirname( input_filename, srcdir, cl_fec_filename,
                                   fec_filename );
             fec_filename += fec_extension; }
      const bool is_lz = has_lz_extension( input_filename );
      const Fec_index fec_index( fec_filename, ignore_errors, is_lz );
      if( fec_index.retval() != 0 )
        { fec_index.show_error( fec_filename );
          set_retval( retval, fec_index.retval() ); continue; }

      struct stat in_stats;
      const char * const input_filenamep = input_filename.c_str();
      const int infd = open_instream( input_filenamep, &in_stats, false, !force );
      if( infd < 0 ) { set_retval( retval, 1 ); continue; }
      const long long file_size = lseek( infd, 0, SEEK_END );
      if( file_size < 0 )
        { show_file_error( input_filenamep, seek_msg, errno );
          set_retval( retval, 1 ); close( infd ); continue; }
      const long prodata_size = fec_index.prodata_size();
      const unsigned long mmapped_size =
        std::min( (long long)prodata_size, file_size );
      const long long size_dif = file_size - prodata_size;
      const uint8_t * const prodata = mmapped_size ? (const uint8_t *)
        mmap( 0, mmapped_size, PROT_READ, MAP_PRIVATE, infd, 0 ) : 0;
      close( infd );
      if( prodata == MAP_FAILED )
        { show_file_error( input_filenamep, mmap_msg, errno );
          set_retval( retval, 1 ); goto err; }
      {
      md5_type computed_prodata_md5;
      const unsigned prodata_blocks = fec_index.prodata_blocks();
      const unsigned long fbs = fec_index.fec_block_size();
      Bad_block_index bb_index( fec_index, prodata, computed_prodata_md5,
                                mmapped_size );
      const bool mismatch = !check_prodata( fec_index, bb_index, input_filename,
                 fec_filename, computed_prodata_md5, size_dif, false, repair );
      if( mismatch && !repair ) set_retval( retval, 2 );
      else if( repair && ( mismatch || size_dif > 0 ) )
        {
        if( !is_lz && !fec_index.has_array() && mismatch )
          { show_diag_msg( input_filename, "Can't repair. No valid CRC "
              "arrays found and protected file not in lzip format." );
            cleanup_and_fail( 2 ); }
        if( verbosity >= 1 && mismatch )
          std::fprintf( stderr, "Repairing file '%s'\n", input_filenamep );
        if( verbosity >= 0 && !fec_index.has_array() && mismatch )
          std::fputs( "warning: Repairing without CRC arrays.\n", stderr );
        const std::vector< unsigned > & bb_vector = bb_index.bb_vector();
        const unsigned bad_blocks = bb_index.bad_blocks();
        const uint8_t * const dstbuf = bad_blocks ?
          repair_prodata( fec_index, bb_index, prodata ) : 0;
        if( bad_blocks && ( !dstbuf ||
              !check_md5_2( prodata, dstbuf, bb_vector, prodata_size, fbs,
              fec_index.prodata_md5() ) ) ) cleanup_and_fail( 2 );
        if( to_fixed )
          {
          output_filename = insert_fixed( input_filename, false );
          set_signal_handler();
          if( !open_outstream( force, true ) || !check_tty_out() )
            { set_retval( retval, 1 ); return retval; }	// don't delete a tty
          }
        else if( to_file && outfd < 0 )	// open outfd after checking infd
          {
          output_filename = default_output_filename;
          set_signal_handler();
          // check tty only once and don't try to delete a tty
          if( !open_outstream( force, false ) || !check_tty_out() ) return 1;
          }
        // write repaired prodata
        for( unsigned col = 0, bi = 0; col < prodata_blocks; ++col )
          {
          const uint8_t * src;
          if( bi < bad_blocks && col == bb_vector[bi] )
            { src = dstbuf + bi * fbs; ++bi; }		// repaired block
          else src = prodata + col * fbs;		// good block
          const long size =
            ( col < prodata_blocks - 1 ) ? fbs : ( prodata_size - 1 ) % fbs + 1;
          if( writeblock( outfd, src, size ) != size )
            { show_file_error( printable_name( output_filename, false ),
                wr_err_msg, errno ); set_retval( retval, 1 ); break; }
          }
        delete[] dstbuf;
        if( retval == 0 && !close_outstream( &in_stats ) )
          set_retval( retval, 1 );
        if( retval ) cleanup_and_fail( retval );
        if( verbosity >= 1 )
          std::fprintf( stderr, "Repaired copy of '%s' written to '%s'\n",
            input_filenamep, printable_name( output_filename, false ) );
        }
      if( ( filelist.size() || i + 1 < filenames.size() ) && verbosity >= 1 )
        std::fputc( '\n', stderr );
      }
err:  if( mmapped_size ) munmap( (void *)prodata, mmapped_size );
      }
    }
  return retval;
  }


int fec_list( const std::vector< std::string > & filenames,
              const bool ignore_errors )
  {
  int retval = 0;
  bool stdin_used = false;
  for( unsigned i = 0; i < filenames.size(); ++i )
    {
    if( filenames[i] == "-" )
      { if( stdin_used ) continue; else stdin_used = true; }
    if( i > 0 && verbosity >= 0 )
      { std::fputc( '\n', stdout ); std::fflush( stdout ); }
    const Fec_index fec_index( filenames[i], ignore_errors );
    if( fec_index.retval() != 0 )
      { fec_index.show_error( filenames[i] );
        set_retval( retval, fec_index.retval() ); continue; }
    if( verbosity >= 0 ) fec_index.show_fec_data( "", filenames[i], stdout );
    }
  return retval;
  }


// write feedback to stdout, diagnostics to stderr
int fec_df( const std::vector< std::string > & filenames )
  {
  const unsigned long long large_member_size = 1ULL << 34;	// 16 GiB
  int retval = 0;
  bool stdin_used = false;
  for( unsigned i = 0; i < filenames.size(); ++i )
    {
    if( filenames[i] == "-" )
      { if( stdin_used ) continue; else stdin_used = true; }
    const Fec_index fec_index( filenames[i] );
    if( fec_index.retval() != 0 )
      { fec_index.show_error( filenames[i] );
        set_retval( retval, fec_index.retval() ); continue; }
    const uint8_t * fecdata = fec_index.fecdata();
    const unsigned long fecdata_size = fec_index.fecdata_size();
//    const unsigned long prodata_size = fec_index.prodata_size();
    unsigned long counter = 0;
    for( unsigned long j = fecdata_size; j >= Lzip_trailer::size; --j )
      if( fecdata[j-1] == 0 )	// most significant byte of member_size
        {
        const Lzip_trailer & trailer =
          *(const Lzip_trailer *)( fecdata + j - trailer.size );
        const unsigned long long member_size = trailer.member_size();
        if( member_size == 0 )			// skip trailing zeros
          { while( j > trailer.size && fecdata[j-9] == 0 ) --j; continue; }
        if( member_size > large_member_size || member_size <= i ||
            !trailer.check_consistency() ) continue;
        if( verbosity >= 2 )
          std::printf( "%s: consistent trailer with member_size = %s bytes\n",
                       filenames[i].c_str(), format_num3( member_size ) );
        ++counter;
        }
    if( verbosity >= 1 || counter > 0 )
      std::printf( "%s: %lu consistent trailers with member size <= %s in %s"
                   " fec bytes\n", filenames[i].c_str(), counter,
                   format_num3( large_member_size ), format_num3( fecdata_size ) );
    }
  return retval;
  }


int fec_dc( const std::string & input_filename,
            const std::string & cl_fec_filename, const unsigned cblocks )
  {
  std::string fec_filename;
  const uint8_t * prodata = 0;
  const Fec_index * const fec_indexp =
    fec_d_init( input_filename, cl_fec_filename, fec_filename, &prodata );
  if( !fec_indexp ) return 0;
  const Fec_index & fec_index = *fec_indexp;
  const unsigned long prodata_size = fec_index.prodata_size();
  const unsigned fec_blocks = fec_index.fec_blocks();
  int retval = 0;
  if( cblocks > fec_blocks )
    { show_file_error( input_filename.c_str(), "Not so may blocks in fec data." );
      set_retval( retval, 1 ); goto err; }
  {
  md5_type computed_prodata_md5;
  Bad_block_index bb_index( fec_index, prodata, computed_prodata_md5,
                            prodata_size );
  if( !check_prodata( fec_index, bb_index, input_filename, fec_filename,
                      computed_prodata_md5 ) )
    { set_retval( retval, 2 ); goto err; }
  const unsigned cblock_size = fec_blocks / cblocks;
  const unsigned prodata_blocks = fec_index.prodata_blocks();
  const long last_pos = prodata_blocks - (prodata_blocks - 1) % cblock_size - 1;
  const unsigned long fbs = fec_index.fec_block_size();
  if( verbosity >= 0 )
    { std::printf( "Testing sets of %u %s of size %s\n", cblocks,
           (cblocks == 1) ? "block" : "blocks", format_num3( cblock_size * fbs ) );
      std::fflush( stdout ); }
  unsigned long combinations = 0, successes = 0, failed_comparisons = 0;
  std::vector< unsigned > pos_vector;
  for( unsigned i = 0; i < cblocks; ++i )
    pos_vector.push_back( i * cblock_size );
  const int saved_verbosity = verbosity;
  verbosity = -1;				// suppress all messages
  while( true )
    {
    ++combinations;
    bb_index.set_bad_blocks( pos_vector, cblock_size );
    const uint8_t * dstbuf = repair_prodata( fec_index, bb_index, prodata );
    if( dstbuf )
      {
      ++successes;
      if( saved_verbosity >= 2 )
        { print_blocks( pos_vector, "  passed the test\n", cblock_size );
          std::fflush( stdout ); }
      if( !check_md5_2( prodata, dstbuf, bb_index.bb_vector(), prodata_size,
                        fbs, computed_prodata_md5 ) )
        { if( saved_verbosity >= 0 )
            { print_blocks( pos_vector, "  comparison failed\n", cblock_size );
              std::fflush( stdout ); }
          ++failed_comparisons; }
      delete[] dstbuf;
      }
    else if( saved_verbosity >= 1 )
      { print_blocks( pos_vector, "  can't repair\n", cblock_size );
        std::fflush( stdout ); }
    unsigned long pos_limit = last_pos;	// advance to next block combination
    int i = cblocks - 1;
    while( i >= 0 )
      {
      if( pos_vector[i] + cblock_size > pos_limit )
        { pos_limit -= cblock_size; --i; continue; }
      pos_vector[i] += cblock_size;
      for( ; i + 1U < cblocks; ++i )
        pos_vector[i+1] = pos_vector[i] + cblock_size;
      break;
      }
    if( i < 0 ) break;
    }
  verbosity = saved_verbosity;		// restore verbosity level

  if( verbosity >= 0 )
    {
    std::printf( "\n%11s block combinations tested"
                 "\n%11s repair attempts returned with zero status",
                 format_num3( combinations ), format_num3( successes ) );
    if( successes > 0 )
      {
      if( failed_comparisons > 0 )
        std::printf( ", of which\n%11s comparisons failed\n",
                     format_num3( failed_comparisons ) );
      else std::fputs( "\n            all comparisons passed\n", stdout );
      }
    else std::fputc( '\n', stdout );
    }
  }
err:
  munmap( (void *)prodata, prodata_size );
  delete fec_indexp;
  return retval;
  }


int fec_dz( const std::string & input_filename,
            const std::string & cl_fec_filename,
            std::vector< Block > & range_vector )
  {
  std::string fec_filename;
  const uint8_t * prodata = 0;
  const Fec_index * const fec_indexp =
    fec_d_init( input_filename, cl_fec_filename, fec_filename, &prodata );
  if( !fec_indexp ) return 0;
  const Fec_index & fec_index = *fec_indexp;
  const unsigned long prodata_size = fec_index.prodata_size();
  int retval = 0;
  if( !truncate_block_vector( range_vector, prodata_size ) )
    { show_file_error( input_filename.c_str(), "Range is beyond end of file." );
      set_retval( retval, 1 ); goto err; }
  {
  md5_type computed_prodata_md5;
  compute_md5( prodata, prodata_size, computed_prodata_md5 );
  if( !fec_index.prodata_match( input_filename, computed_prodata_md5 ) )
    { set_retval( retval, 2 ); goto err; }
  Bad_block_index bb_index( fec_index, range_vector );
  if( !check_prodata( fec_index, bb_index, input_filename, fec_filename,
                      computed_prodata_md5 ) )
    {
    const uint8_t * dstbuf = repair_prodata( fec_index, bb_index, prodata );
    if( !dstbuf ) set_retval( retval, 2 );
    else if( !check_md5_2( prodata, dstbuf, bb_index.bb_vector(), prodata_size,
                           fec_index.fec_block_size(), computed_prodata_md5 ) )
      { if( verbosity >= 0 ) std::fputs( "Comparison failed\n", stdout );
        set_retval( retval, 1 ); }
    else if( verbosity >= 0 )
      std::fputs( "Input file repaired successfully.\n", stdout );
    delete[] dstbuf;
    }
  }
err:
  munmap( (void *)prodata, prodata_size );
  delete fec_indexp;
  return retval;
  }


int fec_dZ( const std::string & input_filename,
            const std::string & cl_fec_filename,
            unsigned delta, unsigned sector_size )
  {
  std::string fec_filename;
  const uint8_t * prodata = 0;
  const Fec_index * const fec_indexp =
    fec_d_init( input_filename, cl_fec_filename, fec_filename, &prodata );
  if( !fec_indexp ) return 0;
  const Fec_index & fec_index = *fec_indexp;
  const unsigned long prodata_size = fec_index.prodata_size();
  int retval = 0;
  if( sector_size > prodata_size ) sector_size = prodata_size;
  if( delta > prodata_size ) delta = prodata_size;
  {
  md5_type computed_prodata_md5;
  Bad_block_index bb_index( fec_index, prodata, computed_prodata_md5,
                            prodata_size );
  if( !check_prodata( fec_index, bb_index, input_filename, fec_filename,
                      computed_prodata_md5 ) )
    { set_retval( retval, 2 ); goto err; }
  const long last_pos = prodata_size - ( prodata_size - 1 ) % sector_size - 1;
  if( verbosity >= 0 )
    { std::printf( "Testing blocks of size %s (delta %s)\n",
                   format_num3( sector_size ), format_num3( delta ) );
      std::fflush( stdout ); }
  unsigned long combinations = 0, successes = 0, failed_comparisons = 0;
  int pct = (prodata_size >= 1000 && isatty( STDERR_FILENO )) ? 0 : 100;
  long pct_pos = (pct < 100) ? 0 : prodata_size;
  const int saved_verbosity = verbosity;
  verbosity = -1;				// suppress all messages
  for( long pos = 0; pos <= last_pos; pos += delta )
    {
    if( ( saved_verbosity == 0 || saved_verbosity == 1 ) && pos >= pct_pos )
      { std::fprintf( stderr, "\r%3u%% done\r", pct ); ++pct;
        pct_pos = next_pct_pos( last_pos, pct ); }
    const int damaged_size =
      std::min( (unsigned long)sector_size, prodata_size - pos );
    ++combinations;
    bb_index.set_bad_blocks( pos, damaged_size );
    const uint8_t * dstbuf = repair_prodata( fec_index, bb_index, prodata );
    if( dstbuf )
      {
      ++successes;
      if( saved_verbosity >= 2 )
        { std::printf( "block %s,%s  passed the test\n",
                       format_num3( pos ), format_num3( damaged_size ) );
          std::fflush( stdout ); }
      if( !check_md5_2( prodata, dstbuf, bb_index.bb_vector(), prodata_size,
                        fec_index.fec_block_size(), computed_prodata_md5 ) )
        { if( saved_verbosity >= 0 )
            { std::printf( "block %s,%s  comparison failed\n",
                           format_num3( pos ), format_num3( damaged_size ) );
              std::fflush( stdout ); }
          ++failed_comparisons; }
      delete[] dstbuf;
      }
    else if( saved_verbosity >= 1 )
      { std::printf( "block %s,%s  can't repair\n",
                     format_num3( pos ), format_num3( damaged_size ) );
        std::fflush( stdout ); }
    }
  verbosity = saved_verbosity;		// restore verbosity level

  if( verbosity >= 0 )
    {
    std::printf( "\n%11s blocks tested"
                 "\n%11s repair attempts returned with zero status",
                 format_num3( combinations ), format_num3( successes ) );
    if( successes > 0 )
      {
      if( failed_comparisons > 0 )
        std::printf( ", of which\n%11s comparisons failed\n",
                     format_num3( failed_comparisons ) );
      else std::fputs( "\n            all comparisons passed\n", stdout );
      }
    else std::fputc( '\n', stdout );
    }
  }
err:
  munmap( (void *)prodata, prodata_size );
  delete fec_indexp;
  return retval;
  }
