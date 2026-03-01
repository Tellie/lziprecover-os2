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

struct le32
  {
  enum { size = 4 };
  uint8_t data[size];

  le32 & operator=( unsigned n )
    { for( int i = 0; i < size; ++i ) { data[i] = (uint8_t)n; n >>= 8; }
      return *this; }
  unsigned val() const
    { unsigned n = 0;
      for( int i = size - 1; i >= 0; --i ) { n <<= 8; n += data[i]; }
      return n; }
  bool operator==( const le32 & b ) const
    { return std::memcmp( data, b.data, size ) == 0; }
  bool operator!=( const le32 & b ) const { return !( *this == b ); }
  };


inline unsigned long long get_le( const uint8_t * const buf, int size )
  { unsigned long long n = 0;
    while( --size >= 0 ) { n <<= 8; n += buf[size]; } return n; }

inline unsigned long long ceil_divide( const unsigned long long size,
                                       const unsigned long block_size )
  { return size / block_size + ( size % block_size > 0 ); }

inline unsigned long ceil_divide( const unsigned long size,
                                  const unsigned long block_size )
  { return size / block_size + ( size % block_size > 0 ); }

inline uint8_t * set_lastbuf( const uint8_t * const prodata,
                   const unsigned long prodata_size, const unsigned long fbs,
                   const bool last_is_missing = false )
  {
  const unsigned long rest = prodata_size % fbs;
  if( rest == 0 ) return 0;		// last data block is complete
  uint8_t * const lastbuf = new uint8_t[fbs];
  if( last_is_missing ) return lastbuf;	// uninitialized buffer
  std::memcpy( lastbuf, prodata + ( prodata_size - rest ), rest );
  std::memset( lastbuf + rest, 0, fbs - rest );
  return lastbuf;		// copy of last data block padded to fbs bytes
  }

enum { min_fbs = 512, max_unit_fbs = 1 << 30 };			//   1 GiB
const unsigned long long max_fbs = 1ULL << 47;			// 128 TiB
enum { max_k8 = 128, max_k16 = 32768, max_nk16 = 2048 };
const unsigned long long max_prodata_size8 = max_fbs * max_k8;	//  16 PiB
const unsigned long long max_prodata_size = max_fbs * max_k16;	//   4 EiB
const char * const fec_extension = ".fec";

inline bool isvalid_fbs( const unsigned long long fbs )
  { return fbs >= min_fbs && fbs <= max_fbs && fbs % min_fbs == 0; }

struct Coded_fbs				// fec_block_size
  {
  enum { size = 2 };
  uint8_t data[size];			// 11-bit mantissa, 5-bit exponent

  Coded_fbs() {}				// default constructor
  Coded_fbs( const unsigned long long fbs, const unsigned unit_fbs )
    {
    unsigned long long m = fbs;
    int e = 0;
    while( m > 2047 || ( m > 1 && e < 9 ) ) { m >>= 1; ++e; }
    if( m << e < fbs && ++m > 2047 ) { m >>= 1; ++e; }
    while( ( m << e ) % unit_fbs != 0 ) if( ++m > 2047 ) { m >>= 1; ++e; }
    if( m == 0 || m > 2047 || e < 9 || e > 40 || m << e < fbs ||
        !isvalid_fbs( m << e ) || !isvalid_fbs( fbs ) )
      internal_error( "Coded_fbs: can't fit fec_block_size in packet." );
    data[0] = m;
    data[1] = ( e - 9 ) << 3 | m >> 8;
    }

  void copy( uint8_t * const buf ) const
    { buf[0] = data[0]; buf[1] = data[1]; }

  unsigned long long val() const
    {
    unsigned long long m = ( ( data[1] & 7 ) << 8 ) | data[0];
    const int e = ( data[1] >> 3 ) + 9;
    return m << e;
    }
  };

enum { fec_magic_l = 4, crc32_l = le32::size };
const uint8_t fec_magic[4] = { 0xB3, 0xA5, 0xB6, 0xAF };	// ~"LZIP"
const uint8_t fec_packet_magic[4] = { fec_magic[0], 'F', 'E', 'C' };

inline bool check_fec_magic( const uint8_t * const image_buffer )
  { return std::memcmp( image_buffer, fec_magic, 4 ) == 0; }

class Packet_base
  {
protected:
  // the packet trailer contains the CRC32 of the payload
  enum Lengths { trailer_size = crc32_l };

  // header_size must be a multiple of 4 for uint32_t alignment in mul_add
  const uint8_t * image_;		// header + payload + trailer
  bool image_is_external;

  Packet_base() : image_is_external( false ) {}
  explicit Packet_base( const uint8_t * const image_buffer )
    : image_( image_buffer ), image_is_external( true ) {}
  ~Packet_base() { if( !image_is_external ) delete[] image_; }

public:
  const uint8_t * image() const { return image_; }
  };


class Chksum_packet : public Packet_base
  {
  enum { current_version = 0 };
  enum Lengths { version_l = 1, flags_l = 1, prodata_size_l = 8,
                 prodata_md5_l = 16 };
  enum Offsets { version_o = fec_magic_l,
                 flags_o = version_o + version_l,
                 fbs_o = flags_o + flags_l,
                 prodata_size_o = fbs_o + Coded_fbs::size,
                 prodata_md5_o = prodata_size_o + prodata_size_l,
                 header_crc_o = prodata_md5_o + prodata_md5_l,
                 header_size = header_crc_o + crc32_l,
                 crc_array_o = header_size };

  static unsigned compute_header_crc( const uint8_t * const image_buffer )
    { return crc32.compute_crc( image_buffer, header_crc_o ); }

public:
  // check image_buffer with check_image before calling this constructor
  explicit Chksum_packet( const uint8_t * const image_buffer )
    : Packet_base( image_buffer ) {}
  Chksum_packet( const uint8_t * const prodata,
                 const unsigned long prodata_size,
                 const md5_type & prodata_md5, const Coded_fbs coded_fbs,
                 const bool gf16_, const bool is_crc_c_ );

  unsigned long long prodata_size() const
    { return get_le( image_ + prodata_size_o, prodata_size_l ); }
  const md5_type & prodata_md5() const
    { return *(md5_type *)(image_ + prodata_md5_o); }
  unsigned long long fec_block_size() const
    { return ((Coded_fbs *)(image_ + fbs_o))->val(); }
  static bool check_flags( const uint8_t * const image_buffer )
    { return image_buffer[flags_o] <= 3; }
  bool gf16() const { return image_[flags_o] & 2; }
  bool is_crc_c() const { return image_[flags_o] & 1; }
  // crc_array contains one CRC32 or one CRC32-C per protected data block
  const le32 * crc_array() const
    { return (const le32 *)(image_ + crc_array_o); }

  bool update_prodata_md5( const md5_type & prodata_md5 );

  unsigned prodata_blocks() const
    { return ceil_divide( prodata_size(), fec_block_size() ); }
  unsigned packet_size() const
    { return prodata_blocks() * sizeof crc_array()[0] +
             header_size + trailer_size; }

  static unsigned long long prodata_blocks( const unsigned long prodata_size,
                                            const unsigned long fbs )
    { return ceil_divide( prodata_size, fbs ); }
  static unsigned long long packet_size( const unsigned long prodata_size,
                                         const unsigned long fbs )
    { return ceil_divide( prodata_size, fbs ) *
      sizeof Chksum_packet( 0 ).crc_array()[0] + header_size + trailer_size; }
  static unsigned min_packet_size()
    { return header_size + le32::size + trailer_size; }
  static uint8_t version( const uint8_t * const image_buffer )
    { return image_buffer[version_o]; }
  static bool check_version( const uint8_t * const image_buffer )
    { return image_buffer[version_o] == current_version; }

  static unsigned check_image( const uint8_t * const image_buffer,
                               const unsigned long max_size );
  bool check_payload_crc() const
    {
    const unsigned paysize = packet_size() - header_size - trailer_size;
    const unsigned payload_crc_o = crc_array_o + paysize;
    const unsigned payload_crc = get_le( image_ + payload_crc_o, crc32_l );
    return crc32.compute_crc( image_ + crc_array_o, paysize ) == payload_crc;
    }
  };


class Fec_packet : public Packet_base
  {
  enum Lengths { fbn_l = 2 };
  enum Offsets { fbn_o = fec_magic_l,
                 fbs_o = fbn_o + fbn_l,
                 header_crc_o = fbs_o + Coded_fbs::size,
                 header_size = header_crc_o + crc32_l,
                 fec_block_o = header_size };

  static unsigned compute_header_crc( const uint8_t * const image_buffer )
    { return crc32.compute_crc( image_buffer, header_crc_o ); }

public:
  // check image_buffer with check_image before calling this constructor
  explicit Fec_packet( const uint8_t * const image_buffer )
    : Packet_base( image_buffer ) {}
  Fec_packet( const uint8_t * const prodata, const uint8_t * const lastbuf,
              const unsigned fbn, const unsigned k,
              const Coded_fbs coded_fbs, const bool gf16 );

  unsigned fec_block_number() const
    { return get_le( image_ + fbn_o, fbn_l ); }
  unsigned long long fec_block_size() const	// number of fec bytes
    { return ((Coded_fbs *)(image_ + fbs_o))->val(); }
  const uint8_t * fec_block() const { return image_ + fec_block_o; }

  unsigned long long packet_size() const
    { return header_size + fec_block_size() + trailer_size; }

  static unsigned long long packet_size( const unsigned long fbs )
    { return header_size + fbs + trailer_size; }
  static unsigned min_packet_size()
    { return header_size + min_fbs + trailer_size; }

  static unsigned long check_image( const uint8_t * const image_buffer,
                                    const unsigned long max_size );
  };


inline void prot_stdin()
  { show_file_error( "(stdin)", "Can't read protected data from standard input." ); }

// defined in fec_create.cc
enum { fc_percent, fc_blocks, fc_bytes };
void cleanup_mutex_lock();
int gf_check( const unsigned k, const bool cl_gf16, const bool fec_random );
void extract_dirname( const std::string & name, std::string & srcdir );
void replace_dirname( const std::string & name, const std::string & srcdir,
                      const std::string & destdir, std::string & outname );
bool has_fec_extension( const std::string & name );
int fec_create( const std::vector< std::string > & filenames,
                const std::string & default_output_filename,
                const unsigned long fb_or_pct, const unsigned cl_block_size,
                const unsigned num_workers, const char debug_level,
                const char fctype, const char fec_level, const char recursive,
                const bool cl_gf16, const bool fec_random, const bool force,
                const bool to_stdout );

// defined in fec_repair.cc
int fec_test( const std::vector< std::string > & filenames,
              const std::string & cl_fec_filename,
              const std::string & default_output_filename,
              const char recursive, const bool force, const bool ignore_errors,
              const bool repair, const bool to_stdout );
int fec_list( const std::vector< std::string > & filenames,
              const bool ignore_errors );
int fec_dc( const std::string & input_filename,
            const std::string & cl_fec_filename, const unsigned cblocks );
int fec_df( const std::vector< std::string > & filenames );
int fec_dz( const std::string & input_filename,
            const std::string & cl_fec_filename,
            std::vector< Block > & range_vector );
int fec_dZ( const std::string & input_filename,
            const std::string & cl_fec_filename,
            unsigned delta, unsigned sector_size );

// defined in recursive.cc
bool next_filename( std::list< std::string > & filelist,
                    std::string & input_filename, int & retval,
                    const char recursive );

// defined in gf8.cc, gf16.cc
void gf8_init();
void gf16_init();
bool gf8_check( const std::vector< unsigned > & fbn_vector, const unsigned k );
bool gf16_check( const std::vector< unsigned > & fbn_vector, const unsigned k );

/* buffer, lastbuf: k blocks of input data, last one possibly padded to fbs.
   fbn: number of the fec block to be created (fbn < max_k).
*/
void rs8_encode( const uint8_t * const buffer, const uint8_t * const lastbuf,
                 uint8_t * const fec_block, const unsigned long fbs,
                 const unsigned fbn, const unsigned k );
void rs16_encode( const uint8_t * const buffer, const uint8_t * const lastbuf,
                  uint8_t * const fec_block, const unsigned long fbs,
                  const unsigned fbn, const unsigned k );

/* buffer, lastbuf: k data blocks, those in bb_vector are missing.
   fecbuf: as many fec blocks as missing data blocks in the order of fbn_vector.
   The repaired data blocks are written in their place in buffer and lastbuf.
*/
void rs8_decode( const uint8_t * const buffer, const uint8_t * const lastbuf,
                 const std::vector< unsigned > & bb_vector,
                 const std::vector< unsigned > & fbn_vector,
                 uint8_t * const fecbuf, uint8_t * const dstbuf,
                 const unsigned long fbs, const unsigned k );
void rs16_decode( const uint8_t * const buffer, const uint8_t * const lastbuf,
                  const std::vector< unsigned > & bb_vector,
                  const std::vector< unsigned > & fbn_vector,
                  uint8_t * const fecbuf, uint8_t * const dstbuf,
                  const unsigned long fbs, const unsigned k );
